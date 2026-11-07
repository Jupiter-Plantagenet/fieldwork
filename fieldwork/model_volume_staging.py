"""Bounded, network-off transfer of worker-owned inputs into Docker named volumes.

The Docker Desktop C: bind bridge can fail before container creation. This module
builds a manifest from a fixed set of local input directories, streams a tar
archive over the Docker CLI's stdin, and embeds the matching read-only verifier
used by the staging container. No host path is mounted into either container.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tarfile
import threading
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable

from .operator_overrides import OVERRIDE_RUN_WRITE_BUDGET_BYTES, space_override

STAGE_SCHEMA = 'fieldwork.model-stage-inputs/v1'
STAGE_MANIFEST = '.fw-stage-manifest.json'
STAGE_ROOT_ENV = 'FW_STAGE_ROOT=/stage'
STAGE_PREFIXES = frozenset({'bundle', 'pixels', 'input', 'resume', 'checkpoint'})
MAX_STAGE_FILES = 10_000
MAX_STAGE_ENTRIES = 20_000
MAX_STAGE_FILE_BYTES = 128 * 1024 * 1024
MAX_STAGE_PROTOCOL_OVERHEAD_BYTES = 32 * 1024 * 1024
DEFAULT_RUN_WRITE_BUDGET_BYTES = 2 * 1024 * 1024 * 1024
MODEL_RUN_WRITE_BUDGET_BYTES = (OVERRIDE_RUN_WRITE_BUDGET_BYTES if space_override()
                                else DEFAULT_RUN_WRITE_BUDGET_BYTES)
MODEL_FIXED_TMP_WRITE_BYTES = 128 * 1024 * 1024
MAX_STAGE_TOTAL_BYTES = (MODEL_RUN_WRITE_BUDGET_BYTES - MODEL_FIXED_TMP_WRITE_BYTES
                         - MAX_STAGE_PROTOCOL_OVERHEAD_BYTES)
MAX_STAGE_MANIFEST_BYTES = 2 * 1024 * 1024
_SHA = re.compile(r'^[0-9a-f]{64}$')


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        raise ValueError('MODEL_STAGE_SOURCE_UNAVAILABLE') from None
    return path.is_symlink() or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return (not path.is_absolute() and bool(path.parts)
            and all(part not in ('', '.', '..') for part in path.parts))


def _inside(root: Path, candidate: Path) -> bool:
    try:
        return os.path.normcase(os.path.commonpath((str(root), str(candidate)))) == os.path.normcase(str(root))
    except (ValueError, OSError):
        return False


def _canonical_root(path: Path) -> tuple[Path, tuple[int, int]]:
    """Anchor a real directory handle before inventory; reject redirected paths."""
    if os.name == 'nt':
        import ctypes

        class _AttributeTagInfo(ctypes.Structure):
            _fields_ = [('attributes', ctypes.c_ulong), ('reparse_tag', ctypes.c_ulong)]

        class _ByHandleInfo(ctypes.Structure):
            _fields_ = [('attributes', ctypes.c_uint32), ('creation_low', ctypes.c_uint32),
                ('creation_high', ctypes.c_uint32), ('access_low', ctypes.c_uint32),
                ('access_high', ctypes.c_uint32), ('write_low', ctypes.c_uint32),
                ('write_high', ctypes.c_uint32), ('volume', ctypes.c_uint32),
                ('size_high', ctypes.c_uint32), ('size_low', ctypes.c_uint32),
                ('links', ctypes.c_uint32), ('index_high', ctypes.c_uint32),
                ('index_low', ctypes.c_uint32)]

        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                           ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
        create.restype = ctypes.c_void_p
        get_ex = kernel.GetFileInformationByHandleEx
        get_ex.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        get_ex.restype = ctypes.c_int
        get_info = kernel.GetFileInformationByHandle
        get_info.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        get_info.restype = ctypes.c_int
        close = kernel.CloseHandle
        close.argtypes = (ctypes.c_void_p,)
        close.restype = ctypes.c_int
        get_path = kernel.GetFinalPathNameByHandleW
        get_path.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32)
        get_path.restype = ctypes.c_uint32
        handle = create(str(path), 0x80, 0x7, None, 3, 0x00200000 | 0x02000000, None)
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            raise ValueError('MODEL_STAGE_SOURCE_UNAVAILABLE')
        try:
            attrs = _AttributeTagInfo(); info = _ByHandleInfo()
            if (not get_ex(handle, 9, ctypes.byref(attrs), ctypes.sizeof(attrs))
                    or not get_info(handle, ctypes.byref(info))):
                raise ValueError('MODEL_STAGE_SOURCE_UNAVAILABLE')
            if attrs.attributes & 0x400 or not attrs.attributes & 0x10:
                raise ValueError('MODEL_STAGE_SOURCE_REPARSE_REFUSED')
            buf = ctypes.create_unicode_buffer(32768)
            length = get_path(handle, buf, len(buf), 0)
            if not length or length >= len(buf):
                raise ValueError('MODEL_STAGE_SOURCE_UNAVAILABLE')
            final = buf.value
            if final.startswith('\\\\?\\UNC\\'):
                final = '\\\\' + final[8:]
            elif final.startswith('\\\\?\\'):
                final = final[4:]
            canonical = Path(final)
            if os.path.normcase(os.path.abspath(str(canonical))) != os.path.normcase(os.path.abspath(str(path))):
                raise ValueError('MODEL_STAGE_SOURCE_ESCAPE')
            return canonical, (int(info.volume), (int(info.index_high) << 32) | int(info.index_low))
        finally:
            close(handle)
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise ValueError('MODEL_STAGE_SOURCE_REPARSE_REFUSED') from None
    try:
        descriptor = Path(f'/proc/self/fd/{fd}')
        if not descriptor.exists():
            raise ValueError('MODEL_STAGE_HANDLE_CONFINEMENT_UNAVAILABLE')
        canonical = descriptor.resolve(strict=True)
        if os.path.normcase(os.path.abspath(str(canonical))) != os.path.normcase(os.path.abspath(str(path))):
            raise ValueError('MODEL_STAGE_SOURCE_ESCAPE')
        info = os.fstat(fd)
        return canonical, (int(info.st_dev), int(info.st_ino))
    finally:
        os.close(fd)


def _root_identity(path: Path) -> tuple[int, int]:
    _, identity = _canonical_root(path)
    return identity


def _open_verified(path: Path, root: Path, root_identity: tuple[int, int]):
    """Open a regular file and verify the opened object still resolves under root."""
    if _root_identity(root) != root_identity:
        raise ValueError('MODEL_STAGE_SOURCE_CHANGED')
    if os.name == 'nt':
        import ctypes
        import msvcrt

        class _AttributeTagInfo(ctypes.Structure):
            _fields_ = [('attributes', ctypes.c_ulong), ('reparse_tag', ctypes.c_ulong)]

        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                           ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
        create.restype = ctypes.c_void_p
        get_info = kernel.GetFileInformationByHandleEx
        get_info.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        get_info.restype = ctypes.c_int
        close_handle = kernel.CloseHandle
        close_handle.argtypes = (ctypes.c_void_p,)
        close_handle.restype = ctypes.c_int
        handle = create(str(path), 0x80000000, 0x7, None, 3, 0x00200000 | 0x08000000, None)
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            raise ValueError('MODEL_STAGE_SOURCE_UNAVAILABLE')
        try:
            info = _AttributeTagInfo()
            if not get_info(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ValueError('MODEL_STAGE_SOURCE_UNAVAILABLE')
            if info.attributes & 0x400 or info.attributes & 0x10:
                raise ValueError('MODEL_STAGE_REPARSE_REFUSED')
            get_path = kernel.GetFinalPathNameByHandleW
            get_path.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32)
            get_path.restype = ctypes.c_uint32
            buf = ctypes.create_unicode_buffer(32768)
            length = get_path(handle, buf, len(buf), 0)
            if not length or length >= len(buf):
                raise ValueError('MODEL_STAGE_SOURCE_UNAVAILABLE')
            final = buf.value
            if final.startswith('\\\\?\\UNC\\'):
                final = '\\\\' + final[8:]
            elif final.startswith('\\\\?\\'):
                final = final[4:]
            if not _inside(root, Path(final)):
                raise ValueError('MODEL_STAGE_SOURCE_ESCAPE')
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None
            stream = os.fdopen(fd, 'rb')
            if _root_identity(root) != root_identity:
                stream.close()
                raise ValueError('MODEL_STAGE_SOURCE_CHANGED')
            return stream
        finally:
            if handle is not None:
                close_handle(handle)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        descriptor_path = Path(f'/proc/self/fd/{fd}')
        if not descriptor_path.exists():
            raise ValueError('MODEL_STAGE_HANDLE_CONFINEMENT_UNAVAILABLE')
        actual = descriptor_path.resolve(strict=True)
        if not _inside(root, actual):
            raise ValueError('MODEL_STAGE_SOURCE_ESCAPE')
        stream = os.fdopen(fd, 'rb')
        if _root_identity(root) != root_identity:
            stream.close()
            raise ValueError('MODEL_STAGE_SOURCE_CHANGED')
        return stream
    except BaseException:
        os.close(fd)
        raise


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _hash_file(path: Path, root: Path, root_identity: tuple[int, int], progress_callback=None) -> tuple[int, str, tuple[int, int, int, int]]:
    digest = hashlib.sha256()
    count = 0
    with _open_verified(path, root, root_identity) as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_size < 0 or opened.st_size > MAX_STAGE_FILE_BYTES):
            raise ValueError('MODEL_STAGE_FILE_BOUNDS')
        identity = _identity(opened)
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count > MAX_STAGE_FILE_BYTES:
                raise ValueError('MODEL_STAGE_FILE_BOUNDS')
            digest.update(chunk)
            if progress_callback is not None:
                progress_callback()
        if count != opened.st_size or _identity(os.fstat(stream.fileno())) != identity:
            raise ValueError('MODEL_STAGE_SOURCE_CHANGED')
    return count, digest.hexdigest(), identity


def collect_stage_inputs(sources: Iterable[tuple[str, str | Path]], *, progress_callback=None) -> tuple[bytes, list[dict]]:
    """Inventory exact regular files under fixed volume prefixes, without reading contents out."""
    records: list[dict] = []
    seen: set[str] = set()
    total = 0
    for prefix, source in sources:
        if prefix not in STAGE_PREFIXES:
            raise ValueError('MODEL_STAGE_PREFIX_REFUSED')
        root = Path(source).absolute()
        for parent in (root, *root.parents):
            if _is_reparse(parent):
                raise ValueError('MODEL_STAGE_SOURCE_REPARSE_REFUSED')
        if not root.is_dir():
            raise ValueError('MODEL_STAGE_SOURCE_INVALID')
        root, root_identity = _canonical_root(root)
        stack = [root]
        visited = 0
        try:
            while stack:
                directory = stack.pop()
                with os.scandir(directory) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > MAX_STAGE_ENTRIES:
                            raise ValueError('MODEL_STAGE_ENTRY_COUNT_BOUNDS')
                        path = Path(entry.path)
                        if _is_reparse(path):
                            raise ValueError('MODEL_STAGE_REPARSE_REFUSED')
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(path)
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            raise ValueError('MODEL_STAGE_FILE_TYPE_REFUSED')
                        try:
                            rel = path.relative_to(root).as_posix()
                        except ValueError:
                            raise ValueError('MODEL_STAGE_SOURCE_ESCAPE') from None
                        name = prefix + '/' + rel
                        if not _safe_relative(name) or name == prefix + '/' + STAGE_MANIFEST or name in seen:
                            raise ValueError('MODEL_STAGE_PATH_REFUSED')
                        if len(records) >= MAX_STAGE_FILES:
                            raise ValueError('MODEL_STAGE_FILE_COUNT_BOUNDS')
                        if progress_callback is None:
                            count, digest, identity = _hash_file(path, root, root_identity)
                        else:
                            count, digest, identity = _hash_file(path, root, root_identity, progress_callback)
                        total += count
                        if total > MAX_STAGE_TOTAL_BYTES:
                            raise ValueError('MODEL_STAGE_TOTAL_BOUNDS')
                        seen.add(name)
                        records.append({'path': name, 'bytes': count, 'sha256': digest,
                                        'source': path, 'root': root, 'root_identity': root_identity,
                                        'identity': identity})
        except OSError:
            raise ValueError('MODEL_STAGE_SOURCE_UNAVAILABLE') from None
    if not records:
        raise ValueError('MODEL_STAGE_INPUTS_EMPTY')
    manifest = {'schema': STAGE_SCHEMA, 'count': len(records), 'total_bytes': total,
                'files': [{'path': r['path'], 'bytes': r['bytes'], 'sha256': r['sha256']}
                          for r in records]}
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(raw) > MAX_STAGE_MANIFEST_BYTES:
        raise ValueError('MODEL_STAGE_MANIFEST_BOUNDS')
    return raw, records


class _VerifiedReader:
    def __init__(self, stream: BinaryIO, record: dict, progress=None):
        self.stream = stream
        self.record = record
        self.progress = progress
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size=-1):
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > self.record['bytes']:
            raise ValueError('MODEL_STAGE_SOURCE_CHANGED')
        if data and self.progress is not None:
            self.progress.record(len(data))
        self.digest.update(data)
        return data

    def verify(self):
        current = self.stream.tell()
        if (self.count != self.record['bytes']
                or self.digest.hexdigest() != self.record['sha256']):
            raise ValueError('MODEL_STAGE_SOURCE_CHANGED')
        after = os.fstat(self.stream.fileno())
        if after.st_size != self.record['bytes']:
            raise ValueError('MODEL_STAGE_SOURCE_CHANGED')
        self.stream.seek(current)


class StageProgressCounter:
    """Thread-safe byte count for a tar writer; lease callbacks stay on the owner thread."""

    def __init__(self):
        self._lock = threading.Lock()
        self._bytes = 0

    def record(self, amount: int) -> None:
        if type(amount) is not int or amount < 0:
            raise ValueError('MODEL_STAGE_PROGRESS_INVALID')
        with self._lock:
            self._bytes += amount

    def snapshot(self) -> int:
        with self._lock:
            return self._bytes


def write_stage_tar(target: BinaryIO, manifest_bytes: bytes, records: list[dict], *, progress=None) -> None:
    """Stream a closed inventory to stdin; detect source mutation during the transfer."""
    with tarfile.open(fileobj=target, mode='w|', format=tarfile.PAX_FORMAT) as archive:
        meta = tarfile.TarInfo(STAGE_MANIFEST)
        meta.size = len(manifest_bytes); meta.mode = 0o444; meta.uid = 0; meta.gid = 0; meta.mtime = 0
        archive.addfile(meta, io.BytesIO(manifest_bytes))
        for record in records:
            source = record['source']
            info = tarfile.TarInfo(record['path'])
            info.size = record['bytes']; info.mode = 0o444; info.uid = 0; info.gid = 0; info.mtime = 0
            with _open_verified(source, record['root'], record['root_identity']) as stream:
                before = os.fstat(stream.fileno())
                if _identity(before) != record['identity']:
                    raise ValueError('MODEL_STAGE_SOURCE_CHANGED')
                reader = _VerifiedReader(stream, record, progress)
                archive.addfile(info, reader)
                reader.verify()
                after = os.fstat(stream.fileno())
                if _identity(before) != _identity(after):
                    raise ValueError('MODEL_STAGE_SOURCE_CHANGED')


# Run only inside the pinned model image. The host and this helper exchange a
# bounded tar stream over stdin; the helper accepts only the exact manifest and
# regular files hashed by collect_stage_inputs, then makes the named volume
# world-readable but unwritable before the model container mounts it read-only.
STAGER_CODE = r'''import hashlib,json,os,stat,sys,tarfile
from pathlib import Path,PurePosixPath
ROOT=Path(os.environ.get('FW_STAGE_ROOT',''))
MAX_FILES=10000
MAX_FILE=128*1024*1024
MAX_TOTAL=2*1024*1024*1024-128*1024*1024-32*1024*1024
MAX_MANIFEST=2*1024*1024
def fail(): raise SystemExit(72)
def safe(name):
 p=PurePosixPath(name)
 return (not p.is_absolute() and bool(p.parts) and all(x not in ('','.','..') for x in p.parts))
try:
 if str(ROOT)!='/stage' or ROOT.is_symlink() or not ROOT.is_dir(): fail()
 if any(ROOT.iterdir()): fail()
 archive=tarfile.open(fileobj=sys.stdin.buffer,mode='r|')
 first=archive.next()
 if first is None or first.name!='.fw-stage-manifest.json' or not first.isfile() or first.size>MAX_MANIFEST: fail()
 f=archive.extractfile(first)
 if f is None: fail()
 raw=f.read(MAX_MANIFEST+1)
 if len(raw)!=first.size or len(raw)>MAX_MANIFEST: fail()
 doc=json.loads(raw.decode('ascii'))
 if type(doc) is not dict or set(doc)!={'schema','count','total_bytes','files'} or doc['schema']!='fieldwork.model-stage-inputs/v1': fail()
 files=doc['files']
 if type(files) is not list or not 1<=len(files)<=MAX_FILES or doc['count']!=len(files): fail()
 expected={};total=0
 for r in files:
  if type(r) is not dict or set(r)!={'path','bytes','sha256'}: fail()
  name=r['path'];size=r['bytes'];digest=r['sha256']
  if (type(name) is not str or not safe(name) or name=='.fw-stage-manifest.json'
      or '\\' in name or '\x00' in name or name.split('/')[0] not in {'bundle','pixels','input','resume','checkpoint'}
      or name in expected): fail()
  if type(size) is not int or not 0<=size<=MAX_FILE: fail()
  if type(digest) is not str or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest): fail()
  total+=size
  if total>MAX_TOTAL: fail()
  expected[name]=(size,digest)
 if type(doc['total_bytes']) is not int or doc['total_bytes']!=total: fail()
 seen=set()
 while True:
  member=archive.next()
  if member is None: break
  name=member.name
  if not safe(name) or name not in expected or name in seen or not member.isfile(): fail()
  size,want=expected[name]
  if member.size!=size: fail()
  source=archive.extractfile(member)
  if source is None: fail()
  dest=ROOT.joinpath(*PurePosixPath(name).parts)
  dest.parent.mkdir(parents=True,exist_ok=True)
  if dest.exists() or dest.is_symlink(): fail()
  h=hashlib.sha256();count=0
  with dest.open('xb') as out:
   while True:
    chunk=source.read(1024*1024)
    if not chunk: break
    count+=len(chunk)
    if count>size: fail()
    h.update(chunk);out.write(chunk)
   out.flush();os.fsync(out.fileno())
  if count!=size or h.hexdigest()!=want: fail()
  os.chmod(dest,0o444);seen.add(name)
 if seen!=set(expected): fail()
 (ROOT/'output').mkdir(mode=0o755,exist_ok=False)
 dirs=sorted((p for p in ROOT.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True)
 for d in dirs: os.chmod(d,0o555)
 os.chmod(ROOT,0o555)
except SystemExit: raise
except BaseException: fail()
'''
