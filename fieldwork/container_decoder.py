"""Pinned, no-network Linux-container image decoder for real W3 intake.

The host reads at most one member (20 MiB) and sends only those bytes over the
container's stdin. No archive path, host directory, environment, credential or
network is passed into the container. The expected image is its actual Docker
config digest, supplied by the operator after a reviewed build.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import threading
import time
import uuid
import warnings
from pathlib import Path

try:
    import psutil
except ImportError:  # the minimal decoder image does not install host process tools.
    psutil = None

MAX_FILE = 20 * 1024 * 1024
MAX_PIXELS = 20_000_000
MAX_OUTPUT = 4096
CONTAINER_START_TIMEOUT = 8
DECODE_TIMEOUT = 12
CONTAINER_LABEL = 'fieldwork.real-intake.decoder'
IMAGE_ID_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
CONTAINER_ID_RE = re.compile(r'^[0-9a-f]{64}$')
PILLOW_VERSION = '13.0.0'
NUMPY_VERSION = '2.5.4'
PHASH_ALGORITHM = 'phash-dct64/v1'
DECODER_VERSION = (f'fieldwork.decode/v2 pillow-{PILLOW_VERSION} numpy-{NUMPY_VERSION} '
                   f'exif-transpose rgb8 alpha-on-white {PHASH_ALGORITHM}')
RESULT_ENVELOPE = 'fieldwork.decoder-result/v2'
FORMATS = {'JPEG', 'PNG', 'WEBP'}
_PHASH_N = 32


class DecoderUnavailable(RuntimeError):
    """Required isolated decoder is unavailable or not the pinned artifact."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class DecoderProtocolError(RuntimeError):
    """Container returned an unrecognized or unbounded result."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def decode_bytes(data: bytes) -> dict:
    """Container entry point; mirrors ``decode_child.decode`` on byte input."""
    if len(data) > MAX_FILE:
        return {'ok': False, 'reason': 'FILE_TOO_LARGE', 'bytes': len(data)}
    try:
        from PIL import Image, ImageOps, __version__ as pillow_version
        import numpy as np

        if pillow_version != PILLOW_VERSION or np.__version__ != NUMPY_VERSION:
            raise DecoderProtocolError('PINNED_DECODER_DEPENDENCY_MISMATCH')
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data)) as im:
            fmt = im.format
            if fmt not in FORMATS:
                return {'ok': False, 'reason': 'UNSUPPORTED_FORMAT:' + str(fmt)}
            if im.width * im.height > MAX_PIXELS:
                return {'ok': False, 'reason': 'PIXEL_LIMIT', 'width': im.width, 'height': im.height}
            if getattr(im, 'is_animated', False) or getattr(im, 'n_frames', 1) != 1:
                return {'ok': False, 'reason': 'MULTIFRAME'}
            im.load()
            im = ImageOps.exif_transpose(im)
            # Match fieldwork.splits.phash exactly: EXIF transpose, grayscale
            # conversion, 32x32 Pillow bilinear resize, float64 DCT-II, low-band
            # median over the 63 AC coefficients, and row-major bit ordering.
            gray = im.convert('L').resize((_PHASH_N, _PHASH_N), Image.Resampling.BILINEAR)
            pixels = np.asarray(gray, dtype=np.float64)
            dct = np.array([[np.cos(np.pi * (2 * x + 1) * u / (2 * _PHASH_N))
                             for x in range(_PHASH_N)] for u in range(_PHASH_N)], dtype=np.float64)
            low = (dct @ pixels @ dct.T)[:8, :8].flatten()
            median = np.median(low[1:])
            bits = (low > median).astype(np.uint8)
            bits[0] = 0
            hash_value = 0
            for bit in bits.tolist():
                hash_value = (hash_value << 1) | int(bit)
            perceptual_hash = f'{hash_value:016x}'
            if im.mode in ('RGBA', 'LA') or (im.mode == 'P' and 'transparency' in im.info):
                rgba = im.convert('RGBA')
                base = Image.new('RGBA', rgba.size, (255, 255, 255, 255))
                im = Image.alpha_composite(base, rgba)
            rgb = im.convert('RGB')
            pixel_sha = hashlib.sha256(b'RGB8|%d|%d|' % rgb.size + rgb.tobytes()).hexdigest()
            return {'ok': True, 'format': fmt, 'width': rgb.width, 'height': rgb.height,
                    'pixel_sha256': pixel_sha, 'phash_algorithm': PHASH_ALGORITHM,
                    'phash_hex': perceptual_hash, 'decoder': DECODER_VERSION}
    except (DecoderProtocolError,):
        raise
    except Exception as exc:
        from PIL import Image
        if isinstance(exc, (Image.DecompressionBombError, Image.DecompressionBombWarning)):
            return {'ok': False, 'reason': 'PIXEL_LIMIT', 'decoder': DECODER_VERSION}
        return {'ok': False, 'reason': 'DECODE_FAILED:' + type(exc).__name__, 'decoder': DECODER_VERSION}


def _entrypoint():
    data = bytearray()
    while len(data) <= MAX_FILE:
        block = os.read(0, min(1024 * 1024, MAX_FILE + 1 - len(data)))
        if not block:
            break
        data.extend(block)
    input_sha256 = hashlib.sha256(data).hexdigest()
    input_bytes = len(data)
    try:
        result = decode_bytes(bytes(data))
    except DecoderProtocolError:
        # A version mismatch is protocol failure, not an ordinary rejected image.
        # The host requires the pinned decoder string and will fail the worker closed.
        result = {'ok': False, 'reason': 'PINNED_DECODER_DEPENDENCY_MISMATCH', 'decoder': 'untrusted'}
    if 'decoder' not in result:
        result['decoder'] = DECODER_VERSION
    envelope = {'schema': RESULT_ENVELOPE, 'input_sha256': input_sha256,
                'input_bytes': input_bytes, 'result': result}
    payload = json.dumps(envelope, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(payload) > MAX_OUTPUT:
        payload = b'{"ok":false,"reason":"DECODER_RESULT_TOO_LARGE"}'
    os.write(1, payload)
    os.write(1, b'\n')


def _local_docker_env() -> dict[str, str]:
    # Remote daemon/context/certificate overrides could route image bytes off-host.
    forbidden = ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY')
    if any(os.environ.get(key) for key in forbidden):
        raise DecoderUnavailable('REMOTE_DOCKER_CONFIGURATION_FORBIDDEN')
    env = {key: value for key, value in os.environ.items()
           if key in ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE')}
    return env


def _docker_command(*args) -> list[str]:
    return ['docker', '--context', 'default', *args]


def container_args(image_id: str, cid_file: str, nonce: str) -> list[str]:
    """Return the complete hardened one-shot invocation (no host mounts)."""
    if not IMAGE_ID_RE.fullmatch(image_id):
        raise ValueError('DECODER_IMAGE_ID_INVALID')
    if not re.fullmatch(r'[0-9a-f]{32}', nonce):
        raise ValueError('DECODER_NONCE_INVALID')
    return _docker_command(
        'run', '--pull=never', '--platform=linux/amd64', '--rm', '--interactive',
        '--cidfile', cid_file, '--network=none', '--read-only', '--cap-drop=ALL',
        f'--label={CONTAINER_LABEL}=1', f'--label={CONTAINER_LABEL}.nonce={nonce}',
        '--security-opt=no-new-privileges=true', '--user=65532:65532',
        '--memory=512m', '--memory-swap=512m', '--cpus=1', '--pids-limit=16',
        '--ulimit=core=0', '--ulimit=nofile=64:64',
        '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m', '--workdir=/tmp',
        '--entrypoint=/usr/local/bin/python', image_id, '-I', '-B',
        '/app/container_decoder.py', '--container')


def _read_container_id(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise DecoderUnavailable('DECODER_CID_UNREADABLE') from None
    if path.is_symlink() or getattr(info, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
        raise DecoderUnavailable('DECODER_CID_REPARSE_POINT')
    try:
        raw = path.read_text(encoding='ascii').strip()
    except FileNotFoundError:
        return None
    except OSError:
        raise DecoderUnavailable('DECODER_CID_UNREADABLE') from None
    if not raw:
        # Docker creates --cidfile before it has published the ID. Treat this
        # transient empty file as pending; ownership is still bound by nonce.
        return None
    if not CONTAINER_ID_RE.fullmatch(raw):
        raise DecoderUnavailable('DECODER_CID_INVALID')
    return raw


class ContainerDecoder:
    """Bounded container decoder with persistent, CID-bound cleanup receipts."""

    version = DECODER_VERSION

    def __init__(self, image_id: str, *, private_dir: str | Path,
                 session_id: str | None = None, docker_env: dict[str, str] | None = None):
        if not IMAGE_ID_RE.fullmatch(image_id):
            raise DecoderUnavailable('DECODER_IMAGE_ID_INVALID')
        if not session_id:
            session_id = uuid.uuid4().hex
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', session_id):
            raise DecoderUnavailable('DECODER_SESSION_INVALID')
        self.image_id = image_id
        try:
            self.base_dir = Path(private_dir).resolve(strict=True)
        except OSError:
            raise DecoderUnavailable('DECODER_PRIVATE_DIR_UNAVAILABLE') from None
        if not self.base_dir.is_dir():
            raise DecoderUnavailable('DECODER_PRIVATE_DIR_UNAVAILABLE')
        self.session_id = session_id
        self.registry_dir = self.base_dir / '.decoder-sessions'
        self.private_dir = self.registry_dir / session_id
        self.registry_dir.mkdir(exist_ok=True)
        self._require_real_directory(self.registry_dir)
        self.private_dir.mkdir(exist_ok=True)
        self._require_real_directory(self.private_dir)
        self.env = _local_docker_env() if docker_env is None else dict(docker_env)
        self._verify_image()
        self._recover_receipts()
        self.restarts = 0
        self.peak_rss = 0  # memory is enforced by container cgroups, not polling.

    @staticmethod
    def _require_real_directory(path: Path):
        try:
            info = path.lstat()
        except OSError:
            raise DecoderUnavailable('DECODER_PRIVATE_DIR_UNAVAILABLE') from None
        if (path.is_symlink() or not path.is_dir()
                or getattr(info, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
            raise DecoderUnavailable('DECODER_PRIVATE_DIR_REPARSE_POINT')

    def _run(self, args, *, timeout=3, capture=False):
        try:
            result = subprocess.run(_docker_command(*args), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=timeout, env=self.env, check=False,
                text=capture)
        except (OSError, subprocess.TimeoutExpired):
            raise DecoderUnavailable('DOCKER_STATE_UNAVAILABLE') from None
        if capture and len(result.stdout) > MAX_OUTPUT:
            raise DecoderUnavailable('DOCKER_STATE_OUTPUT_LIMIT')
        return result

    def _verify_image(self):
        try:
            context = self._run(('context', 'inspect', 'default', '--format={{json .Endpoints.docker}}'),
                                timeout=5, capture=True)
            endpoint = json.loads(context.stdout) if context.returncode == 0 else {}
            host = endpoint.get('Host') if type(endpoint) is dict else None
            if not (host == 'npipe:////./pipe/docker_engine'
                    or type(host) is str and host.startswith('unix:///')):
                raise DecoderUnavailable('LOCAL_DOCKER_ENDPOINT_REQUIRED')
            info = self._run(('info', '--format={{.OSType}}'), timeout=5, capture=True)
            if info.returncode != 0 or info.stdout.strip() != 'linux':
                raise DecoderUnavailable('LINUX_DOCKER_ENGINE_REQUIRED')
            result = self._run(('image', 'inspect', '--format={{.Id}}', self.image_id),
                               timeout=5, capture=True)
        except (ValueError, TypeError):
            raise DecoderUnavailable('LOCAL_DOCKER_UNAVAILABLE') from None
        if result.returncode != 0 or result.stdout.strip() != self.image_id:
            raise DecoderUnavailable('DECODER_IMAGE_NOT_PINNED_LOCALLY')

    def _owner_alive(self, receipt: dict) -> bool:
        if psutil is None:
            raise DecoderUnavailable('DECODER_PROCESS_INSPECTION_UNAVAILABLE')
        try:
            proc = psutil.Process(receipt['owner_pid'])
            return abs(proc.create_time() - receipt['owner_created']) < 0.02
        except psutil.NoSuchProcess:
            return False
        except (psutil.AccessDenied, OSError, TypeError, ValueError):
            raise DecoderUnavailable('DECODER_OWNER_STATUS_UNKNOWN') from None

    @staticmethod
    def _read_receipt(path: Path) -> dict:
        try:
            info = path.lstat()
            parent = path.parent.lstat()
            if (path.is_symlink() or path.parent.is_symlink()
                    or getattr(info, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
                    or getattr(parent, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
                    or info.st_size > 4096):
                raise ValueError()
            value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique_pairs)
        except (OSError, ValueError, TypeError, UnicodeError):
            raise DecoderUnavailable('DECODER_CLEANUP_RECEIPT_INVALID') from None
        expected = {'schema', 'state', 'nonce', 'cid_file', 'owner_pid', 'owner_created'}
        optional = {'cleanup_error', 'updated_utc'}
        if (type(value) is not dict or not expected <= value.keys() or value.keys() - expected - optional
                or value['schema'] != 'fieldwork.decoder-cleanup/v1'
                or value['state'] not in ('active', 'cleanup_required', 'resolved')
                or type(value['nonce']) is not str or not re.fullmatch(r'[0-9a-f]{32}', value['nonce'])
                or value['cid_file'] != '.decoder-' + value['nonce'] + '.cid'
                or type(value['owner_pid']) is not int or value['owner_pid'] <= 0
                or type(value['owner_created']) not in (int, float)):
            raise DecoderUnavailable('DECODER_CLEANUP_RECEIPT_INVALID')
        return value

    def _receipt_paths(self):
        try:
            return list(self.registry_dir.glob('*/.decoder-*.cleanup.json'))
        except OSError:
            raise DecoderUnavailable('DECODER_CLEANUP_REGISTRY_UNAVAILABLE') from None

    def _recover_receipts(self):
        for receipt_path in self._receipt_paths():
            receipt = self._read_receipt(receipt_path)
            if receipt['state'] == 'resolved':
                continue
            if receipt['state'] == 'active' and self._owner_alive(receipt):
                continue
            cid_path = receipt_path.parent / receipt['cid_file']
            self._cleanup_receipt(receipt_path, receipt, cid_path)

    def _list_containers(self, nonce: str) -> list[str]:
        result = self._run(('ps', '--all', '--quiet', '--no-trunc', '--filter',
                            f'label={CONTAINER_LABEL}.nonce={nonce}'), capture=True)
        if result.returncode != 0:
            raise DecoderUnavailable('DECODER_CONTAINER_QUERY_FAILED')
        ids = result.stdout.splitlines()
        if len(ids) > 1 or any(not CONTAINER_ID_RE.fullmatch(value.strip()) for value in ids):
            raise DecoderUnavailable('DECODER_CONTAINER_IDENTITY_AMBIGUOUS')
        return [value.strip() for value in ids if value.strip()]

    def _list_by_id(self, container_id: str) -> list[str]:
        result = self._run(('ps', '--all', '--quiet', '--no-trunc', '--filter',
                            f'id={container_id}'), capture=True)
        if result.returncode != 0:
            raise DecoderUnavailable('DECODER_CONTAINER_QUERY_FAILED')
        ids = [value.strip() for value in result.stdout.splitlines() if value.strip()]
        if len(ids) > 1 or any(not CONTAINER_ID_RE.fullmatch(value) for value in ids):
            raise DecoderUnavailable('DECODER_CONTAINER_IDENTITY_AMBIGUOUS')
        return ids

    def _cleanup_receipt(self, receipt_path: Path, receipt: dict, cid_path: Path):
        nonce = receipt['nonce']
        try:
            ids = self._list_containers(nonce)
            cid = _read_container_id(cid_path)
            if cid and ids and cid != ids[0]:
                raise DecoderUnavailable('DECODER_CID_LABEL_MISMATCH')
            owned_id = ids[0] if ids else cid
            if owned_id:
                id_matches = self._list_by_id(owned_id)
                if ids and id_matches != [owned_id]:
                    raise DecoderUnavailable('DECODER_CONTAINER_IDENTITY_AMBIGUOUS')
                if id_matches:
                    cid = owned_id
                    inspected = self._run(('container', 'inspect', '--format={{json .Config.Labels}}', cid),
                                          capture=True)
                    try:
                        labels = json.loads(inspected.stdout) if inspected.returncode == 0 else {}
                    except (ValueError, TypeError):
                        labels = {}
                    if (type(labels) is not dict or labels.get(CONTAINER_LABEL) != '1'
                            or labels.get(CONTAINER_LABEL + '.nonce') != nonce):
                        raise DecoderUnavailable('DECODER_CONTAINER_LABEL_MISMATCH')
                    # Kill first, then remove. Return codes alone are not proof:
                    # the final label and CID queries must establish absence.
                    self._run(('kill', '--signal=KILL', cid), timeout=3)
                    self._run(('rm', '--force', cid), timeout=3)
            remaining = self._list_containers(nonce)
            if remaining:
                raise DecoderUnavailable('DECODER_CONTAINER_CLEANUP_UNCONFIRMED')
            if cid and self._list_by_id(cid):
                raise DecoderUnavailable('DECODER_CONTAINER_CLEANUP_UNCONFIRMED')
        except DecoderUnavailable as exc:
            self._record_cleanup_failure(receipt_path, receipt, exc.code)
            raise DecoderUnavailable('DECODER_CLEANUP_REQUIRED') from None
        except Exception:
            self._record_cleanup_failure(receipt_path, receipt, 'DECODER_CLEANUP_UNCONFIRMED')
            raise DecoderUnavailable('DECODER_CLEANUP_REQUIRED') from None
        self._finish_receipt(receipt_path, receipt, cid_path)

    @staticmethod
    def _record_cleanup_failure(path: Path, receipt: dict, code: str):
        receipt['state'] = 'cleanup_required'
        receipt['cleanup_error'] = code[:64]
        receipt['updated_utc'] = time.time()
        temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.writing')
        try:
            with temp.open('x', encoding='utf-8') as stream:
                json.dump(receipt, stream, separators=(',', ':'))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, path)
        except OSError:
            temp.unlink(missing_ok=True)

    @staticmethod
    def _finish_receipt(path: Path, receipt: dict, cid_path: Path):
        cid_path.unlink(missing_ok=True)
        if 'cleanup_error' in receipt:
            receipt['state'] = 'resolved'
            receipt['updated_utc'] = time.time()
            temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.writing')
            try:
                with temp.open('x', encoding='utf-8') as stream:
                    json.dump(receipt, stream, separators=(',', ':'))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, path)
            except OSError:
                temp.unlink(missing_ok=True)
                raise DecoderUnavailable('DECODER_CLEANUP_AUDIT_WRITE_FAILED') from None
        else:
            path.unlink(missing_ok=True)

    def _new_receipt(self):
        if psutil is None:
            raise DecoderUnavailable('DECODER_PROCESS_INSPECTION_UNAVAILABLE')
        nonce = uuid.uuid4().hex
        cid_path = self.private_dir / ('.decoder-' + nonce + '.cid')
        receipt_path = self.private_dir / ('.decoder-' + nonce + '.cleanup.json')
        receipt = {'schema': 'fieldwork.decoder-cleanup/v1', 'state': 'active',
                   'nonce': nonce, 'cid_file': cid_path.name, 'owner_pid': os.getpid(),
                   'owner_created': psutil.Process().create_time()}
        fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(receipt, stream, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        return receipt_path, receipt, cid_path

    @staticmethod
    def _stop_cli(proc):
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass

    def decode(self, path: str | Path) -> dict:
        # A prior cleanup failure blocks another decoder until absence is proven.
        self._recover_receipts()
        path = Path(path)
        try:
            with path.open('rb') as stream:
                data = stream.read(MAX_FILE + 1)
                if len(data) > MAX_FILE:
                    return {'ok': False, 'reason': 'FILE_TOO_LARGE', 'bytes': len(data)}
                if stream.read(1):
                    return {'ok': False, 'reason': 'FILE_TOO_LARGE', 'bytes': MAX_FILE + 2}
        except OSError as exc:
            raise DecoderUnavailable('DECODER_INPUT_UNREADABLE') from exc

        receipt_path, receipt, cid_path = self._new_receipt()
        proc = None
        output = bytearray()
        overflow = threading.Event()
        reader_done = threading.Event()
        writer_done = threading.Event()
        threads = []
        decode_result = None
        failure = None
        try:
            proc = subprocess.Popen(container_args(self.image_id, str(cid_path), receipt['nonce']),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=self.env, bufsize=0)
            start_deadline = time.monotonic() + CONTAINER_START_TIMEOUT
            cid = None
            while proc.poll() is None and time.monotonic() < start_deadline:
                cid = _read_container_id(cid_path)
                if cid:
                    break
                time.sleep(.01)
            if not cid:
                raise DecoderUnavailable('CONTAINER_START_FAILED')

            def write_input():
                try:
                    _write_all(proc.stdin, data)
                    proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass
                    writer_done.set()

            def read_output():
                try:
                    while True:
                        block = proc.stdout.read(1024)
                        if not block:
                            break
                        if len(output) + len(block) > MAX_OUTPUT:
                            overflow.set()
                        else:
                            output.extend(block)
                finally:
                    reader_done.set()

            threads = [threading.Thread(target=write_input, daemon=True),
                       threading.Thread(target=read_output, daemon=True)]
            for thread in threads:
                thread.start()
            deadline = time.monotonic() + DECODE_TIMEOUT
            while proc.poll() is None and not overflow.is_set() and time.monotonic() < deadline:
                time.sleep(.02)
            if overflow.is_set() or proc.poll() is None:
                self.restarts += 1
                failure = 'DECODER_OUTPUT_LIMIT' if overflow.is_set() else 'DECODER_TIMEOUT'
            else:
                for thread in threads:
                    thread.join(timeout=2)
                if proc.returncode != 0 or not reader_done.is_set() or not writer_done.is_set() or overflow.is_set():
                    failure = 'DECODER_CONTAINER_FAILED'
                else:
                    try:
                        envelope = json.loads(output.decode('ascii'), object_pairs_hook=_unique_pairs)
                        decode_result = _validate_envelope(envelope, data)
                    except (UnicodeError, ValueError, TypeError):
                        failure = 'DECODER_PROTOCOL_INVALID'
        except OSError:
            failure = 'LOCAL_DOCKER_UNAVAILABLE'
        finally:
            self._stop_cli(proc)
            for thread in threads:
                thread.join(timeout=2)
            stuck = any(thread.is_alive() for thread in threads)
            try:
                self._cleanup_receipt(receipt_path, receipt, cid_path)
            except DecoderUnavailable:
                raise
            if stuck:
                self._record_cleanup_failure(receipt_path, receipt, 'DECODER_PIPE_THREAD_STUCK')
                raise DecoderUnavailable('DECODER_CLEANUP_REQUIRED')
        if failure:
            raise DecoderUnavailable(failure)
        return decode_result

    def close(self):
        self._recover_receipts()


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('DUPLICATE_DECODER_KEY')
        result[key] = value
    return result


def _write_all(stream, data: bytes):
    """Write a complete bounded payload to an unbuffered pipe."""
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = stream.write(view[offset:])
        if type(written) is not int or written <= 0:
            raise BrokenPipeError('DECODER_INPUT_WRITE_INCOMPLETE')
        offset += written


def _validate_envelope(value: object, data: bytes) -> dict:
    if (type(value) is not dict or value.keys() != {'schema', 'input_sha256', 'input_bytes', 'result'}
            or value.get('schema') != RESULT_ENVELOPE
            or value.get('input_bytes') != len(data)
            or value.get('input_sha256') != hashlib.sha256(data).hexdigest()):
        raise DecoderProtocolError('DECODER_INPUT_BINDING_MISMATCH')
    return _validate_result(value['result'])


def _validate_result(value: object) -> dict:
    if type(value) is not dict or value.get('decoder') != DECODER_VERSION or type(value.get('ok')) is not bool:
        raise DecoderProtocolError('DECODER_PROTOCOL_INVALID')
    if value['ok']:
        if (value.keys() != {'ok', 'format', 'width', 'height', 'pixel_sha256',
                             'phash_algorithm', 'phash_hex', 'decoder'}
                or value['format'] not in FORMATS or type(value['width']) is not int
                or type(value['height']) is not int or not 1 <= value['width'] <= MAX_PIXELS
                or not 1 <= value['height'] <= MAX_PIXELS
                or value['width'] * value['height'] > MAX_PIXELS
                or type(value['pixel_sha256']) is not str
                or not re.fullmatch(r'[0-9a-f]{64}', value['pixel_sha256'])
                or value['phash_algorithm'] != PHASH_ALGORITHM
                or type(value['phash_hex']) is not str
                or not re.fullmatch(r'[0-9a-f]{16}', value['phash_hex'])):
            raise DecoderProtocolError('DECODER_PROTOCOL_INVALID')
        return value
    if (value.keys() - {'ok', 'reason', 'bytes', 'width', 'height', 'decoder'}
            or type(value.get('reason')) is not str or len(value['reason']) > 128):
        raise DecoderProtocolError('DECODER_PROTOCOL_INVALID')
    for key in ('bytes', 'width', 'height'):
        if key in value and (type(value[key]) is not int or value[key] < 0 or value[key] > MAX_FILE):
            raise DecoderProtocolError('DECODER_PROTOCOL_INVALID')
    return {'ok': False, 'reason': value['reason']}


if __name__ == '__main__':
    import sys
    if sys.argv[1:] != ['--container']:
        raise SystemExit(2)
    _entrypoint()
