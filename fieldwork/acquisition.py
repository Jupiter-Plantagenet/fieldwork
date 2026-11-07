"""Dataset acquisition: bounded archive staging, ordered inventory, LICENSE parsing.

Owned by the dataset/rights/intake lane. No network I/O here: the caller downloads
and passes the archive path plus the recorded provenance. Everything returned is a
plain JSON-able structure so it can be hashed canonically and archived as evidence.

Extraction policy `fieldwork.extract/v1` (blueprint section 4 proposed bounds):
archive <=512MiB, <=10,000 members, expanded <=1GiB total, each member <=20MiB,
regular files and directories only (symlink/hardlink/device/fifo rejected), no
absolute, drive-qualified, backslash, NUL, or '..' paths, no duplicate normalized
paths, no member escaping the destination after resolution. Every member gets
exactly one disposition with a reason.
"""
import hashlib
import os
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

POLICY = 'fieldwork.extract/v1'
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_EXPANDED = 1024 * 1024 * 1024
MAX_MEMBER = 20 * 1024 * 1024
_WINDOWS_RESERVED = re.compile(r'^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$', re.I)


class ArchiveRejected(ValueError):
    def __init__(self, code, members=None):
        self.code = code
        self.members = members or []
        super().__init__(code)


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    size = 0
    with open(path, 'rb') as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
            size += len(b)
    return h.hexdigest(), size


def _path_problem(name):
    if not name or '\x00' in name:
        return 'EMPTY_OR_NUL_PATH'
    if '\\' in name or ':' in name:
        return 'BACKSLASH_OR_DRIVE_PATH'
    if name.startswith('/'):
        return 'ABSOLUTE_PATH'
    parts = PurePosixPath(name).parts
    if any(p == '..' for p in parts):
        return 'PATH_TRAVERSAL'
    if any(_WINDOWS_RESERVED.match(p) or p.endswith(('.', ' ')) for p in parts if p != '.'):
        return 'RESERVED_PATH_COMPONENT'
    return None


def _normal(name):
    return str(PurePosixPath(*[p for p in PurePosixPath(name).parts if p != '.']))


def _check(name, kind, size, seen, root):
    problem = _path_problem(name)
    norm = None if problem else _normal(name)
    if not problem and norm in seen:
        problem = 'DUPLICATE_PATH'
    if not problem and kind == 'symlink':
        problem = 'SYMLINK_MEMBER'
    if not problem and kind == 'hardlink':
        problem = 'HARDLINK_MEMBER'
    if not problem and kind not in ('file', 'dir'):
        problem = 'SPECIAL_MEMBER'
    if not problem and kind == 'file' and size > MAX_MEMBER:
        problem = 'MEMBER_TOO_LARGE'
    if not problem:
        target = (root / norm).resolve()
        if root != target and root not in target.parents:
            problem = 'ESCAPES_DESTINATION'
    return problem, norm


def _zip_kind(info):
    mode = (info.external_attr >> 16) & 0o170000
    if mode == 0o120000:
        return 'symlink'
    if info.is_dir():
        return 'dir'
    if mode not in (0, 0o100000):
        return 'special'
    return 'file'


def _entries(archive):
    """Yield (name, kind, declared_size, opener) for tar or zip archives."""
    with open(archive, 'rb') as f:
        magic = f.read(4)
    if magic[:4] == b'PK\x03\x04' or magic[:4] == b'PK\x05\x06':
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                yield info.filename, _zip_kind(info), info.file_size, (lambda i=info, z=zf: z.open(i))
        return
    with tarfile.open(archive, 'r:*') as tf:
        for info in tf:
            yield info.name, _kind(info), info.size, (lambda i=info, t=tf: t.extractfile(i))


def stage_archive(archive, dest):
    """Stage a tar(.gz)/zip into an EMPTY dest under the policy. Returns the inventory.

    Two passes: a header pre-scan rejects whole archives (member count, declared
    expansion) before anything is written; the extraction pass enforces per-member
    rules and bounds the ACTUAL decompressed bytes (declared sizes may lie).
    ArchiveRejected carries every pre-scanned member with the archive-level reason.
    """
    archive = Path(archive)
    dest = Path(dest)
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ArchiveRejected('ARCHIVE_TOO_LARGE')
    try:
        declared = []
        total = 0
        for name, kind, size, _ in _entries(archive):
            declared.append({'ordinal': len(declared) + 1, 'name': name, 'type': kind, 'size': size})
            if len(declared) > MAX_MEMBERS:
                raise ArchiveRejected('TOO_MANY_MEMBERS', declared)
            if kind == 'file' and size <= MAX_MEMBER:
                total += size
        if total > MAX_EXPANDED:
            raise ArchiveRejected('EXPANSION_LIMIT', declared)
    except ArchiveRejected:
        raise
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, ValueError) as exc:
        raise ArchiveRejected('ARCHIVE_UNREADABLE:' + type(exc).__name__) from None
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise ArchiveRejected('DESTINATION_NOT_EMPTY')
    root = dest.resolve()
    members = []
    seen = set()
    expanded = 0
    try:
        for name, kind, size, opener in _entries(archive):
            row = {'ordinal': len(members) + 1, 'name': name, 'type': kind, 'size': size}
            members.append(row)
            problem, norm = _check(name, kind, size, seen, root)
            if problem:
                row.update(disposition='rejected', reason=problem)
                continue
            seen.add(norm)
            row['path'] = norm
            if kind == 'dir':
                (root / norm).mkdir(parents=True, exist_ok=True)
                row.update(disposition='directory', reason='DIRECTORY_ENTRY')
                continue
            target = root / norm
            target.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            written = 0
            over = False
            with opener() as src, open(target, 'xb') as out:
                while True:
                    b = src.read(1 << 20)
                    if not b:
                        break
                    written += len(b)
                    if written > MAX_MEMBER or expanded + written > MAX_EXPANDED:
                        over = True
                        break
                    h.update(b)
                    out.write(b)
            if over or written != size:
                target.unlink()
                row.update(disposition='rejected', reason='ACTUAL_SIZE_EXCEEDS_LIMIT' if over else 'SIZE_MISMATCH')
                continue
            expanded += written
            row.update(disposition='staged', reason='STAGED', sha256=h.hexdigest())
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as exc:
        raise ArchiveRejected('ARCHIVE_UNREADABLE:' + type(exc).__name__, members) from None
    return {'policy': POLICY, 'member_count': len(members), 'expanded_bytes': expanded, 'members': members}


stage_tar = stage_archive


def _kind(info):
    if info.isfile():
        return 'file'
    if info.isdir():
        return 'dir'
    if info.issym():
        return 'symlink'
    if info.islnk():
        return 'hardlink'
    return 'special'


# --- LICENSE.txt parsing --------------------------------------------------------
LICENSE_HEADER_URL = 'https://creativecommons.org/licenses/by/2.0/'
_ROW_PHOTO = re.compile(r'^(?P<member>[a-z]+/[^ ]+\.jpg) (?P<label>CC-BY) by (?P<author>.+?) - (?P<url>https://www\.flickr\.com/photos/\S+)$')
_ROW_PROFILE = re.compile(r'^(?P<member>[a-z]+/[^ ]+\.jpg) (?P<label>CC-BY) (?P<url>https://www\.flickr\.com/photos/\S+) - by (?P<author>.+)$')
_PHOTO_URL = re.compile(r'^https://www\.flickr\.com/photos/[^/]+/(?P<pid>[0-9]+)/$')


def parse_license(raw):
    """Parse tf_flowers LICENSE.txt bytes. Returns header, records and unparsed lines.

    Literal values are preserved (no author/URL repair). `source_kind` is
    `photo_page` only when the URL names a specific photo whose numeric ID equals
    the member filename's leading Flickr photo ID.
    """
    text = raw.decode('utf-8')
    lines = text.splitlines()
    header = []
    records = []
    unparsed = []
    for number, line in enumerate(lines, 1):
        if not records and not re.match(r'^[a-z]+/\S+\.jpg ', line):
            header.append(line)
            continue
        if not line.strip():
            continue
        m = _ROW_PHOTO.match(line)
        form = 'photo'
        if not m:
            m = _ROW_PROFILE.match(line)
            form = 'profile'
        if not m:
            unparsed.append({'line_number': number, 'raw': line})
            continue
        member = m['member']
        url = m['url']
        pid_member = member.split('/', 1)[1].split('_', 1)[0]
        um = _PHOTO_URL.match(url)
        kind = 'photo_page' if (form == 'photo' and um and um['pid'] == pid_member) else 'profile_or_other'
        records.append({'line_number': number, 'raw_record': line, 'member': member,
                        'class_dir': member.split('/', 1)[0], 'license_label': m['label'],
                        'author': m['author'], 'source_url': url, 'source_kind': kind,
                        'flickr_photo_id': pid_member})
    return {'header': header, 'records': records, 'unparsed': unparsed}


def attribution_line(rec):
    """TASL-style CC-BY attribution text for one asset (title is not supplied upstream)."""
    return (f'"{rec["member"]}" by {rec["author"]} ({rec["source_url"]}), licensed under '
            f'CC BY 2.0 ({LICENSE_HEADER_URL}) per the tf_flowers LICENSE.txt. '
            'Modified for training: decoded, resized and cropped; no pixels redistributed in model bundles.')
