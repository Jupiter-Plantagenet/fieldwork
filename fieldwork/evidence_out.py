"""Immutable evidence outputs (round 5).

Every run writes a NEW timestamped file with exclusive creation and never overwrites or
deletes an existing one (evidence/live-sse.json used to be overwritten by each run):

    evidence/<stem>/<stem>-<UTC yyyymmddThhmmssZ>-<pid>-<random>.<ext>

and appends one line to evidence/<stem>/INDEX.jsonl (name, sha256, bytes, utc). The index is
append-only; readers wanting "the latest" take its last line. Files are made read-only
after writing. Legacy top-level files (e.g. evidence/live-sse.json) are left untouched as
history.
"""
import hashlib, json, os, secrets, stat
from datetime import datetime, timezone
from pathlib import Path


def write_evidence(root, name, data):
    """Write `data` (bytes, str, or JSON-serialisable) as a new immutable evidence file."""
    stem, dot, ext = name.rpartition('.') if '.' in name else (name, '', 'json')
    if isinstance(data, (dict, list)):
        data = json.dumps(data, indent=2, default=str)
    if isinstance(data, str):
        data = data.encode('utf-8')
    folder = Path(root) / 'evidence' / stem
    folder.mkdir(parents=True, exist_ok=True)
    utc = datetime.now(timezone.utc)
    path = folder / f"{stem}-{utc.strftime('%Y%m%dT%H%M%SZ')}-{os.getpid()}-{secrets.token_hex(3)}.{ext}"
    with path.open('xb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    entry = {'name': path.name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'utc': utc.isoformat()}
    with (folder / 'INDEX.jsonl').open('a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n'); f.flush(); os.fsync(f.fileno())
    return path
