"""Rotate the existing scoped Fieldwork worker credential without scope changes."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from psycopg import connect
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = '814830e3-55a0-4925-ad37-5d3dac7d4df8'


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'fieldwork_activation_helper', ROOT.parent / 'tools' / 'activate_real_worker.py')
    helper = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(helper)
    lock = helper.require_lock()

    pointer = ROOT / '.cache/r5-platform/worker-authority-dir.txt'
    raw_pointer = pointer.read_text(encoding='utf-8').strip()
    if not raw_pointer or '\n' in raw_pointer or '\r' in raw_pointer:
        raise ValueError('AUTHORITY_POINTER_INVALID')
    from fieldwork.scoped_authority import check_private
    candidate = Path(raw_pointer).absolute()
    if candidate.drive.lower() != 'c:':
        raise ValueError('AUTHORITY_NOT_ON_C')
    try:
        candidate.relative_to(Path(os.environ['USERPROFILE']).absolute())
    except ValueError:
        raise ValueError('AUTHORITY_OUTSIDE_USER_PROFILE') from None
    walk = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        walk /= part
        info = walk.lstat()
        if walk.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('AUTHORITY_REPARSE_POINT')
    authority_path = candidate.resolve(strict=True) / 'worker-authority.json'
    check_private(pointer)
    check_private(authority_path)

    from fieldwork.worker_identity import MAX_TTL, MODE, _rotate_file, alive, read_authority, verify
    def require_dead_heartbeat() -> None:
        beat_path = ROOT / 'var/worker.json'
        if not beat_path.is_file():
            raise ValueError('WORKER_HEARTBEAT_MISSING')
        try:
            beat = json.loads(beat_path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            raise ValueError('WORKER_HEARTBEAT_INVALID') from None
        if (beat.get('identity') != MODE or type(beat.get('pid')) is not int
                or type(beat.get('create_time')) not in (int, float)):
            raise ValueError('WORKER_HEARTBEAT_IDENTITY_INVALID')
        if alive(beat['pid'], beat['create_time']):
            raise ValueError('WORKER_HEARTBEAT_LIVE_ROTATION_REFUSED')

    require_dead_heartbeat()
    original_bytes = authority_path.read_bytes()
    original = read_authority(authority_path)
    scopes = original.get('workspaces')
    if not isinstance(scopes, list) or WORKSPACE not in scopes:
        raise ValueError('TARGET_WORKSPACE_SCOPE_REQUIRED')

    with connect(helper.private_operator_dsn(), row_factory=dict_row) as conn:
        before_scope = verify(conn, original['connection']['user'], scopes)
    if not before_scope.get('verified'):
        raise ValueError('EXISTING_SCOPE_VERIFY_FAILED')

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_dir = ROOT / '.local/real-data/activation-backups' / ('worker-credential-rotation-' + stamp)
    backup_dir.mkdir(parents=True, exist_ok=False)
    check_private(backup_dir)
    backup_path = backup_dir / 'worker-authority.before.json'
    fd = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(original_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    if sha(backup_path.read_bytes()) != sha(original_bytes):
        raise ValueError('AUTHORITY_BACKUP_DIGEST_MISMATCH')

    _rotate_file(ROOT / '.local.json', authority_path, MAX_TTL)
    updated_bytes = authority_path.read_bytes()
    updated = read_authority(authority_path)
    if (updated.get('workspaces') != scopes
            or updated['connection'].get('user') != original['connection'].get('user')
            or any(updated['connection'].get(k) != original['connection'].get(k)
                   for k in ('host', 'port', 'dbname', 'sslmode'))
            or updated.get('previous_password') != original['connection'].get('password')
            or updated['connection'].get('password') == original['connection'].get('password')):
        raise ValueError('CREDENTIAL_ROTATION_SCOPE_OR_IDENTITY_CHANGED')
    with connect(**updated['connection'], connect_timeout=3) as conn:
        conn.execute('SELECT 1').fetchone()
    with connect(helper.private_operator_dsn(), row_factory=dict_row) as conn:
        after_scope = verify(conn, updated['connection']['user'], scopes)
    if not after_scope.get('verified'):
        raise ValueError('ROTATED_SCOPE_VERIFY_FAILED')
    require_dead_heartbeat()
    if sha(backup_path.read_bytes()) != sha(original_bytes):
        raise ValueError('AUTHORITY_BACKUP_CHANGED')

    receipt = {'schema': 'fieldwork.scoped-worker-credential-rotation/v1',
        'status': 'PASS', 'at_utc': datetime.now(timezone.utc).isoformat(),
        'lock': lock, 'existing_principal_reused': True, 'scope_unchanged': True,
        'workspace_scope_count': len(scopes), 'target_workspace_present': True,
        'database_credential_probe': True, 'scope_verify_before': True,
        'scope_verify_after': True, 'worker_heartbeat_was_dead': True,
        'backup_path': str(backup_path.relative_to(ROOT)),
        'backup_sha256': sha(original_bytes), 'updated_authority_sha256': sha(updated_bytes),
        'secret_printed': False, 'role_or_scope_reset': False}
    evidence = ROOT / '.local/real-data/workflow-20261102'
    check_private(evidence)
    path = evidence / ('credential-rotation-' + stamp + '.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'status': 'PASS', 'receipt': str(path.relative_to(ROOT)),
        'backup': str(backup_path.relative_to(ROOT)), 'scope_count': len(scopes),
        'credential_probe': True, 'scope_unchanged': True, 'secret_printed': False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        code = str(exc).splitlines()[0]
        if not re.fullmatch(r'[A-Z0-9_]{1,120}', code):
            code = type(exc).__name__.upper()
        print(json.dumps({'status': 'failed', 'code': code, 'secret_printed': False}))
        raise SystemExit(1)
