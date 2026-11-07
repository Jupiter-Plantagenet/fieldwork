"""Review-gated activation for the fixed Fieldwork v2 intake decoder.

This helper starts only the exact new intake worker. It never stops, signals, or
reconfigures another worker. Run under the shared Fieldwork activation lock after
migration 013, private-profile backup, one-shot idle probe, and fresh DB/globals backup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
IMAGE_ID = 'sha256:f1c22ce0d7121dbc4f53d072abb1ade888872ad8b669f035c581fd29dfb4d9a9'
PROFILE = ROOT / '.local/real-data/activation-backups/decoder-v2-20261102T001157Z/intake-authority.v2.json'
PROFILE_BACKUP = ROOT / '.local/real-data/activation-backups/decoder-v2-20261102T001157Z/intake-authority.before.json'
APPLIED_013 = ROOT / '.local/real-data/activation/phash013-20261102T000306Z/applied-013.json'
PYTHON = ROOT / '.venv/Scripts/python.exe'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def under_root(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if ROOT.resolve() not in resolved.parents or not resolved.is_file():
        raise RuntimeError('EVIDENCE_PATH_INVALID')
    return resolved


def require_lock() -> None:
    sys.path.insert(0, str(ROOT.parent / 'tools'))
    import product_lock
    record = product_lock.read_owner(ROOT.parent / '.cache/product-build.lock') or {}
    ancestors = {(p.pid, p.create_time()) for p in psutil.Process().parents()}
    if ((record.get('product'), record.get('purpose')) != ('fieldwork', 'fieldwork-real-activation')
            or (record.get('pid'), record.get('create_time')) not in ancestors):
        raise RuntimeError('HOST_LOCK_REQUIRED')


def verify_013() -> dict:
    result = json.loads(APPLIED_013.read_text(encoding='utf-8'))
    if (result.get('status') != 'applied' or result.get('migration_sha256') !=
            'e595aac22ceae2df189911ea90cd6514a260a19ee6c276d9902912205d65dcf7'
            or result.get('capability_checks', {}).get('repair_capability') is not True
            or result.get('capability_checks', {}).get('feature_table') is not True
            or result.get('capability_checks', {}).get('forced_rls') is not True
            or result.get('capability_checks', {}).get('worker_select') is not True
            or result.get('capability_checks', {}).get('worker_mutate') is not False):
        raise RuntimeError('MIGRATION_013_RECEIPT_INVALID')
    return result


def verify_profile() -> dict:
    from fieldwork.newintake_worker import load_authority
    from fieldwork.scoped_authority import check_private
    check_private(PROFILE_BACKUP)
    check_private(PROFILE)
    old_bytes = PROFILE_BACKUP.read_bytes()
    new_bytes = PROFILE.read_bytes()
    if (sha(old_bytes) != '671489a30ec5b0970759a75d04c3a85254b7f863c5d127ac8231300671625421'
            or sha(new_bytes) != '9bfaa60b2335688aafb5d21b3a01ae30d89f165d20cbea17290047527719c7ed'):
        raise RuntimeError('REVIEWED_PROFILE_BYTES_CHANGED')
    old = json.loads(old_bytes)
    new = json.loads(new_bytes)
    if old.get('decoder_image_id') != 'sha256:8155ab9774815bf6b92e8a892c018b683aa4418385154cb342cc9b22fa92e77d':
        raise RuntimeError('OLD_PROFILE_IMAGE_MISMATCH')
    if new.get('decoder_image_id') != IMAGE_ID:
        raise RuntimeError('NEW_PROFILE_IMAGE_MISMATCH')
    if ({k: v for k, v in old.items() if k != 'decoder_image_id'} !=
            {k: v for k, v in new.items() if k != 'decoder_image_id'}):
        raise RuntimeError('PROFILE_SCOPE_CHANGED')
    loaded = load_authority(PROFILE)
    if loaded['decoder_image_id'] != IMAGE_ID:
        raise RuntimeError('PROFILE_LOAD_MISMATCH')
    return {'profile_sha256': sha(new_bytes), 'backup_sha256': sha(old_bytes)}


def verify_image() -> None:
    info = json.loads(subprocess.check_output(
        ['docker', 'image', 'inspect', IMAGE_ID, '--format', '{{json .}}'],
        cwd=ROOT, text=True))
    if (info.get('Id') != IMAGE_ID or info.get('Os') != 'linux' or info.get('Architecture') != 'amd64'
            or info.get('Config', {}).get('User') not in ('65532:65532', '65532')):
        raise RuntimeError('DECODER_IMAGE_MISMATCH')


def verify_fresh_backup(path: Path) -> dict:
    path = under_root(path)
    if path.stat().st_mtime <= APPLIED_013.stat().st_mtime:
        raise RuntimeError('BACKUP_NOT_AFTER_MIGRATION')
    backup = json.loads(path.read_text(encoding='utf-8'))
    if not backup.get('db') or not backup.get('globals'):
        raise RuntimeError('DATABASE_GLOBALS_BACKUP_REQUIRED')
    for part in ('db', 'globals'):
        record = backup[part]
        candidate = under_root(ROOT / record['path'])
        if sha_file(candidate) != record.get('sha256') or candidate.stat().st_size != record.get('bytes'):
            raise RuntimeError('BACKUP_DIGEST_MISMATCH')
    if backup.get('database') != 'fieldwork':
        raise RuntimeError('BACKUP_DATABASE_MISMATCH')
    return {'manifest_sha256': sha(path.read_bytes()), 'db_sha256': backup['db']['sha256'],
            'globals_sha256': backup['globals']['sha256']}


def active_queue_counts(authority: dict) -> dict[str, int]:
    import psycopg
    from psycopg.rows import dict_row
    conninfo = authority['connection']
    counts = {'queued': 0, 'running': 0}
    with psycopg.connect(host=conninfo['host'], port=conninfo['port'], dbname=conninfo['dbname'],
                         user=conninfo['user'], password=conninfo['password'], sslmode=conninfo['sslmode'],
                         row_factory=dict_row, connect_timeout=3) as conn:
        with conn.cursor() as cur:
            workspaces = cur.execute('SELECT fw_intake_cap_v1.my_workspaces() AS workspaces').fetchone()['workspaces']
            for workspace in workspaces:
                cur.execute("SELECT set_config('fieldwork.workspace',%s,true)", (workspace,))
                row = cur.execute("SELECT count(*) FILTER (WHERE state='queued') AS queued,"
                    "count(*) FILTER (WHERE state='running') AS running FROM public.fw_real_intake_queue WHERE workspace=%s",
                    (workspace,)).fetchone()
                counts['queued'] += row['queued']
                counts['running'] += row['running']
    return counts


def existing_intake_workers() -> list[int]:
    found = []
    for proc in psutil.process_iter(['pid', 'name']):
        if 'python' not in str(proc.info.get('name') or '').casefold():
            continue
        try:
            if Path(proc.cwd()).resolve() != ROOT.resolve():
                continue
            command = proc.cmdline()
            if any(command[i:i + 2] == ['-m', 'fieldwork.newintake_worker']
                   for i in range(len(command) - 1)):
                found.append(proc.info['pid'])
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            raise RuntimeError('PROCESS_SCAN_INCOMPLETE') from None
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--backup-manifest', required=True)
    ap.add_argument('--confirm-start', action='store_true', required=True)
    args = ap.parse_args()
    try:
        require_lock()
        verify_013()
        profile = verify_profile()
        verify_image()
        backup = verify_fresh_backup(Path(args.backup_manifest))
        if existing_intake_workers():
            raise RuntimeError('INTAKE_WORKER_ALREADY_RUNNING')
        from fieldwork.newintake_worker import load_authority
        authority = load_authority(PROFILE)
        before = active_queue_counts(authority)
        if before != {'queued': 0, 'running': 0}:
            raise RuntimeError('INTAKE_QUEUE_NOT_IDLE')
        once = subprocess.run([str(PYTHON), '-B', '-m', 'fieldwork.newintake_worker',
                               '--authority-file', str(PROFILE), '--once'], cwd=ROOT,
                              capture_output=True, text=True, timeout=60)
        if once.returncode != 0:
            raise RuntimeError('INTAKE_IDLE_PROBE_FAILED')
        probe = json.loads(once.stdout.strip().splitlines()[-1])
        if probe.get('result') != 'idle':
            raise RuntimeError('INTAKE_IDLE_PROBE_NOT_IDLE')
        after_probe = active_queue_counts(authority)
        if after_probe != {'queued': 0, 'running': 0}:
            raise RuntimeError('INTAKE_QUEUE_CHANGED_DURING_PROBE')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        output_dir = ROOT / '.local/real-data/activation' / ('decoder-v2-' + stamp)
        output_dir.mkdir(parents=True, exist_ok=False)
        from fieldwork.scoped_authority import check_private
        check_private(output_dir)
        receipt_path = output_dir / 'started.json'
        flags = getattr(subprocess, 'DETACHED_PROCESS', 0x00000008) | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x00000200) | getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
        process = subprocess.Popen([str(PYTHON), '-B', '-m', 'fieldwork.newintake_worker',
                                    '--authority-file', str(PROFILE)], cwd=ROOT,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL,creationflags=flags, close_fds=True)
        time.sleep(3)
        if process.poll() is not None:
            raise RuntimeError('NEW_INTAKE_WORKER_EXITED')
        pid = process.pid
        proc = psutil.Process(pid)
        identity = {'pid': pid, 'create_time': proc.create_time(),
                    'cmdline_has_module': 'fieldwork.newintake_worker' in ' '.join(proc.cmdline()),
                    'image_id': IMAGE_ID}
        if not identity['cmdline_has_module']:
            raise RuntimeError('NEW_INTAKE_WORKER_IDENTITY_MISMATCH')
        receipt = {'status': 'started', 'at_utc': datetime.now(timezone.utc).isoformat(),
                   'image_id': IMAGE_ID, 'authority_profile_sha256': profile['profile_sha256'],
                   'private_profile_backup_sha256': profile['backup_sha256'],
                   'database_globals_backup': backup, 'queue_before': before,
                   'queue_after_idle_probe': after_probe, 'idle_probe_result': 'idle',
                   'worker': identity, 'worker_error_log': '.local/app-logs/intake-worker-errors.log',
                   'worker_output': 'stdout_stderr_discarded; sanitized_error_codes_only'}
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
        check_private(receipt_path)
        print(json.dumps({'status': 'started', 'pid': pid, 'image_id': IMAGE_ID,
                          'receipt': str(receipt_path), 'secret_printed': False}))
        return 0
    except Exception as exc:
        code = getattr(exc, 'code', None) or type(exc).__name__.upper()
        print(json.dumps({'status': 'refused', 'code': str(code)[:64], 'secret_printed': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

