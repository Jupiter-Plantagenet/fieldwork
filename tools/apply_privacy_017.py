"""Back up and apply the reviewed privacy lifecycle migration 017.

This is an operator-only preparation helper. It does not run unless invoked
with --apply-live, a passing scratch rehearsal, a matching independent review,
and the existing Fieldwork retained-migration lock. It writes append-only local
prepared/applied records because this database has no SQL migration journal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
MIGRATION = ROOT / 'migrations/017_privacy_lifecycle.sql'
MIGRATION_SHA256 = '81E7587F33A5A30FA9A8C48369703A5C2266D3AD52926C28AB9B14974EB116EE'
SCRATCH_REPORT = ROOT / '.local/privacy-test-runs/scratch-017-882bce6fe075421e863b9a586e4f158b.json'
SCRATCH_REPORT_SHA256 = '47D64EED3835CF66AA71602E15C08152A5D0E1506222D6B034AA077B5AEF6814'
REHEARSAL_HELPER = ROOT / 'tools/rehearse_privacy_017.py'
REHEARSAL_HELPER_SHA256 = '49811B57A23ED52AE7E936CA0461D3B36A7FF17A5E88BE57B195F228F6846161'
CANCEL_TEST = ROOT / 'tests/test_privacy_delete_cancel_postgres.py'
CANCEL_TEST_SHA256 = '79238E2D89F43A8180D98136912DA623CB44769C5B60504545EB286E0CD1ABB5'
SOURCE_TEST = ROOT / 'tests/test_privacy_lifecycle_source.py'
SOURCE_TEST_SHA256 = 'E28A8798434635AAE33417B4BAD7718A505812D3F7E076E47CF9372DFD754BCA'
BUSINESS_TABLES = (
    'fw_accounts', 'fw_workspace_settings', 'fw_workspace_settings_events',
    'fw_sessions', 'fw_samples', 'fw_versions', 'fw_proposals', 'fw_runs',
    'fw_events', 'fw_attempts', 'fw_checkpoints',
)
ACTIVE_RUN_STATES = ('leased', 'running', 'cancel_requested')
_APPLY_STAGE = 'startup'


def _set_stage(value: str) -> None:
    global _APPLY_STAGE
    _APPLY_STAGE = value


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest().upper()


def _helpers():
    from fieldwork.privacy_lifecycle import _check_c_ancestry
    from fieldwork.scoped_authority import check_private
    return _check_c_ancestry, check_private


def _read_private(path: Path, *, max_bytes: int = 8 * 1024**2) -> bytes:
    check_c, check_private = _helpers()
    safe = check_c(path)
    check_private(safe)
    info = safe.lstat()
    if not safe.is_file() or info.st_size > max_bytes:
        raise ValueError('PRIVATE_INPUT_INVALID')
    raw = safe.read_bytes()
    if len(raw) != info.st_size:
        raise ValueError('PRIVATE_INPUT_CHANGED')
    return raw


def _hash_private_file(path: Path, *, max_bytes: int) -> tuple[str, int]:
    check_c, check_private = _helpers()
    safe = check_c(path)
    check_private(safe)
    before = safe.lstat()
    if not safe.is_file() or before.st_size > max_bytes:
        raise ValueError('PRIVATE_ARTIFACT_INVALID')
    fd = os.open(safe, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError('PRIVATE_ARTIFACT_CHANGED')
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise ValueError('PRIVATE_ARTIFACT_TOO_LARGE')
            digest.update(block)
    finally:
        os.close(fd)
    if safe.stat().st_size != total:
        raise ValueError('PRIVATE_ARTIFACT_CHANGED')
    return digest.hexdigest().upper(), total


def _write_new_private(path: Path, raw: bytes) -> None:
    check_c, check_private = _helpers()
    check_c(path, allow_missing_leaf=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    check_c(path)
    check_private(path)


def _write_private_exception_log() -> str | None:
    """Persist full operator diagnostics privately; public output stays fixed."""
    captured = traceback.format_exc()
    if not captured or captured.strip() == 'NoneType: None':
        return None
    try:
        from fieldwork.privacy_lifecycle import _ensure_private_directory
        directory = ROOT / '.local/privacy-test-runs/privacy017-applier-errors'
        _ensure_private_directory(directory)
        path = directory / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                            + '-' + uuid.uuid4().hex + '.raw.log')
        payload = ('stage=' + _APPLY_STAGE + '\n' + captured).encode('utf-8', errors='replace')
        _write_new_private(path, payload)
        return str(path.relative_to(ROOT)).replace('\\','/')
    except Exception:
        return None


def _source_pins() -> dict[str, dict]:
    check_c, _ = _helpers()
    out = {}
    for path in sorted((ROOT / 'migrations').glob('[0-9][0-9][0-9]_*.sql')):
        check_c(path)
        number = int(path.name[:3])
        if not 3 <= number <= 16:
            continue
        raw = path.read_bytes()
        info = path.stat()
        out[path.name] = {'sha256': sha(raw), 'bytes': len(raw), 'mtime_ns': info.st_mtime_ns}
    return out


def _validate_review_and_rehearsal(review_path: Path) -> tuple[dict, bytes, bytes]:
    migration_bytes = MIGRATION.read_bytes()
    if sha(migration_bytes) != MIGRATION_SHA256:
        raise ValueError('MIGRATION_SOURCE_PIN_MISMATCH')
    expected_sources = {
        'migrations/017_privacy_lifecycle.sql': MIGRATION_SHA256,
        'tools/rehearse_privacy_017.py': REHEARSAL_HELPER_SHA256,
        'tests/test_privacy_delete_cancel_postgres.py': CANCEL_TEST_SHA256,
        'tests/test_privacy_lifecycle_source.py': SOURCE_TEST_SHA256,
        'tools/apply_privacy_017.py': sha(Path(__file__).read_bytes()),
    }
    actual_sources = {
        'migrations/017_privacy_lifecycle.sql': sha(migration_bytes),
        'tools/rehearse_privacy_017.py': sha(REHEARSAL_HELPER.read_bytes()),
        'tests/test_privacy_delete_cancel_postgres.py': sha(CANCEL_TEST.read_bytes()),
        'tests/test_privacy_lifecycle_source.py': sha(SOURCE_TEST.read_bytes()),
        'tools/apply_privacy_017.py': sha(Path(__file__).read_bytes()),
    }
    if actual_sources != expected_sources:
        raise ValueError('REVIEWED_SOURCE_SET_CHANGED')
    review_raw = _read_private(review_path, max_bytes=256 * 1024)
    review = json.loads(review_raw)
    if (review.get('schema') != 'fieldwork.privacy-017-independent-review/v1'
            or review.get('status') != 'PASS'
            or review.get('source_sha256') != expected_sources
            or review.get('scratch_report_sha256') != SCRATCH_REPORT_SHA256):
        raise ValueError('INDEPENDENT_017_REVIEW_REQUIRED')
    scratch_raw = _read_private(SCRATCH_REPORT, max_bytes=4 * 1024**2)
    scratch = json.loads(scratch_raw)
    required_true = (
        'business_row_counts_unchanged',
        'migration_journal_rows_hashes_timestamps_unchanged',
        'checkpoint_pointers_unchanged',
        'frozen_manifest_sql_digests_unchanged',
        'migration_sources_003_016_bytes_checksums_timestamps_unchanged',
        'synthetic_probe_row_counts_restored',
        'synthetic_probe_migration_journal_unchanged',
        'synthetic_probe_checkpoint_pointers_unchanged',
        'synthetic_probe_frozen_manifest_digests_unchanged',
        'scratch_container_absent_verified',
        'scratch_network_absent_verified',
        'retained_applier_postconditions_passed',
        'active_run_quiescence_refused',
        'queued_run_survivors_unchanged',
        'quiescence_lock_wait_observed',
        'active_claim_committed_before_check',
        'committed_active_run_refused',
        'queued_run_survivors_unchanged_after_concurrency',
        'native_sha256_matches_legacy_digest_semantics',
        'pgcrypto_extension_absent',
    )
    if (scratch.get('schema') != 'fieldwork.privacy-017-scratch-rehearsal/v1'
            or scratch.get('status') != 'passed'
            or scratch.get('migration_sha256') != MIGRATION_SHA256
            or scratch.get('migration_applied_to_retained_database') is not False
            or scratch.get('retained_database_connected') is not False
            or scratch.get('focused_test_exit_code') != 0
            or not all(scratch.get(key) is True for key in required_true)
            or sha(scratch_raw) != SCRATCH_REPORT_SHA256):
        raise ValueError('PASSING_017_SCRATCH_REHEARSAL_REQUIRED')
    return review, review_raw, scratch_raw


def _require_lock() -> dict:
    import psutil
    sys.path.insert(0, str(REPO / 'tools'))
    import product_lock
    lock_path = REPO / '.cache/product-build.lock'
    owner = product_lock.read_owner(lock_path) or {}
    ancestors = {(p.pid, p.create_time()) for p in psutil.Process().parents()}
    if ((owner.get('product'), owner.get('purpose')) !=
            ('fieldwork', 'w3-retained-real-data-migration')
            or (owner.get('pid'), owner.get('create_time')) not in ancestors):
        raise ValueError('FIELDWORK_RETAINED_MIGRATION_LOCK_REQUIRED')
    return {'pid': owner['pid'], 'purpose': owner['purpose']}


def _operator_dsn() -> str:
    path = ROOT / '.local.json'
    cfg = json.loads(_read_private(path, max_bytes=64 * 1024))
    dsn = cfg.get('dsn') if isinstance(cfg, dict) else None
    if not isinstance(dsn, str):
        raise ValueError('OPERATOR_DSN_INVALID')
    params = conninfo_to_dict(dsn)
    host = params.get('host')
    hostaddr = params.get('hostaddr')
    forbidden = {'service', 'servicefile'}
    if (host not in ('127.0.0.1', '::1')
            or (hostaddr is not None and hostaddr != host)
            or forbidden.intersection(params)
            or params.get('port') != '5542'
            or params.get('dbname') != 'fieldwork'
            or params.get('user') != 'fieldwork'):
        raise ValueError('RETAINED_DATABASE_IDENTITY_REFUSED')
    return dsn


def _named_cluster_identity() -> dict:
    """Read the exact retained PostgreSQL container identity without secrets."""
    result = subprocess.run([
        'docker', 'exec', 'fieldwork-postgres', 'psql', '-U', 'fieldwork',
        '-d', 'fieldwork', '-X', '-A', '-t', '-F', '|', '-v', 'ON_ERROR_STOP=1',
        '-c', "SELECT system_identifier::text,(SELECT oid::text FROM pg_database WHERE datname=current_database()) FROM pg_control_system()",
    ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    if result.returncode:
        raise ValueError('NAMED_POSTGRES_CLUSTER_IDENTITY_UNAVAILABLE')
    lines = result.stdout.decode('ascii', errors='strict').strip().splitlines()
    if len(lines) != 1 or not re.fullmatch(r'[0-9]+\|[0-9]+', lines[0]):
        raise ValueError('NAMED_POSTGRES_CLUSTER_IDENTITY_INVALID')
    system_id, database_oid = lines[0].split('|')
    return {'container': 'fieldwork-postgres', 'system_identifier': system_id,
        'database_oid': database_oid, 'database': 'fieldwork'}


def _connected_cluster_identity(conn) -> dict:
    row = conn.execute("""
        SELECT system_identifier::text AS system_identifier,
          (SELECT oid::text FROM pg_database WHERE datname=current_database()) AS database_oid,
          current_database() AS database
        FROM pg_control_system()
    """).fetchone()
    if not row or not row['system_identifier'] or not row['database_oid']:
        raise ValueError('CONNECTED_POSTGRES_CLUSTER_IDENTITY_UNAVAILABLE')
    return {'system_identifier': row['system_identifier'],
        'database_oid': row['database_oid'], 'database': row['database']}


def _backup_before_apply(stamp: str) -> dict:
    label = 'privacy-017-preapply-' + stamp
    result = subprocess.run([sys.executable, '-B', '-m', 'tools.r5p_backup', label],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900, check=False)
    if result.returncode:
        raise ValueError('FRESH_PRIVACY_BACKUP_FAILED')
    manifests = sorted((ROOT / 'var/snapshots').glob(label + '-*.json'))
    if len(manifests) != 1:
        raise ValueError('FRESH_PRIVACY_BACKUP_MANIFEST_MISSING')
    manifest_path = manifests[0]
    raw = _read_private(manifest_path, max_bytes=2 * 1024**2)
    manifest = json.loads(raw)
    backup_time = datetime.strptime(manifest.get('at',''), '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    if abs((datetime.now(timezone.utc)-backup_time).total_seconds()) > 600:
        raise ValueError('FRESH_PRIVACY_BACKUP_STALE')
    if (manifest.get('database') != 'fieldwork'
            or manifest.get('container') != 'fieldwork-postgres'
            or not manifest.get('at')):
        raise ValueError('FRESH_PRIVACY_BACKUP_IDENTITY_INVALID')
    for kind in ('db', 'globals'):
        item = manifest.get(kind)
        if not isinstance(item, dict):
            raise ValueError('FRESH_PRIVACY_BACKUP_ARTIFACT_MISSING')
        path = ROOT / item.get('path', '')
        artifact_hash, artifact_bytes = _hash_private_file(path, max_bytes=2 * 1024**3)
        if (artifact_bytes != item.get('bytes') or artifact_hash != item.get('sha256', '').upper()):
            raise ValueError('FRESH_PRIVACY_BACKUP_DIGEST_MISMATCH')
    ledger = manifest.get('privacy_deletion_ledger')
    if not isinstance(ledger, dict) or ledger.get('file_count') is None:
        raise ValueError('PRIVACY_DELETION_LEDGER_BACKUP_REQUIRED')
    ledger_dir = ROOT / ledger.get('path', '')
    ledger_manifest_raw = _read_private(ledger_dir / 'manifest.json', max_bytes=16 * 1024**2)
    ledger_manifest = json.loads(ledger_manifest_raw)
    body = {'schema': ledger_manifest.get('schema'), 'files': ledger_manifest.get('files')}
    canonical = json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')
    canonical_manifest = json.dumps(ledger_manifest, sort_keys=True,
        separators=(',', ':')).encode('utf-8')
    if (body['schema'] != 'fieldwork.privacy-deletion-backup/v1'
            or hashlib.sha256(canonical).hexdigest() != ledger_manifest.get('sha256')
            or sha(canonical_manifest) != ledger.get('manifest_sha256', '').upper()):
        raise ValueError('PRIVACY_DELETION_LEDGER_BACKUP_INVALID')
    entries = ledger_manifest.get('files')
    if not isinstance(entries, list) or len(entries) != ledger.get('file_count') or len(entries) > 100_000:
        raise ValueError('PRIVACY_DELETION_LEDGER_INVENTORY_INVALID')
    for item in entries:
        name = item.get('name') if isinstance(item, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r'[0-9a-f]{64}\.json', name):
            raise ValueError('PRIVACY_DELETION_LEDGER_ENTRY_INVALID')
        digest, byte_count = _hash_private_file(ledger_dir / name, max_bytes=4096)
        if byte_count != item.get('bytes') or digest != str(item.get('sha256','')).upper():
            raise ValueError('PRIVACY_DELETION_LEDGER_ENTRY_INVALID')
    return {'manifest_path': manifest_path, 'manifest': manifest, 'manifest_sha256': sha(raw)}


def _copy_checkpoint_blob(source: Path, target: Path, expected_digest: str,
                          *, max_bytes: int = 4 * 1024**3) -> dict:
    check_c, check_private = _helpers()
    source = check_c(source)
    source_info = source.lstat()
    if (not source.is_dir() or source.is_symlink()
            or getattr(source_info, 'st_file_attributes', 0) & 0x400):
        raise ValueError('REACHABLE_CHECKPOINT_TYPE_INVALID')
    check_private(source)
    check_c(target, allow_missing_leaf=True)
    if target.exists():
        raise ValueError('REACHABLE_CHECKPOINT_BACKUP_COLLISION')
    target.mkdir(parents=True, exist_ok=False)
    check_c(target)
    check_private(target)
    total_bytes = 0
    files = {}
    for name in ('manifest.json', 'state.json', 'state.safetensors'):
        src = check_c(source / name)
        info = src.lstat()
        if (not src.is_file() or src.is_symlink()
                or getattr(info, 'st_file_attributes', 0) & 0x400):
            raise ValueError('REACHABLE_CHECKPOINT_FILE_INVALID')
        check_private(src)
        if total_bytes + info.st_size > max_bytes:
            raise ValueError('REACHABLE_CHECKPOINT_BACKUP_LIMIT')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        check_c(src)
        check_private(src)
        fd = os.open(src, flags)
        out_path = target / name
        out_fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        digest = hashlib.sha256()
        copied = 0
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
                raise ValueError('REACHABLE_CHECKPOINT_CHANGED')
            with os.fdopen(out_fd, 'wb') as out:
                while True:
                    block = os.read(fd, 1024 * 1024)
                    if not block:
                        break
                    copied += len(block)
                    total_bytes += len(block)
                    if total_bytes > max_bytes:
                        raise ValueError('REACHABLE_CHECKPOINT_BACKUP_LIMIT')
                    digest.update(block)
                    out.write(block)
                out.flush()
                os.fsync(out.fileno())
        finally:
            os.close(fd)
        if copied != info.st_size:
            raise ValueError('REACHABLE_CHECKPOINT_CHANGED')
        files[name] = {'bytes': copied, 'sha256': digest.hexdigest().upper()}
        check_c(out_path)
        check_private(out_path)
    from fieldwork.ml import validate_checkpoint
    # Re-check the directory and every fixed leaf immediately before the
    # validator opens them; directory ACL alone does not protect child ACLs.
    check_c(target)
    check_private(target)
    for name in ('manifest.json', 'state.json', 'state.safetensors'):
        leaf = check_c(target / name)
        check_private(leaf)
    validate_checkpoint(target, expected_digest)
    check_c(target)
    check_private(target)
    return {'digest': expected_digest, 'relative_path': str(target.relative_to(ROOT)).replace('\\','/'),
        'bytes': total_bytes, 'files': files, 'validated_readback': True}


def _backup_reachable_checkpoints(conn, manifest_path: Path, stamp: str) -> list[dict]:
    rows = conn.execute('SELECT run,epoch,digest,path FROM public.fw_checkpoints ORDER BY run,epoch').fetchall()
    if len(rows) > 10_000:
        raise ValueError('REACHABLE_CHECKPOINT_COUNT_LIMIT')
    blob_root = manifest_path.with_suffix('')
    blob_root = Path(str(blob_root) + '-checkpoint-blobs')
    check_c, check_private = _helpers()
    check_c(blob_root, allow_missing_leaf=True)
    blob_root.mkdir(parents=True, exist_ok=False)
    check_c(blob_root)
    check_private(blob_root)
    out = []
    total = 0
    copied = {}
    for row in rows:
        if total >= 4 * 1024**3:
            raise ValueError('REACHABLE_CHECKPOINT_TOTAL_LIMIT')
        digest = row['digest']
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('REACHABLE_CHECKPOINT_DIGEST_INVALID')
        if digest in copied:
            check_c, check_private = _helpers()
            source = check_c(Path(row['path']))
            check_private(source)
            for name in ('manifest.json', 'state.json', 'state.safetensors'):
                leaf = check_c(source / name)
                check_private(leaf)
            from fieldwork.ml import validate_checkpoint
            validate_checkpoint(source, digest)
            result = copied[digest]
        else:
            result = _copy_checkpoint_blob(Path(row['path']), blob_root / digest, digest,
                max_bytes=max(1,4 * 1024**3-total))
            copied[digest] = result
            total += result['bytes']
        if total > 4 * 1024**3:
            raise ValueError('REACHABLE_CHECKPOINT_TOTAL_LIMIT')
        out.append({'run': row['run'], 'epoch': row['epoch'], **result})
    inventory = {'schema': 'fieldwork.privacy-017-reachable-checkpoint-backup/v1',
        'at_utc': datetime.now(timezone.utc).isoformat(),
        'source_backup_manifest': str(manifest_path.relative_to(ROOT)).replace('\\','/'),
        'source_backup_manifest_sha256': sha(_read_private(manifest_path)),
        'checkpoint_count': len(out), 'checkpoint_bytes': total, 'checkpoints': out}
    inventory_path = Path(str(blob_root) + '.json')
    _write_new_private(inventory_path, (json.dumps(inventory, sort_keys=True, indent=2)+'\n').encode())
    return [{'inventory_path': str(inventory_path.relative_to(ROOT)).replace('\\','/'),
        'inventory_sha256': sha(inventory_path.read_bytes()), 'checkpoint_count': len(out),
        'checkpoint_bytes': total, 'blob_directory': str(blob_root.relative_to(ROOT)).replace('\\','/')}]


def _inventory(conn) -> dict:
    if not conn.execute("SELECT to_regprocedure('pg_catalog.sha256(bytea)') IS NOT NULL AS ready").fetchone()['ready']:
        raise ValueError('SQL_SHA256_CAPABILITY_REQUIRED')
    present = {row['relname'] for row in conn.execute("""
        SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p')
    """).fetchall()}
    counts = {}
    for table in BUSINESS_TABLES:
        if table in present:
            counts[table] = conn.execute(sql.SQL('SELECT count(*) AS n FROM public.{}').format(
                sql.Identifier(table))).fetchone()['n']
    journals = {}
    for row in conn.execute("""
        SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p')
          AND c.relname ~* '(migration|schema_history|schema_version)' ORDER BY c.relname
    """).fetchall():
        name = row['relname']
        result = conn.execute(sql.SQL("""
            SELECT count(*) AS rows,encode(pg_catalog.sha256(convert_to(coalesce(
              string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),''),'UTF8')),'hex') AS sha256
            FROM public.{} AS t
        """).format(sql.Identifier(name))).fetchone()
        journals[name] = {'rows': result['rows'], 'sha256': result['sha256'].upper()}
    versions = conn.execute("""
        SELECT count(*) AS rows,encode(pg_catalog.sha256(convert_to(coalesce(string_agg(
          workspace||E'\\t'||id||E'\\t'||encode(pg_catalog.sha256(convert_to(manifest::text,'UTF8')),'hex'),
          E'\\n' ORDER BY workspace,id),''),'UTF8')),'hex') AS sha256
        FROM public.fw_versions WHERE state='frozen'
    """).fetchone()
    checkpoints = conn.execute("""
        SELECT count(*) AS rows,encode(pg_catalog.sha256(convert_to(coalesce(string_agg(
          concat_ws(E'\\t',run::text,epoch::text,digest,path),E'\\n' ORDER BY run,epoch),''),
          'UTF8')),'hex') AS sha256 FROM public.fw_checkpoints
    """).fetchone()
    return {'business_row_counts': counts, 'migration_journals': journals,
        'frozen_manifest_sql_digest': {'rows': versions['rows'], 'sha256': versions['sha256'].upper()},
        'checkpoint_pointer_digest': {'rows': checkpoints['rows'], 'sha256': checkpoints['sha256'].upper()}}


def _queued_run_inventory(conn) -> dict:
    row = conn.execute("""
        SELECT count(*) AS rows,
          encode(pg_catalog.sha256(convert_to(coalesce(string_agg(to_jsonb(t)::text,
            E'\\n' ORDER BY to_jsonb(t)::text),''),'UTF8')),'hex') AS sha256
        FROM public.fw_runs AS t WHERE state='queued'
    """).fetchone()
    return {'rows': row['rows'], 'sha256': row['sha256'].upper()}


def _acquire_migration_quiescence(conn) -> dict:
    """Fence claims and writes, then require no genuinely active run."""
    _lock_migration_runs(conn)
    active = conn.execute("""
        SELECT count(*) AS n FROM public.fw_runs WHERE state=ANY(%s)
    """, (list(ACTIVE_RUN_STATES),)).fetchone()['n']
    if active:
        raise ValueError('LIVE_RUNS_NOT_QUIESCENT')
    return _queued_run_inventory(conn)


def _lock_migration_runs(conn) -> None:
    """Take the claim/write fence before this transaction establishes a snapshot."""
    conn.execute('LOCK TABLE public.fw_runs IN SHARE ROW EXCLUSIVE MODE')


def _api_acl_state(conn) -> dict:
    return conn.execute("""
        SELECT c.relacl::text AS table_acl,
          (SELECT coalesce(jsonb_agg(jsonb_build_array(a.attnum,a.attname,a.attacl::text) ORDER BY a.attnum),'[]'::jsonb)
             FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS column_acls
        FROM pg_catalog.pg_class c WHERE c.oid='public.fw_runs'::regclass
    """).fetchone()


def _installed_state(conn) -> dict:
    return conn.execute("""
        SELECT to_regclass('public.fw_privacy_objects') IS NOT NULL AS objects,
          to_regclass('public.fw_privacy_workspace_tombstones') IS NOT NULL AS tombstones,
          to_regprocedure('public.fw_privacy_cancel_deleted_run_v1(text,text)') IS NOT NULL AS cancel_fn,
          EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='public.fw_samples'::regclass
            AND attname='privacy_protected' AND NOT attisdropped) AS protection_bit
    """).fetchone()


def _postconditions(conn, before_acl: dict) -> dict:
    state = _installed_state(conn)
    expected_state = {'objects': True, 'tombstones': True, 'cancel_fn': True, 'protection_bit': True}
    if dict(state) != expected_state:
        raise ValueError('PRIVACY_017_SCHEMA_MARKERS_MISSING')
    rels = conn.execute("""
        SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity
        FROM pg_catalog.pg_class c WHERE c.oid IN ('public.fw_runs'::regclass,'public.fw_events'::regclass)
    """).fetchall()
    if len(rels) != 2 or not all(row['relrowsecurity'] and row['relforcerowsecurity'] for row in rels):
        raise ValueError('PRIVACY_017_FORCED_RLS_MISSING')
    privacy_rls = conn.execute("""
        SELECT count(*) AS n FROM pg_catalog.pg_class c
        WHERE c.oid IN ('public.fw_privacy_objects'::regclass,
                        'public.fw_privacy_workspace_tombstones'::regclass)
          AND c.relrowsecurity
    """).fetchone()['n']
    if privacy_rls != 2:
        raise ValueError('PRIVACY_017_LEDGER_RLS_MISSING')
    policies = conn.execute("""
        SELECT count(*) AS n FROM pg_catalog.pg_policies
        WHERE schemaname='public' AND tablename IN ('fw_runs','fw_events')
          AND policyname IN ('fw_privacy_tombstone_fw_runs','fw_privacy_tombstone_fw_events')
          AND permissive='RESTRICTIVE' AND cmd='ALL' AND roles @> ARRAY['fieldwork_api']::name[]
    """).fetchone()['n']
    if policies != 2:
        raise ValueError('PRIVACY_017_RESTRICTIVE_POLICY_MISSING')
    cancel_grant = conn.execute("""
        SELECT has_function_privilege('fieldwork_api',
          'public.fw_privacy_cancel_deleted_run_v1(text,text)','EXECUTE') AS allowed
    """).fetchone()['allowed']
    if not cancel_grant:
        raise ValueError('PRIVACY_017_CANCEL_CAPABILITY_GRANT_MISSING')
    tombstone_update = conn.execute("""
        SELECT has_table_privilege('fieldwork_api','public.fw_privacy_workspace_tombstones','UPDATE') AS allowed
    """).fetchone()['allowed']
    if tombstone_update:
        raise ValueError('PRIVACY_017_TOMBSTONE_MUTATION_GRANT_WIDENED')
    acl_after = _api_acl_state(conn)
    if dict(acl_after) != dict(before_acl):
        raise ValueError('PRIVACY_017_RUN_ACL_CHANGED')
    protection = conn.execute("""
        SELECT is_nullable,column_default FROM information_schema.columns
        WHERE table_schema='public' AND table_name='fw_samples' AND column_name='privacy_protected'
    """).fetchone()
    if not protection or protection['is_nullable'] != 'NO' or protection['column_default'] not in ('false','false::boolean'):
        raise ValueError('PRIVACY_017_PROTECTION_COLUMN_INVALID')
    return {'schema_markers': dict(state), 'forced_rls_relations': len(rels),
        'privacy_ledger_rls_relations': privacy_rls,
        'restrictive_tombstone_policies': policies, 'api_cancel_capability': True,
        'api_tombstone_update_denied': True,
        'fw_runs_acl_unchanged': True, 'monotonic_sample_protection': True}


def _migration_body(raw: bytes) -> str:
    lines = raw.decode('utf-8').splitlines(keepends=True)
    significant = [i for i, line in enumerate(lines) if line.strip() and not line.lstrip().startswith('--')]
    if len(significant) < 3 or lines[significant[0]].strip().upper() != 'BEGIN;' or lines[significant[-1]].strip().upper() != 'COMMIT;':
        raise ValueError('MIGRATION_TRANSACTION_ENVELOPE_INVALID')
    if any(line.strip() and not line.lstrip().startswith('--') for line in lines[:significant[0]]):
        raise ValueError('MIGRATION_PREFIX_INVALID')
    first,last=significant[0],significant[-1]
    return ''.join(lines[:first]+lines[first+1:last]+lines[last+1:])


def _apply(review_path: Path, out_dir: Path) -> dict:
    _set_stage('lock-review-and-source-pins')
    lock = _require_lock()
    review, review_raw, scratch_raw = _validate_review_and_rehearsal(review_path)
    migration_raw = MIGRATION.read_bytes()
    migration_hash = sha(migration_raw)
    old_pins = _source_pins()
    if migration_hash != MIGRATION_SHA256:
        raise ValueError('MIGRATION_SOURCE_PIN_MISMATCH')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    _set_stage('fresh-backup-and-cluster-identity')
    backup_cluster_identity = _named_cluster_identity()
    backup = _backup_before_apply(stamp)
    backup_manifest = backup['manifest']
    backup_manifest_path = backup['manifest_path']
    if _named_cluster_identity() != backup_cluster_identity:
        raise ValueError('BACKED_UP_POSTGRES_CLUSTER_CHANGED')

    check_c, check_private = _helpers()
    _set_stage('private-source-backup')
    source_backup = ROOT / '.local/real-data/activation-backups' / ('privacy-017-' + stamp)
    check_c(source_backup, allow_missing_leaf=True)
    source_backup.mkdir(parents=True, exist_ok=False)
    check_private(source_backup)
    source_artifacts = {
        '017_privacy_lifecycle.sql': (MIGRATION, migration_hash),
        'rehearse_privacy_017.py': (REHEARSAL_HELPER, REHEARSAL_HELPER_SHA256),
        'test_privacy_delete_cancel_postgres.py': (CANCEL_TEST, CANCEL_TEST_SHA256),
        'test_privacy_lifecycle_source.py': (SOURCE_TEST, SOURCE_TEST_SHA256),
        'apply_privacy_017.py': (Path(__file__), sha(Path(__file__).read_bytes())),
    }
    for name, (source, expected) in source_artifacts.items():
        target = source_backup / name
        raw = source.read_bytes()
        if sha(raw) != expected:
            raise ValueError('ACTIVATION_SOURCE_PIN_MISMATCH')
        _write_new_private(target, raw)
        if sha(target.read_bytes()) != expected:
            raise ValueError('ACTIVATION_SOURCE_BACKUP_MISMATCH')

    out_dir.mkdir(parents=True, exist_ok=True)
    check_c(out_dir)
    check_private(out_dir)
    _set_stage('operator-dsn-and-receipt-preflight')
    dsn = _operator_dsn()
    expected_cluster = backup_cluster_identity
    if expected_cluster.get('database') != backup_manifest.get('database'):
        raise ValueError('BACKED_UP_POSTGRES_CLUSTER_IDENTITY_MISMATCH')
    prepared = None
    prepared_path = out_dir / ('privacy-017-' + stamp + '-prepared.json')
    validated_path = out_dir / ('privacy-017-' + stamp + '-validated.json')
    capability = None
    reconcile = None
    _set_stage('migration-transaction-and-preservation-checks')
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        with conn.transaction():
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            conn.execute("SET LOCAL lock_timeout='5s'")
            conn.execute("SET LOCAL statement_timeout='180s'")
            # This must precede every SELECT in this REPEATABLE READ
            # transaction. A claim already in flight commits before the lock
            # is granted, so the first snapshot includes its new state.
            _lock_migration_runs(conn)
            conn.execute("SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended('fieldwork:privacy-migration-017',0))")
            actual_cluster = _connected_cluster_identity(conn)
            if actual_cluster != {key: expected_cluster[key] for key in
                    ('system_identifier', 'database_oid', 'database')}:
                raise ValueError('DDL_TARGET_NOT_BACKED_UP_NAMED_CLUSTER')
            installed = dict(_installed_state(conn))
            expected_installed = {'objects': True, 'tombstones': True, 'cancel_fn': True,
                'protection_bit': True}
            if any(installed.values()) and installed != expected_installed:
                raise ValueError('PRIVACY_017_PARTIAL_OR_ALREADY_INSTALLED')
            if installed == expected_installed:
                committed_events = []
                validated_events = []
                for path in sorted(out_dir.glob('privacy-017-*-committed.json')):
                    raw = _read_private(path, max_bytes=256 * 1024)
                    event = json.loads(raw)
                    if event.get('migration_sha256') == migration_hash:
                        committed_events.append((path,raw,event))
                if committed_events:
                    prior_path, prior_raw, prior = committed_events[-1]
                    if prior.get('database_ddl_committed') is not True:
                        raise ValueError('PRIVACY_017_COMMITTED_JOURNAL_INVALID')
                    _postconditions(conn, prior['api_runs_acl_before'])
                    reconcile = {'event': 'already_recorded', 'path': str(prior_path.relative_to(ROOT)).replace('\\','/'),
                        'sha256': sha(prior_raw), 'migration_sha256': migration_hash}
                else:
                    for path in sorted(out_dir.glob('privacy-017-*-validated.json')):
                        raw = _read_private(path, max_bytes=512 * 1024)
                        event = json.loads(raw)
                        if (event.get('event') == 'validated_before_commit'
                                and event.get('migration_sha256') == migration_hash
                                and event.get('database_ddl_committed') is False):
                            validated_events.append((path,raw,event))
                    if not validated_events:
                        raise ValueError('PRIVACY_017_INSTALLED_WITHOUT_VALIDATED_JOURNAL')
                    source_path, source_raw, source_event = validated_events[-1]
                    capability = _postconditions(conn, source_event['api_runs_acl_before'])
                    reconcile = {'event': 'reconciled_after_commit_response_loss',
                        'source_validated_event': str(source_path.relative_to(ROOT)).replace('\\','/'),
                        'source_validated_event_sha256': sha(source_raw),
                        'migration_sha256': migration_hash,
                        'database_marker_verified': True,
                        'capability_checks': capability,
                        'reconciled_utc': datetime.now(timezone.utc).isoformat()}
                # Leave the live DB untouched when recording a prior commit or
                # reconciling a response loss; the enclosing transaction is read-only.
            else:
                queued_before = _acquire_migration_quiescence(conn)
                before = _inventory(conn)
                acl_before = dict(_api_acl_state(conn))
                source_pins_before = _source_pins()
                if source_pins_before != old_pins:
                    raise ValueError('APPLIED_MIGRATION_SOURCE_SET_CHANGED')
                checkpoint_blob_backup = _backup_reachable_checkpoints(conn, backup_manifest_path, stamp)
                prepared = {'schema': 'fieldwork.privacy-017-activation-event/v1',
                    'event': 'prepared', 'migration_sha256': migration_hash,
                    'migration_bytes': len(migration_raw), 'migration_mtime_ns': MIGRATION.stat().st_mtime_ns,
                    'source_sha256': {name: digest for name, (_, digest) in source_artifacts.items()},
                    'review_sha256': sha(review_raw), 'scratch_report_sha256': sha(scratch_raw),
                    'backup_manifest': str(backup_manifest_path.relative_to(ROOT)).replace('\\','/'),
                    'backup_manifest_sha256': backup['manifest_sha256'],
                    'backup_dump_sha256': backup_manifest['db']['sha256'].upper(),
                    'backup_globals_sha256': backup_manifest['globals']['sha256'].upper(),
                    'backed_up_cluster_identity': expected_cluster,
                    'privacy_deletion_ledger': backup_manifest['privacy_deletion_ledger'],
                    'reachable_checkpoint_backup': checkpoint_blob_backup,
                    'source_backup': str(source_backup.relative_to(ROOT)).replace('\\','/'),
                    'pre_migration_inventory': before, 'api_runs_acl_before': acl_before,
                    'migration_sources_003_016': source_pins_before,
                    'lock': lock, 'at_utc': datetime.now(timezone.utc).isoformat(),
                    'database_ddl_committed': False}
                _write_new_private(prepared_path, (json.dumps(prepared, sort_keys=True, indent=2)+'\n').encode())
                conn.execute(_migration_body(migration_raw))
                after = _inventory(conn)
                if before != after:
                    raise ValueError('PRIVACY_017_PRESERVATION_INVENTORY_MISMATCH')
                queued_after = _queued_run_inventory(conn)
                if queued_before != queued_after:
                    raise ValueError('PRIVACY_017_QUEUED_RUNS_CHANGED')
                capability = _postconditions(conn, acl_before)
                if _source_pins() != source_pins_before or sha(MIGRATION.read_bytes()) != migration_hash:
                    raise ValueError('MIGRATION_SOURCE_CHANGED_DURING_APPLY')
                for name, (source, expected) in source_artifacts.items():
                    if sha(source.read_bytes()) != expected:
                        raise ValueError('ACTIVATION_SOURCE_CHANGED_DURING_APPLY')
                validated = {**prepared, 'event': 'validated_before_commit',
                    'post_migration_inventory': after,
                    'queued_run_inventory_before': queued_before,
                    'queued_run_inventory_after': queued_after,
                    'pre_post_inventory_unchanged': True, 'capability_checks': capability,
                    'database_ddl_committed': False,
                    'validated_utc': datetime.now(timezone.utc).isoformat()}
                _write_new_private(validated_path,
                    (json.dumps(validated, sort_keys=True, indent=2)+'\n').encode())

    if reconcile:
        _set_stage('response-loss-reconciliation-receipt')
        if reconcile['event'] == 'reconciled_after_commit_response_loss':
            path = out_dir / ('privacy-017-' + stamp + '-reconciled.json')
            _write_new_private(path, (json.dumps(reconcile, sort_keys=True, indent=2)+'\n').encode())
            return {'status': 'reconciled_committed_migration',
                'reconciliation_journal': str(path.relative_to(ROOT)).replace('\\','/'),
                'migration_sha256': migration_hash, 'live_database': 'fieldwork',
                'secret_printed': False}
        return {'status': 'already_recorded', 'migration_sha256': migration_hash,
            'committed_journal': reconcile['path'], 'live_database': 'fieldwork',
            'secret_printed': False}

    _set_stage('committed-receipt')
    committed = {**prepared, 'event': 'committed', 'database_ddl_committed': True,
        'pre_post_inventory_unchanged': True, 'capability_checks': capability,
        'committed_utc': datetime.now(timezone.utc).isoformat()}
    committed_path = out_dir / ('privacy-017-' + stamp + '-committed.json')
    _write_new_private(committed_path, (json.dumps(committed, sort_keys=True, indent=2)+'\n').encode())
    return {'status': 'applied', 'migration_sha256': migration_hash,
        'backup_manifest_sha256': backup['manifest_sha256'],
        'scratch_report_sha256': sha(scratch_raw),
        'prepared_journal': str(prepared_path.relative_to(ROOT)).replace('\\','/'),
        'committed_journal': str(committed_path.relative_to(ROOT)).replace('\\','/'),
        'live_database': 'fieldwork', 'secret_printed': False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply-live', action='store_true',
        help='create a fresh backup, verify review and lock, and apply migration 017')
    parser.add_argument('--review-receipt', type=Path)
    args = parser.parse_args(argv)
    if not args.apply_live:
        print(json.dumps({'status': 'prepared', 'execution_requires': '--apply-live',
            'migration_sha256': MIGRATION_SHA256, 'live_database_ddl': False,
            'service_activation': False, 'secret_printed': False}))
        return 0
    if args.review_receipt is None:
        raise ValueError('INDEPENDENT_017_REVIEW_REQUIRED')
    _set_stage('review-receipt-path')
    review_path = args.review_receipt.resolve(strict=True)
    review_path.relative_to(ROOT)
    out_dir = ROOT / '.local/real-data/activation'
    result = _apply(review_path, out_dir)
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        diagnostic = _write_private_exception_log()
        print(json.dumps({'status': 'refused', 'code': 'PRIVACY_017_APPLY_REFUSED',
            'private_diagnostic_log': diagnostic, 'secret_printed': False}))
        raise SystemExit(2)
