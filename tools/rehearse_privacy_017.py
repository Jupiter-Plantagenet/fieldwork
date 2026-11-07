"""Restore a retained Fieldwork snapshot into a throwaway PostgreSQL cluster and rehearse 017.

This helper is preparation-only unless --execute-scratch is supplied. It never
connects to the retained application database, never applies DDL there, binds
the disposable server to loopback only, and only emits aggregate status. Backup
globals (including role password hashes) are piped to scratch Postgres and are
never displayed or written to a new file.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg import sql
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
DUMP = ROOT / 'var' / 'snapshots' / 'real-worker-restart-before-20261102T044859Z.dump'
GLOBALS = ROOT / 'var' / 'snapshots' / 'real-worker-restart-before-20261102T044859Z-globals.sql'
EXPECTED_DUMP = '9AAD40180B9FEF0F83FE1B9843B0E111F327B443069481F5244B6550819F2328'
EXPECTED_GLOBALS = 'AEBBA09585B94725A110847B35FCE06128BEE925404FAF65ACE615529F7722CE'
EXPECTED_MIGRATION = '81E7587F33A5A30FA9A8C48369703A5C2266D3AD52926C28AB9B14974EB116EE'
MIGRATION = ROOT / 'migrations' / '017_privacy_lifecycle.sql'
IMAGE = 'postgres:16-alpine'
MAX_WAIT_SECONDS = 45
BUSINESS_TABLES = (
    'fw_accounts', 'fw_workspace_settings', 'fw_workspace_settings_events',
    'fw_sessions', 'fw_samples', 'fw_versions', 'fw_proposals', 'fw_runs',
    'fw_events', 'fw_attempts', 'fw_checkpoints',
)


class ScratchRehearsalError(RuntimeError):
    pass


def _privacy_helpers():
    from fieldwork.privacy_lifecycle import (
        _check_c_ancestry, _check_private_path, _ensure_private_directory,
    )
    return _check_c_ancestry, _check_private_path, _ensure_private_directory


def _sha256_private_file(path: Path, *, limit: int = 2 * 1024**3,
                         require_private: bool = True) -> tuple[str, int]:
    check_c, check_private, _ = _privacy_helpers()
    safe = check_c(path)
    if require_private:
        check_private(safe)
    before = safe.lstat()
    if not safe.is_file() or before.st_size > limit:
        raise ScratchRehearsalError('SCRATCH_INPUT_FILE_INVALID')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(safe, flags)
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ScratchRehearsalError('SCRATCH_INPUT_CHANGED')
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise ScratchRehearsalError('SCRATCH_INPUT_TOO_LARGE')
            digest.update(block)
    finally:
        os.close(fd)
    if safe.stat().st_size != total:
        raise ScratchRehearsalError('SCRATCH_INPUT_CHANGED')
    return digest.hexdigest().upper(), total


def _run(cmd: list[str], *, input_path: Path | None = None, timeout: int = 300,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    if input_path:
        fd = os.open(input_path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) |
                     getattr(os, 'O_NOFOLLOW', 0))
        stream = os.fdopen(fd, 'rb')
    else:
        stream = subprocess.DEVNULL
    try:
        return subprocess.run(cmd, stdin=stream, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout,
                              check=False, env=env)
    finally:
        if input_path:
            stream.close()


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])


def _write_private(path: Path, data: bytes) -> None:
    check_c, check_private, _ = _privacy_helpers()
    check_c(path, allow_missing_leaf=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    check_c(path)
    check_private(path)


def _exec_input(container: str, args: list[str], input_path: Path, *, timeout: int = 300,
                stage: str, diagnostic_path: Path) -> None:
    check_c, check_private, _ = _privacy_helpers()
    safe = check_c(input_path)
    if input_path in (DUMP, GLOBALS):
        check_private(safe)
    result = _run(['docker', 'exec', '-i', container, *args], input_path=input_path, timeout=timeout)
    if result.returncode:
        diagnostic = (b'command_stage=' + stage.encode('ascii') + b'\n'
            + b'exit_code=' + str(result.returncode).encode('ascii') + b'\n'
            + b'stdout_bytes=' + str(len(result.stdout or b'')).encode('ascii') + b'\n'
            + b'stdout:\n' + (result.stdout or b'') + b'\nstderr:\n' + (result.stderr or b''))
        _write_private(diagnostic_path, diagnostic)
        raise ScratchRehearsalError('SCRATCH_' + stage.upper() + '_FAILED_' + str(result.returncode))


def _wait_ready(dsn: str, container: str, diagnostic_path: Path) -> dict:
    deadline = time.monotonic() + MAX_WAIT_SECONDS
    inner_ready = False
    inner_ever_ready = False
    host_connect_failed = False
    host_failure_type = None
    host_failure_sqlstate = None
    last_inner = None
    while time.monotonic() < deadline:
        try:
            probe = subprocess.run(['docker','exec',container,'pg_isready','-U','scratchadmin','-d','postgres'],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False,timeout=5)
            last_inner = probe.stdout or b''
            inner_ready = probe.returncode == 0
        except subprocess.TimeoutExpired as exc:
            last_inner = exc.stdout or b'pg_isready timed out'
            inner_ready = False
        if inner_ready:
            inner_ever_ready = True
            try:
                with psycopg.connect(dsn, connect_timeout=2) as c:
                    c.execute('SELECT 1')
                return {'inside_container_ready':True,'host_loopback_connection':True}
            except psycopg.Error as exc:
                host_connect_failed = True
                host_failure_type = type(exc).__name__
                host_failure_sqlstate = getattr(exc, 'sqlstate', None)
        time.sleep(0.75)
    try:
        logs = subprocess.run(['docker','logs',container],stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,check=False,timeout=20)
        logs_raw = logs.stdout or b''
        log_exit = logs.returncode
    except subprocess.TimeoutExpired as exc:
        logs_raw = exc.stdout or b'docker logs timed out'
        log_exit = 'timeout'
    probe_exit = str(locals().get('probe').returncode) if 'probe' in locals() else 'exec-error'
    detail = (b'pg_isready_exit_code=' + probe_exit.encode('ascii') + b'\n'
        + b'inside_container_ready=' + str(inner_ever_ready).encode('ascii') + b'\n'
        + b'host_connection_exception_type=' + str(host_failure_type or 'none').encode('ascii') + b'\n'
        + b'host_connection_sqlstate=' + str(host_failure_sqlstate or 'none').encode('ascii') + b'\n'
        + b'pg_isready_output:\n' + (last_inner or b'') + b'\ncontainer_logs:\n'
        + b'docker_logs_exit_code=' + str(log_exit).encode('ascii') + b'\n'
        + logs_raw)
    _write_private(diagnostic_path,detail)
    if inner_ever_ready and host_connect_failed:
        raise ScratchRehearsalError('SCRATCH_POSTGRES_HOST_CONNECTION_FAILED_' +
            str(host_failure_type or 'UNKNOWN').upper())
    raise ScratchRehearsalError('SCRATCH_POSTGRES_NOT_READY')


def _migration_source_pins() -> dict:
    check_c, _, _ = _privacy_helpers()
    folder = ROOT / 'migrations'
    check_c(folder)
    pins = {}
    for path in sorted(folder.glob('[0-9][0-9][0-9]_*.sql')):
        check_c(path)
        try:
            number = int(path.name[:3])
        except ValueError:
            continue
        if not 3 <= number <= 16:
            continue
        digest, size = _sha256_private_file(path, limit=16 * 1024**2, require_private=False)
        info = path.stat()
        pins[path.name] = {'sha256': digest, 'bytes': size, 'mtime_ns': info.st_mtime_ns}
    return pins


def _database_inventory(conn) -> dict:
    """Return only aggregate counts and SQL-computed digests, never row contents."""
    if not conn.execute("SELECT to_regprocedure('pg_catalog.sha256(bytea)') IS NOT NULL AS ready").fetchone()['ready']:
        raise ScratchRehearsalError('SCRATCH_SHA256_SQL_CAPABILITY_REQUIRED')
    tables = {row['relname'] for row in conn.execute("""
        SELECT c.relname FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p')
    """).fetchall()}
    counts = {}
    for table in BUSINESS_TABLES:
        if table in tables:
            counts[table] = conn.execute(sql.SQL('SELECT count(*) AS n FROM public.{}').format(
                sql.Identifier(table))).fetchone()['n']
    journals = {}
    for row in conn.execute("""
        SELECT c.relname FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p')
          AND c.relname ~* '(migration|schema_history|schema_version)'
        ORDER BY c.relname
    """).fetchall():
        name = row['relname']
        journal = conn.execute(sql.SQL("""
            SELECT count(*) AS row_count,
              encode(pg_catalog.sha256(convert_to(coalesce(
                string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),''),'UTF8')),'hex') AS sha256
            FROM public.{} AS t
        """).format(sql.Identifier(name))).fetchone()
        journals[name] = {'rows': journal['row_count'], 'sha256': journal['sha256'].upper()}

    versions = conn.execute("""
        SELECT count(*) AS row_count,
          encode(pg_catalog.sha256(convert_to(coalesce(string_agg(
            workspace||E'\\t'||id||E'\\t'||encode(pg_catalog.sha256(convert_to(manifest::text,'UTF8')),'hex'),
            E'\\n' ORDER BY workspace,id),''),'UTF8')),'hex') AS sha256
        FROM public.fw_versions WHERE state='frozen'
    """).fetchone()
    checkpoints = conn.execute("""
        SELECT count(*) AS row_count,
          encode(pg_catalog.sha256(convert_to(coalesce(string_agg(
            concat_ws(E'\\t',run::text,epoch::text,digest,path),E'\\n' ORDER BY run,epoch),''),
            'UTF8')),'hex') AS sha256
        FROM public.fw_checkpoints
    """).fetchone()
    return {
        'business_row_counts': counts,
        'migration_journals': journals,
        'frozen_manifest_digest_inventory': {
            'rows': versions['row_count'], 'sha256': versions['sha256'].upper(),
            'digest_computed_inside_sql': True,
        },
        'checkpoint_pointer_inventory': {
            'rows': checkpoints['row_count'], 'sha256': checkpoints['sha256'].upper(),
            'digest_computed_inside_sql': True,
        },
    }


def _verify_native_sha256(conn) -> dict:
    if not conn.execute("SELECT to_regprocedure('pg_catalog.sha256(bytea)') IS NOT NULL AS ready").fetchone()['ready']:
        raise ScratchRehearsalError('SCRATCH_NATIVE_SHA256_UNAVAILABLE')
    samples = (b'', b'fieldwork privacy 017 sha256 equivalence', bytes(range(256)))
    for sample in samples:
        expected = hashlib.sha256(sample).hexdigest()
        actual = conn.execute(
            "SELECT encode(pg_catalog.sha256(%s::bytea),'hex') AS digest", (sample,)
        ).fetchone()['digest']
        if actual.lower() != expected:
            raise ScratchRehearsalError('SCRATCH_NATIVE_SHA256_EQUIVALENCE_FAILED')
    extension = conn.execute("""
        SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_extension WHERE extname='pgcrypto') AS installed
    """).fetchone()['installed']
    if extension:
        raise ScratchRehearsalError('SCRATCH_UNEXPECTED_PGCRYPTO_EXTENSION')
    return {'synthetic_inputs_checked': len(samples),
        'matches_standard_sha256': True, 'pgcrypto_extension_absent': True}


def _quiescence_commit_race(admin_dsn: str) -> dict:
    """Prove an in-flight claim is visible after the migration table lock waits."""
    from tools.apply_privacy_017 import _acquire_migration_quiescence, _queued_run_inventory

    with psycopg.connect(admin_dsn, row_factory=dict_row) as c:
        with c.transaction():
            queued_before = _queued_run_inventory(c)
    if queued_before['rows'] < 1:
        raise ScratchRehearsalError('SCRATCH_QUIESCENCE_QUEUED_FIXTURE_MISSING')

    ready = threading.Event()
    details = {}
    run_id = None
    writer_committed = False
    decision = None

    def applier_waiter():
        with psycopg.connect(admin_dsn, row_factory=dict_row) as applier:
            details['pid'] = applier.info.backend_pid
            ready.set()
            with applier.transaction():
                applier.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
                applier.execute("SET LOCAL lock_timeout='10s'")
                applier.execute("SET LOCAL statement_timeout='15s'")
                try:
                    _acquire_migration_quiescence(applier)
                except ValueError as exc:
                    if str(exc) == 'LIVE_RUNS_NOT_QUIESCENT':
                        return 'refused_active'
                    raise
                return 'admitted'

    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            with psycopg.connect(admin_dsn, row_factory=dict_row) as writer:
                with writer.transaction():
                    writer.execute("SET LOCAL session_replication_role='replica'")
                    changed = writer.execute("""
                        UPDATE public.fw_runs SET state='running'
                        WHERE id=(SELECT id FROM public.fw_runs
                          WHERE state='queued' ORDER BY id LIMIT 1)
                        RETURNING id
                    """).fetchone()
                    if not changed:
                        raise ScratchRehearsalError('SCRATCH_ACTIVE_COMMIT_FIXTURE_UNAVAILABLE')
                    run_id = changed['id']
                    future = pool.submit(applier_waiter)
                    if not ready.wait(timeout=5):
                        raise ScratchRehearsalError('SCRATCH_APPLIER_CONNECTION_NOT_READY')
                    deadline = time.monotonic() + 8
                    lock_wait_observed = False
                    while time.monotonic() < deadline:
                        with psycopg.connect(admin_dsn, row_factory=dict_row) as observer:
                            lock_wait_observed = observer.execute("""
                                SELECT EXISTS(
                                  SELECT 1 FROM pg_catalog.pg_locks
                                  WHERE pid=%s AND locktype='relation'
                                    AND relation='public.fw_runs'::regclass
                                    AND mode='ShareRowExclusiveLock' AND NOT granted
                                ) AS waiting
                            """, (details['pid'],)).fetchone()['waiting']
                        if lock_wait_observed:
                            break
                        if future.done():
                            break
                        time.sleep(0.05)
                    details['lock_wait_observed'] = lock_wait_observed
                    if not lock_wait_observed:
                        raise ScratchRehearsalError('SCRATCH_APPLIER_TABLE_LOCK_WAIT_NOT_OBSERVED')
                writer_committed = True
            decision = future.result(timeout=15)
            if decision != 'refused_active':
                raise ScratchRehearsalError('SCRATCH_COMMITTED_ACTIVE_RUN_NOT_REFUSED')
        finally:
            if writer_committed and run_id is not None:
                with psycopg.connect(admin_dsn, row_factory=dict_row) as cleanup:
                    with cleanup.transaction():
                        cleanup.execute("SET LOCAL session_replication_role='replica'")
                        restored = cleanup.execute("""
                            UPDATE public.fw_runs SET state='queued'
                            WHERE id=%s AND state='running'
                        """, (run_id,))
                        if restored.rowcount != 1:
                            raise ScratchRehearsalError('SCRATCH_ACTIVE_COMMIT_FIXTURE_CLEANUP_FAILED')

    with psycopg.connect(admin_dsn, row_factory=dict_row) as c:
        with c.transaction():
            queued_after = _queued_run_inventory(c)
    if queued_before != queued_after:
        raise ScratchRehearsalError('SCRATCH_ACTIVE_COMMIT_FIXTURE_CHANGED_QUEUED_ROWS')
    return {'queued_before': queued_before, 'queued_after_cleanup': queued_after,
        'lock_wait_observed': bool(details.get('lock_wait_observed')),
        'active_claim_committed_before_check': decision == 'refused_active',
        'active_run_refused': decision == 'refused_active',
        'queued_survivors_unchanged': queued_before == queued_after}


def run_scratch_rehearsal() -> dict:
    check_c, check_private, ensure_private = _privacy_helpers()
    dump_hash, dump_bytes = _sha256_private_file(DUMP)
    globals_hash, globals_bytes = _sha256_private_file(GLOBALS)
    migration_hash, _migration_bytes = _sha256_private_file(MIGRATION, limit=16 * 1024**2,
                                                              require_private=False)
    if dump_hash != EXPECTED_DUMP or globals_hash != EXPECTED_GLOBALS or migration_hash != EXPECTED_MIGRATION:
        raise ScratchRehearsalError('SCRATCH_INPUT_PIN_MISMATCH')

    api_config_path = ROOT / '.local-api.json'
    check_c(api_config_path)
    check_private(api_config_path)
    api_config = json.loads(api_config_path.read_text(encoding='utf-8'))
    api_params = conninfo_to_dict(api_config['dsn'])
    if api_params.get('user') != 'fieldwork_api':
        raise ScratchRehearsalError('SCRATCH_API_ROLE_REQUIRED')
    if not api_params.get('password'):
        raise ScratchRehearsalError('SCRATCH_API_PASSWORD_REQUIRED')

    log_root = ROOT / '.local' / 'privacy-test-runs'
    ensure_private(log_root)
    run_id = uuid.uuid4().hex
    container = 'fieldwork-privacy-017-' + run_id[:16]
    network = 'fieldwork-privacy-017-net-' + run_id[:16]
    database = 'fieldwork_test_privacy_017_' + run_id
    port = _port()
    scratch_password = secrets.token_urlsafe(32)
    run_env = dict(os.environ)
    run_env['POSTGRES_PASSWORD'] = scratch_password
    report_path = log_root / ('scratch-017-' + run_id + '.json')
    pg_test_log = log_root / ('scratch-017-focused-tests-' + run_id + '.raw.log')
    postgres_log = log_root / ('scratch-017-postgres-startup-' + run_id + '.raw.log')
    command_error_logs = {
        stage: log_root / ('scratch-017-' + stage + '-' + run_id + '.raw.log')
        for stage in ('globals-restore', 'backup-restore', 'migration-apply')}
    exception_log = log_root / ('scratch-017-exception-' + run_id + '.raw.log')
    for path in (report_path,pg_test_log,postgres_log,exception_log,*command_error_logs.values()):
        check_c(path,allow_missing_leaf=True)
    if any(path.exists() for path in (report_path,pg_test_log,postgres_log,exception_log,*command_error_logs.values())):
        raise ScratchRehearsalError('SCRATCH_EVIDENCE_COLLISION')

    admin_dsn = make_conninfo(host='127.0.0.1', port=port, dbname='postgres',
        user='scratchadmin', password=scratch_password, connect_timeout=2, sslmode='disable')
    api_params.update({'host': '127.0.0.1', 'port': str(port), 'dbname': database,
                       'connect_timeout': '5', 'sslmode': 'disable'})
    for key in ('hostaddr','service','servicefile','passfile','options','sslrootcert','sslcert','sslkey'):
        api_params.pop(key, None)
    api_dsn = make_conninfo(**api_params)

    report = {
        'schema': 'fieldwork.privacy-017-scratch-rehearsal/v1',
        'started_utc': datetime.now(timezone.utc).isoformat(),
        'report_path': str(report_path.relative_to(ROOT).as_posix()),
        'backup': {'dump_sha256': dump_hash, 'dump_bytes': dump_bytes,
                   'globals_sha256': globals_hash, 'globals_bytes': globals_bytes},
        'migration_sha256': migration_hash,
        'scratch_only': True,
        'retained_database_connected': False,
        'migration_applied_to_retained_database': False,
        'migration_applied_to_scratch': False,
        'focused_test_exit_code': None,
        'focused_test_log': str(pg_test_log.relative_to(ROOT).as_posix()),
        'postgres_startup_diagnostic_log': str(postgres_log.relative_to(ROOT).as_posix()),
        'postgres_readiness': None,
        'scratch_tablespaces': 'default_only',
        'scratch_network': 'dedicated_bridge_loopback_published',
        'postgres_image_id': None,
        'scratch_container_id': None,
        'scratch_container_cleanup': 'not_started',
        'scratch_container_absent_verified': False,
        'scratch_network_cleanup': 'not_created',
        'scratch_network_absent_verified': False,
        'status': 'running',
    }
    container_started = False
    network_created = False
    network_id = None
    network_id_valid = False
    network_cleanup_target = network
    container_id = None
    container_id_valid = False
    container_cleanup_target = container
    scratch_dsn = None
    source_pins_before = _migration_source_pins()
    inventory_before = None
    try:
        # Do not replay host tablespace paths from pg_dumpall globals. In
        # particular, this helper must never dereference legacy D:/G: locations.
        safe_globals = check_c(GLOBALS)
        check_private(safe_globals)
        globals_bytes_raw = safe_globals.read_bytes()
        if re.search(rb'(?im)^\s*(?:CREATE|ALTER|COMMENT)\s+TABLESPACE\b', globals_bytes_raw):
            raise ScratchRehearsalError('SCRATCH_TABLESPACE_GLOBALS_UNSUPPORTED')
        image_check = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
            text=True, encoding='utf-8')
        if image_check.returncode:
            raise ScratchRehearsalError('SCRATCH_POSTGRES_IMAGE_UNAVAILABLE')
        image_id = image_check.stdout.strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
            raise ScratchRehearsalError('SCRATCH_POSTGRES_IMAGE_ID_INVALID')
        report['postgres_image_id'] = image_id
        # Docker's --internal bridge prevents Windows from reaching a published
        # loopback port. Keep this disposable cluster on its own regular bridge;
        # PostgreSQL is still published on 127.0.0.1 only and the bridge is
        # removed in the same bounded cleanup path.
        network_result = subprocess.run(['docker', 'network', 'create',
            '--driver', 'bridge', network], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, text=True, encoding='utf-8')
        if network_result.returncode:
            raise ScratchRehearsalError('SCRATCH_INTERNAL_NETWORK_CREATE_FAILED')
        network_created = True
        network_id = network_result.stdout.strip()
        if not re.fullmatch(r'[0-9a-f]{64}', network_id):
            raise ScratchRehearsalError('SCRATCH_INTERNAL_NETWORK_ID_INVALID')
        network_id_valid = True
        network_cleanup_target = network_id
        created = subprocess.run([
            'docker', 'run', '--detach', '--rm', '--name', container,
            '--network', network,
            '--publish', f'127.0.0.1:{port}:5432', '--memory', '1g', '--cpus', '2',
            '--pids-limit', '256', '--env', 'POSTGRES_USER=scratchadmin',
            '--env', 'POSTGRES_PASSWORD', '--env', 'POSTGRES_DB=postgres', IMAGE,
        ], env=run_env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
           text=True, encoding='utf-8')
        if created.returncode:
            raise ScratchRehearsalError('SCRATCH_CONTAINER_START_FAILED')
        container_started = True
        container_id = created.stdout.strip()
        if not re.fullmatch(r'[0-9a-f]{64}', container_id):
            raise ScratchRehearsalError('SCRATCH_CONTAINER_ID_INVALID')
        container_id_valid = True
        container_cleanup_target = container_id
        report['scratch_container_id'] = container_id
        report['postgres_readiness'] = _wait_ready(admin_dsn,container,postgres_log)

        # Restore role definitions only inside the disposable scratch cluster.
        _exec_input(container, ['psql', '-U', 'scratchadmin', '-d', 'postgres',
                                '--set=ON_ERROR_STOP=1'], GLOBALS,
                    stage='globals-restore', diagnostic_path=command_error_logs['globals-restore'])
        with psycopg.connect(admin_dsn, autocommit=True) as c:
            c.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(database)))

        # pg_restore reads stdin when no archive filename is supplied. A
        # literal '-' is treated as a filename by the supported client.
        _exec_input(container, ['pg_restore', '-U', 'scratchadmin', '-d', database,
                                '--exit-on-error', '--no-tablespaces'], DUMP, timeout=600,
                    stage='backup-restore', diagnostic_path=command_error_logs['backup-restore'])
        admin_params = conninfo_to_dict(admin_dsn)
        scratch_dsn = make_conninfo(**{**admin_params, 'dbname': database})
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as c:
            native_sha256 = _verify_native_sha256(c)
            inventory_before = _database_inventory(c)
            from tools.apply_privacy_017 import _api_acl_state
            acl_before_migration = dict(_api_acl_state(c))
        report['native_sha256_synthetic_equivalence'] = native_sha256
        report['native_sha256_matches_legacy_digest_semantics'] = (
            native_sha256['matches_standard_sha256'])
        report['pgcrypto_extension_absent'] = native_sha256['pgcrypto_extension_absent']
        from tools.apply_privacy_017 import _acquire_migration_quiescence, _queued_run_inventory
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as c:
            with c.transaction():
                queued_before = _acquire_migration_quiescence(c)
        report['queued_run_inventory_before'] = queued_before
        # The restored snapshot contains legacy queued execution-only rows.
        # Preserve them and prove the new admission check refuses a truly
        # active row. The state change is confined to a rolled-back savepoint.
        try:
            with psycopg.connect(scratch_dsn, row_factory=dict_row) as c:
                with c.transaction():
                    try:
                        with c.transaction():
                            c.execute("SET LOCAL session_replication_role='replica'")
                            changed = c.execute("""
                                UPDATE public.fw_runs SET state='running'
                                WHERE id=(SELECT id FROM public.fw_runs
                                  WHERE state='queued' ORDER BY id LIMIT 1)
                            """)
                            if changed.rowcount != 1:
                                raise ScratchRehearsalError('SCRATCH_ACTIVE_RUN_FIXTURE_UNAVAILABLE')
                            _acquire_migration_quiescence(c)
                        raise ScratchRehearsalError('SCRATCH_ACTIVE_RUN_NOT_REFUSED')
                    except ValueError as exc:
                        if str(exc) != 'LIVE_RUNS_NOT_QUIESCENT':
                            raise
                        report['active_run_quiescence_refused'] = True
        except ScratchRehearsalError:
            raise
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as c:
            with c.transaction():
                queued_after_active_probe = _queued_run_inventory(c)
        report['queued_run_inventory_after_active_probe'] = queued_after_active_probe
        if queued_before != queued_after_active_probe:
            raise ScratchRehearsalError('SCRATCH_ACTIVE_PROBE_CHANGED_QUEUED_ROWS')
        concurrency_probe = _quiescence_commit_race(scratch_dsn)
        report['quiescence_commit_race'] = concurrency_probe
        report['quiescence_lock_wait_observed'] = concurrency_probe['lock_wait_observed']
        report['active_claim_committed_before_check'] = concurrency_probe['active_claim_committed_before_check']
        report['committed_active_run_refused'] = concurrency_probe['active_run_refused']
        report['queued_run_survivors_unchanged_after_concurrency'] = (
            concurrency_probe['queued_survivors_unchanged'])
        if not all(report[key] for key in (
                'quiescence_lock_wait_observed',
                'active_claim_committed_before_check',
                'committed_active_run_refused',
                'queued_run_survivors_unchanged_after_concurrency')):
            raise ScratchRehearsalError('SCRATCH_QUIESCENCE_COMMIT_RACE_FAILED')
        report['pre_migration_inventory'] = inventory_before
        report['pre_migration_source_pins_003_016'] = source_pins_before
        _exec_input(container, ['psql', '-U', 'scratchadmin', '-d', database,
                                '--set=ON_ERROR_STOP=1'], MIGRATION, timeout=300,
                    stage='migration-apply', diagnostic_path=command_error_logs['migration-apply'])
        report['migration_applied_to_scratch'] = True
        # Capture preservation invariants before exercising fixture writes. A
        # failed API-role test must not hide whether the migration itself kept
        # the retained backup's business rows and sealed-evidence digests intact.
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as c:
            inventory_after_migration = _database_inventory(c)
            with c.transaction():
                queued_after_migration = _queued_run_inventory(c)
        report['queued_run_inventory_after_migration'] = queued_after_migration
        report['queued_run_survivors_unchanged'] = queued_before == queued_after_migration
        if not report['queued_run_survivors_unchanged']:
            raise ScratchRehearsalError('SCRATCH_QUEUED_RUNS_NOT_PRESERVED')
        report['post_migration_inventory'] = inventory_after_migration
        report['post_migration_source_pins_003_016'] = _migration_source_pins()
        report['business_row_counts_unchanged'] = (
            inventory_before['business_row_counts'] == inventory_after_migration['business_row_counts'])
        report['migration_journal_rows_hashes_timestamps_unchanged'] = (
            inventory_before['migration_journals'] == inventory_after_migration['migration_journals'])
        report['checkpoint_pointers_unchanged'] = (
            inventory_before['checkpoint_pointer_inventory'] == inventory_after_migration['checkpoint_pointer_inventory'])
        report['frozen_manifest_sql_digests_unchanged'] = (
            inventory_before['frozen_manifest_digest_inventory'] == inventory_after_migration['frozen_manifest_digest_inventory'])
        report['migration_sources_003_016_bytes_checksums_timestamps_unchanged'] = (
            source_pins_before == report['post_migration_source_pins_003_016'])
        if not all(report[key] for key in (
                'business_row_counts_unchanged',
                'migration_journal_rows_hashes_timestamps_unchanged',
                'checkpoint_pointers_unchanged',
                'frozen_manifest_sql_digests_unchanged',
                'migration_sources_003_016_bytes_checksums_timestamps_unchanged')):
            raise ScratchRehearsalError('SCRATCH_MIGRATION_PRESERVATION_MISMATCH')
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as c:
            from tools.apply_privacy_017 import _postconditions
            report['retained_applier_postconditions'] = _postconditions(c, acl_before_migration)
            report['retained_applier_postconditions_passed'] = True
            capability = c.execute("SELECT to_regprocedure('public.fw_privacy_cancel_deleted_run_v1(text,text)') IS NOT NULL AS ready").fetchone()['ready']
            api_role = c.execute("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname='fieldwork_api'").fetchone()
            forced = c.execute("""SELECT relrowsecurity,relforcerowsecurity FROM pg_class
                WHERE oid='public.fw_runs'::regclass""").fetchone()
        if (not report.get('retained_applier_postconditions_passed')
                or not capability or not api_role or api_role['rolsuper'] or api_role['rolbypassrls']
                or not forced or not forced['relrowsecurity'] or not forced['relforcerowsecurity']):
            raise ScratchRehearsalError('SCRATCH_PRIVACY_MIGRATION_POSTCONDITION_FAILED')

        api_params_check = conninfo_to_dict(api_dsn)
        if (api_params_check.get('user') != 'fieldwork_api'
                or api_params_check.get('dbname') != database
                or api_params_check.get('host') != '127.0.0.1'
                or int(api_params_check.get('port','0')) != port):
            raise ScratchRehearsalError('SCRATCH_API_DSN_SCOPE_INVALID')
        inner_python = ROOT / '.venv' / 'Scripts' / 'python.exe' if os.name == 'nt' else ROOT / '.venv' / 'bin' / 'python'
        test_env = dict(os.environ)
        test_env['FIELDWORK_PRIVACY_ADMIN_DSN'] = scratch_dsn
        test_env['FIELDWORK_PRIVACY_API_DSN'] = api_dsn
        try:
            probe = subprocess.run([str(inner_python), '-B', '-m', 'pytest', '--noconftest', '-q',
                'tests/test_privacy_lifecycle_source.py',
                'tests/test_privacy_delete_cancel_postgres.py'], cwd=ROOT, env=test_env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, check=False)
        except subprocess.TimeoutExpired as exc:
            raw = exc.stdout or b''
            if isinstance(raw, str):
                raw = raw.encode('utf-8', errors='replace')
            _write_private(pg_test_log, raw)
            raise ScratchRehearsalError('SCRATCH_FOCUSED_TEST_TIMEOUT') from None
        _write_private(pg_test_log, probe.stdout)
        report['focused_test_exit_code'] = probe.returncode
        if probe.returncode:
            raise ScratchRehearsalError('SCRATCH_API_ROLE_PROBE_FAILED')
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as c:
            inventory_after_probe = _database_inventory(c)
        report['post_probe_inventory'] = inventory_after_probe
        report['synthetic_probe_row_counts_restored'] = (
            inventory_after_migration['business_row_counts'] == inventory_after_probe['business_row_counts'])
        report['synthetic_probe_migration_journal_unchanged'] = (
            inventory_after_migration['migration_journals'] == inventory_after_probe['migration_journals'])
        report['synthetic_probe_checkpoint_pointers_unchanged'] = (
            inventory_after_migration['checkpoint_pointer_inventory'] == inventory_after_probe['checkpoint_pointer_inventory'])
        report['synthetic_probe_frozen_manifest_digests_unchanged'] = (
            inventory_after_migration['frozen_manifest_digest_inventory'] == inventory_after_probe['frozen_manifest_digest_inventory'])
        if not all(report[key] for key in (
                'synthetic_probe_row_counts_restored',
                'synthetic_probe_migration_journal_unchanged',
                'synthetic_probe_checkpoint_pointers_unchanged',
                'synthetic_probe_frozen_manifest_digests_unchanged')):
            raise ScratchRehearsalError('SCRATCH_API_PROBE_CLEANUP_MISMATCH')
        report['api_role_nonprivileged_and_rls_forced'] = True
        report['status'] = 'passed'
    except ScratchRehearsalError as exc:
        report['status'] = 'failed'
        report['error_code'] = str(exc)
        for stage, path in command_error_logs.items():
            if str(exc).startswith('SCRATCH_' + stage.split('-')[0].upper()):
                report['error_diagnostic_log'] = str(path.relative_to(ROOT).as_posix())
                break
    except Exception:
        report['status'] = 'failed'
        report['error_code'] = 'SCRATCH_REHEARSAL_UNEXPECTED_FAILURE'
        _write_private(exception_log,traceback.format_exc().encode('utf-8',errors='replace'))
        report['error_diagnostic_log'] = str(exception_log.relative_to(ROOT).as_posix())
    finally:
        if container_started:
            stopped = subprocess.run(['docker', 'stop', '--time', '5', container_cleanup_target],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)
            if stopped.returncode == 0:
                report['scratch_container_cleanup'] = 'stopped_and_rm'
            else:
                removed = subprocess.run(['docker', 'rm', '--force', container_cleanup_target],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)
                report['scratch_container_cleanup'] = 'force_removed_after_stop_failure' if removed.returncode == 0 else 'cleanup_failed'
            docker_ready = subprocess.run(['docker', 'info', '--format', '{{.ID}}'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)
            filter_key = 'id=' + container_id if container_id_valid else 'name=^/' + container
            remaining = subprocess.run(['docker', 'ps', '-a', '--no-trunc', '--filter',
                filter_key, '--format', '{{.ID}}'], stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=False, timeout=30, text=True, encoding='utf-8')
            report['scratch_container_absent_verified'] = (
                container_id_valid and docker_ready.returncode == 0 and remaining.returncode == 0
                and not remaining.stdout.strip())
        if network_created:
            removed_network = subprocess.run(['docker', 'network', 'rm', network_cleanup_target],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)
            report['scratch_network_cleanup'] = 'removed' if removed_network.returncode == 0 else 'cleanup_failed'
            network_filter = 'id=' + network_id if network_id_valid else 'name=^' + network
            networks = subprocess.run(['docker', 'network', 'ls', '--no-trunc', '--filter',
                network_filter, '--format', '{{.ID}}'], stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=False, timeout=30, text=True, encoding='utf-8')
            report['scratch_network_absent_verified'] = (
                network_id_valid and networks.returncode == 0 and not networks.stdout.strip())
        if report['status'] == 'passed' and not (
                report['scratch_container_absent_verified'] and report['scratch_network_absent_verified']):
            report['status'] = 'failed'
            report['error_code'] = 'SCRATCH_RESOURCE_CLEANUP_UNVERIFIED'
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        _write_private(report_path, (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--execute-scratch', action='store_true',
        help='restore the pinned retained backup into a new loopback-only disposable container')
    args = parser.parse_args()
    if not args.execute_scratch:
        print(json.dumps({'status': 'prepared', 'execution_requires': '--execute-scratch',
            'live_database_ddl': False, 'service_activation': False}))
        return 0
    result = run_scratch_rehearsal()
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('focused_test_log',)}))
    return 0 if result.get('status') == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
