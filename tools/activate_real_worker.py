"""Bounded, explicit operator steps for local Fieldwork real-data activation.

Every mutating action requires the shared Fieldwork activation lock to be held by
an ancestor process. This helper never applies DDL at startup and never prints
private configuration or database error text.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
REPO = ROOT
WORKSPACE = '814830e3-55a0-4925-ad37-5d3dac7d4df8'
PURPOSE = 'fieldwork-real-activation'
_DETACHED_HANDOFF = None
MIGRATION_PINS = {
    '003_signed_rights.sql': 'c7dd0600c7891779af8027cbf04e09e68059530dbd7f04389f1c52794277f07c',
    '006_real_data_api.sql': 'cea405d1df917f45c96f6a3cdf7ac6313253254220b5d891a4d32d3079bf8920',
    '007_real_run_worker.sql': 'ceea0dbc6ff722819c682c97033667e782463e2b45c86bc26fe29adb91b7cf05',
    '008_predecode_intake_results.sql': '148a0cb18c440b550a7835884764760d2b554a901e5e64860b71d78337204702',
}
SCHEMA_MIGRATION_PINS = {
    '009_fresh_image_inference.sql': '5adb6f41d423198d04c4ed09ce8bb68aa8560dada792c13abcb55a960beb5227',
    '010_workspace_controls.sql': 'cfe6bf0275dc839c24e8a27b1dd1d2b0b11968902af5b24ea302ad8d07b16a10',
    '011_real_artifact_retention.sql': '02bdcf6e9364f10ba39e95de638ac57541c0891e3b0deccc8f65b04c57a92950',
}
QUALIFIED_SCHEMA_MIGRATION_PINS = {
    **SCHEMA_MIGRATION_PINS,
    '012_qualified_release_inference.sql': '7535502db63723a5fabc6ccc4fb19964f00791ad6ffcb52c82747b7df1bafabf',
}
WORKER_RIGHTS_FIX_MIGRATION = '014_real_worker_rights_encoding.sql'
WORKER_RIGHTS_FIX_SHA256 = '9c0d9c81b34d25252f6fa0c801306ca402e234b6c34b35bad110e5e8ab2024d0'
WORKER_RIGHTS_FIX_REVIEW_BASELINES = {
    'migrations/007_real_run_worker.sql': MIGRATION_PINS['007_real_run_worker.sql'],
    'migrations/012_qualified_release_inference.sql': QUALIFIED_SCHEMA_MIGRATION_PINS['012_qualified_release_inference.sql'],
}
WORKER_RIGHTS_FIX_FUNCTION_HASHES_BEFORE = {
    'fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)':
        '21ae44dc5268ec0fb0c284c54f32f9620c97d7ad4de952c9f9767bde22d4dfd6',
    'fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)':
        'b0b0a01cc1ca1de2022ba70e38575c729de4e15b0adad8715dfffbefa1cbb919',
}
WORKER_RIGHTS_FIX_FUNCTION_HASHES_AFTER = {
    'fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)':
        'e1cdfb94bca3e5595d815abfc295ce2da142ef00176d528405edb5f904d7f692',
    'fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)':
        '3d9d8a84c9020dc201d1b63eb876d116535f3f64126c3ee7ea54bfb621a4a0f0',
}
WORKER_ROW_LOCK_MIGRATION = '015_rights_row_lock_capability.sql'
WORKER_ROW_LOCK_SHA256 = '578de6f33b27241aa6357715f71f98ae74ec9f58c7c5819bbba96f03e7164b87'
WORKER_ROW_LOCK_SOURCE_BASELINES = {
    'migrations/007_real_run_worker.sql': MIGRATION_PINS['007_real_run_worker.sql'],
    'migrations/012_qualified_release_inference.sql': QUALIFIED_SCHEMA_MIGRATION_PINS['012_qualified_release_inference.sql'],
    'migrations/014_real_worker_rights_encoding.sql': WORKER_RIGHTS_FIX_SHA256,
}
QUALIFIED_REVIEW_SHA256 = '60d4da981a314204eb15946092cf8b190b61e8acf4b67199eea52b1cc2812c80'
QUALIFIED_RUNTIME_PINFILE_SHA256 = '9d2414a572a046cd810ad2ede45228503ff4cb2c016fcfac45e1da4444bdd3c4'
QUALIFIED_REHEARSAL_REVIEWED_FALSE_NEGATIVE_SHA256 = '06a03d45b9189ef408b903b82adafd9d633aef441f864e7879e12473d6102040'
IMAGE_ID = re.compile(r'^sha256:[0-9a-f]{64}$')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_error(exc: BaseException) -> dict:
    raw = exc.args[0] if exc.args else ''
    code = raw if isinstance(raw, str) and re.fullmatch(r'[A-Z0-9_]{1,64}', raw) else None
    return {'status': 'refused', 'error_class': type(exc).__name__, 'code': code,
            'secret_printed': False}


def require_lock() -> dict:
    sys.path.insert(0, str(REPO / 'tools'))
    import product_lock
    import psutil
    record = product_lock.read_owner(REPO / '.cache/product-build.lock') or {}
    if isinstance(_DETACHED_HANDOFF, dict):
        expected = _DETACHED_HANDOFF.get('lock_owner')
        gone, reason = product_lock.owner_gone(record) if record else (True, 'OWNER_RECORD_MISSING')
        if (gone or reason != 'OWNER_ALIVE' or not isinstance(expected, dict)
                or record.get('product') != 'fieldwork' or record.get('purpose') != PURPOSE
                or record.get('pid') != expected.get('pid')
                or type(record.get('create_time')) not in (int, float)
                or abs(record['create_time'] - expected.get('create_time', -1)) >= .01):
            raise RuntimeError('FIELDWORK_REAL_ACTIVATION_HANDOFF_LOCK_INVALID')
        return {'pid': record['pid'], 'product': 'fieldwork', 'purpose': PURPOSE,
                'handoff': True}
    ancestors = {(p.pid, p.create_time()) for p in psutil.Process().parents()}
    if (record.get('product') != 'fieldwork' or record.get('purpose') != PURPOSE
            or (record.get('pid'), record.get('create_time')) not in ancestors):
        raise RuntimeError('FIELDWORK_REAL_ACTIVATION_LOCK_REQUIRED')
    return {'pid': record['pid'], 'product': 'fieldwork', 'purpose': PURPOSE}


def private_operator_dsn() -> str:
    path = ROOT / '.local.json'
    doc = json.loads(path.read_text(encoding='utf-8'))
    dsn = doc.get('dsn') if type(doc) is dict else None
    if not isinstance(dsn, str) or not dsn:
        raise ValueError('OPERATOR_FILE_SCHEMA')
    from psycopg.conninfo import conninfo_to_dict
    params = conninfo_to_dict(dsn)
    if params.get('host') not in ('127.0.0.1', '::1') or params.get('dbname') != 'fieldwork':
        raise ValueError('RETAINED_DATABASE_IDENTITY_REFUSED')
    return dsn


def confirm_pins() -> dict[str, str]:
    out = {}
    for name, expected in MIGRATION_PINS.items():
        actual = sha((ROOT / 'migrations' / name).read_bytes())
        if actual != expected:
            raise ValueError('MIGRATION_SOURCE_PIN_MISMATCH')
        out[name] = actual
    return out


def sql_function_body(path: Path, name: str) -> str:
    source = path.read_text(encoding='utf-8')
    escaped = re.escape(name)
    match = re.search(r'CREATE(?: OR REPLACE)? FUNCTION\s+' + escaped +
                      r'\s*\(\)\s+RETURNS\s+trigger.*?AS\s+\$fn\$(.*?)\$fn\$\s*;',
                      source, re.IGNORECASE | re.DOTALL)
    if not match:
        raise ValueError('EXPECTED_MIGRATION_FUNCTION_MISSING')
    return match.group(1).strip()


def migration_transaction_body(path: Path) -> str:
    """Remove only the verified outer BEGIN/COMMIT envelope from a pinned file."""
    lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
    nonblank = [i for i, line in enumerate(lines) if line.strip()]
    if len(nonblank) < 3:
        raise ValueError('MIGRATION_ENVELOPE_INVALID')
    first = next((i for i, line in enumerate(lines)
                  if line.strip() and not line.lstrip().startswith('--')), None)
    if first is None:
        raise ValueError('MIGRATION_OUTER_BEGIN_MISSING')
    if lines[first].strip().upper() != 'BEGIN;':
        raise ValueError('MIGRATION_OUTER_BEGIN_NOT_FIRST')
    if any(line.strip() and not line.lstrip().startswith('--') for line in lines[:first]):
        raise ValueError('MIGRATION_PREFIX_NOT_COMMENTS_ONLY')
    last = nonblank[-1]
    if lines[last].strip().upper() != 'COMMIT;':
        raise ValueError('MIGRATION_OUTER_COMMIT_NOT_LAST')
    # Retain the exact SQL body and every inner block. Only those two verified
    # wrapper lines are omitted so both migration bodies share one PG transaction.
    return ''.join(lines[:first] + lines[first + 1:last] + lines[last + 1:])


def counts(conn) -> dict[str, int]:
    from psycopg import sql
    names = conn.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public' ORDER BY tablename").fetchall()
    return {row[0]: conn.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(row[0]))).fetchone()[0]
            for row in names}


def schema_migration_body(path: Path, *, enveloped: bool) -> str:
    if enveloped:
        return migration_transaction_body(path)
    return path.read_text(encoding='utf-8')


def verify_schema_receipt(path: Path, *, kind: str, pins: dict[str, str]) -> dict:
    raw = path.read_bytes()
    if kind == 'rehearsal':
        receipt = json.loads(raw.decode('utf-8'))
        common = (receipt.get('schema') == 'fieldwork.schema-rehearsal/v1'
                  and receipt.get('live_database_touched') is False
                  and receipt.get('migration_sha256') == pins)
        executed_pass = common and receipt.get('status') == 'PASS'
        checker_only_failure = (
            common and receipt.get('status') == 'FAIL'
            and receipt.get('stage') == 'verify-preserved-data-and-privileges'
            and receipt.get('failure_class') == 'KeyError'
            and receipt.get('restore', {}).get('exit_code') == 0
            and receipt.get('restore', {}).get('objects_owned_by_source_database_owner') is True
            and receipt.get('restore', {}).get('pre_migration_public_tables', 0) >= 20
            and receipt.get('restore', {}).get('pre_migration_rows', 0) > 0
        )
        valid = executed_pass or checker_only_failure
        receipt = {'execution_report_sha256': sha(raw),
                   'disposition': 'executed_pass' if executed_pass else 'reviewed_ddl_committed_checker_failure' if checker_only_failure else 'refused'}
        code = 'MIGRATION_009_011_REHEARSAL_INVALID'
    else:
        text = raw.decode('utf-8')
        valid = ('Independent feature review' in text
                 and 'two findings from the first review are now fixed' in text
                 and 'pass re-review' in text
                 and text.count('RESOLVED BY SOURCE') >= 2
                 and all(digest_value in text for digest_value in pins.values()))
        receipt = {'review_document_sha256': sha(raw), 'reviewer_source_cleared': valid}
        code = 'MIGRATION_009_011_REVIEW_NOT_CLEARED'
    if not valid:
        raise ValueError(code)
    return receipt


def migrate_schema(args) -> dict:
    """Fresh backup then atomically apply the independently reviewed 009-011 set."""
    lock = require_lock()
    retained_pins = confirm_pins()
    pins = {name: sha((ROOT / 'migrations' / name).read_bytes())
            for name in SCHEMA_MIGRATION_PINS}
    if pins != SCHEMA_MIGRATION_PINS:
        raise ValueError('MIGRATION_009_011_SOURCE_PIN_MISMATCH')
    verify_schema_receipt(args.rehearsal_report, kind='rehearsal', pins=pins)
    verify_schema_receipt(args.review_receipt, kind='review', pins=pins)

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_label = 'schema-009-011-' + stamp
    backup_run = subprocess.run([sys.executable, '-m', 'tools.r5p_backup', backup_label], cwd=ROOT,
                                capture_output=True, text=True, check=False)
    if backup_run.returncode:
        raise RuntimeError('FRESH_BACKUP_FAILED')
    backup_dir = ROOT / 'var/snapshots'
    manifest_path = max(backup_dir.glob(backup_label + '-*.json'), key=lambda p: p.stat().st_mtime_ns)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    dump = ROOT / manifest['db']['path']
    if not dump.is_file() or sha(dump.read_bytes()) != manifest['db']['sha256']:
        raise ValueError('FRESH_BACKUP_DIGEST_MISMATCH')

    migration_backup = ROOT / '.local/real-data/activation-backups' / ('migrations-' + stamp)
    migration_backup.mkdir(parents=True, exist_ok=False)
    from fieldwork.scoped_authority import check_private
    check_private(migration_backup)
    all_pins = {**retained_pins, **pins}
    for name, expected in all_pins.items():
        source = ROOT / 'migrations' / name
        target = migration_backup / name
        target.write_bytes(source.read_bytes())
        if sha(target.read_bytes()) != expected:
            raise ValueError('MIGRATION_SOURCE_BACKUP_DIGEST_MISMATCH')

    from psycopg import connect
    dsn = private_operator_dsn()
    with connect(dsn) as conn:
        with conn.transaction():
            missing = conn.execute("""
                SELECT to_regnamespace('fw_real_worker_cap_v1') IS NULL
                    OR to_regclass('public.fw_runs') IS NULL
            """).fetchone()[0]
            already = conn.execute("""
                SELECT to_regclass('public.fw_real_image_inputs') IS NOT NULL
                    OR to_regclass('public.fw_workspace_settings') IS NOT NULL
                    OR to_regclass('public.fw_real_artifact_retention') IS NOT NULL
            """).fetchone()[0]
            if missing or already:
                raise ValueError('LIVE_SCHEMA_NOT_EXPECTED_PRE_ACTIVATION')
            before = counts(conn)
            for name in ('009_fresh_image_inference.sql', '010_workspace_controls.sql',
                         '011_real_artifact_retention.sql'):
                path = ROOT / 'migrations' / name
                body = schema_migration_body(path, enveloped=name in (
                    '009_fresh_image_inference.sql', '011_real_artifact_retention.sql'))
                conn.execute(body)
            after = counts(conn)
            if any(before.get(table) != after.get(table) for table in before):
                raise ValueError('MIGRATION_EXISTING_ROW_COUNTS_CHANGED')
            rls = conn.execute("""
                SELECT count(*)=4 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relname=ANY(%s)
                  AND c.relrowsecurity AND c.relforcerowsecurity
            """, (['fw_real_image_inputs','fw_workspace_settings','fw_workspace_settings_events','fw_real_artifact_retention'],)).fetchone()[0]
            admission = conn.execute("""
                SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='trg_workspace_run_admission_v1' AND NOT tgisinternal)
                   AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='trg_real_inference_retention_fence_v1' AND NOT tgisinternal)
            """).fetchone()[0]
            if not rls or not admission:
                raise ValueError('MIGRATION_POSTCONDITION_FAILED')
    receipt = {'status': 'applied', 'lock': lock, 'migrations': pins,
               'retained_migration_pins': retained_pins,
               'backup_manifest': str(manifest_path.relative_to(ROOT)),
               'migration_source_backup': str(migration_backup.relative_to(ROOT)),
               'backup_sha256': manifest['db']['sha256'], 'before_counts': before,
               'after_counts': after,
               'rehearsal_disposition': verify_schema_receipt(args.rehearsal_report, kind='rehearsal', pins=pins)['disposition'],
               'rehearsal_sha256': sha(args.rehearsal_report.read_bytes()),
               'review_sha256': sha(args.review_receipt.read_bytes()),
               'at_utc': datetime.now(timezone.utc).isoformat()}
    out_dir = ROOT / '.local/real-data/activation'
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / ('schema-migrations-' + stamp + '.json')
    out.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return {'status': 'applied', 'receipt': str(out), 'backup_sha256': receipt['backup_sha256'], 'migrations': pins}


def verify_qualified_review(path: Path) -> dict:
    raw = path.read_bytes()
    if sha(raw) != QUALIFIED_REVIEW_SHA256:
        raise ValueError('QUALIFIED_RUNTIME_REVIEW_SOURCE_CHANGED')
    text = raw.decode('utf-8')
    # Exact reviewed bytes are pinned above; do not require the reviewer to
    # reproduce a magic wording of the internally-called predicate's ACL.
    if ('QF-01' not in text or 'QF-02' not in text
            or 'Code review passes for this scoped review.' not in text):
        raise ValueError('QUALIFIED_RUNTIME_REVIEW_NOT_CLEARED')
    pinfile = ROOT / 'docs/qualified-release-runtime.sha256'
    pin_bytes = pinfile.read_bytes()
    if sha(pin_bytes) != QUALIFIED_RUNTIME_PINFILE_SHA256:
        raise ValueError('QUALIFIED_RUNTIME_PINFILE_CHANGED')
    pins = {}
    for line in pin_bytes.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})\s+([A-Za-z0-9_./-]+)', line)
        if not match:
            raise ValueError('QUALIFIED_RUNTIME_PINFILE_INVALID')
        expected, rel = match.groups()
        if rel in pins or Path(rel).is_absolute() or '..' in Path(rel).parts:
            raise ValueError('QUALIFIED_RUNTIME_PINFILE_INVALID')
        source = ROOT / rel
        if sha(source.read_bytes()) != expected:
            raise ValueError('QUALIFIED_RUNTIME_SOURCE_PIN_MISMATCH')
        pins[rel] = expected
    if (len(pins) < 15 or pins.get('migrations/012_qualified_release_inference.sql')
            != QUALIFIED_SCHEMA_MIGRATION_PINS['012_qualified_release_inference.sql']):
        raise ValueError('QUALIFIED_RUNTIME_PINSET_INCOMPLETE')
    return {'review_sha256': sha(raw), 'pinfile_sha256': sha(pin_bytes), 'source_count': len(pins),
            'migration_012_sha256': pins['migrations/012_qualified_release_inference.sql']}


def verify_qualified_rehearsal(path: Path, pins: dict[str, str]) -> dict:
    raw = path.read_bytes()
    receipt = json.loads(raw.decode('utf-8'))
    expected_retained = {name: sha((ROOT / 'migrations' / name).read_bytes())
                         for name in MIGRATION_PINS}
    common = (receipt.get('schema') == 'fieldwork.schema-rehearsal/v2'
              and receipt.get('live_database_touched') is False
              and receipt.get('migration_sha256') == pins
              and receipt.get('retained_migration_sha256') == expected_retained
              and receipt.get('stage') == 'complete'
              and receipt.get('transaction_atomicity') == '009+010+011+012 committed together'
              and receipt.get('ddl_transaction', {}).get('status') == 'committed'
              and receipt.get('ddl_transaction', {}).get('existing_table_counts_unchanged') is True
              and receipt.get('restore', {}).get('exit_code') == 0
              and receipt.get('restore', {}).get('restored_with_owners') is True
              and receipt.get('restore', {}).get('objects_owned_by_source_database_owner') is True
              and receipt.get('restore', {}).get('pre_migration_public_tables', 0) >= 20
              and receipt.get('restore', {}).get('pre_migration_rows', 0) > 0
              and receipt.get('owned_container_disposed') is True)
    executed_pass = (common and receipt.get('status') == 'PASS'
                     and receipt.get('all_new_tables_empty') is True
                     and receipt.get('all_rls_force_enabled') is True
                     and receipt.get('all_worker_definer_capabilities_correct') is True
                     and receipt.get('qualified_function_execute_grants_verified') is True
                     and receipt.get('qualified_release_guards_verified') is True
                     and receipt.get('noinherit_worker_capability_verified') is True
                     and receipt.get('admission_and_retention_triggers_verified') is True
                     and receipt.get('post_migration', {}).get('existing_table_preservation_pass') is True
                     and receipt.get('resume_admission_negative', {}).get('status') in ('executed_pass', 'not_feasible'))
    grant_map = receipt.get('post_migration', {}).get('qualified_function_execute_grants', {})
    expected_grant_map = {
        'fw_real_worker_cap_v1.qualified_image_profile_ok(jsonb,text,text)': False,
        'fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)': True,
        'fw_real_worker_cap_v1.complete_qualified_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text)': True,
    }
    checker_only = (common and sha(raw) == QUALIFIED_REHEARSAL_REVIEWED_FALSE_NEGATIVE_SHA256
                    and receipt.get('status') == 'FAIL'
                    and receipt.get('failure_class') is None and receipt.get('failure_code') is None
                    and receipt.get('all_new_tables_empty') is True
                    and receipt.get('all_rls_force_enabled') is True
                    and receipt.get('all_worker_definer_capabilities_correct') is True
                    and receipt.get('qualified_function_execute_grants_verified') is False
                    and receipt.get('qualified_release_guards_verified') is True
                    and receipt.get('noinherit_worker_capability_verified') is True
                    and receipt.get('admission_and_retention_triggers_verified') is True
                    and receipt.get('post_migration', {}).get('existing_table_preservation_pass') is True
                    and receipt.get('post_migration', {}).get('qualified_function_execute_grants') == expected_grant_map
                    and receipt.get('resume_admission_negative', {}).get('status') in ('executed_pass', 'not_feasible'))
    valid = executed_pass or checker_only
    if not valid:
        raise ValueError('QUALIFIED_SCHEMA_REHEARSAL_NOT_PASSING')
    return {'report_sha256': sha(raw),
            'disposition': 'executed_pass' if executed_pass else 'reviewed_ddl_committed_profile_grant_checker_false_negative',
            'migration_sha256': pins, 'retained_migration_sha256': expected_retained}


def activate_qualified_schema(args) -> dict:
    """Fresh-backup and atomically apply only reviewed qualified migration 012."""
    lock = require_lock()
    retained_pins = confirm_pins()
    pins = {name: sha((ROOT / 'migrations' / name).read_bytes())
            for name in QUALIFIED_SCHEMA_MIGRATION_PINS}
    if pins != QUALIFIED_SCHEMA_MIGRATION_PINS:
        raise ValueError('QUALIFIED_MIGRATION_SOURCE_PIN_MISMATCH')
    rehearsal = verify_qualified_rehearsal(args.rehearsal_report, pins)
    review = verify_qualified_review(args.review_receipt)

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_label = 'schema-qualified-012-' + stamp
    backup_run = subprocess.run([sys.executable, '-m', 'tools.r5p_backup', backup_label], cwd=ROOT,
                                capture_output=True, text=True, check=False)
    if backup_run.returncode:
        raise RuntimeError('FRESH_BACKUP_FAILED')
    backup_dir = ROOT / 'var/snapshots'
    manifest_path = max(backup_dir.glob(backup_label + '-*.json'), key=lambda p: p.stat().st_mtime_ns)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    dump = ROOT / manifest['db']['path']
    if not dump.is_file() or sha(dump.read_bytes()) != manifest['db']['sha256']:
        raise ValueError('FRESH_BACKUP_DIGEST_MISMATCH')

    source_backup = ROOT / '.local/real-data/activation-backups' / ('qualified-migration-' + stamp)
    source_backup.mkdir(parents=True, exist_ok=False)
    from fieldwork.scoped_authority import check_private
    check_private(source_backup)
    for name, expected in {**retained_pins, **pins}.items():
        source = ROOT / 'migrations' / name
        target = source_backup / name
        target.write_bytes(source.read_bytes())
        if sha(target.read_bytes()) != expected:
            raise ValueError('MIGRATION_SOURCE_BACKUP_DIGEST_MISMATCH')

    from psycopg import connect
    dsn = private_operator_dsn()
    signatures = {
        'profile': 'fw_real_worker_cap_v1.qualified_image_profile_ok(jsonb,text,text)',
        'input': 'fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)',
        'complete': 'fw_real_worker_cap_v1.complete_qualified_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text)',
    }
    with connect(dsn) as conn:
        with conn.transaction():
            ready = conn.execute("""
              SELECT to_regclass('public.fw_real_image_inputs') IS NOT NULL
                 AND to_regclass('public.fw_workspace_settings') IS NOT NULL
                 AND to_regclass('public.fw_real_artifact_retention') IS NOT NULL
                 AND to_regprocedure('fw_real_worker_cap_v1.image_inference_profile_ok(jsonb,text,text)') IS NOT NULL
                 AND to_regprocedure('fw_real_worker_cap_v1.qualified_image_profile_ok(jsonb,text,text)') IS NULL
                 AND to_regprocedure('fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)') IS NULL
                 AND to_regprocedure('fw_real_worker_cap_v1.complete_qualified_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text)') IS NULL
                 AND NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public'
                   AND tablename='fw_holdout_plans' AND policyname='fw_real_worker_qualified_plan')
            """).fetchone()[0]
            if not ready:
                raise ValueError('LIVE_SCHEMA_NOT_EXPECTED_FOR_QUALIFIED_012')
            before = counts(conn)
            body = schema_migration_body(ROOT / 'migrations/012_qualified_release_inference.sql', enveloped=True)
            conn.execute(body)
            after = counts(conn)
            if any(before.get(table) != after.get(table) for table in before):
                raise ValueError('QUALIFIED_MIGRATION_EXISTING_ROW_COUNTS_CHANGED')
            defs = {}
            for key, signature in signatures.items():
                row = conn.execute("""
                  SELECT r.rolname AS owner,p.prosecdef AS secdef,
                    NOT has_function_privilege('public',p.oid,'EXECUTE') AS no_public
                  FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid=to_regprocedure(%s)
                """, (signature,)).fetchone()
                defs[key] = bool(row and row[0] == 'fieldwork_real_worker_definer'
                                 and row[1] and row[2])
            legacy_false = conn.execute("""
              SELECT count(*)=2 AND bool_and(btrim(p.prosrc,E' \\t\\r\\n')='SELECT false')
              FROM pg_proc p WHERE p.oid=ANY(ARRAY[
                'fw_real_worker_cap_v1.inference_profile_ok(jsonb,text,text)'::regprocedure,
                'fw_real_worker_cap_v1.image_inference_profile_ok(jsonb,text,text)'::regprocedure])
            """).fetchone()[0]
            policy_ok = conn.execute("""
              SELECT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public'
                AND tablename='fw_holdout_plans' AND policyname='fw_real_worker_qualified_plan'
                AND 'fieldwork_real_worker_definer'=ANY(roles))
            """).fetchone()[0]
            # Worker logins call only the input/completion capability functions.
            # The profile predicate is SECURITY DEFINER-internal and must stay
            # ungranted to direct worker callers.
            grants_ok = all(conn.execute(
                "SELECT bool_and(has_function_privilege(principal,to_regprocedure(%s),'EXECUTE')) FROM fw_worker_cap_v1.scope",
                (signature,)).fetchone()[0]
                for signature in (signatures['input'], signatures['complete']))
            admission_ok = conn.execute("""
              SELECT position('qualified-release-image-inference/v1' in
                pg_get_functiondef('public.fw_workspace_run_admission_v1()'::regprocedure))>0
            """).fetchone()[0]
            if not (all(defs.values()) and legacy_false and policy_ok and grants_ok and admission_ok):
                diagnostic = ROOT / '.local/real-data/activation' / ('qualified-postconditions-' + stamp + '.json')
                diagnostic.parent.mkdir(parents=True,exist_ok=True)
                diagnostic.write_text(json.dumps({'defs':defs,'legacy_false':legacy_false,'policy_ok':policy_ok,
                                                 'grants_ok':grants_ok,'admission_ok':admission_ok},indent=2),encoding='utf-8')
                raise ValueError('QUALIFIED_MIGRATION_POSTCONDITION_FAILED')
    post_pins = {name: sha((ROOT / 'migrations' / name).read_bytes())
                 for name in {**retained_pins, **pins}}
    if post_pins != {**retained_pins, **pins}:
        raise ValueError('MIGRATION_SOURCE_CHANGED_DURING_ACTIVATION')
    receipt = {'status': 'applied', 'lock': lock, 'migration': pins,
               'retained_migration_pins': retained_pins,
               'qualified_runtime_review': review, 'rehearsal': rehearsal,
               'backup_manifest': str(manifest_path.relative_to(ROOT)),
               'migration_source_backup': str(source_backup.relative_to(ROOT)),
               'backup_sha256': manifest['db']['sha256'], 'before_counts': before,
               'after_counts': after, 'qualified_function_definer_acl': defs,
               'legacy_inference_profiles_disabled': legacy_false,
               'qualified_holdout_policy': policy_ok, 'worker_execute_grants': grants_ok,
               'qualified_admission_limit': admission_ok,
               'at_utc': datetime.now(timezone.utc).isoformat()}
    out_dir = ROOT / '.local/real-data/activation'
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / ('qualified-schema-012-' + stamp + '.json')
    out.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return {'status': 'applied', 'receipt': str(out), 'backup_sha256': receipt['backup_sha256'],
            'migration_sha256': pins, 'qualified_runtime_review_sha256': review['review_sha256']}


def activate_worker_rights_fix_014(args) -> dict:
    """Back up and apply only the reviewed, forward-only 014 runtime repair."""
    lock = require_lock()
    retained = confirm_pins()
    source = ROOT / 'migrations' / WORKER_RIGHTS_FIX_MIGRATION
    migration_sha = sha(source.read_bytes())
    if migration_sha != WORKER_RIGHTS_FIX_SHA256:
        raise ValueError('WORKER_RIGHTS_FIX_SOURCE_PIN_MISMATCH')
    for rel, expected in WORKER_RIGHTS_FIX_REVIEW_BASELINES.items():
        if sha((ROOT / rel).read_bytes()) != expected:
            raise ValueError('WORKER_RIGHTS_FIX_BASELINE_PIN_MISMATCH')

    review_raw = args.review_receipt.read_bytes()
    review = json.loads(review_raw)
    expected_sources = {**WORKER_RIGHTS_FIX_REVIEW_BASELINES,
                        'migrations/014_real_worker_rights_encoding.sql': migration_sha}
    if (review.get('schema') != 'fieldwork.real-worker-014-review/v1'
            or review.get('status') != 'PASS'
            or review.get('source_sha256') != expected_sources
            or review.get('migration_007_012_bytes_unchanged') is not True
            or review.get('protected_members_or_media_not_returned') is not True):
        raise ValueError('WORKER_RIGHTS_FIX_INDEPENDENT_REVIEW_REQUIRED')
    rehearsal_raw = args.rehearsal_report.read_bytes()
    rehearsal = json.loads(rehearsal_raw)
    if (rehearsal.get('schema') != 'fieldwork.real-worker-014-rehearsal/v1'
            or rehearsal.get('status') != 'PASS'
            or rehearsal.get('migration_sha256') != migration_sha
            or rehearsal.get('source_sha256') != expected_sources
            or rehearsal.get('existing_public_rows_preserved') is not True
            or rehearsal.get('typed_dataset_joins_pass') is not True
            or rehearsal.get('strict_base64_roundtrip_pass') is not True
            or rehearsal.get('function_hashes_after_match') is not True
            or rehearsal.get('protected_labels_or_media_not_read') is not True
            or rehearsal.get('protected_member_identifiers_not_returned') is not True
            or rehearsal.get('holdout_evaluation_not_performed') is not True):
        raise ValueError('WORKER_RIGHTS_FIX_REHEARSAL_REQUIRED')

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_label = 'real-worker-rights-014-' + stamp
    backup_run = subprocess.run([sys.executable, '-m', 'tools.r5p_backup', backup_label], cwd=ROOT,
                                capture_output=True, text=True, check=False)
    if backup_run.returncode:
        raise RuntimeError('FRESH_BACKUP_FAILED')
    backup_dir = ROOT / 'var/snapshots'
    manifest_path = max(backup_dir.glob(backup_label + '-*.json'), key=lambda p: p.stat().st_mtime_ns)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    dump = ROOT / manifest['db']['path']
    if not dump.is_file() or sha(dump.read_bytes()) != manifest['db']['sha256']:
        raise ValueError('FRESH_BACKUP_DIGEST_MISMATCH')

    source_backup = ROOT / '.local/real-data/activation-backups' / ('worker-rights-014-' + stamp)
    source_backup.mkdir(parents=True, exist_ok=False)
    from fieldwork.scoped_authority import check_private
    check_private(source_backup)
    for rel, expected in {**retained, **WORKER_RIGHTS_FIX_REVIEW_BASELINES,
                          'migrations/014_real_worker_rights_encoding.sql': migration_sha}.items():
        relative = Path(rel)
        original = (ROOT / relative if relative.parts[0] == 'migrations'
                    else ROOT / 'migrations' / relative)
        target = source_backup / Path(rel).name
        target.write_bytes(original.read_bytes())
        if sha(target.read_bytes()) != expected:
            raise ValueError('WORKER_RIGHTS_FIX_SOURCE_BACKUP_MISMATCH')

    from psycopg import connect
    signatures = tuple(WORKER_RIGHTS_FIX_FUNCTION_HASHES_BEFORE)
    dsn = private_operator_dsn()
    with connect(dsn) as conn:
        with conn.transaction():
            ready = conn.execute("""
              SELECT to_regclass('public.fw_real_image_inputs') IS NOT NULL
                 AND to_regprocedure('fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)') IS NOT NULL
                 AND to_regprocedure('fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)') IS NOT NULL
                 AND NOT EXISTS(SELECT 1 FROM public.fw_runs WHERE config->>'scope' IN
                   ('real-training/v1','real-inference/v1','real-image-inference/v1','qualified-release-image-inference/v1')
                   AND state IN ('queued','leased','running','cancel_requested'))
                 AND NOT EXISTS(SELECT 1 FROM public.fw_slot WHERE id=1 AND run IS NOT NULL)
            """).fetchone()[0]
            if not ready:
                raise ValueError('LIVE_STATE_NOT_IDLE_FOR_WORKER_RIGHTS_FIX')
            types = conn.execute("""
              SELECT
                (SELECT udt_name FROM information_schema.columns WHERE table_schema='public' AND table_name='fw_real_image_inputs' AND column_name='dataset_id') AS input_dataset,
                (SELECT udt_name FROM information_schema.columns WHERE table_schema='public' AND table_name='fw_rights_assets' AND column_name='dataset_id') AS asset_dataset,
                (SELECT udt_name FROM information_schema.columns WHERE table_schema='public' AND table_name='fw_rights_decisions' AND column_name='dataset_id') AS decision_dataset
            """).fetchone()
            if tuple(types) != ('uuid', 'text', 'text'):
                raise ValueError('WORKER_RIGHTS_FIX_COLUMN_TYPES_CHANGED')
            before_defs = {}
            for signature in signatures:
                row = conn.execute('SELECT prosrc FROM pg_proc WHERE oid=to_regprocedure(%s)',
                                   (signature,)).fetchone()
                before_defs[signature] = sha(row[0].encode()) if row else None
            if before_defs != WORKER_RIGHTS_FIX_FUNCTION_HASHES_BEFORE:
                raise ValueError('WORKER_RIGHTS_FIX_BASE_FUNCTION_CHANGED')
            before = counts(conn)
            conn.execute(migration_transaction_body(source))
            after = counts(conn)
            if any(before.get(table) != after.get(table) for table in before):
                raise ValueError('WORKER_RIGHTS_FIX_PUBLIC_ROWS_CHANGED')
            after_defs = {}
            safe_functions = {}
            for signature in signatures:
                row = conn.execute("""
                  SELECT p.prosrc,r.rolname AS owner,p.prosecdef,p.proconfig,
                    NOT has_function_privilege('public',p.oid,'EXECUTE') AS no_public
                  FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid=to_regprocedure(%s)
                """, (signature,)).fetchone()
                after_defs[signature] = sha(row[0].encode()) if row else None
                safe_functions[signature] = bool(row and row[1]=='fieldwork_real_worker_definer'
                    and row[2] and row[3]==['search_path=pg_catalog, pg_temp'] and row[4])
            if after_defs != WORKER_RIGHTS_FIX_FUNCTION_HASHES_AFTER or not all(safe_functions.values()):
                raise ValueError('WORKER_RIGHTS_FIX_POSTCONDITION_FAILED')
            grants = all(conn.execute(
                "SELECT bool_and(has_function_privilege(principal,to_regprocedure(%s),'EXECUTE')) FROM fw_worker_cap_v1.scope",
                (signature,)).fetchone()[0] for signature in signatures)
            if not grants:
                raise ValueError('WORKER_RIGHTS_FIX_WORKER_GRANTS_CHANGED')

    if sha(source.read_bytes()) != migration_sha:
        raise ValueError('WORKER_RIGHTS_FIX_SOURCE_CHANGED_DURING_ACTIVATION')
    receipt = {'status':'applied','lock':lock,'migration_sha256':migration_sha,
               'source_baselines':WORKER_RIGHTS_FIX_REVIEW_BASELINES,
               'review_sha256':sha(review_raw),'rehearsal_sha256':sha(rehearsal_raw),
               'backup_manifest':str(manifest_path.relative_to(ROOT)),
               'backup_sha256':manifest['db']['sha256'],
               'migration_source_backup':str(source_backup.relative_to(ROOT)),
               'before_counts':before,'after_counts':after,
               'function_hashes_before':before_defs,'function_hashes_after':after_defs,
               'function_security_postconditions':safe_functions,
               'worker_execute_grants_preserved':grants,
               'at_utc':datetime.now(timezone.utc).isoformat()}
    out_dir=ROOT/'.local/real-data/activation'; out_dir.mkdir(parents=True,exist_ok=True)
    out=out_dir/('worker-rights-014-'+stamp+'.json')
    out.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    return {'status':'applied','receipt':str(out),'backup_sha256':receipt['backup_sha256'],
            'migration_sha256':migration_sha,'review_sha256':receipt['review_sha256'],
            'rehearsal_sha256':receipt['rehearsal_sha256']}


def activate_worker_row_lock_015(args) -> dict:
    """Fresh-backup and atomically apply the reviewed narrow FOR SHARE grant."""
    lock = require_lock()
    retained = confirm_pins()
    source = ROOT / 'migrations' / WORKER_ROW_LOCK_MIGRATION
    migration_sha = sha(source.read_bytes())
    if migration_sha != WORKER_ROW_LOCK_SHA256:
        raise ValueError('WORKER_ROW_LOCK_SOURCE_PIN_MISMATCH')
    baselines = dict(WORKER_ROW_LOCK_SOURCE_BASELINES)
    for rel, expected in baselines.items():
        if sha((ROOT / rel).read_bytes()) != expected:
            raise ValueError('WORKER_ROW_LOCK_BASELINE_PIN_MISMATCH')
    review_raw = args.review_receipt.read_bytes()
    review = json.loads(review_raw)
    expected_sources = {**baselines, 'migrations/' + WORKER_ROW_LOCK_MIGRATION: migration_sha}
    if (review.get('schema') != 'fieldwork.real-worker-row-lock-015-review/v1'
            or review.get('status') != 'PASS'
            or review.get('source_sha256') != expected_sources
            or review.get('rights_locks_preserved') is not True
            or review.get('only_inert_capability_columns_added') is not True
            or review.get('public_execute_revoked') is not True
            or review.get('protected_rows_or_media_not_read') is not True):
        raise ValueError('WORKER_ROW_LOCK_INDEPENDENT_REVIEW_REQUIRED')
    rehearsal_raw = args.rehearsal_report.read_bytes()
    rehearsal = json.loads(rehearsal_raw)
    if (rehearsal.get('schema') != 'fieldwork.real-worker-row-lock-015-rehearsal/v1'
            or rehearsal.get('status') != 'PASS'
            or rehearsal.get('migration_sha256') != migration_sha
            or rehearsal.get('source_sha256') != expected_sources
            or rehearsal.get('existing_public_rows_preserved') is not True
            or rehearsal.get('scoped_for_share_probe_passed') is not True
            or rehearsal.get('inert_capability_update_rejected') is not True
            or rehearsal.get('business_column_update_denied') is not True
            or rehearsal.get('rights_state_unchanged') is not True
            or rehearsal.get('protected_rows_or_media_not_read') is not True):
        raise ValueError('WORKER_ROW_LOCK_REHEARSAL_REQUIRED')

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_label = 'real-worker-row-lock-015-' + stamp
    backup_run = subprocess.run([sys.executable, '-m', 'tools.r5p_backup', backup_label], cwd=ROOT,
                                capture_output=True, text=True, check=False)
    if backup_run.returncode:
        raise RuntimeError('FRESH_BACKUP_FAILED')
    manifest_path = max((ROOT/'var/snapshots').glob(backup_label+'-*.json'),
                        key=lambda p:p.stat().st_mtime_ns)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    dump = ROOT / manifest['db']['path']
    if (manifest.get('container') != 'fieldwork-postgres' or manifest.get('database') != 'fieldwork'
            or not dump.is_file() or sha(dump.read_bytes()) != manifest['db']['sha256']):
        raise ValueError('FRESH_BACKUP_DIGEST_MISMATCH')
    source_backup = ROOT/'.local/real-data/activation-backups'/('worker-row-lock-015-'+stamp)
    source_backup.mkdir(parents=True, exist_ok=False)
    for rel, expected in {**retained, **baselines,
            'migrations/'+WORKER_ROW_LOCK_MIGRATION:migration_sha}.items():
        original = (ROOT/rel if rel.startswith('migrations/') else ROOT/'migrations'/rel)
        target = source_backup/Path(rel).name
        target.write_bytes(original.read_bytes())
        if sha(target.read_bytes()) != expected:
            raise ValueError('WORKER_ROW_LOCK_SOURCE_BACKUP_MISMATCH')

    from psycopg import connect
    signatures = (
        'fw_real_worker_cap_v1.complete_qualified_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text)',
        'fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)',
        'fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)',
    )
    tables = ('fw_rights_datasets','fw_rights_assets','fw_rights_decisions')
    business_columns = {'fw_rights_datasets':'dataset_id','fw_rights_assets':'member_id',
                        'fw_rights_decisions':'member_id'}
    dsn = private_operator_dsn()
    with connect(dsn) as conn:
        with conn.transaction():
            idle = conn.execute("""
              SELECT NOT EXISTS(SELECT 1 FROM public.fw_runs WHERE config->>'scope' IN
                ('real-training/v1','real-inference/v1','real-image-inference/v1','qualified-release-image-inference/v1')
                AND state IN ('queued','leased','running','cancel_requested'))
                AND NOT EXISTS(SELECT 1 FROM public.fw_slot WHERE id=1 AND run IS NOT NULL)
            """).fetchone()[0]
            if not idle:
                raise ValueError('LIVE_STATE_NOT_IDLE_FOR_WORKER_ROW_LOCK_FIX')
            before_counts = counts(conn)
            before_functions = {}
            for signature in signatures:
                row = conn.execute('SELECT prosrc FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure(%s)',
                                   (signature,)).fetchone()
                if not row:
                    raise ValueError('WORKER_ROW_LOCK_BASE_FUNCTION_MISSING')
                before_functions[signature] = sha(row[0].encode())
            conn.execute(migration_transaction_body(source))
            after_counts = counts(conn)
            if before_counts != after_counts:
                raise ValueError('WORKER_ROW_LOCK_PUBLIC_ROWS_CHANGED')
            post = {}
            for table in tables:
                row = conn.execute("""
                  SELECT c.relrowsecurity,c.relforcerowsecurity,
                    has_column_privilege('fieldwork_real_worker_definer',%s,'row_lock_capability','UPDATE'),
                    has_column_privilege('fieldwork_real_worker_definer',%s,%s,'UPDATE'),
                    (SELECT a.attnotnull AND pg_catalog.pg_get_expr(d.adbin,d.adrelid)='false'
                     FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d
                       ON d.adrelid=a.attrelid AND d.adnum=a.attnum
                     WHERE a.attrelid=c.oid AND a.attname='row_lock_capability' AND NOT a.attisdropped),
                    (SELECT count(*) FROM pg_catalog.pg_trigger tr
                     WHERE tr.tgrelid=c.oid AND NOT tr.tgisinternal
                       AND tr.tgname='fw015_reject_row_lock_capability' AND tr.tgenabled='O'
                       AND tr.tgqual IS NULL)
                  FROM pg_catalog.pg_class c WHERE c.oid=pg_catalog.to_regclass(%s)
                """,('public.'+table,'public.'+table,business_columns[table],'public.'+table)).fetchone()
                post[table] = {'rls':row[0],'force_rls':row[1],'capability_update':row[2],
                    'business_column_update':row[3],'not_null_default_false':row[4],
                    'unconditional_guard_trigger_count':row[5]}
            if any(not (v['rls'] and v['force_rls'] and v['capability_update']
                       and not v['business_column_update'] and v['not_null_default_false']
                       and v['unconditional_guard_trigger_count']==1) for v in post.values()):
                raise ValueError('WORKER_ROW_LOCK_POSTCONDITION_FAILED')
            guard = conn.execute("""
              SELECT r.rolname,p.prosecdef,p.proconfig,
                NOT pg_catalog.has_function_privilege('public',p.oid,'EXECUTE') AS no_public
              FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid=p.proowner
              WHERE p.oid='public.fw015_reject_row_lock_capability_mutation()'::regprocedure
            """).fetchone()
            if not guard or guard[0]!='fieldwork' or guard[1] or guard[2]!=['search_path=pg_catalog, pg_temp'] or not guard[3]:
                raise ValueError('WORKER_ROW_LOCK_GUARD_FUNCTION_POSTCONDITION_FAILED')
            after_functions = {}
            for signature in signatures:
                row = conn.execute('SELECT prosrc FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure(%s)',
                                   (signature,)).fetchone()
                after_functions[signature] = sha(row[0].encode()) if row else None
            if after_functions != before_functions:
                raise ValueError('WORKER_ROW_LOCK_EXISTING_FUNCTION_CHANGED')

    if sha(source.read_bytes()) != migration_sha:
        raise ValueError('WORKER_ROW_LOCK_SOURCE_CHANGED_DURING_ACTIVATION')
    receipt = {'status':'applied','lock':lock,'migration_sha256':migration_sha,
        'source_baselines':baselines,'review_sha256':sha(review_raw),'rehearsal_sha256':sha(rehearsal_raw),
        'backup_manifest':str(manifest_path.relative_to(ROOT)),
        'backup_sha256':manifest['db']['sha256'],'migration_source_backup':str(source_backup.relative_to(ROOT)),
        'before_counts':before_counts,'after_counts':after_counts,
        'rights_table_postconditions':post,'guard_function_owner':'fieldwork',
        'guard_function_security_definer':False,'guard_function_public_execute':False,
        'existing_function_hashes_before':before_functions,'existing_function_hashes_after':after_functions,
        'at_utc':datetime.now(timezone.utc).isoformat()}
    out_dir=ROOT/'.local/real-data/activation';out_dir.mkdir(parents=True,exist_ok=True)
    out=out_dir/('worker-row-lock-015-'+stamp+'.json')
    out.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    return {'status':'applied','receipt':str(out),'backup_sha256':receipt['backup_sha256'],
        'migration_sha256':migration_sha,'review_sha256':receipt['review_sha256'],
        'rehearsal_sha256':receipt['rehearsal_sha256']}


def verify_007_receipt(path: Path) -> None:
    receipt = json.loads(path.read_text(encoding='utf-8'))
    if (receipt.get('result') != 'PASS' or receipt.get('container_removed') is not True
            or receipt.get('migration_sha256_before') != MIGRATION_PINS['007_real_run_worker.sql']
            or receipt.get('migration_sha256_after') != MIGRATION_PINS['007_real_run_worker.sql']
            or receipt.get('steps', [{}])[-1].get('migration_apply_exit') != 0):
        raise ValueError('MIGRATION_007_REHEARSAL_RECEIPT_INVALID')


def verify_008_receipt(path: Path) -> None:
    receipt = json.loads(path.read_text(encoding='utf-8'))
    if (receipt.get('schema') != 'fieldwork.w3-catalog-import-receipt/v1'
            or receipt.get('status') != 'REHEARSAL_PASS'
            or receipt.get('live_write_performed') is not False
            or receipt.get('intake_compatibility_migration_sha256') != MIGRATION_PINS['008_predecode_intake_results.sql']
            or receipt.get('verified', {}).get('aggregate_match') is not True):
        raise ValueError('MIGRATION_008_REHEARSAL_RECEIPT_INVALID')


def migrate(args) -> dict:
    """Fresh-backup then transactionally apply the rehearsed 007/008 pair."""
    lock = require_lock()
    pins = confirm_pins()
    verify_007_receipt(args.rehearsal_007)
    verify_008_receipt(args.rehearsal_008)
    # The existing 003/006 pass is a prerequisite; exact applied receipt is pinned.
    prior = json.loads(args.prior_006_receipt.read_text(encoding='utf-8'))
    if prior.get('status') != 'applied' or prior.get('migrations', {}).get('003_signed_rights.sql') != pins['003_signed_rights.sql'] or prior.get('migrations', {}).get('006_real_data_api.sql') != pins['006_real_data_api.sql']:
        raise ValueError('003_006_APPLIED_RECEIPT_INVALID')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_label = 'real-activation-' + stamp
    backup_run = subprocess.run([sys.executable, '-m', 'tools.r5p_backup', backup_label], cwd=ROOT,
                                capture_output=True, text=True, check=False)
    if backup_run.returncode:
        raise RuntimeError('FRESH_BACKUP_FAILED')
    backup = ROOT / 'var/snapshots'
    manifest_path = max(backup.glob(backup_label + '-*.json'), key=lambda p: p.stat().st_mtime_ns)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    dump = ROOT / manifest['db']['path']
    if not dump.is_file() or sha(dump.read_bytes()) != manifest['db']['sha256']:
        raise ValueError('FRESH_BACKUP_DIGEST_MISMATCH')
    migration_backup = ROOT / '.local/real-data/activation-backups' / ('migrations-' + stamp)
    migration_backup.mkdir(parents=True, exist_ok=False)
    from fieldwork.scoped_authority import check_private
    check_private(migration_backup)
    for name in ('007_real_run_worker.sql', '008_predecode_intake_results.sql'):
        source = ROOT / 'migrations' / name
        target = migration_backup / name
        target.write_bytes(source.read_bytes())
        if sha(target.read_bytes()) != pins[name]:
            raise ValueError('MIGRATION_BACKUP_DIGEST_MISMATCH')
    from psycopg import connect
    dsn = private_operator_dsn()
    with connect(dsn) as conn:
        with conn.transaction():
            # Refuse a repeat or a mixed state. Migration 007 is one-time; 008 is a
            # forward function replacement. No migration ledger is fabricated.
            exists = conn.execute("SELECT to_regnamespace('fw_real_worker_cap_v1') IS NOT NULL").fetchone()[0]
            fn = conn.execute("SELECT to_regprocedure('fw_intake_cap_v1.batch_guard()') IS NOT NULL").fetchone()[0]
            if exists or not fn:
                raise ValueError('LIVE_SCHEMA_NOT_EXPECTED_PRE_ACTIVATION')
            old_guard = sql_function_body(ROOT / 'migrations/006_real_data_api.sql',
                                          'fw_intake_cap_v1.batch_guard')
            actual_old = conn.execute("SELECT prosrc FROM pg_catalog.pg_proc WHERE oid='fw_intake_cap_v1.batch_guard()'::regprocedure").fetchone()[0]
            if actual_old.strip() != old_guard:
                raise ValueError('APPLIED_006_FUNCTION_BODY_DRIFT')
            before = counts(conn)
            conn.execute(migration_transaction_body(ROOT / 'migrations/007_real_run_worker.sql'))
            conn.execute(migration_transaction_body(ROOT / 'migrations/008_predecode_intake_results.sql'))
            new_guard = sql_function_body(ROOT / 'migrations/008_predecode_intake_results.sql',
                                          'fw_intake_cap_v1.batch_guard')
            actual_new = conn.execute("SELECT prosrc FROM pg_catalog.pg_proc WHERE oid='fw_intake_cap_v1.batch_guard()'::regprocedure").fetchone()[0]
            if actual_new.strip() != new_guard:
                raise ValueError('APPLIED_008_FUNCTION_BODY_MISMATCH')
            after = counts(conn)
            if before != after:
                raise ValueError('MIGRATION_ROW_COUNTS_CHANGED')
    receipt = {'status': 'applied', 'lock': lock, 'migrations': pins,
               'backup_manifest': str(manifest_path.relative_to(ROOT)),
               'migration_source_backup': str(migration_backup.relative_to(ROOT)),
               'backup_sha256': manifest['db']['sha256'], 'before_counts': before,
               'after_counts': after, 'at_utc': datetime.now(timezone.utc).isoformat()}
    out_dir = ROOT / '.local/real-data/activation'
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / ('migrations-' + stamp + '.json')
    out.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return {'status': 'applied', 'receipt': str(out), 'backup_sha256': receipt['backup_sha256'], 'migrations': pins}


def image_present(image_id: str) -> None:
    if not IMAGE_ID.fullmatch(image_id):
        raise ValueError('IMAGE_CONFIG_ID_INVALID')
    p = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image_id],
                       capture_output=True, text=True, check=False)
    if p.returncode or p.stdout.strip() != image_id:
        raise ValueError('PINNED_IMAGE_NOT_PRESENT')


def run_owned(args: list[str], *, env=None) -> dict:
    require_lock()
    p = subprocess.run(args, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, check=False)
    # Do not echo subprocess output: configuration and database exceptions can be sensitive.
    if p.returncode:
        raise RuntimeError('PRODUCT_COMMAND_FAILED')
    return {'status': 'completed', 'exit_code': 0}


def provision_intake(args) -> dict:
    require_lock()
    image_present(args.decoder_image_id)
    # Provisioning validates that these C: directories already exist and are
    # private. Create only the four product-owned roots below .local/real-data.
    from fieldwork.scoped_authority import check_private
    real_root = ROOT / '.local/real-data'
    real_root.mkdir(parents=True, exist_ok=True)
    check_private(real_root)
    for name in ('uploads', 'spool', 'quarantine', 'media'):
        path = real_root / name
        path.mkdir(exist_ok=True)
        if path.is_symlink():
            raise ValueError('INTAKE_ROOT_REPARSE_POINT')
        check_private(path)
    authority = ROOT / '.local/real-data/intake-authority.json'
    return run_owned([sys.executable, '-m', 'fieldwork.newintake_worker', '--provision',
        '--operator-file', str(ROOT / '.local.json'), '--authority-file', str(authority),
        '--workspace', WORKSPACE, '--upload-root', str(ROOT / '.local/real-data/uploads'),
        '--spool-root', str(ROOT / '.local/real-data/spool'),
        '--quarantine-root', str(ROOT / '.local/real-data/quarantine'),
        '--media-root', str(ROOT / '.local/real-data/media'),
        '--rights-registry-path', str(ROOT / 'var/commons_r5/rights/reviewers.json'),
        '--decoder-image-id', args.decoder_image_id])


def _authority_arg_matches(raw: str, authority_path: Path) -> bool:
    try:
        return Path(raw).resolve(strict=True) == authority_path.resolve(strict=True)
    except OSError:
        return False


def _issuer_cli(command: list[str], authority_path: Path) -> dict | None:
    """Recognize only the exact worker_identity serve command for this authority."""
    try:
        module_at = command.index('fieldwork.worker_identity')
        if module_at < 1 or command[module_at - 1] != '-m' or command[module_at + 1] != 'serve':
            return None
        tail = command[module_at + 2:]
        values = {}
        i = 0
        while i < len(tail):
            key = tail[i]
            if not key.startswith('--') or i + 1 >= len(tail) or key in values:
                return None
            values[key] = tail[i + 1]
            i += 2
        required = {'--authority-file', '--worker-heartbeat', '--interval'}
        optional = {'--operator-file', '--ttl-seconds'}
        if not required.issubset(values) or set(values) - required - optional:
            return None
        if not _authority_arg_matches(values['--authority-file'], authority_path):
            return None
        heartbeat = Path(values['--worker-heartbeat']).resolve(strict=True)
        if heartbeat != (ROOT / 'var/worker.json').resolve(strict=True):
            return None
        if '--operator-file' in values and Path(values['--operator-file']).resolve(strict=True) != (ROOT / '.local.json').resolve(strict=True):
            return None
        from fieldwork.worker_identity import MAX_TTL
        interval = int(values['--interval'])
        ttl = int(values.get('--ttl-seconds', str(MAX_TTL)))
        if interval not in (30, 60) or ttl != MAX_TTL or interval >= ttl:
            return None
        # Windows' venv redirector and its base interpreter use different argv[0]
        # values while preserving the exact module and option vector.
        return {'command': list(command), 'cli_tail': list(command[1:]),
                'heartbeat': heartbeat}
    except (ValueError, OSError):
        return None


def _inspect_owned_issuer(authority_path: Path) -> dict:
    import psutil
    runtime_path = ROOT / 'var/runtime-worker-issuer.json'
    runtime = json.loads(runtime_path.read_text(encoding='utf-8'))
    if (runtime.get('identity') != 'scoped-worker-v1' or type(runtime.get('pid')) is not int
            or type(runtime.get('create_time')) not in (int, float)):
        raise ValueError('ISSUER_RUNTIME_IDENTITY_INVALID')
    matches = []
    for proc in psutil.process_iter(['pid', 'name']):
        name = str(proc.info.get('name') or '').casefold()
        if 'python' not in name:
            continue
        try:
            command = proc.cmdline()
            cwd = Path(proc.cwd()).resolve()
            candidate = _issuer_cli(command, authority_path) if cwd == ROOT.resolve() else None
            if candidate is not None:
                matches.append((proc, candidate))
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            # We cannot prove uniqueness while a local Python process is opaque.
            raise ValueError('ISSUER_PROCESS_INVENTORY_INCOMPLETE') from None
    if not 1 <= len(matches) <= 2:
        raise ValueError('ISSUER_FAMILY_SIZE_INVALID')
    actual_matches = [(proc, candidate) for proc, candidate in matches
                      if proc.pid == runtime['pid'] and abs(proc.create_time() - runtime['create_time']) < .01]
    if len(actual_matches) != 1:
        raise ValueError('ISSUER_NOT_MATCHED_TO_RUNTIME_RECEIPT')
    proc, candidate = actual_matches[0]
    if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
        raise ValueError('ISSUER_RUNTIME_PROCESS_NOT_LIVE')
    family = [{'process': p, **c} for p, c in matches]
    launch_pid = runtime.get('launch_pid')
    launch_created = runtime.get('launch_create_time')
    launcher = None
    if len(matches) == 2:
        launcher_matches = [(p, c) for p, c in matches
                            if p.pid == launch_pid and type(launch_created) in (int, float)
                            and abs(p.create_time() - launch_created) < .01]
        if len(launcher_matches) != 1 or launch_pid == runtime['pid']:
            raise ValueError('ISSUER_FAMILY_LAUNCHER_MISMATCH')
        launcher, launcher_candidate = launcher_matches[0]
        try:
            actual_parent = proc.parent()
            descendants = launcher.children(recursive=True)
        except psutil.Error:
            raise ValueError('ISSUER_FAMILY_UNINSPECTABLE') from None
        try:
            matching_python_descendants = []
            ancillary = []
            for desc in descendants:
                name = str(desc.name()).casefold()
                desc_candidate = None
                if 'python' in name:
                    try:
                        if Path(desc.cwd()).resolve() == ROOT.resolve():
                            desc_candidate = _issuer_cli(desc.cmdline(), authority_path)
                    except psutil.Error:
                        raise ValueError('ISSUER_FAMILY_UNINSPECTABLE') from None
                    if desc_candidate is not None:
                        matching_python_descendants.append((desc, desc_candidate))
                    else:
                        raise ValueError('ISSUER_FAMILY_UNKNOWN_DESCENDANT')
                elif name in ('conhost.exe', 'conhost'):
                    ancillary.append(desc)
                else:
                    raise ValueError('ISSUER_FAMILY_UNKNOWN_DESCENDANT')
            # The only bounded ancillary Windows child accepted is one conhost
            # directly owned by the recorded issuer interpreter.
            if len(ancillary) > 1:
                raise ValueError('ISSUER_FAMILY_ANCILLARY_COUNT_INVALID')
            if ancillary:
                conhost_parent = ancillary[0].parent()
                if (conhost_parent is None or conhost_parent.pid != proc.pid
                        or abs(conhost_parent.create_time() - proc.create_time()) >= .01):
                    raise ValueError('ISSUER_FAMILY_ANCILLARY_PARENT_INVALID')
        except psutil.Error:
            raise ValueError('ISSUER_FAMILY_UNINSPECTABLE') from None
        if (actual_parent is None or actual_parent.pid != launcher.pid
                or abs(actual_parent.create_time() - launcher.create_time()) >= .01
                or len(matching_python_descendants) != 1
                or matching_python_descendants[0][0].pid != proc.pid
                or abs(matching_python_descendants[0][0].create_time() - proc.create_time()) >= .01
                or launcher_candidate['cli_tail'] != candidate['cli_tail']
                or launcher_candidate['heartbeat'] != candidate['heartbeat']):
            raise ValueError('ISSUER_FAMILY_NOT_SINGLE_PARENT_CHILD')
    elif launch_pid != runtime['pid']:
        # A previous redirector may have exited and been reaped. If that exact
        # launch PID+birth is still live but no longer matches, the family is
        # incomplete and must not be touched.
        if type(launch_pid) is not int or type(launch_created) not in (int, float):
            raise ValueError('ISSUER_RUNTIME_LAUNCH_IDENTITY_INVALID')
        try:
            possible_launcher = psutil.Process(launch_pid)
            if (abs(possible_launcher.create_time() - launch_created) < .01
                    and possible_launcher.is_running()):
                raise ValueError('ISSUER_FAMILY_LAUNCHER_UNMATCHED')
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            raise ValueError('ISSUER_FAMILY_UNINSPECTABLE') from None
    try:
        if launcher is None:
            descendants = proc.children(recursive=True)
            if len(descendants) > 1:
                raise ValueError('ISSUER_FAMILY_ANCILLARY_COUNT_INVALID')
            for desc in descendants:
                if str(desc.name()).casefold() not in ('conhost.exe', 'conhost'):
                    raise ValueError('ISSUER_FAMILY_UNKNOWN_DESCENDANT')
                desc_parent = desc.parent()
                if (desc_parent is None or desc_parent.pid != proc.pid
                        or abs(desc_parent.create_time() - proc.create_time()) >= .01):
                    raise ValueError('ISSUER_FAMILY_ANCILLARY_PARENT_INVALID')
    except psutil.Error:
        raise ValueError('ISSUER_FAMILY_UNINSPECTABLE') from None
    # The launcher can exit after detaching the long-lived issuer. PID birth,
    # exact command, private authority path, product cwd and runtime receipt bind
    # ownership; the historical parent may legitimately have been reparented.
    launch_command = launcher_candidate['command'] if launcher is not None else candidate['command']
    return {'process': proc, 'runtime': runtime, 'family': family,
            'launcher': launcher, 'launch_command': launch_command, **candidate}


def _quiesce_issuer(state: dict) -> None:
    import psutil
    proc = state['process']
    created = state['runtime']['create_time']
    try:
        proc.terminate()
        proc.wait(timeout=12)
    except psutil.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (psutil.Error, psutil.TimeoutExpired):
            raise ValueError('ISSUER_EXIT_NOT_PROVEN') from None
    except psutil.Error:
        raise ValueError('ISSUER_TERMINATION_REFUSED') from None
    _require_process_gone(proc.pid, created)
    launcher = state.get('launcher')
    if launcher is not None:
        launch_pid = launcher.pid
        launch_created = launcher.create_time()
        try:
            launcher.wait(timeout=12)
        except psutil.NoSuchProcess:
            pass
        except psutil.TimeoutExpired:
            # This is the verified single redirector parent from the same
            # issuer family, not a broad process-tree cleanup.
            try:
                launcher.terminate()
                launcher.wait(timeout=5)
            except psutil.TimeoutExpired:
                try:
                    launcher.kill()
                    launcher.wait(timeout=5)
                except (psutil.Error, psutil.TimeoutExpired):
                    raise ValueError('ISSUER_REDIRECTOR_EXIT_NOT_PROVEN') from None
            except psutil.Error:
                raise ValueError('ISSUER_REDIRECTOR_TERMINATION_REFUSED') from None
        except psutil.Error:
            raise ValueError('ISSUER_REDIRECTOR_EXIT_NOT_PROVEN') from None
        _require_process_gone(launch_pid, launch_created)


def _require_process_gone(pid: int, created: float) -> None:
    import psutil
    try:
        current = psutil.Process(pid)
        if abs(current.create_time() - created) < .01 and current.is_running():
            raise ValueError('ISSUER_FAMILY_EXIT_NOT_PROVEN')
    except psutil.NoSuchProcess:
        return
    except psutil.AccessDenied:
        raise ValueError('ISSUER_FAMILY_EXIT_NOT_PROVEN') from None


def _issuer_family_gone(state: dict) -> bool:
    import psutil
    for member in state.get('family', []):
        proc = member['process']
        try:
            created = proc.create_time()
            current = psutil.Process(proc.pid)
            if abs(current.create_time() - created) < .01 and current.is_running():
                return False
        except psutil.NoSuchProcess:
            continue
        except psutil.Error:
            return False
    return True


def _restart_issuer(state: dict, authority_path: Path, stamp: str) -> dict:
    import psutil
    old_pid = state['runtime']['pid']
    argv = state['launch_command']
    expected_family_size = len(state['family'])
    log_dir = ROOT / 'var/activation'
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f'worker-issuer-scope-{stamp}.out.log'
    env = {k: os.environ[k] for k in ('SYSTEMROOT', 'PATH', 'TEMP', 'TMP', 'USERPROFILE') if k in os.environ}
    env['FIELDWORK_WORKER_AUTHORITY'] = str(authority_path)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    log = log_path.open('xb')
    try:
        flags = getattr(subprocess, 'DETACHED_PROCESS', 0) | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
        launched = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT,
                                     creationflags=flags, close_fds=True)
    except BaseException:
        log.close()
        raise
    log.close()
    launch = psutil.Process(launched.pid)
    launch_created = launch.create_time()
    process = None
    family = []
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            members = [launch, *launch.children(recursive=True)]
            matches = []
            for member in members:
                if (Path(member.cwd()).resolve() == ROOT.resolve()):
                    found = _issuer_cli(member.cmdline(), authority_path)
                    if found is not None:
                        matches.append((member, found))
            if len(matches) == expected_family_size:
                launch_matches = [(p, c) for p, c in matches if p.pid == launched.pid
                                  and abs(p.create_time() - launch_created) < .01]
                all_descendants = launch.children(recursive=True)
                if expected_family_size == 1 and len(launch_matches) == 1:
                    ancillary = []
                    unknown_descendant = False
                    for desc in all_descendants:
                        if str(desc.name()).casefold() not in ('conhost.exe', 'conhost'):
                            unknown_descendant = True
                        else:
                            ancillary.append(desc)
                    ancillary_valid = len(ancillary) <= 1 and not unknown_descendant
                    if ancillary and ancillary_valid:
                        conhost_parent = ancillary[0].parent()
                        ancillary_valid = (conhost_parent is not None
                            and conhost_parent.pid == launched.pid
                            and abs(conhost_parent.create_time() - launch_created) < .01)
                    if ancillary_valid:
                        process, candidate = launch_matches[0]
                        family = [(process, candidate)]
                        break
                if expected_family_size == 2 and len(launch_matches) == 1:
                    actual_matches = [(p, c) for p, c in matches if p.pid != launched.pid]
                    if len(actual_matches) == 1:
                        candidate_process, candidate = actual_matches[0]
                        parent = candidate_process.parent()
                        python_descendants = []
                        ancillary = []
                        unknown_descendant = False
                        for desc in all_descendants:
                            name = str(desc.name()).casefold()
                            if 'python' in name:
                                found = None
                                if Path(desc.cwd()).resolve() == ROOT.resolve():
                                    found = _issuer_cli(desc.cmdline(), authority_path)
                                if found is None:
                                    unknown_descendant = True
                                else:
                                    python_descendants.append((desc, found))
                            elif name in ('conhost.exe', 'conhost'):
                                ancillary.append(desc)
                            else:
                                unknown_descendant = True
                        ancillary_valid = len(ancillary) <= 1 and not unknown_descendant
                        if ancillary and ancillary_valid:
                            conhost_parent = ancillary[0].parent()
                            ancillary_valid = (conhost_parent is not None
                                and conhost_parent.pid == candidate_process.pid
                                and abs(conhost_parent.create_time() - candidate_process.create_time()) < .01)
                        if (len(python_descendants) == 1
                                and python_descendants[0][0].pid == candidate_process.pid
                                and abs(python_descendants[0][0].create_time() - candidate_process.create_time()) < .01
                                and ancillary_valid
                                and parent is not None and parent.pid == launched.pid
                                and abs(parent.create_time() - launch_created) < .01
                                and candidate['cli_tail'] == launch_matches[0][1]['cli_tail']
                                and launch_matches[0][1]['cli_tail'] == argv[1:]):
                            process = candidate_process
                            family = [launch_matches[0], actual_matches[0]]
                            break
        except psutil.Error:
            pass
        time.sleep(.25)
    else:
        raise ValueError('FRESH_ISSUER_NOT_OBSERVED')
    created = process.create_time()
    parent = process.parent()
    record = {'pid': process.pid, 'create_time': created,
              'parent_pid': parent.pid if parent else None,
              'parent_create_time': parent.create_time() if parent else None,
              'identity': 'scoped-worker-v1', 'launch_pid': launched.pid,
              'launch_create_time': launch_created,
              'log': str(log_path.relative_to(ROOT)), 'started_utc': datetime.now(timezone.utc).isoformat()}
    if record['pid'] == old_pid:
        raise ValueError('FRESH_ISSUER_PID_REUSED_UNEXPECTEDLY')
    return record


def _write_runtime_issuer(record: dict) -> None:
    path = ROOT / 'var/runtime-worker-issuer.json'
    temp = path.with_name(path.name + '.scope-update.tmp')
    temp.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    os.replace(temp, path)


def _verify_issuer_scope(authority_path: Path, dsn: str, expected: list[str]) -> dict:
    from fieldwork.worker_identity import read_authority, verify
    authority = read_authority(authority_path)
    if authority.get('workspaces') != expected:
        raise ValueError('ISSUER_AUTHORITY_SCOPE_MISMATCH')
    from psycopg import connect
    from psycopg.rows import dict_row
    with connect(dsn, row_factory=dict_row) as conn:
        result = verify(conn, authority['connection']['user'], expected)
    # Verify that exactly one matching issuer is live and it is the recorded fresh process.
    state = _inspect_owned_issuer(authority_path)
    runtime = json.loads((ROOT / 'var/runtime-worker-issuer.json').read_text(encoding='utf-8'))
    if (state['process'].pid != runtime.get('pid') or
            abs(state['process'].create_time() - runtime.get('create_time', -1)) >= .01):
        raise ValueError('FRESH_ISSUER_RUNTIME_RECEIPT_MISMATCH')
    return {'scope_verified': result['verified'], 'issuer_pid': runtime['pid']}


def extend_training_scope(args) -> dict:
    """Append one workspace to the already-provisioned scoped worker identity.

    The scope row and the issuer's private authority JSON are a paired authority
    record. Both pre-change forms are backed up privately; a recovery receipt
    without credentials is left if a cross-file/database failure needs recovery.
    """
    lock = require_lock()
    pointer = ROOT / '.cache/r5-platform/worker-authority-dir.txt'
    raw = pointer.read_text(encoding='utf-8').strip()
    if not raw or '\n' in raw or '\r' in raw:
        raise ValueError('WORKER_AUTHORITY_POINTER_INVALID')
    candidate = Path(raw).absolute()
    if candidate.drive.lower() != 'c:':
        raise ValueError('WORKER_AUTHORITY_NOT_ON_C')
    try:
        candidate.relative_to(Path(os.environ['USERPROFILE']).absolute())
    except ValueError:
        raise ValueError('WORKER_AUTHORITY_OUTSIDE_USER_PROFILE') from None
    # The existing operator-selected authority may live in a private C: user
    # directory outside the checkout. Walk before resolving so a junction cannot
    # turn that authorized pointer into access to another drive.
    walk = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        walk /= part
        info = walk.lstat()
        if walk.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('WORKER_AUTHORITY_REPARSE_POINT')
    private_dir = candidate.resolve(strict=True)
    authority_path = private_dir / 'worker-authority.json'
    from fieldwork.worker_identity import read_authority, write_authority, verify
    from fieldwork.scoped_authority import check_private
    check_private(pointer)
    check_private(private_dir)
    authority = read_authority(authority_path)
    login = authority['connection']['user']
    initial_login = login
    old_scopes = authority.get('workspaces')
    if not isinstance(old_scopes, list) or WORKSPACE in old_scopes:
        raise ValueError('TRAINING_SCOPE_NOT_APPENDABLE')
    new_scopes = list(old_scopes) + [WORKSPACE]
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_dir = ROOT / '.local/real-data/activation-backups' / ('scope-' + stamp)
    backup_dir.mkdir(parents=True, exist_ok=False)
    check_private(backup_dir)
    original_bytes = authority_path.read_bytes()
    old_backup = backup_dir / 'worker-authority.before.json'
    old_backup.write_bytes(original_bytes)
    try:
        old_backup.chmod(0o600)
    except OSError:
        pass
    dsn = private_operator_dsn()
    from psycopg import connect
    journal = backup_dir / 'scope-extension-recovery.json'
    # Journal includes no password, DSN, account/session data, or signing material.
    journal.write_text(json.dumps({'status': 'prepared', 'login': login,
        'old_workspaces': old_scopes, 'new_workspaces': new_scopes,
        'authority_backup_sha256': sha(original_bytes), 'at_utc': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n')
    issuer_state = _inspect_owned_issuer(authority_path)
    issuer_backup = backup_dir / 'runtime-worker-issuer.before.json'
    issuer_backup.write_bytes((ROOT / 'var/runtime-worker-issuer.json').read_bytes())
    try:
        issuer_backup.chmod(0o600)
    except OSError:
        pass
    quiesced = False
    restart_error = None
    try:
        # Revalidate the exact single-process or verified two-process family
        # immediately before termination; a newly appeared independent issuer
        # causes a refusal instead of a broad cleanup.
        latest_state = _inspect_owned_issuer(authority_path)
        if (latest_state['runtime']['pid'] != issuer_state['runtime']['pid']
                or abs(latest_state['runtime']['create_time'] - issuer_state['runtime']['create_time']) >= .01):
            raise ValueError('ISSUER_RUNTIME_CHANGED_BEFORE_QUIESCE')
        issuer_state = latest_state
        _quiesce_issuer(issuer_state)
        quiesced = True
        # Rotation may have completed between the initial backup and quiescence.
        # Re-read and separately preserve the exact stopped issuer authority so
        # a password/previous-password update is never overwritten from stale bytes.
        original_bytes = authority_path.read_bytes()
        authority = read_authority(authority_path)
        login = authority['connection']['user']
        old_scopes = authority.get('workspaces')
        if (login != initial_login or not isinstance(old_scopes, list) or WORKSPACE in old_scopes):
            raise ValueError('TRAINING_SCOPE_NOT_APPENDABLE_AFTER_ISSUER_QUIESCE')
        new_scopes = list(old_scopes) + [WORKSPACE]
        quiesced_backup = backup_dir / 'worker-authority.quiesced.json'
        quiesced_backup.write_bytes(original_bytes)
        try:
            quiesced_backup.chmod(0o600)
        except OSError:
            pass
        journal.write_text(json.dumps({'status': 'issuer_quiesced', 'login': login,
            'old_workspaces': old_scopes, 'new_workspaces': new_scopes,
            'authority_backup_sha256': sha(original_bytes), 'at_utc': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n')
        try:
            # The issuer is positively stopped. Update the exact scope row and
            # private authority file as a serialized operation, retaining all
            # existing scope members and grants. Commit DB first so the still
            # running worker cannot observe a scope its DB capability lacks.
            staged = dict(authority, workspaces=new_scopes)
            from psycopg.rows import dict_row
            with connect(dsn, row_factory=dict_row) as conn:
                rows = conn.execute('SELECT principal,workspaces,version,definer FROM fw_worker_cap_v1.scope WHERE principal=%s FOR UPDATE', (login,)).fetchall()
                if len(rows) != 1 or rows[0]['workspaces'] != old_scopes or rows[0]['version'] != 1:
                    raise ValueError('TRAINING_SCOPE_DATABASE_CHANGED')
                conn.execute('UPDATE fw_worker_cap_v1.scope SET workspaces=%s WHERE principal=%s AND version=1', (new_scopes, login))
                if conn.execute('SELECT workspaces FROM fw_worker_cap_v1.scope WHERE principal=%s', (login,)).fetchone()['workspaces'] != new_scopes:
                    raise ValueError('TRAINING_SCOPE_DATABASE_UPDATE_FAILED')
                verified = verify(conn, login, new_scopes)
            write_authority(authority_path, staged)
            journal.write_text(json.dumps({'status': 'complete', 'login': login,
                'old_workspaces': old_scopes, 'new_workspaces': new_scopes,
                'authority_backup_sha256': sha(original_bytes), 'verified': verified['verified'],
                'at_utc': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n')
        except BaseException:
            # Reconcile the private file to the committed scope before the issuer
            # is restarted. No database or authority secret enters the journal.
            try:
                from psycopg.rows import dict_row
                with connect(dsn, row_factory=dict_row) as conn:
                    row = conn.execute('SELECT workspaces FROM fw_worker_cap_v1.scope WHERE principal=%s', (login,)).fetchone()
                if row and row['workspaces'] == old_scopes:
                    write_authority(authority_path, json.loads(original_bytes))
                    state = 'rolled_back_file'
                elif row and row['workspaces'] == new_scopes:
                    write_authority(authority_path, dict(authority, workspaces=new_scopes))
                    state = 'db_committed_authority_reconciled'
                else:
                    state = 'scope_reconciliation_unresolved'
                journal.write_text(json.dumps({'status': state, 'login': login,
                    'old_workspaces': old_scopes, 'new_workspaces': new_scopes,
                    'at_utc': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n')
            except Exception:
                journal.write_text(json.dumps({'status': 'scope_reconciliation_unresolved', 'login': login,
                    'old_workspaces': old_scopes, 'new_workspaces': new_scopes,
                    'at_utc': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n')
            raise
    finally:
        # Always re-establish the same owned issuer command after confirmed
        # quiescence, including a failed scope update. Do not touch the worker.
        if not quiesced:
            quiesced = _issuer_family_gone(issuer_state)
        if quiesced:
            try:
                fresh = _restart_issuer(issuer_state, authority_path, stamp)
                _write_runtime_issuer(fresh)
                auth_now = read_authority(authority_path)
                scope_check = _verify_issuer_scope(authority_path, dsn, auth_now.get('workspaces', []))
                journal.write_text(json.dumps({'status': 'issuer_restarted_and_scope_verified',
                    'login': login, 'scope_count': len(auth_now['workspaces']),
                    'issuer_pid': scope_check['issuer_pid'],
                    'at_utc': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n')
            except BaseException as exc:
                restart_error = exc
                journal.write_text(json.dumps({'status': 'issuer_restart_or_scope_verification_failed',
                    'login': login, 'error_class': type(exc).__name__,
                    'at_utc': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n')
        if restart_error is not None:
            raise restart_error
    return {'status': 'extended', 'login': login, 'scope_count': len(new_scopes),
            'workspace_added': WORKSPACE, 'verified': True, 'backup': str(backup_dir),
            'issuer_restarted': True, 'secret_printed': False}


def restart_api(args) -> dict:
    require_lock()
    pins = json.loads(args.source_pins.read_text(encoding='utf-8'))
    if isinstance(pins.get('files'), dict):
        pins = pins['files']
    required = {'fieldwork/api.py', 'tools/restart_api.py', 'migrations/006_real_data_api.sql'}
    if not required.issubset(pins):
        raise ValueError('API_SOURCE_PINS_INCOMPLETE')
    before = {}
    for rel in sorted(pins):
        if Path(rel).is_absolute() or '..' in Path(rel).parts or not re.fullmatch(r'[A-Za-z0-9_./-]+',rel):
            raise ValueError('API_SOURCE_PIN_PATH_REFUSED')
        actual = sha((ROOT / rel).read_bytes())
        if actual != pins[rel]:
            raise ValueError('API_SOURCE_PIN_MISMATCH')
        before[rel] = actual
    image_present(args.pixel_image_id)
    image_present(args.model_image_id)
    env = dict(os.environ)
    env['FIELDWORK_REAL_PIXEL_IMAGE_ID'] = args.pixel_image_id
    env['FIELDWORK_REAL_MODEL_IMAGE_ID'] = args.model_image_id
    # The qualified-image selector requires the qualified pin to be the exact
    # same reviewed model config as the real-model runtime. This API serves only
    # the registered release; there is no independent mutable model selection.
    env['FIELDWORK_QUALIFIED_MODEL_IMAGE_ID'] = args.model_image_id
    env['FIELDWORK_RIGHTS_REVIEWERS_FILE'] = str(ROOT / 'var/commons_r5/rights/reviewers.json')
    result = run_owned([sys.executable, '-m', 'tools.restart_api'], env=env)
    after = {rel: sha((ROOT / rel).read_bytes()) for rel in sorted(pins)}
    if after != before:
        raise ValueError('API_SOURCE_CHANGED_DURING_RESTART')
    return {**result, 'source_hashes_before': before, 'source_hashes_after': after,
            'pixel_image_id': args.pixel_image_id, 'model_image_id': args.model_image_id}


def _wait_for_worker_heartbeat(launch: dict, *, expected_worker_id: str,
                               timeout: float = 45.0) -> dict:
    import psutil
    marker = ROOT / 'var/worker.json'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            beat = json.loads(marker.read_text(encoding='utf-8'))
        except (OSError, ValueError, TypeError):
            beat = None
        if isinstance(beat, dict) and (beat.get('worker_id') == expected_worker_id
                and beat.get('identity') == 'scoped-worker-v1'
                and beat.get('profile') == 'scoped-real-training-and-inference'
                and beat.get('operator_paused') is True
                and type(beat.get('pid')) is int
                and type(beat.get('create_time')) in (int, float)):
            try:
                process = psutil.Process(beat['pid'])
                parent = process.parent()
                parent_ok = False
                if parent is not None and parent.pid == launch['launcher_pid']:
                    parent_ok = abs(parent.create_time() - launch['launcher_create_time']) < .01
                elif parent is not None and 'python' in str(parent.name()).casefold():
                    grandparent = parent.parent()
                    parent_command = parent.cmdline()
                    parent_ok = (grandparent is not None
                        and grandparent.pid == launch['launcher_pid']
                        and abs(grandparent.create_time() - launch['launcher_create_time']) < .01
                        and Path(parent.cwd()).resolve() == ROOT.resolve()
                        and 'fieldwork.worker' in parent_command
                        and '--real-runs' in parent_command)
                actual = (abs(process.create_time() - beat['create_time']) < .01
                    and Path(process.cwd()).resolve() == ROOT.resolve()
                    and 'fieldwork.worker' in process.cmdline()
                    and '--real-runs' in process.cmdline()
                    and parent_ok)
            except psutil.Error:
                actual = False
            if actual:
                return {'pid': process.pid, 'create_time': process.create_time(),
                    'worker_id': expected_worker_id, 'identity': beat['identity'],
                    'profile': beat['profile'], 'operator_paused': True,
                    'heartbeat_as_of': beat.get('as_of')}
        time.sleep(.25)
    raise RuntimeError('SCOPED_REAL_WORKER_HEARTBEAT_NOT_CONFIRMED')


def _refuse_live_scoped_worker() -> None:
    """Do not create a second real worker when the exact heartbeat owner lives."""
    import psutil
    marker = ROOT / 'var/worker.json'
    try:
        beat = json.loads(marker.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return
    except (OSError, ValueError, TypeError):
        raise RuntimeError('WORKER_HEARTBEAT_MARKER_UNREADABLE') from None
    if not isinstance(beat, dict) or beat.get('profile') != 'scoped-real-training-and-inference':
        return
    pid, created = beat.get('pid'), beat.get('create_time')
    if type(pid) is not int or type(created) not in (int, float):
        raise RuntimeError('WORKER_HEARTBEAT_IDENTITY_INCOMPLETE')
    try:
        process = psutil.Process(pid)
        actual_created = process.create_time()
    except psutil.NoSuchProcess:
        return
    except psutil.Error:
        raise RuntimeError('WORKER_HEARTBEAT_OWNER_UNINSPECTABLE') from None
    if abs(actual_created - created) >= .01:
        return  # PID reuse is stale history; never signal or stop this process.
    try:
        command, cwd = process.cmdline(), Path(process.cwd()).resolve()
    except psutil.Error:
        raise RuntimeError('WORKER_HEARTBEAT_OWNER_UNINSPECTABLE') from None
    if cwd != ROOT.resolve() or 'fieldwork.worker' not in command or '--real-runs' not in command:
        raise RuntimeError('WORKER_HEARTBEAT_OWNER_MISMATCH')
    raise RuntimeError('SCOPED_REAL_WORKER_ALREADY_LIVE')


def _training_authority():
    pointer = ROOT / '.cache/r5-platform/worker-authority-dir.txt'
    raw = pointer.read_text(encoding='utf-8').strip()
    if not raw or '\n' in raw or '\r' in raw:
        raise ValueError('WORKER_AUTHORITY_POINTER_INVALID')
    candidate = Path(raw).absolute()
    if candidate.drive.lower() != 'c:':
        raise ValueError('WORKER_AUTHORITY_NOT_ON_C')
    try:
        candidate.relative_to(Path(os.environ['USERPROFILE']).absolute())
    except ValueError:
        raise ValueError('WORKER_AUTHORITY_OUTSIDE_USER_PROFILE') from None
    walk = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        walk /= part
        info = walk.lstat()
        if walk.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('WORKER_AUTHORITY_REPARSE_POINT')
    private_dir = candidate.resolve(strict=True)
    authority = private_dir / 'worker-authority.json'
    from fieldwork.scoped_authority import check_private
    check_private(pointer); check_private(private_dir); check_private(authority)
    from fieldwork.worker_identity import read_authority
    auth = read_authority(authority)
    if WORKSPACE not in auth.get('workspaces', []):
        raise ValueError('TRAINING_WORKER_SCOPE_NOT_EXTENDED')
    return authority, auth


def start_issuer(args=None) -> dict:
    """Start the existing scoped credential issuer without changing its scope."""
    require_lock()
    import psutil
    authority, auth = _training_authority()
    matching = []
    for proc in psutil.process_iter(['pid', 'name']):
        if 'python' not in str(proc.info.get('name') or '').casefold():
            continue
        try:
            command = proc.cmdline()
            cwd = Path(proc.cwd()).resolve()
            if cwd == ROOT.resolve() and _issuer_cli(command, authority):
                matching.append(proc)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            raise ValueError('ISSUER_PROCESS_INVENTORY_INCOMPLETE') from None
    if matching:
        raise ValueError('SCOPED_ISSUER_ALREADY_PRESENT')

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup_dir = ROOT / '.local/real-data/activation-backups' / ('issuer-start-' + stamp)
    backup_dir.mkdir(parents=True, exist_ok=False)
    from fieldwork.scoped_authority import check_private
    check_private(backup_dir)
    runtime_path = ROOT / 'var/runtime-worker-issuer.json'
    previous_sha = None
    if runtime_path.exists():
        old_bytes = runtime_path.read_bytes()
        previous_sha = sha(old_bytes)
        saved = backup_dir / 'runtime-worker-issuer.before.json'
        with saved.open('xb') as stream:
            stream.write(old_bytes); stream.flush(); os.fsync(stream.fileno())
        check_private(saved)
    log_dir = ROOT / 'var/activation'
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f'fieldwork-worker-issuer-{stamp}.out.log'
    argv = [str(ROOT / '.venv/Scripts/python.exe'), '-B', '-m', 'fieldwork.worker_identity',
        'serve', '--operator-file', str(ROOT / '.local.json'), '--authority-file', str(authority),
        '--worker-heartbeat', str(ROOT / 'var/worker.json'), '--interval', '30', '--ttl-seconds', '300']
    with log_path.open('xb') as stdout:
        flags = getattr(subprocess, 'DETACHED_PROCESS', 0) | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
        process = subprocess.Popen(argv, cwd=ROOT, env={k:v for k,v in os.environ.items()
            if k in {'SYSTEMROOT','PATH','TEMP','TMP','USERPROFILE'}}, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=subprocess.STDOUT, creationflags=flags, close_fds=True)
    launch = {'launcher_pid': process.pid, 'launcher_create_time': psutil.Process(process.pid).create_time()}
    deadline = time.monotonic() + 20
    found = []
    while time.monotonic() < deadline:
        try:
            launcher_proc = psutil.Process(launch['launcher_pid'])
            if abs(launcher_proc.create_time() - launch['launcher_create_time']) >= .01:
                raise ValueError('ISSUER_WMI_LAUNCHER_IDENTITY_CHANGED')
            for proc in launcher_proc.children(recursive=True):
                try:
                    if (Path(proc.cwd()).resolve() == ROOT.resolve()
                            and _issuer_cli(proc.cmdline(), authority)):
                        found.append(proc)
                except psutil.NoSuchProcess:
                    continue
        except psutil.NoSuchProcess:
            raise ValueError('ISSUER_WMI_LAUNCHER_EXITED') from None
        if found:
            break
        time.sleep(.25)
    if len(found) not in (1, 2):
        raise ValueError('SCOPED_ISSUER_START_NOT_CONFIRMED')
    found.sort(key=lambda process: process.create_time())
    actual = found[-1]
    launch_process = actual.parent()
    if len(found) == 2:
        if launch_process is None or launch_process.pid != found[0].pid:
            raise ValueError('SCOPED_ISSUER_FAMILY_INVALID')
        if _issuer_cli(found[0].cmdline(), authority) is None:
            raise ValueError('SCOPED_ISSUER_FAMILY_INVALID')
    runtime = {'identity': 'scoped-worker-v1', 'pid': actual.pid,
        'create_time': actual.create_time(),
        'launch_pid': launch_process.pid if launch_process else launch['launcher_pid'],
        'launch_create_time': launch_process.create_time() if launch_process else launch['launcher_create_time'],
        'wmi_launcher_pid': launch['launcher_pid'],
        'wmi_launcher_create_time': launch['launcher_create_time'],
        'launch_method': 'Popen-from-WMI-detached-entry', 'started_utc': datetime.now(timezone.utc).isoformat(),
        'log': str(log_path.relative_to(ROOT)), 'authority_scope_count': len(auth['workspaces'])}
    temp = runtime_path.with_name(runtime_path.name + '.wmi.tmp')
    with temp.open('x', encoding='utf-8') as stream:
        json.dump(runtime, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, runtime_path)
    scope_check = _verify_issuer_scope(authority, private_operator_dsn(), auth['workspaces'])
    observation = {'status': 'started-and-scope-verified', 'issuer_pid': actual.pid,
        'issuer_create_time': actual.create_time(), 'wmi_launcher_pid': launch['launcher_pid'],
        'scope_count': len(auth['workspaces']), 'workspace_present': WORKSPACE in auth['workspaces'],
        'runtime_before_sha256': previous_sha, 'runtime_after_sha256': sha(runtime_path.read_bytes()),
        'backup': str(backup_dir.relative_to(ROOT)),
        'scope_verified': scope_check['scope_verified'], 'at_utc': datetime.now(timezone.utc).isoformat()}
    outdir = ROOT / '.local/real-data/activation-observations'
    outdir.mkdir(parents=True, exist_ok=True); check_private(outdir)
    receipt_path = outdir / f'issuer-start-{stamp}.json'
    with receipt_path.open('x', encoding='utf-8') as stream:
        json.dump(observation, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    check_private(receipt_path)
    return {**observation, 'receipt': str(receipt_path.relative_to(ROOT)),
            'issuer_live': True, 'secret_printed': False}


def start_worker(args) -> dict:
    require_lock()
    import psutil
    if args.kind == 'training':
        _refuse_live_scoped_worker()
    if args.kind == 'intake':
        authority = ROOT / '.local/real-data/intake-authority.json'
        if not authority.is_file():
            raise ValueError('INTAKE_AUTHORITY_MISSING')
        argv = [str(ROOT / '.venv/Scripts/python.exe'), '-m', 'fieldwork.newintake_worker', '--authority-file', str(authority)]
        name = 'fieldwork-intake-worker'
    else:
        # Existing scoped identity and issuer are reused. They must already have
        # the exact new workspace in both DB scope and private authority JSON.
        authority, auth = _training_authority()
        if args.pixel_image_id:
            image_present(args.pixel_image_id)
        image_present(args.model_image_id)
        argv = [str(ROOT / '.venv/Scripts/python.exe'), '-m', 'fieldwork.worker', '--real-runs']
        name = 'fieldwork-real-training-worker'
    env = dict(os.environ)
    # The activation handoff pins a local Docker endpoint for its own preflight.
    # Worker model-container execution must use the user's default local context;
    # its closed runner rejects Docker endpoint/TLS overrides by design.
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY'):
        env.pop(key, None)
    env['FIELDWORK_WORKER_AUTHORITY'] = str(authority)
    if args.kind == 'training':
        env['FIELDWORK_HOST_HEAVY_LOCK'] = str(REPO / '.cache/product-build.lock')
        env['FIELDWORK_WORKER_ID'] = 'fieldwork-real-completion-worker'
        env['FIELDWORK_REAL_PIXEL_IMAGE_ID'] = args.pixel_image_id
        env['FIELDWORK_REAL_MODEL_IMAGE_ID'] = args.model_image_id
        # Scoped real-data work verifies signed rights decisions in-process.
        # Give it the same operator-selected public reviewer registry as the API;
        # never pass the steward signing key or operator DSN to the worker.
        env['FIELDWORK_RIGHTS_REVIEWERS_FILE'] = str(ROOT / 'var/commons_r5/rights/reviewers.json')
        if not args.hold_claims:
            raise ValueError('REAL_WORKER_START_REQUIRES_COORDINATOR_HOLD')
        if args.hold_claims:
            # Keep a freshly activated worker idle until the coordinator grants
            # the next real-data job window. The file is an admission marker;
            # the worker's normal heartbeat still proves identity and health.
            pause = ROOT / '.local/worker-training.pause'
            pause.parent.mkdir(parents=True, exist_ok=True)
            from fieldwork.scoped_authority import check_private
            check_private(pause.parent)
            if not pause.exists():
                with pause.open('x', encoding='ascii') as stream:
                    stream.write(secrets.token_urlsafe(24))
                    stream.flush(); os.fsync(stream.fileno())
            check_private(pause)
            env['FIELDWORK_TRAINING_PAUSE_FILE'] = str(pause)
            env['FIELDWORK_TRAINING_PAUSE_NONCE'] = secrets.token_urlsafe(24)
    log_dir = ROOT / 'var/activation'
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    log_path = log_dir / f'{name}-{stamp}.out.log'
    with log_path.open('xb') as stdout:
        flags = getattr(subprocess, 'DETACHED_PROCESS', 0) | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
        process = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=subprocess.STDOUT, creationflags=flags, close_fds=True)
    try:
        launch = {'launcher_pid': process.pid, 'launcher_create_time': psutil.Process(process.pid).create_time()}
    except Exception:
        raise RuntimeError('WORKER_LAUNCH_IDENTITY_UNAVAILABLE') from None
    if args.kind == 'training':
        identity = _wait_for_worker_heartbeat(launch, expected_worker_id=env['FIELDWORK_WORKER_ID'])
    else:
        identity = {'loaded': False, 'reason': 'INTAKE_WORKER_START_NOT_WAITED'}
    return {'status': 'started', **identity, 'launcher_pid': launch['launcher_pid'],
            'launcher_create_time': launch['launcher_create_time'], 'kind': args.kind,
            'launch_method': 'Popen-from-WMI-detached-entry', 'log': str(log_path.relative_to(ROOT)),
            'persistence': 'none'}


_HANDOFF_ENV_KEYS = {
    'SYSTEMROOT', 'PATH', 'TEMP', 'TMP', 'USERPROFILE',
    'DOCKER_HOST',
    'FIELDWORK_REAL_PIXEL_IMAGE_ID', 'FIELDWORK_REAL_MODEL_IMAGE_ID',
    'FIELDWORK_QUALIFIED_MODEL_IMAGE_ID', 'FIELDWORK_RIGHTS_REVIEWERS_FILE',
    'FIELDWORK_WORKER_AUTHORITY', 'FIELDWORK_HOST_HEAVY_LOCK', 'FIELDWORK_WORKER_ID',
    'FIELDWORK_TRAINING_PAUSE_FILE', 'FIELDWORK_TRAINING_PAUSE_NONCE',
    'FIELDWORK_OPERATOR_RAM_OVERRIDE',
    'FIELDWORK_OPERATOR_SPACE_OVERRIDE',
}
_WMI_ACTIONS = {'restart-api', 'start-training', 'start-issuer'}


def _atomic_json(path: Path, value: dict) -> None:
    temp = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    with temp.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, path)


def _dispatch_wmi(action_argv: list[str]) -> int:
    import psutil
    lock = require_lock()
    sys.path.insert(0, str(REPO / 'tools'))
    import product_lock
    owner = product_lock.read_owner(REPO / '.cache/product-build.lock')
    if (not isinstance(owner, dict) or owner.get('product') != 'fieldwork'
            or owner.get('purpose') != PURPOSE or owner.get('pid') != lock['pid']):
        raise RuntimeError('FIELDWORK_REAL_ACTIVATION_LOCK_CHANGED')
    env = {key: value for key, value in os.environ.items() if key in _HANDOFF_ENV_KEYS}
    # Win32_Process.Create does not inherit the caller's Docker context. Pin the
    # detached child to the already-selected local Docker Desktop Linux pipe;
    # never carry a context selector, config directory, or remote endpoint.
    docker = Path(r'C:\Program Files\Docker\Docker\resources\bin\docker.exe')
    if not docker.is_file():
        raise RuntimeError('LOCAL_DOCKER_CLI_MISSING')
    context = subprocess.run([str(docker), 'context', 'show'], capture_output=True,
                             text=True, check=False, timeout=10)
    if context.returncode != 0 or context.stdout.strip() != 'desktop-linux':
        raise RuntimeError('LOCAL_DOCKER_CONTEXT_UNEXPECTED')
    endpoint_result = subprocess.run([str(docker), 'context', 'inspect', 'desktop-linux',
        '--format', '{{(index .Endpoints "docker").Host}}'], capture_output=True,
        text=True, check=False, timeout=10)
    endpoint = endpoint_result.stdout.strip()
    if (endpoint_result.returncode != 0
            or endpoint.lower() != r'npipe:////./pipe/dockerDesktopLinuxEngine'.lower()):
        raise RuntimeError('LOCAL_DOCKER_ENDPOINT_REFUSED')
    docker_env = dict(os.environ)
    docker_env.pop('DOCKER_CONTEXT', None)
    docker_env.pop('DOCKER_HOST', None)
    daemon = subprocess.run([str(docker), '--host', endpoint, 'info', '--format', '{{.ID}}'],
        env=docker_env, capture_output=True, text=True, check=False, timeout=15)
    if daemon.returncode != 0 or not re.fullmatch(r'[A-Fa-f0-9-]{16,80}', daemon.stdout.strip()):
        raise RuntimeError('LOCAL_DOCKER_DAEMON_UNAVAILABLE')
    image_ids = []
    if action_argv and action_argv[0] in {'restart-api', 'start-training'}:
        for option in ('--pixel-image-id', '--model-image-id'):
            if option in action_argv:
                index = action_argv.index(option)
                if index + 1 >= len(action_argv):
                    raise RuntimeError('PINNED_IMAGE_ARGUMENT_INVALID')
                image_ids.append(action_argv[index + 1])
        if '--model-image-id' not in action_argv:
            raise RuntimeError('PINNED_IMAGE_ARGUMENT_INVALID')
        if action_argv[0] == 'restart-api' and '--pixel-image-id' not in action_argv:
            raise RuntimeError('PINNED_IMAGE_ARGUMENT_INVALID')
    for image_id in image_ids:
        image = subprocess.run([str(docker), '--host', endpoint, 'image', 'inspect',
            '--format', '{{.Id}}', image_id], env=docker_env, capture_output=True,
            text=True, check=False, timeout=15)
        if image.returncode != 0 or image.stdout.strip() != image_id:
            raise RuntimeError('PINNED_IMAGE_NOT_PRESENT_ON_INTERACTIVE_DAEMON')
    env['DOCKER_HOST'] = endpoint
    env.pop('DOCKER_CONTEXT', None)
    handoff_dir = ROOT / '.local/real-data/activation-handoffs'
    handoff_dir.mkdir(parents=True, exist_ok=True)
    from fieldwork.scoped_authority import check_private
    check_private(handoff_dir)
    handoff_id = secrets.token_hex(16)
    path = handoff_dir / f'{handoff_id}.json'
    payload = {'schema': 'fieldwork.detached-activation-handoff/v1',
        'status': 'prepared', 'id': handoff_id, 'action_argv': action_argv,
        'environment': env, 'lock_owner': {'pid': owner['pid'], 'create_time': owner['create_time']},
        'lock_path': str(REPO / '.cache/product-build.lock'),
        'purpose': PURPOSE, 'created_utc': datetime.now(timezone.utc).isoformat(),
        'expires_epoch': time.time() + 180}
    _atomic_json(path, payload); check_private(path)
    from fieldwork.wmi_launcher import create_wmi_process
    command = [str(ROOT / '.venv/Scripts/python.exe'), '-B', str(Path(__file__).resolve()),
        '--detached-entry', str(path)]
    launch = create_wmi_process(command, cwd=REPO)
    result_path = path.with_name(path.stem + '.result.json')
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if result_path.is_file():
            result = json.loads(result_path.read_text(encoding='utf-8'))
            if (result.get('schema') != 'fieldwork.detached-activation-result/v1'
                    or result.get('handoff_id') != handoff_id
                    or type(result.get('exit_code')) is not int):
                raise RuntimeError('DETACHED_ACTIVATION_RESULT_INVALID')
            print(json.dumps({'status': 'completed' if result['exit_code'] == 0 else 'refused',
                'exit_code': result['exit_code'], 'result': result.get('result'),
                'handoff': str(path.relative_to(ROOT)), 'wmi_pid': launch['pid'],
                'wmi_create_time': launch['create_time']}))
            return result['exit_code']
        time.sleep(.25)
    try:
        process = psutil.Process(launch['pid'])
        still_owned = abs(process.create_time() - launch['create_time']) < .01
    except psutil.NoSuchProcess:
        still_owned = False
    raise RuntimeError('DETACHED_ACTIVATION_RESULT_TIMEOUT_' + ('PROCESS_LIVE' if still_owned else 'PROCESS_EXITED'))


def _validated_handoff_path(raw_path: str | Path) -> Path:
    """Validate the fixed C: handoff path before resolving any reparse points."""
    if not isinstance(raw_path, (str, Path)):
        raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_PATH_INVALID')
    path = Path(raw_path)
    if not path.is_absolute() or path.drive.lower() != 'c:':
        raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_PATH_INVALID')
    if not re.fullmatch(r'[0-9a-f]{32}\.json', path.name):
        raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_PATH_INVALID')
    expected_parent = ROOT / '.local/real-data/activation-handoffs'
    lexical = os.path.normcase(os.path.normpath(str(path)))
    expected = os.path.normcase(os.path.normpath(str(expected_parent / path.name)))
    if lexical != expected:
        raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_PATH_INVALID')
    walk = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            walk /= part
            info = walk.lstat()
            if walk.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_REPARSE_REFUSED')
        if not path.is_file():
            raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_NOT_REGULAR')
        resolved = path.resolve(strict=True)
    except OSError:
        raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_PATH_INVALID') from None
    if os.path.normcase(os.path.normpath(str(resolved))) != lexical:
        raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_PATH_CHANGED')
    from fieldwork.scoped_authority import check_private
    check_private(path)
    return path


def _detached_entry(path: Path) -> int:
    import contextlib
    import io
    import psutil
    global _DETACHED_HANDOFF
    path = _validated_handoff_path(path)
    from fieldwork.scoped_authority import check_private
    check_private(path)
    payload = json.loads(path.read_text(encoding='utf-8'))
    if (payload.get('schema') != 'fieldwork.detached-activation-handoff/v1'
            or payload.get('status') != 'prepared'
            or not isinstance(payload.get('id'), str)
            or path.stem != payload['id']
            or not isinstance(payload.get('action_argv'), list)
            or not payload['action_argv'] or payload['action_argv'][0] not in _WMI_ACTIONS
            or not isinstance(payload.get('environment'), dict)
            or set(payload.get('environment', {})) - _HANDOFF_ENV_KEYS
            or payload.get('purpose') != PURPOSE
            or payload.get('lock_path') != str(REPO / '.cache/product-build.lock')
            or type(payload.get('expires_epoch')) not in (int, float)
            or time.time() > payload['expires_epoch']):
        raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_INVALID')
    claim_path = path.with_name(path.stem + '.claimed')
    claim = {'pid': os.getpid(), 'create_time': psutil.Process().create_time(),
             'claimed_utc': datetime.now(timezone.utc).isoformat()}
    with claim_path.open('x', encoding='utf-8') as stream:
        json.dump(claim, stream); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    check_private(claim_path)
    for key, value in payload['environment'].items():
        if not isinstance(value, str) or any(c in value for c in '\x00\r\n'):
            raise RuntimeError('DETACHED_ACTIVATION_ENVIRONMENT_INVALID')
        os.environ[key] = value
    _DETACHED_HANDOFF = payload
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exit_code = main(payload['action_argv'], _handoff_file=path)
    raw = output.getvalue().strip()
    try:
        action_result = json.loads(raw) if raw else None
    except ValueError:
        action_result = {'status': 'output-invalid', 'output_sha256': sha(raw.encode('utf-8'))}
        exit_code = 2
    result = {'schema': 'fieldwork.detached-activation-result/v1',
        'handoff_id': payload['id'], 'exit_code': exit_code, 'result': action_result,
        'completed_utc': datetime.now(timezone.utc).isoformat(),
        'worker_pid': os.getpid(), 'worker_create_time': claim['create_time']}
    result_path = path.with_name(path.stem + '.result.json')
    _atomic_json(result_path, result); check_private(result_path)
    return exit_code


def main(argv=None, *, _handoff_file=None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if len(raw_argv) == 2 and raw_argv[0] == '--detached-entry':
        path = None
        try:
            path = _validated_handoff_path(raw_argv[1])
            return _detached_entry(path)
        except BaseException as exc:
            print(json.dumps(safe_error(exc)))
            try:
                if path is not None:
                    failure = {'schema': 'fieldwork.detached-activation-result/v1',
                        'handoff_id': path.stem, 'exit_code': 2,
                        'result': safe_error(exc), 'completed_utc': datetime.now(timezone.utc).isoformat(),
                        'worker_pid': os.getpid()}
                    _atomic_json(path.with_name(path.stem + '.result.json'), failure)
            except BaseException:
                pass
            return 2
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    m = sub.add_parser('migrate'); m.add_argument('--rehearsal-007', type=Path, required=True); m.add_argument('--rehearsal-008', type=Path, required=True); m.add_argument('--prior-006-receipt', type=Path, required=True)
    sm = sub.add_parser('activate-schema', help='Fresh-backup and atomically apply reviewed migrations 009-011')
    sm.add_argument('--rehearsal-report', type=Path, required=True)
    sm.add_argument('--review-receipt', type=Path, required=True)
    qm = sub.add_parser('activate-qualified-schema', help='Fresh-backup and atomically apply reviewed qualified migration 012')
    qm.add_argument('--rehearsal-report', type=Path, required=True)
    qm.add_argument('--review-receipt', type=Path, required=True)
    wf = sub.add_parser('activate-worker-rights-014', help='Back up and apply reviewed forward-only real-worker rights fix 014')
    wf.add_argument('--rehearsal-report', type=Path, required=True)
    wf.add_argument('--review-receipt', type=Path, required=True)
    wl = sub.add_parser('activate-worker-row-lock-015', help='Back up and apply reviewed narrow row-lock capability 015')
    wl.add_argument('--rehearsal-report', type=Path, required=True)
    wl.add_argument('--review-receipt', type=Path, required=True)
    p = sub.add_parser('provision-intake'); p.add_argument('--decoder-image-id', required=True)
    sub.add_parser('extend-training-scope')
    r = sub.add_parser('restart-api'); r.add_argument('--pixel-image-id', required=True); r.add_argument('--model-image-id', required=True); r.add_argument('--source-pins', type=Path, required=True)
    r = sub.add_parser('start-issuer')
    for kind in ('intake', 'training'):
        s = sub.add_parser('start-' + kind); s.set_defaults(kind=kind)
        if kind == 'training':
            s.add_argument('--pixel-image-id', required=True); s.add_argument('--model-image-id', required=True)
            s.add_argument('--hold-claims', action='store_true')
    args = parser.parse_args(raw_argv)
    try:
        if _handoff_file is not None:
            if (_DETACHED_HANDOFF is None or args.action not in _WMI_ACTIONS
                    or raw_argv != _DETACHED_HANDOFF['action_argv']):
                raise RuntimeError('DETACHED_ACTIVATION_HANDOFF_BINDING_INVALID')
        elif args.action in _WMI_ACTIONS:
            return _dispatch_wmi(raw_argv)
        result = {'migrate': migrate, 'activate-schema': migrate_schema,
                  'activate-qualified-schema': activate_qualified_schema,
                  'activate-worker-rights-014': activate_worker_rights_fix_014,
                  'activate-worker-row-lock-015': activate_worker_row_lock_015,
                  'provision-intake': provision_intake,
                  'extend-training-scope': extend_training_scope,
                  'start-issuer': start_issuer,
                  'restart-api': restart_api, 'start-intake': start_worker,
                  'start-training': start_worker}[args.action](args)
        print(json.dumps(result))
        return 0
    except Exception as exc:
        print(json.dumps(safe_error(exc)))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
