"""Apply migration 013 only after an explicit coordinator receipt and host lock.

This helper is prepared for coordinator review; it is not run by source review,
scratch rehearsal, or decoder image build. It refuses to mutate without a fresh
backup, exact source pins, an unchanged retained row-count snapshot, and the
parent Fieldwork migration lock.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / 'migrations/013_intake_perceptual_features.sql'
MANIFEST = ROOT / 'docs/perceptual-grouping-013-final-sha256-20261102.json'
SCRATCH_REPORT = ROOT / '.local/phash013-scratch-f66daee21e62/rehearsal.json'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_counts(c) -> dict[str, int]:
    names = c.execute("""SELECT tablename FROM pg_catalog.pg_tables
        WHERE schemaname='public' ORDER BY tablename""").fetchall()
    return {row['tablename']: c.execute(sql.SQL('SELECT count(*) AS n FROM public.{}').format(
        sql.Identifier(row['tablename']))).fetchone()['n'] for row in names}


def migration_body(migration_bytes: bytes) -> str:
    text = migration_bytes.decode('utf-8')
    if '\nBEGIN;\n' not in text or not text.rstrip().endswith('COMMIT;'):
        raise RuntimeError('MIGRATION_TRANSACTION_WRAPPER_CHANGED')
    body = text.replace('\nBEGIN;\n', '\n', 1)
    body = body.rsplit('\nCOMMIT;', 1)[0]
    return body


def require_lock() -> None:
    sys.path.insert(0, str(ROOT.parent / 'tools'))
    import psutil
    import product_lock

    lock = product_lock.read_owner(ROOT.parent / '.cache/product-build.lock') or {}
    ancestors = {(p.pid, p.create_time()) for p in psutil.Process().parents()}
    if ((lock.get('product'), lock.get('purpose')) != ('fieldwork', 'w3-retained-real-data-migration')
            or (lock.get('pid'), lock.get('create_time')) not in ancestors):
        raise RuntimeError('HOST_LOCK_REQUIRED')


def validate_receipt(receipt_path: Path) -> tuple[dict, dict]:
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    migration_bytes = MIGRATION.read_bytes()
    manifest_bytes = MANIFEST.read_bytes()
    scratch_bytes = SCRATCH_REPORT.read_bytes()
    manifest = json.loads(manifest_bytes)
    for relative, expected in manifest.get('files', {}).items():
        candidate = Path(relative)
        if candidate.is_absolute() or '..' in candidate.parts:
            raise RuntimeError('SOURCE_MANIFEST_PATH_INVALID')
        source_path = (ROOT / candidate).resolve(strict=True)
        if ROOT.resolve() not in source_path.parents or not source_path.is_file():
            raise RuntimeError('SOURCE_MANIFEST_PATH_INVALID')
        if sha(source_path.read_bytes()) != expected:
            raise RuntimeError('SOURCE_MANIFEST_FILE_HASH_MISMATCH')
    scratch_report = json.loads(scratch_bytes)
    if (scratch_report.get('status') != 'passed' or scratch_report.get('source_database_modified') is not False
            or scratch_report.get('live_migration_applied') is not False
            or scratch_report.get('migration_sha256') != sha(migration_bytes)
            or scratch_report.get('all_preexisting_public_rowcounts_unchanged') is not True):
        raise RuntimeError('SCRATCH_REHEARSAL_NOT_PASSED')
    required = {
        'status': 'approved_for_live_013',
        'migration_sha256': sha(migration_bytes),
        'source_manifest_sha256': sha(manifest_bytes),
        'scratch_report_sha256': sha(scratch_bytes),
    }
    for key, expected in required.items():
        if receipt.get(key) != expected:
            raise RuntimeError('APPROVAL_RECEIPT_MISMATCH')
    if receipt.get('approved_by') is None or receipt.get('approved_utc') is None:
        raise RuntimeError('COORDINATOR_APPROVAL_REQUIRED')
    backup_path = Path(receipt.get('backup_dump', ''))
    if not backup_path.is_absolute():
        backup_path = ROOT / backup_path
    backup_path = backup_path.resolve(strict=True)
    if (ROOT.resolve() not in backup_path.parents or not backup_path.is_file()
            or sha(backup_path.read_bytes()) != receipt.get('backup_dump_sha256')):
        raise RuntimeError('FRESH_BACKUP_BINDING_REQUIRED')
    if receipt.get('backup_database') != 'fieldwork' or receipt.get('backup_utc') is None:
        raise RuntimeError('FRESH_BACKUP_BINDING_REQUIRED')
    return receipt, {'migration': migration_bytes, 'source_manifest': manifest_bytes,
                     'scratch_report': scratch_bytes}


def verify_live(c, receipt: dict) -> dict:
    if c.execute("SELECT to_regclass('public.fw_sample_perceptual_features') IS NULL AS absent").fetchone()['absent'] is not True:
        raise RuntimeError('FEATURE_TABLE_ALREADY_EXISTS')
    before = public_counts(c)
    if before != receipt.get('retained_public_counts_before'):
        raise RuntimeError('RETAINED_POPULATION_CHANGED_REBACKUP_REQUIRED')
    return before


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit('usage: python -B -m tools.apply_perceptual_013 <coordinator-approval.json>')
    receipt_path = Path(sys.argv[1]).resolve(strict=True)
    if receipt_path.with_name('applied-013.json').exists():
        raise RuntimeError('APPLY_RECEIPT_ALREADY_EXISTS')
    receipt, pins = validate_receipt(receipt_path)
    require_lock()
    cfg = json.loads((ROOT / '.local.json').read_text(encoding='utf-8'))
    dsn = cfg['dsn']
    params = conninfo_to_dict(dsn)
    if (params.get('host'), params.get('dbname'), params.get('user')) != ('127.0.0.1', 'fieldwork', 'fieldwork'):
        raise RuntimeError('RETAINED_IDENTITY_REFUSED')

    with psycopg.connect(dsn, row_factory=dict_row) as c:
      with c.transaction():
        c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        before = verify_live(c, receipt)
        c.execute(migration_body(pins['migration']))
        after = public_counts(c)
        if any(after.get(name) != count for name, count in before.items()):
            raise RuntimeError('RETAINED_POPULATION_MISMATCH')
        if after.get('fw_sample_perceptual_features') != 0:
            raise RuntimeError('NEW_FEATURE_TABLE_NOT_EMPTY')
        guard = c.execute('''SELECT
            pg_catalog.to_regclass('public.fw_sample_perceptual_features') IS NOT NULL AS feature_table,
            EXISTS (SELECT 1 FROM pg_catalog.pg_class r JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
                WHERE n.nspname='public' AND r.relname='fw_sample_perceptual_features'
                  AND r.relrowsecurity AND r.relforcerowsecurity) AS forced_rls,
            pg_catalog.has_table_privilege('fieldwork_intake_worker',
                'public.fw_sample_perceptual_features','SELECT') AS worker_select,
            (pg_catalog.has_table_privilege('fieldwork_intake_worker','public.fw_sample_perceptual_features','INSERT')
             OR pg_catalog.has_table_privilege('fieldwork_intake_worker','public.fw_sample_perceptual_features','UPDATE')
             OR pg_catalog.has_table_privilege('fieldwork_intake_worker','public.fw_sample_perceptual_features','DELETE')
             OR pg_catalog.has_table_privilege('fieldwork_intake_worker','public.fw_sample_perceptual_features','TRUNCATE')
             OR pg_catalog.has_table_privilege('fieldwork_intake_worker','public.fw_sample_perceptual_features','REFERENCES')
             OR pg_catalog.has_table_privilege('fieldwork_intake_worker','public.fw_sample_perceptual_features','TRIGGER')
             OR pg_catalog.has_table_privilege('fieldwork_intake_worker','public.fw_sample_perceptual_features','SELECT WITH GRANT OPTION')) AS worker_mutate,
            pg_catalog.has_table_privilege('fieldwork_api',
                'public.fw_sample_perceptual_features','SELECT') AS api_read,
            pg_catalog.has_function_privilege('fieldwork_intake_worker',
                'fw_intake_cap_v1.publish_sample_phash(text,uuid,text,text,text,text)','EXECUTE') AS publish_capability,
            pg_catalog.has_function_privilege('fieldwork_intake_worker',
                'fw_intake_cap_v1.repair_sample_phash(text,uuid,text,bigint,text,text,text,text,text)','EXECUTE') AS repair_capability''').fetchone()
        audit_source = ROOT / 'tools/rehearse_perceptual_013.py'
        if not audit_source.is_file():
            raise RuntimeError('PROVISIONER_AUDIT_SOURCE_MISSING')
        # Use the exact SQL and bind count from the reviewed rehearsal helper.
        from tools.rehearse_perceptual_013 import PROVISION_PRIVILEGE_AUDIT
        params = ('fieldwork_intake_worker',) * 11
        audit = c.execute(PROVISION_PRIVILEGE_AUDIT, params).fetchone()
        policy = c.execute('''SELECT
            EXISTS (SELECT 1 FROM pg_catalog.pg_policies WHERE schemaname='public'
              AND tablename='fw_sample_perceptual_features' AND policyname='fw_perceptual_feature_tenant') tenant,
            EXISTS (SELECT 1 FROM pg_catalog.pg_policies WHERE schemaname='public'
              AND tablename='fw_sample_perceptual_features' AND policyname='fw_perceptual_feature_worker_scope'
              AND cmd='SELECT') worker''').fetchone()
        if not all((guard['feature_table'], guard['forced_rls'], guard['worker_select'],
                    not guard['worker_mutate'], guard['api_read'], guard['publish_capability'],
                    guard['repair_capability'], policy['tenant'], policy['worker'], not audit['bad'])):
            raise RuntimeError('POST_MIGRATION_CAPABILITY_CHECK_FAILED')

    result = {'status': 'applied', 'migration_sha256': sha(pins['migration']),
              'source_manifest_sha256': sha(pins['source_manifest']),
              'scratch_report_sha256': sha(pins['scratch_report']),
              'backup_dump_sha256': receipt['backup_dump_sha256'],
              'retained_public_rowcounts_unchanged': True, 'new_feature_table_rows': 0,
              'capability_checks': dict(guard), 'tenant_policy': policy['tenant'],
              'worker_scope_policy': policy['worker'], 'provisioning_audit_bad': audit['bad'],
              'provisioning_audit_binds': {'placeholders': PROVISION_PRIVILEGE_AUDIT.count('%s'), 'values': len(params)},
              'live_database': 'fieldwork'}
    out = receipt_path.with_name('applied-013.json')
    with out.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({'status': 'applied', 'receipt': str(out), 'secret_printed': False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        code = str(exc)
        safe = code if code.isupper() and code.replace('_', '').isalnum() else type(exc).__name__.upper()
        print(json.dumps({'status': 'refused', 'code': safe[:64], 'secret_printed': False}))
        raise SystemExit(2)
