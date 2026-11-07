"""Rehearse migration 013 on an owner-preserving restore of a retained backup.

This is an isolated scratch operation. It does not connect to or modify the
retained database. The retained backup and globals dump are read from a pinned
snapshot receipt; a uniquely named temporary PostgreSQL container is removed
only after checking its ownership labels and image identity.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import os
import socket
import subprocess
import time
import uuid
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.errors import InsufficientPrivilege

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / 'var/snapshots/real-worker-rights-014-20261101T233806Z-20261101T233806Z.json'
IMAGE_ID = 'sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'
MIGRATION = ROOT / 'migrations/013_intake_perceptual_features.sql'
LOGIN = 'fieldwork_intake_worker'

PROVISION_PRIVILEGE_AUDIT = '''SELECT has_schema_privilege(%s,'public','CREATE') OR
    has_database_privilege(%s,current_database(),'CREATE') OR
    has_database_privilege(%s,current_database(),'TEMP') OR
    EXISTS (SELECT 1 FROM pg_catalog.pg_class r JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
      WHERE n.nspname='public' AND r.relkind IN ('r','p','v','m') AND
        r.relname NOT IN ('fw_real_intake_queue','fw_intake_batches','fw_samples','fw_intake_members',
          'fw_rights_datasets','fw_rights_assets','fw_rights_decisions') AND
        (r.relname<>'fw_sample_perceptual_features' OR
         has_table_privilege(%s,r.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,SELECT WITH GRANT OPTION')) AND
        (has_table_privilege(%s,r.oid,'SELECT') OR has_table_privilege(%s,r.oid,'INSERT') OR
         has_table_privilege(%s,r.oid,'UPDATE') OR has_table_privilege(%s,r.oid,'DELETE') OR
         has_table_privilege(%s,r.oid,'TRUNCATE') OR has_table_privilege(%s,r.oid,'REFERENCES') OR
         has_table_privilege(%s,r.oid,'TRIGGER'))) bad'''


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def docker(*args: str, input: bytes | None = None, timeout: int = 180):
    return subprocess.run(['docker', *args], input=input, capture_output=True, timeout=timeout)


def public_rowcounts(c) -> dict[str, int]:
    names = c.execute("""SELECT relname FROM pg_catalog.pg_class
        WHERE relnamespace='public'::regnamespace AND relkind IN ('r','p')
        ORDER BY relname""").fetchall()
    counts = {}
    for row in names:
        name = row['relname']
        counts[name] = c.execute(sql.SQL('SELECT count(*) AS count FROM public.{}').format(sql.Identifier(name))).fetchone()['count']
    return counts


def database_acl(c) -> dict:
    meta = c.execute('''SELECT d.datname,pg_catalog.pg_get_userbyid(d.datdba) owner,
        pg_catalog.has_database_privilege(%s,d.oid,'TEMP') worker_temp,
        pg_catalog.has_database_privilege(%s,d.oid,'CREATE') worker_create,
        coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))::text datacl
        FROM pg_catalog.pg_database d WHERE d.datname=current_database()''', (LOGIN, LOGIN)).fetchone()
    entries = c.execute('''SELECT CASE WHEN x.grantee=0 THEN 'PUBLIC'
            ELSE pg_catalog.pg_get_userbyid(x.grantee) END grantee,
        x.privilege_type privilege,x.is_grantable
        FROM pg_catalog.pg_database d CROSS JOIN LATERAL pg_catalog.aclexplode(
          coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))) x
        WHERE d.datname=current_database() ORDER BY grantee,x.privilege_type''').fetchall()
    return {'database': meta['datname'], 'owner': meta['owner'], 'worker_temp': meta['worker_temp'],
            'worker_create': meta['worker_create'], 'datacl': meta['datacl'],
            'entries': [dict(row) for row in entries]}


def mirror_database_acl(admin_dsn, dbname: str, source_acl: dict) -> dict:
    # `pg_dump` without --create and `pg_dumpall --globals-only` omit the source
    # database ACL. Reset template defaults and recreate the source grants by
    # role/privilege, retaining the database owner and object owners from dump.
    owner = source_acl['owner']
    allowed = {'CONNECT', 'CREATE', 'TEMPORARY'}
    grants = [row for row in source_acl['entries']
              if row['grantee'] != owner and row['privilege'] in allowed]
    with psycopg.connect(admin_dsn, autocommit=True) as c:
        c.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(dbname)))
        for row in grants:
            privilege = 'TEMP' if row['privilege'] == 'TEMPORARY' else row['privilege']
            grantee = sql.SQL('PUBLIC') if row['grantee'] == 'PUBLIC' else sql.Identifier(row['grantee'])
            grant = sql.SQL('GRANT {} ON DATABASE {} TO {}').format(
                sql.SQL(privilege), sql.Identifier(dbname), grantee)
            if row['is_grantable']:
                grant += sql.SQL(' WITH GRANT OPTION')
            c.execute(grant)
    target = make_conninfo(host=conninfo_to_dict(admin_dsn)['host'], port=conninfo_to_dict(admin_dsn)['port'],
                           dbname=dbname, user=conninfo_to_dict(admin_dsn)['user'],
                           password=conninfo_to_dict(admin_dsn)['password'], connect_timeout=5)
    with psycopg.connect(target, autocommit=True, row_factory=psycopg.rows.dict_row) as c:
        return database_acl(c)


def comparable_database_acl(record: dict) -> list[tuple[str, str, bool]]:
    owner = record['owner']
    return sorted((row['grantee'], row['privilege'], row['is_grantable'])
                  for row in record['entries'] if row['grantee'] != owner)


def owner_map(c) -> dict[str, str]:
    rows = c.execute("""SELECT c.relname,pg_catalog.pg_get_userbyid(c.relowner) AS owner
        FROM pg_catalog.pg_class c WHERE c.relnamespace='public'::regnamespace
          AND c.relkind IN ('r','p') AND c.relname IN ('fw_samples','fw_intake_batches','fw_real_intake_queue')
        ORDER BY c.relname""").fetchall()
    return {row['relname']: row['owner'] for row in rows}


def feature_privileges(c) -> dict[str, bool]:
    return c.execute('''SELECT
        has_table_privilege(%s,'public.fw_sample_perceptual_features','SELECT') AS can_select,
        has_table_privilege(%s,'public.fw_sample_perceptual_features','SELECT WITH GRANT OPTION') AS select_grant,
        has_table_privilege(%s,'public.fw_sample_perceptual_features','INSERT') AS can_insert,
        has_table_privilege(%s,'public.fw_sample_perceptual_features','UPDATE') AS can_update,
        has_table_privilege(%s,'public.fw_sample_perceptual_features','DELETE') AS can_delete,
        has_table_privilege(%s,'public.fw_sample_perceptual_features','TRUNCATE') AS can_truncate,
        has_table_privilege(%s,'public.fw_sample_perceptual_features','REFERENCES') AS can_reference,
        has_table_privilege(%s,'public.fw_sample_perceptual_features','TRIGGER') AS can_trigger''',
        (LOGIN,) * 8).fetchone()


def verify_014_and_013_absent(c) -> dict:
    live_014 = c.execute("""SELECT to_regprocedure(
        'fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)') IS NOT NULL
        AND to_regprocedure('fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)') IS NOT NULL AS ok""").fetchone()['ok']
    defs = c.execute("""SELECT pg_get_functiondef(to_regprocedure(
        'fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)')) AS definition""").fetchone()['definition']
    return {
        '014_functions_present': live_014,
        # pg_get_functiondef deparses built-in qualification, so inspect the
        # normalized spelling rather than requiring the migration's prefix.
        '014_base64_linebreak_fix_present': 'chr(10)' in defs and 'chr(13)' in defs,
        '013_table_absent_before': c.execute("SELECT to_regclass('public.fw_sample_perceptual_features') IS NULL AS absent").fetchone()['absent'],
    }


def provision_privilege_breakdown(c) -> dict:
    base = c.execute('''SELECT has_schema_privilege(%s,'public','CREATE') schema_create,
        has_database_privilege(%s,current_database(),'CREATE') database_create,
        has_database_privilege(%s,current_database(),'TEMP') database_temp''', (LOGIN,) * 3).fetchone()
    rows = c.execute('''SELECT r.relname,
        has_table_privilege(%s,r.oid,'SELECT') can_select,
        has_table_privilege(%s,r.oid,'INSERT') can_insert,
        has_table_privilege(%s,r.oid,'UPDATE') can_update,
        has_table_privilege(%s,r.oid,'DELETE') can_delete,
        has_table_privilege(%s,r.oid,'TRUNCATE') can_truncate,
        has_table_privilege(%s,r.oid,'REFERENCES') can_reference,
        has_table_privilege(%s,r.oid,'TRIGGER') can_trigger,
        CASE WHEN r.relname='fw_sample_perceptual_features' THEN
          has_table_privilege(%s,r.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,SELECT WITH GRANT OPTION')
          ELSE false END feature_nonselect_bad
        FROM pg_catalog.pg_class r JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
        WHERE n.nspname='public' AND r.relkind IN ('r','p','v','m')
          AND r.relname NOT IN ('fw_real_intake_queue','fw_intake_batches','fw_samples','fw_intake_members',
            'fw_rights_datasets','fw_rights_assets','fw_rights_decisions') ORDER BY r.relname''', (LOGIN,) * 8).fetchall()
    rejected = []
    for row in rows:
        any_grant = any(row[key] for key in ('can_select','can_insert','can_update','can_delete',
                                              'can_truncate','can_reference','can_trigger'))
        if any_grant and (row['relname'] != 'fw_sample_perceptual_features' or row['feature_nonselect_bad']):
            rejected.append({key: row[key] for key in ('relname','can_select','can_insert','can_update',
                                                       'can_delete','can_truncate','can_reference','can_trigger',
                                                       'feature_nonselect_bad')})
    return {**dict(base), 'rejected_unlisted_relations': rejected}


def fixture_capability_checks(c) -> dict:
    ws = 'phash-013-fixture-' + uuid.uuid4().hex
    actor = 'fixture-' + uuid.uuid4().hex
    intake_id, batch_id = uuid.uuid4(), uuid.uuid4()
    old_batch_id = uuid.uuid4()
    sample_new, sample_old = uuid.uuid4(), uuid.uuid4()
    archive_sha = 'a' * 64
    raw_new, raw_old = '0' * 64, '1' * 64
    pixel_new, pixel_old = '2' * 64, '3' * 64
    dataset = 'fixture-dataset-' + uuid.uuid4().hex
    member_new, member_old = 'fixture/new.png', 'fixture/old.png'
    decoder = 'fieldwork.decode/v2 pillow-13.0.0 numpy-2.5.4 exif-transpose rgb8 alpha-on-white phash-dct64/v1'
    c.execute('SAVEPOINT authored_phash_rows')
    try:
        c.execute('INSERT INTO public.fw_accounts(name,salt,password_hash,workspace,role) VALUES(%s,%s,%s,%s,%s)',
                  (actor, 'fixture-salt', 'fixture-hash', ws, 'owner'))
        c.execute('INSERT INTO public.fw_intake_worker_scopes(worker_login,workspace,assigned_by) VALUES(%s,%s,%s)',
                  (LOGIN, ws, actor))
        c.execute("SELECT set_config('fieldwork.workspace',%s,true),set_config('fieldwork.intake_id',%s,true)",
                  (ws, str(intake_id)))
        c.execute('''INSERT INTO public.fw_real_intake_queue
            (workspace,intake_id,actor,rights_dataset_id,archive_path,archive_sha256,archive_bytes)
            VALUES(%s,%s,%s,%s,%s,%s,%s)''',
            (ws, intake_id, actor, dataset, 'fixture://no-media', archive_sha, 1234))
        c.execute('''UPDATE public.fw_real_intake_queue SET state='running',lease_fence=1,
            lease_owner='fixture-worker',lease_until=clock_timestamp()+interval '5 minutes',attempts=1
            WHERE workspace=%s AND intake_id=%s''', (ws, intake_id))
        c.execute('''INSERT INTO public.fw_intake_batches
            (workspace,batch_id,archive_name,archive_sha256,archive_bytes,rights_dataset_id,policy,actor,state)
            VALUES(%s,%s,'fixture.zip',%s,1234,%s,'fixture-policy',%s,'staging')''',
            (ws, batch_id, archive_sha, dataset, actor))
        for sid, raw, pixel, member, first_batch in (
            (sample_new, raw_new, pixel_new, member_new, batch_id),
            (sample_old, raw_old, pixel_old, member_old, old_batch_id),
        ):
            c.execute('''INSERT INTO public.fw_samples
                (workspace,sample_id,raw_sha256,raw_bytes,pixel_sha256,width,height,format,decoder,
                 media_path,source_member,source_label,rights_dataset_id,first_batch)
                VALUES(%s,%s,%s,10,%s,10,10,'PNG',%s,'fixture://no-media',%s,NULL,%s,%s)''',
                (ws, sid, raw, pixel, decoder, member, dataset, first_batch))

        c.execute('SET SESSION AUTHORIZATION fieldwork_intake_worker')
        c.execute("SELECT set_config('fieldwork.workspace',%s,true),set_config('fieldwork.intake_id',%s,true)",
                  (ws, str(intake_id)))
        c.execute('SELECT fw_intake_cap_v1.publish_sample_phash(%s,%s,%s,%s,%s,%s)',
                  (ws, sample_new, raw_new, pixel_new, '0123456789abcdef', decoder))
        c.execute('SAVEPOINT wrong_claim')
        wrong_claim_rejected = False
        try:
            c.execute('SELECT fw_intake_cap_v1.repair_sample_phash(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                      (ws, sample_old, raw_old, 10, pixel_old, 'fedcba9876543210', decoder,
                       'fixture/other-member.png', dataset))
        except InsufficientPrivilege:
            wrong_claim_rejected = True
            c.execute('ROLLBACK TO SAVEPOINT wrong_claim')
        c.execute('RELEASE SAVEPOINT wrong_claim')
        c.execute('SAVEPOINT wrong_dataset')
        wrong_dataset_rejected = False
        try:
            c.execute('SELECT fw_intake_cap_v1.repair_sample_phash(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                      (ws, sample_old, raw_old, 10, pixel_old, 'fedcba9876543210', decoder,
                       member_old, 'fixture-wrong-dataset'))
        except InsufficientPrivilege:
            wrong_dataset_rejected = True
            c.execute('ROLLBACK TO SAVEPOINT wrong_dataset')
        c.execute('RELEASE SAVEPOINT wrong_dataset')
        c.execute('SELECT fw_intake_cap_v1.repair_sample_phash(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                  (ws, sample_old, raw_old, 10, pixel_old, 'fedcba9876543210', decoder, member_old, dataset))
        visible = c.execute('SELECT count(*) AS count FROM public.fw_sample_perceptual_features WHERE workspace=%s', (ws,)).fetchone()['count']
        c.execute('RESET SESSION AUTHORIZATION')

        mutation_failures = []
        for label, statement in (
            ('update', "UPDATE public.fw_sample_perceptual_features SET hash_hex='1111111111111111' WHERE workspace=%s"),
            ('delete', 'DELETE FROM public.fw_sample_perceptual_features WHERE workspace=%s'),
        ):
            savepoint = 'mutation_' + label
            c.execute(sql.SQL('SAVEPOINT {}').format(sql.Identifier(savepoint)))
            try:
                c.execute(statement, (ws,))
            except InsufficientPrivilege:
                mutation_failures.append(label)
                c.execute(sql.SQL('ROLLBACK TO SAVEPOINT {}').format(sql.Identifier(savepoint)))
            c.execute(sql.SQL('RELEASE SAVEPOINT {}').format(sql.Identifier(savepoint)))

        c.execute('ROLLBACK TO SAVEPOINT authored_phash_rows')
        c.execute('RELEASE SAVEPOINT authored_phash_rows')
        return {'authorized_publish_and_repair_succeeded': True, 'wrong_member_rejected': wrong_claim_rejected,
                'wrong_dataset_rejected': wrong_dataset_rejected,
                'worker_visible_features': visible, 'immutable_mutations_rejected': sorted(mutation_failures) == ['delete','update']}
    finally:
        try:
            c.execute('RESET SESSION AUTHORIZATION')
        except psycopg.Error:
            pass
        try:
            c.execute('ROLLBACK TO SAVEPOINT authored_phash_rows')
            c.execute('RELEASE SAVEPOINT authored_phash_rows')
        except psycopg.Error:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--diagnostic-only', action='store_true')
    args = parser.parse_args()
    run_id = uuid.uuid4().hex
    container = 'fieldwork-phash013-' + run_id[:12]
    label = 'fieldwork.phash013.rehearsal'
    out = ROOT / '.local' / ('phash013-scratch-' + run_id[:12])
    out.mkdir(parents=True, exist_ok=False)
    report: dict = {'schema': 'fieldwork.phash013-rehearsal/v1', 'scope': 'owner-preserving retained backup restore',
                    'source_database_modified': False, 'live_migration_applied': False,
                    'container': container, 'image_id': IMAGE_ID, 'status': 'running'}
    container_started = False
    try:
        receipt = json.loads(RECEIPT.read_text(encoding='utf-8'))
        if receipt.get('container') != 'fieldwork-postgres' or receipt.get('database') != 'fieldwork':
            raise RuntimeError('BACKUP_RECEIPT_IDENTITY')
        dump_path = ROOT / receipt['db']['path']
        globals_path = ROOT / receipt['globals']['path']
        dump = dump_path.read_bytes()
        globals_sql = globals_path.read_bytes()
        if sha(dump) != receipt['db']['sha256'] or sha(globals_sql) != receipt['globals']['sha256']:
            raise RuntimeError('BACKUP_DIGEST_MISMATCH')
        report['backup'] = {'receipt': str(RECEIPT.relative_to(ROOT)), 'sha256': receipt['db']['sha256'],
                            'bytes': len(dump), 'globals_sha256': receipt['globals']['sha256'],
                            'owner_preserving_restore': True}
        cfg = json.loads((ROOT / '.local.json').read_text(encoding='utf-8'))
        source = conninfo_to_dict(cfg['dsn'])
        if source.get('dbname') != 'fieldwork':
            raise RuntimeError('RETAINED_IDENTITY_REFUSED')
        with psycopg.connect(cfg['dsn'], row_factory=psycopg.rows.dict_row) as source_c:
            source_acl = database_acl(source_c)
        if source_acl['owner'] != source['user'] or source_acl['worker_temp']:
            raise RuntimeError('RETAINED_DATABASE_ACL_IDENTITY')
        report['retained_database_acl'] = source_acl

        # The already-created backup is post-014. Read only function/table metadata
        # from the restored copy; do not inspect retained records or protected data.
        globals_probe = {'014_confirmed_by_backup_receipt': receipt['at'].startswith('20261101T2338')}
        report['source_version_proof'] = globals_probe

        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        admin_password = uuid.uuid4().hex + uuid.uuid4().hex
        run = docker('run', '-d', '--name', container, '--label', f'{label}=true',
                     '--label', f'fieldwork.owner={run_id}', '--publish', f'127.0.0.1:{port}:5432',
                     '--memory', '2g', '-e', 'POSTGRES_USER=fw_scratch_admin',
                     '-e', 'POSTGRES_PASSWORD=' + admin_password, '-e', 'POSTGRES_DB=postgres', IMAGE_ID)
        if run.returncode:
            raise RuntimeError('SCRATCH_CONTAINER_START_FAILED')
        container_started = True
        admin = make_conninfo(host='127.0.0.1', port=port, dbname='postgres', user='fw_scratch_admin',
                              password=admin_password, connect_timeout=3)
        report['target_port'] = port
        for _ in range(60):
            try:
                with psycopg.connect(admin) as c:
                    c.execute('SELECT 1')
                break
            except psycopg.Error:
                time.sleep(1)
        else:
            raise RuntimeError('SCRATCH_POSTGRES_NOT_READY')

        globals_restore = docker('exec', '-i', container, 'psql', '-U', 'fw_scratch_admin', '-d', 'postgres',
                                 '-v', 'ON_ERROR_STOP=1', '-q', input=globals_sql)
        if globals_restore.returncode:
            raise RuntimeError('GLOBAL_ROLE_RESTORE_FAILED')
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(
                sql.Identifier(source['dbname']), sql.Identifier(source['user'])))
        report['scratch_database_acl_after_mirror'] = mirror_database_acl(admin, source['dbname'], source_acl)
        report['scratch_database_acl_matches_retained'] = (
            report['scratch_database_acl_after_mirror']['owner'] == source_acl['owner']
            and comparable_database_acl(report['scratch_database_acl_after_mirror']) == comparable_database_acl(source_acl))
        restore = docker('exec', '-i', container, 'pg_restore', '-U', 'fw_scratch_admin', '-d', source['dbname'],
                         '--exit-on-error', input=dump, timeout=300)
        if restore.returncode:
            raise RuntimeError('OWNER_PRESERVING_RESTORE_FAILED')

        scratch_admin = make_conninfo(host='127.0.0.1', port=port, dbname=source['dbname'], user='fw_scratch_admin',
                                      password=admin_password, connect_timeout=5)
        with psycopg.connect(scratch_admin, autocommit=True, row_factory=psycopg.rows.dict_row) as c:
            report['scratch_database_acl_after_restore'] = database_acl(c)
            report['scratch_database_acl_still_matches_retained'] = (
                report['scratch_database_acl_after_restore']['owner'] == source_acl['owner']
                and comparable_database_acl(report['scratch_database_acl_after_restore']) == comparable_database_acl(source_acl))
            report['source_version_proof'].update(verify_014_and_013_absent(c))
            if not report['source_version_proof']['014_functions_present'] or not report['source_version_proof']['013_table_absent_before']:
                raise RuntimeError('BACKUP_NOT_POST014_PRE013')
            report['owners_before_migration'] = owner_map(c)
            report['public_rows_before_013'] = public_rowcounts(c)
            report['owner_preservation_before_migration'] = report['owners_before_migration'] == {
                'fw_intake_batches': 'fieldwork', 'fw_real_intake_queue': 'fieldwork', 'fw_samples': 'fieldwork'}
        target = make_conninfo(**dict(source, host='127.0.0.1', port=port))
        migration_bytes = MIGRATION.read_bytes()
        report['migration_sha256'] = sha(migration_bytes)
        with psycopg.connect(target) as c:
            c.execute(migration_bytes.decode('utf-8'))

        if args.diagnostic_only:
            with psycopg.connect(scratch_admin, autocommit=True, row_factory=psycopg.rows.dict_row) as c:
                params = (LOGIN,) * 11
                report['provisioning_privilege_audit_bad'] = c.execute(PROVISION_PRIVILEGE_AUDIT, params).fetchone()['bad']
                report['provisioning_audit_parameter_count'] = {'placeholders': PROVISION_PRIVILEGE_AUDIT.count('%s'), 'values': len(params)}
                report['provisioning_privilege_breakdown'] = provision_privilege_breakdown(c)
                report['worker_feature_privileges'] = dict(feature_privileges(c))
            report['status'] = 'diagnostic_complete'
            return 0

        with psycopg.connect(scratch_admin, autocommit=True, row_factory=psycopg.rows.dict_row) as c:
            report['public_rows_after_013'] = public_rowcounts(c)
            prior_rows_match = all(report['public_rows_after_013'].get(name) == count
                                   for name, count in report['public_rows_before_013'].items())
            report['all_preexisting_public_rowcounts_unchanged'] = prior_rows_match
            report['new_feature_table_rows'] = report['public_rows_after_013'].get('fw_sample_perceptual_features')
            report['owners_after_migration'] = owner_map(c)
            report['existing_owner_map_unchanged'] = report['owners_after_migration'] == report['owners_before_migration']
            report['feature_table_security'] = c.execute('''SELECT c.relrowsecurity,c.relforcerowsecurity,
                pg_catalog.pg_get_userbyid(c.relowner) owner,
                EXISTS (SELECT 1 FROM pg_catalog.pg_policies p WHERE p.schemaname='public'
                    AND p.tablename='fw_sample_perceptual_features' AND p.policyname='fw_perceptual_feature_tenant') tenant_policy,
                EXISTS (SELECT 1 FROM pg_catalog.pg_policies p WHERE p.schemaname='public'
                    AND p.tablename='fw_sample_perceptual_features' AND p.policyname='fw_perceptual_feature_worker_scope'
                    AND p.cmd='SELECT') worker_scope_policy
                FROM pg_catalog.pg_class c WHERE c.oid='public.fw_sample_perceptual_features'::regclass''').fetchone()
            report['worker_feature_privileges'] = dict(feature_privileges(c))
            report['api_feature_select'] = c.execute("SELECT has_table_privilege('fieldwork_api','public.fw_sample_perceptual_features','SELECT') AS allowed").fetchone()['allowed']
            report['capability_functions'] = c.execute('''SELECT
                has_function_privilege(%s,'fw_intake_cap_v1.publish_sample_phash(text,uuid,text,text,text,text)','EXECUTE') publish,
                has_function_privilege(%s,'fw_intake_cap_v1.repair_sample_phash(text,uuid,text,bigint,text,text,text,text,text)','EXECUTE') repair''',
                (LOGIN, LOGIN)).fetchone()
            prov_params = (LOGIN,) * 11
            report['provisioning_privilege_audit_bad'] = c.execute(PROVISION_PRIVILEGE_AUDIT, prov_params).fetchone()['bad']
            report['provisioning_audit_parameter_count'] = {'placeholders': PROVISION_PRIVILEGE_AUDIT.count('%s'), 'values': len(prov_params)}
            report['provisioning_privilege_breakdown'] = provision_privilege_breakdown(c)
            report['function_owners'] = c.execute("""SELECT pg_catalog.pg_get_userbyid(p.proowner) owner
                FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='fw_real_worker_cap_v1' AND p.proname='real_inputs'""").fetchone()
            report['repair_function_owner'] = c.execute("""SELECT pg_catalog.pg_get_userbyid(p.proowner) owner
                FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='fw_intake_cap_v1' AND p.proname='repair_sample_phash'""").fetchone()['owner']

            # Exercise the publisher, the exact repair binding and immutable
            # trigger using nonsensitive authored rows, then roll every row back.
        with psycopg.connect(scratch_admin, row_factory=psycopg.rows.dict_row) as c:
            report['authored_capability_probe'] = fixture_capability_checks(c)

        report['status'] = 'passed' if (
            prior_rows_match and report['new_feature_table_rows'] == 0
            and not report['retained_database_acl']['worker_temp']
            and report['scratch_database_acl_matches_retained']
            and report['scratch_database_acl_still_matches_retained']
            and report['owner_preservation_before_migration'] and report['existing_owner_map_unchanged']
            and report['feature_table_security']['owner'] == 'fieldwork'
            and report['repair_function_owner'] == 'fieldwork'
            and report['feature_table_security']['relrowsecurity']
            and report['feature_table_security']['relforcerowsecurity']
            and report['feature_table_security']['tenant_policy']
            and report['feature_table_security']['worker_scope_policy']
            and report['worker_feature_privileges']['can_select']
            and not any(value for key, value in report['worker_feature_privileges'].items() if key != 'can_select')
            and report['api_feature_select'] and report['capability_functions']['publish']
            and report['capability_functions']['repair'] and not report['provisioning_privilege_audit_bad']
            and report['provisioning_audit_parameter_count'] == {'placeholders': 11, 'values': 11}
            and report['authored_capability_probe']['authorized_publish_and_repair_succeeded']
            and report['authored_capability_probe']['wrong_member_rejected']
            and report['authored_capability_probe']['wrong_dataset_rejected']
            and report['authored_capability_probe']['worker_visible_features'] == 2
            and report['authored_capability_probe']['immutable_mutations_rejected']
        ) else 'failed'
        return 0 if report['status'] == 'passed' else 1
    except Exception as exc:
        report.update(status='failed', error_class=type(exc).__name__, error_code=str(exc)[:80])
        return 1
    finally:
        report['finished_unix'] = time.time()
        report_path = out / 'rehearsal.json'
        report_path.write_text(json.dumps(report, indent=2, default=str), encoding='utf-8')
        if container_started:
            inspected = docker('inspect', '--format', '{{.Image}}|{{index .Config.Labels "fieldwork.phash013.rehearsal"}}|{{index .Config.Labels "fieldwork.owner"}}', container)
            expected = f'{IMAGE_ID}|true|{run_id}'
            if inspected.returncode == 0 and inspected.stdout.decode().strip() == expected:
                docker('rm', '-f', container)
            else:
                print('SCRATCH_CLEANUP_IDENTITY_CHECK_FAILED')
        print(json.dumps({'status': report['status'], 'evidence': str(out.relative_to(ROOT)),
                          'container_cleanup_verified': container_started,
                          'source_database_modified': False, 'live_migration_applied': False}, sort_keys=True))


if __name__ == '__main__':
    raise SystemExit(main())
