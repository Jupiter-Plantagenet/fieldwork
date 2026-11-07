"""Apply the reviewed, representation-only real-worker rights migration 016."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))
PB_HELPER = REPO / 'tools/activate_real_worker.py'
PB_HELPER_SHA256 = '096d0f6a4dbeaae589ae4c2a423c59d935c9f6dd74d5c0a402b98a59aa767303'
MIGRATION = ROOT / 'migrations/016_real_worker_rights_member_bundle_encoding.sql'
MIGRATION_SHA256 = '6804e8e0a5ae9faf0038582e274b2c04c59bc6ec1cb84979c9b4664fff2356b8'
MIGRATION_PINS = {
    'fieldwork/migrations/007_real_run_worker.sql': 'ceea0dbc6ff722819c682c97033667e782463e2b45c86bc26fe29adb91b7cf05',
    'fieldwork/migrations/009_fresh_image_inference.sql': '5adb6f41d423198d04c4ed09ce8bb68aa8560dada792c13abcb55a960beb5227',
    'fieldwork/migrations/012_qualified_release_inference.sql': '7535502db63723a5fabc6ccc4fb19964f00791ad6ffcb52c82747b7df1bafabf',
    'fieldwork/migrations/014_real_worker_rights_encoding.sql': '9c0d9c81b34d25252f6fa0c801306ca402e234b6c34b35bad110e5e8ab2024d0',
    'fieldwork/migrations/015_rights_row_lock_capability.sql': '578de6f33b27241aa6357715f71f98ae74ec9f58c7c5819bbba96f03e7164b87',
    'fieldwork/migrations/016_real_worker_rights_member_bundle_encoding.sql': MIGRATION_SHA256,
    'fieldwork/fieldwork/real_job.py': '42e93256d49e852d085c6bbea7a22af7758c9583c002b782001fc35dbe15de1b',
    'fieldwork/fieldwork/real_artifact_pipeline.py': 'd6b14b1a19d94341c506a47db17ab93924f56672ca810b1af21d595ccc612c82',
    'tools/activate_real_worker.py': PB_HELPER_SHA256,
}
REHEARSAL_HELPER_SHA256 = 'a29b684a3312947664fa5d3589eed68545be0bde8852425b0accd048d2d4f119'
INDEPENDENT_REVIEW_SHA256 = 'dff40a2905ef9180132c48c6053255b3b68c2d8f0e5e1b572ba8c09710991a67'
FUNCTIONS = {
    'fw_real_worker_cap_v1.real_member_rights(text,text,text,integer,integer,uuid,text)': 'real_member_rights',
    'fw_real_worker_cap_v1.real_bundle_rights(text,text,text,integer,integer,uuid)': 'real_bundle_rights',
    'fw_real_worker_cap_v1.real_artifact_rights(text,integer,integer,double precision)': 'real_artifact_rights',
    'fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid)': 'real_inference_input',
}
SCOPES = ('real-training/v1', 'real-inference/v1', 'real-image-inference/v1',
          'qualified-release-image-inference/v1')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pb_helper():
    if sha(PB_HELPER.read_bytes()) != PB_HELPER_SHA256:
        raise ValueError('PINNED_OPERATOR_HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('fieldwork_activation_helper', PB_HELPER)
    if spec is None or spec.loader is None:
        raise ValueError('OPERATOR_HELPER_UNAVAILABLE')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_sources() -> dict[str, str]:
    actual = {}
    for rel in MIGRATION_PINS:
        path = REPO / rel if rel.startswith('tools/') else REPO / rel
        actual[rel] = sha(path.read_bytes())
    if actual != MIGRATION_PINS:
        raise ValueError('REVIEWED_SOURCE_PINS_CHANGED')
    return actual


def sql_body(path: Path, name: str) -> str:
    text = path.read_text(encoding='utf-8')
    match_start = re.search(r'CREATE(?: OR REPLACE)? FUNCTION\s+fw_real_worker_cap_v1\.'
                            + re.escape(name) + r'\s*\(', text)
    if not match_start:
        raise ValueError('MIGRATION_FUNCTION_BODY_MISSING')
    start = match_start.start()
    end = text.index('\nALTER FUNCTION fw_real_worker_cap_v1.' + name, start)
    chunk = text[start:end]
    match = re.search(r'AS\s+\$fn\$(.*?)\$fn\$', chunk, re.DOTALL)
    if not match:
        raise ValueError('MIGRATION_FUNCTION_BODY_MISSING')
    return match.group(1).strip()


def applied_baseline_body(name: str) -> str:
    body = sql_body(ROOT / 'migrations/007_real_run_worker.sql', name)
    if name != 'real_inference_input':
        return body
    old = 'IF NOT fw_real_worker_cap_v1.inference_profile_ok(r.config,r.workspace,r.actor) THEN'
    new = ('IF NOT (fw_real_worker_cap_v1.inference_profile_ok(r.config,r.workspace,r.actor) OR '
           'fw_real_worker_cap_v1.image_inference_profile_ok(r.config,r.workspace,r.actor)) THEN')
    if body.count(old) != 1:
        raise ValueError('009_PROFILE_PATCH_ANCHOR_MISMATCH')
    body = body.replace(old, new)
    image = ('BEGIN IF fw_real_worker_cap_v1.image_inference_profile_ok((SELECT config FROM public.fw_runs WHERE id=p_run), '
        '(SELECT workspace FROM public.fw_runs WHERE id=p_run), (SELECT actor FROM public.fw_runs WHERE id=p_run)) THEN '
        'RETURN fw_real_worker_cap_v1.real_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,NULL); '
        'END IF; SELECT * INTO r FROM public.fw_runs WHERE id=p_run')
    qualified = ('BEGIN IF fw_real_worker_cap_v1.qualified_image_profile_ok((SELECT config FROM public.fw_runs WHERE id=p_run), '
        '(SELECT workspace FROM public.fw_runs WHERE id=p_run), (SELECT actor FROM public.fw_runs WHERE id=p_run)) THEN '
        'RETURN fw_real_worker_cap_v1.qualified_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,NULL); '
        'END IF; IF fw_real_worker_cap_v1.image_inference_profile_ok((SELECT config FROM public.fw_runs WHERE id=p_run), '
        '(SELECT workspace FROM public.fw_runs WHERE id=p_run), (SELECT actor FROM public.fw_runs WHERE id=p_run)) THEN '
        'RETURN fw_real_worker_cap_v1.real_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,NULL); '
        'END IF; SELECT * INTO r FROM public.fw_runs WHERE id=p_run')
    initial = 'BEGIN\n  SELECT * INTO r FROM public.fw_runs WHERE id=p_run'
    if body.count(initial) != 1:
        raise ValueError('009_DISPATCH_PATCH_ANCHOR_MISMATCH')
    body = body.replace(initial, image, 1)
    if body.count(image) != 1:
        raise ValueError('012_DISPATCH_PATCH_ANCHOR_MISMATCH')
    return body.replace(image, qualified, 1)


def function_state(conn) -> dict[str, dict]:
    result = {}
    for signature in FUNCTIONS:
        row = conn.execute("""SELECT p.prosrc,pg_catalog.pg_get_userbyid(p.proowner) AS owner,
            p.prosecdef,p.provolatile,p.proconfig,p.proacl::text AS acl,
            pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,
            pg_catalog.pg_get_function_result(p.oid) AS result
            FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure(%s)""",
            (signature,)).fetchone()
        if not row:
            raise ValueError('RIGHTS_FUNCTION_MISSING')
        result[signature] = dict(row)
    return result


def idle_state(conn) -> bool:
    return conn.execute("""SELECT NOT EXISTS (
          SELECT 1 FROM public.fw_runs WHERE config->>'scope'=ANY(%s)
            AND state IN ('queued','leased','running','cancel_requested'))
          AND NOT EXISTS (SELECT 1 FROM public.fw_slot WHERE id=1 AND run IS NOT NULL) AS idle""",
          (list(SCOPES),)).fetchone()['idle']


def verify_lock_catalog(conn) -> dict[str, dict]:
    result = {}
    for table in ('fw_rights_datasets', 'fw_rights_assets', 'fw_rights_decisions'):
        row = conn.execute("""SELECT c.relrowsecurity,c.relforcerowsecurity,
          pg_catalog.has_column_privilege('fieldwork_real_worker_definer',%s,'row_lock_capability','UPDATE') AS inert_update,
          (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid
             AND NOT t.tgisinternal AND t.tgname='fw015_reject_row_lock_capability'
             AND t.tgenabled='O' AND t.tgqual IS NULL) AS unconditional_trigger
          FROM pg_catalog.pg_class c WHERE c.oid=pg_catalog.to_regclass(%s)""",
          ('public.'+table,'public.'+table)).fetchone()
        if not row or not (row['relrowsecurity'] and row['relforcerowsecurity']
                           and row['inert_update'] and row['unconditional_trigger'] == 1):
            raise ValueError('ROW_LOCK_CAPABILITY_POSTCONDITION_FAILED')
        result[table] = {'rls':row['relrowsecurity'],'force_rls':row['relforcerowsecurity'],
                         'inert_update':row['inert_update'],
                         'unconditional_trigger_count':row['unconditional_trigger']}
    return result


def activate(args) -> dict:
    operator = pb_helper()
    lock = operator.require_lock()
    sources = verify_sources()
    migration_sha = sha(MIGRATION.read_bytes())
    args.review_receipt = args.review_receipt.resolve(strict=True)
    args.rehearsal_report = args.rehearsal_report.resolve(strict=True)
    args.cleanup_observation = args.cleanup_observation.resolve(strict=True)
    for p in (args.review_receipt,args.rehearsal_report,args.cleanup_observation):
        p.relative_to(REPO)
    review_raw = args.review_receipt.read_bytes()
    review = json.loads(review_raw)
    if sha(review_raw) != INDEPENDENT_REVIEW_SHA256:
        raise ValueError('INDEPENDENT_016_REVIEW_HASH_MISMATCH')
    expected_review_sources = dict(MIGRATION_PINS)
    rights_review = review.get('rights_checks_preserved')
    required_rights_flags = {
        'strict_python_base64_validation',
        'trusted_registry_signature_verification',
        'rights_facts_and_membership_bindings',
        'training_and_bundle_rights_both_verified_for_inference',
        'source_run_version_fence_token_lease_scope_checks',
        'metadata_and_existing_row_lock_catalog_preserved',
    }
    rights_checks_ok = (rights_review is True or
        (type(rights_review) is dict and set(rights_review) == required_rights_flags
         and all(value is True for value in rights_review.values())))
    if (review.get('schema') != 'fieldwork.real-worker-rights-encoding-016-review/v1'
            or review.get('status') != 'PASS'
            or review.get('source_sha256') != expected_review_sources
            or not rights_checks_ok
            or review.get('encoding_only') is not True
            or review.get('ownership_grants_rls_scope_signatures_rights_rowlocks_preserved') is not True):
        raise ValueError('INDEPENDENT_016_REVIEW_REQUIRED')

    rehearsal_raw = args.rehearsal_report.read_bytes()
    rehearsal = json.loads(rehearsal_raw)
    if (rehearsal.get('schema') != 'fieldwork.real-worker-rights-encoding-016-rehearsal/v1'
            or rehearsal.get('status') != 'passed'
            or rehearsal.get('migration_sha256') != migration_sha
            or rehearsal.get('prerequisite_015_sha256') != MIGRATION_PINS['fieldwork/migrations/015_rights_row_lock_capability.sql']
            or rehearsal.get('live_database_touched') is not False
            or rehearsal.get('protected_rows_read') is not False
            or rehearsal.get('strict_base64_consumer_compatibility') is not True
            or rehearsal.get('rights_bytes_unchanged') is not True
            or rehearsal.get('fixture', {}).get('strict_decode_train_exact') is not True
            or rehearsal.get('fixture', {}).get('strict_decode_bundle_exact') is not True):
        raise ValueError('016_SCRATCH_REHEARSAL_REQUIRED')
    review_rehearsal = review.get('rehearsal') or {}
    if (review_rehearsal.get('path') != str(args.rehearsal_report.relative_to(ROOT)).replace('\\','/')
            or review_rehearsal.get('sha256') != sha(rehearsal_raw)
            or review_rehearsal.get('helper_sha256_reported_by_operator') != REHEARSAL_HELPER_SHA256):
        raise ValueError('016_REVIEW_REHEARSAL_BINDING_MISMATCH')
    cleanup_raw = args.cleanup_observation.read_bytes()
    cleanup = json.loads(cleanup_raw)
    if (cleanup.get('schema') != 'fieldwork.real-worker-rights-016-scratch-cleanup-observation/v1'
            or cleanup.get('scratch_report_sha256') != sha(rehearsal_raw)
            or cleanup.get('exact_named_container_absent') is not True
            or cleanup.get('exact_label_owned_container_count') != 0
            or cleanup.get('live_database_touched') is not False):
        raise ValueError('016_SCRATCH_CLEANUP_UNCONFIRMED')
    review_cleanup = review_rehearsal.get('cleanup_observation') or {}
    if (review_cleanup.get('path') != str(args.cleanup_observation.relative_to(ROOT)).replace('\\','/')
            or review_cleanup.get('sha256') != sha(cleanup_raw)):
        raise ValueError('016_REVIEW_CLEANUP_BINDING_MISMATCH')

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_label = 'real-worker-rights-016-' + stamp
    backup_run = subprocess.run([sys.executable, '-m', 'tools.r5p_backup', backup_label], cwd=ROOT,
                                capture_output=True, text=True, check=False)
    if backup_run.returncode:
        raise RuntimeError('FRESH_BACKUP_FAILED')
    manifest_path = max((ROOT / 'var/snapshots').glob(backup_label + '-*.json'),
                        key=lambda p: p.stat().st_mtime_ns)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    dump = ROOT / manifest['db']['path']
    if (manifest.get('container') != 'fieldwork-postgres' or manifest.get('database') != 'fieldwork'
            or not dump.is_file() or sha(dump.read_bytes()) != manifest['db']['sha256']):
        raise ValueError('FRESH_BACKUP_DIGEST_MISMATCH')
    source_backup = ROOT / '.local/real-data/activation-backups' / ('worker-rights-016-' + stamp)
    source_backup.mkdir(parents=True, exist_ok=False)
    from fieldwork.scoped_authority import check_private
    check_private(source_backup)
    artifacts = {**MIGRATION_PINS,
        str(args.review_receipt.relative_to(REPO)).replace('\\','/'): sha(review_raw),
        str(args.rehearsal_report.relative_to(REPO)).replace('\\','/'): sha(rehearsal_raw),
        str(args.cleanup_observation.relative_to(REPO)).replace('\\','/'): sha(cleanup_raw)}
    for rel, expected in artifacts.items():
        source = REPO / rel if rel.startswith('tools/') else REPO / rel
        target = source_backup / Path(rel).name
        target.write_bytes(source.read_bytes())
        if sha(target.read_bytes()) != expected:
            raise ValueError('ACTIVATION_SOURCE_BACKUP_DIGEST_MISMATCH')

    from psycopg import connect
    from psycopg.rows import dict_row
    with connect(operator.private_operator_dsn(), row_factory=dict_row) as conn:
        with conn.transaction():
            if not idle_state(conn):
                raise ValueError('LIVE_REAL_QUEUE_NOT_IDLE')
            before = function_state(conn)
            for signature, name in FUNCTIONS.items():
                source_body = applied_baseline_body(name)
                if before[signature]['prosrc'].strip() != source_body:
                    raise ValueError('LIVE_BASELINE_FUNCTION_BODY_MISMATCH')
            lock_before = verify_lock_catalog(conn)
            conn.execute(operator.migration_transaction_body(MIGRATION))
            after = function_state(conn)
            lock_after = verify_lock_catalog(conn)
            if lock_before != lock_after:
                raise ValueError('ROW_LOCK_CAPABILITY_CHANGED')
            for signature, name in FUNCTIONS.items():
                expected_body = sql_body(MIGRATION, name)
                if after[signature]['prosrc'].strip() != expected_body:
                    raise ValueError('LIVE_016_FUNCTION_BODY_MISMATCH')
                for key in ('owner','prosecdef','provolatile','proconfig','acl','arguments','result'):
                    if before[signature][key] != after[signature][key]:
                        raise ValueError('LIVE_FUNCTION_METADATA_CHANGED')
            if not idle_state(conn):
                raise ValueError('LIVE_REAL_QUEUE_CHANGED_DURING_MIGRATION')

    if sha(MIGRATION.read_bytes()) != migration_sha or verify_sources() != sources:
        raise ValueError('SOURCE_CHANGED_DURING_ACTIVATION')
    receipt = {'schema':'fieldwork.real-worker-rights-encoding-016-activation/v1',
        'status':'applied','lock':lock,'migration_sha256':migration_sha,
        'source_sha256':sources,'review_sha256':sha(review_raw),
        'rehearsal_sha256':sha(rehearsal_raw),'cleanup_observation_sha256':sha(cleanup_raw),
        'backup_manifest':str(manifest_path.relative_to(ROOT)),
        'backup_sha256':manifest['db']['sha256'],
        'migration_source_backup':str(source_backup.relative_to(ROOT)),
        'target_functions':list(FUNCTIONS),'function_metadata_unchanged':True,
        'row_lock_capability_catalog_unchanged':lock_before==lock_after,
        'live_real_queue_idle':True,'protected_rows_or_media_read':False,
        'at_utc':datetime.now(timezone.utc).isoformat()}
    out_dir=ROOT/'.local/real-data/activation'; out_dir.mkdir(parents=True,exist_ok=True)
    check_private(out_dir)
    out=out_dir/('worker-rights-016-'+stamp+'.json')
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as stream:
        json.dump(receipt,stream,sort_keys=True,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    return {'status':'applied','receipt':str(out.relative_to(ROOT)),
            'backup_sha256':receipt['backup_sha256'],'migration_sha256':migration_sha,
            'review_sha256':receipt['review_sha256'],'rehearsal_sha256':receipt['rehearsal_sha256']}


def check_only() -> dict:
    operator = pb_helper()
    lock = operator.require_lock()
    sources = verify_sources()
    from psycopg import connect
    from psycopg.rows import dict_row
    with connect(operator.private_operator_dsn(), row_factory=dict_row) as conn:
        with conn.transaction():
            conn.execute('SET TRANSACTION READ ONLY')
            live = function_state(conn)
    checks = {}
    all_passed = True
    for signature, name in FUNCTIONS.items():
        baseline = applied_baseline_body(name)
        repaired = sql_body(MIGRATION, name)
        variables = {'real_member_rights':['rd.envelope'], 'real_bundle_rights':['envelope'],
                     'real_artifact_rights':['envelope'],
                     'real_inference_input':['training_envelope','bundle_envelope']}[name]
        expected = baseline
        for variable in variables:
            encoded = f"pg_catalog.encode({variable},'base64')"
            canonical = (f"pg_catalog.replace(pg_catalog.replace(pg_catalog.encode({variable},'base64'),"
                        "pg_catalog.chr(10),''),pg_catalog.chr(13),'')")
            if expected.count(encoded) != 1:
                raise ValueError('BASELINE_ENCODING_EXPRESSION_COUNT_INVALID')
            expected = expected.replace(encoded, canonical)
        live_matches = live[signature]['prosrc'].strip() == baseline
        migration_matches = repaired == expected
        all_passed = all_passed and live_matches and migration_matches
        checks[signature] = {'live_matches_applied_forward_baseline':live_matches,
            'migration_matches_applied_forward_baseline_plus_canonicalization':migration_matches,
            'live_prosrc_sha256':sha(live[signature]['prosrc'].encode()),
            'baseline_prosrc_sha256':sha(baseline.encode()),
            'live_chars':len(live[signature]['prosrc'].strip()),'baseline_chars':len(baseline)}
    return {'status':'checked' if all_passed else 'diagnostic_mismatch','lock':lock,
            'source_sha256':sources,'function_probes':checks,
            'database_access':'read-only metadata only','live_mutation_performed':False}


def main(argv=None) -> int:
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only',action='store_true')
    parser.add_argument('--review-receipt',type=Path)
    parser.add_argument('--rehearsal-report',type=Path)
    parser.add_argument('--cleanup-observation',type=Path)
    args=parser.parse_args(argv)
    try:
        if args.check_only:
            result=check_only()
            print(json.dumps(result))
            return 0 if result.get('status') == 'checked' else 1
        else:
            if not args.review_receipt or not args.rehearsal_report or not args.cleanup_observation:
                raise ValueError('ACTIVATION_EVIDENCE_ARGUMENTS_REQUIRED')
            result=activate(args)
        print(json.dumps(result))
        return 0
    except Exception as exc:
        raw=exc.args[0] if exc.args else ''
        code=raw if isinstance(raw,str) and re.fullmatch(r'[A-Z0-9_]{1,64}',raw) else None
        print(json.dumps({'status':'refused','error_class':type(exc).__name__,'code':code,
                          'secret_printed':False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
