"""Rehearse 016 on a retained, ownership-preserving scratch restore only."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fieldwork.scoped_authority import check_private

PORT = 15546
CONTAINER_PREFIX = 'fieldwork-rights-encoding-016-'
BACKUP = ROOT / 'var/snapshots/real-worker-row-lock-015-20261102T014249Z-20261102T014250Z.json'
MIGRATION = ROOT / 'migrations/016_real_worker_rights_member_bundle_encoding.sql'
PREREQUISITE_015 = ROOT / 'migrations/015_rights_row_lock_capability.sql'
WORKSPACE = '814830e3-55a0-4925-ad37-5d3dac7d4df8'
MEMBER_SHA256 = 'bb2e2d28b00939ca386adde2da47b1a60b82aa2cbf1289382220b7ca2c4f724e'
ASSET_SHA256 = 'b89c644bc6e41f199df4d7dcf8a23271ede22bc604e72276d5ea9b94e50e4b0b'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(cmd: list[str], *, data: bytes | None = None, timeout: int = 300,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False, env=env)


def outer_body(path: Path) -> str:
    lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
    nonblank = [i for i, line in enumerate(lines) if line.strip()]
    first = next((i for i, line in enumerate(lines)
                  if line.strip() and not line.lstrip().startswith('--')), None)
    if (first is None or lines[first].strip().upper() != 'BEGIN;'
            or lines[nonblank[-1]].strip().upper() != 'COMMIT;'):
        raise ValueError('MIGRATION_ENVELOPE_INVALID')
    return ''.join(lines[:first] + lines[first + 1:nonblank[-1]] + lines[nonblank[-1] + 1:])


def sql_body(path: Path, name: str) -> str:
    text = path.read_text(encoding='utf-8')
    match_start = re.search(r'CREATE(?: OR REPLACE)? FUNCTION\s+fw_real_worker_cap_v1\.'
                            + re.escape(name) + r'\s*\(', text)
    if not match_start:
        raise ValueError('MIGRATION_FUNCTION_BODY_MISSING')
    end = text.index('\nALTER FUNCTION fw_real_worker_cap_v1.' + name, match_start.start())
    match_body = re.search(r'AS\s+\$fn\$(.*?)\$fn\$', text[match_start.start():end], re.DOTALL)
    if not match_body:
        raise ValueError('MIGRATION_FUNCTION_BODY_MISSING')
    return match_body.group(1).strip()


def applied_baseline_inference() -> str:
    body = sql_body(ROOT / 'migrations/007_real_run_worker.sql', 'real_inference_input')
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


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = ROOT / '.local/real-data/workflow-20261102' / ('rights-encoding-016-scratch-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    check_private(out)
    container = CONTAINER_PREFIX + stamp.lower()
    report = {'schema': 'fieldwork.real-worker-rights-encoding-016-rehearsal/v1',
              'status': 'running', 'started_utc': datetime.now(timezone.utc).isoformat(),
              'live_database_touched': False, 'protected_rows_read': False,
              'container': container, 'port': PORT}
    created = False
    try:
        manifest = json.loads(BACKUP.read_text(encoding='utf-8'))
        if manifest.get('container') != 'fieldwork-postgres' or manifest.get('database') != 'fieldwork':
            raise ValueError('BACKUP_IDENTITY_INVALID')
        dump = ROOT / manifest['db']['path']
        globals_path = ROOT / manifest['globals']['path']
        dump_bytes, globals_raw = dump.read_bytes(), globals_path.read_bytes()
        migration_raw = MIGRATION.read_bytes()
        migration_015_raw = PREREQUISITE_015.read_bytes()
        if sha(dump_bytes) != manifest['db']['sha256'] or sha(globals_raw) != manifest['globals']['sha256']:
            raise ValueError('BACKUP_DIGEST_MISMATCH')
        if sha(migration_raw) != '6804e8e0a5ae9faf0038582e274b2c04c59bc6ec1cb84979c9b4664fff2356b8':
            raise ValueError('MIGRATION_SOURCE_PIN_MISMATCH')
        if sha(migration_015_raw) != '578de6f33b27241aa6357715f71f98ae74ec9f58c7c5819bbba96f03e7164b87':
            raise ValueError('PREREQUISITE_015_SOURCE_PIN_MISMATCH')
        report['migration_sha256'] = sha(migration_raw)
        report['prerequisite_015_sha256'] = sha(migration_015_raw)
        report['backup_dump_sha256'] = sha(dump_bytes)
        report['backup_globals_sha256'] = sha(globals_raw)
        if run(['docker', '--context', 'default', 'inspect', container]).returncode == 0:
            raise ValueError('OWNED_CONTAINER_NAME_ALREADY_EXISTS')
        with socket.socket() as probe:
            try:
                probe.bind(('127.0.0.1', PORT))
            except OSError:
                raise ValueError('REHEARSAL_PORT_NOT_FREE') from None
        pg_image = run(['docker', '--context', 'default', 'inspect', 'fieldwork-postgres', '--format={{.Image}}'])
        image = pg_image.stdout.decode('ascii', 'strict').strip()
        if pg_image.returncode or not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            raise ValueError('LOCAL_POSTGRES_IMAGE_UNAVAILABLE')
        local = json.loads((ROOT / '.local.json').read_text(encoding='utf-8'))
        params = conninfo_to_dict(local['dsn'])
        if params.get('host') not in ('127.0.0.1', '::1') or params.get('dbname') != 'fieldwork':
            raise ValueError('LIVE_DATABASE_IDENTITY_REFUSED')
        secret = secrets.token_urlsafe(32)
        env = dict(os.environ); env['POSTGRES_PASSWORD'] = secret
        started = run(['docker', '--context', 'default', 'run', '--pull=never', '-d', '--name', container,
            '--label', 'fieldwork.real-worker-rights-encoding-016=1',
            '-p', f'127.0.0.1:{PORT}:5432', '-e', 'POSTGRES_USER=postgres', '-e', 'POSTGRES_PASSWORD',
            '--memory', '768m', '--cpus', '1.0', '--shm-size', '64m',
            '--tmpfs', '/var/lib/postgresql/data:rw,noexec,nosuid,size=512m', image], timeout=120, env=env)
        if started.returncode:
            raise RuntimeError('SCRATCH_POSTGRES_START_FAILED')
        created = True
        admin = make_conninfo(host='127.0.0.1', port=PORT, dbname='postgres', user='postgres',
                              password=secret, connect_timeout=3)
        ready = False
        for _ in range(60):
            try:
                with psycopg.connect(admin) as conn:
                    conn.execute('SELECT 1')
                ready = True; break
            except psycopg.Error:
                time.sleep(1)
        if not ready:
            raise RuntimeError('SCRATCH_POSTGRES_READINESS_TIMEOUT')
        safe_globals = re.sub(rb"(?i)\s+PASSWORD\s+(?:'[^']*'|NULL)", b'', globals_raw)
        if re.search(rb'(?i)PASSWORD\s+', safe_globals):
            raise ValueError('GLOBAL_PASSWORD_REDACTION_INCOMPLETE')
        roles = run(['docker', '--context', 'default', 'exec', '-i', container, 'psql', '-U', 'postgres',
                     '-d', 'postgres', '-v', 'ON_ERROR_STOP=1'], data=safe_globals)
        if roles.returncode:
            raise RuntimeError('SANITIZED_GLOBALS_RESTORE_FAILED')
        owner, dbname = params['user'], params['dbname']
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(dbname), sql.Identifier(owner)))
        restored = run(['docker', '--context', 'default', 'exec', '-i', container, 'pg_restore', '-U', 'postgres',
                        '-d', dbname, '--exit-on-error'], data=dump_bytes, timeout=600)
        if restored.returncode:
            raise RuntimeError('OWNERSHIP_PRESERVING_RESTORE_FAILED')
        op = make_conninfo(host='127.0.0.1', port=PORT, dbname=dbname, user='postgres', password=secret,
                           connect_timeout=5)
        with psycopg.connect(op, row_factory=dict_row, autocommit=True) as conn:
            report['stage'] = 'apply-015-to-pre-015-retained-backup-scratch'
            with conn.transaction():
                conn.execute(outer_body(PREREQUISITE_015))
            report['stage'] = 'select-known-nonprotected-train-rights-only'
            inference_sig = 'fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid)'
            live_inference = conn.execute('SELECT prosrc FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure(%s)',
                                          (inference_sig,)).fetchone()
            if not live_inference or live_inference['prosrc'].strip() != applied_baseline_inference():
                raise ValueError('SCRATCH_APPLIED_012_FUNCTION_BASELINE_MISMATCH')
            row = conn.execute("""SELECT d.dataset_id::text AS dataset,a.member_id,a.asset_sha256,
                pg_catalog.octet_length(td.envelope) AS train_bytes,
                pg_catalog.octet_length(bd.envelope) AS bundle_bytes,
                pg_catalog.encode(pg_catalog.sha256(td.envelope),'hex') AS train_digest,
                pg_catalog.encode(pg_catalog.sha256(bd.envelope),'hex') AS bundle_digest,
                pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(a.member_id,'UTF8')),'hex') AS member_digest
              FROM public.fw_rights_datasets d
              JOIN public.fw_rights_assets a ON a.workspace=d.workspace AND a.dataset_id=d.dataset_id
              JOIN public.fw_rights_decisions td ON td.workspace=a.workspace AND td.dataset_id=a.dataset_id
                AND td.member_id=a.member_id AND td.purpose='local_private_training'
              JOIN public.fw_rights_decisions bd ON bd.workspace=a.workspace AND bd.dataset_id=a.dataset_id
                AND bd.member_id=a.member_id AND bd.purpose='model_bundle'
              WHERE d.workspace=%s AND a.asset_sha256=%s AND a.rights_state='reviewed'
                AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(a.member_id,'UTF8')),'hex')=%s""",
                (WORKSPACE, ASSET_SHA256, MEMBER_SHA256)).fetchall()
            if len(row) != 1 or row[0]['member_digest'] != MEMBER_SHA256:
                raise ValueError('NONPROTECTED_TRAIN_RIGHTS_FIXTURE_NOT_UNIQUE')
            picked = row[0]
            if min(picked['train_bytes'], picked['bundle_bytes']) < 60:
                raise ValueError('SIGNED_RIGHTS_ENVELOPE_TOO_SHORT_FOR_WRAP_TEST')
            before = conn.execute("""SELECT pg_catalog.encode(td.envelope,'base64') AS train_raw,
                pg_catalog.encode(bd.envelope,'base64') AS bundle_raw,
                pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(td.envelope,'base64'),
                  pg_catalog.chr(10),''),pg_catalog.chr(13),'') AS train_clean,
                pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(bd.envelope,'base64'),
                  pg_catalog.chr(10),''),pg_catalog.chr(13),'') AS bundle_clean
              FROM public.fw_rights_decisions td JOIN public.fw_rights_decisions bd
                ON bd.workspace=td.workspace AND bd.dataset_id=td.dataset_id AND bd.member_id=td.member_id
              WHERE td.workspace=%s AND td.dataset_id=%s AND td.member_id=%s
                AND td.purpose='local_private_training' AND bd.purpose='model_bundle'""",
                (WORKSPACE, picked['dataset'], picked['member_id'])).fetchone()
            raw_train, raw_bundle = before['train_raw'], before['bundle_raw']
            rejected_before = []
            for encoded in (raw_train, raw_bundle):
                try:
                    base64.b64decode(encoded, validate=True)
                except ValueError:
                    rejected_before.append(True)
                else:
                    rejected_before.append(False)
            clean_train = base64.b64decode(before['train_clean'], validate=True)
            clean_bundle = base64.b64decode(before['bundle_clean'], validate=True)
            if (b'\n' not in raw_train.encode() or b'\n' not in raw_bundle.encode()
                    or rejected_before != [True, True]
                    or sha(clean_train) != picked['train_digest'] or sha(clean_bundle) != picked['bundle_digest']):
                raise ValueError('SIGNED_RIGHTS_CANONICALIZATION_FIXTURE_FAILED')
            report['fixture'] = {'workspace_id': WORKSPACE, 'dataset_id': picked['dataset'],
                'member_sha256': picked['member_digest'], 'asset_sha256': picked['asset_sha256'],
                'train_envelope_bytes': picked['train_bytes'], 'bundle_envelope_bytes': picked['bundle_bytes'],
                'raw_train_base64_wrapped': True, 'raw_bundle_base64_wrapped': True,
                'strict_decode_train_exact': True, 'strict_decode_bundle_exact': True,
                'protected_rows_read': False}
            report['stage'] = 'apply-reviewed-forward-migration-in-scratch'
            body = outer_body(MIGRATION)
            with conn.transaction():
                conn.execute(body)
            report['stage'] = 'verify-capability-function-source-and-point-of-use-decoding'
            expected = {'real_member_rights': ['replace'], 'real_bundle_rights': ['replace'],
                        'real_artifact_rights': ['replace'], 'real_inference_input': ['replace']*2}
            signatures = {
                'real_member_rights': 'fw_real_worker_cap_v1.real_member_rights(text,text,text,integer,integer,uuid,text)',
                'real_bundle_rights': 'fw_real_worker_cap_v1.real_bundle_rights(text,text,text,integer,integer,uuid)',
                'real_artifact_rights': 'fw_real_worker_cap_v1.real_artifact_rights(text,integer,integer,double precision)',
                'real_inference_input': 'fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid)'}
            for name, signature in signatures.items():
                prosrc = conn.execute('SELECT prosrc FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure(%s)',
                                      (signature,)).fetchone()
                if (not prosrc or prosrc['prosrc'].count("pg_catalog.chr(10)") != len(expected[name])
                        or prosrc['prosrc'].count("pg_catalog.chr(13)") != len(expected[name])):
                    raise ValueError('WORKER_FUNCTION_CANONICALIZATION_NOT_INSTALLED')
                if prosrc['prosrc'].strip() != sql_body(MIGRATION, name):
                    raise ValueError('SCRATCH_FUNCTION_BODY_MISMATCH')
            after = conn.execute("""SELECT pg_catalog.replace(pg_catalog.replace(
                pg_catalog.encode(td.envelope,'base64'),pg_catalog.chr(10),''),pg_catalog.chr(13),'') AS train_clean,
                pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(bd.envelope,'base64'),
                pg_catalog.chr(10),''),pg_catalog.chr(13),'') AS bundle_clean
              FROM public.fw_rights_decisions td JOIN public.fw_rights_decisions bd
                ON bd.workspace=td.workspace AND bd.dataset_id=td.dataset_id AND bd.member_id=td.member_id
              WHERE td.workspace=%s AND td.dataset_id=%s AND td.member_id=%s
                AND td.purpose='local_private_training' AND bd.purpose='model_bundle'""",
                (WORKSPACE, picked['dataset'], picked['member_id'])).fetchone()
            if (base64.b64decode(after['train_clean'], validate=True) != clean_train
                    or base64.b64decode(after['bundle_clean'], validate=True) != clean_bundle):
                raise ValueError('POST_MIGRATION_STRICT_DECODE_CHANGED_BYTES')
            report['strict_base64_consumer_compatibility'] = True
            report['rights_bytes_unchanged'] = True
            report['status'] = 'passed'
        return 0
    except Exception as exc:
        report['status'] = 'failed'
        code = str(exc).splitlines()[0]
        report['failure_code'] = code if code.isupper() and len(code) < 120 else type(exc).__name__.upper()
        return 1
    finally:
        if created:
            inspect = run(['docker', '--context', 'default', 'inspect',
                '--format={{.Id}}|{{index .Config.Labels "fieldwork.real-worker-rights-encoding-016"}}', container])
            identity = inspect.stdout.decode('ascii', 'strict').strip().split('|') if inspect.returncode == 0 else []
            if len(identity) == 2 and re.fullmatch(r'[0-9a-f]{64}', identity[0]) and identity[1] == '1':
                removed = run(['docker', '--context', 'default', 'rm', '-f', container], timeout=60)
                absent = run(['docker', '--context', 'default', 'inspect', container])
                report['scratch_container_cleanup_confirmed'] = removed.returncode == 0 and absent.returncode != 0
                if not report['scratch_container_cleanup_confirmed'] and report['status'] == 'passed':
                    report['status'] = 'failed'
                    report['failure_code'] = 'SCRATCH_CONTAINER_CLEANUP_UNCONFIRMED'
            else:
                report['scratch_container_cleanup_confirmed'] = False
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        report['live_database_touched'] = False
        report_path = out / 'rehearsal.json'
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': report['status'], 'stage': report.get('stage'),
                          'migration_sha256': report.get('migration_sha256'),
                          'report': str(report_path.relative_to(ROOT))}))


if __name__ == '__main__':
    raise SystemExit(main())
