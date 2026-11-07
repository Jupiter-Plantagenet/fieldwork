"""Rehearse the forward-only 014 rights encoding repair on a disposable DB copy.

The only row-bearing input is an existing retained Fieldwork backup. The script
does not connect to the live database, emit table contents, or query protected
members, labels or media. The database container is pinned to the existing local
Fieldwork PostgreSQL image config ID, bound to loopback, resource-capped and
removed before exit.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
PORT = 15543
CONTAINER_PREFIX = 'fieldwork-worker014-rehearsal-'
MIGRATION = '014_real_worker_rights_encoding.sql'
MIGRATION_SHA256 = '9c0d9c81b34d25252f6fa0c801306ca402e234b6c34b35bad110e5e8ab2024d0'
SOURCE_PINS = {
    'migrations/007_real_run_worker.sql': 'ceea0dbc6ff722819c682c97033667e782463e2b45c86bc26fe29adb91b7cf05',
    'migrations/012_qualified_release_inference.sql': '7535502db63723a5fabc6ccc4fb19964f00791ad6ffcb52c82747b7df1bafabf',
    'migrations/014_real_worker_rights_encoding.sql': MIGRATION_SHA256,
}
FUNCTIONS_BEFORE = {
    'fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)':
        '21ae44dc5268ec0fb0c284c54f32f9620c97d7ad4de952c9f9767bde22d4dfd6',
    'fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)':
        'b0b0a01cc1ca1de2022ba70e38575c729de4e15b0adad8715dfffbefa1cbb919',
}
FUNCTIONS_AFTER = {
    'fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)':
        'e1cdfb94bca3e5595d815abfc295ce2da142ef00176d528405edb5f904d7f692',
    'fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)':
        '3d9d8a84c9020dc201d1b63eb876d116535f3f64126c3ee7ea54bfb621a4a0f0',
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(cmd: list[str], *, input_bytes: bytes | None = None, timeout: int = 300,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=input_bytes, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=False, env=env)


def resource_gate() -> dict[str, int]:
    import shutil
    disk = shutil.disk_usage(ROOT.drive + '\\')
    perf = subprocess.run(['powershell', '-NoProfile', '-Command',
                           "$os=Get-CimInstance Win32_OperatingSystem; $m=Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory; Write-Output ([string]$os.FreePhysicalMemory); Write-Output ([string]$m.PercentCommittedBytesInUse)"],
                          capture_output=True, text=True, timeout=15, check=False)
    if perf.returncode:
        raise ValueError('COMMIT_GATE_UNAVAILABLE')
    try:
        available_kib, commit = (int(line.strip()) for line in perf.stdout.splitlines() if line.strip())
    except ValueError:
        raise ValueError('HOST_RESOURCE_GATE_INVALID') from None
    available = available_kib * 1024
    if disk.free < 50 * 1024**3 or available <= 6 * 1024**3 or commit >= 85:
        raise ValueError('HOST_RESOURCE_GATE_REFUSED')
    return {'c_free_bytes': disk.free, 'available_ram_bytes': available,
            'percent_committed_bytes_in_use': commit}


def outer_body(path: Path) -> str:
    lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
    nonblank = [i for i, line in enumerate(lines) if line.strip()]
    first = next((i for i, line in enumerate(lines)
                  if line.strip() and not line.lstrip().startswith('--')), None)
    if (first is None or lines[first].strip().upper() != 'BEGIN;'
            or lines[nonblank[-1]].strip().upper() != 'COMMIT;'):
        raise ValueError('MIGRATION_ENVELOPE_INVALID')
    return ''.join(lines[:first] + lines[first + 1:nonblank[-1]] + lines[nonblank[-1] + 1:])


def table_counts(conn) -> dict[str, int]:
    names = conn.execute("""
      SELECT c.relname FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind IN ('r','p') ORDER BY c.relname
    """).fetchall()
    return {row['relname']: conn.execute(
        sql.SQL('SELECT count(*) AS row_count FROM public.{}').format(sql.Identifier(row['relname']))
    ).fetchone()['row_count'] for row in names}


def function_hashes(conn) -> tuple[dict[str, str | None], dict[str, bool]]:
    hashes, security = {}, {}
    for sig in FUNCTIONS_BEFORE:
        row = conn.execute("""
          SELECT p.prosrc,r.rolname AS owner,p.prosecdef,p.proconfig,
            NOT has_function_privilege('public',p.oid,'EXECUTE') AS no_public
          FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid=p.proowner
          WHERE p.oid=to_regprocedure(%s)
        """, (sig,)).fetchone()
        hashes[sig] = digest(row['prosrc'].encode()) if row else None
        security[sig] = bool(row and row['owner']=='fieldwork_real_worker_definer'
            and row['prosecdef'] and row['proconfig']==['search_path=pg_catalog, pg_temp']
            and row['no_public'])
    return hashes, security


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--backup-manifest', type=Path, required=True)
    ap.add_argument('--out', type=Path)
    args = ap.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = (args.out or ROOT / '.local/round5-resume' / ('real-worker-014-' + stamp)).resolve()
    out.mkdir(parents=True, exist_ok=False)
    container = CONTAINER_PREFIX + stamp.lower()
    report: dict[str, object] = {'schema':'fieldwork.real-worker-014-rehearsal/v1',
        'started_utc':datetime.now(timezone.utc).isoformat(), 'live_database_touched':False,
        'container':container, 'port':PORT, 'stage':'validate-gates-and-pins'}
    created = False
    try:
        report['host_resource_gate'] = resource_gate()
        manifest_path = args.backup_manifest.resolve(strict=True)
        try:
            manifest_path.relative_to((ROOT/'var/snapshots').resolve(strict=True))
        except ValueError:
            raise ValueError('BACKUP_PATH_OUTSIDE_RETAINED_SNAPSHOTS') from None
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if manifest.get('container') != 'fieldwork-postgres' or manifest.get('database') != 'fieldwork':
            raise ValueError('BACKUP_DATABASE_IDENTITY_UNEXPECTED')
        dump_path = ROOT / manifest['db']['path']
        globals_path = ROOT / manifest['globals']['path']
        dump = dump_path.read_bytes(); globals_raw = globals_path.read_bytes()
        if digest(dump) != manifest['db']['sha256'] or digest(globals_raw) != manifest['globals']['sha256']:
            raise ValueError('BACKUP_DIGEST_MISMATCH')
        for rel, expected in SOURCE_PINS.items():
            if digest((ROOT/rel).read_bytes()) != expected:
                raise ValueError('SOURCE_PIN_MISMATCH')
        report['backup']={'manifest':str(manifest_path.relative_to(ROOT)),
            'dump_bytes':len(dump),'dump_sha256':digest(dump),
            'globals_sha256':digest(globals_raw)}
        report['migration_sha256']=MIGRATION_SHA256
        report['source_sha256']=SOURCE_PINS
        local=json.loads((ROOT/'.local.json').read_text(encoding='utf-8'))
        params=conninfo_to_dict(local['dsn'])
        if params.get('host') not in ('127.0.0.1','::1') or params.get('dbname')!='fieldwork':
            raise ValueError('LIVE_DATABASE_IDENTITY_REFUSED')
        existing=run(['docker','inspect',container])
        if existing.returncode==0: raise ValueError('OWNED_CONTAINER_NAME_ALREADY_EXISTS')
        with socket.socket() as probe:
            try: probe.bind(('127.0.0.1',PORT))
            except OSError: raise ValueError('REHEARSAL_PORT_NOT_FREE') from None
        source_container=run(['docker','inspect','fieldwork-postgres','--format={{.Image}}'])
        image_id=source_container.stdout.decode().strip()
        if source_container.returncode or not re.fullmatch(r'sha256:[0-9a-f]{64}',image_id):
            raise ValueError('LOCAL_POSTGRES_IMAGE_ID_UNAVAILABLE')
        report['postgres_image_id']=image_id
        pw=secrets.token_urlsafe(32)
        docker_env=dict(os.environ); docker_env['POSTGRES_PASSWORD']=pw
        proc=run(['docker','run','--pull=never','-d','--name',container,
            '-p',f'127.0.0.1:{PORT}:5432','-e','POSTGRES_USER=postgres','-e','POSTGRES_PASSWORD',
            '--memory','768m','--cpus','1.0','--shm-size','64m','--tmpfs',
            '/var/lib/postgresql/data:rw,noexec,nosuid,size=512m',image_id],timeout=120,env=docker_env)
        if proc.returncode: raise RuntimeError('ISOLATED_POSTGRES_START_FAILED')
        created=True
        admin=make_conninfo(host='127.0.0.1',port=PORT,dbname='postgres',user='postgres',password=pw,connect_timeout=3)
        ready=False
        for _ in range(60):
            try:
                with psycopg.connect(admin) as c: c.execute('SELECT 1')
                ready=True;break
            except psycopg.Error: time.sleep(1)
        if not ready: raise RuntimeError('ISOLATED_POSTGRES_READINESS_TIMEOUT')
        # Remove role password clauses before replaying globals. Keep exact object
        # owners and memberships; the copied database is unreachable from outside C:.
        globals_safe=re.sub(rb"(?i)\s+PASSWORD\s+(?:'[^']*'|NULL)",b'',globals_raw)
        if re.search(rb'(?i)PASSWORD\s+',globals_safe): raise ValueError('GLOBAL_PASSWORD_REDACTION_INCOMPLETE')
        report['stage']='restore-sanitized-globals'
        roles=run(['docker','exec','-i',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1'],input_bytes=globals_safe)
        if roles.returncode: raise RuntimeError('SANITIZED_GLOBALS_RESTORE_FAILED')
        report['stage']='create-scratch-database'
        owner=params['user']; dbname=params['dbname']
        with psycopg.connect(admin,autocommit=True) as c:
            c.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(dbname),sql.Identifier(owner)))
        report['stage']='restore-scratch-database'
        restored=run(['docker','exec','-i',container,'pg_restore','-U','postgres','-d',dbname,'--exit-on-error'],input_bytes=dump,timeout=600)
        if restored.returncode: raise RuntimeError('OWNERSHIP_PRESERVING_RESTORE_FAILED')
        op=make_conninfo(host='127.0.0.1',port=PORT,dbname=dbname,user='postgres',password=pw)
        report['stage']='verify-restored-functions-and-types'
        with psycopg.connect(op,row_factory=dict_row) as c:
            c.execute('SET default_transaction_read_only=off')
            pre, _ = function_hashes(c)
            if pre != FUNCTIONS_BEFORE: raise ValueError('SCRATCH_BASE_FUNCTION_HASH_MISMATCH')
            types=c.execute("""
              SELECT (SELECT udt_name FROM information_schema.columns WHERE table_schema='public' AND table_name='fw_real_image_inputs' AND column_name='dataset_id') AS input_dataset,
                     (SELECT udt_name FROM information_schema.columns WHERE table_schema='public' AND table_name='fw_rights_assets' AND column_name='dataset_id') AS asset_dataset,
                     (SELECT udt_name FROM information_schema.columns WHERE table_schema='public' AND table_name='fw_rights_decisions' AND column_name='dataset_id') AS decision_dataset
            """).fetchone()
            if tuple(types.values()) != ('uuid','text','text'): raise ValueError('SCRATCH_COLUMN_TYPES_UNEXPECTED')
            report['stage']='apply-forward-migration-and-check-preservation'
            before=table_counts(c)
            with c.transaction():
                c.execute(outer_body(ROOT/'migrations'/MIGRATION))
            after=table_counts(c)
            report['existing_public_rows_preserved']=before==after
            if before!=after: raise ValueError('SCRATCH_PUBLIC_ROW_COUNTS_CHANGED')
            post, security=function_hashes(c)
            report['function_hashes_after_match']=post==FUNCTIONS_AFTER
            report['function_hashes_before']=pre;report['function_hashes_after']=post
            report['function_security_postconditions']=security
            if post!=FUNCTIONS_AFTER or not all(security.values()): raise ValueError('SCRATCH_FUNCTION_POSTCONDITION_FAILED')
            grants={sig:bool(c.execute("SELECT bool_and(has_function_privilege(principal,to_regprocedure(%s),'EXECUTE')) AS all_granted FROM fw_worker_cap_v1.scope",(sig,)).fetchone()['all_granted']) for sig in FUNCTIONS_AFTER}
            report['worker_execute_grants_preserved']=all(grants.values())
            if not all(grants.values()): raise ValueError('SCRATCH_WORKER_GRANTS_CHANGED')
            report['stage']='zero-row-typed-rights-joins'
            c.execute("""SELECT 1 FROM public.fw_rights_assets a JOIN public.fw_real_image_inputs i
              ON a.dataset_id=i.dataset_id::text AND a.member_id=i.member_id
               AND a.asset_sha256=i.asset_sha256 AND a.asset_bytes=i.asset_bytes LIMIT 0""")
            c.execute("""SELECT 1 FROM public.fw_rights_decisions d JOIN public.fw_real_image_inputs i
              ON d.dataset_id=i.dataset_id::text AND d.member_id=i.member_id
               AND d.purpose='local_private_training' LIMIT 0""")
            c.execute("""SELECT 1 FROM public.fw_rights_decisions d JOIN public.fw_real_image_inputs i
              ON d.dataset_id=i.dataset_id::text AND d.member_id=i.member_id
               AND d.purpose='model_bundle' LIMIT 0""")
            report['typed_dataset_joins_pass']=True
            report['stage']='strict-base64-authored-roundtrip'
            authored=bytes((i%251 for i in range(1025)))
            encoded=c.execute("SELECT encode(%s::bytea,'base64') AS encoded",(authored,)).fetchone()['encoded']
            cleaned=c.execute("SELECT replace(replace(encode(%s::bytea,'base64'),chr(10),''),chr(13),'') AS cleaned",(authored,)).fetchone()['cleaned']
            roundtrip=base64.b64decode(cleaned,validate=True)
            wrapped=('\n' in encoded or '\r' in encoded)
            if not wrapped or roundtrip!=authored: raise ValueError('SCRATCH_STRICT_BASE64_ROUNDTRIP_FAILED')
            report['strict_base64_roundtrip_pass']=True
        report['protected_labels_or_media_not_read']=True
        report['protected_member_identifiers_not_returned']=True
        report['holdout_evaluation_not_performed']=True
        report['status']='PASS';report['stage']='complete'
    except BaseException as exc:
        report['status']='FAIL';report['failure_class']=type(exc).__name__
        if isinstance(exc, KeyError) and exc.args and isinstance(exc.args[0], (str, int)):
            key = str(exc.args[0])
            report['failure_key'] = key if re.fullmatch(r'[A-Za-z0-9_]{1,64}',key) else 'UNSAFE_KEY_REDACTED'
        if isinstance(exc,psycopg.Error): report['sqlstate']=exc.sqlstate
        raw=exc.args[0] if exc.args else ''
        report['failure_code']=raw if isinstance(raw,str) and re.fullmatch(r'[A-Z0-9_]{1,80}',raw) else None
    finally:
        if created:
            stop=run(['docker','rm','-f',container],timeout=120)
            report['container_removed']=stop.returncode==0
        else: report['container_removed']=True
        if not report.get('container_removed'): report['status']='FAIL'
        report['finished_utc']=datetime.now(timezone.utc).isoformat()
        evidence=out/'report.json'
        evidence.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({'status':report['status'],'evidence':str(evidence.relative_to(ROOT))}))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
