"""Rehearse 015 on an ownership-preserving disposable restore of Fieldwork."""
from __future__ import annotations

import argparse
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
PORT = 15545
CONTAINER_PREFIX = 'fieldwork-rowlock015-rehearsal-'
MIGRATION = '015_rights_row_lock_capability.sql'
MIGRATION_SHA256 = '578de6f33b27241aa6357715f71f98ae74ec9f58c7c5819bbba96f03e7164b87'
SOURCE_SHA256 = {
    'migrations/007_real_run_worker.sql': 'ceea0dbc6ff722819c682c97033667e782463e2b45c86bc26fe29adb91b7cf05',
    'migrations/012_qualified_release_inference.sql': '7535502db63723a5fabc6ccc4fb19964f00791ad6ffcb52c82747b7df1bafabf',
    'migrations/014_real_worker_rights_encoding.sql': '9c0d9c81b34d25252f6fa0c801306ca402e234b6c34b35bad110e5e8ab2024d0',
}
PROBE_RUN = 'd92cf927-24e5-4395-9ebb-ab4e1a79cfa0'
PROBE_MEMBER_SHA256 = 'bb2e2d28b00939ca386adde2da47b1a60b82aa2cbf1289382220b7ca2c4f724e'
PROBE_ASSET_SHA256 = 'b89c644bc6e41f199df4d7dcf8a23271ede22bc604e72276d5ea9b94e50e4b0b'
PROBE_ASSET_BYTES = 56644
WORKSPACE = '814830e3-55a0-4925-ad37-5d3dac7d4df8'
VERSION = '553eec3b-7173-442a-b99d-995ca63c18a5'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(cmd: list[str], *, input_bytes: bytes | None = None, timeout: int = 300,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=input_bytes, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=False, env=env)


def resource_gate() -> dict[str, int | str]:
    import psutil
    import shutil
    disk = shutil.disk_usage(ROOT.drive + '\\')
    vm = psutil.virtual_memory()
    perf = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
      'Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | '
      'Select-Object CommittedBytes,CommitLimit,PercentCommittedBytesInUse | ConvertTo-Json -Compress'],
      stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False,text=True)
    try:
        counters=json.loads(perf.stdout)
        commit=int(counters['PercentCommittedBytesInUse'])
        committed=int(counters['CommittedBytes']);limit=int(counters['CommitLimit'])
    except (ValueError,TypeError,KeyError,json.JSONDecodeError):
        raise ValueError('HOST_COMMIT_COUNTER_UNAVAILABLE') from None
    if perf.returncode or limit <= 0 or committed < 0 or committed > limit:
        raise ValueError('HOST_COMMIT_COUNTER_INVALID')
    if disk.free < 50 * 1024**3 or vm.available <= 6 * 1024**3 or commit >= 85:
        raise ValueError('HOST_RESOURCE_GATE_REFUSED')
    return {'c_free_bytes':disk.free,'available_ram_bytes':vm.available,
            'commit_percent':commit,'commit_source':'Win32_PerfFormattedData_PerfOS_Memory',
            'committed_bytes':committed,'commit_limit_bytes':limit}


def outer_body(path: Path) -> str:
    lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
    nonblank = [i for i,line in enumerate(lines) if line.strip()]
    first = next((i for i,line in enumerate(lines)
                  if line.strip() and not line.lstrip().startswith('--')), None)
    if (first is None or lines[first].strip().upper()!='BEGIN;'
            or lines[nonblank[-1]].strip().upper()!='COMMIT;'):
        raise ValueError('MIGRATION_ENVELOPE_INVALID')
    return ''.join(lines[:first]+lines[first+1:nonblank[-1]]+lines[nonblank[-1]+1:])


def public_counts(conn) -> dict[str,int]:
    names=conn.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public' ORDER BY tablename").fetchall()
    return {r['tablename']:conn.execute(sql.SQL('SELECT count(*) AS n FROM public.{}').format(
        sql.Identifier(r['tablename']))).fetchone()['n'] for r in names}


def source_hashes(conn) -> dict[str,str|None]:
    signatures=(
      'fw_real_worker_cap_v1.complete_qualified_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text)',
      'fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)',
      'fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)')
    result={}
    for sig in signatures:
        row=conn.execute('SELECT prosrc FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure(%s)',(sig,)).fetchone()
        result[sig]=digest(row['prosrc'].encode()) if row else None
    return result


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--backup-manifest',type=Path,required=True)
    ap.add_argument('--out',type=Path)
    args=ap.parse_args()
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out=(args.out or ROOT/'.local/round5-resume'/('worker-rowlock-015-'+stamp)).resolve()
    out.mkdir(parents=True,exist_ok=False)
    container=CONTAINER_PREFIX+stamp.lower()
    report={'schema':'fieldwork.real-worker-row-lock-015-rehearsal/v1',
      'started_utc':datetime.now(timezone.utc).isoformat(),'live_database_touched':False,
      'container':container,'port':PORT,'stage':'validate-backup-and-source'}
    created=False
    try:
        report['host_resource_gate']=resource_gate()
        report['stage']='resolve-retained-backup'
        manifest_path=args.backup_manifest.resolve(strict=True)
        manifest_path.relative_to((ROOT/'var/snapshots').resolve(strict=True))
        manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
        if manifest.get('container')!='fieldwork-postgres' or manifest.get('database')!='fieldwork':
            raise ValueError('BACKUP_DATABASE_IDENTITY_UNEXPECTED')
        dump=ROOT/manifest['db']['path']; globals_path=ROOT/manifest['globals']['path']
        report['stage']='verify-retained-backup-digests'
        dump_bytes=dump.read_bytes(); globals_raw=globals_path.read_bytes()
        if digest(dump_bytes)!=manifest['db']['sha256'] or digest(globals_raw)!=manifest['globals']['sha256']:
            raise ValueError('BACKUP_DIGEST_MISMATCH')
        source={rel:digest((ROOT/rel).read_bytes()) for rel in SOURCE_SHA256}
        source[f'migrations/{MIGRATION}']=digest((ROOT/'migrations'/MIGRATION).read_bytes())
        if source != {**SOURCE_SHA256,f'migrations/{MIGRATION}':MIGRATION_SHA256}:
            raise ValueError('SOURCE_PIN_MISMATCH')
        report['migration_sha256']=MIGRATION_SHA256;report['source_sha256']=source
        report['backup']={'manifest':str(manifest_path.relative_to(ROOT)),
          'dump_bytes':len(dump_bytes),'dump_sha256':digest(dump_bytes),'globals_sha256':digest(globals_raw)}
        local=json.loads((ROOT/'.local.json').read_text(encoding='utf-8'))
        report['stage']='validate-local-postgres-identity'
        params=conninfo_to_dict(local['dsn'])
        if params.get('host') not in ('127.0.0.1','::1') or params.get('dbname')!='fieldwork':
            raise ValueError('LIVE_DATABASE_IDENTITY_REFUSED')
        if run(['docker','inspect',container]).returncode==0:
            raise ValueError('OWNED_CONTAINER_NAME_ALREADY_EXISTS')
        with socket.socket() as probe:
            try:probe.bind(('127.0.0.1',PORT))
            except OSError:raise ValueError('REHEARSAL_PORT_NOT_FREE') from None
        local_pg=run(['docker','inspect','fieldwork-postgres','--format={{.Image}}'])
        image=local_pg.stdout.decode('ascii','strict').strip()
        if local_pg.returncode or not re.fullmatch(r'sha256:[0-9a-f]{64}',image):
            raise ValueError('LOCAL_POSTGRES_IMAGE_UNAVAILABLE')
        report['postgres_image_id']=image
        password=secrets.token_urlsafe(32); docker_env=dict(os.environ);docker_env['POSTGRES_PASSWORD']=password
        proc=run(['docker','run','--pull=never','-d','--name',container,'-p',f'127.0.0.1:{PORT}:5432',
          '-e','POSTGRES_USER=postgres','-e','POSTGRES_PASSWORD','--memory','768m','--cpus','1.0',
          '--shm-size','64m','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,size=512m',image],
          timeout=120,env=docker_env)
        if proc.returncode:raise RuntimeError('SCRATCH_POSTGRES_START_FAILED')
        created=True
        admin=make_conninfo(host='127.0.0.1',port=PORT,dbname='postgres',user='postgres',password=password,connect_timeout=3)
        ready=False
        for _ in range(60):
            try:
                with psycopg.connect(admin) as conn:conn.execute('SELECT 1')
                ready=True;break
            except psycopg.Error:time.sleep(1)
        if not ready:raise RuntimeError('SCRATCH_POSTGRES_READINESS_TIMEOUT')
        globals_safe=re.sub(rb"(?i)\s+PASSWORD\s+(?:'[^']*'|NULL)",b'',globals_raw)
        if re.search(rb'(?i)PASSWORD\s+',globals_safe):raise ValueError('GLOBAL_PASSWORD_REDACTION_INCOMPLETE')
        report['stage']='restore-owned-roles-and-db'
        restored_roles=run(['docker','exec','-i',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1'],input_bytes=globals_safe)
        if restored_roles.returncode:raise RuntimeError('SANITIZED_GLOBALS_RESTORE_FAILED')
        owner=params['user'];dbname=params['dbname']
        with psycopg.connect(admin,autocommit=True) as conn:
            conn.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(dbname),sql.Identifier(owner)))
        restored=run(['docker','exec','-i',container,'pg_restore','-U','postgres','-d',dbname,'--exit-on-error'],input_bytes=dump_bytes,timeout=600)
        if restored.returncode:raise RuntimeError('OWNERSHIP_PRESERVING_RESTORE_FAILED')
        op=make_conninfo(host='127.0.0.1',port=PORT,dbname=dbname,user='postgres',password=password,connect_timeout=5)
        with psycopg.connect(op,row_factory=dict_row,autocommit=True) as conn:
            report['stage']='select-nonprotected-train-input-row'
            probe=conn.execute("""SELECT workspace::text AS workspace,dataset_id::text AS dataset,
                member_id,asset_sha256,asset_bytes FROM public.fw_real_image_inputs
                WHERE run=%s""",(PROBE_RUN,)).fetchall()
            if (len(probe)!=1 or digest(probe[0]['member_id'].encode())!=PROBE_MEMBER_SHA256
                    or probe[0]['asset_sha256']!=PROBE_ASSET_SHA256 or probe[0]['asset_bytes']!=PROBE_ASSET_BYTES
                    or probe[0]['workspace']!=WORKSPACE):
                raise ValueError('NONPROTECTED_TRAIN_PROBE_BINDING_MISMATCH')
            workspace,dataset,member,asset=(probe[0][k] for k in ('workspace','dataset','member_id','asset_sha256'))
            report['stage']='select-exact-train-rights-rows'
            d=conn.execute("SELECT state FROM public.fw_rights_datasets WHERE workspace=%s AND dataset_id=%s",(workspace,dataset)).fetchall()
            a=conn.execute("SELECT rights_state,asset_sha256,asset_bytes,pg_catalog.encode(pg_catalog.sha256(canonical_license),'hex') AS license_hash FROM public.fw_rights_assets WHERE workspace=%s AND dataset_id=%s AND member_id=%s AND asset_sha256=%s",(workspace,dataset,member,asset)).fetchall()
            decisions=conn.execute("SELECT purpose,pg_catalog.encode(pg_catalog.sha256(envelope),'hex') AS envelope_hash FROM public.fw_rights_decisions WHERE workspace=%s AND dataset_id=%s AND member_id=%s AND purpose IN ('local_private_training','model_bundle') ORDER BY purpose",(workspace,dataset,member)).fetchall()
            if (len(d)!=1 or d[0]['state']!='authenticated' or len(a)!=1 or a[0]['rights_state']!='reviewed'
                    or a[0]['asset_sha256']!=asset or a[0]['asset_bytes']!=PROBE_ASSET_BYTES
                    or [x['purpose'] for x in decisions]!=['local_private_training','model_bundle']):
                raise ValueError('NONPROTECTED_TRAIN_RIGHTS_FIXTURE_NOT_READY')
            rights_before={'dataset_state':d[0]['state'],'asset_state':a[0]['rights_state'],
              'asset_sha256':a[0]['asset_sha256'],'asset_bytes':a[0]['asset_bytes'],
              'license_sha256':a[0]['license_hash'],'decisions':decisions}
            report['stage']='read-frozen-version-digest'
            version=conn.execute("SELECT revision,manifest->>'digest' AS digest FROM public.fw_versions WHERE workspace=%s AND id=%s AND state='frozen'",(workspace,VERSION)).fetchone()
            if not version:raise ValueError('FROZEN_VERSION_DIGEST_NOT_FOUND')
            version_before={'revision':version['revision'],'digest':version['digest']}
            counts_before=public_counts(conn);functions_before=source_hashes(conn)
            if any(v is None for v in functions_before.values()):raise ValueError('WORKER_FUNCTIONS_MISSING')
            # The fixture is one previously API-verified rights-cleared train upload.
            # No manifest labels, protected split members, media paths or bytes are read.
            report['stage']='apply-migration-to-scratch-transaction'
            with conn.transaction():conn.execute(outer_body(ROOT/'migrations'/MIGRATION))
            report['stage']='verify-row-counts-and-function-preservation'
            counts_after=public_counts(conn)
            if counts_before!=counts_after:raise ValueError('SCRATCH_PUBLIC_ROW_COUNTS_CHANGED')
            functions_after=source_hashes(conn)
            if functions_after!=functions_before:raise ValueError('SCRATCH_WORKER_FUNCTIONS_CHANGED')
            report['stage']='verify-column-privileges-and-guards'
            privilege_rows={}
            for table,business in {'fw_rights_datasets':'dataset_id','fw_rights_assets':'member_id','fw_rights_decisions':'member_id'}.items():
                row=conn.execute("""SELECT c.relrowsecurity,c.relforcerowsecurity,
                    pg_catalog.has_column_privilege('fieldwork_real_worker_definer',%s,'row_lock_capability','UPDATE') AS capability,
                    pg_catalog.has_column_privilege('fieldwork_real_worker_definer',%s,%s,'UPDATE') AS business,
                    (SELECT a.attnotnull AND pg_catalog.pg_get_expr(d.adbin,d.adrelid)='false'
                     FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
                     WHERE a.attrelid=c.oid AND a.attname='row_lock_capability' AND NOT a.attisdropped) AS default_false,
                    (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid
                     AND t.tgname='fw015_reject_row_lock_capability' AND NOT t.tgisinternal
                     AND t.tgenabled='O' AND t.tgqual IS NULL) AS trigger_count
                    FROM pg_catalog.pg_class c WHERE c.oid=pg_catalog.to_regclass(%s)""",
                    ('public.'+table,'public.'+table,business,'public.'+table)).fetchone()
                privilege_rows[table]=dict(row)
            if any(not (v['relrowsecurity'] and v['relforcerowsecurity'] and v['capability']
                    and not v['business'] and v['default_false'] and v['trigger_count']==1)
                    for v in privilege_rows.values()):raise ValueError('SCRATCH_ROW_LOCK_PRIVILEGE_POSTCONDITION_FAILED')
            guard=conn.execute("""SELECT r.rolname,p.prosecdef,p.proconfig,
                NOT pg_catalog.has_function_privilege('public',p.oid,'EXECUTE') AS no_public
                FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid=p.proowner
                WHERE p.oid='public.fw015_reject_row_lock_capability_mutation()'::regprocedure""").fetchone()
            if not guard or guard['rolname']!='fieldwork' or guard['prosecdef'] or guard['proconfig']!=['search_path=pg_catalog, pg_temp'] or not guard['no_public']:
                raise ValueError('SCRATCH_GUARD_FUNCTION_POSTCONDITION_FAILED')
            role=conn.execute("SELECT principal FROM fw_worker_cap_v1.scope WHERE %s=ANY(workspaces)",(workspace,)).fetchall()
            if len(role)!=1:raise ValueError('SCOPED_PRINCIPAL_NOT_UNIQUE')
            principal=role[0]['principal']
            report['stage']='create scratch probe schema'
            conn.execute('CREATE SCHEMA fw015_probe AUTHORIZATION fieldwork_real_worker_definer')
            conn.execute('REVOKE ALL ON SCHEMA fw015_probe FROM PUBLIC')
            conn.execute(sql.SQL('GRANT USAGE ON SCHEMA fw015_probe TO {}').format(sql.Identifier(principal)))
            # Scratch-only probes are SECURITY DEFINER owned by the same NOLOGIN
            # definer as production. Their sole EXECUTE grantee is the cloned scoped principal.
            report['stage']='create scratch FOR SHARE probe function'
            conn.execute("""CREATE FUNCTION fw015_probe.fw015_probe_for_share(p_workspace text,p_dataset text,p_member text,p_asset text)
              RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $probe$
              BEGIN
                BEGIN
                  PERFORM 1 FROM public.fw_rights_datasets WHERE workspace=p_workspace AND dataset_id=p_dataset AND state='authenticated' FOR SHARE;
                  IF NOT FOUND THEN RETURN false; END IF;
                EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'FW015_PROBE_DATASET' USING ERRCODE=SQLSTATE; END;
                BEGIN
                  PERFORM 1 FROM public.fw_rights_assets WHERE workspace=p_workspace AND dataset_id=p_dataset AND member_id=p_member AND asset_sha256=p_asset AND rights_state='reviewed' FOR SHARE;
                  IF NOT FOUND THEN RETURN false; END IF;
                EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'FW015_PROBE_ASSET' USING ERRCODE=SQLSTATE; END;
                BEGIN
                  PERFORM 1 FROM public.fw_rights_decisions WHERE workspace=p_workspace AND dataset_id=p_dataset AND member_id=p_member AND purpose='local_private_training' FOR SHARE;
                  IF NOT FOUND THEN RETURN false; END IF;
                EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'FW015_PROBE_TRAIN_DECISION' USING ERRCODE=SQLSTATE; END;
                BEGIN
                  PERFORM 1 FROM public.fw_rights_decisions WHERE workspace=p_workspace AND dataset_id=p_dataset AND member_id=p_member AND purpose='model_bundle' FOR SHARE;
                  IF NOT FOUND THEN RETURN false; END IF;
                EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'FW015_PROBE_BUNDLE_DECISION' USING ERRCODE=SQLSTATE; END;
                RETURN true;
              END $probe$""")
            report['stage']='create scratch inert update probe function'
            conn.execute("""CREATE FUNCTION fw015_probe.fw015_probe_inert_update(p_workspace text,p_dataset text)
              RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $probe$
              BEGIN
                UPDATE public.fw_rights_datasets SET row_lock_capability=NOT row_lock_capability
                  WHERE workspace::text=p_workspace AND dataset_id::text=p_dataset;
                RETURN 'NO_ERROR';
              EXCEPTION WHEN insufficient_privilege THEN RETURN SQLSTATE;
              END $probe$""")
            report['stage']='create scratch business update probe function'
            conn.execute("""CREATE FUNCTION fw015_probe.fw015_probe_business_update(p_workspace text,p_dataset text)
              RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $probe$
              BEGIN
                UPDATE public.fw_rights_datasets SET state=state
                  WHERE workspace::text=p_workspace AND dataset_id::text=p_dataset;
                RETURN 'NO_ERROR';
              EXCEPTION WHEN insufficient_privilege THEN RETURN SQLSTATE;
              END $probe$""")
            for fn in ('fw015_probe_for_share(text,text,text,text)','fw015_probe_inert_update(text,text)','fw015_probe_business_update(text,text)'):
                name,argspec=fn.split('(',1);argspec=argspec.rstrip(')')
                report['stage']='set scratch probe function owner'
                conn.execute(f'ALTER FUNCTION fw015_probe.{name}({argspec}) OWNER TO fieldwork_real_worker_definer')
                report['stage']='revoke scratch probe function PUBLIC execute'
                conn.execute(f'REVOKE ALL ON FUNCTION fw015_probe.{name}({argspec}) FROM PUBLIC')
                report['stage']='grant scratch probe function to scoped principal'
                conn.execute(f'GRANT EXECUTE ON FUNCTION fw015_probe.{name}({argspec}) TO {sql.Identifier(principal).as_string(conn)}')
        report['stage']='connect as scratch scoped principal'
        with psycopg.connect(op,row_factory=dict_row,autocommit=True) as conn:
            report['stage']='set session authorization to scratch scoped principal'
            conn.execute(sql.SQL('SET SESSION AUTHORIZATION {}').format(sql.Identifier(principal)))
            try:
                report['stage']='probe scoped FOR SHARE locks'
                locked=conn.execute('SELECT fw015_probe.fw015_probe_for_share(%s,%s,%s,%s) AS ok',
                    (workspace,dataset,member,asset)).fetchone()['ok']
                report['stage']='probe inert capability update guard'
                inert=conn.execute('SELECT fw015_probe.fw015_probe_inert_update(%s,%s) AS sqlstate',
                    (workspace,dataset)).fetchone()['sqlstate']
                report['stage']='probe business column update denial'
                business=conn.execute('SELECT fw015_probe.fw015_probe_business_update(%s,%s) AS sqlstate',
                    (workspace,dataset)).fetchone()['sqlstate']
            finally:
                conn.execute('RESET SESSION AUTHORIZATION')
            if not locked or inert!='42501' or business!='42501':
                raise ValueError('SCRATCH_DEFINER_ROW_LOCK_PROBE_FAILED')
        with psycopg.connect(op,row_factory=dict_row) as conn:
            rights_after=conn.execute("""SELECT d.state AS dataset_state,a.rights_state AS asset_state,
                a.asset_sha256,a.asset_bytes,pg_catalog.encode(pg_catalog.sha256(a.canonical_license),'hex') AS license_hash,
                (SELECT jsonb_agg(jsonb_build_object('purpose',purpose,'envelope_hash',pg_catalog.encode(pg_catalog.sha256(envelope),'hex')) ORDER BY purpose)
                 FROM public.fw_rights_decisions WHERE workspace=%s AND dataset_id::text=%s AND member_id=%s
                 AND purpose IN ('local_private_training','model_bundle')) AS decisions
                FROM public.fw_rights_datasets d JOIN public.fw_rights_assets a
                  ON a.workspace=d.workspace AND a.dataset_id=d.dataset_id
                WHERE d.workspace=%s AND d.dataset_id=%s AND a.member_id=%s AND a.asset_sha256=%s""",
                (workspace,dataset,member,workspace,dataset,member,asset)).fetchone()
            ver=conn.execute("SELECT revision,manifest->>'digest' AS digest FROM public.fw_versions WHERE workspace=%s AND id=%s AND state='frozen'",(workspace,VERSION)).fetchone()
            if not rights_after or not ver:raise ValueError('RIGHTS_OR_VERSION_POSTSTATE_MISSING')
            rights_projection={'dataset_state':rights_after['dataset_state'],'asset_state':rights_after['asset_state'],
              'asset_sha256':rights_after['asset_sha256'],'asset_bytes':rights_after['asset_bytes'],
              'license_sha256':rights_after['license_hash'],'decisions':rights_after['decisions']}
            version_after={'revision':ver['revision'],'digest':ver['digest']}
        if rights_projection!=rights_before or version_after!=version_before:
            raise ValueError('RIGHTS_OR_FROZEN_VERSION_CHANGED')
        report.update({'existing_public_rows_preserved':counts_before==counts_after,
          'existing_worker_functions_unchanged':functions_before==functions_after,
          'rights_locks_preserved':True,'scoped_for_share_probe_passed':bool(locked),
          'inert_capability_update_rejected':inert=='42501','business_column_update_denied':business=='42501',
          'rights_state_unchanged':rights_projection==rights_before,
          'frozen_version_digest_unchanged':version_after==version_before,
          'row_lock_postconditions':privilege_rows,'trigger_guard_security':{
            'owner':guard['rolname'],'security_definer':guard['prosecdef'],'search_path':guard['proconfig'],
            'public_execute':not guard['no_public']},
          'probe_member_sha256':PROBE_MEMBER_SHA256,'probe_asset_sha256':PROBE_ASSET_SHA256,
          'probe_asset_bytes':PROBE_ASSET_BYTES,'protected_rows_or_media_not_read':True,
          'holdout_evaluation_not_performed':True,'status':'PASS','stage':'complete'})
    except BaseException as exc:
        report['status']='FAIL';report['failure_class']=type(exc).__name__
        if isinstance(exc,FileNotFoundError):
            report['missing_basename']=Path(exc.filename).name if exc.filename else None
        if isinstance(exc,psycopg.Error):report['sqlstate']=exc.sqlstate
        if isinstance(exc,psycopg.errors.UndefinedFunction):
            primary=getattr(getattr(exc,'diag',None),'message_primary',None) or ''
            match=re.search(r'function\s+([A-Za-z0-9_.]+\([^)]*\))\s+does not exist',primary)
            if match:report['undefined_function_signature']=match.group(1)[:160]
            elif primary.startswith('operator does not exist:'):
                report['undefined_routine_kind']='operator'
                detail=primary.split(':',1)[-1].strip()
                if re.fullmatch(r'[A-Za-z0-9_. <>!=]{1,120}',detail):report['undefined_operator_types']=detail
            else:report['undefined_routine_kind']='other'
        primary=getattr(getattr(exc,'diag',None),'message_primary',None) or ''
        if primary in {'FW015_PROBE_DATASET','FW015_PROBE_ASSET','FW015_PROBE_TRAIN_DECISION','FW015_PROBE_BUNDLE_DECISION'}:
            report['probe_failure_stage']=primary
        raw=exc.args[0] if exc.args else ''
        report['failure_code']=raw if isinstance(raw,str) and re.fullmatch(r'[A-Z0-9_]{1,80}',raw) else None
    finally:
        report['container_removed']=(run(['docker','rm','-f',container],timeout=120).returncode==0) if created else True
        if not report['container_removed']:report['status']='FAIL'
        report['finished_utc']=datetime.now(timezone.utc).isoformat()
        evidence=out/'report.json';evidence.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({'status':report['status'],'evidence':str(evidence.relative_to(ROOT))},sort_keys=True))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
