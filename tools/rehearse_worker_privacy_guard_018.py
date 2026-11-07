from __future__ import annotations
import argparse, hashlib, json, os, re, secrets, socket, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row

ROOT=Path(__file__).resolve().parents[1]
MIGRATION='018_worker_privacy_guard_execute.sql'
CONTAINER_PREFIX='fieldwork-worker-privacy018-'
PORT=15546
WORKSPACE='814830e3-55a0-4925-ad37-5d3dac7d4df8'
EXPECTED={
 'migrations/017_privacy_lifecycle.sql':'81e7587f33a5a30fa9a8c48369703a5c2266d3ad52926c28ab9b14974eb116ee',
 'migrations/018_worker_privacy_guard_execute.sql':'0073beb0c1fe6093ae5e63b062bb38a160bede8bcf062bf6244cdf505bf184c8',
}

def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def run(cmd,*,input_bytes=None,timeout=300,env=None):
 return subprocess.run(cmd,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False,env=env)
def resource_gate():
 import psutil,shutil
 disk=shutil.disk_usage(ROOT.drive+'\\'); vm=psutil.virtual_memory()
 p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
  'Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | Select-Object CommittedBytes,CommitLimit,PercentCommittedBytesInUse | ConvertTo-Json -Compress'],
  stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False,text=True)
 try: x=json.loads(p.stdout); commit=int(x['PercentCommittedBytesInUse']); used=int(x['CommittedBytes']); limit=int(x['CommitLimit'])
 except Exception: raise RuntimeError('HOST_COMMIT_COUNTER_UNAVAILABLE') from None
 if p.returncode or limit<=0 or used>limit or disk.free<50*1024**3 or vm.available<=6*1024**3 or commit>=85:
  raise RuntimeError('HOST_RESOURCE_GATE_REFUSED')
 return {'c_free_bytes':disk.free,'available_ram_bytes':vm.available,'commit_percent':commit,
  'commit_source':'Win32_PerfFormattedData_PerfOS_Memory','committed_bytes':used,'commit_limit_bytes':limit}
def outer_body(path):
 lines=path.read_text(encoding='utf-8').splitlines(keepends=True)
 first=next((i for i,l in enumerate(lines) if l.strip() and not l.lstrip().startswith('--')),None)
 nonblank=[i for i,l in enumerate(lines) if l.strip()]
 if first is None or lines[first].strip().upper()!='BEGIN;' or lines[nonblank[-1]].strip().upper()!='COMMIT;': raise RuntimeError('MIGRATION_ENVELOPE_INVALID')
 return ''.join(lines[:first]+lines[first+1:nonblank[-1]]+lines[nonblank[-1]+1:])
def auth_probe(conn, role):
 conn.execute('SET ROLE '+sql.Identifier(role).as_string(conn))
 try:
  conn.execute('SET TRANSACTION READ ONLY')
  v=conn.execute('SELECT public.fw_privacy_workspace_deleted_v1(%s) AS deleted',(WORKSPACE,)).fetchone()['deleted']
  return {'sqlstate':None,'returned':bool(v)}
 except psycopg.errors.InsufficientPrivilege as e:
  s=e.sqlstate;conn.rollback();return {'sqlstate':s,'returned':None}
 finally:
  try:conn.execute('RESET ROLE')
  except psycopg.Error:conn.rollback()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--backup-manifest',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);args=ap.parse_args()
 stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'); out=args.out.resolve(); out.mkdir(parents=True,exist_ok=False)
 cname=CONTAINER_PREFIX+stamp.lower(); nonce=secrets.token_hex(16); created=False; report={'schema':'fieldwork.worker-privacy-guard-018-rehearsal/v1','stage':'start','live_database_touched':False,'container':cname,'port':PORT,'started_utc':datetime.now(timezone.utc).isoformat()}
 try:
  report['host_resource_gate']=resource_gate()
  mp=args.backup_manifest.resolve(strict=True);mp.relative_to((ROOT/'var/snapshots').resolve(strict=True));m=json.loads(mp.read_text(encoding='utf-8'))
  if m.get('container')!='fieldwork-postgres' or m.get('database')!='fieldwork':raise RuntimeError('BACKUP_DATABASE_IDENTITY_UNEXPECTED')
  dump=ROOT/m['db']['path']; globals_path=ROOT/m['globals']['path'];dbraw=dump.read_bytes();globals_raw=globals_path.read_bytes()
  if sha(dbraw)!=m['db']['sha256'] or sha(globals_raw)!=m['globals']['sha256']:raise RuntimeError('BACKUP_DIGEST_MISMATCH')
  pins={k:sha((ROOT/k).read_bytes()) for k in EXPECTED}
  if any(EXPECTED[k] and pins[k]!=EXPECTED[k] for k in EXPECTED):raise RuntimeError('SOURCE_PIN_MISMATCH')
  pins['tools/rehearse_worker_privacy_guard_018.py']=sha(Path(__file__).read_bytes())
  report['source_sha256']=pins;report['backup']={'manifest':str(mp.relative_to(ROOT)),'dump_bytes':len(dbraw),'dump_sha256':sha(dbraw),'globals_sha256':sha(globals_raw)}
  local=json.loads((ROOT/'.local.json').read_text(encoding='utf-8'));params=conninfo_to_dict(local['dsn'])
  if params.get('host') not in ('127.0.0.1','::1') or params.get('dbname')!='fieldwork':raise RuntimeError('LIVE_DATABASE_IDENTITY_REFUSED')
  with socket.socket() as s:
   try:s.bind(('127.0.0.1',PORT))
   except OSError:raise RuntimeError('SCRATCH_PORT_NOT_FREE') from None
  if run(['docker','inspect',cname]).returncode==0:raise RuntimeError('OWNED_CONTAINER_NAME_ALREADY_EXISTS')
  image=run(['docker','inspect','fieldwork-postgres','--format={{.Image}}'])
  image_id=image.stdout.decode('ascii','strict').strip()
  if image.returncode or not re.fullmatch(r'sha256:[0-9a-f]{64}',image_id):raise RuntimeError('LOCAL_POSTGRES_IMAGE_UNAVAILABLE')
  report['postgres_image_id']=image_id
  password=secrets.token_urlsafe(32);env=dict(os.environ);env['POSTGRES_PASSWORD']=password
  r=run(['docker','run','--pull=never','-d','--name',cname,'--label','fieldwork.owner=worker-privacy018-rehearsal','--label','fieldwork.nonce='+nonce,'-p',f'127.0.0.1:{PORT}:5432','-e','POSTGRES_USER=postgres','-e','POSTGRES_PASSWORD','--memory','768m','--cpus','1.0','--shm-size','64m','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,size=512m',image_id],timeout=120,env=env)
  if r.returncode:raise RuntimeError('SCRATCH_POSTGRES_START_FAILED')
  created=True
  admin=make_conninfo(host='127.0.0.1',port=PORT,dbname='postgres',user='postgres',password=password,connect_timeout=3)
  ready=False
  for _ in range(60):
   try:
    with psycopg.connect(admin) as c:c.execute('SELECT 1')
    ready=True;break
   except psycopg.Error:time.sleep(1)
  if not ready:raise RuntimeError('SCRATCH_POSTGRES_READINESS_TIMEOUT')
  globals_safe=re.sub(rb"(?i)\s+PASSWORD\s+(?:'[^']*'|NULL)",b'',globals_raw)
  if re.search(rb'(?i)PASSWORD\s+',globals_safe):raise RuntimeError('GLOBAL_PASSWORD_REDACTION_INCOMPLETE')
  if run(['docker','exec','-i',cname,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1'],input_bytes=globals_safe).returncode:raise RuntimeError('SANITIZED_GLOBALS_RESTORE_FAILED')
  owner=params['user'];dbname=params['dbname']
  with psycopg.connect(admin,autocommit=True) as c:c.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(dbname),sql.Identifier(owner)))
  if run(['docker','exec','-i',cname,'pg_restore','-U','postgres','-d',dbname,'--exit-on-error'],input_bytes=dbraw,timeout=600).returncode:raise RuntimeError('OWNERSHIP_PRESERVING_RESTORE_FAILED')
  scratch=make_conninfo(host='127.0.0.1',port=PORT,dbname=dbname,user='postgres',password=password,connect_timeout=5)
  with psycopg.connect(scratch,row_factory=dict_row,autocommit=True) as c:
   report['stage']='verify_pre_migration_failure_as_start_owner'
   pre=c.execute('''SELECT pg_catalog.pg_get_userbyid(p.proowner) AS owner,p.prosecdef AS secdef,
     pg_catalog.has_function_privilege('fw_worker_v1_definer','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS start_owner_execute,
     pg_catalog.has_function_privilege('fieldwork_real_worker_definer','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS real_owner_execute,
     pg_catalog.has_function_privilege('fieldwork_api','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS api_execute
     FROM pg_catalog.pg_proc p WHERE p.oid='fw_worker_cap_v1.start(text,text,text,integer,integer,text,uuid,text)'::regprocedure''').fetchone()
   if pre['owner']!='fw_worker_v1_definer' or not pre['secdef'] or pre['start_owner_execute'] or not pre['real_owner_execute'] or not pre['api_execute']:raise RuntimeError('SCRATCH_PRECONDITION_MISMATCH')
   with psycopg.connect(scratch,row_factory=dict_row) as probe:
    pre_call=auth_probe(probe,'fw_worker_v1_definer')
   if pre_call['sqlstate']!='42501':raise RuntimeError('SCRATCH_017_FAILURE_NOT_REPRODUCED')
   report['pre_018']={'start_owner':pre['owner'],'start_owner_execute':pre['start_owner_execute'],'real_owner_execute':pre['real_owner_execute'],'api_execute':pre['api_execute'],'owner_guard_call_sqlstate':pre_call['sqlstate']}
   report['stage']='apply_018_transaction'
   with c.transaction():c.execute(outer_body(ROOT/'migrations'/MIGRATION))
   report['stage']='verify_post_migration_scoped_permissions'
   post=c.execute('''SELECT pg_catalog.has_function_privilege('fw_worker_v1_definer','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS start_owner_execute,
     pg_catalog.has_function_privilege('fieldwork_real_worker_definer','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS real_owner_execute,
     pg_catalog.has_function_privilege('fieldwork_api','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS api_execute,
     pg_catalog.has_function_privilege('fieldwork_intake_worker','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS intake_execute,
     EXISTS(SELECT 1 FROM pg_catalog.aclexplode((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure)) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
    ''').fetchone()
   if not post['start_owner_execute'] or not post['real_owner_execute'] or not post['api_execute'] or not post['intake_execute'] or post['public_execute']:raise RuntimeError('SCRATCH_POST_PRIVILEGE_CHECK_FAILED')
   login=c.execute("SELECT principal FROM fw_worker_cap_v1.scope WHERE %s=ANY(workspaces)",(WORKSPACE,)).fetchone()['principal']
   if c.execute('SELECT pg_catalog.has_function_privilege(%s,%s,%s) AS ok',(login,'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')).fetchone()['ok']:raise RuntimeError('SCOPED_LOGIN_GOT_DIRECT_PRIVILEGE')
   with psycopg.connect(scratch,row_factory=dict_row) as probe:
    post_call=auth_probe(probe,'fw_worker_v1_definer')
   if post_call.get('sqlstate') is not None or post_call.get('returned') is not False:raise RuntimeError('SCRATCH_OWNER_CALL_DID_NOT_PASS')
   report['post_018']={**post,'scoped_login_direct_execute':False,'owner_guard_call':post_call}
   report['stage']='verified'
  report['status']='PASS';report['finished_utc']=datetime.now(timezone.utc).isoformat()
 except Exception as exc:
  report.update(status='FAIL',error_code=(str(exc) if str(exc).isupper() and len(str(exc))<100 else 'REHEARSAL_EXCEPTION_'+type(exc).__name__),failed_stage=report.get('stage'),finished_utc=datetime.now(timezone.utc).isoformat())
 finally:
  cleanup={'attempted':created,'confirmed':not created}
  if created:
   i=run(['docker','inspect',cname,'--format={{json .Config.Labels}}'],timeout=30)
   try:labels=json.loads(i.stdout.decode('utf-8','strict')) if i.returncode==0 else {}
   except Exception:labels={}
   if i.returncode==0 and labels.get('fieldwork.owner')=='worker-privacy018-rehearsal' and labels.get('fieldwork.nonce')==nonce:
    rm=run(['docker','rm','-f',cname],timeout=60)
    absent=run(['docker','inspect',cname],timeout=20).returncode!=0
    cleanup['confirmed']=rm.returncode==0 and absent
   else:cleanup['confirmed']=False
  report['scratch_container_cleanup']=cleanup
  report['finished_utc']=datetime.now(timezone.utc).isoformat()
  (out/'rehearsal.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
 print(json.dumps({'status':report.get('status'),'failed_stage':report.get('failed_stage'),'error_code':report.get('error_code'),'report':str(out/'rehearsal.json'),'cleanup_confirmed':cleanup['confirmed']}))
 return 0 if report.get('status')=='PASS' and cleanup['confirmed'] else 2
if __name__=='__main__':raise SystemExit(main())



