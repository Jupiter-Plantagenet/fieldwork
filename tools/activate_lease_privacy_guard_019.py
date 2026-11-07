from __future__ import annotations
import hashlib, json, os, shutil, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parent
WORKSPACE='814830e3-55a0-4925-ad37-5d3dac7d4df8'
VERSION='01a0f1aa-90cd-4875-9060-8c8f0204520b'
RUN='4b71572f-9d06-4b9f-86fb-162aa4b18616'
MIGRATION=ROOT/'migrations/019_lease_privacy_guard_execute.sql'
EXPECTED='8698b0f0c8e02d09f577e90d11673db336a8b71bcca944e275f4ddfd136bbf34'
EXPECTED_017='81e7587f33a5a30fa9a8c48369703a5c2266d3ad52926c28ab9b14974eb116ee'
EXPECTED_018='0073beb0c1fe6093ae5e63b062bb38a160bede8bcf062bf6244cdf505bf184c8'
EXPECTED_REHEARSAL_HELPER='352a5f9f329c4f788208b9e85abe01f90c35e92058f98f568b35107a22f38795'
EXPECTED_SYSTEM_IDENTIFIER='7700868276222033955'
EXPECTED_DATABASE_OID=16384
REHEARSAL=ROOT/'.local/round5-resume/lease-privacy019-scratch-20261102T1042Z/rehearsal.json'
CATALOG_RECEIPT=ROOT/'.local/real-data/activation/lease-privacy019-catalog-20261102T104455Z.json'
CATALOG_RECEIPT_SHA256='986ea808c457ff05ca8c4270cd245a25b2dd537ba77ee134a582d653dcdd3acf'

def digest(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()
def sha_file(p:Path)->str:return digest(p.read_bytes())
def require_lock():
 import psutil
 lock=REPO/'.cache/product-build.lock'; record=json.loads((lock/'owner.json').read_text(encoding='utf-8'))
 ancestors={(p.pid,p.create_time()) for p in psutil.Process().parents()}
 if record.get('product')!='fieldwork' or record.get('purpose')!='fieldwork-real-activation' or (record.get('pid'),record.get('create_time')) not in ancestors:
  raise RuntimeError('FIELDWORK_REAL_ACTIVATION_LOCK_REQUIRED')
 return {'pid':record['pid'],'product':'fieldwork','purpose':'fieldwork-real-activation'}
def migration_body(path):
 lines=path.read_text(encoding='utf-8').splitlines(keepends=True)
 nonblank=[i for i,l in enumerate(lines) if l.strip()]
 first=next((i for i,l in enumerate(lines) if l.strip() and not l.lstrip().startswith('--')),None)
 if first is None or lines[first].strip().upper()!='BEGIN;' or lines[nonblank[-1]].strip().upper()!='COMMIT;':raise RuntimeError('MIGRATION_ENVELOPE_INVALID')
 return ''.join(lines[:first]+lines[first+1:nonblank[-1]]+lines[nonblank[-1]+1:])
def count_snapshot(c):
 rows=c.execute("SELECT workspace,id,state FROM public.fw_runs WHERE state='queued' ORDER BY workspace,id").fetchall()
 encoded='\n'.join(r['workspace']+'|'+r['id']+'|'+r['state'] for r in rows).encode()
 version=c.execute('''SELECT state,revision,
   pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(manifest::text,'UTF8')),'hex') AS manifest_sha256
   FROM public.fw_versions WHERE workspace=%s AND id=%s''',(WORKSPACE,VERSION)).fetchone()
 return {'queued_count':len(rows),'queued_digest':digest(encoded),'version':dict(version) if version else None}
def helper_facts(c):
 return c.execute('''SELECT
   (SELECT pg_catalog.pg_get_userbyid(p.proowner) FROM pg_catalog.pg_proc p WHERE p.oid='fw_lease_cap_v1.expire(text,integer,integer,text)'::regprocedure) AS expire_owner,
   (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid='fw_lease_cap_v1.expire(text,integer,integer,text)'::regprocedure) AS expire_secdef,
   (SELECT p.proconfig FROM pg_catalog.pg_proc p WHERE p.oid='fw_lease_cap_v1.expire(text,integer,integer,text)'::regprocedure) AS expire_config,
   (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid='fw_lease_cap_v1.expire(text,integer,integer,text)'::regprocedure) AS expire_source_sha,
   (SELECT p.proacl::text FROM pg_catalog.pg_proc p WHERE p.oid='fw_lease_cap_v1.expire(text,integer,integer,text)'::regprocedure) AS expire_acl,
   pg_catalog.has_function_privilege('fw_lease_machine_v1','fw_lease_cap_v1.expire(text,integer,integer,text)','EXECUTE') AS lease_login_expire_execute,
   (SELECT NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication
      FROM pg_catalog.pg_roles r WHERE r.rolname='fw_lease_machine_v1_owner') AS lease_owner_safe,
   EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member OR r.oid=m.roleid
      WHERE r.rolname IN ('fw_lease_machine_v1','fw_lease_machine_v1_owner')) AS lease_membership_present,
   (SELECT pg_catalog.pg_get_userbyid(p.proowner) FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure) AS guard_owner,
   (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure) AS guard_secdef,
   (SELECT p.proconfig FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure) AS guard_config,
   (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure) AS guard_source_sha,
   (SELECT p.proacl::text FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure) AS guard_acl,
   pg_catalog.has_function_privilege('fw_lease_machine_v1_owner','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS lease_owner_guard_execute,
   pg_catalog.has_function_privilege('fw_lease_machine_v1','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS lease_login_guard_execute,
   pg_catalog.has_function_privilege('fw_worker_v1_definer','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS worker_definer_execute,
   pg_catalog.has_function_privilege('fieldwork_real_worker_definer','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS real_definer_execute,
   pg_catalog.has_function_privilege('fieldwork_api','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS api_execute,
   pg_catalog.has_function_privilege('fieldwork_intake_worker','public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS intake_execute,
   EXISTS(SELECT 1 FROM pg_catalog.aclexplode((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure)) a
     WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute,
   (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_run_delete_fence_v1()'::regprocedure) AS trigger_source_sha,
   (SELECT pg_catalog.pg_get_userbyid(p.proowner) FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_run_delete_fence_v1()'::regprocedure) AS trigger_owner,
   (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_run_delete_fence_v1()'::regprocedure) AS trigger_secdef,
   (SELECT p.proconfig FROM pg_catalog.pg_proc p WHERE p.oid='public.fw_privacy_run_delete_fence_v1()'::regprocedure) AS trigger_config''').fetchone()
def write_receipt(path:Path, receipt:dict):
 temp=path.with_suffix(path.suffix+'.tmp')
 payload=(json.dumps(receipt,indent=2,sort_keys=True)+'\n').encode('utf-8')
 with open(temp,'xb') as f:
  f.write(payload);f.flush();os.fsync(f.fileno())
 os.replace(temp,path)
 try:
  fd=os.open(path.parent,os.O_RDONLY);os.fsync(fd);os.close(fd)
 except OSError:pass
def verify_backup_file(item:dict)->dict:
 rel=Path(item.get('path',''))
 if rel.is_absolute() or '..' in rel.parts or len(rel.parts)<3 or rel.parts[:2]!=('var','snapshots'):
  raise RuntimeError('BACKUP_FILE_PATH_INVALID')
 path=ROOT/rel
 from fieldwork.scoped_authority import check_private
 check_private(path)
 raw=path.read_bytes();actual={'path':rel.as_posix(),'bytes':len(raw),'sha256':digest(raw)}
 if actual['bytes']!=item.get('bytes') or actual['sha256']!=item.get('sha256'):
  raise RuntimeError('BACKUP_FILE_DIGEST_MISMATCH')
 return actual
def main():
 require_lock()
 if sha_file(MIGRATION)!=EXPECTED:raise RuntimeError('MIGRATION_SOURCE_PIN_MISMATCH')
 rehearsal=json.loads(REHEARSAL.read_text(encoding='utf-8'))
 if (rehearsal.get('status')!='PASS' or rehearsal.get('live_database_touched') is not False
     or rehearsal.get('scratch_container_cleanup',{}).get('confirmed') is not True
     or rehearsal.get('source_sha256',{}).get('migrations/019_lease_privacy_guard_execute.sql')!=EXPECTED
     or rehearsal.get('source_sha256',{}).get('tools/rehearse_lease_privacy_019.py')!=EXPECTED_REHEARSAL_HELPER
     or rehearsal.get('pre_019',{}).get('expire_sqlstate')!='42501'
     or rehearsal.get('post_019',{}).get('target_state')!='cancelled'):
  raise RuntimeError('SCRATCH_REHEARSAL_BINDING_FAILED')
 if sha_file(CATALOG_RECEIPT)!=CATALOG_RECEIPT_SHA256:raise RuntimeError('CATALOG_RECEIPT_PIN_MISMATCH')
 catalog=json.loads(CATALOG_RECEIPT.read_text(encoding='utf-8'))
 catalog_functions={row['signature']:row for row in catalog.get('function_facts',[])}
 expiry_catalog=next((v for k,v in catalog_functions.items() if k.endswith('expire(text,integer,integer,text)')),None)
 trigger_catalog=next((v for k,v in catalog_functions.items() if k.endswith('fw_privacy_run_delete_fence_v1()')),None)
 guard_catalog=next((v for k,v in catalog_functions.items() if k.endswith('fw_privacy_workspace_deleted_v1(text)')),None)
 if (catalog.get('database',{}).get('identity',{}).get('database_oid')!=EXPECTED_DATABASE_OID
     or catalog.get('database',{}).get('identity',{}).get('system_identifier')!=EXPECTED_SYSTEM_IDENTIFIER
     or catalog.get('privacy_run_trigger_attached') is not True
     or not expiry_catalog or not trigger_catalog or not guard_catalog
     or trigger_catalog.get('source_sha') not in MIGRATION.read_text(encoding='utf-8')):
  raise RuntimeError('CATALOG_RECEIPT_SOURCE_BINDING_FAILED')
 stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 source_before={p.name:digest(p.read_bytes()) for p in (ROOT/'migrations').glob('[0-9][0-1][0-9]_*.sql') if 3<=int(p.name[:3])<=18}
 if source_before.get('017_privacy_lifecycle.sql')!=EXPECTED_017 or source_before.get('018_worker_privacy_guard_execute.sql')!=EXPECTED_018:
  raise RuntimeError('PRIOR_MIGRATION_SOURCE_PIN_MISMATCH')
 out=ROOT/'.local/real-data/activation';out.mkdir(parents=True,exist_ok=True)
 source_backup=ROOT/'.local/real-data/activation-backups'/('lease-privacy019-'+stamp)
 source_backup.mkdir(parents=True,exist_ok=False)
 from fieldwork.scoped_authority import check_private
 check_private(source_backup.parent);check_private(source_backup)
 for name in sorted(source_before):
  shutil.copy2(ROOT/'migrations'/name,source_backup/name)
 shutil.copy2(MIGRATION,source_backup/MIGRATION.name)
 if any(digest((source_backup/n).read_bytes())!=h for n,h in source_before.items()) or digest((source_backup/MIGRATION.name).read_bytes())!=EXPECTED:raise RuntimeError('MIGRATION_SOURCE_BACKUP_MISMATCH')
 label='lease-privacy019-before-'+stamp
 backup=subprocess.run([sys.executable,'-B','-m','tools.r5p_backup',label],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300,check=False)
 if backup.returncode:raise RuntimeError('FRESH_BACKUP_FAILED')
 manifests=sorted((ROOT/'var/snapshots').glob(label+'-*.json'),key=lambda p:p.stat().st_mtime_ns)
 if len(manifests)!=1:raise RuntimeError('FRESH_BACKUP_MANIFEST_AMBIGUOUS')
 mp=manifests[0];bm=json.loads(mp.read_text(encoding='utf-8'))
 if bm.get('container')!='fieldwork-postgres' or bm.get('database')!='fieldwork':raise RuntimeError('FRESH_BACKUP_DATABASE_IDENTITY')
 local=json.loads((ROOT/'.local.json').read_text(encoding='utf-8'));dsn=local.get('dsn')
 params=conninfo_to_dict(dsn) if isinstance(dsn,str) else {}
 if params.get('host') not in ('127.0.0.1','::1') or params.get('port')!='5542' or params.get('dbname')!='fieldwork':raise RuntimeError('RETAINED_DATABASE_IDENTITY_REFUSED')
 backup_files={'db':verify_backup_file(bm.get('db',{})),'globals':verify_backup_file(bm.get('globals',{}))}
 pins={p.name:digest(p.read_bytes()) for p in (ROOT/'migrations').glob('[0-9][0-1][0-9]_*.sql') if 3<=int(p.name[:3])<=18}
 if pins!=source_before:raise RuntimeError('PRIOR_MIGRATION_CHANGED_BEFORE_APPLY')
 receipt={'schema':'fieldwork.lease-privacy-guard-019-live-activation/v1','started_utc':datetime.now(timezone.utc).isoformat(),
  'lock':require_lock(),'migration_sha256':EXPECTED,'source_backup':str(source_backup.relative_to(ROOT)),
  'prior_migration_sha256':pins,'rehearsal':str(REHEARSAL.relative_to(ROOT)),
  'catalog_receipt':str(CATALOG_RECEIPT.relative_to(ROOT)),'catalog_receipt_sha256':CATALOG_RECEIPT_SHA256,
  'database_identity':{'host':'loopback','port':5542,'database_oid':EXPECTED_DATABASE_OID,'system_identifier':EXPECTED_SYSTEM_IDENTIFIER},
  'backup':{'manifest':str(mp.relative_to(ROOT)),'db':backup_files['db'],'globals':backup_files['globals']},
  'status':'preflight'}
 path=out/('lease-privacy019-'+stamp+'.json')
 with psycopg.connect(dsn,row_factory=dict_row) as c:
  c.execute('SET TRANSACTION READ ONLY')
  facts=helper_facts(c); before=count_snapshot(c)
  identity=c.execute('''SELECT pg_catalog.current_database() AS database, d.oid AS database_oid,
      (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_identifier
    FROM pg_catalog.pg_database d WHERE d.datname=pg_catalog.current_database()''').fetchone()
  target=c.execute('''SELECT state,revision,fence,epoch,attempt,lease<=clock_timestamp() AS overdue
    FROM public.fw_runs WHERE workspace=%s AND id=%s''',(WORKSPACE,RUN)).fetchone()
  slot=c.execute('SELECT run,fence,launching FROM public.fw_slot WHERE id=1').fetchone()
  if not identity or identity['database']!='fieldwork' or identity['database_oid']!=EXPECTED_DATABASE_OID or identity['system_identifier']!=EXPECTED_SYSTEM_IDENTIFIER:raise RuntimeError('RETAINED_DATABASE_CLUSTER_IDENTITY_REFUSED')
  if facts['expire_owner']!='fw_lease_machine_v1_owner' or not facts['expire_secdef'] or facts['expire_config']!=['search_path=pg_catalog, pg_temp'] or facts['expire_source_sha']!=expiry_catalog['source_sha'] or not facts['lease_login_expire_execute'] or not facts['lease_owner_safe'] or facts['lease_membership_present']:raise RuntimeError('019_LEASE_EXPIRE_CAPABILITY_PRECONDITION_FAILED')
  if facts['guard_owner']!='fieldwork' or not facts['guard_secdef'] or facts['guard_config']!=['search_path=pg_catalog, public'] or facts['guard_source_sha']!=guard_catalog['source_sha'] or facts['lease_owner_guard_execute'] or facts['lease_login_guard_execute'] or facts['public_execute'] or not facts['worker_definer_execute'] or not facts['real_definer_execute'] or not facts['api_execute'] or not facts['intake_execute']:raise RuntimeError('019_PRIVACY_HELPER_PRECONDITION_FAILED')
  if facts['trigger_owner']!='fieldwork' or facts['trigger_secdef'] or facts['trigger_config']!=['search_path=pg_catalog, public'] or facts['trigger_source_sha']!=trigger_catalog['source_sha']:raise RuntimeError('019_PRIVACY_TRIGGER_PRECONDITION_FAILED')
  if before['queued_count']!=21 or not before['version'] or before['version']['state']!='frozen':raise RuntimeError('BUSINESS_QUEUE_OR_VERSION_PRECONDITION_FAILED')
  if not target or target['state']!='cancel_requested' or not target['overdue'] or slot['run'] is not None or slot['launching']:raise RuntimeError('FAILED_RUN_OR_SLOT_PRECONDITION_FAILED')
  receipt.update({'pre_apply':{'guard':dict(facts),'queue':before,'target_run':dict(target),'slot':dict(slot)},'status':'preconditions_passed'})
 receipt['status']='prepared';receipt['prepared_utc']=datetime.now(timezone.utc).isoformat()
 write_receipt(path,receipt)
 body=migration_body(MIGRATION)
 with psycopg.connect(dsn,row_factory=dict_row) as c:
  with c.transaction():
   c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
   c.execute("SET LOCAL lock_timeout='5s'")
   c.execute("SET LOCAL statement_timeout='30s'")
   c.execute('LOCK TABLE public.fw_slot IN SHARE MODE')
   c.execute('LOCK TABLE public.fw_runs, public.fw_versions IN SHARE MODE')
   locked_before=count_snapshot(c)
   locked_target=c.execute('''SELECT state,revision,fence,epoch,attempt,lease<=clock_timestamp() AS overdue
    FROM public.fw_runs WHERE workspace=%s AND id=%s''',(WORKSPACE,RUN)).fetchone()
   locked_slot=c.execute('SELECT run,fence,launching FROM public.fw_slot WHERE id=1').fetchone()
   facts_before=helper_facts(c)
   if locked_before!=before or not locked_target or dict(locked_target)!=dict(target) or dict(locked_slot)!=dict(slot) or dict(facts_before)!=dict(facts):
    raise RuntimeError('ATOMIC_APPLY_PRECONDITION_DRIFT')
   c.execute(body)
   facts_after=helper_facts(c); after=count_snapshot(c)
   target_after=c.execute('''SELECT state,revision,fence,epoch,attempt,lease<=clock_timestamp() AS overdue
    FROM public.fw_runs WHERE workspace=%s AND id=%s''',(WORKSPACE,RUN)).fetchone()
   slot_after=c.execute('SELECT run,fence,launching FROM public.fw_slot WHERE id=1').fetchone()
   after_pins={p.name:digest(p.read_bytes()) for p in (ROOT/'migrations').glob('[0-1][0-1][0-9]_*.sql') if 3<=int(p.name[:3])<=18}
   stable_fields=('expire_owner','expire_secdef','expire_config','expire_source_sha','expire_acl','lease_login_expire_execute','lease_owner_safe','lease_membership_present','guard_owner','guard_secdef','guard_config','guard_source_sha','trigger_source_sha','trigger_owner','trigger_secdef','trigger_config','lease_login_guard_execute','worker_definer_execute','real_definer_execute','api_execute','intake_execute','public_execute')
   if any(facts_after[k]!=facts[k] for k in stable_fields) or facts_after['lease_owner_guard_execute'] is not True or facts['lease_owner_guard_execute'] is not False:raise RuntimeError('019_PRIVACY_HELPER_GRANT_POSTCONDITION_FAILED')
   if after['queued_count']!=before['queued_count'] or after['queued_digest']!=before['queued_digest'] or after['version']!=before['version']:raise RuntimeError('BUSINESS_QUEUE_OR_VERSION_CHANGED')
   if not target_after or dict(target_after)!=dict(target) or dict(slot_after)!=dict(slot):raise RuntimeError('FAILED_RUN_OR_SLOT_CHANGED')
   if after_pins!=source_before:raise RuntimeError('PRIOR_MIGRATION_BYTES_CHANGED')
   receipt.update({'post_apply':{'guard':dict(facts_after),'queue':after,'target_run':dict(target_after),'slot':dict(slot_after)},
    'prior_migration_sha256_after':after_pins,'status':'committed','committed_utc':datetime.now(timezone.utc).isoformat()})
 receipt['status']='applied';write_receipt(path,receipt)
 print(json.dumps({'status':receipt['status'],'receipt':str(path.relative_to(ROOT)),'backup_manifest':str(mp.relative_to(ROOT)),'migration_sha256':EXPECTED,'queued_count':after['queued_count'],'lease_owner_guard_execute':facts_after['lease_owner_guard_execute']}))
if __name__=='__main__':main()
