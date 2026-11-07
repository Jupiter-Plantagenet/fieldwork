"""ML-T-RESTORE proof: retained backup -> restore into an EMPTY, separate PostgreSQL instance.

1. Inside one REPEATABLE READ transaction on the source, export a snapshot,
   hash every public/capability table, and pg_dump that exact snapshot
   (custom format) plus roles (globals).
2. Start a brand-new empty PostgreSQL container (never the source), restore
   roles and the database with original ownership, grants and RLS policies.
3. Copy every committed checkpoint blob into an empty restored blob root,
   verify every manifest/file digest against the restored fw_checkpoints row,
   and rewrite paths to the restored root.
4. Verify table hashes equal the source snapshot, the API principal can log in,
   is non-superuser/non-bypass, sees no rows without a tenant and only its
   tenant's rows with one, and the fw_checkpoint_read_v1 helper verifies.
5. Restore fencing BEFORE any worker is enabled: running -> interrupted,
   cancel_requested -> cancelled, fence+1, slot cleared. Then an old worker
   carrying the pre-restore fence/generation of a live attempt is refused for
   heartbeat, checkpoint publish and complete.

Usage: python -m tools.restore_proof --out <dir> [--source-container fieldwork-postgres]
Credentials are read from private profiles and never printed.
"""
import argparse,hashlib,json,os,shutil,subprocess,sys,time,uuid
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.conninfo import conninfo_to_dict,make_conninfo
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))

TABLES_SQL="""SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' ORDER BY 1,2"""


MEDIA_SQL="""SELECT DISTINCT s->>'sha256' sha256, s->>'file' file FROM fw_versions v,
LATERAL jsonb_array_elements(v.manifest->'samples') s WHERE v.manifest->>'scope'='real-rights-cleared' AND s ? 'file'"""
BUNDLES_SQL="""SELECT id,artifact_result->>'artifact_directory' d,artifact_result->>'bundle_digest' b FROM fw_runs
WHERE config->>'scope'='real-training/v1' AND artifact_status='verified' ORDER BY id"""


def table_hashes(c):
    out={}
    for t in c.execute(TABLES_SQL).fetchall():
        q=sql.SQL('SELECT count(*) n, md5(coalesce(string_agg(x::text, chr(10) ORDER BY x::text),\'\')) h FROM {}.{} x').format(sql.Identifier(t['nspname']),sql.Identifier(t['relname']))
        r=c.execute(q).fetchone();out[t['nspname']+'.'+t['relname']]={'rows':r['n'],'md5':r['h']}
    return out


def docker(*args,input=None,env=None,check=True,timeout=120):
    e=[]
    for k,v in (env or {}).items():e+=['-e',f'{k}={v}']
    cmd=['docker','exec',*(['-i'] if input is not None else []),*e,*args]
    r=subprocess.run(cmd,input=input,capture_output=True,timeout=timeout)
    if check and r.returncode:raise RuntimeError('docker exec failed: '+r.stderr.decode(errors='replace')[-600:])
    return r


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);ap.add_argument('--source-container',default='fieldwork-postgres')
    ap.add_argument('--target-container',default='fieldwork-pg-restore-proof');ap.add_argument('--target-port',type=int,default=5553)
    ap.add_argument('--keep',action='store_true')
    ap.add_argument('--backup-only',action='store_true',help='write a digest-manifested backup to --out and stop')
    ap.add_argument('--from-backup',help='restore from a backup directory (e.g. on an external volume) instead of the live DB')
    a=ap.parse_args()
    out=Path(a.out).absolute()
    from fieldwork.privacy_lifecycle import _check_c_ancestry,export_deletion_ledger,verify_apply_deletion_ledger
    _check_c_ancestry(out,allow_missing_leaf=True)
    out.mkdir(parents=True,exist_ok=True,mode=0o700)
    _check_c_ancestry(out)
    os.environ['MSYS_NO_PATHCONV']='1'
    from fieldwork.scoped_authority import check_private
    check_private(out)
    privacy_ledger=None if a.from_backup else export_deletion_ledger(out/'privacy-deletions')
    op=json.load(open(ROOT/'.local.json'))['dsn'];api=json.load(open(ROOT/'.local-api.json'))['dsn']
    P=conninfo_to_dict(op);A=conninfo_to_dict(api);rep={'schema':1,'started':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    # Container-local loopback connections are trust-authenticated: no password is passed to docker exec.
    if a.from_backup:
        # Restore path: everything comes from the (external) backup directory; its manifest is verified first.
        bdir=Path(a.from_backup).absolute();t_restore0=time.monotonic()
        man=json.loads((bdir/'backup-manifest.json').read_text(encoding='utf-8'))
        bad=[k for k,v in man['files'].items() if not (bdir/k).is_file() or hashlib.sha256((bdir/k).read_bytes()).hexdigest()!=v]
        if bad:raise SystemExit('BACKUP_MANIFEST_MISMATCH:'+','.join(bad[:5]))
        dump=(bdir/'database.dump').read_bytes();glob=(bdir/'globals.sql').read_bytes()
        src=json.loads((bdir/'source-table-hashes.json').read_text(encoding='utf-8'))
        for sub_dir in ('blobs','bundles','keys','privacy-deletions','media'):
            if (bdir/sub_dir).is_dir():shutil.copytree(bdir/sub_dir,out/sub_dir,dirs_exist_ok=True)
        blobs=out/'blobs'
        rep['backup']=dict(man['backup'],restored_from=str(bdir),manifest_files_verified=len(man['files']))
        rep['rpo_seconds']=round(time.time()-man['created_epoch'],1)
        privacy_ledger=man.get('privacy_ledger')
    else:
      # 1. consistent snapshot: hashes + dump of the same snapshot
      with psycopg.connect(op,row_factory=dict_row) as c:
        c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        snap=c.execute('SELECT pg_export_snapshot() s').fetchone()['s']
        src=table_hashes(c)
        cps=c.execute('SELECT run,epoch,digest,path FROM fw_checkpoints ORDER BY run,epoch').fetchall()
        bundles=c.execute(BUNDLES_SQL).fetchall()
        media_rows=c.execute(MEDIA_SQL).fetchall()
        dump=docker(a.source_container,'pg_dump','-h','127.0.0.1','-U',P['user'],'-d',P['dbname'],'-Fc','--snapshot',snap,timeout=300).stdout
        glob=docker(a.source_container,'pg_dumpall','-h','127.0.0.1','-U',P['user'],'--globals-only').stdout
      created=time.time()
      (out/'database.dump').write_bytes(dump);(out/'globals.sql').write_bytes(glob)
      (out/'source-table-hashes.json').write_text(json.dumps(src),encoding='utf-8')
      rep['backup']={'database_bytes':len(dump),'database_sha256':hashlib.sha256(dump).hexdigest(),'globals_sha256':hashlib.sha256(glob).hexdigest(),'tables':len(src),'source_rows':sum(v['rows'] for v in src.values()),'committed_checkpoints':len(cps)}
      # blobs: copy every committed checkpoint into backup/blobs/<digest>
      blobs=out/'blobs';missing=[]
      for cp in cps:
        s_=Path(cp['path']);t=blobs/cp['digest']
        if t.exists():continue
        if not (s_/'manifest.json').exists():missing.append(cp['digest']);continue
        shutil.copytree(s_,t)
      rep['backup']['unreachable_checkpoint_blobs']=len(missing)
      # reachable real bundles of verified real runs, and the trusted reviewer registry (public keys only)
      bmissing=[]
      for b in bundles:
        srcb=ROOT/'var/runs'/b['id']/(b['d'] or '_')/'bundle'
        if not b['d'] or not (srcb/'manifest.json').is_file():bmissing.append(b['id']);continue
        shutil.copytree(srcb,out/'bundles'/b['id'],dirs_exist_ok=True)
      rep['backup']['verified_real_bundles']=len(bundles)-len(bmissing);rep['backup']['unreachable_bundles']=len(bmissing)
      # reachable dataset media referenced by every version manifest, stored content-addressed by sha256
      mmissing=[];mcount=0
      for m_ in media_rows:
        f_=Path(m_['file']);t_=out/'media'/(m_['sha256']+f_.suffix.lower())
        if t_.exists():continue
        if not f_.is_file():mmissing.append(m_['sha256']);continue
        t_.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(f_,t_);mcount+=1
      rep['backup']['dataset_media_files']=mcount;rep['backup']['unreachable_media']=len(mmissing)
      reg=os.environ.get('FIELDWORK_RIGHTS_REVIEWERS_FILE') or str(ROOT/'var/commons_r5/rights/reviewers.json')
      (out/'keys').mkdir(exist_ok=True);shutil.copy2(reg,out/'keys'/'reviewers.json')
      files={f.relative_to(out).as_posix():hashlib.sha256(f.read_bytes()).hexdigest() for f in out.rglob('*') if f.is_file() and f.name!='backup-manifest.json'}
      (out/'backup-manifest.json').write_text(json.dumps({'created_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(created)),'created_epoch':created,
          'backup':rep['backup'],'privacy_ledger':privacy_ledger,'files':files},indent=1,default=str),encoding='utf-8')
      if a.backup_only:
        print(json.dumps({'backup':rep['backup'],'files':len(files),'out':str(out)},default=str));return
      t_restore0=time.monotonic();rep['rpo_seconds']=round(time.time()-created,1)
    # 2. empty instance
    subprocess.run(['docker','rm','-f',a.target_container],capture_output=True)
    t0=time.monotonic();tpw=uuid.uuid4().hex
    subprocess.run(['docker','run','-d','--name',a.target_container,'-p',f'127.0.0.1:{a.target_port}:5432','-e','POSTGRES_USER=restoreadmin','-e','POSTGRES_PASSWORD='+tpw,'-e','POSTGRES_DB=postgres','--memory','1g','postgres:16-alpine'],check=True,capture_output=True)
    admin=make_conninfo(host='127.0.0.1',port=a.target_port,dbname='postgres',user='restoreadmin',password=tpw,connect_timeout=3)
    for _ in range(60):
        try:
            with psycopg.connect(admin) as c:c.execute('SELECT 1');break
        except psycopg.Error:time.sleep(1)
    with psycopg.connect(admin,autocommit=True) as c:
        rep['target_empty_before_restore']=c.execute("SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')").fetchone()[0]==0
    g=docker(a.target_container,'psql','-U','restoreadmin','-d','postgres','-v','ON_ERROR_STOP=0','-q',input=glob,check=False)
    rep['globals_restore_errors']=g.stderr.decode(errors='replace').count('ERROR')
    with psycopg.connect(admin,autocommit=True) as c:
        c.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(P['dbname']),sql.Identifier(P['user'])))
    r=docker(a.target_container,'pg_restore','-U','restoreadmin','-d',P['dbname'],'--exit-on-error',input=dump,timeout=300)
    T=dict(P,port=a.target_port,host='127.0.0.1');top=make_conninfo(**T);TA=dict(A,port=a.target_port,host='127.0.0.1');tapi=make_conninfo(**TA)
    from fieldwork.store import Store
    privacy_restore=verify_apply_deletion_ledger(Store(dsn=top),out/'privacy-deletions')
    # 3/4. verify equality before any fencing
    with psycopg.connect(top,row_factory=dict_row) as c:
        dst=table_hashes(c)
    rep['tables_equal']=dst==src;rep['table_diff']=[k for k in set(src)|set(dst) if src.get(k)!=dst.get(k)]
    restored_blobs=out/'restored-host/var/checkpoints';restored_blobs.mkdir(parents=True,exist_ok=True)
    from fieldwork.ml import validate_checkpoint
    verified=0
    with psycopg.connect(top,row_factory=dict_row) as c:
        for cp in c.execute('SELECT run,epoch,digest,path FROM fw_checkpoints').fetchall():
            src_blob=blobs/cp['digest']
            if not src_blob.exists():continue
            dest=restored_blobs/cp['digest']
            if not dest.exists():shutil.copytree(src_blob,dest)
            validate_checkpoint(dest,cp['digest']);verified+=1
            c.execute('UPDATE fw_checkpoints SET path=%s WHERE run=%s AND epoch=%s',(str(dest),cp['run'],cp['epoch']))
            c.execute('UPDATE fw_runs SET checkpoint=%s WHERE id=%s AND checkpoint=%s',(str(dest),cp['run'],cp['path']))
        rep['restored_checkpoints_digest_verified']=verified
        from fieldwork.real_bundle import verify_real_bundle
        bver,bfail=0,[]
        for bd in (sorted((out/'bundles').iterdir()) if (out/'bundles').is_dir() else []):
            row=c.execute("SELECT artifact_result->>'bundle_digest' b,config FROM fw_runs WHERE id=%s",(bd.name,)).fetchone()
            try:
                verify_real_bundle(bd,expected_digest=row['b'],expected_lineage={'version_id':row['config']['version_id'],
                    'dataset_digest':row['config']['version_digest'],'model_image_id':row['config']['model_image_id']});bver+=1
            except Exception as exc:bfail.append((bd.name,type(exc).__name__))
        rep['restored_bundles_verified']=bver;rep['restored_bundle_failures']=bfail
        media_ok,media_bad=0,[]
        for m_ in c.execute(MEDIA_SQL).fetchall():
            cand=list((out/'media').glob(m_['sha256']+'.*')) if (out/'media').is_dir() else []
            if len(cand)!=1 or hashlib.sha256(cand[0].read_bytes()).hexdigest()!=m_['sha256']:media_bad.append(m_['sha256'])
            else:media_ok+=1
        rep['restored_media_digest_verified']=media_ok;rep['restored_media_failures']=len(media_bad)
        rep['restored_keys']=sorted(k.name for k in (out/'keys').iterdir()) if (out/'keys').is_dir() else []
        workspaces=[r['workspace'] for r in c.execute('SELECT workspace,count(*) FROM fw_runs GROUP BY 1 ORDER BY 2 DESC LIMIT 2').fetchall()]
    # tenant controls with the restored API principal
    from fieldwork.checkpoint_read import verify
    with psycopg.connect(tapi,row_factory=dict_row) as c:
        flags=c.execute('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=session_user').fetchone()
        verify(c,A['user']);rep['restored_api_checkpoint_helper_verify']='passed';rep['restored_api_flags']=dict(flags)
        rep['no_tenant_rows_visible']=c.execute('SELECT count(*) n FROM fw_runs').fetchone()['n']
    with psycopg.connect(tapi,row_factory=dict_row) as c:
        c.execute("SELECT set_config('fieldwork.workspace',%s,true)",(workspaces[0],))
        seen=c.execute('SELECT DISTINCT workspace FROM fw_runs').fetchall()
        rep['tenant_scoped_only_own_workspace']=[r['workspace'] for r in seen]==[workspaces[0]]
    # 5. restore fencing BEFORE any worker: the product command (round 5), not ad hoc SQL.
    from fieldwork.store import Conflict,CancelGenerationConflict
    s=Store(dsn=top);s.blob_root=restored_blobs
    rep['restore_fence']=s.restore_fence(source='restore_proof '+rep['backup']['database_sha256'])
    # 6. Old worker with a GENUINELY pre-backup live attempt (review F1). 'prod' is a copy of
    # the restored DB standing in for production: a worker claims and heartbeats there, the
    # backup is taken WHILE that attempt is live, the backup is restored into 'restored2' and
    # restore-fenced, a new worker claims, and the old worker (its own attempt id, fence,
    # generation and restore generation) is refused for heartbeat, checkpoint and complete.
    with psycopg.connect(admin,autocommit=True) as c:
        for db in ['proof_prod','proof_restored2']:c.execute(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(sql.Identifier(db)))
        c.execute(sql.SQL('CREATE DATABASE proof_prod TEMPLATE {} OWNER {}').format(sql.Identifier(P['dbname']),sql.Identifier(P['user'])))
    prod=Store(dsn=make_conninfo(**dict(T,dbname='proof_prod')));prod.blob_root=restored_blobs
    src_cp=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'
    meta=json.loads((src_cp/'state.json').read_text());metrics={k:meta[k] for k in ['epoch','train_loss','validation_loss','updates']}
    run=prod.submit('restore-proof-'+uuid.uuid4().hex,'proof',str(uuid.uuid4()),{'epochs':1,'dataset_digest':meta['dataset_digest'],'scope':'synthetic-execution-only'})
    old=prod.claim(run['id'])
    prod.heartbeat(run['id'],old['fence'],old['cancel_generation'],attempt=old['attempt'],restore_generation=old['restore_generation'])
    live_dump=docker(a.target_container,'pg_dump','-U','restoreadmin','-d','proof_prod','-Fc',timeout=300).stdout
    with psycopg.connect(admin,autocommit=True) as c:
        c.execute(sql.SQL('CREATE DATABASE proof_restored2 OWNER {}').format(sql.Identifier(P['user'])))
    docker(a.target_container,'pg_restore','-U','restoreadmin','-d','proof_restored2','--exit-on-error',input=live_dump,timeout=300)
    r2=Store(dsn=make_conninfo(**dict(T,dbname='proof_restored2')));r2.blob_root=restored_blobs
    with r2.connect() as c:rep['old_attempt_live_in_backup']=c.execute('SELECT state,attempt=%s live FROM fw_runs WHERE id=%s',(old['attempt'],run['id'])).fetchone()
    fence2=r2.restore_fence(source='restore_proof live-attempt backup')
    rep['live_attempt_restore_fence']={k:fence2[k] for k in ['fence_floor','runs_fenced','slot_cleared_run']}
    with r2.connect() as c:c.execute("UPDATE fw_runs SET state='queued',revision=revision+1 WHERE id=%s AND state='interrupted' AND checkpoint IS NULL",(run['id'],))  # operator re-queue (no checkpoint to resume)
    new=r2.claim(run['id'])
    scope=dict(attempt=old['attempt'],restore_generation=old['restore_generation'])
    refused={}
    for name,call in [('heartbeat',lambda:r2.heartbeat(run['id'],old['fence'],old['cancel_generation'],**scope)),
                      ('publish',lambda:r2.publish(run['id'],old['fence'],old['cancel_generation'],src_cp,metrics,**scope)),
                      ('complete',lambda:r2.complete(run['id'],old['fence'],old['cancel_generation'],{},**scope))]:
        try:call();refused[name]='ACCEPTED'
        except CancelGenerationConflict as e:refused[name]='WRONG_REFUSAL:'+str(e)
        except Conflict as e:refused[name]=str(e)
    with r2.connect() as c:refused['checkpoints_committed']=c.execute('SELECT count(*) n FROM fw_checkpoints WHERE run=%s',(run['id'],)).fetchone()['n']
    refused['new_attempt_fence_above_floor']=new['fence']>fence2['fence_floor']>old['fence']
    rep['old_worker_refused']=refused
    rep['rto_seconds']=round(time.monotonic()-t0,2)
    rep['rto_seconds_including_backup_copy_in']=round(time.monotonic()-t_restore0,2)
    rep['privacy_deletion_ledger']={'backup':privacy_ledger,'restore':privacy_restore}
    rep['scope']='retained DB + committed checkpoint blobs restored into a separate empty local container; not encrypted off-host DR'
    (out/'restore-proof.json').write_text(json.dumps(rep,indent=2,default=str))
    if not a.keep:subprocess.run(['docker','rm','-f',a.target_container],capture_output=True)
    print(json.dumps(rep,default=str))
    # Exact expected refusals (review F9: not "any exception string").
    ok=(rep['tables_equal'] and rep['backup']['unreachable_checkpoint_blobs']==0 and not rep.get('restored_bundle_failures')
        and rep['backup'].get('unreachable_bundles',0)==0 and rep['backup'].get('unreachable_media',0)==0
        and rep.get('restored_media_failures',0)==0 and not rep['restored_api_flags']['rolsuper']
        and rep['no_tenant_rows_visible']==0 and rep['tenant_scoped_only_own_workspace'] and rep['globals_restore_errors']==0
        and rep['old_attempt_live_in_backup']['state']=='running' and rep['old_attempt_live_in_backup']['live']
        and all(refused[k]=='FENCED_OR_EXPIRED_OR_CANCELLED' for k in ['heartbeat','publish','complete'])
        and refused['checkpoints_committed']==0 and refused['new_attempt_fence_above_floor'])
    rep['ok']=ok
    sys.exit(0 if ok else 1)

if __name__=='__main__':main()
