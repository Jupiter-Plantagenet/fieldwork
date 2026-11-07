"""ML-T-MIGRATE proof on a RESTORED COPY (separate empty container), never the source.

Restores the pre-activation backup (schema before migrations/004 and before the
checkpoint-read helper), then:
  * new binary against old schema: claim and cancel fail closed with
    CANCEL_GENERATION_SCHEMA_REQUIRED (no receipt written), API readiness check
    fails with CHECKPOINT_READ_V1_REQUIRED  -> incompatible combinations refused;
  * forward expand migration via tools.activate_generation (one transaction);
  * every pre-existing column projection, event/outbox row and checkpoint
    reference is unchanged; event ids stay unique (no duplicate outbox effects);
  * repeat activation is a no-op;
  * queued legacy jobs survive and are claimable by the new binary (issued 0);
  * contract rollback rehearsal (drop the two additive columns) inside a
    transaction restores the exact original projection; rolled back, not kept.

Usage: python -m tools.migrate_proof --dump <pre-activation.dump> --globals <globals.sql> --out <dir>
"""
import argparse,json,os,subprocess,sys,time,uuid
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.conninfo import conninfo_to_dict,make_conninfo
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.restore_proof import docker,table_hashes

PROJECTION={'fw_runs':'id,workspace,actor,idem,digest,config,state,fence,epoch,revision,attempt,lease,checkpoint,result,artifact_status,artifact_result',
            'fw_attempts':'id,run,fence','fw_events':'seq,event_id,workspace,run,kind,payload,object_revision','fw_checkpoints':'run,epoch,attempt,digest,path'}


def projections(c):
    out={}
    for t,cols in PROJECTION.items():
        out[t]=c.execute(sql.SQL('SELECT count(*) n, md5(coalesce(string_agg(x::text,chr(10) ORDER BY x::text),\'\')) h FROM (SELECT {} FROM {}) x').format(sql.SQL(cols),sql.Identifier(t))).fetchone()
    return out


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dump',required=True);ap.add_argument('--globals',required=True);ap.add_argument('--out',required=True)
    ap.add_argument('--container',default='fieldwork-pg-migrate-proof');ap.add_argument('--port',type=int,default=5554);a=ap.parse_args()
    os.environ['MSYS_NO_PATHCONV']='1';out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    P=conninfo_to_dict(json.load(open(ROOT/'.local.json'))['dsn']);A=conninfo_to_dict(json.load(open(ROOT/'.local-api.json'))['dsn'])
    rep={'schema':1,'started':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    subprocess.run(['docker','rm','-f',a.container],capture_output=True);pw=uuid.uuid4().hex
    subprocess.run(['docker','run','-d','--name',a.container,'-p',f'127.0.0.1:{a.port}:5432','-e','POSTGRES_USER=migrateadmin','-e','POSTGRES_PASSWORD='+pw,'--memory','1g','postgres:16-alpine'],check=True,capture_output=True)
    admin=make_conninfo(host='127.0.0.1',port=a.port,dbname='postgres',user='migrateadmin',password=pw,connect_timeout=3)
    for _ in range(60):
        try:
            with psycopg.connect(admin) as c:c.execute('SELECT 1');break
        except psycopg.Error:time.sleep(1)
    try:
        docker(a.container,'psql','-U','migrateadmin','-d','postgres','-q',input=Path(a.globals).read_bytes(),check=False)
        with psycopg.connect(admin,autocommit=True) as c:c.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(P['dbname']),sql.Identifier(P['user'])))
        docker(a.container,'pg_restore','-U','migrateadmin','-d',P['dbname'],'--exit-on-error',input=Path(a.dump).read_bytes(),timeout=300)
        op=make_conninfo(**dict(P,host='127.0.0.1',port=a.port));api=make_conninfo(**dict(A,host='127.0.0.1',port=a.port))
        with psycopg.connect(op,row_factory=dict_row) as c:
            before=projections(c);all_before=table_hashes(c)
            rep['pre_schema_has_generation']=c.execute("SELECT count(*) n FROM information_schema.columns WHERE column_name='cancel_generation'").fetchone()['n']
            queued=c.execute("SELECT id,workspace FROM fw_runs WHERE state='queued' ORDER BY id LIMIT 1").fetchone()
            receipts_before=c.execute("SELECT count(*) n FROM fw_events WHERE kind='command_receipt'").fetchone()['n']
            rep['outbox_rows_before']=c.execute("SELECT count(*) n FROM fw_events WHERE kind<>'command_receipt'").fetchone()['n']
        # new binary vs old schema
        from fieldwork.store import Store,GenerationSchemaRequired,RestoreGenerationSchemaRequired
        s=Store(dsn=op);refusals={}
        try:s.claim(queued['id']);refusals['claim']=False
        except (GenerationSchemaRequired,RestoreGenerationSchemaRequired) as e:refusals['claim']=str(e)
        try:s.cancel_command(queued['workspace'],'migrate-proof',str(uuid.uuid4()),queued['id'],1,'migration compatibility probe');refusals['cancel_command']=False
        except GenerationSchemaRequired as e:refusals['cancel_command']=str(e)
        import fieldwork.api as apimod
        apimod.store=Store(dsn=api,request=True)
        try:apimod.checkpoint_dependency();refusals['api_startup']=False
        except RuntimeError as e:refusals['api_startup']=str(e)
        rep['new_binary_on_old_schema_refused']=refusals
        with psycopg.connect(op,row_factory=dict_row) as c:
            rep['no_receipt_written_on_refusal']=c.execute("SELECT count(*) n FROM fw_events WHERE kind='command_receipt'").fetchone()['n']==receipts_before
        # forward expand
        from tools.activate_generation import activate
        rep['activation']=activate(op,api);rep['activation_repeat']=activate(op,api)
        with psycopg.connect(op,row_factory=dict_row) as c:
            after=projections(c)
            rep['preexisting_projections_unchanged']=after==before
            rep['event_ids_unique']=c.execute('SELECT count(*)=count(DISTINCT event_id) u FROM fw_events').fetchone()['u']
            rep['legacy_rows_null_generation']=c.execute('SELECT count(*) n FROM fw_runs WHERE cancel_generation IS NULL').fetchone()['n']
            rep['checkpoint_refs_resolve']=c.execute('SELECT count(*) n FROM fw_checkpoints cp LEFT JOIN fw_attempts a ON a.id=cp.attempt WHERE a.id IS NULL').fetchone()['n']==0
            unchanged={k:v for k,v in table_hashes(c).items() if all_before.get(k)==v}
            rep['tables_byte_identical_after_expand']=sorted(unchanged)
        try:apimod.checkpoint_dependency();rep['api_startup_after_activation']='passed'
        except RuntimeError as e:rep['api_startup_after_activation']=str(e)
        # Structural contract-rollback check ONLY (review F9): dropping the two added columns in
        # one transaction restores the original hashes by construction. It is not an
        # old-binary run and proves nothing about writes made by the new binary.
        with psycopg.connect(op,row_factory=dict_row) as c:
            c.execute('ALTER TABLE fw_runs DROP COLUMN cancel_generation');c.execute('ALTER TABLE fw_attempts DROP COLUMN cancel_generation')
            rep['structural_column_drop_restores_original_hashes']=table_hashes(c)==all_before
            c.rollback()
        # Round 5: the new binary also requires migrations/005 (restore generation).
        from tools.activate_round5 import activate as activate5
        rep['activation_005']={k:v for k,v in activate5(op,api).items() if k in ('migration_005','after')}
        with psycopg.connect(op,row_factory=dict_row) as c:
            rep['outbox_rows_since_expand']=c.execute("SELECT count(*) n FROM fw_events WHERE kind<>'command_receipt'").fetchone()['n']-rep['outbox_rows_before']
        # queued legacy job survives the migration and is claimable by the new binary
        rec=s.claim(queued['id']);rep['legacy_queued_claimed_generation']=rec['cancel_generation']
        s.release_slot(queued['id'])
    finally:
        subprocess.run(['docker','rm','-f',a.container],capture_output=True)
    (out/'migrate-proof.json').write_text(json.dumps(rep,indent=2,default=str));print(json.dumps(rep,default=str))
    ok=(all(v not in (False,None) for v in rep['new_binary_on_old_schema_refused'].values()) and rep['preexisting_projections_unchanged']
        and rep['event_ids_unique'] and rep['api_startup_after_activation']=='passed' and rep['no_receipt_written_on_refusal']
        and rep['activation_repeat'].get('migration_004')=='already_applied' and rep['checkpoint_refs_resolve']
        and rep['legacy_queued_claimed_generation']==0 and rep['outbox_rows_since_expand']==0)
    sys.exit(0 if ok else 1)

if __name__=='__main__':main()
