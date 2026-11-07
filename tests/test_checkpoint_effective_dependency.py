"""Administrator-authored drift only; run through second correction packet."""
import json,os
from contextlib import contextmanager
import pytest,psycopg
from psycopg import sql
from psycopg.types.json import Jsonb
from fastapi.testclient import TestClient
from fieldwork.store import Store,TENANT,ROOT
from fieldwork.checkpoint_read import SIGNATURE,verify,install
import fieldwork.api as api


@pytest.fixture
def runtime():
    assert os.environ.get('FW_SECOND_PACKET')=='s29d2'
    admin=Store();request=Store(request=True);role=os.environ['FW_SECOND_ROLE']
    with request.connect() as conn:
        row=conn.execute('SELECT current_database() db,current_user AS role,session_user AS login').fetchone()
        assert row=={'db':os.environ['FW_SECOND_DATABASE'],'role':role,'login':role}
    assert api.store.dsn==request.dsn
    return admin,request,role


@contextmanager
def tenant(request,workspace):
    token=TENANT.set(workspace)
    try:
        with request.connect() as conn:yield conn
    finally:TENANT.reset(token)


def observe(admin,request,role):
    result={}
    for name,store in [('operator',admin),('request',request)]:
        try:
            with store.connect() as conn:verify(conn,role)
            result[name]=True
        except ValueError as e:result[name]=str(e)
    try:
        api.checkpoint_dependency();result['dependency']=True
    except RuntimeError as e:result['dependency']=str(e)
    result['readiness']=getattr(api.ready(),'status_code',200)
    try:
        with TestClient(api.app):pass
        result['startup']=True
    except RuntimeError as e:result['startup']=str(e)
    return result


def save(name,value):
    from fieldwork.evidence_out import write_evidence
    write_evidence(ROOT,name,json.dumps(value,indent=2,default=str))  # new timestamped file; never overwrite


@pytest.mark.parametrize('label,revoke,grant',[
    ('checkpoint_select','REVOKE SELECT ON public.fw_checkpoints FROM {}','GRANT SELECT ON public.fw_checkpoints TO {}'),
    ('checkpoint_lock','REVOKE UPDATE(digest) ON public.fw_checkpoints FROM {}','GRANT UPDATE(digest) ON public.fw_checkpoints TO {}'),
    ('run_select','REVOKE SELECT ON public.fw_runs FROM {}','GRANT SELECT ON public.fw_runs TO {}'),
])
def test_owner_missing_effective_dependency_rejects(runtime,label,revoke,grant):
    admin,request,role=runtime;owner=sql.Identifier(role+'_cp_lock')
    with admin.connect() as conn:conn.execute(sql.SQL(revoke).format(owner))
    try:
        # Actual helper fails despite caller EXECUTE. Capture before asserting admission.
        with tenant(request,'') as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
                conn.execute('SELECT * FROM fw_checkpoint_read_v1.locked_digest(%s,1,%s)',('absent',''))
        observed=observe(admin,request,role);observed['actual_helper_sqlstate']=exc.value.sqlstate
        save('owner-'+label+'.json',observed)
        assert observed['operator']=='CHECKPOINT_OWNER_ACCESS_REQUIRED',observed
        assert observed['request']=='CHECKPOINT_OWNER_ACCESS_REQUIRED',observed
        assert observed['readiness']==503 and observed['startup'] is not True,observed
    finally:
        with admin.connect() as conn:conn.execute(sql.SQL(grant).format(owner))
    assert observe(admin,request,role)['readiness']==200


@pytest.fixture
def authored_rows(runtime):
    admin,request,role=runtime
    # Synthetic catalog fixtures only, never claimed as model/result acceptance.
    for rid,w in [('r-a','tenant-a'),('r-b','tenant-b')]:
        with admin.connect() as conn:
            conn.execute("INSERT INTO public.fw_runs(id,workspace,actor,idem,digest,config,state,result,artifact_status,artifact_result) VALUES(%s,%s,'fixture',%s,'fixture','{}','succeeded',%s,'verified','{}')",(rid,w,rid,Jsonb({'best':{'epoch':1}})))
            conn.execute('INSERT INTO public.fw_attempts(id,run,fence) VALUES(%s,%s,1)',('a-'+rid,rid))
            conn.execute("INSERT INTO public.fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES(%s,1,%s,'fixture-digest','fixture-only','{}')",(rid,'a-'+rid))
    try:yield runtime
    finally:
        with admin.connect() as conn:
            conn.execute("DELETE FROM public.fw_checkpoints WHERE run IN ('r-a','r-b')")
            conn.execute("DELETE FROM public.fw_attempts WHERE run IN ('r-a','r-b')")
            conn.execute("DELETE FROM public.fw_runs WHERE id IN ('r-a','r-b')")


@pytest.mark.parametrize('path',[
    'pg_catalog,pg_temp','"pg_catalog", "pg_temp"','pg_catalog,"pg_temp"',
    ' PG_CATALOG , pg_TEMP ','"pg_catalog", PG_TEMP','\tpg_catalog\t,\n"pg_temp"\r',
])
def test_supported_path_postgres_semantics_and_helper(authored_rows,path):
    admin,request,role=authored_rows
    with admin.connect() as conn:
        conn.execute('CREATE TEMP TABLE path_probe(x integer)')
        conn.execute("SELECT set_config('search_path',%s,true)",(path,))
        schemas=conn.execute('SELECT current_schemas(true) schemas').fetchone()['schemas']
        assert schemas[0]=='pg_catalog' and schemas[1].startswith('pg_temp_') and len(schemas)==2,schemas
        conn.execute('ALTER FUNCTION '+SIGNATURE+' SET search_path FROM CURRENT')
        stored=conn.execute('SELECT proconfig FROM pg_proc WHERE oid=to_regprocedure(%s)',(SIGNATURE,)).fetchone()['proconfig']
    try:
        with tenant(request,'tenant-a') as conn:
            got=conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')").fetchone()
            assert got=={'digest':'fixture-digest'}
        observed=observe(admin,request,role)
        save('path-'+str(abs(hash(path)))+'.json',{'path':path,'stored':stored,'schemas':schemas,'helper':got,'admission':observed})
        assert observed=={'operator':True,'request':True,'dependency':True,'readiness':200,'startup':True},observed
    finally:
        with admin.connect() as conn:conn.execute('ALTER FUNCTION '+SIGNATURE+' SET search_path=pg_catalog,pg_temp')


@pytest.mark.parametrize('path',[
    '"pg_catalog,pg_temp"','pg_temp,pg_catalog','pg_catalog,public,pg_temp',
    '"$user",pg_temp','pg_catalog,"PG_TEMP"','"PG_CATALOG",pg_temp',
    'pg_catalog,pg_temp,pg_temp','pg_catalog',
])
def test_unsupported_path_denied(runtime,path):
    admin,request,role=runtime
    with admin.connect() as conn:
        conn.execute("SELECT set_config('search_path',%s,true)",(path,))
        conn.execute('ALTER FUNCTION '+SIGNATURE+' SET search_path FROM CURRENT')
    try:
        observed=observe(admin,request,role)
        assert observed['operator']=='CHECKPOINT_FUNCTION_MISMATCH' and observed['request']=='CHECKPOINT_FUNCTION_MISMATCH',observed
        assert observed['readiness']==503 and observed['startup'] is not True,observed
    finally:
        with admin.connect() as conn:conn.execute('ALTER FUNCTION '+SIGNATURE+' SET search_path=pg_catalog,pg_temp')


@pytest.mark.parametrize('flag,inverse',[
    ('BYPASSRLS','NOBYPASSRLS'),('SUPERUSER','NOSUPERUSER'),
    ('CREATEDB','NOCREATEDB'),('CREATEROLE','NOCREATEROLE'),('REPLICATION','NOREPLICATION'),
])
def test_unsafe_declared_runtime_role_rejected(runtime,flag,inverse):
    admin,request,role=runtime
    with admin.connect() as conn:conn.execute(sql.SQL('ALTER ROLE {} '+flag).format(sql.Identifier(role)))
    try:
        observed=observe(admin,request,role);save('runtime-'+flag+'.json',observed)
        assert observed['operator']=='UNSAFE_CHECKPOINT_API_ROLE' and observed['request']=='UNSAFE_CHECKPOINT_API_ROLE',observed
        assert observed['readiness']==503 and observed['startup'] is not True,observed
    finally:
        with admin.connect() as conn:conn.execute(sql.SQL('ALTER ROLE {} '+inverse).format(sql.Identifier(role)))
    assert observe(admin,request,role)['readiness']==200


def test_actual_rls_baseline_and_bypass_drift_denial(authored_rows):
    admin,request,role=authored_rows
    with tenant(request,'tenant-a') as conn:
        baseline=conn.execute("SELECT id FROM public.fw_runs WHERE id IN ('r-a','r-b') ORDER BY id").fetchall()
        cross=conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-b',1,'tenant-a')").fetchone()
        assert baseline==[{'id':'r-a'}] and cross is None
    with tenant(request,'') as conn:assert conn.execute('SELECT id FROM public.fw_runs').fetchall()==[]
    with admin.connect() as conn:conn.execute(sql.SQL('ALTER ROLE {} BYPASSRLS').format(sql.Identifier(role)))
    try:
        with tenant(request,'tenant-a') as conn:raw=conn.execute("SELECT id FROM public.fw_runs WHERE id IN ('r-a','r-b') ORDER BY id").fetchall()
        # A DBA can make raw SQL unsafe. The application must refuse admission;
        # no claim that a verifier repairs a privileged administrator's alteration.
        assert raw==[{'id':'r-a'},{'id':'r-b'}]
        observed=observe(admin,request,role)
        save('real-row-bypass-drift.json',{'baseline':baseline,'cross_helper':cross,'unsafe_raw_sql':raw,'admission':observed})
        assert observed['operator']=='UNSAFE_CHECKPOINT_API_ROLE' and observed['request']=='UNSAFE_CHECKPOINT_API_ROLE',observed
        assert observed['readiness']==503 and observed['startup'] is not True,observed
    finally:
        with admin.connect() as conn:conn.execute(sql.SQL('ALTER ROLE {} NOBYPASSRLS').format(sql.Identifier(role)))


def test_minimal_effective_column_privileges_are_sufficient(authored_rows):
    admin,request,role=authored_rows;owner=sql.Identifier(role+'_cp_lock')
    with admin.connect() as conn:
        conn.execute(sql.SQL('REVOKE SELECT ON public.fw_runs,public.fw_checkpoints FROM {}').format(owner))
        conn.execute(sql.SQL('GRANT SELECT(id,workspace,state,artifact_status,result) ON public.fw_runs TO {}').format(owner))
        conn.execute(sql.SQL('GRANT SELECT(run,epoch,digest) ON public.fw_checkpoints TO {}').format(owner))
    try:
        observed=observe(admin,request,role)
        with tenant(request,'tenant-a') as conn:got=conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')").fetchone()
        assert got=={'digest':'fixture-digest'} and observed['readiness']==200,observed
        # SHARE requires UPDATE on a column, not specifically the projected one.
        with admin.connect() as conn:
            conn.execute(sql.SQL('REVOKE UPDATE(digest) ON public.fw_checkpoints FROM {}').format(owner))
            conn.execute(sql.SQL('GRANT UPDATE(path) ON public.fw_checkpoints TO {}').format(owner))
        assert observe(admin,request,role)['readiness']==200
        with tenant(request,'tenant-a') as conn:assert conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')").fetchone()==got
    finally:
        with admin.connect() as conn:
            conn.execute(sql.SQL('REVOKE SELECT(id,workspace,state,artifact_status,result) ON public.fw_runs FROM {}').format(owner))
            conn.execute(sql.SQL('REVOKE SELECT(run,epoch,digest),UPDATE(path) ON public.fw_checkpoints FROM {}').format(owner))
            conn.execute(sql.SQL('GRANT SELECT ON public.fw_runs,public.fw_checkpoints TO {}').format(owner))
            conn.execute(sql.SQL('GRANT UPDATE(digest) ON public.fw_checkpoints TO {}').format(owner))


def test_owner_public_schema_usage_required(runtime):
    admin,request,role=runtime;owner=sql.Identifier(role+'_cp_lock')
    with admin.connect() as conn:conn.execute(sql.SQL('REVOKE USAGE ON SCHEMA public FROM PUBLIC,{}').format(owner))
    try:
        with tenant(request,'') as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('absent',1,'')")
        observed=observe(admin,request,role)
        assert observed['operator']=='CHECKPOINT_OWNER_ACCESS_REQUIRED' and observed['request']=='CHECKPOINT_OWNER_ACCESS_REQUIRED',observed
        assert observed['readiness']==503 and observed['startup'] is not True
    finally:
        with admin.connect() as conn:conn.execute(sql.SQL('GRANT USAGE ON SCHEMA public TO PUBLIC,{}').format(owner))


@pytest.mark.parametrize('mutation,inverse',[
    ('ALTER FUNCTION '+SIGNATURE+' SECURITY INVOKER','ALTER FUNCTION '+SIGNATURE+' SECURITY DEFINER'),
    ('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO PUBLIC','REVOKE EXECUTE ON FUNCTION '+SIGNATURE+' FROM PUBLIC'),
    ('ALTER FUNCTION '+SIGNATURE+' SET statement_timeout=1000','ALTER FUNCTION '+SIGNATURE+' RESET statement_timeout'),
    ('ALTER TABLE public.fw_checkpoints NO FORCE ROW LEVEL SECURITY','ALTER TABLE public.fw_checkpoints FORCE ROW LEVEL SECURITY'),
    ('ALTER TABLE public.fw_runs DISABLE ROW LEVEL SECURITY','ALTER TABLE public.fw_runs ENABLE ROW LEVEL SECURITY'),
    ('ALTER ROLE {owner} LOGIN','ALTER ROLE {owner} NOLOGIN'),
    ('ALTER ROLE {owner} BYPASSRLS','ALTER ROLE {owner} NOBYPASSRLS'),
    ('GRANT {owner} TO {role}','REVOKE {owner} FROM {role}'),
    ('REVOKE EXECUTE ON FUNCTION '+SIGNATURE+' FROM {role}','GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO {role}'),
    ('GRANT UPDATE(digest) ON public.fw_checkpoints TO {role}','REVOKE UPDATE(digest) ON public.fw_checkpoints FROM {role}'),
])
def test_existing_security_invariants(runtime,mutation,inverse):
    admin,request,role=runtime
    def statement(text):return sql.SQL(text).format(role=sql.Identifier(role),owner=sql.Identifier(role+'_cp_lock'))
    with admin.connect() as conn:conn.execute(statement(mutation))
    try:
        observed=observe(admin,request,role)
        assert observed['operator'] is not True and observed['request'] is not True,observed
        assert observed['readiness']==503 and observed['startup'] is not True,observed
    finally:
        with admin.connect() as conn:conn.execute(statement(inverse))
    assert observe(admin,request,role)['readiness']==200


def test_startup_readiness_readonly_and_projection_unchanged(runtime):
    admin,request,role=runtime
    def projection():
        with admin.connect() as conn:
            tables=[r['tablename'] for r in conn.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")]
            return {t:conn.execute(sql.SQL('SELECT to_jsonb(t) row FROM public.{} t ORDER BY to_jsonb(t)::text').format(sql.Identifier(t))).fetchall() for t in tables}
    before=projection()
    with admin.connect() as conn:conn.execute(sql.SQL('ALTER ROLE {} SET default_transaction_read_only=on').format(sql.Identifier(role)))
    try:
        with TestClient(api.app) as client:
            assert client.get('/health/ready').status_code==200
            assert client.get('/health/live').status_code==200
        with request.connect() as conn:assert conn.execute('SHOW transaction_read_only').fetchone()['transaction_read_only']=='on'
        assert projection()==before
    finally:
        with admin.connect() as conn:conn.execute(sql.SQL('ALTER ROLE {} RESET default_transaction_read_only').format(sql.Identifier(role)))


def test_actual_parent_child_share_lock_chain(authored_rows):
    import time
    from concurrent.futures import ThreadPoolExecutor
    from fieldwork.evidence_snapshot import accepted_evidence
    admin,request,role=authored_rows
    writer=admin.connect();contender=admin.connect()
    token=TENANT.set('tenant-a')
    try:reader=request.connect()
    finally:TENANT.reset(token)
    def edge(waiter,blocker):
        deadline=time.monotonic()+4
        while time.monotonic()<deadline:
            with admin.connect() as conn:row=conn.execute('SELECT pid,pg_blocking_pids(pid) blockers,wait_event_type,query FROM pg_stat_activity WHERE pid=%s',(waiter,)).fetchone()
            if row and blocker in row['blockers'] and row['wait_event_type']=='Lock':return row
            time.sleep(.02)
        raise AssertionError('physical lock edge not observed')
    class OneConnection:
        def connect(self):return reader
    def read():
        with pytest.raises(KeyError,match='bundle_digest'):accepted_evidence(OneConnection(),ROOT/'var/runs','r-a','tenant-a')
    graphs=[]
    try:
        wp=writer.execute('SELECT pg_backend_pid() pid').fetchone()['pid']
        cp=contender.execute('SELECT pg_backend_pid() pid').fetchone()['pid']
        rp=reader.execute('SELECT pg_backend_pid() pid').fetchone()['pid']
        writer.execute("UPDATE public.fw_checkpoints SET path='pending' WHERE run='r-a'")
        with ThreadPoolExecutor(2) as pool:
            pending=pool.submit(read)
            try:
                graphs.append(edge(rp,wp))
                update=pool.submit(contender.execute,"UPDATE public.fw_runs SET revision=revision+1 WHERE id='r-a'")
                try:graphs.append(edge(cp,rp))
                finally:writer.rollback()
                pending.result(5);update.result(5);contender.rollback()
            finally:writer.rollback()
        save('actual-parent-child-locks.json',{'graphs':graphs,'artifact_rejection':'authored malformed scaffold; not model acceptance'})
        assert len(graphs)==2
        # Child SHARE also blocks direct digest rewrite and delete until rollback.
        for mutation in ["UPDATE public.fw_checkpoints SET digest='evil' WHERE run='r-a'","DELETE FROM public.fw_checkpoints WHERE run='r-a'"]:
            with tenant(request,'tenant-a') as conn:
                pid=conn.execute('SELECT pg_backend_pid() pid').fetchone()['pid']
                assert conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')").fetchone()
                with ThreadPoolExecutor(1) as pool:
                    pending=pool.submit(writer.execute,mutation)
                    try:graphs.append(edge(wp,pid))
                    finally:conn.rollback()
                    pending.result(5);writer.rollback()
        save('actual-parent-child-locks.json',{'graphs':graphs,'artifact_rejection':'authored malformed scaffold; not model acceptance'})
    finally:
        for conn in [writer,reader,contender]:
            if not conn.closed:conn.rollback();conn.close()


@pytest.mark.parametrize('config',[
    None,[],['search_path="pg_catalog,pg_temp"'],
    ['search_path="pg_catalog", "pg_temp"','statement_timeout=1000'],
    ['search_path=pg_catalog,,pg_temp'],['search_path=pg_catalog,pg_temp;public'],
    ['search_path=pg_catalog,"pg_""temp"'],['search_path=pg_catalog,pg_temp,'],
    ['search_path=pg_catalog,pg_temp\x00'],['search_path=pg_catalog,pg_temp --x'],
])
def test_fixed_path_malformed_config_rejects(config):
    from fieldwork.checkpoint_read import _fixed_path
    assert not _fixed_path(config)


def test_missing_or_changed_body_denied(runtime):
    admin,request,role=runtime
    with admin.connect() as conn:definition=conn.execute('SELECT pg_get_functiondef(to_regprocedure(%s)) definition',(SIGNATURE,)).fetchone()['definition']
    try:
        for statement in ['DROP FUNCTION '+SIGNATURE,
            "CREATE OR REPLACE FUNCTION fw_checkpoint_read_v1.locked_digest(p_run text,p_epoch integer,p_workspace text) RETURNS TABLE(digest text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS 'BEGIN RETURN; END'"]:
            with admin.connect() as conn:conn.execute(statement)
            if statement.startswith('CREATE'):
                with admin.connect() as conn:
                    conn.execute(sql.SQL('ALTER FUNCTION '+SIGNATURE+' OWNER TO {}').format(sql.Identifier(role+'_cp_lock')))
                    conn.execute('REVOKE ALL ON FUNCTION '+SIGNATURE+' FROM PUBLIC')
                    conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO {}').format(sql.Identifier(role)))
            try:
                observed=observe(admin,request,role)
                assert observed['operator'] is not True and observed['request'] is not True
                assert observed['readiness']==503 and observed['startup'] is not True,observed
            finally:
                with admin.connect() as conn:
                    conn.execute(definition)
                    conn.execute(sql.SQL('ALTER FUNCTION '+SIGNATURE+' OWNER TO {}').format(sql.Identifier(role+'_cp_lock')))
                    conn.execute('REVOKE ALL ON FUNCTION '+SIGNATURE+' FROM PUBLIC')
                    conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO {}').format(sql.Identifier(role)))
    finally:assert observe(admin,request,role)['readiness']==200


def test_api_schema_usage_drift_denied(runtime):
    admin,request,role=runtime
    with admin.connect() as conn:conn.execute(sql.SQL('REVOKE USAGE ON SCHEMA fw_checkpoint_read_v1 FROM {}').format(sql.Identifier(role)))
    try:
        with pytest.raises(RuntimeError):api.checkpoint_dependency()
        assert getattr(api.ready(),'status_code',200)==503
        with pytest.raises(RuntimeError):
            with TestClient(api.app):pass
        with request.connect() as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('absent',1,'')")
        with admin.connect() as conn:
            with pytest.raises(ValueError,match='CHECKPOINT_SCHEMA_USAGE_REQUIRED'):verify(conn,role)
    finally:
        with admin.connect() as conn:conn.execute(sql.SQL('GRANT USAGE ON SCHEMA fw_checkpoint_read_v1 TO {}').format(sql.Identifier(role)))


def test_valid_install_readiness_helper_and_denials(runtime):
    admin,request,role=runtime
    with admin.connect() as conn:install(conn,role);verify(conn,role)
    # Real execution remains distinct from readiness's read-only catalog check.
    got=observe(admin,request,role)
    assert got=={'operator':True,'request':True,'dependency':True,'readiness':200,'startup':True},got
    with tenant(request,'') as conn:
        assert conn.execute('SELECT * FROM fw_checkpoint_read_v1.locked_digest(%s,1,%s)',('absent','')).fetchone() is None
    for statement in ["UPDATE public.fw_checkpoints SET digest='evil'","UPDATE public.fw_checkpoints SET path='evil'",sql.SQL('SET ROLE {}').format(sql.Identifier(role+'_cp_lock'))]:
        with request.connect() as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:conn.execute(statement)
            assert exc.value.sqlstate=='42501'
