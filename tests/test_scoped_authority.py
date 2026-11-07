"""Scoped capability tests: disposable databases / globally unique owned roles only."""
import copy
import os
import uuid
import pytest
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row


@pytest.fixture
def machine(isolated_store,request):
    from fieldwork.scoped_authority import provision, MachineBackend
    from fieldwork.db_security import install
    s=isolated_store; login='fwm_'+uuid.uuid4().hex; api='fwa_'+uuid.uuid4().hex
    a=specification();p=conninfo_to_dict(s.dsn)
    a['connection'].update(host=p['host'],port=int(p['port']),dbname=p['dbname'],user=login,password=uuid.uuid4().hex)
    if getattr(request,'param',None)=='quoted':
        a['connection']['user']=login=login+'\"x'
        a['workspaces']=["scope'); SELECT 'not SQL"]
    install(s,api,uuid.uuid4().hex)
    try:
        provision(s.connect,a)
        if os.environ.get('FWM_EVIDENCE'):
            import json
            from pathlib import Path
            with s.connect() as c:
                snapshot={t:c.execute(sql.SQL('SELECT * FROM public.{} ORDER BY 1').format(sql.Identifier(t))).fetchall()
                          for t in ['fw_slot','fw_attempts','fw_checkpoints']}
            with (Path(os.environ['FWM_EVIDENCE'])/(login.replace(chr(34),'_')+'-isolated-before.json')).open('x') as f:
                json.dump({'isolated_database':a['connection']['dbname'],'label':'isolated-only; no dataset-rights certification','protected':snapshot},f,default=str)
        yield s,a,MachineBackend(a),api
    finally:
        if os.environ.get('FWM_EVIDENCE'):
            import json
            from pathlib import Path
            with s.connect() as c:
                snapshot={t:c.execute(sql.SQL('SELECT * FROM public.{} ORDER BY 1').format(sql.Identifier(t))).fetchall()
                          for t in ['fw_slot','fw_attempts','fw_checkpoints']}
            with (Path(os.environ['FWM_EVIDENCE'])/(login.replace(chr(34),'_')+'-isolated-after.json')).open('x') as f:
                json.dump({'isolated_database':a['connection']['dbname'],'label':'isolated-only; no dataset-rights certification','protected':snapshot},f,default=str)
        with s.connect() as c:
            c.execute('DROP SCHEMA IF EXISTS fw_lease_cap_v1 CASCADE')
            for role in [login,login+'_owner',api]:
                c.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
                c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))


def seed(s, workspace='scope-a', cancel=False):
    r=s.submit(workspace,'fixture',uuid.uuid4().hex,{'epochs':1});r=s.claim(r['id'])
    if cancel:s.cancel(workspace,r['id'])
    with s.connect() as c:
        c.execute("UPDATE public.fw_runs SET lease=clock_timestamp()-interval '1 second' WHERE id=%s",(r['id'],))
    return r['id']


@pytest.mark.parametrize('cancel',[False,True])
def test_real_scoped_expiry_and_idempotent_provision(machine,cancel):
    from fieldwork.scoped_authority import provision
    from fieldwork.lease_recovery import scan_once
    s,a,b,api=machine;rid=seed(s,cancel=cancel)
    with s.connect() as c:
        before={t:c.execute(sql.SQL('SELECT * FROM public.{} ORDER BY 1').format(sql.Identifier(t))).fetchall() for t in ['fw_slot','fw_attempts','fw_checkpoints']}
        policies=c.execute("SELECT policyname,qual,with_check FROM pg_policies WHERE policyname='fw_tenant' ORDER BY tablename").fetchall()
        password=c.execute('SELECT rolpassword FROM pg_authid WHERE rolname=%s',(a['connection']['user'],)).fetchone()
    provision(s.connect,a)
    b.verify()
    result=scan_once(b);assert len(result['transitions'])==1 and not result['errors']
    assert s.get(rid)['state']==('cancelled' if cancel else 'interrupted')
    assert scan_once(b)['transitions']==[]
    with s.connect() as c:
        assert c.execute("SELECT count(*) n FROM public.fw_events WHERE run=%s AND kind='expired'",(rid,)).fetchone()['n']==1
        assert password==c.execute('SELECT rolpassword FROM pg_authid WHERE rolname=%s',(a['connection']['user'],)).fetchone()
        assert policies==c.execute("SELECT policyname,qual,with_check FROM pg_policies WHERE policyname='fw_tenant' ORDER BY tablename").fetchall()
        assert before=={t:c.execute(sql.SQL('SELECT * FROM public.{} ORDER BY 1').format(sql.Identifier(t))).fetchall() for t in before}


def specification():
    return {'purpose':'fieldwork-training-lease-controller','authority_mode':'scoped-machine-v1',
            'connection':{'host':'127.0.0.1','port':5542,'dbname':'fixture','user':'fw_machine','password':'fixture-only','sslmode':'disable'},
            'capability_schema':'fw_lease_cap_v1','capability_version':1,'workspaces':['scope-a']}


def test_strict_machine_configuration():
    from fieldwork.scoped_authority import validate
    assert validate(specification()) == specification()
    for key in specification()['connection']:
        bad=specification();del bad['connection'][key]
        with pytest.raises(ValueError):validate(bad)
    global_scope=specification();global_scope['workspaces']=['*'];assert validate(global_scope)==global_scope
    for field,value in [('capability_schema','public'),('capability_version',2),('dsn','service=anything'),('workspaces',['*','scope-a'])]:
        bad=specification();bad[field]=value
        with pytest.raises(ValueError):validate(bad)
    for value in ['service=bad','postgresql://bad/db','dbname=other',' ']:
        bad=specification();bad['connection']['dbname']=value
        with pytest.raises(ValueError):validate(bad)
    for key in ['service','passfile','options','hostaddr']:
        bad=specification();bad['connection'][key]='bad'
        with pytest.raises(ValueError):validate(bad)
    os.environ['PGPASSWORD']='not-used'
    try:
        with pytest.raises(ValueError):validate(specification())
    finally:del os.environ['PGPASSWORD']

@pytest.mark.parametrize('machine',['quoted'],indirect=True)
def test_quoted_identifiers_and_bound_workspace_are_data(machine):
    s,a,b,api=machine
    rid=seed(s,a['workspaces'][0]);b.verify()
    assert b.expire(b.candidates('',16)[0])['run']==rid
    assert s.get(rid)['state']=='interrupted'


def test_generate_new_private_fixture_authority_and_operator_cli(isolated_store,tmp_path):
    import json,subprocess,sys
    from fieldwork.scoped_authority import provision_file
    from fieldwork.db_security import install
    s=isolated_store;api='fwa_'+uuid.uuid4().hex;login='fwm_'+uuid.uuid4().hex
    a=specification();p=conninfo_to_dict(s.dsn)
    a['connection'].update(host=p['host'],port=int(p['port']),dbname=p['dbname'],user=login)
    plan=copy.deepcopy(a);del plan['connection']['password']
    output=tmp_path/'private'/'authority.json';install(s,api,uuid.uuid4().hex)
    try:
        provision_file(s.connect,plan,output)
        first=output.read_bytes()
        op={k:p[k] for k in ['host','dbname','user','password']};op.update(port=int(p['port']),sslmode='disable')
        operator=output.parent/'operator.json';operator.write_text(json.dumps(op))
        planfile=tmp_path/'plan.json';planfile.write_text(json.dumps(plan))
        result=subprocess.run([sys.executable,'-m','fieldwork.scoped_authority','--operator-file',str(operator),'--plan-file',str(planfile),'--authority-file',str(output),'--confirm-provision'],capture_output=True,text=True,timeout=20)
        assert result.returncode==0,result.stdout
        assert output.read_bytes()==first and '"activated": false' in result.stdout
        assert op['password'] not in result.stdout+result.stderr
    finally:
        with s.connect() as c:
            c.execute('DROP SCHEMA IF EXISTS fw_lease_cap_v1 CASCADE')
            for role in [login,login+'_owner',api]:
                c.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
                c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))


def test_new_cli_and_private_operator_provision_are_opt_in(machine,tmp_path):
    import json,subprocess,sys
    from fieldwork.scoped_authority import provision_file
    s,a,b,api=machine
    plan=copy.deepcopy(a);del plan['connection']['password']
    output=tmp_path/'private'/'authority.json'
    # Existing authority is written securely by utility, repeat must not rotate it.
    provision_file(s.connect,plan,output,existing_authority=a)
    first=output.read_bytes()
    provision_file(s.connect,plan,output)
    assert output.read_bytes()==first
    rid=seed(s)
    result=subprocess.run([sys.executable,'-m','fieldwork.lease_recovery','--authority-file',str(output),'--once'],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stdout
    assert a['connection']['password'] not in result.stdout+result.stderr
    assert s.get(rid)['state']=='interrupted'
    for field,value in [('dbname','postgres'),('user',api)]:
        bad=copy.deepcopy(a);bad['connection'][field]=value
        p=tmp_path/'private'/(field+'.json');p.write_text(json.dumps(bad))
        result=subprocess.run([sys.executable,'-m','fieldwork.lease_recovery','--authority-file',str(p),'--once'],capture_output=True,text=True,timeout=15)
        assert result.returncode==2


def test_bad_function_mode_and_changed_scope_provision_fail_without_repair(machine):
    from fieldwork.scoped_authority import provision
    s,a,b,api=machine
    bad=copy.deepcopy(a);bad['workspaces']=['foreign']
    with pytest.raises(ValueError,match='EXISTING_CAPABILITY_MISMATCH'):provision(s.connect,bad)
    with s.connect() as c:
        c.execute('ALTER FUNCTION fw_lease_cap_v1.expire(text,integer,integer,text) SET search_path=public')
    with pytest.raises(ValueError):b.verify()



def test_machine_cannot_broaden_or_mutate_business(machine):
    s,a,b,api=machine
    rid=seed(s,'foreign-scope');foreign=s.get(rid)
    with b.connect() as c:
        c.execute("SELECT set_config('fieldwork.workspace','foreign-scope',false)")
        assert c.execute('SELECT id FROM public.fw_runs').fetchall()==[]
        assert c.execute('SELECT fw_lease_cap_v1.expire(%s,%s,%s,%s) v',(rid,foreign['fence'],foreign['revision'],foreign['state'])).fetchone()['v'] is None
    attempts=[
        'UPDATE public.fw_runs SET fence=999',"UPDATE public.fw_runs SET state='succeeded'",
        'DELETE FROM public.fw_runs',"INSERT INTO public.fw_events(workspace) VALUES('scope-a')",
        'SELECT * FROM public.fw_accounts','SELECT * FROM public.fw_sessions',
        'SELECT * FROM public.fw_checkpoints','UPDATE public.fw_versions SET revision=999',
        "UPDATE fw_lease_cap_v1.scope SET workspaces=ARRAY['foreign-scope']",
        'SELECT config,result,checkpoint FROM public.fw_runs',
        'SET ROLE '+api,'SET ROLE '+a['connection']['user']+'_owner',
        "SET SESSION AUTHORIZATION '"+api+"'",
    ]
    for statement in attempts:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with b.connect() as c:c.execute(statement)
    bad=copy.deepcopy(a);bad['workspaces']=['foreign-scope']
    from fieldwork.scoped_authority import MachineBackend
    with pytest.raises(ValueError,match='SCOPE_MISMATCH'):MachineBackend(bad).verify()
    assert s.get(rid)['state']=='running'


@pytest.mark.parametrize('gate',['renew','fence','revision','state','lock','rollback'])
def test_exact_guards_and_atomic_event(machine,gate):
    s,a,b,api=machine;rid=seed(s);candidate=b.candidates('',16)[0]
    before=s.get(rid)
    with s.connect() as c:
        if gate=='renew':c.execute("UPDATE public.fw_runs SET lease=clock_timestamp()+interval '45 seconds' WHERE id=%s",(rid,))
        elif gate=='fence':c.execute('UPDATE public.fw_runs SET fence=fence+1 WHERE id=%s',(rid,))
        elif gate=='revision':c.execute('UPDATE public.fw_runs SET revision=revision+1 WHERE id=%s',(rid,))
        elif gate=='state':c.execute("UPDATE public.fw_runs SET state='succeeded' WHERE id=%s",(rid,))
        elif gate=='rollback':
            c.execute("CREATE FUNCTION public.fail_event() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'fixture'; END$$")
            c.execute('CREATE TRIGGER fixture_failure BEFORE INSERT ON public.fw_events FOR EACH ROW EXECUTE FUNCTION public.fail_event()')
        elif gate=='lock':
            c.execute('SELECT id FROM public.fw_runs WHERE id=%s FOR UPDATE',(rid,))
            assert b.expire(candidate) is None
    if gate=='rollback':
        with pytest.raises(psycopg.errors.RaiseException):b.expire(candidate)
        assert s.get(rid)==before
    elif gate!='lock':assert b.expire(candidate) is None
    with s.connect() as c:
        assert c.execute("SELECT count(*) n FROM public.fw_events WHERE run=%s AND kind='expired'",(rid,)).fetchone()['n']==0


def test_request_api_principal_and_public_execute_denied(machine):
    s,a,b,api=machine
    with s.connect() as c:
        assert not c.execute("SELECT has_function_privilege(%s,'fw_lease_cap_v1.expire(text,integer,integer,text)','EXECUTE') v",(api,)).fetchone()['v']
        assert not c.execute("SELECT has_schema_privilege(%s,'fw_lease_cap_v1','USAGE') v",(api,)).fetchone()['v']
    # Separate real login, not SET ROLE, using fixture-owned password only.
    password=uuid.uuid4().hex
    with s.connect() as c:c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(sql.Identifier(api),sql.Literal(password)))
    p=dict(a['connection'],user=api,password=password)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with psycopg.connect(**p) as c:c.execute("SELECT fw_lease_cap_v1.expire('x',1,1,'running')")


@pytest.mark.parametrize('drift',['role','function','rls','publicexecute','scopewrite'])
def test_startup_rejects_drift_before_writes(machine,drift):
    s,a,b,api=machine;rid=seed(s)
    with s.connect() as c:
        if drift=='role':c.execute(sql.SQL('ALTER ROLE {} BYPASSRLS').format(sql.Identifier(a['connection']['user'])))
        elif drift=='function':c.execute("ALTER FUNCTION fw_lease_cap_v1.expire(text,integer,integer,text) SECURITY INVOKER")
        elif drift=='rls':c.execute('ALTER TABLE public.fw_runs DISABLE ROW LEVEL SECURITY')
        elif drift=='publicexecute':c.execute('GRANT EXECUTE ON FUNCTION fw_lease_cap_v1.expire(text,integer,integer,text) TO PUBLIC')
        elif drift=='scopewrite':c.execute(sql.SQL('GRANT UPDATE ON fw_lease_cap_v1.scope TO {}').format(sql.Identifier(a['connection']['user'])))
    with pytest.raises(ValueError):b.verify()
    assert s.get(rid)['state']=='running'


def test_unsafe_existing_role_not_repaired(isolated_store):
    from fieldwork.scoped_authority import provision
    s=isolated_store;a=specification();p=conninfo_to_dict(s.dsn);login='unsafe_'+uuid.uuid4().hex
    a['connection'].update(host=p['host'],port=int(p['port']),dbname=p['dbname'],user=login)
    try:
        with s.connect() as c:c.execute(sql.SQL('CREATE ROLE {} SUPERUSER').format(sql.Identifier(login)))
        with pytest.raises(ValueError,match='EXISTING_ROLE_NOT_ADOPTED'):provision(s.connect,a)
        with s.connect() as c:
            assert c.execute('SELECT rolsuper FROM pg_roles WHERE rolname=%s',(login,)).fetchone()['rolsuper']
            assert not c.execute("SELECT 1 FROM pg_namespace WHERE nspname='fw_lease_cap_v1'").fetchone()
    finally:
        with s.connect() as c:c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(login)))
