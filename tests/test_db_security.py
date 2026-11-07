import uuid
import pytest,psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo


def cleanup_test_capability(store,role):
    """Only this test's disposable capability, in dependency order."""
    from fieldwork.checkpoint_read import SCHEMA,SIGNATURE
    assert role.startswith('fieldwork_test_api_')
    owner=role+'_cp_lock'
    with store.connect() as c:
        actual=c.execute('SELECT pg_get_userbyid(proowner) AS owner FROM pg_proc WHERE oid=to_regprocedure(%s)',(SIGNATURE,)).fetchone()
        assert actual and actual['owner']==owner
        c.execute(sql.SQL('DROP FUNCTION '+SIGNATURE))
        c.execute(sql.SQL('DROP SCHEMA {}').format(sql.Identifier(SCHEMA)))
        for name in [owner,role]:
            c.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(name)))
            c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(name)))


def test_nonowner_runtime_rls_default_deny_reused_connection_and_composite_fk(isolated_store):
    from fieldwork.db_security import install
    s=isolated_store;role='fieldwork_test_api_'+uuid.uuid4().hex;password=uuid.uuid4().hex
    a=s.submit('tenant-a','author','one',{'epochs':1});b=s.submit('tenant-b','author','one',{'epochs':1})
    install(s,role,password)
    params=conninfo_to_dict(s.dsn);params.update(user=role,password=password)
    try:
        with psycopg.connect(make_conninfo(**params),autocommit=True) as c:
            identity=c.execute('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone();assert identity==(False,False)
            assert c.execute('SELECT id FROM fw_runs').fetchall()==[]
            with c.transaction():
                c.execute("SELECT set_config('fieldwork.workspace','tenant-a',true)")
                assert c.execute('SELECT id FROM fw_runs').fetchall()==[(a['id'],)]
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    with c.transaction():c.execute('UPDATE fw_runs SET workspace=%s WHERE id=%s',('tenant-b',a['id']))
            assert c.execute('SELECT id FROM fw_runs').fetchall()==[]
            with c.transaction():
                c.execute("SELECT set_config('fieldwork.workspace','tenant-b',true)")
                assert c.execute('SELECT id FROM fw_runs').fetchall()==[(b['id'],)]
            with pytest.raises(psycopg.errors.InsufficientPrivilege):c.execute('SELECT * FROM fw_slot')
        with s.connect() as c:
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                c.execute("INSERT INTO fw_events(workspace,run,kind,payload) VALUES(%s,%s,'cross','{}')",('tenant-b',a['id']))
    finally:
        cleanup_test_capability(s,role)


def test_api_uses_restricted_principal_with_request_local_scope(isolated_store,monkeypatch):
    from fieldwork.db_security import install
    from fieldwork.store import Store
    from fastapi.testclient import TestClient
    import fieldwork.api as api
    s=isolated_store;role='fieldwork_test_api_'+uuid.uuid4().hex;password=uuid.uuid4().hex
    monkeypatch.setattr(api,'store',s);api.create_account('scope-user',password,'tenant-a','researcher')
    run=s.submit('tenant-a','scope-user','one',{'epochs':1});s.submit('tenant-b','other','one',{'epochs':1})
    install(s,role,password)
    params=conninfo_to_dict(s.dsn);params.update(user=role,password=password)
    try:
        request_store=Store(dsn=make_conninfo(**params),request=True)
        monkeypatch.setattr(api,'store',request_store)
        with TestClient(api.app) as c:
            assert c.post('/auth/session',json={'name':'scope-user','password':password}).status_code==200
            snapshot=c.get('/api/v1/workspaces/tenant-a/snapshot');assert snapshot.status_code==200,snapshot.text
            assert [r['id'] for r in snapshot.json()['runs']]==[run['id']]
            assert c.get('/api/v1/workspaces/tenant-b/snapshot').status_code==404
        with request_store.connect() as c:assert c.execute('SELECT id FROM fw_runs').fetchall()==[]
    finally:
        cleanup_test_capability(s,role)
