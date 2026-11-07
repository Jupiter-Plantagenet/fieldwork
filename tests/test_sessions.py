from tests.isolated_api import use_isolated_api
import uuid
from fastapi.testclient import TestClient
from fieldwork.api import app,create_account


def test_successful_login_revokes_presented_old_cookie():
    name='rotation-'+uuid.uuid4().hex;pw=uuid.uuid4().hex
    create_account(name,pw,'session-test','researcher')
    with TestClient(app) as c:
        assert c.post('/auth/session',json={'name':name,'password':pw}).status_code==200
        old=c.cookies.get('fieldwork_session')
        assert c.post('/auth/session',json={'name':name,'password':pw}).status_code==200
        assert c.cookies.get('fieldwork_session')!=old
        assert c.get('/auth/session',headers={'Cookie':'fieldwork_session='+old}).status_code==401
        assert c.get('/auth/session').status_code==200


def test_idle_expiry_and_account_role_change_revoke_session(isolated_store,monkeypatch):
    import fieldwork.api as api
    use_isolated_api(isolated_store,monkeypatch)
    name='idle-'+uuid.uuid4().hex;pw=uuid.uuid4().hex
    create_account(name,pw,'session-test','researcher')
    with TestClient(app) as c:
        c.post('/auth/session',json={'name':name,'password':pw})
        with isolated_store.connect() as db:
            db.execute("UPDATE fw_sessions SET last_seen=now()-interval '31 minutes'")
        assert c.get('/auth/session').status_code==401
        c.post('/auth/session',json={'name':name,'password':pw})
        with isolated_store.connect() as db:db.execute("UPDATE fw_accounts SET role='viewer' WHERE name=%s",(name,))
        assert c.get('/auth/session').status_code==401
