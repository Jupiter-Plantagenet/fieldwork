"""Disposable-only mandatory v1 dependency regression (packet runner required)."""
import os,uuid
from pathlib import Path
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo
from fastapi.testclient import TestClient
from fieldwork.store import ROOT,Store
from fieldwork.db_security import install
from fieldwork.checkpoint_read import SCHEMA,SIGNATURE
import fieldwork.api as api


@pytest.fixture
def upgraded(monkeypatch):
    assert os.environ.get('FW_STARTUP_PACKET')=='s29c1a'
    s=Store();role='fw_startup_'+uuid.uuid4().hex[:16];password=uuid.uuid4().hex
    install(s,role,password)
    params=conninfo_to_dict(s.dsn);params.update(user=role,password=password)
    request=Store(dsn=make_conninfo(**params),request=True)
    monkeypatch.setattr(api,'store',request)
    assert ROOT==Path(os.environ['FW_STARTUP_MIRROR']).resolve()
    with request.connect() as c:
        row=c.execute('SELECT current_database() db,current_user AS role,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
        assert row['db']==os.environ['FW_STARTUP_DATABASE'] and row['role']==role
        assert not row['rolsuper'] and not row['rolbypassrls']
    try:yield s,role,request
    finally:
        with s.connect() as c:
            c.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(SCHEMA)))
            for name in [role+'_cp_lock',role]:
                c.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(name)))
                c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(name)))


def test_startup_requires_actual_v1_helper(upgraded):
    s,role,request=upgraded
    with s.connect() as c:c.execute(sql.SQL('DROP FUNCTION '+SIGNATURE))
    with pytest.raises(RuntimeError,match='CHECKPOINT_READ_V1_REQUIRED'):
        with TestClient(api.app):pass


def test_readiness_rechecks_execution_after_startup(upgraded):
    s,role,request=upgraded
    with TestClient(api.app) as client:
        assert client.get('/health/ready').status_code==200
        with s.connect() as c:
            c.execute(sql.SQL('REVOKE EXECUTE ON FUNCTION '+SIGNATURE+' FROM {}').format(sql.Identifier(role)))
        response=client.get('/health/ready')
        assert response.status_code==503,response.text
        assert response.json()['code']=='CHECKPOINT_READ_V1_DEPENDENCY:CHECKPOINT_EXECUTE_REQUIRED'
        assert client.get('/health/live').status_code==200


@pytest.mark.parametrize('mutation,code',[
    ('REVOKE EXECUTE ON FUNCTION '+SIGNATURE+' FROM {role}','CHECKPOINT_EXECUTE_REQUIRED'),
    ('DROP SCHEMA fw_checkpoint_read_v1 CASCADE','CHECKPOINT_READ_V1_REQUIRED'),
    ('ALTER FUNCTION '+SIGNATURE+' RENAME TO locked_digest_v0','CHECKPOINT_READ_V1_REQUIRED'),
    ('ALTER FUNCTION '+SIGNATURE+' SECURITY INVOKER','CHECKPOINT_FUNCTION_MISMATCH'),
    ('ALTER FUNCTION '+SIGNATURE+' SET search_path=public','CHECKPOINT_FUNCTION_MISMATCH'),
    ('ALTER FUNCTION '+SIGNATURE+' OWNER TO {admin}','CHECKPOINT_FUNCTION_MISMATCH'),
    ('ALTER ROLE {owner} LOGIN','UNSAFE_CHECKPOINT_OWNER'),
    ('ALTER TABLE public.fw_checkpoints NO FORCE ROW LEVEL SECURITY','CHECKPOINT_RLS_REQUIRED'),
    ('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO PUBLIC','CHECKPOINT_PUBLIC_EXECUTE'),
    ('GRANT UPDATE(digest) ON public.fw_checkpoints TO {role}','CHECKPOINT_API_COLUMN_WRITE_FORBIDDEN'),
    ("CREATE OR REPLACE FUNCTION fw_checkpoint_read_v1.locked_digest(p_run text,p_epoch integer,p_workspace text) RETURNS TABLE(digest text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS 'BEGIN RETURN; END'",'CHECKPOINT_FUNCTION_MISMATCH'),
])
def test_nonowner_startup_rejects_dependency_drift(upgraded,mutation,code):
    s,role,request=upgraded
    with s.connect() as c:
        admin=c.execute('SELECT current_user AS name').fetchone()['name']
        c.execute(sql.SQL(mutation).format(role=sql.Identifier(role),owner=sql.Identifier(role+'_cp_lock'),admin=sql.Identifier(admin)))
    with pytest.raises(RuntimeError,match=code):
        with TestClient(api.app):pass


def test_valid_upgraded_startup_and_readiness_are_read_only(upgraded):
    s,role,request=upgraded
    def projection():
        with s.connect() as c:
            tables=[r['tablename'] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")]
            return {t:c.execute(sql.SQL('SELECT to_jsonb(t) row FROM public.{} t ORDER BY to_jsonb(t)::text').format(sql.Identifier(t))).fetchall() for t in tables}
    before=projection()
    with s.connect() as c:c.execute(sql.SQL('ALTER ROLE {} SET default_transaction_read_only=on').format(sql.Identifier(role)))
    with TestClient(api.app) as client:
        assert client.get('/health/ready').status_code==200
        assert client.get('/health/live').status_code==200
        with request.connect() as c:
            assert c.execute('SHOW transaction_read_only').fetchone()['transaction_read_only']=='on'
    assert before==projection()


def test_readiness_rechecks_dropped_helper(upgraded):
    s,role,request=upgraded
    with TestClient(api.app) as client:
        with s.connect() as c:c.execute(sql.SQL('DROP FUNCTION '+SIGNATURE))
        response=client.get('/health/ready')
        assert response.status_code==503
        assert response.json()['code']=='CHECKPOINT_READ_V1_REQUIRED'
        assert client.get('/health/live').status_code==200
