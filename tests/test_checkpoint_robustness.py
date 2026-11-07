"""Real PostgreSQL representation and owned-fixture teardown regressions."""
import os
import pytest
from psycopg import sql
from fieldwork.store import Store
from fieldwork.checkpoint_read import SCHEMA,SIGNATURE,verify
from test_checkpoint_startup import upgraded


def test_compact_fixed_path_from_current_is_equivalent(upgraded):
    s,role,request=upgraded
    with s.connect() as c:
        c.execute("SELECT set_config('search_path','pg_catalog,pg_temp',true)")
        c.execute(sql.SQL('ALTER FUNCTION '+SIGNATURE+' SET search_path FROM CURRENT'))
        config=c.execute('SELECT proconfig FROM pg_proc WHERE oid=to_regprocedure(%s)',(SIGNATURE,)).fetchone()['proconfig']
        assert config==['search_path=pg_catalog,pg_temp']
        verify(c,role)
    from fastapi.testclient import TestClient
    import fieldwork.api as api
    with TestClient(api.app) as client:assert client.get('/health/ready').status_code==200


@pytest.mark.parametrize('path',['pg_catalog,pg_temp',' pg_catalog , pg_temp ','pg_catalog\t,\tpg_temp'])
def test_equivalent_fixed_whitespace_path(upgraded,path):
    s,role,request=upgraded
    with s.connect() as c:
        c.execute("SELECT set_config('search_path',%s,true)",(path,))
        c.execute(sql.SQL('ALTER FUNCTION '+SIGNATURE+' SET search_path FROM CURRENT'))
        verify(c,role)


@pytest.mark.parametrize('path',['public,pg_catalog,pg_temp','$user,pg_catalog,pg_temp','pg_catalog,public,pg_temp','pg_temp,pg_catalog','pg_catalog','"pg_catalog,pg_temp"','pg_catalog,pg_temp,public'])
def test_untrusted_or_single_quoted_schema_path_rejected(upgraded,path):
    s,role,request=upgraded
    with s.connect() as c:
        c.execute("SELECT set_config('search_path',%s,true)",(path,))
        c.execute(sql.SQL('ALTER FUNCTION '+SIGNATURE+' SET search_path FROM CURRENT'))
        with pytest.raises(ValueError,match='CHECKPOINT_FUNCTION_MISMATCH'):verify(c,role)


def test_additional_function_guc_rejected(upgraded):
    s,role,request=upgraded
    with s.connect() as c:
        c.execute(sql.SQL('ALTER FUNCTION '+SIGNATURE+' SET statement_timeout=1000'))
        with pytest.raises(ValueError,match='CHECKPOINT_FUNCTION_MISMATCH'):verify(c,role)


def test_security_teardown_twice_in_same_owned_database(monkeypatch):
    assert os.environ.get('FW_STARTUP_PACKET')=='s29c1a'
    import test_db_security as security
    s=Store()
    with s.connect() as c:
        assert c.execute('SELECT current_database() db').fetchone()['db']==os.environ['FW_STARTUP_DATABASE']
        baseline=[r['rolname'] for r in c.execute('SELECT rolname FROM pg_roles ORDER BY rolname')]
    for check in [security.test_nonowner_runtime_rls_default_deny_reused_connection_and_composite_fk,security.test_api_uses_restricted_principal_with_request_local_scope]:
        for iteration in range(2):
            with s.connect() as c:old_ids=[r['id'] for r in c.execute('SELECT id FROM fw_runs')]
            if check==security.test_api_uses_restricted_principal_with_request_local_scope:
                check(s,monkeypatch)
                with s.connect() as c:
                    c.execute("DELETE FROM fw_sessions WHERE name='scope-user'")
                    c.execute("DELETE FROM fw_accounts WHERE name='scope-user'")
            else:check(s)
            with s.connect() as c:
                created=[r['id'] for r in c.execute('SELECT id FROM fw_runs') if r['id'] not in old_ids]
                c.execute('DELETE FROM fw_events WHERE run=ANY(%s)',(created,))
                c.execute('DELETE FROM fw_runs WHERE id=ANY(%s)',(created,))
                assert c.execute('SELECT 1 FROM pg_namespace WHERE nspname=%s',(SCHEMA,)).fetchone() is None,'test-owned capability schema leaked'
                assert [r['rolname'] for r in c.execute('SELECT rolname FROM pg_roles ORDER BY rolname')]==baseline,'test-owned helper owner leaked'
