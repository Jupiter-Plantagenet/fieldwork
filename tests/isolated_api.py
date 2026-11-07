"""Serve fieldwork.api from a REAL nonowner request principal inside an isolated DB.

The isolated_store fixture yields the DBA (operator) store. API tests previously
pointed fieldwork.api at that superuser store, which can never satisfy the
mandatory fw_checkpoint_read_v1 startup check and bypasses RLS. This helper
provisions a unique NOSUPERUSER/NOBYPASSRLS login with db_security.install
(RLS policies, grants and the checkpoint-read helper) in the throwaway DB, and
points the API at it. Roles are dropped by the isolated_store teardown.
"""
import secrets,uuid
from psycopg.conninfo import conninfo_to_dict,make_conninfo


def provision_request_principal(s):
    from fieldwork import db_security
    from fieldwork.store import Store
    login='fwt_'+uuid.uuid4().hex[:12];password=secrets.token_urlsafe(32)
    s.extra_roles=getattr(s,'extra_roles',[])+[login+'_cp_lock',login]
    db_security.install(s,login,password)
    params=conninfo_to_dict(s.dsn);params.update(user=login,password=password)
    request=Store(dsn=make_conninfo(**params),request=True);request.admin=s
    return request


def use_isolated_api(s,monkeypatch):
    import fieldwork.api as api
    request=provision_request_principal(s)
    monkeypatch.setattr(api,'store',request)
    return request
