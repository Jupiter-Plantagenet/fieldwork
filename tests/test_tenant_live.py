"""ML-T-TENANT over a real HTTP socket against a running API using the nonowner request principal.

Run against a disposable deployment: FIELDWORK_LIVE_BASE (default the canonical 8102).
Two workspaces; every workspace-scoped route is probed cross-tenant (path swap and
object-id swap), SSE/polling streams, revoked membership, and 64 interleaved
concurrent requests check that per-request RLS context never leaks.
"""
import concurrent.futures,json,os,uuid
import httpx,psycopg
from psycopg.rows import dict_row
from fieldwork.api import create_account
from fieldwork.store import Store,ROOT
BASE=os.environ.get('FIELDWORK_LIVE_BASE','http://127.0.0.1:8102')
ORIGIN='http://127.0.0.1:8102'
# Migration 011 requires a non-null config scope. This test writes to the LIVE database, where the worker
# claims only scope=synthetic-execution-only (or real scopes); an inert scope keeps the rows queued (the test
# asserts state=='queued', revision==1) and unclaimable by the live worker, like the old scope-less fixture.
INERT_SCOPE='live-transport-fixture-inert/v1'


def _login(name,password):
    c=httpx.Client(base_url=BASE,timeout=20)
    r=c.post('/auth/session',json={'name':name,'password':password});assert r.status_code==200,r.text
    c.headers.update({'Origin':ORIGIN,'X-CSRF-Token':r.json()['csrf']});return c


def test_cross_tenant_routes_streams_revocation_and_rls_context():
    s=Store();tag=uuid.uuid4().hex[:10];wa,wb='tenant-a-'+tag,'tenant-b-'+tag;pw=uuid.uuid4().hex
    create_account('ua-'+tag,pw,wa,'researcher');create_account('ub-'+tag,pw,wb,'researcher')
    ra=s.submit(wa,'ua-'+tag,'k',{'epochs':1,'scope':INERT_SCOPE});rb=s.submit(wb,'ub-'+tag,'k',{'epochs':1,'scope':INERT_SCOPE})
    a=_login('ua-'+tag,pw);b=_login('ub-'+tag,pw)
    results={}
    try:
        own=a.get(f'/api/v1/workspaces/{wa}/runs/{ra["id"]}');assert own.status_code==200
        reads=['', '/evaluation','/records','/slices','/artifacts','/flags']
        for suffix in reads:
            # B's session against A's workspace path: membership 404 (no existence leak).
            results['path'+suffix]=b.get(f'/api/v1/workspaces/{wa}/runs/{ra["id"]}{suffix}').status_code
            # B's own path with A's run id: object 404 identical to a missing id.
            results['object'+suffix]=b.get(f'/api/v1/workspaces/{wb}/runs/{ra["id"]}{suffix}').status_code
            results['missing'+suffix]=b.get(f'/api/v1/workspaces/{wb}/runs/{uuid.uuid4()}{suffix}').status_code
        for suffix in reads:
            assert results['path'+suffix]==404,results
            assert results['object'+suffix]==results['missing'+suffix] and results['object'+suffix] in (404,409),results
        key=str(uuid.uuid4())
        x=b.post(f'/api/v1/workspaces/{wb}/runs/{ra["id"]}/cancel',headers={'Idempotency-Key':key,'If-Match':'"1"'},json={'expected_revision':1,'reason':'cross tenant probe'})
        assert x.status_code==404,x.text
        assert b.post(f'/api/v1/workspaces/{wa}/runs/{ra["id"]}/cancel',headers={'Idempotency-Key':str(uuid.uuid4()),'If-Match':'"1"'},json={'expected_revision':1,'reason':'cross tenant probe'}).status_code==404
        assert b.post(f'/api/v1/workspaces/{wb}/runs/{ra["id"]}/resume',json={'replay_epoch':1}).status_code in (404,409)
        assert s.get(ra['id'])['state']=='queued' and s.get(ra['id'])['revision']==1
        assert b.get(f'/api/v1/workspaces/{wa}/snapshot').status_code==404
        assert b.get(f'/api/v1/workspaces/{wa}/events').status_code==404
        assert b.get(f'/api/v1/workspaces/{wa}/events/stream?replay_only=true').status_code==404
        own_events=b.get(f'/api/v1/workspaces/{wb}/events').json()['items']
        assert own_events and all(e['run']!=ra['id'] for e in own_events)
        assert b.get(f'/api/v1/workspaces/{wa}/bundles/{ra["id"]}/download').status_code==404
        assert b.get(f'/api/v1/workspaces/{wb}/bundles/{ra["id"]}/download').status_code in (403,404)
        # Interleaved concurrent requests: per-request tenant GUC never leaks.
        def probe(i):
            c,w,mine,other=(a,wa,ra,rb) if i%2 else (b,wb,rb,ra)
            snap=c.get(f'/api/v1/workspaces/{w}/snapshot').json()
            return {r['id'] for r in snap['runs']}=={mine['id']} and other['id'] not in json.dumps(snap)
        with concurrent.futures.ThreadPoolExecutor(8) as ex:assert all(ex.map(probe,range(64)))
        # Request principal is not owner/superuser/BYPASSRLS.
        with psycopg.connect(json.load(open(ROOT/'.local-api.json'))['dsn'],row_factory=dict_row) as c:
            flags=c.execute('SELECT rolsuper,rolbypassrls,(SELECT pg_get_userbyid(relowner)=session_user FROM pg_class WHERE oid=\'public.fw_runs\'::regclass) AS owner FROM pg_roles WHERE rolname=session_user').fetchone()
            assert not any(flags.values()),flags
        # Revoked membership: moving the account to another workspace invalidates the session.
        with s.connect() as c:c.execute('UPDATE fw_accounts SET workspace=%s WHERE name=%s',('elsewhere-'+tag,'ub-'+tag))
        assert b.get(f'/api/v1/workspaces/{wb}/snapshot').status_code==401
        assert b.get('/auth/session').status_code==401
    finally:
        a.close();b.close()
