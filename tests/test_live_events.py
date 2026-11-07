"""Actual HTTP SSE transport/revocation, separate generated test session."""
import json,os,time,uuid
import httpx
from fieldwork.api import create_account
from fieldwork.store import Store,ROOT
BASE=os.environ.get('FIELDWORK_LIVE_BASE','http://127.0.0.1:8102')
# Migration 011 requires a non-null config scope. This fixture runs against the LIVE database, where the
# worker claims only scope=synthetic-execution-only (or real scopes); an inert scope keeps the row queued and
# unclaimable by the live worker, matching the old scope-less fixture's behaviour.
INERT_SCOPE='live-transport-fixture-inert/v1'


def test_live_http_stream_revocation_closes_within_thirty_seconds():
    name='live-events-'+uuid.uuid4().hex;password=uuid.uuid4().hex;workspace=name
    create_account(name,password,workspace,'researcher');s=Store();run=s.submit(workspace,name,'event-fixture',{'epochs':1,'scope':INERT_SCOPE})
    with httpx.Client(base_url=BASE,timeout=10) as c:
        login=c.post('/auth/session',json={'name':name,'password':password});assert login.status_code==200
        headers={'Origin':'http://127.0.0.1:8102','X-CSRF-Token':login.json()['csrf']}
        with c.stream('GET','/api/v1/workspaces/'+workspace+'/events/stream') as response:
            assert response.status_code==200
            lines=response.iter_lines();event=None
            for line in lines:
                if line.startswith('data: '):event=json.loads(line[6:]);break
            assert event and event['run']==run['id'] and event['object_revision']==1
            with httpx.Client(base_url=BASE,cookies=c.cookies,timeout=10) as logout:
                assert logout.post('/auth/logout',headers=headers).status_code==200
            started=time.monotonic();revoked=False
            for line in lines:
                if line=='event: access_revoked':revoked=True
            elapsed=time.monotonic()-started
            assert revoked and elapsed<30
        report={'actual_http_transport':True,'workspace':workspace,'run':run['id'],'event_id':event['event_id'],'workspace_sequence':event['seq'],'object_revision':event['object_revision'],'revocation_closed_seconds':elapsed,'session_or_cookie_printed':False}
        __import__('fieldwork.evidence_out',fromlist=['x']).write_evidence(ROOT,'live-sse.json',report)
