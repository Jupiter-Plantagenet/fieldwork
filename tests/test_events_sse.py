import json
from fastapi.testclient import TestClient
import fieldwork.api as api
from tests.test_annotations import account
from tests.isolated_api import use_isolated_api



def test_sse_durable_replay_cursor_is_workspace_bound_and_snapshot_has_watermark(isolated_store,monkeypatch):
    use_isolated_api(isolated_store,monkeypatch);api.create_account('stream-user','fixture-password','stream-a','researcher')
    one=isolated_store.submit('stream-a','stream-user','one',{'epochs':1});isolated_store.submit('stream-b','another','one',{'epochs':1})
    base='/api/v1/workspaces/stream-a'
    with TestClient(api.app) as c:
        account(c,'stream-user','fixture-password');c.headers['Accept']='text/event-stream'
        r=c.get(base+'/events?replay_only=true');assert r.status_code==200,r.text
        assert r.headers['content-type'].startswith('text/event-stream')
        messages=[json.loads(line[6:]) for line in r.text.splitlines() if line.startswith('data: ')]
        assert len(messages)==1 and messages[0]['run']==one['id']
        event=messages[0];assert isinstance(event['seq'],str) and event['event_id'] and event['object_revision']==1
        assert event['schema_version']=='1.0' and event['type']=='ML-RunChanged' and event['sequence']==event['seq'] and event['revision']==1 and event['run_id']==one['id'] and event['state']=='queued'
        cursor=next(line[4:] for line in r.text.splitlines() if line.startswith('id: '))
        assert cursor==event['seq']
        assert 'data: ' not in c.get(base+'/events/stream?replay_only=true',headers={'Last-Event-ID':cursor}).text
        isolated_store.submit('stream-a','stream-user','two',{'epochs':1})
        replay=c.get(base+'/events/stream?replay_only=true',headers={'Last-Event-ID':cursor})
        assert replay.text.count('data: ')==1
        assert c.get(base+'/snapshot').json()['last_sequence'].isdecimal()
        assert c.get(base+'/events/stream?replay_only=true',headers={'Last-Event-ID':cursor+'x'}).status_code==409
        assert c.get('/api/v1/workspaces/stream-b/events/stream?replay_only=true',headers={'Last-Event-ID':cursor}).status_code==404
        with isolated_store.connect() as db:db.execute("UPDATE fw_events SET created=clock_timestamp()-interval '8 days' WHERE workspace='stream-a' AND seq=%s",(int(cursor),))
        assert c.get(base+'/events/stream?replay_only=true',headers={'Last-Event-ID':cursor}).status_code==410


def test_open_stream_closes_after_real_session_revocation(isolated_store,monkeypatch):
    import asyncio,time
    from starlette.requests import Request
    from fieldwork.events import stream,replay
    use_isolated_api(isolated_store,monkeypatch);api.create_account('revoked-stream','fixture-password','stream-revoke','researcher')
    isolated_store.submit('stream-revoke','revoked-stream','one',{'epochs':1})
    with TestClient(api.app) as c:
        headers=account(c,'revoked-stream','fixture-password');cookie=c.cookies.get('fieldwork_session')
        async def receive():return {'type':'http.request','body':b'','more_body':False}
        request=Request({'type':'http','method':'GET','path':'/events/stream','headers':[(b'cookie',('fieldwork_session='+cookie).encode())]},receive=receive)
        async def exercise():
            iterator=stream(isolated_store,'stream-revoke',request,api.session,0,replay(isolated_store,'stream-revoke',0),False)
            first=await anext(iterator);assert 'event: domain' in first
            assert c.post('/auth/logout',headers=headers).status_code==200
            started=time.monotonic()
            for _ in range(4):
                message=await asyncio.wait_for(anext(iterator),timeout=5)
                if 'event: access_revoked' in message:
                    assert time.monotonic()-started<30;await iterator.aclose();return
            raise AssertionError('Revoked stream was not closed')
        asyncio.run(exercise())
