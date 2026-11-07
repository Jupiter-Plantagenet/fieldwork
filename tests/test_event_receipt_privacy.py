"""Real API/replay/SSE code over authored SQL adapter rows, NOT PG/auth proof."""
import copy
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import json
import uuid
import pytest

PRIVATE = {'command_receipt', 'evaluation_flag'}


class Database:
    def __init__(self):
        now = datetime.now(timezone.utc)
        self.rows = [dict(seq=1, workspace='lab', run='run-a', kind='queued', payload={'state':'queued'},
                          created=now, event_id=uuid.uuid4(), object_revision=1)]
        # More than the public page size; filtering AFTER LIMIT would starve it.
        for seq in range(2, 504):
            self.rows.append(dict(seq=seq,workspace='lab',run='run-a',kind='command_receipt' if seq%2 else 'evaluation_flag',
                                  payload={'key':'PRIVATE-KEY','actor':'PRIVATE-ACTOR','reason':'PRIVATE-REASON','response_body':'PRIVATE-RESPONSE'},
                                  created=now,event_id=uuid.uuid4(),object_revision=1))
        self.rows.append(dict(self.rows[0],seq=504,kind='cancelled',payload={'state':'cancelled'}))
        self.result=[];self.one=None;self.calls=[]

    @contextmanager
    def connect(self, **kwargs): yield self

    def execute(self, sql, params=()):
        self.calls.append((sql,params)); self.one=None; self.result=[]
        if 'to_regclass' in sql:  # real_capabilities() schema probe: parameterless, unrelated to event rows
            self.one=dict(intake=False,runs=False,image_inputs=False,workspace_controls=False);return self
        rows=[r for r in self.rows if r['workspace']==params[0]]
        # This adapter deliberately honors SQL predicates; no public sanitizing stub.
        for kind in PRIVATE:
            if f"kind IS DISTINCT FROM '{kind}'" in sql:
                rows=[r for r in rows if r['kind']!=kind]
        if 'AS runs' in sql:
            self.one={'runs':[], 'last_sequence':str(max((r['seq'] for r in rows),default=0))}
        elif 'max(seq) cutoff' in sql:
            old=[r['seq'] for r in rows if r['created']<datetime.now(timezone.utc)-timedelta(days=7)]
            self.one={'cutoff':max(old,default=None)}
        elif sql.startswith('SELECT seq'):
            rows=[r for r in rows if r['seq']>params[1]]
            if "created>=clock_timestamp()" in sql:rows=[r for r in rows if r['created']>=datetime.now(timezone.utc)-timedelta(days=7)]
            self.result=copy.deepcopy(sorted(rows,key=lambda r:r['seq'])[:500])
        else:raise AssertionError('Unexpected SQL: '+sql)
        return self

    def fetchone(self):return self.one
    def fetchall(self):return self.result


@pytest.fixture
def adapter(monkeypatch):
    from fieldwork.store import Store
    monkeypatch.setattr(Store,'__init__',lambda self,*a,**k:None)
    from fieldwork import api
    from fastapi.testclient import TestClient
    db=Database();store=object.__new__(Store);monkeypatch.setattr(store,'connect',db.connect);monkeypatch.setattr(api,'store',store)
    monkeypatch.setattr(api,'generate',lambda *a:dict(scope='authored',classes=['A'],digest='a'*64,samples=[],rights='authored no real rights claim'))
    user=dict(name='viewer',workspace='lab',role='viewer',csrf='authored')
    api.app.dependency_overrides[api.session]=lambda:user
    # stream() deliberately reauthenticates outside FastAPI DI; keep this seam
    # explicitly authored too, rather than accidentally calling retained auth.
    monkeypatch.setattr(api,'session',lambda request:user)
    client=TestClient(api.app)
    yield api,client,store,db
    api.app.dependency_overrides.clear();client.close()


BASE='/api/v1/workspaces/lab'


@pytest.mark.parametrize('path,headers', [('/events',{}),('/events?replay_only=true',{'Accept':'text/event-stream'}),('/events/stream?replay_only=true',{})])
def test_public_event_routes_do_not_expose_receipts_or_starve_public_pages(adapter,path,headers):
    api,client,store,db=adapter;before=copy.deepcopy(db.rows)
    response=client.get(BASE+path,headers=headers)
    assert response.status_code==200,response.text
    assert 'PRIVATE-' not in response.text
    assert 'command_receipt' not in response.text
    assert 'evaluation_flag' not in response.text
    if path=='/events':
        assert [r['seq'] for r in response.json()['items']]==[1,504]
    else:
        messages=[json.loads(x[6:]) for x in response.text.splitlines() if x.startswith('data: ')]
        assert [r['seq'] for r in messages]==['1','504']
    assert db.rows==before, 'Filtering must not rewrite/delete replay receipts'


def test_snapshot_cursor_population_excludes_internal_receipts(adapter):
    api,client,store,db=adapter;db.rows.pop() # highest public watermark is now 1
    response=client.get(BASE+'/snapshot')
    assert response.status_code==200,response.text
    assert response.json()['last_sequence']=='1'
    assert response.json()['capabilities'].get('evaluation_flags') is True
    assert len(db.rows)==503


def test_expired_private_receipt_does_not_expire_public_cursor(adapter):
    api,client,store,db=adapter
    for row in db.rows:
        if row['kind'] in PRIVATE:row['created']-=timedelta(days=8)
    response=client.get(BASE+'/events/stream?replay_only=true',headers={'Last-Event-ID':'1'})
    assert response.status_code==200,response.text
    assert 'id: 504' in response.text
    assert 'PRIVATE-' not in response.text


def test_expired_public_event_still_requires_resnapshot(adapter):
    api,client,store,db=adapter;db.rows[0]['created']-=timedelta(days=8)
    assert client.get(BASE+'/events/stream?replay_only=true',headers={'Last-Event-ID':'1'}).status_code==410


def test_other_workspace_denied_without_event_read(adapter):
    api,client,store,db=adapter
    assert client.get(BASE.replace('/lab','/other')+'/events').status_code==404
    assert not db.calls


@pytest.mark.parametrize('path', ['/events', '/events/stream?replay_only=true'])
def test_initial_replay_excludes_old_public_but_preserves_audit_and_null_legacy(adapter, path):
    api, client, store, db = adapter
    db.rows[0]['created'] -= timedelta(days=8)
    db.rows.append(dict(db.rows[-1], seq=505, kind=None, payload={'legacy':'visible'}))
    before = copy.deepcopy(db.rows)
    response = client.get(BASE+path)
    assert response.status_code == 200
    if path == '/events':
        items = response.json()['items']
        assert [row['seq'] for row in items] == [504,505]
    else:
        items = [json.loads(x[6:]) for x in response.text.splitlines() if x.startswith('data: ')]
        assert [row['seq'] for row in items] == ['504','505']
    assert items[-1]['kind'] is None
    assert db.rows == before


@pytest.mark.parametrize('after', [0,1])
def test_polling_expired_or_consumed_old_cursor_requires_resnapshot(adapter, after):
    api, client, store, db = adapter
    db.rows[0]['created'] -= timedelta(days=8)
    before = copy.deepcopy(db.rows)
    response = client.get(BASE+f'/events?after={after}')
    assert response.status_code == 410, response.text
    assert 'EVENT_CURSOR_EXPIRED_RESNAPSHOT' in response.text
    assert db.rows == before


def test_polling_current_cursor_ignores_expired_private_rows(adapter):
    api, client, store, db = adapter
    for row in db.rows:
        if row['kind'] in PRIVATE: row['created'] -= timedelta(days=8)
    response = client.get(BASE+'/events?after=1')
    assert response.status_code == 200
    assert [row['seq'] for row in response.json()['items']] == [504]

