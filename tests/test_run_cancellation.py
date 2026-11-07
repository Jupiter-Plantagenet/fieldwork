"""Ordinary ASGI/SQL-adapter tests; not PostgreSQL or physical-race proof."""
import copy
import sys
import types
from contextlib import contextmanager
import pytest


class Database:
    def __init__(self, state='queued', revision=7):
        # Models the schema after migrations/004 (cancel_generation present).
        self.run=dict(id='run-a',workspace='lab',state=state,revision=revision,fence=3,cancel_generation=0,config=dict(scope='synthetic-execution-only'))
        self.receipts=[]
        self.calls=[]
        self.row=None

    @contextmanager
    def connect(self, **kwargs):
        before=copy.deepcopy((self.run,self.receipts))
        try:yield self
        except BaseException:
            self.run,self.receipts=before
            raise

    def execute(self,sql,params=()):
        self.calls.append((sql,params));self.row=None
        if 'pg_advisory_xact_lock' in sql:pass
        elif sql.startswith('SELECT payload FROM fw_events'):
            workspace,kind,actor,key=params
            canonical_key="COALESCE(payload->>'key_identity',LOWER(payload->>'key'))" in sql
            self.row=next((dict(payload=p) for w,k,p in self.receipts if w==workspace and k==kind and p['actor']==actor and (p.get('key_identity',p['key'].lower()) if canonical_key else p['key'])==key),None)
        elif sql.startswith('SELECT to_regclass('):
            # api.real_capabilities(): schema probe; this fixture models a schema with no real-run/intake objects.
            self.row=dict(intake=False,runs=False,image_inputs=False,workspace_controls=False)
        elif sql.startswith('SELECT * FROM fw_runs'):
            self.row=copy.deepcopy(self.run) if params==(self.run['id'],self.run['workspace']) else None
        elif sql.startswith('SELECT revision FROM fw_runs'):self.row=dict(revision=self.run['revision'])
        elif sql.startswith('UPDATE fw_runs SET state='):
            self.run.update(state=params[0],fence=self.run['fence']+1,revision=self.run['revision']+1)
        elif sql.startswith('INSERT INTO fw_events'):
            workspace,rid,kind,payload,*rest=params
            if kind=='command_receipt':self.receipts.append((workspace,kind,copy.deepcopy(payload.obj)))
        else:raise AssertionError('Unexpected SQL: '+sql)
        return self

    def fetchone(self):return self.row


@pytest.fixture
def adapter(monkeypatch):
    # Same no-settings/no-lifespan seam as signed-rights adapters; prevent PIL
    # import entirely. The real data canonical/digest functions remain in use.
    if 'fieldwork.data' not in sys.modules:
        pil=types.ModuleType('PIL')
        pil.Image=pil.ImageDraw=pil.ImageOps=pil.ImageEnhance=None
        monkeypatch.setitem(sys.modules,'PIL',pil)
    from fieldwork.store import Store
    monkeypatch.setattr(Store,'__init__',lambda self,*a,**k:None)
    from fieldwork import api
    from fastapi.testclient import TestClient
    db=Database();store=object.__new__(Store)
    monkeypatch.setattr(store,'connect',db.connect)
    monkeypatch.setattr(api,'store',store)
    user=dict(name='alice',workspace='lab',role='researcher',csrf='csrf')
    api.app.dependency_overrides[api.session]=lambda:user
    client=TestClient(api.app)
    yield api,client,db,user
    api.app.dependency_overrides.clear();client.close()


SCOPE_READ='SELECT * FROM fw_runs WHERE id=%s AND workspace=%s'


def assert_no_command_effects(db):
    # api.fixture_run() (scope guard against real runs) does one plain read-only
    # run lookup before the cancel command is validated. Nothing else may
    # happen: no advisory lock, no row lock, no update, no receipt.
    assert [sql for sql,params in db.calls] in ([],[SCOPE_READ])
    assert not db.receipts


URL='/api/v1/workspaces/lab/runs/run-a/cancel'
HEADERS={'origin':'http://127.0.0.1:5102','x-csrf-token':'csrf','If-Match':'"7"','Idempotency-Key':'22222222-2222-4222-8222-222222222222'}
BODY={'expected_revision':7,'reason':'Stop this queued experiment'}


def test_stale_route_is_durable_and_does_not_cancel(adapter):
    api,client,db,user=adapter
    db.run['revision']=8
    first=client.post(URL,json=BODY,headers=HEADERS)
    assert first.status_code==412,first.text
    assert first.json()['code']=='STALE_REVISION'
    assert db.run['state']=='queued'
    assert len(db.receipts)==1
    db.run['revision']=7
    second=client.post(URL,json=BODY,headers=HEADERS)
    assert second.content==first.content
    assert second.status_code==412
    assert db.run['state']=='queued'


@pytest.mark.parametrize('state,expected', [('queued','cancelled'),('interrupted','cancelled'),('running','cancel_requested'),('succeeded','succeeded'),('failed','failed'),('cancelled','cancelled')])
def test_states_and_slot_protection(adapter,state,expected):
    api,client,db,user=adapter;db.run['state']=state
    if state==expected:db.run['revision']=9
    response=client.post(URL,json=BODY,headers=HEADERS)
    assert response.status_code==200,response.text
    assert response.json()==dict(state=expected,completion_won=state=='succeeded')
    assert db.run['revision']==(8 if state!=expected else 9)
    assert db.run['fence']==(4 if state!=expected else 3)
    assert not any('fw_slot' in sql for sql,params in db.calls)
    # db.calls[0] is the read-only scope guard; the command itself then takes
    # the advisory lock first and locks the run row FOR UPDATE.
    assert db.calls[0][0]==SCOPE_READ
    assert 'pg_advisory_xact_lock' in db.calls[1][0]
    assert 'FOR UPDATE' in next(sql for sql,params in db.calls[1:] if sql.startswith('SELECT * FROM fw_runs'))


@pytest.mark.parametrize('change',['reason','expected_revision','run_id'])
def test_changed_request_reuse_conflicts(adapter,change):
    api,client,db,user=adapter
    assert client.post(URL,json=BODY,headers=HEADERS).status_code==200
    body=dict(BODY);headers=dict(HEADERS);url=URL
    if change=='reason':body['reason']='Different reason'
    elif change=='expected_revision':body['expected_revision']=8;headers['If-Match']='"8"'
    else:
        # run-b must exist so the fixture-scope guard passes and the key's
        # original run binding (not a 404) is what rejects the reuse.
        url=URL.replace('run-a','run-b');db.run.update(id='run-b',state='queued',revision=7)
    response=client.post(url,json=body,headers=headers)
    assert response.status_code==409 and response.json()['code']=='IDEMPOTENCY_CONFLICT'
    assert len(db.receipts)==1


@pytest.mark.parametrize('field,value',[('expected_revision',True),('expected_revision','7'),('expected_revision',0),('reason',''),('reason','  '),('reason','x'*2001),('actor','forged')])
def test_invalid_body(adapter,field,value):
    api,client,db,user=adapter;body=dict(BODY);body[field]=value
    assert client.post(URL,json=body,headers=HEADERS).status_code==422
    assert_no_command_effects(db)


@pytest.mark.parametrize('field,value,status',[('If-Match',None,428),('If-Match','7',422),('If-Match','W/"7"',422),('If-Match','"8"',422),('Idempotency-Key',None,422),('Idempotency-Key','bad',422),('origin','https://invalid.example',403),('x-csrf-token','wrong',403)])
def test_invalid_headers(adapter,field,value,status):
    api,client,db,user=adapter;headers=dict(HEADERS)
    if value is None:headers.pop(field)
    else:headers[field]=value
    assert client.post(URL,json=BODY,headers=headers).status_code==status
    assert_no_command_effects(db)


@pytest.mark.parametrize('role',['viewer','reviewer','worker'])
def test_roles_denied(adapter,role):
    api,client,db,user=adapter;user['role']=role
    assert client.post(URL,json=BODY,headers=HEADERS).status_code==403
    assert not db.calls


def test_internal_cancel_compatibility(adapter):
    api,client,db,user=adapter;db.run['state']='running'
    assert api.store.cancel('lab','run-a')=='cancel_requested'
    assert api.store.cancel('lab','run-a')=='cancel_requested'
    assert db.run['revision']==8 and db.run['fence']==4
    assert not any('fw_slot' in sql for sql,params in db.calls)


def test_store_rejects_invalid_key_before_storage(adapter):
    api,client,db,user=adapter
    with pytest.raises(ValueError,match='IDEMPOTENCY_KEY_REQUIRED'):
        api.store.cancel_command('lab','alice','bad','run-a',7,BODY['reason'])
    assert not db.calls


def test_exact_success_replay_across_store_instances(adapter,monkeypatch):
    api,client,db,user=adapter;db.run['state']='running'
    first=client.post(URL,json=BODY,headers=HEADERS)
    db.run.update(state='cancelled',revision=10)
    from fieldwork.store import Store
    replacement=object.__new__(Store);monkeypatch.setattr(replacement,'connect',db.connect)
    monkeypatch.setattr(api,'store',replacement)
    second=client.post(URL,json=BODY,headers=HEADERS)
    assert second.status_code==first.status_code==200
    assert second.content==first.content
    assert second.json()['state']=='cancel_requested'
    assert len(db.receipts)==1
    reads=[sql for sql,params in db.calls if sql.startswith('SELECT payload FROM fw_events')]
    assert all('created' not in sql and 'interval' not in sql for sql in reads)


def test_actor_workspace_and_command_scope(adapter):
    api,client,db,user=adapter
    assert client.post(URL,json=BODY,headers=HEADERS).status_code==200
    user['name']='bob'
    assert client.post(URL,json=BODY,headers=HEADERS).status_code==200
    user['workspace']='other';db.run.update(workspace='other',state='queued',revision=7)
    assert client.post(URL.replace('/lab/','/other/'),json=BODY,headers=HEADERS).status_code==200
    assert len(db.receipts)==3
    assert all(p['command']=='ML-Cancel' for w,k,p in db.receipts)
    assert all("payload->>'command'='ML-Cancel'" in sql for sql,params in db.calls if sql.startswith('SELECT payload'))


def test_membership_and_session_denied(adapter):
    from fastapi import HTTPException
    api,client,db,user=adapter
    assert client.post(URL.replace('/lab/','/other/'),json=BODY,headers=HEADERS).status_code==404
    def no_session():raise HTTPException(401,'SESSION')
    api.app.dependency_overrides[api.session]=no_session
    assert client.post(URL,json=BODY,headers=HEADERS).status_code==401
    assert not db.calls


def test_missing_run_receipt_replays_exact_404(adapter):
    api,client,db,user=adapter
    url=URL.replace('run-a','absent')
    first=client.post(url,json=BODY,headers=HEADERS)
    second=client.post(url,json=BODY,headers=HEADERS)
    assert first.status_code==second.status_code==404
    assert first.content==second.content
    assert len(db.receipts)==1


def test_store_level_missing_run_receipt_replays_exact_404(adapter):
    # Companion to the API-level test above (which currently fails: api.fixture_run
    # answers 404 before store.cancel_command, so no receipt is written). This
    # proves the store itself still binds the 404 outcome durably to the key.
    api,client,db,user=adapter
    first=api.store.cancel_command('lab','alice',HEADERS['Idempotency-Key'],'absent',7,BODY['reason'])
    second=api.store.cancel_command('lab','alice',HEADERS['Idempotency-Key'],'absent',7,BODY['reason'])
    assert first[0]==second[0]==404
    assert first==second
    assert len(db.receipts)==1


@pytest.mark.parametrize('key',['abcdefab-cdef-4abc-8def-abcdefabcdef','ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF'])
def test_uuid_key_case_does_not_create_a_second_command_identity(adapter,key):
    api,client,db,user=adapter
    other_case=key.upper() if key.islower() else key.lower()
    headers={**HEADERS,'Idempotency-Key':key}
    first=client.post(URL,json=BODY,headers=headers)
    assert first.status_code==200
    replay=client.post(URL,json=BODY,headers={**headers,'Idempotency-Key':other_case})
    assert replay.content==first.content and len(db.receipts)==1
    scopes=[params[0] for sql,params in db.calls if 'pg_advisory_xact_lock' in sql]
    assert scopes[0]==scopes[1]
    db.run.update(id='run-b',state='queued',revision=7)
    response=client.post(URL.replace('run-a','run-b'),json=BODY,
                         headers={**headers,'Idempotency-Key':other_case})
    assert response.status_code==409,response.text
    assert response.json()['code']=='IDEMPOTENCY_CONFLICT'
    assert len(db.receipts)==1 and db.run['state']=='queued'
    assert db.receipts[0][2]['key']==key


@pytest.mark.parametrize('reason',['x'*1500,'🌿'*1500])
def test_long_unicode_reason_is_preserved(adapter,reason):
    api,client,db,user=adapter
    response=client.post(URL,json={**BODY,'reason':reason},headers=HEADERS)
    assert response.status_code==200,response.text
    assert db.receipts[0][2]['reason']==reason


def test_snapshot_advertises_revisioned_cancel_without_mutation(adapter,monkeypatch,tmp_path):
    api,client,db,user=adapter
    monkeypatch.setattr(api,'generate',lambda _:dict(scope='authored-test',classes=[],digest='unit',samples=[],rights='authored-test'))
    monkeypatch.setattr(api.store,'snapshot',lambda _:dict(runs=[],last_sequence='0'))
    monkeypatch.setattr(api,'ROOT',tmp_path)
    response=client.get('/api/v1/workspaces/lab/snapshot')
    assert response.status_code==200
    assert response.json()['capabilities']=={'revisioned_cancel':True,'evaluation_flags':True,
        'real_intake':False,'real_runs':False,'real_image_inference':False,'workspace_controls':False}
    # Only the read-only real-capability schema probe may touch the database.
    assert all(sql.startswith('SELECT to_regclass(') for sql,params in db.calls)
    assert db.run==Database().run and not db.receipts


def test_receipt_failure_rolls_back_cancellation(adapter,monkeypatch):
    api,client,db,user=adapter;execute=db.execute
    def failing(sql,params=()):
        if sql.startswith('INSERT INTO fw_events') and params[2]=='command_receipt':raise RuntimeError('receipt unavailable')
        return execute(sql,params)
    monkeypatch.setattr(db,'execute',failing)
    with pytest.raises(Exception,match='receipt unavailable'):client.post(URL,json=BODY,headers=HEADERS)
    assert db.run['state']=='queued' and db.run['revision']==7 and not db.receipts
