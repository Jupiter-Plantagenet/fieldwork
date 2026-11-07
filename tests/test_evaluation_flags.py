"""ASGI + actual SQL adapter behavior only; no retained DB, auth or model claim."""
import copy
from contextlib import contextmanager
import pytest
from fieldwork.data import canonical, digest


class Database:
    def __init__(self):
        self.run = dict(id='run-a', workspace='lab', revision=7, state='succeeded')
        self.events = []
        self.row = None
        self.rows = []
        self.calls = []
        self.fail_insert = False
        self.fail_public = False

    @contextmanager
    def connect(self, **kwargs):
        before = copy.deepcopy(self.events)
        try:
            yield self
        except BaseException:
            self.events = before
            raise

    def execute(self, sql, params=()):
        self.calls.append((sql, params)); self.row = None; self.rows = []
        if 'pg_advisory_xact_lock' in sql:
            pass
        elif sql.startswith('SELECT payload FROM fw_events'):
            w, kind, actor, key = params
            self.row = next((dict(payload=p) for workspace, run, k, p in self.events
                             if workspace == w and k == kind and p['actor'] == actor and p['key'] == key), None)
        elif sql.startswith('SELECT * FROM fw_runs'):
            self.row = copy.deepcopy(self.run) if params == ('run-a', 'lab') else None
        elif sql.startswith('INSERT INTO fw_events'):
            if self.fail_insert:
                raise RuntimeError('injected insert failure')
            w, run, kind, payload, revision = params
            if self.fail_public and kind == 'ML-DataChanged':
                raise RuntimeError('injected public event failure')
            self.events.append((w, run, kind, copy.deepcopy(payload.obj)))
        elif sql.startswith('SELECT payload->'):
            w, rid, kind = params
            self.rows = [dict(flag=p['flag']) for workspace, run, k, p in self.events
                         if (workspace, run, k) == (w, rid, kind)]
        else:
            raise AssertionError('Unexpected SQL: ' + sql)
        return self

    def fetchone(self): return self.row
    def fetchall(self): return self.rows


@pytest.fixture
def adapter(monkeypatch):
    from fieldwork.store import Store
    monkeypatch.setattr(Store, '__init__', lambda self, *a, **k: None)
    from fieldwork import api
    from fastapi.testclient import TestClient
    db = Database(); store = object.__new__(Store)
    monkeypatch.setattr(store, 'connect', db.connect)
    monkeypatch.setattr(api, 'store', store)
    ev = dict(metrics=dict(cells={'0:1': ['s2', 's1']}, missing=['s3']),
              population=[dict(id='s1', label=0), dict(id='s2', label=0), dict(id='s3', label=0)],
              independent={})
    monkeypatch.setattr(api, 'evaluation_core', lambda *args: copy.deepcopy(ev))
    user = dict(name='alice', workspace='lab', role='researcher', csrf='csrf')
    api.app.dependency_overrides[api.session] = lambda: user
    client = TestClient(api.app)
    yield api, client, db, user, ev
    api.app.dependency_overrides.clear(); client.close()


URL = '/api/v1/workspaces/lab/runs/run-a/flags'
HEADERS = {'origin': 'http://127.0.0.1:5102', 'x-csrf-token': 'csrf',
           'If-Match': '"7"', 'Idempotency-Key': '22222222-2222-4222-8222-222222222222'}


def body(ev, bucket='cell'):
    return dict(expected_revision=7, actual=0, predicted=1 if bucket == 'cell' else None,
                bucket=bucket, slice_digest=digest(canonical(['s1', 's2'] if bucket == 'cell' else ['s3'])),
                evaluation_digest=digest(canonical(ev)), reason='Review these examples in a future dataset plan')


def test_flag_persists_exact_full_slice_and_replays_without_mutating_evaluation(adapter, monkeypatch):
    api, client, db, user, ev = adapter
    original = copy.deepcopy((db.run, ev))
    first = client.post(URL, headers=HEADERS, json=body(ev))
    assert first.status_code == 201, first.text
    result = first.json()
    assert result['evaluation_mutated'] is False
    assert result['flag']['sample_ids'] == ['s1', 's2']
    assert result['flag']['actor'] == 'alice'
    assert result['flag']['predicate'] == dict(actual=0, predicted=1, bucket='cell')
    db.run['revision'] = 8
    assert client.post(URL, headers=HEADERS, json=body(ev)).content == first.content
    assert len(db.events) == 2
    loaded = client.get(URL)
    assert loaded.status_code == 200 and loaded.json()['items'] == [result['flag']]
    assert ev == original[1]
    assert not any(sql.startswith(('UPDATE', 'DELETE')) for sql, _ in db.calls)


def test_missing_bucket_is_flagged_without_relabel(adapter):
    api, client, db, user, ev = adapter
    response = client.post(URL, headers=HEADERS, json=body(ev, 'missing'))
    assert response.status_code == 201, response.text
    assert response.json()['flag']['sample_ids'] == ['s3']
    assert response.json()['flag']['predicate']['predicted'] is None


@pytest.mark.parametrize('change', ['slice_digest', 'evaluation_digest'])
def test_changed_evidence_rejected_before_persist(adapter, change):
    api, client, db, user, ev = adapter
    command = body(ev); command[change] = '0' * 64
    response = client.post(URL, headers=HEADERS, json=command)
    assert response.status_code == 412, response.text
    assert not db.events


def test_changed_request_key_reuse_conflicts(adapter):
    api, client, db, user, ev = adapter
    assert client.post(URL, headers=HEADERS, json=body(ev)).status_code == 201
    command = body(ev); command['reason'] = 'A distinct follow-up reason'
    assert client.post(URL, headers=HEADERS, json=command).status_code == 409
    assert len(db.events) == 2


@pytest.mark.parametrize('role', ['viewer', 'holdout_steward', 'worker'])
def test_forbidden_flag_roles(adapter, role):
    api, client, db, user, ev = adapter; user['role'] = role
    assert client.post(URL, headers=HEADERS, json=body(ev)).status_code == 403
    assert not db.calls


def test_reviewer_can_flag(adapter):
    api, client, db, user, ev = adapter; user['role'] = 'reviewer'
    assert client.post(URL, headers=HEADERS, json=body(ev)).status_code == 201


@pytest.mark.parametrize('change', ['csrf', 'origin', 'workspace', 'revision', 'key', 'reason', 'extra', 'predicted'])
def test_validation_and_tenant_denials(adapter, change):
    api, client, db, user, ev = adapter
    headers = dict(HEADERS); command = body(ev); url = URL
    expected = 422
    if change == 'csrf': headers['x-csrf-token'] = 'wrong'; expected = 403
    elif change == 'origin': headers['origin'] = 'https://invalid.example'; expected = 403
    elif change == 'workspace': url = URL.replace('/lab/', '/other/'); expected = 404
    elif change == 'revision': headers.pop('If-Match'); expected = 428
    elif change == 'key': headers['Idempotency-Key'] = 'bad'
    elif change == 'reason': command['reason'] = ' ' * 10
    elif change == 'extra': command['label'] = 2
    elif change == 'predicted': command['predicted'] = None
    assert client.post(url, headers=headers, json=command).status_code == expected
    assert not db.events


def test_stale_run_and_unknown_run_deny(adapter):
    api, client, db, user, ev = adapter
    db.run['revision'] = 8
    assert client.post(URL, headers=HEADERS, json=body(ev)).status_code == 412
    assert client.post(URL.replace('run-a', 'run-b'), headers=HEADERS, json=body(ev)).status_code == 404
    assert not db.events


def test_failed_insert_cannot_report_success(adapter):
    api, client, db, user, ev = adapter; db.fail_insert = True
    with pytest.raises(RuntimeError, match='injected insert failure'):
        client.post(URL, headers=HEADERS, json=body(ev))
    assert not db.events


def test_public_event_failure_rolls_back_flag_and_receipt(adapter):
    api, client, db, user, ev = adapter
    db.fail_public = True
    with pytest.raises(RuntimeError, match='injected public event failure'):
        client.post(URL, headers=HEADERS, json=body(ev))
    assert not db.events
    db.fail_public = False
    assert client.post(URL, headers=HEADERS, json=body(ev)).status_code == 201
    assert [row[2] for row in db.events] == ['evaluation_flag', 'ML-DataChanged']


def test_public_flag_event_redacted_and_exact_replay_emits_once(adapter):
    api, client, db, user, ev = adapter
    first = client.post(URL, headers=HEADERS, json=body(ev))
    assert first.status_code == 201
    events = [p for _, _, kind, p in db.events if kind == 'ML-DataChanged']
    assert len(events) == 1
    public = events[0]
    assert set(public) == {'command', 'flag_id', 'evaluation_digest', 'correlation_id'}
    assert public['flag_id'] == first.json()['flag_id']
    import uuid
    assert str(uuid.UUID(public['correlation_id'])) == public['correlation_id']
    assert public['correlation_id'] != HEADERS['Idempotency-Key']
    db.run['revision'] = 8
    assert client.post(URL, headers=HEADERS, json=body(ev)).content == first.content
    assert len(db.events) == 2


@pytest.mark.parametrize('status', [401,403])
def test_access_refusal_precedes_receipt_lookup_but_recovery_replays(adapter, status):
    api, client, db, user, ev = adapter
    from fastapi import HTTPException
    first = client.post(URL, headers=HEADERS, json=body(ev))
    before = copy.deepcopy(db.events); calls = len(db.calls)
    if status == 401:
        def refused(): raise HTTPException(401, 'SESSION')
        api.app.dependency_overrides[api.session] = refused
    else: user['role'] = 'viewer'
    assert client.post(URL, headers=HEADERS, json=body(ev)).status_code == status
    assert len(db.calls) == calls and db.events == before
    api.app.dependency_overrides[api.session] = lambda: user
    user['role'] = 'researcher'; db.run['revision'] = 8
    assert client.post(URL, headers=HEADERS, json=body(ev)).content == first.content
    assert db.events == before


def test_committed_public_flag_reaches_polling_sse_and_watermark_only(adapter, monkeypatch):
    api, client, db, user, ev = adapter
    first = client.post(URL, headers=HEADERS, json=body(ev))
    assert first.status_code == 201
    assert client.post(URL, headers=HEADERS, json=body(ev)).content == first.content
    before = copy.deepcopy(db.events)
    # Feed exactly the committed writer payloads to the transport SQL adapter.
    from test_event_receipt_privacy import Database as EventDatabase
    from datetime import datetime, timezone
    import uuid, json
    transport = EventDatabase()
    transport.rows.clear()
    transport.rows.extend(dict(seq=i,workspace=w,run=r,kind=k,payload=p,created=datetime.now(timezone.utc),event_id=uuid.uuid4(),object_revision=7)
                          for i,(w,r,k,p) in enumerate(db.events,1))
    monkeypatch.setattr(api.store, 'connect', transport.connect)
    monkeypatch.setattr(api, 'session', lambda request: user)
    monkeypatch.setattr(api, 'generate', lambda *args: dict(scope='authored',classes=['A'],digest='a'*64,samples=[],rights='no clearance claim'))
    base = '/api/v1/workspaces/lab'
    polled = client.get(base+'/events')
    assert polled.status_code == 200, polled.text
    assert [r['kind'] for r in polled.json()['items']] == ['ML-DataChanged']
    assert [r['seq'] for r in polled.json()['items']] == [2]
    for path, headers in [('/events/stream?replay_only=true',{}),('/events?replay_only=true',{'Accept':'text/event-stream'})]:
        response = client.get(base+path, headers=headers)
        assert response.status_code == 200
        messages = [json.loads(x[6:]) for x in response.text.splitlines() if x.startswith('data: ')]
        assert len(messages) == 1 and messages[0]['payload'] == polled.json()['items'][0]['payload']
        assert messages[0]['seq'] == '2'
        for private in ['request_digest','response_body',HEADERS['Idempotency-Key'],body(ev)['reason']]:
            assert private not in response.text
            assert private not in polled.text
    snapshot = client.get(base+'/snapshot')
    assert snapshot.status_code == 200, snapshot.text
    assert snapshot.json()['last_sequence'] == '2'
    assert db.events == before


