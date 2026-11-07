"""ML-T-QUEUE matrix on current source.

Frozen pass condition: one logical run per same idempotency key/digest; 409 for a changed digest; a
queued run remains without charts/ETA/checkpoints (worker disconnected); browser/API restart does not
lose the job; 20-queued-run cap.

Real FastAPI app under a real non-owner request principal against the isolated PostgreSQL. The live
RAM/disk numbers consulted by the submit gate are monkeypatched ONLY as the input of the real decision
code. The restart case runs a REAL separate uvicorn process and hard-kills it.
"""
import concurrent.futures
import json
import os
import socket
import subprocess
import sys
import threading
import time
import types
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

import fieldwork.api as api
from fieldwork.store import ROOT, Conflict
from tests.isolated_api import use_isolated_api

GIB = 1024 ** 3
ORIGIN = 'http://127.0.0.1:5102'


def healthy_host(monkeypatch):
    monkeypatch.setattr(api.psutil, 'virtual_memory', lambda: types.SimpleNamespace(available=64 * GIB))
    monkeypatch.setattr(api.shutil, 'disk_usage', lambda _p: types.SimpleNamespace(total=500 * GIB, used=0, free=400 * GIB))
    monkeypatch.delenv('FIELDWORK_OPERATOR_SPACE_OVERRIDE', raising=False)


def login(client, name, password):
    r = client.post('/auth/session', json={'name': name, 'password': password})
    assert r.status_code == 200, r.text
    return {'Origin': ORIGIN, 'X-CSRF-Token': r.json()['csrf']}


def runs_in(s, workspace):
    with s.connect() as c:
        return c.execute('SELECT * FROM fw_runs WHERE workspace=%s ORDER BY id', (workspace,)).fetchall()


@pytest.fixture
def qapi(isolated_store, monkeypatch):
    use_isolated_api(isolated_store, monkeypatch)
    healthy_host(monkeypatch)
    pw = uuid.uuid4().hex
    api.create_account('qauthor', pw, 'qm', 'owner')
    api.create_account('qother', pw, 'qm-other', 'owner')
    return types.SimpleNamespace(s=isolated_store, pw=pw, base='/api/v1/workspaces/qm', other='/api/v1/workspaces/qm-other')


# ------------------------------------------------------------------ idempotency
def test_response_loss_replays_return_one_logical_run(qapi):
    with TestClient(api.app) as c:
        h = {**login(c, 'qauthor', qapi.pw), 'Idempotency-Key': 'lost-response'}
        first = c.post(qapi.base + '/runs', json={'epochs': 1}, headers=h)
        assert first.status_code == 202
        replays = [c.post(qapi.base + '/runs', json={'epochs': 1}, headers=h) for _ in range(6)]
        assert {r.status_code for r in replays} == {202}
        assert {r.json()['id'] for r in replays} == {first.json()['id']}
        # a replayed body is the SAME run object (same revision: replays create no new revision/event)
        assert {r.json()['revision'] for r in replays} == {first.json()['revision']}
    rows = runs_in(qapi.s, 'qm')
    assert len(rows) == 1 and rows[0]['state'] == 'queued'
    with qapi.s.connect() as conn:
        events = conn.execute("SELECT kind FROM fw_events WHERE run=%s AND kind='queued'", (rows[0]['id'],)).fetchall()
    assert len(events) == 1


@pytest.mark.parametrize('body', [{'epochs': 2}, {'epochs': 1, 'seed': 7}, {'epochs': 1, 'learning_rate': '0.01'}, {'epochs': 1, 'batch_size': 16}])
def test_changed_digest_with_same_key_is_409_and_creates_nothing(qapi, body):
    with TestClient(api.app) as c:
        h = {**login(c, 'qauthor', qapi.pw), 'Idempotency-Key': 'conflict-key'}
        original = c.post(qapi.base + '/runs', json={'epochs': 1}, headers=h)
        assert original.status_code == 202
        conflict = c.post(qapi.base + '/runs', json=body, headers=h)
        assert conflict.status_code == 409 and conflict.json()['code'] == 'IDEMPOTENCY_CONFLICT'
        # the original key still replays its original run afterwards
        assert c.post(qapi.base + '/runs', json={'epochs': 1}, headers=h).json()['id'] == original.json()['id']
    rows = runs_in(qapi.s, 'qm')
    assert len(rows) == 1 and rows[0]['config']['epochs'] == 1


def test_missing_or_oversized_key_is_rejected(qapi):
    with TestClient(api.app) as c:
        h = login(c, 'qauthor', qapi.pw)
        assert c.post(qapi.base + '/runs', json={'epochs': 1}, headers=h).status_code == 422
        assert c.post(qapi.base + '/runs', json={'epochs': 1}, headers={**h, 'Idempotency-Key': 'k' * 201}).status_code == 422
    assert runs_in(qapi.s, 'qm') == []


def test_concurrent_same_key_same_digest_creates_exactly_one_run(qapi):
    n = 8
    clients = []
    for _ in range(n):
        cl = TestClient(api.app)
        clients.append((cl, login(cl, 'qauthor', qapi.pw)))
    barrier = threading.Barrier(n)

    def post(i):
        cl, h = clients[i]
        barrier.wait(timeout=20)
        r = cl.post(qapi.base + '/runs', json={'epochs': 1}, headers={**h, 'Idempotency-Key': 'race-same'})
        return r.status_code, r.json().get('id')

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(post, range(n)))
    assert {code for code, _ in results} == {202}
    assert len({rid for _, rid in results}) == 1
    assert len(runs_in(qapi.s, 'qm')) == 1


def test_concurrent_same_key_different_digests_one_winner_rest_409(qapi):
    n = 6
    clients = []
    for _ in range(n):
        cl = TestClient(api.app)
        clients.append((cl, login(cl, 'qauthor', qapi.pw)))
    barrier = threading.Barrier(n)

    def post(i):
        cl, h = clients[i]
        barrier.wait(timeout=20)
        r = cl.post(qapi.base + '/runs', json={'epochs': 1 + i}, headers={**h, 'Idempotency-Key': 'race-diff'})
        return r.status_code, r.json().get('code') or r.json().get('id')

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(post, range(n)))
    codes = sorted(code for code, _ in results)
    assert codes == [202] + [409] * (n - 1), results
    assert len(runs_in(qapi.s, 'qm')) == 1


# ------------------------------------------------------------------ 20-queued cap
def test_queue_cap_20_via_http_replay_and_conflict_still_answer_at_the_cap(qapi):
    with TestClient(api.app) as c:
        h = login(c, 'qauthor', qapi.pw)
        ids = []
        for i in range(20):
            r = c.post(qapi.base + '/runs', json={'epochs': 1}, headers={**h, 'Idempotency-Key': 'cap-%d' % i})
            assert r.status_code == 202, (i, r.text)
            ids.append(r.json()['id'])
        over = c.post(qapi.base + '/runs', json={'epochs': 1}, headers={**h, 'Idempotency-Key': 'cap-overflow'})
        assert over.status_code == 429 and over.json()['code'] == 'QUEUE_FULL' and over.headers['retry-after'] == '30'
        assert len(runs_in(qapi.s, 'qm')) == 20
        # replay of an accepted key at the cap returns its run (it does not consume a slot, is not refused)
        again = c.post(qapi.base + '/runs', json={'epochs': 1}, headers={**h, 'Idempotency-Key': 'cap-3'})
        assert again.status_code == 202 and again.json()['id'] == ids[3]
        # changed digest on an accepted key is 409, not QUEUE_FULL
        assert c.post(qapi.base + '/runs', json={'epochs': 2}, headers={**h, 'Idempotency-Key': 'cap-3'}).status_code == 409
        # the cap is per workspace (checked next)
    with TestClient(api.app) as c2:
        h2 = login(c2, 'qother', qapi.pw)
        assert c2.post(qapi.other + '/runs', json={'epochs': 1}, headers={**h2, 'Idempotency-Key': 'o1'}).status_code == 202
    assert len(runs_in(qapi.s, 'qm')) == 20


def test_queue_cap_counts_only_queued_runs_and_is_atomic_under_concurrency(isolated_store):
    s = isolated_store
    n = 32
    barrier = threading.Barrier(n)

    def submit(i):
        st = type(s)(dsn=s.dsn)
        barrier.wait(timeout=30)
        try:
            return st.submit('cap-race', 'author', 'k%d' % i, {'epochs': 1})['id']
        except Conflict as exc:
            return str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(submit, range(n)))
    assert results.count('QUEUE_FULL') == n - 20 and len(set(r for r in results if r != 'QUEUE_FULL')) == 20
    assert len(runs_in(s, 'cap-race')) == 20
    # a claimed (leased) run leaves the queued set: exactly one more fits, then it is full again
    head = sorted(runs_in(s, 'cap-race'), key=lambda r: r['id'])[0]
    a = s.claim(head['id'])
    try:
        assert len([r for r in runs_in(s, 'cap-race') if r['state'] == 'queued']) == 19
        s.submit('cap-race', 'author', 'extra', {'epochs': 1})
        with pytest.raises(Conflict, match='QUEUE_FULL'):
            s.submit('cap-race', 'author', 'extra-2', {'epochs': 1})
    finally:
        s.release_slot(head['id'], fence=a['fence'])


# ------------------------------------------------- queued run without a worker
def test_queued_run_without_worker_shows_no_progress_charts_eta_or_checkpoints(qapi, monkeypatch, tmp_path):
    from fieldwork import api_screens
    monkeypatch.setattr(api_screens, 'ROOT', tmp_path)  # no var/worker.json: a disconnected worker
    with TestClient(api.app) as c:
        h = {**login(c, 'qauthor', qapi.pw), 'Idempotency-Key': 'no-worker'}
        rid = c.post(qapi.base + '/runs', json={'epochs': 3}, headers=h).json()['id']
        time.sleep(1.2)
        detail = c.get(qapi.base + f'/runs/{rid}').json()
        assert detail['checkpoints'] == [] and detail['run']['state'] == 'queued'
        assert detail['run']['epoch'] == 0 and detail['run'].get('result') is None
        flat = json.dumps(detail).lower()
        for banned in ('"eta', 'chart', 'train_loss', 'validation_loss', 'seconds_remaining', 'progress'):
            assert banned not in flat, banned
        ops = c.get(qapi.base + '/screens/operations').json()
        row = next(r for r in ops['runs'] if r['id'] == rid)
        assert ops['worker']['status'] == 'none' and row['display_state'] == 'queued_no_worker'
        assert ops['queue_length'] == 1 and row['epoch'] == 0
        lineage = c.get(qapi.base + f'/screens/runs/{rid}/lineage').json()
        assert lineage['checkpoints'] == [] and lineage['attempts'] == []
        assert [e['kind'] for e in lineage['events']] == ['queued']
        snap = c.get(qapi.base + '/snapshot').json()
        assert [r['state'] for r in snap['runs']] == ['queued']
    # an actively beating worker flips only the display state, never the run
    (tmp_path / 'var').mkdir()
    (tmp_path / 'var/worker.json').write_text(json.dumps({'pid': 1, 'as_of': datetime.now(timezone.utc).isoformat(), 'profile': 'x', 'hard_isolation': False}))
    with TestClient(api.app) as c:
        login(c, 'qauthor', qapi.pw)
        ops = c.get(qapi.base + '/screens/operations').json()
        assert next(r for r in ops['runs'] if r['id'] == rid)['display_state'] == 'queued'
    with qapi.s.connect() as conn:
        assert conn.execute('SELECT count(*) n FROM fw_checkpoints WHERE run=%s', (rid,)).fetchone()['n'] == 0


# -------------------------------------------------------- restart with queued jobs
CHILD_API = '''
import sys, types
import uvicorn
import fieldwork.api as api
from fieldwork.store import Store
api.store = Store(dsn=sys.argv[1], request=True)
api.psutil.virtual_memory = lambda: types.SimpleNamespace(available=64 * 1024 ** 3)
api.shutil.disk_usage = lambda p: types.SimpleNamespace(total=500 * 1024 ** 3, used=0, free=400 * 1024 ** 3)
uvicorn.run(api.app, host='127.0.0.1', port=int(sys.argv[2]), log_level='warning')
'''

CHILD_WORKER_VIEW = '''
import json, sys
from fieldwork.store import Store
s = Store(dsn=sys.argv[1])
head = s.next_run()
a = s.claim(head['id'], start=False) if head else None
print(json.dumps({'head': head and head['id'], 'state_after_claim': a and a['state']}))
if a: s.release_slot(head['id'], fence=a['fence'])
'''


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def start_api(dsn, port):
    proc = subprocess.Popen([sys.executable, '-B', '-c', CHILD_API, dsn, str(port)], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError('api process died on start: %s' % proc.returncode)
        try:
            if httpx.get('http://127.0.0.1:%d/health/live' % port, timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            time.sleep(.3)
    proc.kill()
    raise AssertionError('api process did not become live')


def test_hard_killed_api_process_and_worker_restart_do_not_lose_queued_jobs(isolated_store, monkeypatch):
    request = use_isolated_api(isolated_store, monkeypatch)
    pw = uuid.uuid4().hex
    api.create_account('rauthor', pw, 'qrestart', 'owner')
    base = '/api/v1/workspaces/qrestart'
    procs = []
    try:
        port = free_port()
        p1 = start_api(request.dsn, port)
        procs.append(p1)
        url = 'http://127.0.0.1:%d' % port
        browser = httpx.Client(base_url=url, timeout=20)
        csrf = browser.post('/auth/session', json={'name': 'rauthor', 'password': pw}).json()['csrf']
        h = {'Origin': ORIGIN, 'X-CSRF-Token': csrf}
        ids = []
        for i in range(3):
            r = browser.post(base + '/runs', json={'epochs': 1}, headers={**h, 'Idempotency-Key': 'rk-%d' % i})
            assert r.status_code == 202
            ids.append(r.json()['id'])
        # hard kill: no shutdown handlers, response to the "next" request is lost
        p1.kill()
        p1.wait(timeout=20)
        with pytest.raises(httpx.HTTPError):
            browser.get(base + '/snapshot')
        # restarted API process (new PID, new port); the browser keeps its cookie jar: DB-backed session survives
        port2 = free_port()
        p2 = start_api(request.dsn, port2)
        procs.append(p2)
        assert p2.pid != p1.pid
        browser.base_url = httpx.URL('http://127.0.0.1:%d' % port2)
        snap = browser.get(base + '/snapshot')
        assert snap.status_code == 200
        assert sorted(r['id'] for r in snap.json()['runs']) == sorted(ids)
        assert {r['state'] for r in snap.json()['runs']} == {'queued'}
        # response-loss replay across the restart is the same logical run
        again = browser.post(base + '/runs', json={'epochs': 1}, headers={**h, 'Idempotency-Key': 'rk-1'})
        assert again.status_code == 202 and again.json()['id'] == ids[1]
        assert browser.post(base + '/runs', json={'epochs': 2}, headers={**h, 'Idempotency-Key': 'rk-1'}).status_code == 409
        # a browser restart (empty cookie jar, fresh login) sees the same queue
        fresh = httpx.Client(base_url='http://127.0.0.1:%d' % port2, timeout=20)
        assert fresh.get(base + '/snapshot').status_code == 401
        fresh.post('/auth/session', json={'name': 'rauthor', 'password': pw})
        assert sorted(r['id'] for r in fresh.get(base + '/snapshot').json()['runs']) == sorted(ids)
        p2.kill()
        p2.wait(timeout=20)
        # a fresh worker-side process finds the same queue head and can claim it (restart with queued jobs)
        out = subprocess.run([sys.executable, '-B', '-c', CHILD_WORKER_VIEW, isolated_store.dsn], cwd=ROOT,
                             capture_output=True, text=True, timeout=120)
        assert out.returncode == 0, out.stderr[-1500:]
        report = json.loads(out.stdout.strip().splitlines()[-1])
        # next_run selects the queue head (lowest id) among synthetic-execution-only queued runs; the claim wins it
        assert report == {'head': sorted(ids)[0], 'state_after_claim': 'leased'}
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
    rows = runs_in(isolated_store, 'qrestart')
    assert sorted(r['id'] for r in rows) == sorted(ids) and len(rows) == 3
