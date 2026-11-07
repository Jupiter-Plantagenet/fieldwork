"""ML-T-QUEUE on the REAL-SCOPE submit route (POST /api/v1/workspaces/{ws}/real/runs, scope real-training/v1).

Frozen pass condition (portfolio-engineering/ACCEPTANCE-REGISTER.csv, ML-T-QUEUE): one logical run per same
idempotency key/digest; conflict 409 for changed digest; queued remains without charts/ETA/checkpoints;
browser/API restart does not lose job. Task brief adds the queued-run cap and a TCP-level response loss.

Everything runs through the real FastAPI app (all routers) under the retained nonowner request principal
`fieldwork_api` against the retained migration chain 003..023 (tests/chain_support.py) and a real frozen
rights-cleared version (tests/leak_world.py) whose train/validation members carry REAL Ed25519-signed decisions
(tests/signed_world.py). Nothing under test is mocked. The only environment inputs set are the two pinned image
ids the route reads (FIELDWORK_REAL_PIXEL_IMAGE_ID / FIELDWORK_REAL_MODEL_IMAGE_ID) and the reviewer registry path;
no container is started and no training runs. The response-loss and restart cases run a REAL separate uvicorn
process on a local port, drop the TCP connection with RST, and hard-kill the process.

Real-code caps (found in source): fieldwork/store.py Store.submit refuses QUEUE_FULL at 20 queued runs per workspace
(any scope); migration 010 trigger fw_workspace_run_admission_v1 additionally refuses WORKSPACE_RUN_LIMIT once a
workspace has `max_concurrent_runs` active real runs (default 2, owner-settable 1..16). The real route maps both to
HTTP 423 (fieldwork/real_runs_api.py _admission_error).
"""
import json, os, socket, struct, subprocess, sys, time, uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.chain_support import chain, make_account, login, real_worker, ORIGIN, PASSWORD  # noqa: F401
from tests.leak_world import build_world
from tests.signed_world import Signer

DECODER = 'sha256:' + 'a' * 64
MODEL = 'sha256:' + 'b' * 64
EVIDENCE = {}


@pytest.fixture(scope='module')
def env(chain, tmp_path_factory):
    mp = pytest.MonkeyPatch()
    signer = Signer(tmp_path_factory.mktemp('registry') / 'reviewers.json')
    signer.write_registry()
    mp.setenv('FIELDWORK_RIGHTS_REVIEWERS_FILE', str(signer.path))
    mp.setenv('FIELDWORK_REAL_PIXEL_IMAGE_ID', DECODER)
    mp.setenv('FIELDWORK_REAL_MODEL_IMAGE_ID', MODEL)
    try:
        yield SimpleNamespace(chain=chain, signer=signer)
    finally:
        mp.undo()
        out = Path(__file__).resolve().parents[1] / 'var' / 'matrix-state-queue-real-scope.json'
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(EVIDENCE, indent=1, default=str))


def new_ws(env, prefix):
    ws = str(uuid.uuid4())
    W = build_world(env.chain, ws, prefix=prefix)
    env.signer.sign_world(env.chain, W)
    W['researcher'] = f'{prefix}-researcher-{uuid.uuid4().hex[:6]}'
    make_account(env.chain, W['researcher'], 'researcher', ws)
    W['base'] = f'/api/v1/workspaces/{ws}'
    return W


def body(W, **changes):
    return {'version_id': W['version_id'], 'version_revision': 4, 'epochs': 1, 'batch_size': 8,
            'learning_rate': '0.001', 'seed': 7, **changes}


def rows(env, ws, scope=None):
    with env.chain.dba.connect() as c:
        out = c.execute('SELECT * FROM fw_runs WHERE workspace=%s ORDER BY id', (ws,)).fetchall()
    return [r for r in out if scope is None or r['config'].get('scope') == scope]


def queued_events(env, rid):
    with env.chain.dba.connect() as c:
        return c.execute("SELECT count(*) n FROM fw_events WHERE run=%s AND kind='queued'", (rid,)).fetchone()['n']


def checkpoints(env, ws):
    with env.chain.dba.connect() as c:
        return c.execute('SELECT count(*) n FROM fw_checkpoints k JOIN fw_runs r ON r.id=k.run WHERE r.workspace=%s',
                         (ws,)).fetchone()['n']


# ------------------------------------------------------------------ idempotent replay
def test_real_scope_replay_same_key_returns_same_run_and_creates_no_second_row(env):
    W = new_ws(env, 'qr1')
    with TestClient(env.chain.api.app) as c:
        h = {**login(c, W['researcher']), 'Idempotency-Key': 'real-replay'}
        first = c.post(W['base'] + '/real/runs', json=body(W), headers=h)
        assert first.status_code == 202, first.text
        run = first.json()
        assert run['scope'] == 'real-training/v1' and run['state'] == 'queued' and run['version_id'] == W['version_id']
        replays = [c.post(W['base'] + '/real/runs', json=body(W), headers=h) for _ in range(6)]
        assert {r.status_code for r in replays} == {202}
        assert {r.json()['id'] for r in replays} == {run['id']}
        assert {r.json()['revision'] for r in replays} == {run['revision']}
        # queued without a worker: no progress/charts/ETA/checkpoints on the real status + list surfaces
        status = c.get(W['base'] + f"/real/runs/{run['id']}")
        listing = c.get(W['base'] + '/real/runs')
        assert status.status_code == 200 and listing.status_code == 200
        st = status.json()['run']
        assert st['state'] == 'queued' and st['epoch'] == 0 and st['artifact_status'] == 'not_started'
        assert [i['id'] for i in listing.json()['items']] == [run['id']]
        for blob in (status.text.lower(), listing.text.lower()):
            for banned in ('"eta', 'chart', 'train_loss', 'validation_loss', 'seconds_remaining', 'progress', 'checkpoint'):
                assert banned not in blob, banned
    db = rows(env, W['workspace'])
    assert len(db) == 1 and db[0]['id'] == run['id'] and db[0]['state'] == 'queued'
    assert db[0]['config']['scope'] == 'real-training/v1' and db[0]['idem'] == 'real-replay'
    assert queued_events(env, run['id']) == 1 and checkpoints(env, W['workspace']) == 0
    EVIDENCE['replay'] = {'replays': 6, 'rows': len(db), 'queued_events': 1}


# ------------------------------------------------------------------ changed digest -> 409
def test_real_scope_same_key_changed_body_is_409_and_creates_nothing(env):
    W = new_ws(env, 'qr2')
    changed = [{'epochs': 2}, {'seed': 8}, {'batch_size': 16}, {'learning_rate': '0.01'}]
    with TestClient(env.chain.api.app) as c:
        h = {**login(c, W['researcher']), 'Idempotency-Key': 'real-conflict'}
        original = c.post(W['base'] + '/real/runs', json=body(W), headers=h)
        assert original.status_code == 202, original.text
        codes = []
        for change in changed:
            r = c.post(W['base'] + '/real/runs', json=body(W, **change), headers=h)
            assert r.status_code == 409, (change, r.status_code, r.text)
            assert r.json()['code'] == 'IDEMPOTENCY_CONFLICT'
            codes.append(r.status_code)
        again = c.post(W['base'] + '/real/runs', json=body(W), headers=h)
        assert again.status_code == 202 and again.json()['id'] == original.json()['id']
    db = rows(env, W['workspace'])
    assert len(db) == 1 and db[0]['config']['epochs'] == 1 and db[0]['config']['seed'] == 7
    EVIDENCE['conflict'] = {'changed_bodies': len(changed), 'codes': codes, 'rows': len(db)}


# ------------------------------------------------------------------ caps
def test_real_scope_workspace_run_limit_refuses_with_no_row_and_replay_still_answers(env):
    W = new_ws(env, 'qr3')
    with TestClient(env.chain.api.app) as c:
        h = login(c, W['researcher'])
        ids = []
        for i in range(2):  # default max_concurrent_runs=2 (migration 010) with no settings row
            r = c.post(W['base'] + '/real/runs', json=body(W), headers={**h, 'Idempotency-Key': f'lim-{i}'})
            assert r.status_code == 202, r.text
            ids.append(r.json()['id'])
        over = c.post(W['base'] + '/real/runs', json=body(W), headers={**h, 'Idempotency-Key': 'lim-over'})
        assert over.status_code == 423 and over.json()['detail'] == 'WORKSPACE_RUN_LIMIT', over.text
        assert len(rows(env, W['workspace'])) == 2
        replay = c.post(W['base'] + '/real/runs', json=body(W), headers={**h, 'Idempotency-Key': 'lim-1'})
        assert replay.status_code == 202 and replay.json()['id'] == ids[1]
        assert c.post(W['base'] + '/real/runs', json=body(W, epochs=3),
                      headers={**h, 'Idempotency-Key': 'lim-1'}).status_code == 409
    assert sorted(r['id'] for r in rows(env, W['workspace'])) == sorted(ids)
    EVIDENCE['workspace_run_limit'] = {'accepted': 2, 'refused': [423, 'WORKSPACE_RUN_LIMIT'], 'rows': 2}


def test_real_scope_queue_cap_20_refuses_next_submit_with_no_row(env):
    """20-queued cap (Store.submit). Real runs alone stop at max_concurrent_runs<=16, so the workspace is raised to
    16 by an owner settings row and the remaining 4 queued slots are filled by ordinary synthetic queued runs."""
    W = new_ws(env, 'qr4')
    with env.chain.dba.connect() as c:
        c.execute('INSERT INTO fw_workspace_settings(workspace,max_concurrent_runs) VALUES(%s,16)', (W['workspace'],))
    with TestClient(env.chain.api.app) as c:
        h = login(c, W['researcher'])
        real_ids = []
        for i in range(16):
            r = c.post(W['base'] + '/real/runs', json=body(W), headers={**h, 'Idempotency-Key': f'cap-{i}'})
            assert r.status_code == 202, (i, r.text)
            real_ids.append(r.json()['id'])
        r17 = c.post(W['base'] + '/real/runs', json=body(W), headers={**h, 'Idempotency-Key': 'cap-real-17'})
        assert r17.status_code == 423 and r17.json()['detail'] == 'WORKSPACE_RUN_LIMIT'
        for i in range(4):
            # same config shape the synthetic route (fieldwork/api.py submit) writes
            env.chain.dba.submit(W['workspace'], W['researcher'], f'syn-{i}',
                                 {'epochs': 1, 'seed': 42, 'batch_size': 8, 'learning_rate': '0.001',
                                  'dataset_digest': '0' * 64, 'recipe': 'compact-cnn/v1',
                                  'scope': 'synthetic-execution-only'})
        assert len([r for r in rows(env, W['workspace']) if r['state'] == 'queued']) == 20
        over = c.post(W['base'] + '/real/runs', json=body(W), headers={**h, 'Idempotency-Key': 'cap-overflow'})
        assert over.status_code == 423 and over.json()['detail'] == 'QUEUE_FULL', over.text
        # replay of an accepted key at the cap returns its run; a changed digest is 409, not QUEUE_FULL
        again = c.post(W['base'] + '/real/runs', json=body(W), headers={**h, 'Idempotency-Key': 'cap-5'})
        assert again.status_code == 202 and again.json()['id'] == real_ids[5]
        assert c.post(W['base'] + '/real/runs', json=body(W, seed=9),
                      headers={**h, 'Idempotency-Key': 'cap-5'}).status_code == 409
    db = rows(env, W['workspace'])
    assert len(db) == 20 and len([r for r in db if r['config'].get('scope') == 'real-training/v1']) == 16
    assert not [r for r in db if r['idem'] in ('cap-overflow', 'cap-real-17')]
    EVIDENCE['queue_cap'] = {'real_queued': 16, 'synthetic_queued': 4, 'over_cap': [423, 'QUEUE_FULL'], 'rows': 20}


# ------------------------------------------------------------------ real uvicorn process
CHILD_API = '''
import sys
import uvicorn
import fieldwork.api as api
api.store.dsn = sys.argv[1]   # same Store object the routers captured at import (request principal)
uvicorn.run(api.app, host='127.0.0.1', port=int(sys.argv[2]), log_level='warning')
'''


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def start_api(dsn, port):
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.Popen([sys.executable, '-B', '-c', CHILD_API, dsn, str(port)], cwd=root, env=dict(os.environ),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError('api process died on start: %s' % proc.returncode)
        try:
            if httpx.get('http://127.0.0.1:%d/health/live' % port, timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            time.sleep(.5)
    proc.kill()
    raise AssertionError('api process did not become live')


def browser_login(url, name):
    client = httpx.Client(base_url=url, timeout=30)
    r = client.post('/auth/session', json={'name': name, 'password': PASSWORD})
    assert r.status_code == 200, r.text
    return client, {'Origin': ORIGIN, 'X-CSRF-Token': r.json()['csrf']}


def raw_request(port, path, payload, cookie, csrf, key):
    data = json.dumps(payload).encode()
    head = (f'POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n'
            f'Content-Length: {len(data)}\r\nOrigin: {ORIGIN}\r\nX-CSRF-Token: {csrf}\r\nIdempotency-Key: {key}\r\n'
            f'Cookie: fieldwork_session={cookie}\r\nConnection: close\r\n\r\n').encode()
    return head + data


def rst_close(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))  # close() sends RST
    sock.close()


def wait_row(env, ws, key, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [r for r in rows(env, ws) if r['idem'] == key]
        if found:
            return found
        time.sleep(.5)
    return []


def test_real_scope_tcp_response_loss_then_retry_returns_original_run(env):
    W = new_ws(env, 'qr5')
    with env.chain.dba.connect() as c:  # three keys below; lift the default 2-active real-run limit
        c.execute('INSERT INTO fw_workspace_settings(workspace,max_concurrent_runs) VALUES(%s,4)', (W['workspace'],))
    procs = []
    try:
        port = free_port()
        procs.append(start_api(env.chain.request.dsn, port))
        url = 'http://127.0.0.1:%d' % port
        browser, h = browser_login(url, W['researcher'])
        cookie = browser.cookies.get('fieldwork_session')
        path = W['base'] + '/real/runs'
        cases = {}
        # (a) request fully sent and committed server-side, then the socket is reset without reading a single byte:
        #     the client never receives the response
        s = socket.create_connection(('127.0.0.1', port), timeout=30)
        s.sendall(raw_request(port, path, body(W), cookie, h['X-CSRF-Token'], 'tcp-drop-a'))
        found = wait_row(env, W['workspace'], 'tcp-drop-a')
        rst_close(s)
        assert len(found) == 1, 'server must commit the run'
        cases['a'] = found[0]['id']
        # (b) the first response byte is received, then the connection is reset (response cut mid-stream)
        s = socket.create_connection(('127.0.0.1', port), timeout=30)
        s.sendall(raw_request(port, path, body(W), cookie, h['X-CSRF-Token'], 'tcp-drop-b'))
        first_byte = s.recv(1)
        rst_close(s)
        assert first_byte == b'H'
        found = wait_row(env, W['workspace'], 'tcp-drop-b')
        assert len(found) == 1
        cases['b'] = found[0]['id']
        # (c) reset immediately after sending: the request itself may or may not have been processed. After the
        #     retry there must be exactly one run for the key either way.
        s = socket.create_connection(('127.0.0.1', port), timeout=30)
        s.sendall(raw_request(port, path, body(W), cookie, h['X-CSRF-Token'], 'tcp-drop-c'))
        rst_close(s)
        time.sleep(3)
        c_before = len([r for r in rows(env, W['workspace']) if r['idem'] == 'tcp-drop-c'])
        assert c_before in (0, 1)
        r = browser.post(path, json=body(W), headers={**h, 'Idempotency-Key': 'tcp-drop-c'})
        assert r.status_code == 202, r.text
        cases['c'] = r.json()['id']
        EVIDENCE['tcp_case_c_committed_before_retry'] = c_before
        # retries with the same key (as a browser/API client would after a network error): the original run
        for key, rid in cases.items():
            for _ in range(3):
                r = browser.post(path, json=body(W), headers={**h, 'Idempotency-Key': 'tcp-drop-' + key})
                assert r.status_code == 202 and r.json()['id'] == rid, r.text
            assert browser.post(path, json=body(W, epochs=2),
                                headers={**h, 'Idempotency-Key': 'tcp-drop-' + key}).status_code == 409
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
                p.wait(timeout=20)
    db = rows(env, W['workspace'])
    assert sorted(r['id'] for r in db) == sorted(cases.values()) and len(db) == 3
    assert all(queued_events(env, rid) == 1 for rid in cases.values())
    assert {r['state'] for r in db} == {'queued'}
    EVIDENCE['tcp_response_loss'] = {'cases': ['committed_then_rst_unread', 'rst_after_first_byte', 'rst_immediately_after_send'], 'retries_each': 3,
                                     'rows': len(db), 'queued_events_each': 1}


def test_real_scope_hard_killed_api_restart_keeps_queued_real_runs_listable(env, tmp_path):
    W = new_ws(env, 'qr6')
    procs = []
    try:
        port = free_port()
        p1 = start_api(env.chain.request.dsn, port)
        procs.append(p1)
        browser, h = browser_login('http://127.0.0.1:%d' % port, W['researcher'])
        path = W['base'] + '/real/runs'
        ids = []
        for i in range(2):
            r = browser.post(path, json=body(W), headers={**h, 'Idempotency-Key': f'restart-{i}'})
            assert r.status_code == 202, r.text
            ids.append(r.json()['id'])
        p1.kill()
        p1.wait(timeout=20)
        with pytest.raises(httpx.HTTPError):
            browser.get(path)
        port2 = free_port()
        p2 = start_api(env.chain.request.dsn, port2)
        procs.append(p2)
        assert p2.pid != p1.pid
        browser.base_url = httpx.URL('http://127.0.0.1:%d' % port2)
        listing = browser.get(path)
        assert listing.status_code == 200
        assert sorted(i['id'] for i in listing.json()['items']) == sorted(ids)
        assert {i['state'] for i in listing.json()['items']} == {'queued'}
        for rid in ids:
            st = browser.get(path + '/' + rid).json()['run']
            assert st['state'] == 'queued' and st['epoch'] == 0 and st['artifact_status'] == 'not_started'
        again = browser.post(path, json=body(W), headers={**h, 'Idempotency-Key': 'restart-1'})
        assert again.status_code == 202 and again.json()['id'] == ids[1]
        assert browser.post(path, json=body(W, seed=11), headers={**h, 'Idempotency-Key': 'restart-1'}).status_code == 409
        fresh = httpx.Client(base_url='http://127.0.0.1:%d' % port2, timeout=30)
        assert fresh.get(path).status_code == 401
        fresh, _ = browser_login('http://127.0.0.1:%d' % port2, W['researcher'])
        assert sorted(i['id'] for i in fresh.get(path).json()['items']) == sorted(ids)
        p2.kill()
        p2.wait(timeout=20)
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
    # the scoped real worker capability still selects a queued real run of this workspace after the restart
    w = real_worker(env.chain, tmp_path, [W['workspace']])
    head = w.next_real_run()
    assert head and head['id'] in ids
    db = rows(env, W['workspace'])
    assert sorted(r['id'] for r in db) == sorted(ids) and {r['state'] for r in db} == {'queued'}
    assert checkpoints(env, W['workspace']) == 0
    EVIDENCE['restart'] = {'queued_before': 2, 'listed_after': 2, 'worker_head_in_queue': True}
