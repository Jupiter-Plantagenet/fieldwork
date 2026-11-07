"""Read-only UI screen projections: membership scoping, RLS, server-derived policy."""
from tests.isolated_api import use_isolated_api
import uuid
from fastapi.testclient import TestClient
import fieldwork.api as api

SCREENS = ['operations', 'splits', 'configure', 'access', 'inference']


def login(client, name, password):
    r = client.post('/auth/session', json={'name': name, 'password': password}); assert r.status_code == 200, r.text


def test_screen_reads_are_scoped_read_only_and_policy_matches_guards(isolated_store, monkeypatch):
    use_isolated_api(isolated_store, monkeypatch)
    pw = uuid.uuid4().hex; tag = uuid.uuid4().hex[:8]
    wa, wb = 'P5UI-a-' + tag, 'P5UI-b-' + tag
    api.create_account('P5UI-owner-' + tag, pw, wa, 'owner')
    api.create_account('P5UI-viewer-' + tag, pw, wa, 'viewer')
    api.create_account('P5UI-other-' + tag, pw, wb, 'researcher')
    run = isolated_store.submit(wa, 'P5UI-owner-' + tag, 'P5UI-key-' + tag, {'epochs': 2})
    other = isolated_store.submit(wb, 'P5UI-other-' + tag, 'P5UI-key-' + tag, {'epochs': 1})
    with TestClient(api.app) as c:
        assert c.get(f'/api/v1/workspaces/{wa}/screens/operations').status_code == 401
        login(c, 'P5UI-viewer-' + tag, pw)
        base = f'/api/v1/workspaces/{wa}'
        for s in SCREENS:
            assert c.get(f'/api/v1/workspaces/{wb}/screens/{s}').status_code == 404, s  # membership 404
            assert c.get(f'{base}/screens/{s}').status_code == 200, s
        ops = c.get(base + '/screens/operations').json()
        assert [r['id'] for r in ops['runs']] == [run['id']] and ops['queue_length'] == 1
        assert ops['runs'][0]['display_state'] in ('queued', 'queued_no_worker')
        assert c.get(f'{base}/screens/runs/{other["id"]}/lineage').status_code == 404  # RLS / scoped object
        lin = c.get(f'{base}/screens/runs/{run["id"]}/lineage').json()
        assert lin['attempts'] == [] and lin['checkpoints'] == [] and lin['recovery']['blocked_code'] == 'NOT_INTERRUPTED'
        assert [e['kind'] for e in lin['events']] == ['queued']
        acc = c.get(base + '/screens/access').json()
        assert {m['name'] for m in acc['members']} == {'P5UI-owner-' + tag, 'P5UI-viewer-' + tag}
        assert all(set(m) == {'name', 'role'} for m in acc['members'])
        policy = {p['action']: p['roles'] for p in acc['policy']}
        assert policy['Submit, cancel, resume, create/freeze version, propose label'] == ['owner', 'researcher']
        assert policy['Review label proposal or exact version'] == ['owner', 'reviewer']
        assert policy['Flag an evaluation slice'] == ['owner', 'researcher', 'reviewer']
        assert c.get(base + '/screens/configure').json()['may_submit'] is False
        sp = c.get(base + '/screens/splits').json()
        assert sp['splits']['holdout']['membership_digest'] is None and sp['splits']['holdout']['sealed'] is True
        assert sp['integrity']['problems'] == []
        inf = c.get(base + '/screens/inference').json()
        assert inf['ordinary_inference'] == {'allowed': False, 'code': 'QUALIFIED_RELEASE_REQUIRED'} and inf['role_may_request'] is False
        for s in SCREENS:  # read-only: no write verbs registered
            assert c.post(f'{base}/screens/{s}', json={}).status_code == 405
