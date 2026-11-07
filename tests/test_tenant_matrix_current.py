"""ML-T-TENANT matrix on CURRENT source (retained migration chain 003..020 incl. 017 privacy fence and 018-020).

Two workspaces, each with owner/researcher/reviewer/viewer accounts and real objects (frozen real version, samples,
runs, plans, drafts, proposals, events, a verified synthetic evidence run). Every workspace-scoped operation of the
real OpenAPI document is enumerated programmatically and probed with the other tenant's session. Everything runs
through the real FastAPI app, the real nonowner request principal `fieldwork_api` under forced RLS and the real
scoped worker capabilities; no component under test is mocked.
"""
import concurrent.futures, itertools, json, re, uuid
from contextlib import ExitStack
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from tests.chain_support import chain, make_account, login, real_worker, worker_scope, ORIGIN, PASSWORD  # noqa: F401
from tests.leak_world import build_world, HOLDOUT_TAG
from tests.test_postfix_evidence import accepted_fixture

STATE = {}
ROLES = ('owner', 'researcher', 'reviewer', 'viewer')


def operations(app):
    out = []
    for path, methods in app.openapi()['paths'].items():
        if '{workspace_id}' in path:
            for method, op in methods.items():
                if method in ('get', 'post', 'put', 'delete', 'patch'):
                    out.append((method.upper(), path, op))
    return out


@pytest.fixture(scope='module')
def world(chain, tmp_path_factory):
    import fieldwork.api as api
    from fieldwork.real_run_profile import training_config, RECIPE_DIGEST, PREPROCESS_DIGEST
    tag = uuid.uuid4().hex[:8]
    W = {'tag': tag, 'A': {}, 'B': {}, 'C': {}}
    for key in ('A', 'B'):
        ws = str(uuid.uuid4())
        w = W[key] = build_world(chain, ws, prefix='t' + key.lower())
        w['accounts'] = {role: f'{key.lower()}-{role}-{tag}' for role in ROLES}
        for role, name in w['accounts'].items():
            make_account(chain, name, role, ws)
        cfg = training_config(version_id=w['version_id'], version_revision=4, version_digest=w['manifest']['digest'],
                              workspace=ws, dataset_id=w['rights_dataset'], actor=w['accounts']['researcher'],
                              recipe_digest=RECIPE_DIGEST, preprocess_digest=PREPROCESS_DIGEST,
                              decoder_image_id='sha256:' + 'a' * 64, model_image_id='sha256:' + 'b' * 64, epochs=1,
                              batch_size=8, learning_rate='0.001', weight_decay='0.0001', seed=3, idempotency_key='t-' + key)
        w['real_run'] = chain.dba.submit(ws, w['accounts']['researcher'], 't-' + key, cfg)['id']
        w['syn_run'] = chain.dba.submit(ws, w['accounts']['researcher'], 't-syn-' + key,
                                        {'epochs': 1, 'scope': 'synthetic-execution-only'})['id']
        w['intake_id'] = str(uuid.uuid4())
        with chain.dba.connect() as c:
            c.execute('''INSERT INTO fw_real_intake_queue(workspace,intake_id,actor,rights_dataset_id,archive_path,archive_sha256,archive_bytes)
                VALUES(%s,%s,%s,%s,'q.archive',%s,5)''', (ws, w['intake_id'], w['accounts']['researcher'], w['rights_dataset'], uuid.uuid4().hex * 2))
            w['plan_id'] = str(uuid.uuid4())
            c.execute('''INSERT INTO fw_holdout_plans(workspace,plan_id,version_id,version_digest,population_digest,population_count,
                candidate_model_digest,candidate_checkpoint_digest,evaluator,usefulness_spec_sha256,steward,state)
                VALUES(%s,%s,%s,%s,%s,10,%s,%s,'e',repeat('5',64),'nobody','authorized')''',
                      (ws, w['plan_id'], w['version_id'], w['manifest']['digest'], w['population_digest'], 'c' * 64, 'd' * 64))
    W['accounts_all'] = {}
    a_run, folder = accepted_fixture(chain.dba, Path(chain.runs), W['A']['workspace'])
    W['A']['evidence_run'] = a_run['id']
    with ExitStack() as stack:
        clients = {}
        for key in ('A', 'B'):
            for role in ROLES:
                client = stack.enter_context(TestClient(api.app))
                clients[(key, role)] = (client, login(client, W[key]['accounts'][role]))
        anon = stack.enter_context(TestClient(api.app))
        clients['anon'] = (anon, {})
        W['clients'] = clients
        # A draft synthetic version + proposal in A, created through the real routes.
        ca, ha = clients[('A', 'researcher')]
        a_ws = W['A']['workspace']
        draft = ca.post(f'/api/v1/workspaces/{a_ws}/versions', headers=ha, json={})
        assert draft.status_code == 201, draft.text
        W['A']['draft_id'] = draft.json()['id']
        prop = ca.post(f"/api/v1/workspaces/{a_ws}/versions/{draft.json()['id']}/proposals",
                       headers={**ha, 'If-Match': str(draft.json()['revision'])},
                       json={'sample_id': 'SYN-0-0', 'label': 1, 'reason': 'tenant matrix probe proposal'})
        assert prop.status_code == 201, prop.text
        W['A']['proposal_id'] = prop.json()['id']
        yield W


def C(world, key, role='researcher'):
    return world['clients'][(key, role)] if key in ('A', 'B') else world['clients'][key]


def ws(world, key):
    return world[key]['workspace']


def ids_for(world, key):
    w = world[key]
    return {'run_id': [w['real_run'], w['syn_run']], 'version_id': [w['version_id'], w['draft_id'] if 'draft_id' in w else str(uuid.uuid4())],
            'sample_id': [w['holdout'][0]['id'], w['train_val'][0]['id'], 'SYN-0-0'], 'bundle_id': [w['real_run'], w['syn_run']],
            'plan_id': [w['plan_id']], 'intake_id': [w['intake_id']], 'dataset_id': [w['rights_dataset']],
            'proposal_id': [w.get('proposal_id', str(uuid.uuid4()))], 'release_id': ['flowers-r5-small-residual-v1'],
            'input_id': [str(uuid.uuid4())], 'member_name': [w['accounts']['researcher']], 'purpose': ['model_bundle'],
            'workspace_id': [w['workspace']]}


def body_for(path):
    uid = str(uuid.uuid4())
    table = [
        ('/runs/{run_id}/cancel', {'expected_revision': 1, 'reason': 'tenant probe'}),
        ('/runs/{run_id}/resume', {'replay_epoch': 1}),
        ('/runs/{run_id}/flags', {'expected_revision': 1, 'actual': 0, 'predicted': 1, 'bucket': 'cell', 'slice_digest': 'a' * 64,
                                  'evaluation_digest': 'b' * 64, 'reason': 'tenant probe reason'}),
        ('/proposals/{proposal_id}/review', {'digest': 'a' * 64, 'approve': True, 'reason': 'tenant probe review'}),
        ('/versions/{version_id}/proposals', {'sample_id': 'SYN-0-0', 'label': 1, 'reason': 'tenant probe proposal'}),
        ('/versions/{version_id}/review', {'digest': 'a' * 64, 'reason': 'tenant probe review'}),
        ('/versions/{version_id}/freeze', {}),
        ('/real/versions/{version_id}/split-plan', {'revision': 1}),
        ('/real/versions/{version_id}/freeze', {'revision': 1}),
        ('/real/holdout/plans/{plan_id}/invalidate', {'reason': 'tenant probe invalidation'}),
        ('/real/runs/{run_id}/cancel', {'expected_revision': 1, 'reason': 'tenant probe'}),
        ('/real/runs/{run_id}/resume', {'replay_epoch': 1}),
        ('/real/versions', {'intake_id': uid}),
        ('/real/holdout/plans', {'version_id': 'x', 'version_digest': 'a' * 64, 'population_digest': 'a' * 64, 'population_count': 1,
                                 'population_tag': 't', 'candidate_model_digest': 'a' * 64, 'candidate_checkpoint_digest': 'a' * 64,
                                 'evaluator': 'e', 'usefulness_spec_sha256': 'a' * 64}),
        ('/real/runs', {'version_id': 'x', 'version_revision': 1}),
        ('/real/inferences', {'run_id': 'x', 'sample_id': 'y'}),
        ('/real/settings/members/{member_name}', {'role': 'viewer'}),
        ('/real/privacy/', {'legal_hold': True, 'pinned': True, 'reason_code': 'rights_review'}),
    ]
    for suffix, body in table:
        if path.endswith(suffix) or (suffix.endswith('/') and suffix in path):
            return body
    return {}


def fill(path, params, combo):
    url = path
    for p, v in zip(params, combo):
        url = url.replace('{' + p['name'] + '}', str(v))
    return url


def request(client, method, url, headers, path, **kw):
    h = {**headers, 'Idempotency-Key': str(uuid.uuid4()), 'If-Match': '"1"'} if method != 'GET' else dict(headers)
    q = {}
    if method == 'GET' and '/rights/preflight' in path:
        q = {'purpose': 'model_bundle'}
    if '/real/intakes' in path and method == 'POST':
        q = {'dataset_id': str(uuid.uuid4())}
    if '/rights/{purpose}' in path:
        q = {'member_id': 'x'}
    if path.endswith('/real/holdout/plans') and method == 'GET':
        q = {'version_id': 'x'}
    if path.endswith('/slices'):
        q = {'actual': 0, 'predicted': 0}
    if 'validation/slices' in path:
        q = {'actual': 0, 'predicted': 0}
    if method == 'GET' and path.endswith('/events/stream'):
        q = {'replay_only': 'true'}
    if method == 'GET':
        return client.get(url, headers=h, params=q)
    return client.request(method, url, headers=h, json=body_for(path), params=q)


# --------------------------------------------------------------------------------------------- membership 404 matrix
def test_enumerated_operation_count(chain):
    ops = operations(chain.api.app)
    assert len(ops) >= 60
    STATE['operations'] = len(ops)
    STATE['methods'] = sorted({m for m, _, _ in ops})


def test_other_tenant_session_gets_identical_404_on_every_operation_even_vs_unknown_workspace(world, chain):
    """B's session against A's workspace path: 404 for EVERY operation, byte-identical to a workspace that does not
    exist (no existence leak), for two roles of B (researcher, viewer: the full-role sweep exhausts the host's ephemeral ports)."""
    ops = operations(chain.api.app)
    count = 0
    for role in ('researcher', 'viewer'):
        client, headers = C(world, 'B', role)
        for method, path, op in ops:
            params = [p for p in op.get('parameters', []) if p['in'] == 'path' and p['name'] != 'workspace_id']
            choices = [ids_for(world, 'A').get(p['name'], [str(uuid.uuid4())])[:2] for p in params]
            for combo in itertools.product(*choices):
                real = request(client, method, fill(path, [{'name': 'workspace_id'}] + params, (ws(world, 'A'), *combo)), headers, path)
                ghost = request(client, method, fill(path, [{'name': 'workspace_id'}] + params, (str(uuid.uuid4()), *combo)), headers, path)
                assert real.status_code == 404 == ghost.status_code, (role, method, path, real.status_code, real.text[:120])
                assert real.json() == ghost.json() == {'detail': 'OBJECT_OR_MEMBERSHIP'}, (role, method, path)
                count += 2
    STATE['membership_probes'] = count
    assert count >= 300


def test_unauthenticated_requests_get_401_everywhere_and_no_read_without_session(world, chain):
    client, _ = C(world, 'anon')
    count = 0
    for method, path, op in operations(chain.api.app):
        params = [p for p in op.get('parameters', []) if p['in'] == 'path']
        combo = [ws(world, 'A') if p['name'] == 'workspace_id' else str(uuid.uuid4()) for p in params]
        r = request(client, method, fill(path, params, combo), {}, path)
        assert r.status_code == 401 and r.json() == {'detail': 'SESSION'}, (method, path, r.status_code)
        count += 1
    STATE['anon_probes'] = count


# --------------------------------------------------------------------------------------------- object swap / no writes
def _state_fingerprint(chain, workspace):
    with chain.dba.connect() as c:
        out = {}
        for table, key in [('fw_runs', 'id'), ('fw_versions', 'id'), ('fw_proposals', 'id'), ('fw_holdout_plans', 'plan_id'),
                           ('fw_real_intake_queue', 'intake_id'), ('fw_samples', 'sample_id'), ('fw_events', 'seq'),
                           ('fw_accounts', 'name')]:
            out[table] = c.execute(f'SELECT count(*) AS n, md5(string_agg(t::text, \'|\' ORDER BY t::text)) AS h FROM {table} t WHERE workspace=%s',
                                   (workspace,)).fetchone()
        return {k: (v['n'], v['h']) for k, v in out.items()}


def test_own_path_with_other_tenant_object_ids_is_indistinguishable_from_absent_and_writes_nothing(world, chain):
    ops = operations(chain.api.app)
    before = _state_fingerprint(chain, ws(world, 'A'))
    skip_write = ('workspace-deletion',)  # no object id: covered by the membership matrix
    count = 0
    for role in ('researcher', 'owner'):
        client, headers = C(world, 'B', role)
        for method, path, op in ops:
            if any(s in path for s in skip_write):
                continue
            params = [p for p in op.get('parameters', []) if p['in'] == 'path' and p['name'] != 'workspace_id']
            if not params:
                continue
            choices = [ids_for(world, 'A')[p['name']] if p['name'] in ids_for(world, 'A') else [str(uuid.uuid4())] for p in params]
            for combo in itertools.product(*choices):
                a_obj = request(client, method, fill(path, [{'name': 'workspace_id'}] + params, (ws(world, 'B'), *combo)), headers, path)
                ghost_combo = tuple(str(uuid.uuid4()) if len(c) > 12 else c for c in combo)
                ghost = request(client, method, fill(path, [{'name': 'workspace_id'}] + params, (ws(world, 'B'), *ghost_combo)), headers, path)
                assert a_obj.status_code < 500 and ghost.status_code < 500, (method, path, a_obj.text[:150])
                # Same status and same body as an absent object: A's object existence cannot be inferred.
                assert _norm(a_obj) == _norm(ghost) or _only_echo_differs(a_obj, ghost), \
                    (role, method, path, a_obj.status_code, a_obj.text[:160], ghost.status_code, ghost.text[:160])
                for secret in (*ids_for(world, 'A')['run_id'], world['A']['version_id'], world['A']['plan_id']):
                    assert secret not in a_obj.text.replace(combo[0] if combo else '', '') or secret in str(combo), (method, path)
                count += 1
    after = _state_fingerprint(chain, ws(world, 'A'))
    assert before == after, 'cross-tenant write detected'
    STATE['object_probes'] = count
    assert count >= 100


def _norm(r):
    """Status + body with the per-response random correlation id removed."""
    try:
        body = r.json()
    except ValueError:
        return r.status_code, r.text
    if isinstance(body, dict):
        body = {k: v for k, v in body.items() if k != 'correlation_id'}
    return r.status_code, body


def _only_echo_differs(a, b):
    """Validation errors echo the caller's own path input; compare shape without the echoed value."""
    if a.status_code != b.status_code or a.status_code != 422:
        return False
    def shape(r):
        return [(e.get('type'), tuple(e.get('loc', ()))) for e in r.json().get('detail', [])]
    return shape(a) == shape(b)


def test_read_routes_for_other_tenants_objects_are_404_with_absent_identical_bodies(world, chain):
    client, headers = C(world, 'B', 'researcher')
    a, b_ws = world['A'], ws(world, 'B')
    probes = [f"/runs/{a['syn_run']}", f"/runs/{a['syn_run']}/evaluation", f"/runs/{a['syn_run']}/records",
              f"/runs/{a['syn_run']}/slices?actual=0&predicted=0", f"/runs/{a['syn_run']}/artifacts", f"/runs/{a['syn_run']}/flags",
              f"/runs/{a['evidence_run']}", f"/runs/{a['evidence_run']}/evaluation", f"/runs/{a['evidence_run']}/records",
              f"/runs/{a['evidence_run']}/slices?actual=0&predicted=0", f"/runs/{a['evidence_run']}/artifacts",
              f"/versions/{a['version_id']}", f"/versions/{a['draft_id']}", f"/bundles/{a['evidence_run']}/download",
              f"/real/runs/{a['real_run']}", f"/real/intakes/{a['intake_id']}", f"/screens/runs/{a['syn_run']}/lineage",
              f"/real/runs/{a['real_run']}/validation", f"/real/runs/{a['real_run']}/bundle", f"/real/runs/{a['real_run']}/bundle/download",
              f"/real/samples/{a['holdout'][0]['id']}/media", f"/real/samples/{a['train_val'][0]['id']}/media"]
    for suffix in probes:
        r = client.get(f'/api/v1/workspaces/{b_ws}{suffix}', headers=headers)
        g = client.get(f'/api/v1/workspaces/{b_ws}' + re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|' + re.escape(a['version_id']), str(uuid.uuid4()), suffix), headers=headers)
        assert r.status_code == g.status_code, (suffix, r.status_code, r.text, g.status_code, g.text)
        assert r.status_code in (403, 404, 409) and r.status_code != 200, (suffix, r.status_code)
        assert _norm(r) == _norm(g) or r.status_code == 422, (suffix, r.text, g.text)
        if 'bundle' in suffix and 'download' in suffix and 'real' not in suffix:
            continue
    STATE['read_object_probes'] = len(probes)


# --------------------------------------------------------------------------------------------- streams and feeds
def test_streams_polling_and_snapshot_never_cross_tenants(world):
    client_b, hb = C(world, 'B', 'researcher')
    client_a, ha = C(world, 'A', 'researcher')
    a_ids = {world['A']['real_run'], world['A']['syn_run'], world['A']['evidence_run']}
    b_ws, a_ws = ws(world, 'B'), ws(world, 'A')
    for path in ('/events?after=0', '/events/stream?replay_only=true', '/snapshot', '/screens/operations', '/versions',
                 '/real/runs', '/real/intakes', '/qualified-releases'):
        own = client_b.get(f'/api/v1/workspaces/{b_ws}{path}', headers=hb)
        assert own.status_code == 200, (path, own.status_code)
        assert not [i for i in a_ids if i in own.text] and world['A']['version_id'] not in own.text and world['A']['holdout'][0]['id'] not in own.text
        cross = client_b.get(f'/api/v1/workspaces/{a_ws}{path}', headers=hb)
        assert cross.status_code == 404
        assert client_a.get(f'/api/v1/workspaces/{a_ws}{path}', headers=ha).status_code == 200
    for cursor in ('0', '1', '999999999'):
        r = client_b.get(f'/api/v1/workspaces/{a_ws}/events/stream?replay_only=true', headers={**hb, 'Last-Event-ID': cursor})
        assert r.status_code == 404 and r.json() == {'detail': 'OBJECT_OR_MEMBERSHIP'}
    # A's cursor replayed on B's own stream yields only B's events.
    seq_a = client_a.get(f'/api/v1/workspaces/{a_ws}/events?after=0', headers=ha).json()['items']
    b_stream = client_b.get(f'/api/v1/workspaces/{b_ws}/events/stream?replay_only=true', headers={**hb, 'Last-Event-ID': '0'})
    assert b_stream.status_code in (200, 410) and not [i for i in a_ids if i in b_stream.text]
    assert seq_a


def test_downloads_exports_and_media_are_scoped(world):
    client_b, hb = C(world, 'B', 'owner')
    a = world['A']
    for suffix in (f"/runs/{a['evidence_run']}/records", f"/bundles/{a['evidence_run']}/download",
                   f"/real/runs/{a['real_run']}/bundle/download", f"/qualified-releases/flowers-r5-small-residual-v1/download",
                   f"/real/support-diagnostics"):
        cross = client_b.get(f"/api/v1/workspaces/{ws(world, 'A')}{suffix}", headers=hb)
        assert cross.status_code == 404
    diag = client_b.get(f"/api/v1/workspaces/{ws(world, 'B')}/real/support-diagnostics", headers=hb)
    assert diag.status_code == 200
    assert a['real_run'] not in diag.text and ws(world, 'A') not in diag.text and a['holdout'][0]['id'] not in diag.text


# --------------------------------------------------------------------------------------------- CSRF / role / known 403
def test_every_write_route_rejects_missing_wrong_or_foreign_csrf_and_origin(world, chain):
    client, headers = C(world, 'A', 'researcher')
    other_client, other_headers = C(world, 'A', 'owner')
    a_ws = ws(world, 'A')
    count = 0
    for method, path, op in operations(chain.api.app):
        if method == 'GET':
            continue
        params = [p for p in op.get('parameters', []) if p['in'] == 'path']
        combo = [a_ws if p['name'] == 'workspace_id' else ids_for(world, 'A').get(p['name'], [str(uuid.uuid4())])[0] for p in params]
        url = fill(path, params, combo)
        cases = {'no_token_no_origin': {}, 'origin_only': {'Origin': ORIGIN},
                 'token_only': {'X-CSRF-Token': headers['X-CSRF-Token']},
                 'evil_origin': {**headers, 'Origin': 'https://evil.invalid'},
                 'wrong_token': {'Origin': ORIGIN, 'X-CSRF-Token': 'x' * 43},
                 'other_sessions_token': {'Origin': ORIGIN, 'X-CSRF-Token': other_headers['X-CSRF-Token']}}
        for name, h in cases.items():
            r = request(client, method, url, h, path)
            if 'rights/{purpose}' in path or path.endswith('/real/intakes'):
                pass
            assert r.status_code == 403, (name, method, path, r.status_code, r.text[:120])
            count += 1
    STATE['csrf_probes'] = count
    assert count >= 150


def test_role_matrix_known_forbidden_actions_are_403(world, chain):
    a_ws = ws(world, 'A')
    viewer, vh = C(world, 'A', 'viewer')
    count = 0
    for method, path, op in operations(chain.api.app):
        if method == 'GET':
            continue
        params = [p for p in op.get('parameters', []) if p['in'] == 'path']
        combo = [a_ws if p['name'] == 'workspace_id' else ids_for(world, 'A').get(p['name'], [str(uuid.uuid4())])[0] for p in params]
        r = request(viewer, method, fill(path, params, combo), vh, path)
        assert r.status_code == 403, ('viewer', method, path, r.status_code, r.text[:100])
        count += 1
    STATE['viewer_write_probes'] = count
    # Researcher/reviewer on owner-only and steward-only controls; reviewer cannot submit runs.
    for who, method, suffix, expect in [
            ('researcher', 'PUT', '/real/settings', 'OWNER_REQUIRED'), ('researcher', 'POST', '/real/workspace-deletion', 'OWNER_REQUIRED'),
            ('reviewer', 'PUT', f"/real/settings/members/{world['A']['accounts']['viewer']}", 'OWNER_REQUIRED'),
            ('owner', 'POST', '/real/holdout/plans', 'HOLDOUT_STEWARD_REQUIRED'), ('reviewer', 'POST', '/runs', 'ROLE'),
            ('reviewer', 'POST', '/versions', 'ROLE'), ('researcher', 'POST', f"/proposals/{world['A']['proposal_id']}/review", 'ROLE')]:
        c, h = C(world, 'A', who)
        r = request(c, method, f'/api/v1/workspaces/{a_ws}{suffix}', h, suffix)
        assert r.status_code == 403 and r.json()['detail'] == expect, (who, suffix, r.status_code, r.text)


# --------------------------------------------------------------------------------------------- revocation
def test_session_revocation_matrix(world, chain):
    import fieldwork.api as api
    tag = uuid.uuid4().hex[:6]
    a_ws = ws(world, 'A')
    results = {}
    def fresh(name, role='researcher', workspace=a_ws):
        make_account(chain, name, role, workspace)
        c = TestClient(chain.api.app); c.__enter__()
        h = login(c, name)
        assert c.get(f'/api/v1/workspaces/{workspace}/snapshot', headers=h).status_code == 200
        return c, h, name
    labels = ['moved_workspace', 'role_changed', 'session_expired', 'idle_timeout', 'session_row_deleted']
    for label in labels:
        name = f'rev-{label}-{tag}'.replace('_', '-')
        c, h, n = fresh(name)
        with chain.dba.connect() as db:
            sql = {'moved_workspace': ("UPDATE fw_accounts SET workspace=%s WHERE name=%s", ('moved-' + tag, n)),
                   'role_changed': ("UPDATE fw_accounts SET role='viewer' WHERE name=%s", (n,)),
                   'session_expired': ("UPDATE fw_sessions SET expires=clock_timestamp()-interval '1 second' WHERE name=%s", (n,)),
                   'idle_timeout': ("UPDATE fw_sessions SET last_seen=clock_timestamp()-interval '31 minutes' WHERE name=%s", (n,)),
                   'session_row_deleted': ("DELETE FROM fw_sessions WHERE name=%s", (n,))}[label]
            db.execute(*sql)
        for path in ('/auth/session', f'/api/v1/workspaces/{a_ws}/snapshot', f'/api/v1/workspaces/{a_ws}/events/stream?replay_only=true'):
            assert c.get(path, headers=h).status_code == 401, (label, path)
        r = c.post(f'/api/v1/workspaces/{a_ws}/runs', json={'epochs': 1}, headers={**h, 'Idempotency-Key': str(uuid.uuid4())})
        assert r.status_code == 401, (label, r.status_code)
        results[label] = 401
        c.__exit__(None, None, None)
    # Logout then reuse of the old cookie and token.
    c, h, n = fresh(f'rev-logout-{tag}')
    cookie = c.cookies.get('fieldwork_session')
    assert c.post('/auth/logout', headers=h).status_code == 200
    assert TestClient(chain.api.app).get('/auth/session', headers={'Cookie': 'fieldwork_session=' + cookie}).status_code == 401
    results['logout'] = 401
    c.__exit__(None, None, None)
    # Real membership change by an owner through the real route revokes the member's live session.
    victim, vh, vname = fresh(f'rev-member-{tag}')
    oc, oh = C(world, 'A', 'owner')
    r = oc.put(f'/api/v1/workspaces/{a_ws}/real/settings/members/{vname}', headers=oh, json={'role': 'viewer'})
    assert r.status_code == 200 and r.json()['sessions_revoked'] is True, r.text
    assert victim.get('/auth/session', headers=vh).status_code == 401
    results['owner_changes_role_via_api'] = 401
    victim.__exit__(None, None, None)
    # Privacy workspace tombstone (migration 017 fence) revokes sessions and blocks login; the cached fence memo in
    # api.session() only skips the to_regprocedure lookup, the tombstone predicate still runs on every request.
    tomb = f'tomb-{tag}'
    make_account(chain, f'tomb-user-{tag}', 'researcher', tomb)
    tc = TestClient(chain.api.app); tc.__enter__()
    th = login(tc, f'tomb-user-{tag}')
    assert tc.get(f'/api/v1/workspaces/{tomb}/snapshot', headers=th).status_code == 200
    assert chain.api._PRIVACY_FENCE_SEEN is not None  # positive memo is primed
    with chain.dba.connect() as db:
        db.execute('''INSERT INTO fw_privacy_workspace_tombstones(workspace,request_id,requested_by,expected_settings_revision,deleted_utc,archive_due_utc)
            VALUES(%s,%s,'tenant-matrix',1,now(),now()+interval '7 days')''', (tomb, str(uuid.uuid4())))
        db.execute("UPDATE fw_privacy_workspace_tombstones SET deleted_utc=deleted_utc WHERE workspace=%s", (tomb,))
    assert tc.get(f'/api/v1/workspaces/{tomb}/snapshot', headers=th).status_code == 401
    assert TestClient(chain.api.app).post('/auth/session', json={'name': f'tomb-user-{tag}', 'password': PASSWORD}).status_code == 403
    results['workspace_tombstone'] = 401
    tc.__exit__(None, None, None)
    # The tombstone is per workspace: the other tenants keep working with the memo primed.
    assert C(world, 'A', 'researcher')[0].get(f'/api/v1/workspaces/{a_ws}/snapshot').status_code == 200
    assert C(world, 'B', 'researcher')[0].get(f"/api/v1/workspaces/{ws(world, 'B')}/snapshot").status_code == 200
    STATE['revocations'] = results
    assert len(results) == 8


# --------------------------------------------------------------------------------------------- pooled RLS / principal
def test_request_principal_is_not_owner_superuser_or_bypassrls(world, chain):
    with psycopg.connect(chain.request.dsn, row_factory=dict_row) as c:
        who = c.execute('SELECT session_user AS su, current_user AS cu').fetchone()
        flags = c.execute('SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=session_user').fetchone()
        owned = c.execute('''SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r'
            AND pg_get_userbyid(relowner)=session_user''').fetchall()
        members = c.execute('''SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=session_user''').fetchall()
    assert who['su'] == who['cu'] == 'fieldwork_api'
    assert not any(flags.values()) and owned == [] and members == []
    # The pooled/serving store of the app is that same principal (no operator DSN reachable from the app object).
    assert 'fieldwork_api' in chain.api.store.dsn and chain.api.store.is_request is True


def test_every_tenant_table_is_rls_enabled_and_foreign_context_sees_nothing(world, chain):
    A, B = ws(world, 'A'), ws(world, 'B')
    with chain.dba.connect() as c:
        rows = c.execute('''SELECT c.relname, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced,
              (has_table_privilege('fieldwork_api', c.oid, 'SELECT') OR has_table_privilege('fieldwork_api', c.oid, 'INSERT')
               OR has_table_privilege('fieldwork_api', c.oid, 'UPDATE') OR has_table_privilege('fieldwork_api', c.oid, 'DELETE')) AS api_access,
              has_table_privilege('fieldwork_api', c.oid, 'SELECT') AS api_select
            FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind='r'
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='workspace' AND NOT a.attisdropped)
            ORDER BY 1''').fetchall()
    tables = {r['relname']: r for r in rows}
    assert len(tables) >= 25
    # Any tenant table the request principal can touch must have RLS enabled; fw_accounts is the global login
    # directory (looked up by name before any workspace is known) and is the one documented exception.
    no_rls = sorted(t for t, r in tables.items() if r['api_access'] and not r['rls'])
    assert no_rls == ['fw_accounts'], no_rls
    # FORCE only matters to the table owner; the request principal owns none (asserted separately). Record the rest.
    not_forced = sorted(t for t, r in tables.items() if r['api_access'] and r['rls'] and not r['forced'])
    checked = 0
    with psycopg.connect(chain.request.dsn, row_factory=dict_row) as c:
        for table, meta in tables.items():
            if table == 'fw_accounts' or not meta['api_select']:
                continue
            for ctx, other in ((A, B), (B, A), ('', A), ('nonexistent', A)):
                with c.transaction():
                    c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (ctx,))
                    found = c.execute(f'SELECT DISTINCT workspace FROM public.{table}').fetchall()
                assert {r['workspace'] for r in found} <= {ctx}, (table, ctx, found)
                assert other not in {r['workspace'] for r in found}
                checked += 1
            c.commit()
    STATE['rls_tables'] = len(tables)
    STATE['rls_checks'] = checked
    STATE['rls_not_forced'] = not_forced
    STATE['rls_no_api_access'] = sorted(t for t, r in tables.items() if not r['api_access'])


def test_pooled_connection_context_is_transaction_local_and_never_reused_across_tenants(world, chain):
    A, B = ws(world, 'A'), ws(world, 'B')
    seen = []
    with psycopg.connect(chain.request.dsn, row_factory=dict_row) as c:  # ONE connection reused like a pool slot
        for i in range(60):
            ctx = A if i % 2 == 0 else B
            with c.transaction():
                c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (ctx,))
                rows = {r['workspace'] for r in c.execute('SELECT workspace FROM fw_runs').fetchall()}
                assert rows == {ctx}
            c.commit()  # a pooled connection returns to the pool between requests
            # Between tenants the setting is empty again, never the previous tenant's value.
            assert c.execute("SELECT current_setting('fieldwork.workspace',true) AS g").fetchone()['g'] in ('', None)
            assert c.execute('SELECT count(*) AS n FROM fw_runs').fetchone()['n'] == 0
            c.commit()
            seen.append(ctx)
        # A session-level (non-local) context is the pooling hazard: the app never uses it, and even then B-after-A
        # needs an explicit new set_config; with none the previous value would persist -> prove why `true` is required.
        c.execute("SELECT set_config('fieldwork.workspace',%s,false)", (A,))
        assert c.execute('SELECT count(*) AS n FROM fw_runs').fetchone()['n'] > 0
        c.execute("RESET fieldwork.workspace")
        assert c.execute('SELECT count(*) AS n FROM fw_runs').fetchone()['n'] == 0
        c.commit()
    # The app's own connection factory: contextvar per request, set with is_local=true on every connect().
    from fieldwork.store import TENANT
    for i in range(40):
        ctx = A if i % 2 == 0 else B
        token = TENANT.set(ctx)
        try:
            with chain.api.store.connect() as sc:
                rows = {r['workspace'] for r in sc.execute('SELECT workspace FROM fw_runs').fetchall()}
        finally:
            TENANT.reset(token)
        assert rows == {ctx}
    token = TENANT.set('')
    try:
        with chain.api.store.connect() as sc:
            assert sc.execute('SELECT count(*) AS n FROM fw_runs').fetchone()['n'] == 0
    finally:
        TENANT.reset(token)
    STATE['pool_cycles'] = len(seen)


def test_interleaved_concurrent_requests_of_both_tenants_never_see_each_others_rows(world, chain):
    A, B = ws(world, 'A'), ws(world, 'B')
    ca, ha = C(world, 'A', 'researcher')
    cb, hb = C(world, 'B', 'researcher')
    a_secret = {world['A']['real_run'], world['A']['syn_run'], world['A']['version_id']}
    b_secret = {world['B']['real_run'], world['B']['syn_run'], world['B']['version_id']}
    def probe(i):
        c, h, w, mine, other = (ca, ha, A, a_secret, b_secret) if i % 2 == 0 else (cb, hb, B, b_secret, a_secret)
        out = []
        for path in ('/snapshot', '/versions', '/events?after=0', '/real/runs', '/screens/operations'):
            r = c.get(f'/api/v1/workspaces/{w}{path}', headers=h)
            out.append(r.status_code == 200 and not any(s in r.text for s in other))
        return all(out)
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        assert all(ex.map(probe, range(96)))
    STATE['concurrent_requests'] = 96 * 5


# --------------------------------------------------------------------------------------------- worker authority
def test_scoped_worker_cannot_choose_another_workspaces_run_or_reuse_credentials(world, chain, tmp_path):
    from fieldwork.store import Conflict
    A, B = ws(world, 'A'), ws(world, 'B')
    w = real_worker(chain, tmp_path, [A])
    rid_a, rid_b = world['A']['real_run'], world['B']['real_run']
    # Discovery: only the scoped workspace's queue is visible.
    assert w.next_real_run()['id'] == rid_a
    assert w.get(rid_b) is None and w.get(world['B']['syn_run']) is None
    with pytest.raises(Conflict):
        w.claim_real(rid_b, start=False, worker_id='probe')
    with pytest.raises(Conflict):
        w.claim(world['B']['syn_run'], 0, start=False, worker_id='probe')
    run = w.claim_real(rid_a, start=True, worker_id='tenant-matrix')
    scope = (run['attempt'], run['fence'], run['cancel_generation'], run['restore_generation'])
    assert w.real_inputs(rid_a, *scope)['samples']
    # The credential is bound to (run, attempt): it cannot be replayed on any other run, in any workspace.
    token = w._tokens[run['attempt']]
    for other in (rid_b, world['A']['syn_run'], world['B']['syn_run'], str(uuid.uuid4())):
        with pytest.raises(Conflict):
            w.real_inputs(other, *scope)
        with pytest.raises(Conflict):
            w.heartbeat(other, run['fence'], run['cancel_generation'], attempt=run['attempt'], restore_generation=run['restore_generation'])
        with pytest.raises(Conflict):
            w.real_member_rights(other, *scope, world['B']['train_val'][0]['id'])
    # B's sample ids are not reachable through A's run either.
    with pytest.raises(Conflict):
        w.real_member_rights(rid_a, *scope, world['B']['train_val'][0]['id'])
    # Direct SQL: the login has no table privilege; the scoped GUC cannot widen the capability.
    with w.connect() as c:
        for table in ('fw_runs', 'fw_events', 'fw_versions', 'fw_samples', 'fw_holdout_plans', 'fw_accounts', 'fw_sessions'):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute(f'SELECT 1 FROM public.{table} LIMIT 1')
        c.execute("SELECT set_config('fieldwork.workspace',%s,false)", (B,))
        assert c.execute('SELECT fw_worker_cap_v1.get_run(%s) v', (rid_b,)).fetchone()['v'] is None
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with c.transaction():
                c.execute("SELECT fw_worker_cap_v1.check_live('x',%s,'a',1,0,NULL,ARRAY['running'],'F','F')", (rid_b,))
    chain.dba.release_slot(rid_a)
    STATE['worker_foreign_probes'] = 20


def test_summary(world):
    for key in ('membership_probes', 'anon_probes', 'object_probes', 'csrf_probes'):
        assert STATE.get(key, 0) > 0, key


def test_write_state_summary(world):
    import json as _json
    from fieldwork.store import ROOT
    out = Path(ROOT) / 'var' / 'matrix-state-tenant.json'
    out.parent.mkdir(exist_ok=True)
    out.write_text(_json.dumps(STATE, default=str))
