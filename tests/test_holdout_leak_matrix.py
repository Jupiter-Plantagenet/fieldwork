"""ML-T-HOLDOUT leak matrix (frozen condition in portfolio-engineering/ACCEPTANCE-REGISTER.csv).

A researcher tries to enumerate the sealed holdout through media, counts, version/manifest views, search/filter
parameters, validation exports, worker requests and the event feeds, while a *simulated AI steward* (an operator-
assigned account bound to a trusted reviewer key; no human steward is claimed) authorizes and consumes the plan.

Every case drives the REAL code path: the real FastAPI app (all routers), the real nonowner request principal
`fieldwork_api` under forced RLS, the retained migration chain 003..020, the real scoped worker capability and the
real holdout module. Holdout members are sentinel strings; any appearance of an id, raw/pixel digest, source
name, group, media path or perceptual hash in any response body or header fails the test.
"""
import itertools, json, re, uuid
from contextlib import ExitStack
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.chain_support import chain, make_account, login, real_worker, ORIGIN  # noqa: F401  (chain is a fixture)
from tests.leak_world import build_world, HOLDOUT_TAG
from tests.test_postfix_evidence import accepted_fixture

STATE = {}


def blob(response):
    return response.text + '\n' + '\n'.join(f'{k}: {v}' for k, v in response.headers.items())


def assert_clean(response, sentinels, where=''):
    text = blob(response)
    hit = [s for s in sentinels if s in text]
    assert not hit, f'{where} leaked {len(hit)} protected value(s) (status {response.status_code})'
    assert response.status_code < 500, f'{where} server error {response.status_code}: {response.text[:200]}'


def absent_shape(response):
    keep = ('content-type', 'cache-control', 'x-content-type-options', 'x-frame-options', 'content-length')
    return response.status_code, response.text, {k: v for k, v in response.headers.items() if k in keep}


@pytest.fixture(scope='module')
def world(chain, tmp_path_factory):
    import fieldwork.api as api
    ws = str(uuid.uuid4())
    W = build_world(chain, ws, prefix='hw')
    tag = uuid.uuid4().hex[:8]
    W['accounts'] = {role: f'{role}-{tag}' for role in ('researcher', 'owner', 'reviewer', 'viewer')}
    W['steward_name'] = f'ai-steward-sim-{tag}'  # simulated AI steward (operator-assigned owner account)
    for role, name in W['accounts'].items():
        make_account(chain, name, role, ws)
    make_account(chain, W['steward_name'], 'owner', ws)
    # Operator-provisioned steward assignment bound to a trusted reviewer key (public registry file, loaded per call).
    reviewer_id, key_id = str(uuid.uuid4()), str(uuid.uuid4())
    registry = tmp_path_factory.mktemp('registry') / 'reviewers.json'
    registry.write_text(json.dumps({'schema': 1, 'reviewers': [{
        'reviewer_id': reviewer_id, 'key_id': key_id, 'public_key_hex': 'ab' * 32, 'workspace_ids': [ws],
        'purposes': ['local_private_training']}]}))
    mp = pytest.MonkeyPatch()
    mp.setenv('FIELDWORK_RIGHTS_REVIEWERS_FILE', str(registry))
    with chain.dba.connect() as c:
        c.execute('INSERT INTO fw_holdout_stewards(workspace,actor,reviewer_id,key_id,assigned_by) VALUES(%s,%s,%s,%s,%s)',
                  (ws, W['steward_name'], reviewer_id, key_id, 'operator'))
    # Synthetic workspace with a verified evidence run (validation-only bundle) for the legacy routes.
    syn = 'hold-syn-' + tag
    make_account(chain, 'syn-researcher-' + tag, 'researcher', syn)
    run, folder = accepted_fixture(chain.dba, Path(chain.runs), syn)
    W.update(syn=syn, syn_run=run['id'], syn_user='syn-researcher-' + tag)
    # A queued real training run bound to the frozen version (server-created config, as the real route would).
    from fieldwork.real_run_profile import training_config, RECIPE_DIGEST, PREPROCESS_DIGEST
    config = training_config(version_id=W['version_id'], version_revision=4, version_digest=W['manifest']['digest'],
                             workspace=ws, dataset_id=W['rights_dataset'], actor=W['accounts']['researcher'],
                             recipe_digest=RECIPE_DIGEST, preprocess_digest=PREPROCESS_DIGEST,
                             decoder_image_id='sha256:' + 'a' * 64, model_image_id='sha256:' + 'b' * 64, epochs=1,
                             batch_size=8, learning_rate='0.001', weight_decay='0.0001', seed=7,
                             idempotency_key='hw-real-run')
    W['real_run'] = chain.dba.submit(ws, W['accounts']['researcher'], 'hw-real-run', config)['id']
    with ExitStack() as stack:
        clients = {}
        for key, name in {**W['accounts'], 'steward': W['steward_name'], 'syn': W['syn_user']}.items():
            client = stack.enter_context(TestClient(api.app))
            clients[key] = (client, login(client, name))
        clients['anon'] = (stack.enter_context(TestClient(api.app)), {})
        W['clients'] = clients
        yield W
    mp.undo()


def C(world, who):
    return world['clients'][who]


def base(world):
    return f"/api/v1/workspaces/{world['workspace']}"


# ------------------------------------------------------------------------------------------------ media
def test_real_media_protected_equals_absent_for_every_role(world):
    """No existence oracle: protected (holdout) and content-alias ids answer exactly like an absent id."""
    absent = {}
    for who in ('researcher', 'owner', 'reviewer', 'viewer', 'steward', 'anon'):
        client, h = C(world, who)
        ref = client.get(f"{base(world)}/real/samples/{uuid.uuid4()}/media")
        assert_clean(ref, world['sentinels'], who + ' absent')
        absent[who] = absent_shape(ref)
        probes = [m['id'] for m in world['holdout']] + [world['alias_id']]
        for sid in probes:
            r = client.get(f"{base(world)}/real/samples/{sid}/media")
            assert_clean(r, world['sentinels'], f'{who} media {sid[:8]}')
            assert absent_shape(r) == absent[who], (who, sid, r.status_code, r.text)
    assert absent['researcher'][0] == 404 and absent['anon'][0] == 401
    # An ordinary, unprotected sample without a current signed decision is a *known* forbidden action: 403.
    client, _ = C(world, 'researcher')
    plain = client.get(f"{base(world)}/real/samples/{world['plain_id']}/media")
    assert plain.status_code == 403 and plain.json() == {'detail': 'MEDIA_RIGHTS_REQUIRED'}
    # Neither a train/validation member nor a pool member of the frozen version leaks pixels without a decision.
    for m in world['train_val'][:2] + world['pool'][:1]:
        r = client.get(f"{base(world)}/real/samples/{m['id']}/media")
        assert r.status_code == 403 and r.headers['content-type'].startswith('application/json')
    STATE['media_probes'] = 6 * 11 + 4


def test_media_probe_with_malformed_ids_does_not_reveal_protected_membership(world):
    client, _ = C(world, 'researcher')
    for sid in ['SYN-0-8', 'not-a-uuid', '..%2f..%2f']:
        r = client.get(f"{base(world)}/real/samples/{sid}/media")
        assert_clean(r, world['sentinels'], 'malformed ' + sid)
        assert r.status_code in (404, 422)
    # Probing with a protected digest/group as the id only echoes the caller's own input in the 422; no row is touched.
    for secret in (world['holdout'][0]['sha256'], world['holdout'][0]['group']):
        r = client.get(f"{base(world)}/real/samples/{secret}/media")
        assert r.status_code == 422 and r.json()['detail'][0]['loc'] == ['path', 'sample_id']


# ------------------------------------------------------------------------------------------------ version/manifest/counts
def test_version_views_exclude_protected_rows_and_audit(world):
    for who in ('researcher', 'viewer', 'steward'):
        client, _ = C(world, who)
        listing = client.get(f"{base(world)}/versions")
        detail = client.get(f"{base(world)}/versions/{world['version_id']}")
        assert listing.status_code == 200 and detail.status_code == 200
        for r in (listing, detail):
            assert_clean(r, world['sentinels'], f'{who} versions')
        manifest = detail.json()['manifest']
        ids = {s['id'] for s in manifest['samples']}
        assert ids.isdisjoint(world['holdout_ids']) and len(ids) == len(world['manifest']['samples']) - len(world['holdout'])
        assert all(s['split'] != 'holdout' and 'holdout_population' not in s for s in manifest['samples'])
        assert 'group_audit' not in manifest and 'quarantine' not in manifest
        # Aggregates only: per-class support for the sealed population is allowed, per-item rows are not.
        assert manifest['protected_population_support'][HOLDOUT_TAG]['0']['samples'] == 2
        assert detail.json()['proposals'] == []
    # Unknown/other-workspace versions answer 404 with no body difference from an absent id.
    client, _ = C(world, 'researcher')
    a = client.get(f"{base(world)}/versions/{uuid.uuid4()}")
    b = client.get(f"{base(world)}/versions/{world['version_id']}x")
    assert a.status_code == b.status_code == 404 and a.text == b.text


def test_frozen_version_write_paths_do_not_distinguish_protected_ids(world):
    client, headers = C(world, 'researcher')
    codes = set()
    for sid in [world['holdout'][0]['id'], world['train_val'][0]['id'], str(uuid.uuid4())]:
        r = client.post(f"{base(world)}/versions/{world['version_id']}/proposals", headers={**headers, 'If-Match': '4'},
                        json={'sample_id': sid, 'label': 1, 'reason': 'probe a protected id on a frozen version'})
        assert_clean(r, world['sentinels'], 'propose on frozen')
        codes.add((r.status_code, r.text))
    assert len(codes) == 1  # FROZEN_VERSION for every id, protected or not


def test_researcher_cannot_create_a_holdout_population_or_see_split_plan_membership(world):
    client, headers = C(world, 'researcher')
    r = client.post(f"{base(world)}/real/versions/{world['version_id']}/split-plan", headers=headers, json={'revision': 4})
    assert_clean(r, world['sentinels'], 'split-plan')
    assert r.status_code in (409, 423)  # frozen version


# ------------------------------------------------------------------------------------------------ sweep
def _fill(world, name, extra):
    syn_ids = ['SYN-0-8', 'SYN-3-8', 'SYN-0-0']
    pools = {
        'workspace_id': [world['workspace']],
        'run_id': [world['real_run'], str(uuid.uuid4())],
        'sample_id': [world['holdout'][0]['id'], world['alias_id'], world['plain_id'], world['train_val'][0]['id'],
                      world['pool'][0]['id'], str(uuid.uuid4())] + syn_ids,
        'version_id': [world['version_id'], str(uuid.uuid4())],
        'bundle_id': [world['real_run'], str(uuid.uuid4())],
        'plan_id': [str(uuid.uuid4())] + extra.get('plan_ids', []),
        'release_id': ['flowers-r5-small-residual-v1', str(uuid.uuid4())],
        'dataset_id': [world['rights_dataset'], str(uuid.uuid4())],
    }
    return pools.get(name, [str(uuid.uuid4())])


def _query_value(world, name, schema):
    fixed = {'actual': 0, 'predicted': 0, 'bucket': 'cell', 'version_id': world['version_id'], 'purpose': 'model_bundle',
             'member_id': world['holdout'][0]['source_member'], 'dataset_id': world['rights_dataset'], 'after': 0,
             'offset': 0, 'limit': 5, 'replay_only': 'true'}
    if name in fixed:
        return fixed[name]
    return 0 if schema.get('type') == 'integer' else 'x'


def workspace_operations(app):
    spec = app.openapi()
    out = []
    for path, methods in spec['paths'].items():
        if '{workspace_id}' not in path:
            continue
        for method, op in methods.items():
            if method in ('get', 'post', 'put', 'delete', 'patch'):
                out.append((method.upper(), path, op))
    return out


def test_every_get_route_leaks_nothing_to_researcher_and_viewer(world, chain):
    ops = [o for o in workspace_operations(chain.api.app) if o[0] == 'GET']
    assert len(ops) >= 30
    count = 0
    for who in ('researcher', 'viewer'):
        client, _ = C(world, who)
        for _, path, op in ops:
            params = [p for p in op.get('parameters', []) if p['in'] == 'path']
            queries = {p['name']: _query_value(world, p['name'], p.get('schema', {}))
                       for p in op.get('parameters', []) if p['in'] == 'query' and (p.get('required') or p['name'] == 'replay_only')}
            choices = [_fill(world, p['name'], {}) for p in params]
            for combo in itertools.product(*choices):
                url = path
                for p, v in zip(params, combo):
                    url = url.replace('{' + p['name'] + '}', str(v))
                r = client.get(url, params=queries)
                assert_clean(r, world['sentinels'], f'{who} GET {path}')
                count += 1
    STATE['get_requests'] = count
    STATE['get_routes'] = len(ops)
    assert count >= 100


def test_non_destructive_write_routes_leak_nothing_to_researcher(world, chain):
    skip = ('workspace-deletion', '/real/settings', '/hold')  # tenant-state mutations, not holdout surfaces
    ops = [o for o in workspace_operations(chain.api.app) if o[0] in ('POST', 'PUT') and not any(s in o[1] for s in skip)]
    client, headers = C(world, 'researcher')
    count = 0
    for method, path, op in ops:
        params = [p for p in op.get('parameters', []) if p['in'] == 'path']
        choices = [_fill(world, p['name'], {})[:3] for p in params]
        for combo in itertools.product(*choices):
            url = path
            for p, v in zip(params, combo):
                url = url.replace('{' + p['name'] + '}', str(v))
            h = {**headers, 'Idempotency-Key': str(uuid.uuid4()), 'If-Match': '"1"'}
            r = client.request(method, url, headers=h, json={})
            assert_clean(r, world['sentinels'], f'researcher {method} {path}')
            count += 1
    STATE['write_requests'] = count
    assert count >= 20


# ------------------------------------------------------------------------------------------------ synthetic fixture surfaces
def test_synthetic_surfaces_hide_holdout_rows_and_validation_exports_contain_no_holdout(world, chain):
    from fieldwork.data import generate
    m = generate(chain.api.DATA)
    hold = [s for s in m['samples'] if s['split'] == 'holdout']
    val_ids = {s['id'] for s in m['samples'] if s['split'] == 'validation'}
    sentinels = {s['id'] for s in hold} | {s['sha256'] for s in hold} | {s['pixel_sha256'] for s in hold} | {s['file'] for s in hold}
    client, _ = C(world, 'syn')
    b = f"/api/v1/workspaces/{world['syn']}"
    snap = client.get(b + '/snapshot')
    assert_clean(snap, sentinels, 'snapshot')
    assert {s['id'] for s in snap.json()['samples']}.isdisjoint({s['id'] for s in hold})
    assert snap.json()['counts']['holdout'] == len(hold)  # aggregate count only
    run = f"{b}/runs/{world['syn_run']}"
    for suffix in ('', '/evaluation', '/records', '/artifacts', '/flags'):
        assert_clean(client.get(run + suffix), sentinels, 'syn ' + suffix)
    rows = [json.loads(line) for line in client.get(run + '/records').text.splitlines() if line]
    assert rows and {r['id'] for r in rows} <= val_ids  # exports carry validation members only
    for actual, predicted in itertools.product(range(5), repeat=2):
        r = client.get(run + f'/slices?actual={actual}&predicted={predicted}&limit=20')
        assert_clean(r, sentinels, 'slices')
        assert set(r.json()['sample_ids']) <= val_ids
    assert_clean(client.get(run + '/slices?actual=0&bucket=missing&limit=20'), sentinels, 'slices missing')
    for path in ('/screens/splits', '/screens/configure', '/screens/access', '/screens/inference', '/screens/operations'):
        assert_clean(client.get(b + path), sentinels, path)
    splits = client.get(b + '/screens/splits').json()['splits']['holdout']
    assert splits['sealed'] is True and splits['membership_digest'] is None
    assert client.get(b + f"/bundles/{world['syn_run']}/download").status_code == 403
    assert client.get(b + f"/bundles/{uuid.uuid4()}/download").status_code == 403
    STATE['syn_export_rows'] = len(rows)


def test_synthetic_media_route_status_codes_documented(world, chain):
    """Synthetic author-generated fixture route: sealed id -> 403 HOLDOUT_SEALED, absent -> 404 (documented contract
    in tests/test_api.py and /screens/access). No pixels or label cross either response."""
    client, _ = C(world, 'syn')
    b = f"/api/v1/workspaces/{world['syn']}"
    sealed = client.get(b + '/samples/SYN-0-8/media')
    absent = client.get(b + '/samples/SYN-0-99/media')
    ok = client.get(b + '/samples/SYN-0-0/media')
    assert sealed.status_code == 403 and absent.status_code == 404 and ok.status_code == 200
    assert sealed.headers['content-type'].startswith('application/json') and sealed.json() == {'detail': 'HOLDOUT_SEALED'}
    STATE['syn_media_oracle'] = (sealed.status_code, absent.status_code)


# ------------------------------------------------------------------------------------------------ steward flow
@pytest.fixture(scope='module')
def flow(world, chain):
    """Simulated AI steward lifecycle driven through the real routes and the real holdout module."""
    from fieldwork import holdout
    out = {}
    plans = f"{base(world)}/real/holdout/plans"
    body = {'version_id': world['version_id'], 'version_digest': world['manifest']['digest'],
            'population_digest': world['population_digest'], 'population_count': len(world['population']),
            'population_tag': HOLDOUT_TAG, 'candidate_model_digest': 'c' * 64, 'candidate_checkpoint_digest': 'd' * 64,
            'evaluator': 'fieldwork.metrics.evaluate (simulated AI steward fixture)', 'usefulness_spec_sha256': 'e' * 64}
    out['body'] = body
    out['refused'] = {}
    for who in ('researcher', 'owner', 'reviewer', 'viewer', 'anon'):
        client, h = C(world, who)
        r = client.post(plans, headers=h, json=body)
        out['refused'][who] = (r.status_code, r.text)
        g = client.get(plans, params={'version_id': world['version_id']}, headers=h)
        out['refused'][who + ':list'] = (g.status_code, g.text)
    client, h = C(world, 'steward')
    out['wrong_pop'] = client.post(plans, headers=h, json={**body, 'population_digest': 'f' * 64}).status_code
    out['wrong_ver'] = client.post(plans, headers=h, json={**body, 'version_digest': 'f' * 64}).status_code
    created = client.post(plans, headers=h, json=body)
    out['created'] = (created.status_code, created.json(), blob(created))
    plan_id = created.json()['plan_id']
    out['second'] = client.post(plans, headers=h, json=body)
    out['listing'] = client.get(plans, params={'version_id': world['version_id']}, headers=h)
    steward = world['steward_name']
    with pytest.raises(holdout.HoldoutRefused) as e:
        holdout.consume(chain.dba, world['workspace'], world['accounts']['researcher'], plan_id, 'c' * 64)
    out['researcher_consume'] = e.value.code
    with pytest.raises(holdout.HoldoutRefused) as e:
        holdout.consume(chain.dba, world['workspace'], world['accounts']['owner'], plan_id, 'c' * 64)
    out['owner_consume'] = e.value.code
    with pytest.raises(holdout.HoldoutRefused) as e:
        holdout.consume(chain.dba, world['workspace'], steward, plan_id, '9' * 64)
    out['swap_before'] = e.value.code
    out['consumed'] = holdout.consume(chain.dba, world['workspace'], steward, plan_id, 'c' * 64)
    # Failed evaluation: the process dies before any result is recorded. Exposure stays consumed.
    with chain.dba.connect() as c:
        c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (world['workspace'],))
        out['after_failure'] = dict(c.execute('SELECT state,exposures,result,consumed_utc FROM fw_holdout_plans WHERE plan_id=%s', (plan_id,)).fetchone())
    with pytest.raises(holdout.HoldoutRefused) as e:
        holdout.consume(chain.dba, world['workspace'], steward, plan_id, '8' * 64)
    out['swap_after_failure'] = e.value.code
    out['retry_same_model'] = holdout.consume(chain.dba, world['workspace'], steward, plan_id, 'c' * 64)
    holdout.record_result(chain.dba, world['workspace'], plan_id, '1' * 64,
                          {'gate': 'failed', 'accuracy': 0.5, 'n': len(world['population'])})
    out['after_result'] = client.get(plans, params={'version_id': world['version_id']}, headers=h)
    out['third'] = client.post(plans, headers=h, json=body)
    # A different frozen version that re-seals the same content under a new tag/ids/groups.
    out['overlap'] = _overlapping_version(world, chain, client, h, body)
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    try:  # pre-021 schema (migrations 003..020): the steward route has no UPDATE privilege on fw_holdout_plans
        client.post(f'{plans}/{plan_id}/invalidate', headers=h, json={'reason': 'post-exposure tuning detected in fixture'})
        out['invalidate_unfixed'] = 'NO_ERROR'
    except psycopg.errors.InsufficientPrivilege as exc:
        out['invalidate_unfixed'] = 'InsufficientPrivilege: ' + str(exc).splitlines()[0]
    # Migration 021 (column-level grant + transition guard; applied to the retained database 2026-11-03).
    with chain.dba.connect() as c:
        c.execute((Path(__file__).resolve().parents[1] / 'migrations/021_holdout_plan_invalidate_grant.sql').read_text(encoding='utf-8'))
    out['invalidate'] = client.post(f'{plans}/{plan_id}/invalidate', headers=h, json={'reason': 'post-exposure tuning detected in fixture'})
    out['invalidate_researcher'] = C(world, 'researcher')[0].post(f'{plans}/{plan_id}/invalidate', headers=C(world, 'researcher')[1], json={'reason': 'researcher tries to invalidate'})
    with pytest.raises(holdout.HoldoutRefused) as e:
        holdout.consume(chain.dba, world['workspace'], steward, plan_id, 'c' * 64)
    out['consume_after_invalidate'] = e.value.code
    out['after_invalidate_authorize'] = client.post(plans, headers=h, json=body)
    out['plan_id'] = plan_id
    STATE['plan_id'] = plan_id
    # Direct request-principal probes of the guard: cannot restore `authorized`, edit counters or digests.
    guard = {}
    with psycopg.connect(chain.request.dsn, autocommit=False) as api_db:
        api_db.execute("SELECT set_config('fieldwork.workspace',%s,true)", (world['workspace'],))
        for name, stmt in {'restore_authorized': "UPDATE fw_holdout_plans SET state='authorized'",
                           'zero_exposures': 'UPDATE fw_holdout_plans SET exposures=0',
                           'swap_model': "UPDATE fw_holdout_plans SET candidate_model_digest='" + '7' * 64 + "'"}.items():
            try:
                with api_db.transaction():
                    api_db.execute(stmt)
                guard[name] = 'ALLOWED'
            except psycopg.errors.InsufficientPrivilege:
                guard[name] = 'denied'
    out['guard'] = guard
    return out


def _overlapping_version(world, chain, client, headers, body):
    import copy
    from fieldwork.data import canonical, digest
    from fieldwork.protected_population import population_members
    from psycopg.types.json import Jsonb
    m = copy.deepcopy(world['manifest'])
    tag = 'holdout-sealed-population-B'
    for s in m['samples']:
        if s['split'] == 'holdout':
            s.update(id=str(uuid.uuid4()), group='ov-' + s['group'], holdout_population=tag)
    vid = 'ov-v-' + uuid.uuid4().hex[:10]
    m.pop('digest')
    m['version_id'] = vid
    m['digest'] = digest(canonical(m))
    members, pdigest = population_members(m, tag)
    with chain.dba.connect() as c:
        c.execute('''INSERT INTO fw_versions(workspace,id,author,parent_digest,state,revision,manifest,reviewed_digest,reviewer,review_reason)
            VALUES(%s,%s,'fixture-author',%s,'frozen',4,%s,%s,'fixture-reviewer','fixture review')''',
                  (world['workspace'], vid, m['parent_digest'], Jsonb(m), m['review_digest']))
    resp = client.post(f"{base(world)}/real/holdout/plans", headers=headers, json={
        **body, 'version_id': vid, 'version_digest': m['digest'], 'population_digest': pdigest,
        'population_count': len(members), 'population_tag': tag})
    return resp


def test_holdout_authorization_is_steward_only_and_owner_is_not_a_shortcut(flow):
    for who in ('researcher', 'owner', 'reviewer', 'viewer'):
        assert flow['refused'][who][0] == 403 and 'HOLDOUT_STEWARD_REQUIRED' in flow['refused'][who][1], who
        assert flow['refused'][who + ':list'][0] == 403
    assert flow['refused']['anon'][0] == 401
    assert flow['researcher_consume'] == 'STEWARD_ROLE_REQUIRED' and flow['owner_consume'] == 'STEWARD_ROLE_REQUIRED'


def test_exactly_one_locked_plan_binds_candidate_and_population(flow, world):
    assert flow['wrong_pop'] == 409 and flow['wrong_ver'] == 409
    status, payload, text = flow['created']
    assert status == 201 and payload['state'] == 'authorized' and payload['holdout_rows_returned'] == 0
    assert not [s for s in world['sentinels'] if s in text]
    assert flow['second'].status_code == 409 and flow['second'].json()['detail'] == 'LIVE_HOLDOUT_PLAN_EXISTS'
    listing = flow['listing']
    assert listing.status_code == 200 and listing.json()['holdout_rows_returned'] == 0
    assert not [s for s in world['sentinels'] if s in blob(listing)]
    plan = listing.json()['plans'][0]
    assert plan['candidate_model_digest'] == 'c' * 64 and plan['population_count'] == 10


def test_exposure_is_consumed_before_evaluation_and_stays_consumed_on_failure(flow):
    assert flow['consumed']['state'] == 'consumed' and flow['consumed']['exposures'] == 1
    assert flow['after_failure']['state'] == 'consumed' and flow['after_failure']['exposures'] == 1
    assert flow['after_failure']['result'] is None and flow['after_failure']['consumed_utc'] is not None
    assert flow['after_result'].json()['plans'][0]['state'] == 'consumed'
    assert flow['after_result'].json()['plans'][0]['result_sha256'] == '1' * 64  # failed gate result retained


def test_retries_cannot_swap_the_locked_model(flow):
    assert flow['swap_before'] == 'MODEL_SWAP' and flow['swap_after_failure'] == 'MODEL_SWAP'
    assert flow['retry_same_model']['exposures'] == 2 and flow['retry_same_model']['state'] == 'consumed'


def test_consumed_population_and_overlapping_content_can_never_be_resealed_as_unseen(flow):
    assert flow['third'].status_code == 409 and flow['third'].json()['detail'] == 'HOLDOUT_POPULATION_ALREADY_CONSUMED'
    assert flow['overlap'].status_code == 409 and flow['overlap'].json()['detail'] == 'HOLDOUT_CONTENT_ALREADY_EXPOSED'


def test_pre_021_schema_reproduces_the_invalidate_privilege_defect(flow):
    """Migrations 003..020 alone: no UPDATE on fw_holdout_plans for the request principal (fixed by 021, applied live 2026-11-03)."""
    assert flow['invalidate_unfixed'].startswith('InsufficientPrivilege: permission denied for table fw_holdout_plans')


def test_migration_021_restricts_the_request_principal_to_one_way_invalidation(flow):
    assert flow['guard'] == {'restore_authorized': 'denied', 'zero_exposures': 'denied', 'swap_model': 'denied'}


def test_post_exposure_tuning_invalidates_the_plan_and_unseen_status_is_not_restored(flow):
    assert flow['invalidate'].status_code == 200 and flow['invalidate'].json()['state'] == 'invalidated'
    assert flow['invalidate'].json()['was_consumed'] is True and flow['invalidate'].json()['exposures'] == 2
    assert flow['invalidate_researcher'].status_code == 403
    assert flow['consume_after_invalidate'] == 'PLAN_INVALIDATED'
    assert flow['after_invalidate_authorize'].status_code == 409
    assert flow['after_invalidate_authorize'].json()['detail'] == 'HOLDOUT_POPULATION_ALREADY_CONSUMED'


# ------------------------------------------------------------------------------------------------ worker / job mounts
def test_scoped_worker_job_inputs_contain_only_train_and_validation(world, chain, tmp_path):
    """Worker request path: the real SQL capability returns the job's input list (the 'mount' contract)."""
    w = real_worker(chain, tmp_path, [world['workspace']])
    rid = world['real_run']
    assert w.next_real_run()['id'] == rid
    run = w.claim_real(rid, start=True, worker_id='holdout-matrix')
    scope = (run['attempt'], run['fence'], run['cancel_generation'], run['restore_generation'])
    inputs = w.real_inputs(rid, *scope)
    served = {s['id'] for s in inputs['samples']}
    assert served == {m['id'] for m in world['train_val']}
    assert served.isdisjoint(world['holdout_ids']) and served.isdisjoint({m['id'] for m in world['pool']})
    text = json.dumps(inputs)
    assert not [s for s in world['sentinels'] if s in text]
    assert {s['split'] for s in inputs['samples']} == {'train', 'validation'}
    from fieldwork.store import Conflict
    for sid in [world['holdout'][0]['id'], world['pool'][0]['id'], world['alias_id'], str(uuid.uuid4())]:
        with pytest.raises(Conflict):
            w.real_member_rights(rid, *scope, sid)
    with pytest.raises(Conflict, match='REAL_BUNDLE_RIGHTS_NOT_READY'):  # no signed model_bundle decisions in the fixture
        w.real_bundle_rights(rid, *scope)
    # A foreign attempt/credential cannot read inputs of this run (no run choice beyond the claimed attempt).
    with pytest.raises(Conflict):
        w.real_inputs(rid, str(uuid.uuid4()), run['fence'], run['cancel_generation'], run['restore_generation'])
    STATE['worker_samples'] = len(served)
    chain.dba.release_slot(rid)


# ------------------------------------------------------------------------------------------------ event feeds
def test_event_feeds_poll_sse_replay_and_snapshot_hold_no_protected_value(world, flow):
    for who in ('researcher', 'viewer', 'steward'):
        client, _ = C(world, who)
        b = base(world)
        poll = client.get(b + '/events?after=0')
        assert_clean(poll, world['sentinels'], 'poll')
        assert poll.json()['items'], 'the real run produced events'
        sse = client.get(b + '/events/stream?replay_only=true')
        assert_clean(sse, world['sentinels'], 'sse')
        assert sse.text.count('event: domain') == len(poll.json()['items'])
        replay = client.get(b + '/events/stream?replay_only=true', headers={'Last-Event-ID': '0'})
        assert_clean(replay, world['sentinels'], 'sse replay')
        assert_clean(client.get(b + '/snapshot'), world['sentinels'], 'snapshot')
    # Holdout plan lifecycle writes no workspace event (nothing about the sealed plan crosses the feed).
    kinds = {e['kind'] for e in C(world, 'researcher')[0].get(base(world) + '/events?after=0').json()['items']}
    assert not [k for k in kinds if 'holdout' in (k or '')]


def test_summary_counters(world):
    assert STATE.get('get_requests', 0) >= 100 and STATE.get('media_probes', 0) >= 60


def test_write_state_summary(world):
    import json as _json
    from fieldwork.store import ROOT
    out = Path(ROOT) / 'var' / 'matrix-state-holdout.json'
    out.parent.mkdir(exist_ok=True)
    out.write_text(_json.dumps(STATE, default=str))
