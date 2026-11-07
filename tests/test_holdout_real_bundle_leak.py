"""ML-T-HOLDOUT against a REAL private-real model bundle, before and after holdout consumption.

Frozen element (portfolio-engineering/ACCEPTANCE-REGISTER.csv, ML-T-HOLDOUT): "test protected IDs/labels/per-item
rows nested in bundle manifests, prediction exports, paths and job mounts both before and after consumption".

Real code paths only:
* the frozen rights-cleared version with a sealed holdout population is the leak world (tests/leak_world.py) inside
  the retained migration chain 003..023 (tests/chain_support.py), with REAL Ed25519-signed decisions
  (tests/signed_world.py);
* the training run is queued through the real route POST /real/runs as a researcher;
* the job "mount" is the scoped worker's real SQL capability `fw_real_worker_cap_v1.real_inputs` (RealWorkerStore),
  and the job staging directory is written with the product's fieldwork.real_pixels.write_rgb8 in the exact
  inputs.json shape of fieldwork/real_job._stage_pixels;
* the bundle is built by the product builder fieldwork/real_bundle.build (which itself calls verify_real_bundle) from a
  committed checkpoint written by fieldwork/ml.checkpoint. No training is run: the checkpoint is a fresh compact CNN
  after ONE AdamW step on a 2x3x16x16 random batch (validate_checkpoint requires optimizer moments), exactly like
  tests/hostile_fixtures.make_checkpoint; the decoder container is not started, the pixel files are synthetic RGB8;
* the bundle routes GET .../real/runs/{id}/bundle and /bundle/download are called as a researcher (and viewer)
  through the real FastAPI app under the nonowner request principal;
* consumption is the *simulated AI steward* flow: an operator-assigned owner account bound to the fixture reviewer
  key authorizes the plan through POST /real/holdout/plans and consumes it with fieldwork.holdout.consume.
  No human steward is claimed.

The terminal run state (succeeded / artifact verified + artifact_verified event) is written by the operator
connection because the fenced artifact worker needs the model container (not started on this host).

Leak check: every protected value of every holdout member (id, raw sha256, pixel sha256, source member name, group,
media path, perceptual hash) is searched case-insensitively in every byte scanned, plus the dash-less uuid hex and the
raw binary forms (16-byte uuid, 32-byte digests).
"""
import hashlib, json, random, uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.chain_support import chain, make_account, login, real_worker  # noqa: F401
from tests.leak_world import build_world, HOLDOUT_TAG
from tests.signed_world import Signer

DECODER = 'sha256:' + 'a' * 64
MODEL = 'sha256:' + 'b' * 64
STATE = {}


# ------------------------------------------------------------------------------------------------ scanning
def needles(world):
    text, raw = set(), set()
    for m in world['holdout']:
        for v in (m['id'], m['sha256'], m['pixel_sha256'], m['source_member'], m['group'], m['file'], m['phash']['hex']):
            text.add(v.lower().encode())
        text.add(m['id'].replace('-', '').lower().encode())
        raw.add(uuid.UUID(m['id']).bytes)
        raw.add(bytes.fromhex(m['sha256']))
        raw.add(bytes.fromhex(m['pixel_sha256']))
    return text, raw


def hits(world, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    text, raw = world['needles']
    low = data.lower()
    return [n for n in text if n in low] + [r.hex() for r in raw if r in data]


def scan_tree(world, root):
    scanned, found = 0, {}
    for p in sorted(Path(root).rglob('*')):
        rel = p.relative_to(root).as_posix()
        h = hits(world, rel)  # paths are scanned too
        if p.is_file():
            h += hits(world, p.read_bytes())
            scanned += 1
        if h:
            found[rel] = len(h)
    return scanned, found


def response_bytes(r):
    return r.content + b'\n' + '\n'.join(f'{k}: {v}' for k, v in r.headers.items()).encode()


# ------------------------------------------------------------------------------------------------ world
@pytest.fixture(scope='module')
def bw(chain, tmp_path_factory):
    import fieldwork.api as api
    from fieldwork import real_workspace_api
    mp = pytest.MonkeyPatch()
    tmp = tmp_path_factory.mktemp('real-bundle-leak')
    signer = Signer(tmp / 'reviewers.json')
    mp.setenv('FIELDWORK_RIGHTS_REVIEWERS_FILE', str(signer.path))
    mp.setenv('FIELDWORK_REAL_PIXEL_IMAGE_ID', DECODER)
    mp.setenv('FIELDWORK_REAL_MODEL_IMAGE_ID', MODEL)
    artifact_root = tmp / 'artifact-root'
    mp.setattr(real_workspace_api, 'ROOT', artifact_root)  # where the bundle routes look for var/runs/<run>/...
    ws = str(uuid.uuid4())
    W = build_world(chain, ws, prefix='rb')
    signer.sign_world(chain, W)
    W['needles'] = needles(W)
    W['validation_ids'] = {m['id'] for m in W['train_val'] if m['split'] == 'validation'}
    W['train_val_ids'] = {m['id'] for m in W['train_val']}
    tag = uuid.uuid4().hex[:6]
    W['researcher'], W['viewer'] = f'rb-researcher-{tag}', f'rb-viewer-{tag}'
    W['steward'] = f'ai-steward-sim-{tag}'  # simulated AI steward (operator-assigned owner account)
    make_account(chain, W['researcher'], 'researcher', ws)
    make_account(chain, W['viewer'], 'viewer', ws)
    make_account(chain, W['steward'], 'owner', ws)
    with chain.dba.connect() as c:
        c.execute('INSERT INTO fw_holdout_stewards(workspace,actor,reviewer_id,key_id,assigned_by) VALUES(%s,%s,%s,%s,%s)',
                  (ws, W['steward'], signer.reviewer_id, signer.key_id, 'operator'))
    W['base'] = f'/api/v1/workspaces/{ws}'
    W['tmp'], W['artifact_root'], W['signer'] = tmp, artifact_root, signer
    clients = {}
    for who in ('researcher', 'viewer', 'steward'):
        client = TestClient(api.app)
        client.__enter__()
        clients[who] = (client, login(client, W[who]))
    W['clients'] = clients
    try:
        yield W
    finally:
        for client, _ in clients.values():
            client.__exit__(None, None, None)
        mp.undo()
        out = Path(__file__).resolve().parents[1] / 'var' / 'matrix-state-holdout-real-bundle.json'
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(STATE, indent=1, default=str))


def submit_real(W, key):
    client, h = W['clients']['researcher']
    r = client.post(W['base'] + '/real/runs', headers={**h, 'Idempotency-Key': key},
                    json={'version_id': W['version_id'], 'version_revision': 4, 'epochs': 1, 'batch_size': 8,
                          'learning_rate': '0.001', 'seed': 7})
    assert r.status_code == 202, r.text
    assert not hits(W, response_bytes(r))
    return r.json()['id']


def mount(W, chain, rid, tmp):
    """Claim the run with the scoped real worker and fetch its job input list through the real SQL capability."""
    tmp.mkdir(parents=True, exist_ok=True)
    w = real_worker(chain, tmp, [W['workspace']])
    head = w.next_real_run()
    assert head and head['id'] == rid
    run = w.claim_real(rid, start=True, worker_id='holdout-real-bundle')
    scope = (run['attempt'], run['fence'], run['cancel_generation'], run['restore_generation'])
    return w, run, scope, w.real_inputs(rid, *scope)


def assert_mount_clean(W, inputs, where):
    served = [s['id'] for s in inputs['samples']]
    assert len(served) == len(set(served)) == len(W['train_val'])
    assert set(served) == W['train_val_ids'], where
    assert set(served).isdisjoint(W['holdout_ids']) and set(served).isdisjoint({m['id'] for m in W['pool']})
    assert {s['split'] for s in inputs['samples']} == {'train', 'validation'}
    assert not hits(W, json.dumps(inputs)), where + ': protected value in job input list'


def stage_inputs(W, inputs, stage):
    """The job staging directory, in the exact shape of fieldwork/real_job._stage_pixels (synthetic RGB8 pixels)."""
    from fieldwork.data import canonical
    from fieldwork.real_pixels import write_rgb8
    from fieldwork.real_run_profile import RECIPE_DIGEST, PREPROCESS_DIGEST
    stage.mkdir(parents=True)
    rng = random.Random(5)
    groups = {'train': [], 'validation': []}
    for index, sample in enumerate(inputs['samples']):
        payload = bytes(rng.getrandbits(8) for _ in range(144 * 144 * 3))
        claimed = hashlib.sha256(b'RGB8|144|144|' + payload).hexdigest()
        pixel = write_rgb8(stage, 'pixel-%06d.rgb' % index, 144, 144, payload, claimed)
        row = {k: sample[k] for k in ('id', 'label', 'split', 'source_member')}
        row['source_sha256'] = sample['sha256']
        groups[sample['split']].append({**row, **pixel})
    manifest = {'schema': 'fieldwork.real-pixel-input/v1', 'version_id': inputs['version_id'],
                'version_digest': inputs['version_digest'], 'recipe': 'compact-cnn/real-v1',
                'recipe_digest': RECIPE_DIGEST, 'preprocess': 'short-edge144-rgb-v1',
                'preprocess_digest': PREPROCESS_DIGEST, 'decoder_image_id': DECODER,
                'classes': inputs['classes'], 'train': groups['train'], 'validation': groups['validation']}
    (stage / 'inputs.json').write_bytes(canonical(manifest))
    return manifest


def committed_checkpoint(root, dataset_digest):
    """ml.checkpoint after one AdamW step on a 2x3x16x16 random batch (no training run)."""
    import torch
    from fieldwork.ml import model, checkpoint
    torch.set_num_threads(1)
    torch.manual_seed(1)
    random.seed(1)
    net = model()
    opt = torch.optim.AdamW(net.parameters(), lr=0.001, weight_decay=0.0001)
    generator = torch.Generator().manual_seed(1)
    loss = torch.nn.functional.cross_entropy(net(torch.rand(2, 3, 16, 16)), torch.tensor([0, 1]))
    opt.zero_grad(); loss.backward(); opt.step()
    meta = dict(epoch=1, train_loss=1.0, validation_loss=1.0, updates=1, next_epoch=2, dataset_digest=dataset_digest,
                seed=7, best={'epoch': 1, 'loss': 1.0}, initial_digest='b' * 64)
    path = Path(root) / 'epoch-1'
    return path, checkpoint(path, net, opt, generator, meta)


@pytest.fixture(scope='module')
def built(bw, chain):
    """Queue -> scoped worker mount -> staged inputs -> committed checkpoint -> real bundle -> verified run."""
    import fieldwork.api as api
    from fieldwork import real_bundle
    from fieldwork.data import canonical, digest
    from psycopg.types.json import Jsonb
    W = bw
    rid = submit_real(W, 'rb-run-1')
    w, run, scope, inputs = mount(W, chain, rid, W['tmp'] / 'worker-1')
    assert_mount_clean(W, inputs, 'mount before consumption')
    rights = w.real_bundle_rights(rid, *scope)  # fresh model_bundle rights for the artifact population
    assert not hits(W, json.dumps(rights))
    stage = W['tmp'] / 'job-1' / 'stage'
    staged = stage_inputs(W, inputs, stage)
    ckpt, ckpt_digest = committed_checkpoint(W['tmp'] / 'job-1' / 'checkpoints', W['manifest']['digest'])
    # decision digests exactly as fieldwork/real_artifact_pipeline._fresh_bundle_rights derives them: verify every
    # model_bundle envelope served by the worker capability against the trusted registry
    import base64
    from fieldwork.rights_decision import ExpectedFacts, verify_decision
    from fieldwork.rights_registry import load_trusted_registry
    rows = rights['rights'] if isinstance(rights, dict) else rights
    assert {r['source_member'] for r in rows} == {s['source_member'] for s in inputs['samples']}
    decisions = [verify_decision(base64.b64decode(r['rights_envelope_b64'], validate=True),
                                 registry=load_trusted_registry(), expected=ExpectedFacts(**r['rights_facts']))
                 for r in rows]
    assert {d.purpose for d in decisions} == {'model_bundle'}
    bundle = W['artifact_root'] / 'var' / 'runs' / rid / 'real-artifact-attempt-1' / 'bundle'
    manifest = real_bundle.build(ckpt, stage, bundle, expected_checkpoint_digest=ckpt_digest,
                                 version_id=W['version_id'], version_digest=W['manifest']['digest'],
                                 classes=inputs['classes'], rights_decision_digests=[d.decision_digest for d in decisions],
                                 model_image_id=MODEL)
    bundle_digest = digest(canonical(manifest))
    real_bundle.verify_real_bundle(bundle, expected_digest=bundle_digest,
                                   expected_lineage={'version_id': W['version_id'], 'dataset_digest': W['manifest']['digest'],
                                                     'checkpoint_digest': ckpt_digest, 'model_image_id': MODEL})
    lineage = json.loads((bundle / 'lineage.json').read_text())
    chain.dba.release_slot(rid)
    with chain.dba.connect() as c:
        c.execute('''UPDATE fw_runs SET state='succeeded',epoch=1,lease=NULL,result=%s,artifact_status='verified',
            artifact_result=%s WHERE id=%s''',
                  (Jsonb({'selected': {'epoch': 1}}), Jsonb({'artifact_directory': 'real-artifact-attempt-1',
                   'bundle_digest': bundle_digest, 'model_digest': lineage['model_digest']}), rid))
        row = c.execute('SELECT * FROM fw_runs WHERE id=%s', (rid,)).fetchone()
        chain.dba.event(c, row, 'artifact_verified', {'bundle_digest': bundle_digest})
    files = {p.relative_to(bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in bundle.rglob('*') if p.is_file()}
    STATE['bundle'] = {'files': sorted(files), 'bundle_digest': bundle_digest, 'model_digest': lineage['model_digest'],
                       'validation_rows': len(staged['validation']), 'train_rows': len(staged['train'])}
    return {'rid': rid, 'bundle': bundle, 'digest': bundle_digest, 'files': files, 'lineage': lineage,
            'ckpt_digest': ckpt_digest, 'stage': stage, 'checkpoint': ckpt, 'inputs': inputs}


def assert_bundle_files_clean(W, b, where):
    from fieldwork.real_bundle import verify_real_bundle, FILES
    verify_real_bundle(b['bundle'], expected_digest=b['digest'])
    scanned, found = scan_tree(W, b['bundle'])
    assert scanned == len(FILES) + 1 and not found, f'{where}: protected values in bundle files {found}'
    population = json.loads((b['bundle'] / 'evaluation/population.json').read_text())
    predictions = [json.loads(line) for line in (b['bundle'] / 'evaluation/predictions.jsonl').read_text().splitlines() if line]
    metrics = json.loads((b['bundle'] / 'evaluation/metrics.json').read_text())
    report = json.loads((b['bundle'] / 'evaluation/independent-report.json').read_text())
    # per-item rows are validation members only (no holdout label/id row), and every validation member is there once
    assert sorted(r['id'] for r in population) == sorted(W['validation_ids'])
    assert sorted(r['id'] for r in predictions) == sorted(W['validation_ids'])
    assert metrics['n'] == report['n'] == len(W['validation_ids'])
    assert sum(metrics['support']) == len(W['validation_ids'])
    cell_ids = {i for v in metrics['cells'].values() for i in v}
    assert cell_ids <= W['validation_ids']
    holdout_digests = {m['sha256'] for m in W['holdout']} | {m['pixel_sha256'] for m in W['holdout']}
    assert not {r['sha256'] for r in population} & holdout_digests
    for name in ('rights/review.json', 'lineage.json', 'manifest.json'):
        assert not hits(W, (b['bundle'] / name).read_bytes()), name
    return scanned


def bundle_routes(W, b, where):
    out = {}
    for who in ('researcher', 'viewer'):
        client, _ = W['clients'][who]
        inspect = client.get(f"{W['base']}/real/runs/{b['rid']}/bundle")
        download = client.get(f"{W['base']}/real/runs/{b['rid']}/bundle/download")
        for r in (inspect, download):
            assert not hits(W, response_bytes(r)), f'{where}: {who} {r.request.url.path} leaked'
            assert r.status_code < 500, r.text
        assert download.status_code == 403
        if who == 'researcher':
            assert inspect.status_code == 200, (who, inspect.text)
            body = inspect.json()
            assert body['bundle_digest'] == b['digest'] and body['download_allowed'] is False
            assert body['public_export_authorized'] is False
            assert set(body['manifest']['files']) == set(b['files']) - {'manifest.json'}
            out[who] = (inspect.status_code, download.status_code, download.json()['detail'], body['manifest'])
        else:  # viewer has no model_bundle rights purpose: refused before any bundle byte is read
            assert inspect.status_code == 403 and inspect.json()['detail'] == 'REAL_BUNDLE_RIGHTS_NOT_READY'
            out[who] = (inspect.status_code, download.status_code, download.json()['detail'], None)
    assert out['researcher'][2] == 'QUALIFIED_RELEASE_REQUIRED' and out['viewer'][2] == 'BUNDLE_DOWNLOAD_ROLE_REQUIRED'
    return out


# ------------------------------------------------------------------------------------------------ before consumption
def test_before_consumption_job_mount_and_staging_contain_only_train_validation(bw, built):
    W, b = bw, built
    assert_mount_clean(W, b['inputs'], 'mount before consumption')
    staged = json.loads((b['stage'] / 'inputs.json').read_text())
    assert {r['id'] for r in staged['train'] + staged['validation']} == W['train_val_ids']
    scanned, found = scan_tree(W, b['stage'])
    assert scanned == len(W['train_val']) + 1 and not found
    scanned_ckpt, found_ckpt = scan_tree(W, b['checkpoint'])
    assert scanned_ckpt == 3 and not found_ckpt
    STATE['before_mount'] = {'served': len(b['inputs']['samples']), 'staging_files': scanned}


def test_before_consumption_every_bundle_file_is_clean(bw, built):
    W = bw
    # positive control: the scanner is not vacuous (upper-case id, dash-less hex, raw digest bytes, upper-case digest)
    m = W['holdout'][3]
    assert hits(W, 'x' + m['id'].upper() + 'x') and hits(W, m['id'].replace('-', ''))
    assert hits(W, b'#' + bytes.fromhex(m['pixel_sha256']) + b'#') and hits(W, m['sha256'].upper())
    assert not hits(W, json.dumps(sorted(W['train_val_ids'])))
    STATE['before_bundle_files_scanned'] = assert_bundle_files_clean(W, built, 'before consumption')


def test_before_consumption_bundle_routes_are_clean(bw, built):
    out = bundle_routes(bw, built, 'before consumption')
    STATE['before_routes'] = {k: v[:3] for k, v in out.items()}
    STATE['before_route_manifest'] = out['researcher'][3]


# ------------------------------------------------------------------------------------------------ consumption
@pytest.fixture(scope='module')
def consumed(bw, built, chain):
    """Simulated AI steward: authorize the plan for THIS bundle's model and consume the sealed population."""
    from fieldwork import holdout
    W, b = bw, built
    client, h = W['clients']['steward']
    plan = client.post(W['base'] + '/real/holdout/plans', headers=h, json={
        'version_id': W['version_id'], 'version_digest': W['manifest']['digest'],
        'population_digest': W['population_digest'], 'population_count': len(W['population']),
        'population_tag': HOLDOUT_TAG, 'candidate_model_digest': b['lineage']['model_digest'],
        'candidate_checkpoint_digest': b['ckpt_digest'],
        'evaluator': 'fieldwork.metrics.evaluate (simulated AI steward)', 'usefulness_spec_sha256': 'e' * 64})
    assert plan.status_code == 201, plan.text
    assert not hits(W, response_bytes(plan))
    plan_id = plan.json()['plan_id']
    state = holdout.consume(chain.dba, W['workspace'], W['steward'], plan_id, b['lineage']['model_digest'])
    assert state['state'] == 'consumed' and state['exposures'] == 1
    holdout.record_result(chain.dba, W['workspace'], plan_id, '1' * 64,
                          {'gate': 'failed', 'accuracy': 0.2, 'n': len(W['population'])})  # aggregate only
    listing = client.get(W['base'] + '/real/holdout/plans', params={'version_id': W['version_id']}, headers=h)
    assert listing.status_code == 200 and not hits(W, response_bytes(listing))
    assert listing.json()['plans'][0]['state'] == 'consumed'
    STATE['consumed'] = {'plan_id': plan_id, 'exposures': state['exposures'], 'steward': 'simulated AI steward'}
    return plan_id


# ------------------------------------------------------------------------------------------------ after consumption
def test_after_consumption_bundle_files_unchanged_and_clean(bw, built, consumed):
    W, b = bw, built
    now = {p.relative_to(b['bundle']).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
           for p in b['bundle'].rglob('*') if p.is_file()}
    assert now == b['files']
    STATE['after_bundle_files_scanned'] = assert_bundle_files_clean(W, b, 'after consumption')


def test_after_consumption_bundle_routes_are_clean_and_unchanged(bw, built, consumed):
    out = bundle_routes(bw, built, 'after consumption')
    assert out['researcher'][3] == STATE['before_route_manifest']
    STATE['after_routes'] = {k: v[:3] for k, v in out.items()}


def test_after_consumption_new_job_mount_still_only_train_validation(bw, built, consumed, chain):
    W = bw
    rid = submit_real(W, 'rb-run-2')
    w, run, scope, inputs = mount(W, chain, rid, W['tmp'] / 'worker-2')
    assert_mount_clean(W, inputs, 'mount after consumption')
    from fieldwork.store import Conflict
    for sid in [W['holdout'][0]['id'], W['holdout'][5]['id'], W['alias_id']]:
        with pytest.raises(Conflict):
            w.real_member_rights(rid, *scope, sid)
    chain.dba.release_slot(rid)
    STATE['after_mount'] = {'served': len(inputs['samples'])}
