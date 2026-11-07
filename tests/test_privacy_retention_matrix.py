"""ML-T-PRIVACY retention matrix on the retained migration chain 003..023 (simulated clock).

Every window is proven on BOTH sides of its boundary by backdating the clock inputs the real code reads
(row timestamps through the owner/DBA connection, file mtimes, snapshot receipt `at`, deletion intent
`deleted_utc`). The code under test is not mocked: the real scanner pass
(`fieldwork.privacy_lifecycle.run_privacy_pass`), the real FastAPI routes under the real nonowner request
principal `fieldwork_api` with forced RLS, the real intake-worker error writer and the real private log
handler all run unchanged. Real bytes live in a throwaway product root (`privacy_lifecycle.ROOT` and its
archive/ledger roots are pointed at a pytest temp directory on C:), so archive copies, digests and source
removal are observed on disk.

Environmental seams only (documented in docs/acceptance-privacy-retention-20261103.md):
  * `real_retention._host_admission` is pinned to admitted (RAM/disk host gate, waived by the user; it is a
    load gate, not a retention rule);
  * `real_retention._global_lock_module` returns the REAL portfolio product_lock module with its lock path
    moved into the temp root, so the live host lock is never touched.
"""
import hashlib, importlib.util, json, logging, os, re, time, uuid
from datetime import timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict
from psycopg.types.json import Jsonb

from tests.chain_support import chain, make_account, login, PASSWORD  # noqa: F401

TAG = uuid.uuid4().hex[:8]
MARK = ('PRIVACY-MATRIX-IMAGE-' + TAG).encode()
SECRET = 'PRIVACY-MATRIX-SECRET-' + uuid.uuid4().hex
H24, D7, D30, D90, D180 = '24 hours', '7 days', '30 days', '90 days', '180 days'


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _blob(label):
    return b'\x89PNG\r\n\x1a\n' + MARK + b':' + label.encode() + b':' + os.urandom(48)


def _product_lock_module(lock_path):
    for parent in Path(__file__).resolve().parents:
        candidate = parent / 'tools' / 'product_lock.py'
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location('privacy_matrix_product_lock', candidate)
            module = importlib.util.module_from_spec(spec)
            prior = os.environ.get('PORTFOLIO_PRODUCT_LOCK')
            os.environ['PORTFOLIO_PRODUCT_LOCK'] = str(lock_path)  # binds DEFAULT and every default argument
            try:
                spec.loader.exec_module(module)
            finally:
                if prior is None:
                    os.environ.pop('PORTFOLIO_PRODUCT_LOCK', None)
                else:
                    os.environ['PORTFOLIO_PRODUCT_LOCK'] = prior
            assert Path(module.DEFAULT) == lock_path  # never the live host lock
            return module
    raise RuntimeError('PRODUCT_LOCK_MODULE_NOT_FOUND')


@pytest.fixture(scope='module')
def w(chain, tmp_path_factory):
    from fieldwork import privacy_lifecycle as L, real_retention as RR
    from fieldwork.privacy_logging import PrivateTimedRotatingFileHandler
    import fieldwork.api as api
    root = tmp_path_factory.mktemp('privroot')
    mp = pytest.MonkeyPatch()
    mp.setattr(L, 'ROOT', root)
    mp.setattr(L, 'ARCHIVE_ROOT', root / '.local' / 'privacy-archive')
    mp.setattr(L, 'DELETION_LEDGER_ROOT', root / '.local' / 'privacy-deletions')
    mp.setattr(RR, '_host_admission', lambda: {'admitted': True, 'simulated_host_gate': True})
    lock = _product_lock_module(root / '.cache' / 'product-build.lock')
    mp.setattr(RR, '_global_lock_module', lambda: lock)
    # Managed API log configuration (tools/restart_api.py, tools/durable_runtime.py): the real private
    # daily handler, uvicorn INFO, access WARNING (and --no-access-log), root WARNING.
    (root / 'var').mkdir()
    log_path = root / 'var' / 'api-live.log'
    handler = PrivateTimedRotatingFileHandler(str(log_path), when='midnight', interval=1, backupCount=0,
                                              encoding='utf-8', delay=True)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    levels = {'uvicorn': logging.INFO, 'uvicorn.error': logging.INFO, 'uvicorn.access': logging.WARNING, '': logging.WARNING}
    saved = {name: logging.getLogger(name).level for name in levels}
    for name, level in levels.items():
        logging.getLogger(name).addHandler(handler)
        logging.getLogger(name).setLevel(level)
    client = TestClient(api.app)
    client.__enter__()
    try:
        yield SimpleNamespace(chain=chain, root=root, L=L, api=api, client=client, log_path=log_path,
                              outputs=[], workspaces=[], secrets=set())
    finally:
        client.__exit__(None, None, None)
        for name in levels:
            logging.getLogger(name).removeHandler(handler)
            logging.getLogger(name).setLevel(saved[name])
        handler.close()
        mp.undo()


# ------------------------------------------------------------------------------------------------ helpers
def dba(w, sql, params=(), one=False):
    with w.chain.dba.connect() as c:
        cur = c.execute(sql, params)
        if cur.description is None:
            return None
        return cur.fetchone() if one else cur.fetchall()


def as_api(w, workspace):
    from fieldwork.store import TENANT
    token = TENANT.set(workspace)
    try:
        return w.chain.request.connect()
    finally:
        TENANT.reset(token)


def workspace(w, prefix, *roles):
    ws = 'pr-' + prefix + '-' + TAG
    w.workspaces.append(ws)
    dba(w, '''INSERT INTO fw_workspace_settings(workspace,revision,retention_days,max_concurrent_runs,max_epochs)
              VALUES(%s,1,180,2,100)''', (ws,))
    names = {}
    for role in roles or ('owner',):
        names[role] = ws + '-' + role
        make_account(w.chain, names[role], role, ws)
    return ws, names


def session(w, name):
    headers = login(w.client, name)
    w.secrets.add(headers['X-CSRF-Token'])
    w.secrets.update(v for v in w.client.cookies.values())
    return headers


def run_pass(w):
    from fieldwork.privacy_lifecycle import run_privacy_pass
    result = run_privacy_pass(w.chain.dba, max_items=20)
    assert result['status'] == 'complete', result
    w.outputs.append(json.dumps(result, sort_keys=True, default=str))  # what privacy_loop prints
    return result


def obj(w, kind, ws, key):
    return dba(w, 'SELECT * FROM fw_privacy_objects WHERE object_kind=%s AND workspace=%s AND object_key=%s',
               (kind, ws, key), one=True)


def obj_by_path(w, kind, path):
    return dba(w, 'SELECT * FROM fw_privacy_objects WHERE object_kind=%s AND source_path=%s', (kind, str(path)), one=True)


def assert_archived(w, row, data, source):
    assert row is not None, 'object was not registered'
    assert row['state'] == 'archived', dict(row)
    assert row['live_bytes_retired'] is True, dict(row)
    assert row['content_sha256'] == _sha(data) and row['content_bytes'] == len(data)
    archived = (w.root / row['archive_path']).resolve()
    assert archived.is_relative_to((w.root / '.local' / 'privacy-archive').resolve())
    assert _sha(archived.read_bytes()) == _sha(data)  # private archive copy preserves the exact bytes
    assert not Path(source).exists()  # live access path is gone


def assert_live(source, data):
    assert Path(source).read_bytes() == data


def write(path, data, age_seconds=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if age_seconds is not None:
        stamp = time.time() - age_seconds
        os.utime(path, (stamp, stamp))
    return path


def fresh_input(w, ws, actor, age):
    run_id = 'pr-run-' + uuid.uuid4().hex[:12]
    input_id = str(uuid.uuid4())
    data = _blob('fresh-' + input_id)
    path = write(w.root / '.local' / 'real-inference-uploads' / (input_id + '.img'), data)
    dba(w, '''INSERT INTO fw_runs(id,workspace,actor,idem,digest,config,state)
              VALUES(%s,%s,%s,%s,%s,%s,'succeeded')''',
        (run_id, ws, actor, run_id, '0' * 64, Jsonb({'scope': 'qualified-release-image-inference/v1'})))
    dba(w, '''INSERT INTO fw_real_image_inputs(workspace,run,input_id,dataset_id,member_id,asset_sha256,asset_bytes,
              upload_key,created_utc) VALUES(%s,%s,%s,%s,'member.png',%s,%s,%s,clock_timestamp()-%s::interval)''',
        (ws, run_id, input_id, str(uuid.uuid4()), _sha(data), len(data), input_id, age))
    return SimpleNamespace(id=input_id, run=run_id, path=path, data=data)


def intake(w, ws, actor, age):
    intake_id = str(uuid.uuid4())
    data = _blob('intake-' + intake_id)
    path = write(w.root / '.local' / 'real-data' / 'uploads' / (intake_id + '.archive'), data)
    dba(w, '''INSERT INTO fw_real_intake_queue(workspace,intake_id,actor,rights_dataset_id,archive_path,archive_sha256,
              archive_bytes,created_utc) VALUES(%s,%s,%s,'pr-rights',%s,%s,%s,clock_timestamp()-%s::interval)''',
        (ws, intake_id, actor, str(path), _sha(data), len(data), age))
    return SimpleNamespace(id=intake_id, path=path, data=data)


def sample(w, ws, age):
    sample_id = str(uuid.uuid4())
    data = _blob('sample-' + sample_id)
    path = write(w.root / '.local' / 'real-data' / 'media' / ws / (sample_id + '.png'), data)
    dba(w, '''INSERT INTO fw_samples(workspace,sample_id,raw_sha256,raw_bytes,pixel_sha256,width,height,format,decoder,
              media_path,source_member,first_batch,created_utc)
              VALUES(%s,%s,%s,%s,%s,8,8,'png','pr-decoder',%s,'member.png',%s,clock_timestamp()-%s::interval)''',
        (ws, sample_id, _sha(data), len(data), _sha(data[::-1]), str(path), str(uuid.uuid4()), age))
    return SimpleNamespace(id=sample_id, path=path, data=data)


def checkpoint(w, ws, actor, age):
    run_id = 'pr-train-' + uuid.uuid4().hex[:12]
    data = _blob('checkpoint-' + run_id)
    path = write(w.root / 'var' / 'runs' / run_id / 'epoch-1.ckpt', data)
    dba(w, '''INSERT INTO fw_runs(id,workspace,actor,idem,digest,config,state) VALUES(%s,%s,%s,%s,%s,%s,'succeeded')''',
        (run_id, ws, actor, run_id, '0' * 64, Jsonb({'scope': 'real-training/v1', 'epochs': 1})))
    dba(w, '''INSERT INTO fw_attempts(id,run,fence,restore_generation)
              VALUES(%s,%s,1,(SELECT restore_generation FROM fw_control WHERE id=1))''', ('att-' + run_id, run_id))
    dba(w, '''INSERT INTO fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES(%s,1,%s,%s,%s,'{}'::jsonb)''',
        (run_id, 'att-' + run_id, _sha(data), str(path)))
    dba(w, '''INSERT INTO fw_events(workspace,run,kind,payload,created)
              VALUES(%s,%s,'epoch_committed',%s,clock_timestamp()-%s::interval)''', (ws, run_id, Jsonb({'epoch': 1}), age))
    return SimpleNamespace(id=run_id, key=run_id + ':1', path=path, data=data)


HOLD = {'legal_hold': True, 'pinned': False, 'reason_code': 'legal_obligation'}
PIN = {'legal_hold': False, 'pinned': True, 'reason_code': 'release_evidence'}


# ------------------------------------------------------------------------------------------------- tests
def test_audit_90d_read_window_preserves_bytes_and_settings_publish_the_frozen_policy(w):
    from fieldwork.privacy_lifecycle import POLICY
    ws, users = workspace(w, 'audit')
    dba(w, '''INSERT INTO fw_workspace_settings_events(workspace,actor,event_type,detail,at_utc) VALUES
              (%s,'pr','settings.updated','{"marker":"inside-90d"}'::jsonb,clock_timestamp()-interval '89 days 23 hours 50 minutes'),
              (%s,'pr','settings.updated','{"marker":"outside-90d"}'::jsonb,clock_timestamp()-interval '90 days 10 minutes')''',
        (ws, ws))
    session(w, users['owner'])
    body = w.client.get(f'/api/v1/workspaces/{ws}/real/settings')
    assert body.status_code == 200, body.text
    body = body.json()
    markers = [e['detail'].get('marker') for e in body['audit']]
    assert 'inside-90d' in markers and 'outside-90d' not in markers
    assert {k: v for k, v in body['privacy_policy'].items() if k != 'preservation'} == POLICY
    assert body['privacy_policy']['preservation'] == 'private_archive_and_tombstone'
    assert set(body['privacy_coverage']) >= {'fresh_inputs', 'staged_intake', 'application_logs', 'event_replay',
                                             'audit', 'dataset_media', 'backups'}
    with as_api(w, ws) as c:  # forced RLS read window for the real request principal
        seen = [r['detail']['marker'] for r in c.execute(
            "SELECT detail FROM fw_workspace_settings_events WHERE detail ? 'marker'").fetchall()]
    assert seen == ['inside-90d']
    kept = dba(w, "SELECT count(*) AS n FROM fw_workspace_settings_events WHERE workspace=%s AND detail ? 'marker'", (ws,), one=True)
    assert kept['n'] == 2  # audit bytes are preserved; only the read window closes


def test_event_replay_7d_boundary_no_longer_serves_older_events(w):
    ws, users = workspace(w, 'events', 'viewer')
    run_id = 'pr-ev-' + uuid.uuid4().hex[:10]
    dba(w, '''INSERT INTO fw_runs(id,workspace,actor,idem,digest,config) VALUES(%s,%s,'pr',%s,%s,%s)''',
        (run_id, ws, run_id, '0' * 64, Jsonb({'scope': 'synthetic-events/v1', 'epochs': 1})))
    seqs = []
    for kind, age in (('queued', '7 days 10 minutes'), ('running', '6 days 23 hours 50 minutes'), ('succeeded', '1 minute')):
        seqs.append(dba(w, '''INSERT INTO fw_events(workspace,run,kind,payload,created)
            VALUES(%s,%s,%s,%s,clock_timestamp()-%s::interval) RETURNING seq''', (ws, run_id, kind, Jsonb({'state': kind}), age), one=True)['seq'])
    old, inside, new = seqs
    session(w, users['viewer'])
    base = f'/api/v1/workspaces/{ws}'
    fresh = w.client.get(base + '/events')
    assert fresh.status_code == 200, fresh.text
    assert [int(r['seq']) for r in fresh.json()['items']] == [inside, new]  # 7d+ event no longer served
    for after in (0, old):
        expired = w.client.get(base + f'/events?after={after}')
        assert expired.status_code == 410 and 'EVENT_CURSOR_EXPIRED_RESNAPSHOT' in expired.text
    sse = w.client.get(base + '/events/stream?replay_only=true', headers={'Last-Event-ID': str(old)})
    assert sse.status_code == 410
    resumed = w.client.get(base + f'/events?after={inside}')
    assert [int(r['seq']) for r in resumed.json()['items']] == [new]
    assert dba(w, 'SELECT count(*) AS n FROM fw_events WHERE workspace=%s', (ws,), one=True)['n'] == 3  # bytes kept


def test_fresh_inference_inputs_24h_boundary_and_legal_hold_exception(w):
    ws, users = workspace(w, 'fresh')
    actor = users['owner']
    kept = fresh_input(w, ws, actor, '23 hours 50 minutes')
    expired = fresh_input(w, ws, actor, '24 hours 10 minutes')
    held = fresh_input(w, ws, actor, '24 hours 10 minutes')
    h = session(w, actor)
    r = w.client.put(f'/api/v1/workspaces/{ws}/real/privacy/fresh-inputs/{held.id}/hold', json=HOLD, headers=h)
    assert r.status_code == 200, r.text
    run_pass(w)
    assert_archived(w, obj(w, 'fresh_inference_input', ws, expired.id), expired.data, expired.path)
    assert dba(w, 'SELECT public.fw_privacy_input_blocked_v1(%s,%s) AS b', (ws, expired.id), one=True)['b'] is True
    assert obj(w, 'fresh_inference_input', ws, kept.id) is None  # just before 24 h: untouched
    assert_live(kept.path, kept.data)
    row = obj(w, 'fresh_inference_input', ws, held.id)
    assert row['legal_hold'] is True and row['state'] == 'active' and row['archive_path'] is None
    assert_live(held.path, held.data)  # explicit legal-hold exception past the window
    # Lineage rows stay; only bytes move to the private archive.
    assert dba(w, 'SELECT count(*) AS n FROM fw_real_image_inputs WHERE workspace=%s', (ws,), one=True)['n'] == 3


def test_abandoned_staging_24h_queue_and_orphan_upload_files(w):
    ws, users = workspace(w, 'stage')
    actor = users['owner']
    kept = intake(w, ws, actor, '23 hours 50 minutes')
    expired = intake(w, ws, actor, '24 hours 10 minutes')
    held = intake(w, ws, actor, '24 hours 10 minutes')
    uploads = w.root / '.local' / 'real-data' / 'uploads'
    orphan_old_data, orphan_new_data = _blob('orphan-old'), _blob('orphan-new')
    orphan_old = write(uploads / ('.upload-' + uuid.uuid4().hex + '.part'), orphan_old_data, 24 * 3600 + 600)
    orphan_new = write(uploads / ('.upload-' + uuid.uuid4().hex + '.part'), orphan_new_data, 24 * 3600 - 600)
    h = session(w, actor)
    r = w.client.put(f'/api/v1/workspaces/{ws}/real/privacy/intakes/{held.id}/hold', json=HOLD, headers=h)
    assert r.status_code == 200, r.text
    run_pass(w)
    assert_archived(w, obj(w, 'abandoned_staging', ws, expired.id), expired.data, expired.path)
    assert obj(w, 'abandoned_staging', ws, kept.id) is None
    assert_live(kept.path, kept.data)
    row = obj(w, 'abandoned_staging', ws, held.id)
    assert row['legal_hold'] is True and row['state'] == 'active'
    assert_live(held.path, held.data)
    assert_archived(w, obj_by_path(w, 'filesystem_staging', orphan_old), orphan_old_data, orphan_old)
    assert obj_by_path(w, 'filesystem_staging', orphan_new) is None
    assert_live(orphan_new, orphan_new_data)


def test_application_logs_30d_and_log_writers_emit_no_image_bytes_or_secrets(w, monkeypatch, capsys):
    logs = w.root / '.local' / 'app-logs'
    var = w.root / 'var'
    line = b'{"code":"PRIVACY_MATRIX_FIXTURE","secret_printed":false}\n'
    old_app = write(logs / 'old-intake-worker-errors.log', line + b'old', 30 * 86400 + 3600)
    new_app = write(logs / 'recent-intake-worker-errors.log', line + b'new', 30 * 86400 - 3600)
    old_api = write(var / 'api-live.log.2026-09-30', b'old api line\n', 30 * 86400 + 3600)
    new_api = write(var / 'api-live.log.2026-10-04', b'new api line\n', 30 * 86400 - 3600)
    unmanaged = write(var / 'unmanaged-console.log', b'not a managed stream\n', 40 * 86400)
    run_pass(w)
    for path in (old_app, old_api):
        data = b'old api line\n' if path == old_api else line + b'old'
        assert_archived(w, obj_by_path(w, 'application_log', path), data, path)
    for path in (new_app, new_api, unmanaged):
        assert obj_by_path(w, 'application_log', path) is None and path.exists()

    # Real intake-worker failure writer: a failure whose input carries a secret records only a fixed code.
    import fieldwork.newintake_worker as NW
    monkeypatch.setattr(NW, 'ROOT', w.root)
    authority = write(w.root / ('authority-' + SECRET + '.json'),
                      ('{"connection":{"password":"' + SECRET + '","image":"' + MARK.decode() + '"').encode())
    assert NW._main(['--authority-file', str(authority)]) == 2
    printed = capsys.readouterr().out
    error_log = (logs / 'intake-worker-errors.log').read_bytes()
    for blob in (printed.encode(), error_log):
        assert SECRET.encode() not in blob and MARK not in blob and str(w.root).encode() not in blob
    for raw in error_log.splitlines():
        entry = json.loads(raw)
        assert set(entry) == {'status', 'code', 'secret_printed'} and entry['secret_printed'] is False
        assert re.fullmatch(r'[A-Z0-9_]{1,64}', entry['code'])
    # Persisted scanner diagnostics are fixed codes only (no paths, exception text or bytes).
    for row in dba(w, 'SELECT last_error_code FROM fw_privacy_objects WHERE last_error_code IS NOT NULL'):
        assert re.fullmatch(r'PRIVACY_[A-Z0-9_]{1,56}', row['last_error_code'])


def test_dataset_media_and_checkpoints_180d_with_pin_hold_and_frozen_version_protection(w):
    ws, users = workspace(w, 'media')
    actor = users['owner']
    young = sample(w, ws, '179 days 23 hours 50 minutes')
    expired = sample(w, ws, '180 days 10 minutes')
    pinned = sample(w, ws, '180 days 10 minutes')
    held = sample(w, ws, '180 days 10 minutes')
    frozen_holdout = sample(w, ws, '180 days 10 minutes')
    frozen_train = sample(w, ws, '180 days 10 minutes')
    manifest = {'scope': 'real-rights-cleared', 'samples': [{'id': frozen_holdout.id, 'split': 'holdout'},
                                                           {'id': frozen_train.id, 'split': 'train'}]}
    dba(w, '''INSERT INTO fw_versions(workspace,id,author,parent_digest,state,manifest)
              VALUES(%s,'pr-frozen',%s,%s,'frozen',%s)''', (ws, actor, '0' * 64, Jsonb(manifest)))
    dba(w, "SELECT public.fw_privacy_seal_version_members_v1(%s,'pr-frozen')", (ws,))
    ck_young = checkpoint(w, ws, actor, '179 days 23 hours 50 minutes')
    ck_old = checkpoint(w, ws, actor, '180 days 10 minutes')
    ck_held = checkpoint(w, ws, actor, '180 days 10 minutes')
    h = session(w, actor)
    base = f'/api/v1/workspaces/{ws}/real'
    for target, body in ((pinned, PIN), (held, HOLD)):
        r = w.client.put(f'{base}/privacy/dataset-samples/{target.id}/hold', json=body, headers=h)
        assert r.status_code == 200, r.text
    r = w.client.put(f'{base}/runs/{ck_held.id}/privacy/hold', json=HOLD, headers=h)
    assert r.status_code == 200, r.text
    run_pass(w)

    assert_archived(w, obj(w, 'dataset_artifact', ws, expired.id), expired.data, expired.path)
    # A train-split member of a frozen version is an ordinary retention class (migration 017 design).
    assert_archived(w, obj(w, 'dataset_artifact', ws, frozen_train.id), frozen_train.data, frozen_train.path)
    for gone in (expired, frozen_train):
        assert dba(w, 'SELECT public.fw_privacy_sample_blocked_v1(%s,%s) AS b', (ws, gone.id), one=True)['b'] is True
    assert obj(w, 'dataset_artifact', ws, young.id) is None
    for keep in (young, pinned, held, frozen_holdout):
        assert_live(keep.path, keep.data)
    assert obj(w, 'dataset_artifact', ws, pinned.id)['pinned'] is True
    assert obj(w, 'dataset_artifact', ws, pinned.id)['state'] == 'active'
    assert obj(w, 'dataset_artifact', ws, held.id)['legal_hold'] is True
    assert obj(w, 'dataset_artifact', ws, held.id)['state'] == 'active'
    protected = dba(w, 'SELECT privacy_protected FROM fw_samples WHERE workspace=%s AND sample_id=%s',
                    (ws, frozen_holdout.id), one=True)['privacy_protected']
    assert protected is True and obj(w, 'dataset_artifact', ws, frozen_holdout.id) is None
    with as_api(w, ws) as c:  # request principal no longer sees archived sample media rows
        visible = {str(r['sample_id']) for r in c.execute('SELECT sample_id FROM fw_samples').fetchall()}
    assert visible == {young.id, pinned.id, held.id, frozen_holdout.id}

    assert_archived(w, obj(w, 'run_artifact', ws, ck_old.key), ck_old.data, ck_old.path)
    assert dba(w, 'SELECT public.fw_privacy_checkpoint_blocked_v1(%s,1) AS b', (ck_old.id,), one=True)['b'] is True
    assert obj(w, 'run_artifact', ws, ck_young.key) is None
    assert_live(ck_young.path, ck_young.data)
    row = obj(w, 'run_artifact', ws, ck_held.key)
    assert row['legal_hold'] is True and row['state'] == 'active'
    assert_live(ck_held.path, ck_held.data)


def _tombstone(w, ws):
    return dba(w, 'SELECT * FROM fw_privacy_workspace_tombstones WHERE workspace=%s', (ws,), one=True)


def test_workspace_deletion_blocks_access_now_archives_live_blobs_within_7d_and_keeps_holds(w):
    L = w.L
    ws, users = workspace(w, 'delete')
    owner = users['owner']
    media, held = sample(w, ws, '1 minute'), sample(w, ws, '1 minute')
    inp = fresh_input(w, ws, owner, '1 minute')
    queued = intake(w, ws, owner, '1 minute')
    h = session(w, owner)
    base = f'/api/v1/workspaces/{ws}/real'
    assert w.client.put(f'{base}/privacy/dataset-samples/{held.id}/hold', json=HOLD, headers=h).status_code == 200
    revision = w.client.get(f'{base}/settings').json()['settings']['revision']
    r = w.client.post(f'{base}/workspace-deletion', json={'expected_revision': revision}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()['access_revoked'] is True and r.json()['sessions_revoked'] is True

    # Live access is blocked immediately: the session, a new login, and every RLS-fenced read.
    assert w.client.get('/auth/session').status_code == 401
    relogin = w.client.post('/auth/session', json={'name': owner, 'password': PASSWORD})
    assert relogin.status_code == 403 and 'WORKSPACE_PRIVACY_TOMBSTONED' in relogin.text
    with as_api(w, ws) as c:
        assert c.execute('SELECT count(*) AS n FROM fw_workspace_settings').fetchone()['n'] == 0
        assert c.execute('SELECT count(*) AS n FROM fw_samples').fetchone()['n'] == 0
        assert c.execute('SELECT count(*) AS n FROM fw_runs').fetchone()['n'] == 0
    tomb = _tombstone(w, ws)
    assert tomb['state'] == 'revoked' and tomb['archive_due_utc'] - tomb['deleted_utc'] == timedelta(days=7)
    ledger = L._read_deletion_tombstone(L._deletion_ledger_path(ws), ws)
    assert ledger['state'] == 'committed' and ledger['request_id'] == str(tomb['request_id'])
    for item in (media, held, inp, queued):  # archive-on-delete: bytes untouched until the scanner moves them
        assert_live(item.path, item.data)

    # Simulated clock: a second workspace whose owner-authorized deletion happened 7 days 1 hour ago.
    late_ws, late_users = workspace(w, 'late')
    late_media = sample(w, late_ws, '8 days')
    late_input = fresh_input(w, late_ws, late_users['owner'], '8 days')
    db_now = dba(w, 'SELECT clock_timestamp() AS t', one=True)['t']
    L.append_deletion_tombstone(late_ws, str(uuid.uuid4()), db_now - timedelta(days=7, hours=1),
                                requested_by=late_users['owner'], expected_revision=1,
                                restore_generation=dba(w, 'SELECT restore_generation::text AS g FROM fw_control WHERE id=1', one=True)['g'])

    for _ in range(6):  # the deletion pass is bounded (2 workspaces x 2 objects per pass)
        result = run_pass(w)
        assert result['workspace_deletions'].get('status') != 'blocked', result['workspace_deletions']
        if _tombstone(w, ws)['state'] == 'archived' and (_tombstone(w, late_ws) or {}).get('state') == 'archived':
            break
    tomb, late = _tombstone(w, ws), _tombstone(w, late_ws)
    diagnostics = [(r['workspace'][-14:], r['object_key'].split(':')[0], r['state'], r['last_error_code'], r['live_bytes_retired'],
                    r['legal_hold']) for r in dba(w, '''SELECT * FROM fw_privacy_objects WHERE object_kind='workspace_deleted_blob'
                    AND workspace IN (%s,%s) ORDER BY workspace,object_key''', (ws, late_ws))]
    (w.root / 'deletion-diagnostics.json').write_text(json.dumps(
        {'tomb': dict(tomb), 'late': dict(late), 'objects': diagnostics, 'outputs': w.outputs[-3:]}, default=str, indent=1))
    assert tomb['state'] == 'archived', (dict(tomb), dict(late), diagnostics, w.outputs[-1])
    assert late['state'] == 'archived', (dict(late), diagnostics)
    assert tomb['state'] == 'archived' and tomb['updated_utc'] <= tomb['archive_due_utc']  # within 7 days
    assert late['state'] == 'archived' and late['archive_due_utc'] < late['updated_utc']  # overdue backlog drains
    assert late['deleted_utc'] == db_now - timedelta(days=7, hours=1)
    blob = lambda space, key: obj(w, 'workspace_deleted_blob', space, key)
    assert_archived(w, blob(ws, 'dataset_media:' + media.id), media.data, media.path)
    assert_archived(w, blob(ws, 'fresh_input:' + inp.id), inp.data, inp.path)
    assert_archived(w, blob(ws, 'intake:' + queued.id), queued.data, queued.path)
    assert_archived(w, blob(late_ws, 'dataset_media:' + late_media.id), late_media.data, late_media.path)
    assert_archived(w, blob(late_ws, 'fresh_input:' + late_input.id), late_input.data, late_input.path)
    # The 8-day-old input had already left live storage under its own 24 h class; deletion records that
    # archive instead of a permanent PRIVACY_SOURCE_NOT_PRESENT recovery state.
    prior = obj(w, 'fresh_inference_input', late_ws, late_input.id)
    assert prior['state'] == 'archived' and blob(late_ws, 'fresh_input:' + late_input.id)['archive_path'] == prior['archive_path']
    kept = blob(ws, 'dataset_media:' + held.id)  # legal hold: private copy made, live bytes explicitly retained
    assert kept['legal_hold'] is True and kept['state'] == 'archived' and kept['live_bytes_retired'] is False
    assert _sha((w.root / kept['archive_path']).read_bytes()) == _sha(held.data)
    assert_live(held.path, held.data)
    # Catalog rows are preserved for audit; only access and live bytes are removed.
    assert dba(w, 'SELECT count(*) AS n FROM fw_samples WHERE workspace=%s', (ws,), one=True)['n'] == 2


def test_backup_ledger_30d_expiry_and_restore_reapplies_the_tombstone(w):
    L = w.L
    snapshots = w.root / 'var' / 'snapshots'
    snapshots.mkdir(mode=0o700)
    db_now = dba(w, 'SELECT clock_timestamp() AS t', one=True)['t'].astimezone(timezone.utc)
    snaps = {}
    for label, age in (('old', timedelta(days=30, hours=1)), ('recent', timedelta(days=29, hours=23))):
        at = (db_now - age).strftime('%Y%m%dT%H%M%SZ')
        base = snapshots / f'pr-{label}-{at}'
        ledger = L.export_deletion_ledger(Path(str(base) + '-privacy-deletions'))  # as tools/r5p_backup.py
        files = {}
        for kind, suffix in (('db', '.dump'), ('globals', '-globals.sql')):
            data = os.urandom(256)
            path = write(Path(str(base) + suffix), data)
            files[kind] = {'path': path.relative_to(w.root).as_posix(), 'bytes': len(data), 'sha256': _sha(data)}
        receipt = {'container': 'fieldwork-pg-verify', 'database': 'pr', 'at': at, 'privacy_deletion_ledger': ledger, **files}
        receipt_path = write(Path(str(base) + '.json'), json.dumps(receipt, indent=2).encode())
        package = w.root / ledger['path']
        snaps[label] = SimpleNamespace(at=at, receipt=receipt, receipt_path=receipt_path, package=package,
                                       paths=[w.root / files['db']['path'], w.root / files['globals']['path'],
                                              receipt_path, *sorted(package.iterdir())])
    assert receipt['privacy_deletion_ledger']['file_count'] >= 2  # both deleted workspaces are in the ledger
    for _ in range(3):
        run_pass(w)
        if all((obj_by_path(w, 'backup_artifact', p) or {}).get('state') == 'archived' for p in snaps['old'].paths):
            break
    for path in snaps['old'].paths:
        row = obj_by_path(w, 'backup_artifact', path)
        assert row is not None, path.name
        assert row['expires_utc'] - row['created_utc'] == timedelta(days=30)
        assert row['created_utc'].astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ') == snaps['old'].at  # receipted, not mtime fallback
        assert row['state'] == 'archived' and row['live_bytes_retired'] is True, dict(row)
        assert not path.exists() and (w.root / row['archive_path']).is_file()
    db_row = obj_by_path(w, 'backup_artifact', snaps['old'].paths[0])
    assert db_row['expected_sha256'] == snaps['old'].receipt['db']['sha256'] == db_row['content_sha256']
    manifest = json.loads((w.root / obj_by_path(w, 'backup_artifact', snaps['old'].package / 'manifest.json')['archive_path']).read_bytes())
    for entry in manifest['files']:  # each ledger entry is carried with its 30-day backup expiry and digest
        row = obj_by_path(w, 'backup_artifact', snaps['old'].package / entry['name'])
        assert row['expected_sha256'] == entry['sha256'] == row['content_sha256']
    for path in snaps['recent'].paths:  # just before 30 days: registered with a future expiry, still live
        row = obj_by_path(w, 'backup_artifact', path)
        assert row is not None and row['state'] == 'active' and path.exists()
        assert row['expires_utc'] - row['created_utc'] == timedelta(days=30)

    # Restore of a database that predates the deletion: the tombstone is gone until the ledger is applied.
    deleted_ws = 'pr-delete-' + TAG
    before = _tombstone(w, deleted_ws)
    dba(w, 'DELETE FROM fw_privacy_workspace_tombstones WHERE workspace=%s', (deleted_ws,))
    assert dba(w, 'SELECT public.fw_privacy_workspace_deleted_v1(%s) AS d', (deleted_ws,), one=True)['d'] is False
    applied = L.verify_apply_deletion_ledger(w.chain.dba, snaps['recent'].package)
    assert applied['status'] == 'verified_and_applied' and applied['restored_tombstones'] == 1
    after = _tombstone(w, deleted_ws)
    assert (after['request_id'], after['deleted_utc'], after['archive_due_utc']) == (
        before['request_id'], before['deleted_utc'], before['archive_due_utc'])
    with as_api(w, deleted_ws) as c:
        assert c.execute('SELECT count(*) AS n FROM fw_workspace_settings').fetchone()['n'] == 0
    relogin = w.client.post('/auth/session', json={'name': deleted_ws + '-owner', 'password': PASSWORD})
    assert relogin.status_code == 403


def test_scanner_output_and_managed_api_log_contain_no_image_bytes_paths_or_secrets(w):
    logging.getLogger('uvicorn.error').info('privacy-matrix canary %s', TAG)  # proves the managed handler is live
    for h in logging.getLogger('uvicorn.error').handlers:
        h.flush()
    api_log = w.log_path.read_bytes()
    assert ('privacy-matrix canary ' + TAG).encode() in api_log
    passwords = {PASSWORD, conninfo_to_dict(w.chain.request.dsn).get('password'), conninfo_to_dict(w.chain.dba.dsn).get('password')}
    forbidden = [MARK, SECRET.encode(), *(p.encode() for p in passwords if p), *(s.encode() for s in w.secrets if s)]
    assert w.outputs, 'scanner passes ran'
    scanner = '\n'.join(w.outputs).encode()
    for blob in (api_log, scanner):
        for item in forbidden:
            assert item not in blob
    for text in w.outputs:  # no live paths and no workspace names in the printed pass summary
        assert str(w.root) not in text and str(w.root).replace('\\', '\\\\') not in text
        assert not any(ws in text for ws in w.workspaces)
