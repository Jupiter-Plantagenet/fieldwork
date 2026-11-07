"""Scoped worker machine identity (round 5) on REAL PostgreSQL.

Proves, as the real scoped login over a password-authenticated TCP connection:
* the worker can do its job: ML-Claim (leased) -> ML-Start -> heartbeat -> checkpoint commit
  -> complete, with idempotent replay of internal commands;
* it cannot read other tenants: out-of-scope runs are invisible to every function, and the
  login has no SELECT/INSERT/UPDATE/DELETE on any public table;
* it cannot bypass the fence: direct DML is denied; stale fence, wrong attempt, wrong
  restore generation and a forged credential are refused;
* an expired credential is refused: an expired attempt credential (function refusal) and an
  expired login password (server refuses authentication).
"""
import json, secrets, uuid
from pathlib import Path
import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

SOURCE = Path(__file__).resolve().parents[1] / 'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'


@pytest.fixture
def scoped(isolated_store, tmp_path):
    from fieldwork import worker_identity as WI
    s = isolated_store
    login = 'fw_worker_t' + uuid.uuid4().hex[:10]
    s.extra_roles = getattr(s, 'extra_roles', []) + [login, login + '_definer']
    mine, other = 'p5-ws-' + uuid.uuid4().hex[:6], 'p5-other-' + uuid.uuid4().hex[:6]
    password = secrets.token_urlsafe(32)
    from tests.isolated_api import provision_request_principal
    provision_request_principal(s)  # retained shape: FORCE RLS + request principal installed
    with s.connect() as c:
        WI.provision(c, login, password, [mine])
    d = conninfo_to_dict(s.dsn)
    authority = {'authority_mode': WI.MODE, 'connection': {'host': '127.0.0.1', 'port': int(d['port']), 'dbname': d['dbname'],
                 'user': login, 'password': password, 'sslmode': 'disable'}, 'workspaces': [mine]}
    path = tmp_path / ('private-' + uuid.uuid4().hex[:6]) / 'worker-authority.json'
    WI.write_authority(path, authority)
    w = WI.WorkerStore(path); w.blob_root = tmp_path / 'blobs'
    meta = json.loads((SOURCE / 'state.json').read_text())
    cfg = {'epochs': 1, 'dataset_digest': meta['dataset_digest'], 'scope': 'synthetic-execution-only', 'recipe': 'compact-cnn/v1', 'seed': meta['seed']}
    yield dict(s=s, w=w, WI=WI, login=login, mine=mine, other=other, cfg=cfg, meta=meta, path=path, authority=authority)
    with s.connect() as c:  # roles are dropped by isolated_store teardown after the DB
        c.execute(sql.SQL('ALTER ROLE {} NOLOGIN').format(sql.Identifier(login)))


def metrics(meta):
    return {k: meta[k] for k in ['epoch', 'train_loss', 'validation_loss', 'updates']}


def test_scoped_worker_does_its_job_with_idempotent_internal_commands(scoped):
    s, w, cfg, meta = scoped['s'], scoped['w'], scoped['cfg'], scoped['meta']
    r = s.submit(scoped['mine'], 'alice', str(uuid.uuid4()), cfg)
    with s.connect() as c:
        report = scoped['WI'].verify(c, scoped['login'], [scoped['mine']])
    assert report['verified'] and report['functions'] == len(scoped['WI'].W.FUNCTIONS)
    assert w.next_run([])['id'] == r['id']
    key = str(uuid.uuid4())
    a = w.claim(r['id'], r['cancel_generation'], start=False, worker_id='w1', key=key)
    assert a['state'] == 'leased' and a['fence'] == 1 and uuid.UUID(a['restore_generation'])
    again = w.claim(r['id'], r['cancel_generation'], start=False, worker_id='w1', key=key)  # response lost: replay
    assert again['attempt'] == a['attempt'] and again['fence'] == a['fence']
    scope = dict(attempt=a['attempt'], restore_generation=a['restore_generation'])
    started = w.start(r['id'], a['attempt'], a['fence'], 0, a['digest'], restore_generation=a['restore_generation'], key=str(uuid.uuid4()))
    assert started['state'] == 'running'
    hb = str(uuid.uuid4())
    first = w.heartbeat(r['id'], a['fence'], 0, key=hb, **scope); second = w.heartbeat(r['id'], a['fence'], 0, key=hb, **scope)
    assert first['lease_expires_at'] == second['lease_expires_at']  # same key replays the receipt
    pk = str(uuid.uuid4())
    w.publish(r['id'], a['fence'], 0, SOURCE, metrics(meta), key=pk, **scope)
    w.publish(r['id'], a['fence'], 0, SOURCE, metrics(meta), key=pk, **scope)  # replay, no duplicate
    with s.connect() as c:
        assert c.execute('SELECT count(*) n FROM fw_checkpoints WHERE run=%s', (r['id'],)).fetchone()['n'] == 1
        receipts = c.execute('SELECT command,actor FROM fw_command_receipts WHERE run=%s ORDER BY created', (r['id'],)).fetchall()
    assert [x['command'] for x in receipts] == ['ML-Claim', 'ML-Start', 'ML-Heartbeat', 'ML-CheckpointCommit'] and {x['actor'] for x in receipts} == {scoped['login']}
    done = w.complete(r['id'], a['fence'], 0, {'best': {'epoch': 1}}, key=str(uuid.uuid4()), **scope)
    assert done['state'] == 'succeeded'
    with s.connect() as c:
        kinds = [e['kind'] for e in c.execute("SELECT kind FROM fw_events WHERE run=%s AND kind<>'command_receipt' ORDER BY seq", (r['id'],)).fetchall()]
        attempt = c.execute('SELECT restore_generation,worker_id,started_at,ended_at FROM fw_attempts WHERE id=%s', (a['attempt'],)).fetchone()
        creds = c.execute('SELECT count(*) n FROM fw_worker_cap_v1.credentials WHERE attempt=%s', (a['attempt'],)).fetchone()['n']
    assert kinds == ['queued', 'claimed', 'started', 'epoch_committed', 'succeeded', 'artifact_pending']
    assert str(attempt['restore_generation']) == a['restore_generation'] and attempt['worker_id'] == scoped['login'] + ':w1' and attempt['started_at'] and attempt['ended_at']
    assert creds == 0  # attempt credential revoked at completion


def test_scoped_worker_cannot_read_other_tenants(scoped):
    s, w, cfg = scoped['s'], scoped['w'], scoped['cfg']
    theirs = s.submit(scoped['other'], 'bob', str(uuid.uuid4()), cfg)
    assert w.get(theirs['id']) is None and w.next_run([]) is None
    from fieldwork.store import Conflict
    with pytest.raises(Conflict, match='NOT_QUEUED_OR_SLOT_BUSY'):
        w.claim(theirs['id'], 0, start=False, worker_id='w1')
    with w.connect() as c:
        for table in ['fw_runs', 'fw_events', 'fw_attempts', 'fw_checkpoints', 'fw_accounts', 'fw_sessions', 'fw_slot', 'fw_command_receipts', 'fw_worker_cap_v1.credentials', 'fw_worker_cap_v1.scope']:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute('SELECT 1 FROM ' + ('public.' + table if '.' not in table else table) + ' LIMIT 1')
        # A tenant GUC does not widen the capability (restrictive policy on the definer).
        c.execute("SELECT set_config('fieldwork.workspace',%s,false)", (scoped['other'],))
        assert c.execute('SELECT fw_worker_cap_v1.get_run(%s) v', (theirs['id'],)).fetchone()['v'] is None
        # Internal helpers are not callable by the login.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with c.transaction():
                c.execute("SELECT fw_worker_cap_v1.check_live('x',%s,'a',1,0,NULL,ARRAY['running'],'F','F')", (theirs['id'],))


def test_scoped_worker_cannot_bypass_the_fence(scoped):
    s, w, cfg, meta = scoped['s'], scoped['w'], scoped['cfg'], scoped['meta']
    from fieldwork.store import Conflict, CancelGenerationConflict
    r = s.submit(scoped['mine'], 'alice', str(uuid.uuid4()), cfg)
    a = w.claim(r['id'], 0, start=True, worker_id='w1')
    scope = dict(attempt=a['attempt'], restore_generation=a['restore_generation'])
    with w.connect() as c:
        for stmt in ["UPDATE public.fw_runs SET lease=now()+interval '1 hour'", "UPDATE public.fw_runs SET state='running'",
                     "INSERT INTO public.fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES('x',1,'x','x','x','{}')",
                     "DELETE FROM public.fw_events", "UPDATE public.fw_slot SET run=NULL"]:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute(stmt)
    with pytest.raises(Conflict, match='FENCED_OR_EXPIRED'):
        w.heartbeat(r['id'], a['fence'] - 1, 0, **scope)
    # Another attempt id: the credential is bound to the attempt, so it is refused first.
    with pytest.raises(Conflict, match='CREDENTIAL_EXPIRED_OR_INVALID'):
        w.heartbeat(r['id'], a['fence'], 0, attempt=str(uuid.uuid4()), restore_generation=a['restore_generation'])
    with pytest.raises(Conflict, match='RESTORE_GENERATION_FENCED'):
        w.heartbeat(r['id'], a['fence'], 0, attempt=a['attempt'], restore_generation=str(uuid.uuid4()))
    real = w._tokens[a['attempt']]
    w._tokens[a['attempt']] = 'forged-' + secrets.token_hex(16)
    with pytest.raises(Conflict, match='CREDENTIAL_EXPIRED_OR_INVALID'):
        w.heartbeat(r['id'], a['fence'], 0, **scope)
    w._tokens[a['attempt']] = real
    # A browser cancel fences the worker; the typed refusal names the generation to acknowledge.
    s.cancel(scoped['mine'], r['id'])
    with pytest.raises(CancelGenerationConflict) as exc:
        w.heartbeat(r['id'], a['fence'], 0, **scope)
    assert (exc.value.state, exc.value.current_generation) == ('cancel_requested', 1)
    with pytest.raises(Conflict):  # refused before any blob is written
        w.publish(r['id'], a['fence'], 0, SOURCE, metrics(meta), **scope)
    assert not w.blob_root.exists() or not any(w.blob_root.iterdir())
    with s.connect() as c:
        assert c.execute('SELECT count(*) n FROM fw_checkpoints WHERE run=%s', (r['id'],)).fetchone()['n'] == 0


def test_expired_credentials_are_refused(scoped):
    s, w, cfg = scoped['s'], scoped['w'], scoped['cfg']
    from fieldwork.store import Conflict
    r = s.submit(scoped['mine'], 'alice', str(uuid.uuid4()), cfg)
    a = w.claim(r['id'], 0, start=True, worker_id='w1')
    scope = dict(attempt=a['attempt'], restore_generation=a['restore_generation'])
    with s.connect() as c:  # operator ages the attempt credential past its 5-minute lifetime
        c.execute("UPDATE fw_worker_cap_v1.credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE attempt=%s", (a['attempt'],))
    with pytest.raises(Conflict, match='CREDENTIAL_EXPIRED_OR_INVALID'):
        w.heartbeat(r['id'], a['fence'], 0, **scope)
    # Login password lifetime: the server refuses authentication once VALID UNTIL passes.
    with s.connect() as c:
        c.execute(sql.SQL("ALTER ROLE {} VALID UNTIL '2000-01-01T00:00:00Z'").format(sql.Identifier(scoped['login'])))
    with pytest.raises(psycopg.OperationalError):
        w.connect().close()
    # Rotation restores access with a fresh <=5 min password; >5 min is rejected.
    with pytest.raises(ValueError, match='5_MINUTES'):
        scoped['WI']._until(301)
    with s.connect() as c:
        new = scoped['WI'].rotate(c, scoped['login'], 60)
        until = c.execute('SELECT rolvaliduntil-now() AS left FROM pg_roles WHERE rolname=%s', (scoped['login'],)).fetchone()['left']
    assert until.total_seconds() <= 60
    auth = dict(scoped['authority'], connection=dict(scoped['authority']['connection'], password=new))
    scoped['WI'].write_authority(scoped['path'], auth)
    w.connect().close()
    with s.connect() as c:
        out = scoped['WI'].revoke(c, scoped['login'])
    assert out['revoked']
    with pytest.raises(psycopg.OperationalError):
        w.connect().close()


def test_worker_loop_runs_under_scoped_identity_until_resource_gate(scoped, monkeypatch, tmp_path):
    """worker.main with FIELDWORK_WORKER_AUTHORITY: selects only in-scope work through the
    capability and refuses at the unchanged resource gate (no claim)."""
    import types
    from fieldwork import worker, worker_heartbeat
    s = scoped['s']
    r = s.submit(scoped['mine'], 'alice', str(uuid.uuid4()), scoped['cfg'])
    monkeypatch.setenv('FIELDWORK_WORKER_AUTHORITY', str(scoped['path']))
    monkeypatch.delenv('FIELDWORK_HOST_HEAVY_LOCK', raising=False)
    monkeypatch.setattr(worker, 'ROOT', tmp_path)
    # The heartbeat marker moved to fieldwork.worker_heartbeat (own ROOT, refuses to overwrite a LIVE
    # worker's var/worker.json); redirect it so this test neither collides with a running worker nor
    # leaves the marker outside tmp_path.
    monkeypatch.setattr(worker_heartbeat, 'ROOT', tmp_path)
    monkeypatch.setattr(worker, 'preflight', lambda **kwargs: (False, {'code': 'RESOURCE_PREFLIGHT'}))
    monkeypatch.setattr(worker.sys, 'argv', ['worker', '--once'])
    assert worker.main() == 23
    beat = json.loads((tmp_path / 'var/worker.json').read_text())
    assert beat['identity'] == 'scoped-worker-v1' and beat['create_time']
    assert s.get(r['id'])['state'] == 'queued'


def test_operator_pause_keeps_scoped_worker_alive_without_claim(scoped, monkeypatch, tmp_path):
    from fieldwork import worker, worker_heartbeat
    s=scoped['s'];r=s.submit(scoped['mine'],'alice',str(uuid.uuid4()),scoped['cfg'])
    marker=tmp_path/'training.pause';marker.write_text('coordinator heavy window pending')
    monkeypatch.setenv('FIELDWORK_WORKER_AUTHORITY',str(scoped['path']))
    monkeypatch.setenv('FIELDWORK_TRAINING_PAUSE_FILE',str(marker))
    monkeypatch.setattr(worker,'ROOT',tmp_path)
    monkeypatch.setattr(worker_heartbeat,'ROOT',tmp_path)  # see the scoped-identity loop test above
    monkeypatch.setattr(worker,'preflight',lambda:(_ for _ in ()).throw(AssertionError('no heavy admission while paused')))
    monkeypatch.setattr(worker.sys,'argv',['worker','--once'])
    assert worker.main()==28
    beat=json.loads((tmp_path/'var/worker.json').read_text())
    assert beat['identity']=='scoped-worker-v1' and beat['operator_paused'] is True
    assert s.get(r['id'])['state']=='queued' and s.get(r['id'])['attempt'] is None
    marker.unlink();assert worker.operator_paused() is False


def test_pause_marker_permission_error_is_fail_closed(monkeypatch,tmp_path):
    from fieldwork import worker
    marker=tmp_path/'pause';monkeypatch.setenv('FIELDWORK_TRAINING_PAUSE_FILE',str(marker))
    monkeypatch.setattr(worker.Path,'stat',lambda self:(_ for _ in ()).throw(PermissionError()))
    assert worker.operator_paused() is True


def test_request_principal_cannot_rewrite_execution_authority(isolated_store):
    """Review F5: column grants + fw_runs_guard. The browser principal can perform only
    cancel/resume transitions; lease, fence rollback, generation reset and revival fail."""
    from tests.isolated_api import provision_request_principal
    from fieldwork.store import TENANT
    s = isolated_store; ws = 'p5-guard-' + uuid.uuid4().hex[:6]
    api = provision_request_principal(s)
    r = s.submit(ws, 'alice', str(uuid.uuid4()), {'epochs': 1})
    a = s.claim(r['id'])
    token = TENANT.set(ws)
    try:
        with api.connect() as c:
            for stmt, args in [("UPDATE fw_runs SET lease=now()+interval '1 hour' WHERE id=%s", (r['id'],)),
                               ("UPDATE fw_runs SET fence=0 WHERE id=%s", (r['id'],)),
                               ("UPDATE fw_runs SET state='succeeded',revision=revision+1 WHERE id=%s", (r['id'],)),
                               ("UPDATE fw_runs SET epoch=5 WHERE id=%s", (r['id'],)),
                               ("UPDATE fw_runs SET cancel_generation=NULL WHERE id=%s", (r['id'],))]:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    with c.transaction():
                        c.execute(stmt, args)
        status, body = api.cancel_command(ws, 'alice', str(uuid.uuid4()), r['id'], s.get(r['id'])['revision'], 'P5 guard check')
        assert status == 200 and json.loads(body)['state'] == 'cancel_requested'
        with api.connect() as c:  # cancel_requested -> running revival is refused
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute("UPDATE fw_runs SET state='running',fence=fence+1,revision=revision+1,cancel_generation=cancel_generation+1 WHERE id=%s", (r['id'],))
    finally:
        TENANT.reset(token)
    after = s.get(r['id'])
    assert after['state'] == 'cancel_requested' and after['cancel_generation'] == 1 and after['fence'] == a['fence'] + 1
