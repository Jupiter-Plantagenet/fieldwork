"""ML-T-FENCE, stale-writer part, on current source.

Frozen pass condition (this lane): a stale fence cannot renew, commit or complete; competing claims yield
one live heavy-slot owner; attempts are immutable; at most 3 attempts / 2 infrastructure retries.
(Heartbeat cadence and 'expiry marked within 10 s of lease end' belong to the lease-recovery controller
tests and are not covered here.)

Both implementations are exercised on the real isolated PostgreSQL: `fieldwork.store.Store` (owner path
used by the supervised worker today) and the scoped `WorkerStore` SQL capability functions
(`fw_worker_cap_v1.*`) under a real non-owner login.
"""
import concurrent.futures
import json
import threading
import uuid

import psycopg
import pytest

from fieldwork.store import CancelGenerationConflict, Conflict, ROOT, Store
from tests.matrix_support import code_of
from tests.test_worker_identity import metrics as scoped_metrics, scoped  # noqa: F401  (fixture)

SOURCE = ROOT / 'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'
META = json.loads((SOURCE / 'state.json').read_text())
METRICS = {k: META[k] for k in ['epoch', 'train_loss', 'validation_loss', 'updates']}
RESULT = json.loads((SOURCE.parent / 'result.json').read_text())
DIAG = 'd' * 64
W = 'fmatrix'


def submit(s, epochs=1, workspace=W):
    return s.submit(workspace, 'a', str(uuid.uuid4()), {'epochs': epochs, 'dataset_digest': META['dataset_digest'], 'scope': 'synthetic-execution-only'})


def scope_of(a):
    return dict(attempt=a['attempt'], restore_generation=a.get('restore_generation'))


def next_attempt(s, rid, workspace, previous, replay_epoch):
    """Release the previous attempt's physical slot (no child), requeue through resume, claim a new attempt."""
    s.release_slot(rid, fence=previous['fence'])
    s.resume(workspace, rid, replay_epoch)
    return s.claim(rid)


def attempts(s, rid):
    with s.connect() as c:
        return c.execute('SELECT * FROM fw_attempts WHERE run=%s ORDER BY fence', (rid,)).fetchall()


# ----------------------------------------------------------- stale writer (Store)
def test_stale_fence_cannot_renew_commit_or_complete_after_expiry_and_reclaim(isolated_store):
    s = isolated_store
    r = submit(s)
    rid = r['id']
    a1 = s.claim(rid)
    hb_key, pub_key, done_key = (str(uuid.uuid4()) for _ in range(3))
    s.heartbeat(rid, a1['fence'], a1['cancel_generation'], key=hb_key, **scope_of(a1))
    s.publish(rid, a1['fence'], a1['cancel_generation'], SOURCE, METRICS, key=pub_key, **scope_of(a1))
    s.expire_for_test(rid)  # lease lapses: fence revoked, interrupted
    assert s.get(rid)['state'] == 'interrupted' and s.get(rid)['fence'] > a1['fence']
    # (1) stale writer after expiry, before any re-claim: renew / commit / complete / fail all refused
    for op in (lambda: s.heartbeat(rid, a1['fence'], a1['cancel_generation'], **scope_of(a1)),
               lambda: s.publish(rid, a1['fence'], a1['cancel_generation'], SOURCE, METRICS, **scope_of(a1)),
               lambda: s.complete(rid, a1['fence'], a1['cancel_generation'], RESULT, **scope_of(a1)),
               lambda: s.fail(rid, a1['attempt'], a1['fence'], 'STALE', True, DIAG)):
        with pytest.raises(Conflict):
            op()
    assert s.get(rid)['state'] == 'interrupted'
    a2 = next_attempt(s, rid, W, a1, replay_epoch=2)
    assert a2['state'] == 'running' and a2['fence'] > a1['fence'] and a2['attempt'] != a1['attempt']
    before = s.get(rid)
    # (2) the run is running again: the old attempt's old fence is still refused, with and without the saved keys
    for op in (lambda: s.heartbeat(rid, a1['fence'], a1['cancel_generation'], key=hb_key, **scope_of(a1)),
               lambda: s.publish(rid, a1['fence'], a1['cancel_generation'], SOURCE, METRICS, key=pub_key, **scope_of(a1)),
               lambda: s.complete(rid, a1['fence'], a1['cancel_generation'], RESULT, key=done_key, **scope_of(a1)),
               lambda: s.fail(rid, a1['attempt'], a1['fence'], 'STALE', False, DIAG),
               # mixed credentials: old attempt id with the new fence, new attempt id with the old fence
               lambda: s.heartbeat(rid, a2['fence'], a2['cancel_generation'], attempt=a1['attempt'], restore_generation=a1['restore_generation']),
               lambda: s.complete(rid, a2['fence'], a2['cancel_generation'], RESULT, attempt=a1['attempt'], restore_generation=a1['restore_generation']),
               lambda: s.heartbeat(rid, a1['fence'], a1['cancel_generation'], attempt=a2['attempt'], restore_generation=a2['restore_generation']),
               lambda: s.complete(rid, a1['fence'], a1['cancel_generation'], RESULT, attempt=a2['attempt'], restore_generation=a2['restore_generation'])):
        with pytest.raises(Conflict):
            op()
    after = s.get(rid)
    for k in ('state', 'fence', 'revision', 'epoch', 'checkpoint', 'attempt', 'lease', 'result'):
        assert after[k] == before[k], k  # nothing the stale writer sent changed the current attempt's run
    assert len(s.checkpoints(rid)) == 1
    # (3) only the current fence completes
    s.heartbeat(rid, a2['fence'], a2['cancel_generation'], **scope_of(a2))
    assert s.complete(rid, a2['fence'], a2['cancel_generation'], RESULT, **scope_of(a2))['state'] == 'succeeded'
    with pytest.raises(Conflict):  # and after completion the stale writer is still refused
        s.complete(rid, a1['fence'], a1['cancel_generation'], RESULT, **scope_of(a1))
    s.release_slot(rid)


def test_stale_writer_after_cancel_gets_a_typed_refusal_and_cannot_commit(isolated_store):
    s = isolated_store
    r = submit(s)
    a = s.claim(r['id'])
    try:
        s.cancel(W, r['id'])
        for op in (lambda: s.heartbeat(r['id'], a['fence'], a['cancel_generation'], **scope_of(a)),
                   lambda: s.publish(r['id'], a['fence'], a['cancel_generation'], SOURCE, METRICS, **scope_of(a)),
                   lambda: s.complete(r['id'], a['fence'], a['cancel_generation'], RESULT, **scope_of(a))):
            with pytest.raises(CancelGenerationConflict) as e:
                op()
            assert e.value.code == 'CANCEL_GENERATION_FENCED' and e.value.state == 'cancel_requested'
        assert s.checkpoints(r['id']) == [] and s.get(r['id'])['result'] is None
    finally:
        s.release_slot(r['id'])


# --------------------------------------------------------------- competing claims
def test_competing_claims_on_one_run_produce_one_attempt(isolated_store):
    s = isolated_store
    rid = submit(s)['id']
    n = 6
    barrier = threading.Barrier(n)

    def claim(i):
        st = Store(dsn=s.dsn)
        barrier.wait(timeout=20)
        try:
            return st.claim(rid, start=False, worker_id='w%d' % i)['attempt']
        except Conflict as exc:
            return str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(claim, range(n)))
    wins = [x for x in results if x != 'NOT_QUEUED_OR_SLOT_BUSY']
    assert len(wins) == 1 and results.count('NOT_QUEUED_OR_SLOT_BUSY') == n - 1, results
    assert [x['id'] for x in attempts(s, rid)] == wins
    assert s.get(rid)['fence'] == 1 and s.get(rid)['state'] == 'leased'
    s.release_slot(rid)


def test_competing_claims_on_different_runs_share_one_physical_slot(isolated_store):
    s = isolated_store
    rids = [submit(s)['id'] for _ in range(4)]
    barrier = threading.Barrier(len(rids))

    def claim(rid):
        st = Store(dsn=s.dsn)
        barrier.wait(timeout=20)
        try:
            return rid, st.claim(rid, start=False)['fence']
        except Conflict as exc:
            return rid, str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(rids)) as pool:
        results = list(pool.map(claim, rids))
    winners = [rid for rid, out in results if isinstance(out, int)]
    assert len(winners) == 1 and [out for _, out in results if not isinstance(out, int)] == ['NOT_QUEUED_OR_SLOT_BUSY'] * 3
    with s.connect() as c:
        assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run'] == winners[0]
        assert c.execute("SELECT count(*) n FROM fw_runs WHERE state IN ('leased','running')").fetchone()['n'] == 1
        assert c.execute('SELECT count(*) n FROM fw_attempts').fetchone()['n'] == 1
    s.release_slot(winners[0])


# ---------------------------------------------------------------- immutable attempts
def test_attempt_rows_are_immutable_after_the_attempt_ends(isolated_store):
    s = isolated_store
    r = submit(s, epochs=2)
    rid = r['id']
    a1 = s.claim(rid)
    s.publish(rid, a1['fence'], a1['cancel_generation'], SOURCE, METRICS, **scope_of(a1))
    assert s.fail(rid, a1['attempt'], a1['fence'], 'WORKER_INFRASTRUCTURE_FAILED', True, DIAG)['state'] == 'interrupted'
    first = {x['id']: dict(x) for x in attempts(s, rid)}
    ended = first[a1['attempt']]['ended_at']
    assert ended is not None
    a2 = next_attempt(s, rid, W, a1, replay_epoch=2)
    # a late duplicate/stale fail from attempt 1 is refused and cannot rewrite it
    with pytest.raises(Conflict):
        s.fail(rid, a1['attempt'], a1['fence'], 'LATE', False, DIAG)
    with pytest.raises(Conflict):
        s.complete(rid, a1['fence'], a1['cancel_generation'], RESULT, **scope_of(a1))
    now = {x['id']: dict(x) for x in attempts(s, rid)}
    assert now[a1['attempt']] == first[a1['attempt']], 'ended attempt row changed'
    assert len(now) == 2 and now[a2['attempt']]['fence'] > now[a1['attempt']]['fence']
    # (run, fence) is unique and attempt ids are never reused
    with s.connect() as c, pytest.raises(psycopg.errors.UniqueViolation):
        c.execute('INSERT INTO fw_attempts(id,run,fence) VALUES(%s,%s,%s)', (str(uuid.uuid4()), rid, a1['fence']))
    with s.connect() as c, pytest.raises(psycopg.errors.UniqueViolation):
        c.execute('INSERT INTO fw_attempts(id,run,fence) VALUES(%s,%s,%s)', (a1['attempt'], rid, 999))
    assert a1['attempt'] != a2['attempt'] and uuid.UUID(a2['attempt'])
    s.release_slot(rid)


# ------------------------------------------------- max 3 attempts / 2 infra retries
def drive_failures(s, rid, workspace, retryable_flags):
    """Claim -> (publish epoch 1 once) -> fail, repeated; returns the per-attempt resulting states."""
    states = []
    a = s.claim(rid)
    s.publish(rid, a['fence'], a['cancel_generation'], SOURCE, METRICS, **scope_of(a))
    for i, retryable in enumerate(retryable_flags):
        states.append(s.fail(rid, a['attempt'], a['fence'], 'WORKER_INFRASTRUCTURE_FAILED', retryable, DIAG)['state'])
        if states[-1] != 'interrupted':
            break
        a = next_attempt(s, rid, workspace, a, replay_epoch=2)
    return states, a


def test_two_infra_retries_then_third_failure_is_terminal(isolated_store):
    s = isolated_store
    rid = submit(s, epochs=2)['id']
    states, last = drive_failures(s, rid, W, [True, True, True, True])
    assert states == ['interrupted', 'interrupted', 'failed']
    assert len(attempts(s, rid)) == 3 and s.get(rid)['state'] == 'failed'
    with pytest.raises(Conflict):  # a failed run cannot be resumed or reclaimed
        s.resume(W, rid, 2)
    with pytest.raises(Conflict):
        s.claim(rid)
    s.release_slot(rid, fence=last['fence'])


def test_non_retryable_failure_is_terminal_on_the_first_attempt(isolated_store):
    s = isolated_store
    rid = submit(s, epochs=2)['id']
    states, last = drive_failures(s, rid, W, [False])
    assert states == ['failed'] and len(attempts(s, rid)) == 1
    s.release_slot(rid, fence=last['fence'])


def test_resume_is_refused_once_three_attempts_exist_even_for_lease_expiry(isolated_store):
    s = isolated_store
    rid = submit(s, epochs=2)['id']
    a = s.claim(rid)
    s.publish(rid, a['fence'], a['cancel_generation'], SOURCE, METRICS, **scope_of(a))
    for n in (1, 2):
        s.expire_for_test(rid)
        assert s.get(rid)['state'] == 'interrupted'
        a = next_attempt(s, rid, W, a, replay_epoch=2)
        assert len(attempts(s, rid)) == n + 1
    s.expire_for_test(rid)  # third attempt expires
    assert s.get(rid)['state'] == 'interrupted' and len(attempts(s, rid)) == 3
    s.release_slot(rid, fence=a['fence'])
    with pytest.raises(Conflict, match='ATTEMPT_BUDGET'):
        s.resume(W, rid, 2)
    assert s.get(rid)['state'] == 'interrupted' and len(attempts(s, rid)) == 3


# --------------------------------------------- scoped SQL capability (non-owner login)
def test_scoped_sql_path_stale_fence_cannot_renew_commit_or_complete(scoped):
    s, w, cfg = scoped['s'], scoped['w'], scoped['cfg']
    r = s.submit(scoped['mine'], 'alice', str(uuid.uuid4()), cfg)
    rid = r['id']
    a1 = w.claim(rid, 0, start=True, worker_id='w1')
    sc1 = scope_of(a1)
    w.publish(rid, a1['fence'], 0, SOURCE, scoped_metrics(scoped['meta']), **sc1)
    s.expire_for_test(rid)
    for op in (lambda: w.heartbeat(rid, a1['fence'], 0, **sc1),
               lambda: w.publish(rid, a1['fence'], 0, SOURCE, scoped_metrics(scoped['meta']), **sc1),
               lambda: w.complete(rid, a1['fence'], 0, {'best': {'epoch': 1}}, **sc1)):
        with pytest.raises(Conflict):
            op()
    w.release_slot(rid, fence=a1['fence'])
    s.resume(scoped['mine'], rid, 2)
    a2 = w.claim(rid, 0, start=True, worker_id='w2')
    assert a2['attempt'] != a1['attempt'] and a2['fence'] > a1['fence']
    before = s.get(rid)
    # the old attempt cannot act even if it borrows the NEW attempt's valid credential
    real = dict(w._tokens)
    w._tokens[a1['attempt']] = w._tokens[a2['attempt']]
    for op in (lambda: w.heartbeat(rid, a1['fence'], 0, **sc1),
               lambda: w.publish(rid, a1['fence'], 0, SOURCE, scoped_metrics(scoped['meta']), **sc1),
               lambda: w.complete(rid, a1['fence'], 0, {'best': {'epoch': 1}}, **sc1),
               lambda: w.fail(rid, a1['attempt'], a1['fence'], 'STALE', False, DIAG, restore_generation=a1['restore_generation']),
               lambda: w.heartbeat(rid, a2['fence'], 0, attempt=a1['attempt'], restore_generation=a1['restore_generation'])):
        with pytest.raises(Conflict):
            op()
    w._tokens.update(real)
    after = s.get(rid)
    for k in ('state', 'fence', 'revision', 'epoch', 'attempt', 'lease'):
        assert after[k] == before[k], k
    sc2 = scope_of(a2)
    w.heartbeat(rid, a2['fence'], 0, **sc2)
    assert w.complete(rid, a2['fence'], 0, {'best': {'epoch': 1}}, **sc2)['state'] == 'succeeded'
    # the login cannot touch attempt history at all
    with w.connect() as c:
        for stmt in ("UPDATE public.fw_attempts SET fence=fence+1", "UPDATE public.fw_attempts SET ended_at=NULL", "DELETE FROM public.fw_attempts",
                     "INSERT INTO public.fw_attempts(id,run,fence) VALUES('x','x',99)"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute(stmt)
    w.release_slot(rid, fence=a2['fence'])


def test_scoped_sql_path_allows_two_infra_retries_then_fails_terminally(scoped):
    s, w, cfg = scoped['s'], scoped['w'], scoped['cfg']
    cfg = dict(cfg, epochs=2)
    r = s.submit(scoped['mine'], 'alice', str(uuid.uuid4()), cfg)
    rid = r['id']
    states = []
    a = w.claim(rid, 0, start=True, worker_id='w1')
    w.publish(rid, a['fence'], 0, SOURCE, scoped_metrics(scoped['meta']), **scope_of(a))
    for i in range(3):
        states.append(w.fail(rid, a['attempt'], a['fence'], 'WORKER_INFRASTRUCTURE_FAILED', True, DIAG, restore_generation=a['restore_generation'])['state'])
        w.release_slot(rid, fence=a['fence'])
        if states[-1] != 'interrupted':
            break
        s.resume(scoped['mine'], rid, 2)
        a = w.claim(rid, 0, start=True, worker_id='w%d' % (i + 2))
    assert states == ['interrupted', 'interrupted', 'failed']
    with s.connect() as c:
        assert c.execute('SELECT count(*) n FROM fw_attempts WHERE run=%s', (rid,)).fetchone()['n'] == 3
    with pytest.raises(Conflict):
        s.resume(scoped['mine'], rid, 2)
