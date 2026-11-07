"""ML-T-CANCEL matrix on current source: barrier-controlled cancel vs checkpoint/complete in each DB lock ordering.

Frozen pass condition: cancel wins forbids completion/artifact publication; complete wins returns
`succeeded` plus `completion_won`; cancel stays pending until receipt or expiry/fence revoke; queued
cancel never starts; the physical resource slot is held until process exit is proven.

Real isolated PostgreSQL, real threads, orderings fixed by PostgreSQL lock barriers (run row lock,
fw_slot lock, and the ML-Cancel command advisory lock), real tiny child processes for the physical-slot
cases. The browser command is `Store.cancel_command` (revisioned, durable receipt); the internal
cancel is covered by the older tests.
"""
import json
import subprocess
import sys
import threading
import uuid

import pytest

from fieldwork.data import canonical
from fieldwork.store import CancelGenerationConflict, Conflict, ROOT
from tests.matrix_support import code_of, labelled_store, run_ordered, wait_for_database_lock

SOURCE = ROOT / 'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'
META = json.loads((SOURCE / 'state.json').read_text())
METRICS = {k: META[k] for k in ['epoch', 'train_loss', 'validation_loss', 'updates']}
RESULT = json.loads((SOURCE.parent / 'result.json').read_text())
W = 'cmatrix'
LOCK_RUN = 'SELECT 1 FROM fw_runs WHERE id=%s FOR UPDATE'


def new_run(s, *, claim=True, published=False):
    r = s.submit(W, 'author', str(uuid.uuid4()), {'epochs': 1, 'dataset_digest': META['dataset_digest'], 'scope': 'synthetic-execution-only'})
    if not claim:
        return r, None
    a = s.claim(r['id'])
    if published:
        s.publish(r['id'], a['fence'], a['cancel_generation'], SOURCE, METRICS, attempt=a['attempt'])
    return r, a


def cancel_cmd(rid, revision, actor='canceller'):
    def run(st):
        status, body = st.cancel_command(W, actor, str(uuid.uuid4()), rid, revision, 'matrix cancel')
        return status, json.loads(body)
    return run


def complete_op(rid, a):
    return lambda st: st.complete(rid, a['fence'], a['cancel_generation'], RESULT, attempt=a['attempt'])


def publish_op(rid, a):
    return lambda st: st.publish(rid, a['fence'], a['cancel_generation'], SOURCE, METRICS, attempt=a['attempt'])


def kinds(s, rid):
    with s.connect() as c:
        return [r['kind'] for r in c.execute("SELECT kind FROM fw_events WHERE run=%s AND kind<>'command_receipt' ORDER BY seq", (rid,)).fetchall()]


def slot_run(s):
    with s.connect() as c:
        return c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run']


def assert_no_completion_or_artifact(s, rid):
    r = s.get(rid)
    assert r['result'] is None and r['artifact_status'] == 'not_started' and r['artifact_result'] is None
    assert r['artifact_attempts'] == 0 and r['state'] in ('cancel_requested', 'cancelled')
    ks = kinds(s, rid)
    assert 'succeeded' not in ks and 'artifact_pending' not in ks


# ---------------------------------------------------------------- complete vs cancel
@pytest.mark.parametrize('first', ['cancel', 'complete'])
def test_complete_versus_browser_cancel_at_run_row_lock(isolated_store, first):
    s = isolated_store
    r, a = new_run(s, published=True)
    rid = r['id']
    rev = s.get(rid)['revision']
    ops = {'cancel': cancel_cmd(rid, rev), 'complete': complete_op(rid, a)}
    other = 'complete' if first == 'cancel' else 'cancel'
    try:
        o1, o2 = run_ordered(s, LOCK_RUN, (rid,), ops[first], ops[other])
        results = {first: o1, other: o2}
        generation = s.get(rid)['cancel_generation']
        if first == 'cancel':
            status, body = results['cancel'][1]
            assert (status, body) == (200, {'state': 'cancel_requested', 'completion_won': False})
            assert code_of(results['complete']) == 'CANCEL_GENERATION_FENCED'
            assert isinstance(results['complete'][1], CancelGenerationConflict)
            assert generation == a['cancel_generation'] + 1
            assert_no_completion_or_artifact(s, rid)
            with pytest.raises(Conflict):  # nothing can publish artifacts for a cancel-won run
                s.artifact_transition(rid, a['fence'], 'building', {})
            with pytest.raises(Conflict):
                s.claim_artifacts(rid)
        else:
            assert results['complete'][0] == 'ok' and results['complete'][1]['state'] == 'succeeded'
            status, body = results['cancel'][1]
            assert (status, body) == (200, {'state': 'succeeded', 'completion_won': True})
            assert generation == a['cancel_generation']  # the losing cancel never bumps the generation
            run = s.get(rid)
            assert run['state'] == 'succeeded' and run['artifact_status'] == 'pending' and run['result'] == RESULT
            assert kinds(s, rid).count('succeeded') == 1 and 'cancel_requested' not in kinds(s, rid)
            # artifact stage proceeds for the completion winner
            s.artifact_transition(rid, a['fence'], 'building', {})
            assert s.get(rid)['artifact_status'] == 'building'
        assert slot_run(s) == rid  # neither outcome released the physical slot
    finally:
        s.release_slot(rid)


@pytest.mark.parametrize('first', ['cancel', 'checkpoint'])
def test_checkpoint_versus_browser_cancel_at_run_row_lock(isolated_store, first):
    s = isolated_store
    r, a = new_run(s)
    rid = r['id']
    rev = s.get(rid)['revision']
    ops = {'cancel': cancel_cmd(rid, rev), 'checkpoint': publish_op(rid, a)}
    other = 'checkpoint' if first == 'cancel' else 'cancel'
    try:
        o1, o2 = run_ordered(s, LOCK_RUN, (rid,), ops[first], ops[other])
        results = {first: o1, other: o2}
        run = s.get(rid)
        if first == 'cancel':
            assert results['cancel'][1] == (200, {'state': 'cancel_requested', 'completion_won': False})
            assert code_of(results['checkpoint']) == 'CANCEL_GENERATION_FENCED'
            assert run['epoch'] == 0 and run['checkpoint'] is None and s.checkpoints(rid) == []
            assert 'epoch_committed' not in kinds(s, rid)
        else:
            # checkpoint committed first; the If-Match revision the canceller read is now stale: 412, state untouched
            assert results['checkpoint'][0] == 'ok'
            status, body = results['cancel'][1]
            assert status == 412 and body['code'] == 'STALE_REVISION' and body['object_revision'] == run['revision']
            assert run['state'] == 'running' and run['epoch'] == 1 and len(s.checkpoints(rid)) == 1
            # retry with the fresh revision cancels, and the committed checkpoint stays committed
            status, body = cancel_cmd(rid, run['revision'])(s)
            assert (status, body['state']) == (200, 'cancel_requested')
            assert s.get(rid)['epoch'] == 1 and len(s.checkpoints(rid)) == 1
        assert slot_run(s) == rid
    finally:
        s.release_slot(rid)


def test_cancel_receipt_replay_is_byte_exact_after_completion_won(isolated_store):
    s = isolated_store
    r, a = new_run(s, published=True)
    rid = r['id']
    rev = s.get(rid)['revision']
    key = str(uuid.uuid4())
    try:
        s.complete(rid, a['fence'], a['cancel_generation'], RESULT, attempt=a['attempt'])
        first = s.cancel_command(W, 'canceller', key, rid, rev, 'matrix cancel')
        assert json.loads(first[1]) == {'state': 'succeeded', 'completion_won': True}
        assert s.cancel_command(W, 'canceller', key, rid, rev, 'matrix cancel') == first
        with pytest.raises(Conflict, match='IDEMPOTENCY_CONFLICT'):
            s.cancel_command(W, 'canceller', key, rid, rev, 'a different reason')
        assert s.get(rid)['state'] == 'succeeded'
    finally:
        s.release_slot(rid)


# ------------------------------------------------- the other two DB lock orderings
def test_cancel_wins_while_complete_is_queued_behind_the_slot_lock(isolated_store):
    """complete takes fw_slot FOR UPDATE then the run row; cancel_command takes only the run row.
    Hold the slot lock, park complete on it, let the cancel commit, then release: the late complete
    must be refused and no completion/artifact state may exist."""
    s = isolated_store
    r, a = new_run(s, published=True)
    rid = r['id']
    rev = s.get(rid)['revision']
    label = 'fw-matrix-' + uuid.uuid4().hex
    actor = labelled_store(s, label)
    out = {}
    try:
        with s.connect() as blocker:
            blocker.execute('SELECT 1 FROM fw_slot WHERE id=1 FOR UPDATE')
            t = threading.Thread(target=lambda: out.update(complete=_cap(complete_op(rid, a), actor)))
            t.start()
            wait_for_database_lock(s, label)
            status, body = cancel_cmd(rid, rev)(s)  # only needs the run row: commits while complete is parked
            assert (status, body['state']) == (200, 'cancel_requested')
            blocker.commit()
        t.join(timeout=20)
        assert code_of(out['complete']) == 'CANCEL_GENERATION_FENCED'
        assert_no_completion_or_artifact(s, rid)
        assert slot_run(s) == rid
    finally:
        s.release_slot(rid)


def test_complete_wins_while_cancel_is_queued_behind_its_command_advisory_lock(isolated_store):
    s = isolated_store
    r, a = new_run(s, published=True)
    rid = r['id']
    rev = s.get(rid)['revision']
    key = str(uuid.uuid4())
    scope = canonical([W, 'canceller', 'ML-Cancel', key]).decode()
    label = 'fw-matrix-' + uuid.uuid4().hex
    actor = labelled_store(s, label)
    out = {}
    try:
        with s.connect() as blocker:
            blocker.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))', (scope,))
            t = threading.Thread(target=lambda: out.update(cancel=_cap(
                lambda st: st.cancel_command(W, 'canceller', key, rid, rev, 'matrix cancel'), actor)))
            t.start()
            wait_for_database_lock(s, label)
            done = s.complete(rid, a['fence'], a['cancel_generation'], RESULT, attempt=a['attempt'])
            assert done['state'] == 'succeeded'
            blocker.commit()
        t.join(timeout=20)
        status, body = out['cancel'][1]
        assert status == 200 and json.loads(body) == {'state': 'succeeded', 'completion_won': True}
        run = s.get(rid)
        assert run['state'] == 'succeeded' and run['cancel_generation'] == a['cancel_generation']
        assert run['artifact_status'] == 'pending' and run['result'] == RESULT
    finally:
        s.release_slot(rid)


def _cap(fn, store):
    from tests.matrix_support import capture
    return capture(fn, store)


# ------------------------------------------------------------------ queued cancel
def test_queued_cancel_never_starts(isolated_store):
    s = isolated_store
    r, _ = new_run(s, claim=False)
    rid = r['id']
    status, body = cancel_cmd(rid, r['revision'])(s)
    assert (status, body) == (200, {'state': 'cancelled', 'completion_won': False})
    run = s.get(rid)
    assert run['state'] == 'cancelled' and run['cancel_generation'] == 1 and run['attempt'] is None
    with pytest.raises(Conflict, match='NOT_QUEUED_OR_SLOT_BUSY'):
        s.claim(rid)
    assert slot_run(s) is None  # a refused claim does not touch the slot
    assert s.next_run() is None
    with s.connect() as c:
        assert c.execute('SELECT count(*) n FROM fw_attempts WHERE run=%s', (rid,)).fetchone()['n'] == 0
    with pytest.raises(Conflict):
        s.resume(W, rid, 1)
    assert 'claimed' not in kinds(s, rid) and 'started' not in kinds(s, rid)


@pytest.mark.parametrize('first', ['cancel', 'claim'])
def test_queued_cancel_versus_claim_at_run_row_lock(isolated_store, first):
    s = isolated_store
    r, _ = new_run(s, claim=False)
    rid = r['id']
    ops = {'cancel': cancel_cmd(rid, r['revision']), 'claim': lambda st: st.claim(rid, start=False)}
    other = 'claim' if first == 'cancel' else 'cancel'
    try:
        o1, o2 = run_ordered(s, LOCK_RUN, (rid,), ops[first], ops[other])
        results = {first: o1, other: o2}
        run = s.get(rid)
        if first == 'cancel':
            assert results['cancel'][1][0] == 200 and results['cancel'][1][1]['state'] == 'cancelled'
            assert code_of(results['claim']) == 'NOT_QUEUED_OR_SLOT_BUSY'
            assert run['state'] == 'cancelled' and run['attempt'] is None and slot_run(s) is None
        else:
            assert results['claim'][0] == 'ok' and results['claim'][1]['state'] == 'leased'
            # the queued->leased claim bumped the revision, so the canceller's If-Match is stale: refused, run leased
            status, body = results['cancel'][1]
            assert status == 412 and run['state'] == 'leased' and slot_run(s) == rid
            # a fresh-revision cancel of a leased run is cancel_requested and keeps the slot
            status, body = cancel_cmd(rid, run['revision'])(s)
            assert (status, body['state']) == (200, 'cancel_requested') and slot_run(s) == rid
    finally:
        if slot_run(s) == rid:
            s.release_slot(rid)


# --------------------------------------- pending until receipt/expiry; physical slot held
def test_cancel_stays_pending_slot_held_until_child_exit_is_proven_then_receipt_acknowledges(isolated_store):
    s = isolated_store
    r = s.submit(W, 'author', str(uuid.uuid4()), {'epochs': 1, 'dataset_digest': META['dataset_digest'], 'scope': 'synthetic-execution-only'})
    a = s.claim(r['id'], start=False)
    rid = r['id']
    s.start(rid, a['attempt'], a['fence'], a['cancel_generation'], a['digest'], restore_generation=a['restore_generation'])
    s.begin_child(rid, a['fence'])
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'])
    try:
        s.register_child(rid, a['fence'], child)
        status, body = cancel_cmd(rid, s.get(rid)['revision'])(s)
        assert (status, body['state']) == (200, 'cancel_requested')
        gen = s.get(rid)['cancel_generation']
        # worker with the old fence is revoked (typed refusal naming the generation to acknowledge)
        with pytest.raises(CancelGenerationConflict) as e:
            s.heartbeat(rid, a['fence'], a['cancel_generation'], attempt=a['attempt'], restore_generation=a['restore_generation'])
        assert (e.value.state, e.value.current_generation) == ('cancel_requested', gen)
        # pending: repeated cancels change nothing; slot and run state persist while the child lives
        before = s.get(rid)
        for _ in range(3):
            assert cancel_cmd(rid, before['revision'])(s)[1]['state'] == 'cancel_requested'
        assert s.get(rid)['revision'] == before['revision'] and s.get(rid)['cancel_generation'] == gen
        # physical slot: an acknowledgement while the child is alive is refused and rolls everything back
        with pytest.raises(Conflict, match='CHILD_EXIT_UNCONFIRMED'):
            s.acknowledge_cancel(rid, a['fence'], gen, exit_receipt={'child': child.pid, 'exit': 'claimed'})
        assert slot_run(s) == rid and s.get(rid)['state'] == 'cancel_requested'
        assert s.reconcile_training_slot() == 'OWNER_ALIVE' and slot_run(s) == rid
        assert s.release_own_slot() in ('OWN_RUN_ACTIVE', 'CHILD_ALIVE') and slot_run(s) == rid
        # a wrong generation cannot acknowledge, even with the child gone
        child.kill()
        child.wait(timeout=20)
        with pytest.raises(CancelGenerationConflict):
            s.acknowledge_cancel(rid, a['fence'], gen + 1, exit_receipt={'child': child.pid, 'exit': 'observed'})
        assert slot_run(s) == rid and s.get(rid)['state'] == 'cancel_requested'
        # receipt for the observed generation with proven exit: cancelled and the slot is released together
        assert s.acknowledge_cancel(rid, a['fence'], gen, exit_receipt={'child': child.pid, 'exit': 'observed'}) == 'cancelled'
        assert slot_run(s) is None and s.get(rid)['state'] == 'cancelled'
        with s.connect() as c:
            assert c.execute('SELECT exit_receipt_digest FROM fw_attempts WHERE id=%s', (a['attempt'],)).fetchone()['exit_receipt_digest']
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=20)
        if slot_run(s) == rid:
            s.release_slot(rid)


def test_cancel_pending_resolves_by_lease_expiry_and_slot_still_needs_exit_proof(isolated_store):
    s = isolated_store
    r = s.submit(W, 'author', str(uuid.uuid4()), {'epochs': 1, 'dataset_digest': META['dataset_digest'], 'scope': 'synthetic-execution-only'})
    a = s.claim(r['id'], start=False)
    rid = r['id']
    s.start(rid, a['attempt'], a['fence'], a['cancel_generation'], a['digest'], restore_generation=a['restore_generation'])
    s.begin_child(rid, a['fence'])
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'])
    try:
        s.register_child(rid, a['fence'], child)
        cancel_cmd(rid, s.get(rid)['revision'])(s)
        assert s.get(rid)['state'] == 'cancel_requested'
        with pytest.raises(Conflict):  # lease still live: expiry may not resolve it early
            s.expire(rid)
        s.expire_for_test(rid)  # no receipt arrives: lease lapses -> cancelled
        run = s.get(rid)
        assert run['state'] == 'cancelled' and 'expired' in kinds(s, rid)
        # the run is terminal but the physical slot is still held: the child is alive
        assert slot_run(s) == rid
        with pytest.raises(Conflict, match='CHILD_EXIT_UNCONFIRMED'):
            s.release_slot(rid, fence=a['fence'])
        assert slot_run(s) == rid
        child.kill()
        child.wait(timeout=20)
        s.release_slot(rid, fence=a['fence'])
        assert slot_run(s) is None and s.get(rid)['state'] == 'cancelled'
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=20)
        if slot_run(s) == rid:
            s.release_slot(rid)


def test_cancel_won_run_cannot_publish_artifacts_even_with_a_live_slot_and_old_fence(isolated_store):
    s = isolated_store
    r, a = new_run(s, published=True)
    rid = r['id']
    try:
        status, body = cancel_cmd(rid, s.get(rid)['revision'])(s)
        assert body['state'] == 'cancel_requested'
        run_before = s.get(rid)
        for stage in ('building', 'inference', 'verified', 'failed'):
            with pytest.raises(Conflict):
                s.artifact_transition(rid, a['fence'], stage, {})
            with pytest.raises(Conflict):
                s.artifact_transition(rid, run_before['fence'], stage, {})
        with pytest.raises(Conflict):
            s.claim_artifacts(rid)
        with pytest.raises(Conflict):
            s.complete(rid, a['fence'], a['cancel_generation'], RESULT, attempt=a['attempt'])
        with pytest.raises(Conflict):
            s.complete(rid, run_before['fence'], run_before['cancel_generation'], RESULT, attempt=a['attempt'])
        after = s.get(rid)
        assert after['revision'] == run_before['revision']
        assert_no_completion_or_artifact(s, rid)
        assert s.recover_artifacts() == []
    finally:
        s.release_slot(rid)


# ------------------------------------- the scoped SQL capability path (what the live worker uses)
from tests.test_worker_identity import metrics as scoped_metrics, scoped  # noqa: E402,F401  (fixture)


def wait_for_login_lock(admin, login, timeout=15):
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with admin.connect() as c:
            row = c.execute("SELECT 1 FROM pg_stat_activity WHERE usename=%s AND wait_event_type='Lock'", (login,)).fetchone()
        if row:
            return
        time.sleep(.005)
    raise AssertionError('scoped worker never reached the PostgreSQL lock barrier')


@pytest.mark.parametrize('operation', ['complete', 'checkpoint'])
@pytest.mark.parametrize('first', ['cancel', 'operation'])
def test_scoped_worker_capability_cancel_vs_publication_ordering(scoped, operation, first):
    import concurrent.futures
    s, w, meta = scoped['s'], scoped['w'], scoped['meta']
    mine = scoped['mine']
    r = s.submit(mine, 'alice', str(uuid.uuid4()), scoped['cfg'])
    rid = r['id']
    a = w.claim(rid, 0, start=True, worker_id='w1')
    sc = dict(attempt=a['attempt'], restore_generation=a['restore_generation'])
    if operation == 'complete':
        w.publish(rid, a['fence'], 0, SOURCE, scoped_metrics(meta), **sc)
    rev = s.get(rid)['revision']
    label = 'fw-matrix-' + uuid.uuid4().hex
    canceller = labelled_store(s, label)

    def do_cancel():
        status, body = canceller.cancel_command(mine, 'canceller', str(uuid.uuid4()), rid, rev, 'matrix cancel')
        return status, json.loads(body)

    def do_op():
        try:
            if operation == 'complete':
                return 'ok', w.complete(rid, a['fence'], 0, {'best': {'epoch': 1}}, **sc)
            return 'ok', w.publish(rid, a['fence'], 0, SOURCE, scoped_metrics(meta), **sc)
        except Conflict as exc:
            return 'err', exc

    waits = {'cancel': lambda: wait_for_database_lock(s, label), 'operation': lambda: wait_for_login_lock(s, scoped['login'])}
    actors = {'cancel': do_cancel, 'operation': do_op}
    other = 'operation' if first == 'cancel' else 'cancel'
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        with s.connect() as blocker:
            blocker.execute(LOCK_RUN, (rid,))
            f1 = pool.submit(actors[first])
            waits[first]()
            f2 = pool.submit(actors[other])
            waits[other]()
            blocker.commit()
        results = {first: f1.result(timeout=30), other: f2.result(timeout=30)}
    run = s.get(rid)
    if first == 'cancel':
        assert results['cancel'] == (200, {'state': 'cancel_requested', 'completion_won': False})
        assert results['operation'][0] == 'err' and isinstance(results['operation'][1], CancelGenerationConflict)
        assert results['operation'][1].code == 'CANCEL_GENERATION_FENCED'
        assert run['state'] == 'cancel_requested' and run['result'] is None and run['artifact_status'] == 'not_started'
        if operation == 'checkpoint':
            assert run['epoch'] == 0 and s.checkpoints(rid) == []
        else:
            assert 'succeeded' not in kinds(s, rid) and 'artifact_pending' not in kinds(s, rid)
    elif operation == 'complete':
        assert results['operation'][0] == 'ok' and results['operation'][1]['state'] == 'succeeded'
        assert results['cancel'] == (200, {'state': 'succeeded', 'completion_won': True})
        assert run['state'] == 'succeeded' and run['cancel_generation'] == 0 and run['artifact_status'] == 'pending'
    else:
        assert results['operation'][0] == 'ok'
        assert results['cancel'][0] == 412 and results['cancel'][1]['code'] == 'STALE_REVISION'
        assert run['state'] == 'running' and run['epoch'] == 1 and len(s.checkpoints(rid)) == 1
    assert slot_run(s) == rid  # the physical slot is still held in every outcome
