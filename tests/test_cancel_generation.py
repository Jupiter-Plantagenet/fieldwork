"""Explicit cancel_generation protocol through the real Store/supervisor/worker/API code.

The database is a hand-authored, threaded SQL adapter with FIFO row locks held to
transaction end and undo-on-exception. It is NOT PostgreSQL parsing, MVCC, lock
manager, RLS/grant or physical worker-exit proof. Race orderings are scheduled
by observing actors enqueued on the authored run-row lock (barriers), never by
timing sleeps.
"""
import copy
import json
import sys
import threading
import types
from contextlib import contextmanager
import pytest

RUN = 'run-a'
WORKSPACE = 'lab'
KEY1 = '11111111-1111-4111-8111-111111111111'
KEY2 = '22222222-2222-4222-8222-222222222222'
METRICS = {'epoch': 1, 'train_loss': 0.5, 'validation_loss': 0.6, 'updates': 3}


class Transaction:
    def __init__(self, db):
        self.db = db
        self.held = []
        self.undo = []
        self.row = None

    def _save(self, kind, key):
        if (kind, key) in [(k, x) for k, x, _ in self.undo]:
            return
        table = self.db.table(kind)
        self.undo.append((kind, key, copy.deepcopy(table.get(key, None))))

    def rollback(self):
        for kind, key, value in reversed(self.undo):
            table = self.db.table(kind)
            if value is None:
                table.pop(key, None)
            else:
                table[key] = value
        self.undo.clear()

    def fetchone(self):
        return self.row

    def execute(self, sql, params=()):
        return self.db.execute(self, sql, params)


class LockingDatabase:
    """Authored rows for one run, one physical slot, attempts, checkpoints and events."""

    def __init__(self, owner):
        self.cond = threading.Condition()
        self.locks = {}
        self.waiting = {}
        self.has_generation_column = True
        self.fail = None
        self.calls = []
        self.runs = {RUN: dict(id=RUN, workspace=WORKSPACE, state='queued', revision=7, fence=3, epoch=0,
                               attempt=None, checkpoint=None, result=None, artifact_status='not_started',
                               config={'epochs': 1, 'dataset_digest': 'authored-dataset'},
                               digest='authored-config-digest', cancel_generation=0, _live=True)}
        # Round 5 (migrations/005): deployment restore generation and internal-command receipts.
        self.control = dict(restore_generation='authored-restore-generation', fence_floor=0)
        self.receipt_rows = {}
        self.attempts = {}
        self.checkpoints = {}
        self.events = {}
        self.seq = 0
        self.slots = {1: dict(id=1, run=None, fence=None, owner_pid=None, owner_created=None,
                              pid=None, child_created=None, launching=False)}
        self.owner = owner

    @property
    def run(self):
        return self.runs[RUN]

    @property
    def slot(self):
        return self.slots[1]

    def table(self, kind):
        return {'run': self.runs, 'attempt': self.attempts, 'checkpoint': self.checkpoints,
                'event': self.events, 'slot': self.slots, 'receipt': self.receipt_rows}[kind]

    # ---- FIFO row locks held until transaction end -------------------------------------
    def acquire(self, txn, name):
        with self.cond:
            lock = self.locks.setdefault(name, {'owner': None, 'queue': []})
            if lock['owner'] is txn:
                return
            must_wait = lock['owner'] is not None or bool(lock['queue'])
            lock['queue'].append(txn)
            if must_wait:
                self.waiting[threading.current_thread().name] = name
                self.cond.notify_all()
            if not self.cond.wait_for(lambda: lock['owner'] is None and lock['queue'][0] is txn, timeout=10):
                raise AssertionError('authored lock wait timed out: ' + name)
            lock['queue'].pop(0)
            lock['owner'] = txn
            txn.held.append(name)
            self.waiting.pop(threading.current_thread().name, None)
            self.cond.notify_all()

    def release(self, txn):
        with self.cond:
            for name in txn.held:
                self.locks[name]['owner'] = None
            txn.held.clear()
            self.cond.notify_all()

    def wait_until_waiting(self, actor, name):
        with self.cond:
            if not self.cond.wait_for(lambda: self.waiting.get(actor) == name, timeout=10):
                raise AssertionError(actor + ' never reached authored lock barrier ' + name)

    @contextmanager
    def connect(self, **kwargs):
        txn = Transaction(self)
        try:
            yield txn
        except BaseException:
            txn.rollback()
            raise
        finally:
            self.release(txn)

    def hold(self, name):
        txn = Transaction(self)
        self.acquire(txn, name)
        return txn

    # ---- authored SQL interpretation ---------------------------------------------------
    def out(self, row):
        if row is None:
            return None
        result = {k: copy.deepcopy(v) for k, v in row.items() if not k.startswith('_')}
        if not self.has_generation_column:
            result.pop('cancel_generation', None)
        return result

    def execute(self, txn, sql, params=()):
        with self.cond:
            self.calls.append((threading.current_thread().name, sql, params))
        if self.fail and self.fail(sql, params):
            raise RuntimeError('authored-injected-failure')
        if not self.has_generation_column and 'cancel_generation' in sql:
            raise AssertionError('old schema: column cancel_generation does not exist')
        txn.row = None
        run = self.runs.get(params[0]) if params else None
        if sql == 'SELECT pg_advisory_xact_lock(hashtextextended(%s,0))':
            self.acquire(txn, 'advisory:' + params[0])
        elif sql.startswith('SELECT payload FROM fw_events WHERE workspace=%s AND kind=%s'):
            workspace, kind, actor, key = params
            txn.row = next((dict(payload=copy.deepcopy(e['payload'])) for _, e in sorted(self.events.items())
                            if e['workspace'] == workspace and e['kind'] == kind and e['payload']['command'] == 'ML-Cancel'
                            and e['payload']['actor'] == actor and e['payload']['key_identity'] == key), None)
        elif sql == 'SELECT * FROM fw_slot WHERE id=1 FOR UPDATE':
            self.acquire(txn, 'slot')
            txn.row = copy.deepcopy(self.slot)
        elif sql in ('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE', 'SELECT * FROM fw_runs WHERE id=%s AND workspace=%s FOR UPDATE',
                     'SELECT *,lease>clock_timestamp() AS live FROM fw_runs WHERE id=%s FOR UPDATE'):
            self.acquire(txn, 'run:' + params[0])
            run = self.runs.get(params[0])
            if run is not None and len(params) == 2 and run['workspace'] != params[1]:
                run = None
            txn.row = self.out(run)
            if txn.row is not None and 'AS live' in sql:
                txn.row['live'] = run['_live']
        elif sql in ('SELECT * FROM fw_runs WHERE id=%s', 'SELECT * FROM fw_runs WHERE id=%s AND workspace=%s'):
            txn.row = self.out(run)
        elif sql == 'SELECT revision FROM fw_runs WHERE id=%s':
            txn.row = dict(revision=run['revision'])
        elif sql == 'INSERT INTO fw_events(workspace,run,kind,payload,object_revision) VALUES(%s,%s,%s,%s,%s)':
            with self.cond:
                self.seq += 1
                seq = self.seq
            txn._save('event', seq)
            workspace, rid, kind, payload, revision = params
            self.events[seq] = dict(seq=seq, workspace=workspace, run=rid, kind=kind,
                                    payload=copy.deepcopy(payload.obj), object_revision=revision)
        elif sql == 'UPDATE fw_runs SET state=%s,fence=fence+1,revision=revision+1,cancel_generation=%s WHERE id=%s':
            state, generation, rid = params
            txn._save('run', rid)
            r = self.runs[rid]
            r.update(state=state, fence=r['fence'] + 1, revision=r['revision'] + 1, cancel_generation=generation)
        elif sql == 'INSERT INTO fw_attempts(id,run,fence,cancel_generation) VALUES(%s,%s,%s,%s)':
            aid, rid, fence, generation = params
            txn._save('attempt', aid)
            self.attempts[aid] = dict(id=aid, run=rid, fence=fence, cancel_generation=generation)
        elif sql == 'UPDATE fw_slot SET run=%s,fence=%s,owner_pid=%s,owner_created=%s,pid=NULL,child_created=NULL,launching=false WHERE id=1':
            txn._save('slot', 1)
            self.slot.update(run=params[0], fence=params[1], owner_pid=params[2], owner_created=params[3],
                             pid=None, child_created=None, launching=False)
        elif sql == ("UPDATE fw_runs SET state='running',fence=%s,attempt=%s,cancel_generation=%s,"
                     "lease=now()+interval '45 seconds',revision=revision+1 WHERE id=%s RETURNING *"):
            fence, aid, generation, rid = params
            txn._save('run', rid)
            r = self.runs[rid]
            r.update(state='running', fence=fence, attempt=aid, cancel_generation=generation,
                     revision=r['revision'] + 1, _live=True)
            txn.row = self.out(r)
        elif sql == "UPDATE fw_runs SET lease=clock_timestamp()+interval '45 seconds' WHERE id=%s RETURNING lease":
            txn._save('run', params[0])
            self.runs[params[0]]['_live'] = True
            self.runs[params[0]]['lease'] = 'authored-renewed-lease'
            txn.row = dict(lease='authored-renewed-lease')
        elif sql == 'SELECT * FROM fw_checkpoints WHERE run=%s AND epoch=%s':
            txn.row = copy.deepcopy(self.checkpoints.get((params[0], params[1])))
        elif sql == 'INSERT INTO fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES(%s,%s,%s,%s,%s,%s)':
            rid, epoch, attempt, md, path, metrics = params
            txn._save('checkpoint', (rid, epoch))
            self.checkpoints[(rid, epoch)] = dict(run=rid, epoch=epoch, attempt=attempt, digest=md, path=path,
                                                  metrics=copy.deepcopy(metrics.obj))
        elif sql == 'UPDATE fw_runs SET epoch=%s,checkpoint=%s,revision=revision+1 WHERE id=%s':
            epoch, path, rid = params
            txn._save('run', rid)
            self.runs[rid].update(epoch=epoch, checkpoint=path, revision=self.runs[rid]['revision'] + 1)
        elif sql.startswith("UPDATE fw_runs SET state='succeeded',result=%s,"):
            rid = params[-1]
            txn._save('run', rid)
            self.runs[rid].update(state='succeeded', result=copy.deepcopy(params[0].obj), artifact_status='pending',
                                  revision=self.runs[rid]['revision'] + 1)
        elif sql == 'UPDATE fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL WHERE id=1':
            txn._save('slot', 1)
            self.slot.update(run=None, pid=None, child_created=None, owner_pid=None, owner_created=None, fence=None)
        elif sql == ("UPDATE fw_runs SET state='cancelled',revision=revision+1 WHERE id=%s "
                     "AND state='cancel_requested' AND cancel_generation=%s RETURNING *"):
            rid, generation = params
            r = self.runs[rid]
            if r['state'] == 'cancel_requested' and r['cancel_generation'] == generation:
                txn._save('run', rid)
                r.update(state='cancelled', revision=r['revision'] + 1)
                txn.row = self.out(r)
        elif sql == "UPDATE fw_runs SET state='failed',fence=fence+1,revision=revision+1 WHERE id=%s":
            txn._save('run', params[0])
            self.runs[params[0]].update(state='failed', fence=self.runs[params[0]]['fence'] + 1,
                                        revision=self.runs[params[0]]['revision'] + 1)
        elif sql == 'UPDATE fw_slot SET launching=true,pid=NULL,child_created=NULL WHERE id=1':
            txn._save('slot', 1)
            self.slot.update(launching=True, pid=None, child_created=None)
        elif sql == 'UPDATE fw_slot SET launching=false,pid=%s,child_created=%s WHERE id=1':
            txn._save('slot', 1)
            self.slot.update(launching=False, pid=params[0], child_created=params[1])
        elif sql == 'UPDATE fw_slot SET launching=false,pid=NULL,child_created=NULL WHERE id=1':
            txn._save('slot', 1)
            self.slot.update(launching=False, pid=None, child_created=None)
        elif sql.startswith('SELECT restore_generation,fence_floor FROM fw_control WHERE id=1'):
            txn.row = dict(self.control)
        elif sql == 'INSERT INTO fw_attempts(id,run,fence,cancel_generation,restore_generation,worker_id) VALUES(%s,%s,%s,%s,%s,%s)':
            aid, rid, fence, generation, restore_generation, worker_id = params
            txn._save('attempt', aid)
            self.attempts[aid] = dict(id=aid, run=rid, fence=fence, cancel_generation=generation,
                                      restore_generation=restore_generation, worker_id=worker_id)
        elif sql == ("UPDATE fw_runs SET state='leased',fence=%s,attempt=%s,cancel_generation=%s,"
                     "lease=clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=%s RETURNING *"):
            fence, aid, generation, rid = params
            txn._save('run', rid)
            r = self.runs[rid]
            r.update(state='leased', fence=fence, attempt=aid, cancel_generation=generation,
                     revision=r['revision'] + 1, _live=True, lease='authored-lease')
            txn.row = self.out(r)
        elif sql == "UPDATE fw_runs SET state='running',lease=clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=%s RETURNING *":
            txn._save('run', params[0])
            r = self.runs[params[0]]
            r.update(state='running', revision=r['revision'] + 1, _live=True, lease='authored-renewed-lease')
            txn.row = self.out(r)
        elif sql.startswith('UPDATE fw_attempts SET'):
            aid = params[-1]
            if aid in self.attempts:
                txn._save('attempt', aid)
                if 'exit_receipt_digest' in sql and self.attempts[aid].get('exit_receipt_digest') is None:
                    self.attempts[aid]['exit_receipt_digest'] = params[0]
        elif sql == 'SELECT restore_generation FROM fw_attempts WHERE id=%s':
            a = self.attempts.get(params[0])
            txn.row = dict(restore_generation=a.get('restore_generation')) if a else None
        elif sql == 'SELECT count(*) n FROM fw_attempts WHERE run=%s':
            txn.row = dict(n=sum(1 for a in self.attempts.values() if a['run'] == params[0]))
        elif sql == 'UPDATE fw_runs SET state=%s,fence=fence+1,revision=revision+1 WHERE id=%s AND fence=%s AND attempt=%s RETURNING *':
            state, rid, fence, aid = params
            r = self.runs[rid]
            if r['fence'] == fence and r['attempt'] == aid:
                txn._save('run', rid)
                r.update(state=state, fence=r['fence'] + 1, revision=r['revision'] + 1)
                txn.row = self.out(r)
        elif sql == 'SELECT workspace FROM fw_runs WHERE id=%s':
            txn.row = dict(workspace=run['workspace']) if run else None
        elif sql.startswith('SELECT request_digest,status,response FROM fw_command_receipts'):
            txn.row = copy.deepcopy(self.receipt_rows.get(tuple(params)))
        elif sql.startswith('INSERT INTO fw_command_receipts'):
            workspace, actor, command, key, request_digest, status, response, rid = params
            txn._save('receipt', (workspace, actor, command, key))
            self.receipt_rows[(workspace, actor, command, key)] = dict(request_digest=request_digest, status=status,
                                                                         response=copy.deepcopy(response.obj))
        else:
            raise AssertionError('Unexpected SQL: ' + sql)
        return txn

    # ---- helpers ------------------------------------------------------------------------
    def public(self):
        return [e for _, e in sorted(self.events.items()) if e['kind'] != 'command_receipt']

    def receipts(self):
        return [e for _, e in sorted(self.events.items()) if e['kind'] == 'command_receipt']

    def snapshot(self):
        return copy.deepcopy((self.runs, self.attempts, self.checkpoints, self.events, self.slots))


class Actor(threading.Thread):
    def __init__(self, name, fn):
        super().__init__(name=name, daemon=True)
        self.fn = fn
        self.result = None
        self.error = None

    def run(self):
        try:
            self.result = self.fn()
        except BaseException as exc:  # recorded for deterministic assertion
            self.error = exc


@pytest.fixture
def env(monkeypatch, tmp_path):
    # Never import torch: publish's ml/checkpoint_store imports are replaced by
    # authored stand-ins. The Store's own lineage/epoch/SQL logic remains real.
    ml = types.ModuleType('fieldwork.ml')
    ml.validate_checkpoint = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, 'fieldwork.ml', ml)
    staged = tmp_path / 'authored-checkpoint'
    staged.mkdir()
    (staged / 'state.json').write_text(json.dumps(dict(METRICS, dataset_digest='authored-dataset', next_epoch=2)))
    checkpoint_store = types.ModuleType('fieldwork.checkpoint_store')
    checkpoint_store.promote = lambda source, root: (staged, 'a' * 64)
    monkeypatch.setitem(sys.modules, 'fieldwork.checkpoint_store', checkpoint_store)
    from fieldwork import store as module
    db = LockingDatabase(module.identity())
    store = object.__new__(module.Store)
    monkeypatch.setattr(store, 'connect', db.connect)
    store.blob_root = tmp_path / 'blobs'
    return types.SimpleNamespace(module=module, store=store, db=db, path=staged, tmp=tmp_path)


def claimed(env, generation=0):
    env.db.run['cancel_generation'] = generation
    return env.store.claim(RUN, expected_cancel_generation=generation)


def code(exc):
    return str(exc.value)


# ---- issuance -------------------------------------------------------------------------------

def test_claim_issues_current_generation_on_run_attempt_and_event(env):
    a = claimed(env, 0)
    assert a['cancel_generation'] == 0 and a['state'] == 'running' and a['fence'] == 4
    assert env.db.attempts[a['attempt']]['cancel_generation'] == 0
    # ML-Claim (leased) then ML-Start (running): two events, in order.
    assert [e['kind'] for e in env.db.public()[-2:]] == ['claimed', 'started']
    assert env.db.public()[-2]['payload']['cancel_generation'] == 0 and env.db.public()[-2]['payload']['state'] == 'leased'
    assert env.db.public()[-1]['payload']['state'] == 'running'


def test_claim_of_legacy_null_queued_row_issues_zero_explicitly(env):
    env.db.run['cancel_generation'] = None
    a = env.store.claim(RUN, expected_cancel_generation=None)
    assert a['cancel_generation'] == 0 and env.db.run['cancel_generation'] == 0
    assert env.db.attempts[a['attempt']]['cancel_generation'] == 0


def test_claim_refuses_when_observed_generation_changed(env):
    env.db.run['cancel_generation'] = 2
    before = env.db.snapshot()
    with pytest.raises(env.module.CancelGenerationConflict) as exc:
        env.store.claim(RUN, expected_cancel_generation=1)
    assert code(exc) == 'CANCEL_GENERATION_CHANGED' and exc.value.current_generation == 2
    assert env.db.snapshot() == before


# ---- cancel writers -------------------------------------------------------------------------

def test_running_cancel_increments_generation_exactly_once(env):
    a = claimed(env, 0)
    revision = env.db.run['revision']
    status, body = env.store.cancel_command(WORKSPACE, 'alice', KEY1, RUN, revision, 'Stop it')
    assert status == 200 and json.loads(body) == {'state': 'cancel_requested', 'completion_won': False}
    assert env.db.run['cancel_generation'] == 1 and env.db.run['fence'] == a['fence'] + 1
    event = env.db.public()[-1]
    assert event['kind'] == 'cancel_requested' and event['payload']['cancel_generation'] == 1
    assert env.db.receipts()[-1]['payload']['cancel_generation'] == 1
    # Exact retry replays; repeated/different cancels of cancel_requested do not re-increment,
    # so an acknowledgement of generation 1 cannot be invalidated by a duplicate click.
    assert env.store.cancel_command(WORKSPACE, 'alice', KEY1, RUN, revision, 'Stop it') == (status, body)
    assert env.store.cancel_command(WORKSPACE, 'alice', KEY2, RUN, revision + 1, 'Again')[0] == 200
    assert env.store.cancel(WORKSPACE, RUN) == 'cancel_requested'
    assert env.db.run['cancel_generation'] == 1 and env.db.run['revision'] == revision + 1


@pytest.mark.parametrize('state', ['queued', 'interrupted'])
def test_queued_or_interrupted_cancel_is_terminal_and_increments(env, state):
    env.db.run['state'] = state
    assert env.store.cancel(WORKSPACE, RUN) == 'cancelled'
    assert env.db.run['cancel_generation'] == 1
    with pytest.raises(env.module.Conflict, match='NOT_QUEUED'):
        env.store.claim(RUN, expected_cancel_generation=0)


@pytest.mark.parametrize('state', ['succeeded', 'failed', 'cancelled'])
def test_terminal_cancel_never_increments(env, state):
    env.db.run.update(state=state, cancel_generation=0)
    status, body = env.store.cancel_command(WORKSPACE, 'alice', KEY1, RUN, 99, 'late')
    assert status == 200 and json.loads(body)['state'] == state
    assert env.db.run['cancel_generation'] == 0


def test_legacy_null_running_row_cancel_records_generation_one(env):
    env.db.run.update(state='running', cancel_generation=None)
    assert env.store.cancel(WORKSPACE, RUN) == 'cancel_requested'
    assert env.db.run['cancel_generation'] == 1


# ---- worker-facing refusals -----------------------------------------------------------------

def operations(env, a, generation):
    return {
        'heartbeat': lambda: env.store.heartbeat(RUN, a['fence'], generation,attempt=a['attempt']),
        'checkpoint': lambda: env.store.publish(RUN, a['fence'], generation, env.path, dict(METRICS),attempt=a['attempt']),
        'complete': lambda: env.store.complete(RUN, a['fence'], generation, {'best': {'epoch': 1}},attempt=a['attempt']),
    }


@pytest.mark.parametrize('operation', ['heartbeat', 'checkpoint', 'complete'])
def test_stale_generation_refused_even_when_fence_state_and_lease_match(env, operation):
    a = claimed(env, 0)
    env.db.run.update(cancel_generation=1, epoch=1 if operation == 'complete' else 0)  # authored: fence untouched
    before = env.db.snapshot()
    with pytest.raises(env.module.CancelGenerationConflict) as exc:
        operations(env, a, 0)[operation]()
    assert code(exc) == 'CANCEL_GENERATION_FENCED'
    assert (exc.value.state, exc.value.current_generation) == ('running', 1)
    assert env.db.snapshot() == before


@pytest.mark.parametrize('operation', ['heartbeat', 'checkpoint', 'complete'])
def test_worker_started_before_cancel_cannot_publish_after_it(env, operation):
    a = claimed(env, 0)
    if operation == 'complete':
        env.db.run['epoch'] = 1
    env.store.cancel_command(WORKSPACE, 'alice', KEY1, RUN, env.db.run['revision'], 'Stop it')
    before = env.db.snapshot()
    with pytest.raises(env.module.CancelGenerationConflict) as exc:
        operations(env, a, a['cancel_generation'])[operation]()
    assert code(exc) == 'CANCEL_GENERATION_FENCED'
    assert (exc.value.state, exc.value.current_generation) == ('cancel_requested', 1)
    assert env.db.snapshot() == before and not env.db.checkpoints and env.db.run['state'] == 'cancel_requested'


@pytest.mark.parametrize('value', [None, True, '0', -1, 1.0, 2147483648])
@pytest.mark.parametrize('operation', ['heartbeat', 'checkpoint', 'complete'])
def test_absent_or_invalid_generation_rejected_before_any_sql(env, operation, value):
    a = claimed(env, 0)
    calls = len(env.db.calls)
    with pytest.raises(ValueError, match='CANCEL_GENERATION_REQUIRED'):
        operations(env, a, value)[operation]()
    assert len(env.db.calls) == calls


def test_pre_generation_call_shapes_fail_closed(env):
    a = claimed(env, 0)
    calls = len(env.db.calls)
    with pytest.raises(TypeError):
        env.store.heartbeat(RUN, a['fence'],attempt=a['attempt'])
    with pytest.raises(TypeError):
        env.store.publish(RUN, a['fence'], env.path, dict(METRICS),attempt=a['attempt'])
    with pytest.raises(TypeError):
        env.store.complete(RUN, a['fence'], {'best': {'epoch': 1}},attempt=a['attempt'])
    with pytest.raises(TypeError):
        env.store.release_slot(RUN, a['fence'], 0)  # generation is keyword-only, never positional
    assert len(env.db.calls) == calls
    assert not env.db.checkpoints and env.db.run['state'] == 'running'


def test_heartbeat_with_current_generation_renews_and_reports(env):
    a = claimed(env, 0)
    env.db.run['_live'] = False
    with pytest.raises(env.module.Conflict, match='FENCED_OR_EXPIRED'):
        env.store.heartbeat(RUN, a['fence'], 0,attempt=a['attempt'])  # expired lease is never revived
    env.db.run['_live'] = True
    assert env.store.heartbeat(RUN, a['fence'], 0,attempt=a['attempt']) == {
        'lease_expires_at': 'authored-renewed-lease', 'cancel_requested': False, 'cancel_generation': 0}


def test_legacy_null_running_row_is_unverifiable_for_worker_publication(env):
    a = claimed(env, 0)
    env.db.run['cancel_generation'] = None
    with pytest.raises(env.module.CancelGenerationConflict, match='CANCEL_GENERATION_UNVERIFIABLE'):
        env.store.heartbeat(RUN, a['fence'], 0,attempt=a['attempt'])


def test_checkpoint_and_complete_with_current_generation_commit(env):
    a = claimed(env, 0)
    env.store.publish(RUN, a['fence'], 0, env.path, dict(METRICS),attempt=a['attempt'])
    assert env.db.run['epoch'] == 1 and (RUN, 1) in env.db.checkpoints
    env.store.complete(RUN, a['fence'], 0, {'best': {'epoch': 1}},attempt=a['attempt'])
    assert env.db.run['state'] == 'succeeded' and env.db.run['cancel_generation'] == 0


# ---- old schema -----------------------------------------------------------------------------

def test_old_schema_fails_closed_without_receipt_or_ddl(env):
    env.db.run['state'] = 'running'
    env.db.has_generation_column = False
    before = env.db.snapshot()
    with pytest.raises(env.module.GenerationSchemaRequired, match='CANCEL_GENERATION_SCHEMA_REQUIRED'):
        env.store.cancel_command(WORKSPACE, 'alice', KEY1, RUN, 7, 'Stop it')
    with pytest.raises(env.module.GenerationSchemaRequired):
        env.store.cancel(WORKSPACE, RUN)
    with pytest.raises(env.module.GenerationSchemaRequired):
        env.store.heartbeat(RUN, 3, 0, attempt='authored-attempt')
    env.db.run['state'] = 'queued'
    with pytest.raises(env.module.GenerationSchemaRequired):
        env.store.claim(RUN, expected_cancel_generation=0)
    env.db.run['state'] = 'running'  # undo only the authored setup change above
    assert env.db.snapshot() == before
    assert not any('ALTER' in sql or 'CREATE' in sql for _, sql, _ in env.db.calls)


def test_api_maps_old_schema_to_typed_503(env, monkeypatch):
    # Same no-settings seam as test_run_cancellation: importing api must not read
    # a local credential file. No lifespan runs (no `with TestClient`).
    monkeypatch.setattr(env.module.Store, '__init__', lambda self, *a, **k: None)
    from fieldwork import api
    from fastapi.testclient import TestClient
    env.db.run['state'] = 'running'
    env.db.has_generation_column = False
    # api.fixture_run() now routes real-run scopes elsewhere (409 REAL_RUN_ROUTE_REQUIRED);
    # this authored run must carry the synthetic-fixture scope to reach the cancel command.
    env.db.run['config'] = {**env.db.run['config'], 'scope': 'synthetic-execution-only'}
    monkeypatch.setattr(api, 'store', env.store)
    api.app.dependency_overrides[api.session] = lambda: dict(name='alice', workspace=WORKSPACE, role='researcher', csrf='csrf')
    client = TestClient(api.app)
    try:
        response = client.post('/api/v1/workspaces/lab/runs/run-a/cancel', json={'expected_revision': 7, 'reason': 'Stop it'},
                               headers={'origin': 'http://127.0.0.1:5102', 'x-csrf-token': 'csrf', 'If-Match': '"7"',
                                        'Idempotency-Key': KEY1})
        assert response.status_code == 503, response.text
        assert response.json()['code'] == 'CANCEL_GENERATION_SCHEMA_REQUIRED'
        assert not env.db.receipts() and env.db.run['state'] == 'running'
    finally:
        api.app.dependency_overrides.clear()
        client.close()


# ---- cancel acknowledgement -----------------------------------------------------------------

def cancelled_attempt(env):
    a = claimed(env, 0)
    env.store.cancel_command(WORKSPACE, 'alice', KEY1, RUN, env.db.run['revision'], 'Stop it')
    return a


def test_ack_naming_observed_generation_terminalizes_once(env):
    a = cancelled_attempt(env)
    revision = env.db.run['revision']
    assert env.store.release_slot(RUN, fence=a['fence'], cancel_generation=1) == 'cancelled'
    assert env.db.run['state'] == 'cancelled' and env.db.run['revision'] == revision + 1
    assert env.db.slot['run'] is None
    event = env.db.public()[-1]
    assert event['kind'] == 'cancelled' and event['payload'] == {'state': 'cancelled', 'cancel_generation': 1,
                                                                 'attempt': a['attempt'], 'exit_receipt_digest': None,
                                                                 'lease_expired': False}
    assert event['object_revision'] == revision + 1
    count = len(env.db.events)
    # Duplicate acknowledgement after the slot is gone is idempotent and silent.
    assert env.store.release_slot(RUN, fence=a['fence'], cancel_generation=1) == 'cancelled'
    assert env.store.acknowledge_cancel(RUN, a['fence'], 1) == 'cancelled'
    assert len(env.db.events) == count and env.db.run['revision'] == revision + 1


@pytest.mark.parametrize('acked', [0, 2])
def test_wrong_generation_ack_retains_slot_and_run(env, acked):
    a = cancelled_attempt(env)
    before = env.db.snapshot()
    with pytest.raises(env.module.CancelGenerationConflict) as exc:
        env.store.release_slot(RUN, fence=a['fence'], cancel_generation=acked)
    assert code(exc) == 'WRONG_GENERATION' and exc.value.current_generation == 1
    assert env.db.snapshot() == before


def test_old_ack_cannot_acknowledge_a_newer_cancel(env):
    a = cancelled_attempt(env)
    env.db.run['cancel_generation'] = 2  # authored newer cancel of the same cancel_requested row
    before = env.db.snapshot()
    with pytest.raises(env.module.CancelGenerationConflict, match='WRONG_GENERATION'):
        env.store.release_slot(RUN, fence=a['fence'], cancel_generation=1)
    assert env.db.snapshot() == before
    # Even after the slot is released without acknowledgement, the old ack stays refused.
    assert env.store.release_slot(RUN, fence=a['fence']) is None
    assert env.db.run['state'] == 'cancel_requested'
    with pytest.raises(env.module.CancelGenerationConflict, match='WRONG_GENERATION'):
        env.store.release_slot(RUN, fence=a['fence'], cancel_generation=1)
    assert env.db.run['state'] == 'cancel_requested'


def test_ack_of_uncancelled_running_attempt_is_refused(env):
    a = claimed(env, 0)
    before = env.db.snapshot()
    with pytest.raises(env.module.CancelGenerationConflict, match='WRONG_GENERATION'):
        env.store.release_slot(RUN, fence=a['fence'], cancel_generation=0)
    assert env.db.snapshot() == before


def test_slot_release_without_ack_leaves_cancel_pending(env):
    a = cancelled_attempt(env)
    assert env.store.release_slot(RUN, fence=a['fence']) is None
    assert env.db.slot['run'] is None and env.db.run['state'] == 'cancel_requested'


def test_ack_after_expiry_cancelled_same_generation_is_idempotent_slot_release(env):
    a = cancelled_attempt(env)
    env.db.run.update(state='cancelled', revision=env.db.run['revision'] + 1)  # authored ML-Expire winner
    count = len(env.db.events)
    assert env.store.release_slot(RUN, fence=a['fence'], cancel_generation=1) == 'cancelled'
    assert env.db.slot['run'] is None and len(env.db.events) == count


def test_legacy_null_cancel_requested_cannot_be_acked_but_slot_releases(env):
    a = cancelled_attempt(env)
    env.db.run['cancel_generation'] = None
    with pytest.raises(env.module.CancelGenerationConflict, match='WRONG_GENERATION'):
        env.store.release_slot(RUN, fence=a['fence'], cancel_generation=1)
    assert env.store.release_slot(RUN, fence=a['fence']) is None
    assert env.db.run['state'] == 'cancel_requested'


def test_ack_event_failure_rolls_back_slot_and_run(env):
    a = cancelled_attempt(env)
    before = env.db.snapshot()
    env.db.fail = lambda sql, params: sql.startswith('INSERT INTO fw_events') and params[2] == 'cancelled'
    with pytest.raises(RuntimeError, match='authored-injected-failure'):
        env.store.release_slot(RUN, fence=a['fence'], cancel_generation=1)
    assert env.db.snapshot() == before
    env.db.fail = None
    assert env.store.release_slot(RUN, fence=a['fence'], cancel_generation=1) == 'cancelled'


def test_ack_still_requires_owner_and_confirmed_exit(env):
    a = cancelled_attempt(env)
    env.db.slot['pid'], env.db.slot['child_created'] = env.module.identity()  # live child
    before = env.db.snapshot()
    with pytest.raises(env.module.Conflict, match='CHILD_EXIT_UNCONFIRMED'):
        env.store.release_slot(RUN, fence=a['fence'], cancel_generation=1)
    with pytest.raises(env.module.Conflict, match='SLOT_OWNER_FENCED'):
        env.store.release_slot(RUN, fence=a['fence'] + 1, cancel_generation=1)
    assert env.db.snapshot() == before


@pytest.mark.parametrize('value', [None, True, '1', -1])
def test_acknowledge_cancel_requires_explicit_generation(env, value):
    a = cancelled_attempt(env)
    calls = len(env.db.calls)
    with pytest.raises(ValueError, match='CANCEL_GENERATION_REQUIRED'):
        env.store.acknowledge_cancel(RUN, a['fence'], value)
    assert len(env.db.calls) == calls


# ---- barrier-scheduled races ---------------------------------------------------------------

@pytest.mark.parametrize('operation', ['checkpoint', 'complete'])
@pytest.mark.parametrize('first', ['cancel', 'operation'])
def test_cancel_versus_publication_linearizes_at_run_lock(env, operation, first):
    a = claimed(env, 0)
    if operation == 'complete':
        env.db.run['epoch'] = 1
    revision = env.db.run['revision']
    work = {
        'cancel': lambda: env.store.cancel_command(WORKSPACE, 'alice', KEY1, RUN, revision, 'Stop it'),
        'operation': operations(env, a, a['cancel_generation'])[operation],
    }
    second = 'operation' if first == 'cancel' else 'cancel'
    blocker = env.db.hold('run:' + RUN)
    actors = {}
    for name in (first, second):
        actors[name] = Actor(name, work[name])
        actors[name].start()
        env.db.wait_until_waiting(name, 'run:' + RUN)
    env.db.release(blocker)
    for actor in actors.values():
        actor.join(10)
        assert not actor.is_alive()
    cancel, op = actors['cancel'], actors['operation']
    assert cancel.error is None
    status, body = cancel.result
    if first == 'cancel':
        assert (status, json.loads(body)['state']) == (200, 'cancel_requested')
        assert isinstance(op.error, env.module.CancelGenerationConflict)
        assert (str(op.error), op.error.state, op.error.current_generation) == ('CANCEL_GENERATION_FENCED', 'cancel_requested', 1)
        assert not env.db.checkpoints and env.db.run['state'] == 'cancel_requested'
        assert env.db.run['cancel_generation'] == 1
    elif operation == 'complete':
        assert op.error is None and env.db.run['state'] == 'succeeded'
        assert (status, json.loads(body)) == (200, {'state': 'succeeded', 'completion_won': True})
        assert env.db.run['cancel_generation'] == 0
    else:
        # Checkpoint commit advanced the revision; the If-Match-bound cancel loses
        # deterministically with a durable 412 and changes no generation.
        assert op.error is None and (RUN, 1) in env.db.checkpoints
        assert status == 412 and json.loads(body)['code'] == 'STALE_REVISION'
        assert env.db.run['cancel_generation'] == 0 and env.db.run['state'] == 'running'
        # A subsequent explicit cancel still cancels and retains the committed checkpoint.
        assert env.store.cancel_command(WORKSPACE, 'alice', KEY2, RUN, env.db.run['revision'], 'Stop it')[0] == 200
        assert env.db.run['cancel_generation'] == 1 and (RUN, 1) in env.db.checkpoints
    assert env.db.slot['run'] == RUN  # physical slot never freed by cancel/complete races


@pytest.mark.parametrize('first', ['cancel', 'heartbeat'])
def test_internal_cancel_versus_heartbeat_linearizes(env, first):
    a = claimed(env, 0)
    work = {'cancel': lambda: env.store.cancel(WORKSPACE, RUN),
            'heartbeat': lambda: env.store.heartbeat(RUN, a['fence'], 0,attempt=a['attempt'])}
    second = 'heartbeat' if first == 'cancel' else 'cancel'
    blocker = env.db.hold('run:' + RUN)
    actors = {}
    for name in (first, second):
        actors[name] = Actor(name, work[name])
        actors[name].start()
        env.db.wait_until_waiting(name, 'run:' + RUN)
    env.db.release(blocker)
    for actor in actors.values():
        actor.join(10)
    assert actors['cancel'].result == 'cancel_requested'
    if first == 'cancel':
        assert str(actors['heartbeat'].error) == 'CANCEL_GENERATION_FENCED'
    else:
        assert actors['heartbeat'].error is None and actors['heartbeat'].result['cancel_requested'] is False
    assert env.db.run['cancel_generation'] == 1


# ---- supervisor and worker client ------------------------------------------------------------

class Process:
    pid = None

    def __init__(self, on_poll=None):
        self.returncode = None
        self.calls = []
        self.on_poll = on_poll

    def poll(self):
        if self.on_poll and self.returncode is None:
            hook, self.on_poll = self.on_poll, None
            hook()
        return self.returncode

    def kill(self):
        self.calls.append('kill')

    def wait(self, timeout):
        self.calls.append('wait')
        self.returncode = -9
        return self.returncode


@pytest.fixture
def clock(monkeypatch):
    from fieldwork import supervisor
    monkeypatch.setattr(supervisor, 'time', types.SimpleNamespace(monotonic=lambda: 100, sleep=lambda _: None))
    return supervisor


def test_supervisor_sends_issued_generation_and_records_observed_cancel(env, clock):
    a = claimed(env, 0)
    seen = []
    heartbeat = env.store.heartbeat
    env.store.heartbeat = lambda *args, **kwargs: seen.append((args, kwargs['attempt'], kwargs['restore_generation'])) or heartbeat(*args, **kwargs)
    process = Process(on_poll=lambda: env.store.cancel(WORKSPACE, RUN))
    clock.watch(env.store, a, process, env.tmp)
    assert seen == [((RUN, a['fence'], 0), a['attempt'], 'authored-restore-generation')]
    assert process.calls == ['kill', 'wait'] and a['observed_cancel_generation'] == 1
    assert env.store.release_slot(RUN, fence=a['fence'], cancel_generation=a['observed_cancel_generation']) == 'cancelled'


def test_supervisor_records_generation_from_typed_heartbeat_refusal(env, clock):
    a = claimed(env, 0)
    env.store.cancel(WORKSPACE, RUN)
    process = Process()
    with pytest.raises(env.module.CancelGenerationConflict, match='CANCEL_GENERATION_FENCED'):
        clock.watch(env.store, a, process, env.tmp)
    assert process.calls == ['kill', 'wait'] and a['observed_cancel_generation'] == 1


def test_supervisor_does_not_record_ack_for_unrelated_refusal(env, clock):
    a = claimed(env, 0)
    env.db.run['_live'] = False
    process = Process()
    with pytest.raises(env.module.Conflict, match='FENCED_OR_EXPIRED'):
        clock.watch(env.store, a, process, env.tmp)
    assert 'observed_cancel_generation' not in a


@pytest.mark.parametrize('path', ['observed', 'refused'])
def test_training_worker_acknowledges_only_the_generation_it_observed(env, monkeypatch, clock, path):
    from fieldwork import worker
    monkeypatch.setattr(worker, 'Store', lambda: env.store)
    monkeypatch.setattr(worker, 'ROOT', env.tmp)
    monkeypatch.setattr(worker, 'generate', lambda _: {'digest': 'authored-dataset'})
    monkeypatch.setattr(worker.psutil, 'virtual_memory', lambda: types.SimpleNamespace(available=1 << 40))
    monkeypatch.setattr(worker.shutil, 'disk_usage', lambda _: types.SimpleNamespace(free=1 << 40))
    env.db.run['config'] = {'epochs': 1, 'dataset_digest': 'authored-dataset', 'scope': 'synthetic-execution-only',
                            'recipe': 'compact-cnn/v1'}
    acks = []
    release = env.store.release_slot
    env.store.release_slot = lambda *args, **kwargs: acks.append(kwargs) or release(*args, **kwargs)
    process = Process(on_poll=(lambda: env.store.cancel(WORKSPACE, RUN)) if path == 'observed' else None)

    def popen(*args, **kwargs):
        if path == 'refused':
            env.store.cancel(WORKSPACE, RUN)  # cancel lands before the first heartbeat
        return process
    monkeypatch.setattr(worker.subprocess, 'Popen', popen)
    if path == 'observed':
        assert worker.execute(RUN) == 0
    else:
        with pytest.raises(env.module.CancelGenerationConflict):
            worker.execute(RUN)
    assert [{k: ack[k] for k in ('fence', 'cancel_generation')} for ack in acks] == [{'fence': 4, 'cancel_generation': 1}]
    assert len(acks[0]['exit_receipt']) and acks[0]['key']  # ML-AcknowledgeCancel carries the exit receipt
    assert len(env.db.attempts[env.db.run['attempt']]['exit_receipt_digest']) == 64
    assert env.db.run['state'] == 'cancelled' and env.db.slot['run'] is None
    assert env.db.attempts[env.db.run['attempt']]['cancel_generation'] == 0


def test_training_worker_refused_ack_frees_slot_and_leaves_cancel_pending(env, monkeypatch, clock):
    from fieldwork import worker
    monkeypatch.setattr(worker, 'Store', lambda: env.store)
    monkeypatch.setattr(worker, 'ROOT', env.tmp)
    monkeypatch.setattr(worker, 'generate', lambda _: {'digest': 'authored-dataset'})
    monkeypatch.setattr(worker.psutil, 'virtual_memory', lambda: types.SimpleNamespace(available=1 << 40))
    monkeypatch.setattr(worker.shutil, 'disk_usage', lambda _: types.SimpleNamespace(free=1 << 40))
    env.db.run['config'] = {'epochs': 1, 'dataset_digest': 'authored-dataset', 'scope': 'synthetic-execution-only',
                            'recipe': 'compact-cnn/v1'}
    acks = []
    release = env.store.release_slot

    def wrong_then_plain(*args, **kwargs):
        acks.append(kwargs)
        if kwargs.get('cancel_generation') is not None:
            kwargs = {**kwargs, 'cancel_generation': 7}  # authored defect: not the observed value
        return release(*args, **kwargs)
    env.store.release_slot = wrong_then_plain
    process = Process(on_poll=lambda: env.store.cancel(WORKSPACE, RUN))
    monkeypatch.setattr(worker.subprocess, 'Popen', lambda *a, **k: process)
    assert worker.execute(RUN) == 0
    assert [{k: v for k, v in ack.items() if k in ('fence', 'cancel_generation')} for ack in acks] == [{'fence': 4, 'cancel_generation': 1}, {'fence': 4}]
    # Slot is free for the next claim; the cancel is not falsely acknowledged.
    assert env.db.slot['run'] is None
    assert env.db.run['state'] == 'cancel_requested' and env.db.run['cancel_generation'] == 1


def test_training_worker_claim_refuses_generation_changed_after_selection(env, monkeypatch):
    from fieldwork import worker
    monkeypatch.setattr(worker, 'Store', lambda: env.store)
    monkeypatch.setattr(worker, 'ROOT', env.tmp)
    monkeypatch.setattr(worker, 'generate', lambda _: {'digest': 'authored-dataset'})
    monkeypatch.setattr(worker.psutil, 'virtual_memory', lambda: types.SimpleNamespace(available=1 << 40))
    monkeypatch.setattr(worker.shutil, 'disk_usage', lambda _: types.SimpleNamespace(free=1 << 40))
    env.db.run['config'] = {'epochs': 1, 'dataset_digest': 'authored-dataset', 'scope': 'synthetic-execution-only',
                            'recipe': 'compact-cnn/v1'}
    get = env.store.get

    def selected_then_changed(rid, workspace=None):
        row = get(rid, workspace)
        env.db.run['cancel_generation'] = 5  # authored concurrent change after the worker's read
        return row
    env.store.get = selected_then_changed
    with pytest.raises(env.module.CancelGenerationConflict, match='CANCEL_GENERATION_CHANGED'):
        worker.execute(RUN)
    assert env.db.run['state'] == 'queued' and env.db.slot['run'] is None and not env.db.attempts
