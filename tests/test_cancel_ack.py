"""release_slot SQL-adapter regressions, NOT PostgreSQL or physical-worker proof.

Round 3: acknowledgement now names the cancel generation the worker observed
(release_slot(..., cancel_generation=N)); slot-only release no longer changes run state.
"""
import copy
import sys
import types
from contextlib import contextmanager
from typing import Any
import pytest


class Database:
    def __init__(self, owner):
        self.slot: dict[str, Any] = dict(run='authored-run', fence=3, owner_pid=owner[0],
                         owner_created=owner[1], pid=None, child_created=None, launching=False)
        self.run: dict[str, Any] = dict(id='authored-run', workspace='authored-lab', state='cancel_requested',
                        revision=8, fence=4, result={'preserved': 'authored-result'}, cancel_generation=1)
        self.events = []
        self.row = None
        self.fail_event = False

    @contextmanager
    def connect(self):
        before = copy.deepcopy((self.slot, self.run, self.events))
        try:
            yield self
        except BaseException:
            self.slot, self.run, self.events = before
            raise

    def execute(self, sql, params=()):
        self.row = None
        if sql.startswith('SELECT * FROM fw_slot'):
            self.row = copy.deepcopy(self.slot)
        elif sql.startswith('UPDATE fw_slot SET run=NULL'):
            for name in ('run', 'pid', 'child_created', 'owner_pid', 'owner_created', 'fence'):
                self.slot[name] = None
        elif sql == 'SELECT * FROM fw_runs WHERE id=%s FOR UPDATE':
            self.row = copy.deepcopy(self.run) if params[0] == self.run['id'] else None
        elif sql.startswith("UPDATE fw_runs SET state='cancelled'"):
            assert "AND cancel_generation=%s" in sql
            if self.run['id'] == params[0] and self.run['state'] == 'cancel_requested' and self.run['cancel_generation'] == params[1]:
                self.run['state'] = 'cancelled'
                if 'revision=revision+1' in sql:
                    self.run['revision'] += 1
                if 'RETURNING' in sql:
                    self.row = copy.deepcopy(self.run)
        elif sql.startswith('SELECT revision FROM fw_runs'):
            self.row = dict(revision=self.run['revision'])
        elif sql.startswith('INSERT INTO fw_events'):
            if self.fail_event:
                raise RuntimeError('authored-event-insert-failure')
            workspace, rid, kind, payload, revision = params
            self.events.append(dict(workspace=workspace, run=rid, kind=kind,
                                    payload=copy.deepcopy(payload.obj), object_revision=revision))
        else:
            raise AssertionError('Unexpected SQL: ' + sql)
        return self

    def fetchone(self):
        return self.row


@pytest.fixture
def adapter(monkeypatch):
    if 'fieldwork.data' not in sys.modules:
        pil = types.ModuleType('PIL')
        setattr(pil, 'Image', None)
        setattr(pil, 'ImageDraw', None)
        monkeypatch.setitem(sys.modules, 'PIL', pil)
    from fieldwork import store as module
    db = Database(module.identity())
    store = object.__new__(module.Store)
    monkeypatch.setattr(store, 'connect', db.connect)
    return module, store, db


def test_confirmed_cancel_ack_increments_revision_and_appends_one_terminal_event(adapter):
    _, store, db = adapter
    before = copy.deepcopy(db.run)
    assert store.release_slot('authored-run', fence=3, cancel_generation=1) == 'cancelled'
    assert db.run['state'] == 'cancelled'
    assert db.run['revision'] == before['revision'] + 1
    assert db.run['fence'] == before['fence']
    assert db.run['result'] == before['result']
    assert db.slot['run'] is None
    assert db.events == [dict(workspace='authored-lab', run='authored-run', kind='cancelled',
                              payload={'state': 'cancelled', 'cancel_generation': 1, 'attempt': None,
                                       'exit_receipt_digest': None, 'lease_expired': False}, object_revision=9)]
    assert store.release_slot('authored-run', fence=3, cancel_generation=1) == 'cancelled'
    assert len(db.events) == 1
    assert db.run['revision'] == 9


@pytest.mark.parametrize('guard', ['fence', 'owner_pid', 'owner_created', 'launching', 'live_child', 'unknown_child'])
def test_cancel_ack_retains_slot_and_run_when_ownership_or_exit_is_unconfirmed(adapter, guard):
    module, store, db = adapter
    fence = 3
    if guard == 'fence':
        fence = 4
    elif guard == 'owner_pid':
        db.slot['owner_pid'] = -1
    elif guard == 'owner_created':
        db.slot['owner_created'] += 1
    elif guard == 'launching':
        db.slot['launching'] = True
    else:
        db.slot['pid'], db.slot['child_created'] = module.identity()
        if guard == 'unknown_child':
            db.slot['child_created'] = None
    before = copy.deepcopy((db.slot, db.run, db.events))
    with pytest.raises(module.Conflict, match='SLOT_OWNER_FENCED|CHILD_EXIT_UNCONFIRMED'):
        store.release_slot('authored-run', fence=fence, cancel_generation=1)
    assert (db.slot, db.run, db.events) == before


@pytest.mark.parametrize('state', ['succeeded', 'failed', 'cancelled', 'interrupted'])
def test_slot_cleanup_does_not_revise_or_emit_for_an_already_settled_run(adapter, state):
    _, store, db = adapter
    db.run['state'] = state
    before = copy.deepcopy(db.run)
    store.release_slot('authored-run', fence=3)
    assert db.run == before
    assert db.slot['run'] is None
    assert db.events == []


def test_cancel_ack_event_failure_rolls_back_modeled_state_and_slot(adapter):
    _, store, db = adapter
    before = copy.deepcopy((db.slot, db.run, db.events))
    db.fail_event = True
    with pytest.raises(RuntimeError, match='authored-event-insert-failure'):
        store.release_slot('authored-run', fence=3, cancel_generation=1)
    assert (db.slot, db.run, db.events) == before


@pytest.mark.parametrize('fenced_heartbeat', [False, True])
def test_supervisor_protocol_confirms_exit_before_cancel_ack(adapter, monkeypatch, tmp_path, fenced_heartbeat):
    # Process/clock stand-ins exercise the real watch branches, NOT physical exit.
    module, store, db = adapter
    from fieldwork import supervisor
    calls = []

    class Process:
        returncode = None
        def poll(self):
            return self.returncode
        def kill(self):
            calls.append('kill')
        def wait(self, timeout):
            calls.append('wait')
            self.returncode = -1
            return self.returncode

    def heartbeat(*args, **kwargs):
        if fenced_heartbeat:
            # What live() now raises for a worker whose issued generation was cancelled.
            raise module.CancelGenerationConflict('CANCEL_GENERATION_FENCED', 'cancel_requested', 1)

    monkeypatch.setattr(store, 'heartbeat', heartbeat)
    monkeypatch.setattr(store, 'get', lambda *args: copy.deepcopy(db.run))
    monkeypatch.setattr(supervisor, 'time', types.SimpleNamespace(monotonic=lambda: 100, sleep=lambda _: None))
    process = Process()
    attempt = {'id': 'authored-run', 'fence': 3, 'cancel_generation': 0}
    try:
        if fenced_heartbeat:
            with pytest.raises(module.Conflict, match='CANCEL_GENERATION_FENCED'):
                supervisor.watch(store, attempt, process, tmp_path)
        else:
            supervisor.watch(store, attempt, process, tmp_path)
    finally:
        assert calls == ['kill', 'wait']
        assert process.poll() is not None
        assert attempt['observed_cancel_generation'] == 1
        store.release_slot('authored-run', fence=3, cancel_generation=attempt['observed_cancel_generation'])
    assert db.run['state'] == 'cancelled' and db.run['revision'] == 9
    assert len(db.events) == 1 and db.events[0]['object_revision'] == 9
