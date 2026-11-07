"""Real worker liveness follows successful fenced progress, not a free-running timer."""
import json
import os
from pathlib import Path
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from fieldwork.artifact_state import identity
from fieldwork import worker_heartbeat
from fieldwork.real_worker_identity import RealWorkerStore
from fieldwork.worker_identity import MODE, WorkerStore, _heartbeat_live


def _heartbeat(worker_id, *, age_seconds=121, pid=None, created=None):
    current_pid, current_created = identity()
    return {
        'pid': current_pid if pid is None else pid,
        'create_time': current_created if created is None else created,
        'identity': MODE,
        'profile': 'scoped-real-training-and-inference',
        'worker_id': worker_id,
        'as_of': (datetime.now(timezone.utc) - timedelta(seconds=age_seconds)).isoformat(),
    }


def test_successful_long_phase_progress_refreshes_issuer_marker_after_121_seconds(tmp_path, monkeypatch):
    worker_id = 'fieldwork-test-worker'
    monkeypatch.setenv('FIELDWORK_WORKER_ID', worker_id)
    path = tmp_path / 'worker.json'
    original = _heartbeat(worker_id, age_seconds=121)
    path.write_text(json.dumps(original), encoding='utf-8')

    assert _heartbeat_live(path, max_age=120) == (False, 'WORKER_HEARTBEAT_STALE')

    store = RealWorkerStore.__new__(RealWorkerStore)
    store._refresh_liveness_after_progress(path)

    updated = json.loads(path.read_text(encoding='utf-8'))
    assert updated['as_of'] != original['as_of']
    assert {k: updated[k] for k in ('pid', 'create_time', 'identity', 'profile', 'worker_id')} == {
        k: original[k] for k in ('pid', 'create_time', 'identity', 'profile', 'worker_id')
    }
    assert _heartbeat_live(path, max_age=120) == (True, 'WORKER_LIVE')


def test_unset_worker_id_uses_same_effective_fallback_as_supervisor(tmp_path, monkeypatch):
    monkeypatch.delenv('FIELDWORK_WORKER_ID', raising=False)
    worker_id = worker_heartbeat.effective_worker_id()
    path = tmp_path / 'worker.json'
    path.write_text(json.dumps(_heartbeat(worker_id)), encoding='utf-8')

    worker_heartbeat.refresh_worker_heartbeat_after_progress(path)

    assert _heartbeat_live(path, max_age=120) == (True, 'WORKER_LIVE')


def test_stopped_phase_does_not_refresh_stale_marker(tmp_path, monkeypatch):
    worker_id = 'fieldwork-test-worker'
    monkeypatch.setenv('FIELDWORK_WORKER_ID', worker_id)
    path = tmp_path / 'worker.json'
    path.write_text(json.dumps(_heartbeat(worker_id, age_seconds=121)), encoding='utf-8')

    # No successful progress callback means no update; the issuer fails closed.
    assert _heartbeat_live(path, max_age=120) == (False, 'WORKER_HEARTBEAT_STALE')


@pytest.mark.parametrize(('field', 'value'), [
    ('create_time', -1.0),
    ('identity', 'trusted-operator'),
    ('profile', 'trusted-synthetic-only'),
    ('worker_id', 'other-worker'),
])
def test_progress_refresh_refuses_mismatched_marker_identity(tmp_path, monkeypatch, field, value):
    worker_id = 'fieldwork-test-worker'
    monkeypatch.setenv('FIELDWORK_WORKER_ID', worker_id)
    path = tmp_path / 'worker.json'
    marker = _heartbeat(worker_id)
    marker[field] = value
    original = json.dumps(marker)
    path.write_text(original, encoding='utf-8')

    store = RealWorkerStore.__new__(RealWorkerStore)
    with pytest.raises(OSError, match='WORKER_HEARTBEAT_REFRESH_FAILED'):
        store._refresh_liveness_after_progress(path)

    assert path.read_text(encoding='utf-8') == original


def test_progress_refresh_rejects_a_different_pid_birth(tmp_path, monkeypatch):
    worker_id = 'fieldwork-test-worker'
    monkeypatch.setenv('FIELDWORK_WORKER_ID', worker_id)
    path = tmp_path / 'worker.json'
    marker = _heartbeat(worker_id)
    marker['pid'] = os.getpid() + 100000
    original = json.dumps(marker)
    path.write_text(original, encoding='utf-8')

    store = RealWorkerStore.__new__(RealWorkerStore)
    with pytest.raises(OSError, match='WORKER_HEARTBEAT_REFRESH_FAILED'):
        store._refresh_liveness_after_progress(path)

    assert path.read_text(encoding='utf-8') == original


def test_db_heartbeat_must_succeed_before_marker_refresh(monkeypatch):
    store = RealWorkerStore.__new__(RealWorkerStore)
    events = []
    monkeypatch.setattr(WorkerStore, 'heartbeat', lambda *a, **k: events.append('db') or {'renewed': True})
    monkeypatch.setattr(RealWorkerStore, '_refresh_liveness_after_progress', lambda *a, **k: events.append('marker'))

    assert store.heartbeat('run', 1, 0, attempt='attempt') == {'renewed': True}
    assert events == ['db', 'marker']

    events.clear()
    def refused(*_args, **_kwargs):
        events.append('db')
        raise OSError('database_refused')
    monkeypatch.setattr(WorkerStore, 'heartbeat', refused)
    with pytest.raises(OSError, match='database_refused'):
        store.heartbeat('run', 1, 0, attempt='attempt')
    assert events == ['db']


def test_artifact_heartbeat_must_succeed_before_marker_refresh(monkeypatch):
    store = RealWorkerStore.__new__(RealWorkerStore)
    events = []
    monkeypatch.setattr(WorkerStore, 'artifact_heartbeat', lambda *a, **k: events.append('db'))
    monkeypatch.setattr(RealWorkerStore, '_refresh_liveness_after_progress', lambda *a, **k: events.append('marker'))

    store.artifact_heartbeat('run', 1)
    assert events == ['db', 'marker']

    events.clear()
    def refused(*_args, **_kwargs):
        events.append('db')
        raise OSError('database_refused')
    monkeypatch.setattr(WorkerStore, 'artifact_heartbeat', refused)
    with pytest.raises(OSError, match='database_refused'):
        store.artifact_heartbeat('run', 1)
    assert events == ['db']


def test_temp_replace_failure_cleans_temp_and_preserves_current_marker(tmp_path, monkeypatch):
    worker_id = 'fieldwork-test-worker'
    monkeypatch.setenv('FIELDWORK_WORKER_ID', worker_id)
    path = tmp_path / 'worker.json'
    marker = _heartbeat(worker_id)
    original = json.dumps(marker)
    path.write_text(original, encoding='utf-8')

    def fail_replace(*_args, **_kwargs):
        raise OSError('replace_refused')
    monkeypatch.setattr(worker_heartbeat.os, 'replace', fail_replace)
    store = RealWorkerStore.__new__(RealWorkerStore)
    with pytest.raises(OSError, match='WORKER_HEARTBEAT_REFRESH_FAILED'):
        store._refresh_liveness_after_progress(path)

    assert path.read_text(encoding='utf-8') == original
    assert list(tmp_path.glob('.worker-heartbeat-*.tmp')) == []


def test_concurrent_new_marker_cannot_be_clobbered_by_old_progress_writer(tmp_path, monkeypatch):
    old_worker_id = 'old-worker'
    monkeypatch.setenv('FIELDWORK_WORKER_ID', old_worker_id)
    path = tmp_path / 'worker.json'
    old = _heartbeat(old_worker_id)
    path.write_text(json.dumps(old), encoding='utf-8')
    old_pid = old['pid']
    old_stopped = threading.Event()
    entered_atomic_write = threading.Event()
    allow_old_write = threading.Event()
    new_done = threading.Event()
    outcomes = []
    original_write = worker_heartbeat._write_marker

    def simulated_alive(pid, created):
        if pid == old_pid:
            return not old_stopped.is_set()
        return False

    def pause_old_write(target, value):
        if value.get('worker_id') == old_worker_id:
            entered_atomic_write.set()
            if not allow_old_write.wait(3):
                raise TimeoutError('test_write_release_timeout')
        return original_write(target, value)

    monkeypatch.setattr(worker_heartbeat, 'alive', simulated_alive)
    monkeypatch.setattr(worker_heartbeat, '_write_marker', pause_old_write)

    def old_progress():
        worker_heartbeat.refresh_worker_heartbeat_after_progress(path)

    def new_startup():
        new_marker = _heartbeat('new-worker', pid=old_pid + 100000, created=1.0)
        try:
            worker_heartbeat.publish_worker_heartbeat(new_marker, path)
            outcomes.append('published')
        except OSError as exc:
            outcomes.append(str(exc))
        finally:
            new_done.set()

    old_thread = threading.Thread(target=old_progress)
    new_thread = threading.Thread(target=new_startup)
    old_thread.start()
    assert entered_atomic_write.wait(2)
    new_thread.start()
    time.sleep(.05)
    assert not new_done.is_set()
    old_stopped.set()
    allow_old_write.set()
    old_thread.join(2)
    new_thread.join(2)

    assert not old_thread.is_alive() and not new_thread.is_alive()
    assert outcomes == ['published']
    final = json.loads(path.read_text(encoding='utf-8'))
    assert final['worker_id'] == 'new-worker'


def _activation_helper():
    import importlib.util
    helper_path = Path(__file__).resolve().parents[1] / 'tools' / 'activate_real_worker.py'
    spec = importlib.util.spec_from_file_location('fieldwork_activation_helper_test', helper_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_detached_handoff_rejects_wrong_drive_and_lexical_parent_before_resolution():
    helper = _activation_helper()
    with pytest.raises(RuntimeError, match='DETACHED_ACTIVATION_HANDOFF_PATH_INVALID'):
        helper._validated_handoff_path('D:\\private\\' + 'a' * 32 + '.json')
    invalid = helper.ROOT / '.local/real-data/activation-handoffs/..' / ('a' * 32 + '.json')
    with pytest.raises(RuntimeError, match='DETACHED_ACTIVATION_HANDOFF_PATH_INVALID'):
        helper._validated_handoff_path(invalid)


def test_detached_handoff_refuses_reparse_parent_before_resolve(tmp_path, monkeypatch):
    from types import SimpleNamespace
    helper = _activation_helper()
    helper.ROOT = tmp_path / 'fieldwork'
    handoff_dir = helper.ROOT / '.local/real-data/activation-handoffs'
    handoff_dir.mkdir(parents=True)
    target = handoff_dir / ('b' * 32 + '.json')
    target.write_text('{}', encoding='utf-8')
    original_lstat = Path.lstat

    def injected_reparse(path):
        if os.path.normcase(os.path.normpath(str(path))) == os.path.normcase(os.path.normpath(str(handoff_dir))):
            return SimpleNamespace(st_mode=0o040755, st_file_attributes=0x400)
        return original_lstat(path)

    monkeypatch.setattr(Path, 'lstat', injected_reparse)
    with pytest.raises(RuntimeError, match='DETACHED_ACTIVATION_HANDOFF_REPARSE_REFUSED'):
        helper._validated_handoff_path(target)


def test_detached_handoff_claim_is_one_time_and_stale_lock_fails_closed(tmp_path, monkeypatch):
    from fieldwork import scoped_authority
    helper = _activation_helper()
    helper.ROOT = tmp_path / 'fieldwork'
    helper.REPO = tmp_path
    (tmp_path / 'tools').mkdir()
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'tools'))
    handoff_dir = helper.ROOT / '.local/real-data/activation-handoffs'
    handoff_dir.mkdir(parents=True)
    handoff_id = 'c' * 32
    path = handoff_dir / f'{handoff_id}.json'
    payload = {'schema': 'fieldwork.detached-activation-handoff/v1', 'status': 'prepared',
        'id': handoff_id, 'action_argv': ['start-issuer'], 'environment': {},
        'lock_owner': {'pid': 1, 'create_time': 1.0},
        'lock_path': str(tmp_path / '.cache/product-build.lock'), 'purpose': helper.PURPOSE,
        'created_utc': datetime.now(timezone.utc).isoformat(), 'expires_epoch': time.time() + 60}
    path.write_text(json.dumps(payload), encoding='utf-8')
    monkeypatch.setattr(scoped_authority, 'check_private', lambda _path: None)
    monkeypatch.setattr(helper, '_DETACHED_HANDOFF', None)

    assert helper._detached_entry(path) == 2
    result = json.loads(path.with_name(path.stem + '.result.json').read_text(encoding='utf-8'))
    assert result['exit_code'] == 2
    assert result['result']['code'] == 'FIELDWORK_REAL_ACTIVATION_HANDOFF_LOCK_INVALID'
    with pytest.raises(FileExistsError):
        helper._detached_entry(path)
