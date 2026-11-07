"""Focused tests for immutable budget history, process CPU limits, and pause leases."""
import json
import hashlib
import importlib.util
import math
import os
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import psutil
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import r5_train as train  # noqa: E402
import r5_host  # noqa: E402

CFG = train.rr.default_config(threads=1)


def _init_files(tmp_path):
    ledger = tmp_path / 'config-ledger.json'
    history = tmp_path / 'config-history.jsonl'
    train.initialize_budget_ledger(ledger, history, lock_record=_bootstrap_lock_record())
    return ledger, history


def _bootstrap_lock_record():
    p = psutil.Process()
    purpose = 'round5-config-ledger-bootstrap'
    return {'pid': os.getpid(), 'create_time': p.create_time(),
            'owner': f'fieldwork-dataset-round5-{purpose}-{os.getpid()}',
            'product': 'fieldwork', 'purpose': purpose}


def _lock_record(tag):
    p = psutil.Process()
    return {'pid': os.getpid(), 'create_time': p.create_time(),
            'owner': f'fieldwork-dataset-round5-train-{tag}-{os.getpid()}',
            'product': 'fieldwork', 'purpose': f'train-{tag}'}


def _job_scope(row, pid, create_time, launcher_pid, launcher_create_time):
    flags = r5_host.JOB_OBJECT_LIMIT_JOB_TIME | r5_host.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    return {'schema_version': 1, 'launch_nonce': row['launch_nonce'],
            'job_object_name': 'Local\\FieldworkTraining-' + ('a' * 64),
            'child_pid': pid, 'child_create_time': create_time,
            'launcher_pid': launcher_pid, 'launcher_create_time': launcher_create_time,
            'in_exact_job': True, 'kill_on_close': True, 'limit_flags': flags,
            'cpu_limit_ticks': (row['cpu_seconds_reserved'] - 30) * r5_host.CPU_TIME_TICKS_PER_SECOND,
            'reserved_cpu_seconds': row['cpu_seconds_reserved'], 'job_scope_nonce': 'b' * 64}


def _reconcile_lock_record():
    p = psutil.Process()
    purpose = 'round5-config-ledger-reconcile'
    return {'pid': os.getpid(), 'create_time': p.create_time(),
            'owner': f'fieldwork-dataset-round5-{purpose}-{os.getpid()}',
            'product': 'fieldwork', 'purpose': purpose}


def _reserve(ledger, history, tag):
    return train.reserve_configuration(ledger, tag, CFG, 'bounded test',
                                       lock_record=_lock_record(tag), history_path=history)


def _finish_failed(ledger, history, state, attempt, elapsed=1):
    train.finish_attempt(ledger, state, attempt, status='failed', elapsed_s=elapsed,
                         cpu_seconds_charged=1, fields={'error_type': 'SyntheticFailure'}, history_path=history)


def _contend(ledger, history, lock, tag):
    with lock:
        try:
            state, row, _ = _reserve(ledger, history, tag)
            _finish_failed(ledger, history, state, row)
            return ('reserved', row['tag'])
        except SystemExit as exc:
            return ('refused', str(exc))


def _run_pair(ledger, history, tags):
    lock = threading.Lock()
    barrier = threading.Barrier(2)
    def contender(tag):
        barrier.wait(timeout=3)
        return _contend(ledger, history, lock, tag)
    with ThreadPoolExecutor(max_workers=2) as pool:
        return list(pool.map(contender, tags))


def test_two_serialized_contenders_same_tag_only_reserve_once(tmp_path):
    ledger, history = _init_files(tmp_path)
    results = _run_pair(ledger, history, ('r5cfg2', 'r5cfg2'))

    assert sorted(result[0] for result in results) == ['refused', 'reserved']
    assert ('refused', 'TAG_ALREADY_USED') in results
    state = train._load_current_ledger(ledger, history)
    assert [row['tag'] for row in state['configs']] == ['cfg1', 'r5cfg2']


def test_two_serialized_contenders_cannot_cross_config_cap(tmp_path):
    ledger, history = _init_files(tmp_path)
    for i in range(4):
        state, row, _ = _reserve(ledger, history, f'prior{i}')
        _finish_failed(ledger, history, state, row)

    results = _run_pair(ledger, history, ('r5cfg5', 'r5cfg6'))

    assert sorted(result[0] for result in results) == ['refused', 'reserved']
    assert any(result[1] == 'EXPLORATION_CONFIG_CAP_EXHAUSTED configs=6' for result in results if result[0] == 'refused')
    assert len(train._load_current_ledger(ledger, history)['configs']) == train.CAP_CONFIGS_TOTAL


def test_failed_attempt_remains_in_hash_chained_history_and_tag_cannot_be_reused(tmp_path):
    ledger, history = _init_files(tmp_path)
    state, attempt, _ = _reserve(ledger, history, 'r5cfg2')
    _finish_failed(ledger, history, state, attempt, elapsed=12.5)

    persisted = train._load_current_ledger(ledger, history)
    failed = persisted['configs'][-1]
    assert len(persisted['configs']) == 2
    assert failed['tag'] == 'r5cfg2' and failed['status'] == 'failed'
    assert failed['cpu_seconds_charged'] == 1
    with pytest.raises(SystemExit, match='TAG_ALREADY_USED'):
        _reserve(ledger, history, 'r5cfg2')


def test_exact_cfg1_baseline_is_required_and_immutable(tmp_path):
    ledger, history = _init_files(tmp_path)
    state = train._load_current_ledger(ledger, history)
    state['configs'][0]['elapsed_s'] += 1
    with pytest.raises(SystemExit, match='LEDGER_BASELINE_INVALID'):
        train._validate_ledger(state)
    state['configs'][0] = {'tag': 'replacement', **state['configs'][0]}
    with pytest.raises(SystemExit):
        train._validate_ledger(state)


def test_missing_initialized_ledger_never_reverts_to_baseline(tmp_path):
    ledger, history = _init_files(tmp_path)
    ledger.unlink()
    with pytest.raises(SystemExit, match='LEDGER_MISSING_AFTER_INITIALIZATION'):
        train._load_current_ledger(ledger, history)


def test_explicit_bootstrap_is_one_time_and_creates_cfg1_only(tmp_path):
    ledger = tmp_path / 'config-ledger.json'
    history = tmp_path / 'config-history.jsonl'
    receipt = train.initialize_budget_ledger(ledger, history, lock_record=_bootstrap_lock_record())
    state = train._load_current_ledger(ledger, history)
    assert state['configs'] == [train.ROUND4_CONFIG1]
    assert receipt['history_digest'] == train._genesis_event()['digest']
    assert train._anchor_paths(ledger)[0].is_file()
    assert train._anchor_paths(ledger)[1].is_file()
    with pytest.raises(SystemExit, match='LEDGER_BOOTSTRAP_STATE_ALREADY_EXISTS'):
        train.initialize_budget_ledger(ledger, history, lock_record=_bootstrap_lock_record())


def test_coordinated_ledger_history_reset_diverges_from_durable_anchor(tmp_path):
    ledger, history = _init_files(tmp_path)
    state, row, _ = _reserve(ledger, history, 'r5cfg2')
    _finish_failed(ledger, history, state, row)
    anchor, receipt = train._anchor_paths(ledger)
    anchor_before = anchor.read_bytes()
    # Simulate restoring both mutable files to the pristine genesis snapshot.
    genesis = train._genesis_event()
    history.write_bytes(train._json_bytes(genesis) + b'\n')
    train._write_ledger_atomic(ledger, train._genesis_ledger(genesis))
    with pytest.raises(SystemExit):
        train._load_current_ledger(ledger, history)
    assert anchor.read_bytes() == anchor_before and receipt.exists()


def test_missing_or_tampered_history_fails_closed(tmp_path):
    ledger, history = _init_files(tmp_path)
    history.unlink()
    with pytest.raises(SystemExit, match='LEDGER_HISTORY_MISSING_OR_UNSAFE'):
        train._load_current_ledger(ledger, history)


def test_history_chain_tampering_fails_closed(tmp_path):
    ledger, history = _init_files(tmp_path)
    state, row, _ = _reserve(ledger, history, 'r5cfg2')
    state, row = train.record_spawn_intent(ledger, 'r5cfg2', history_path=history)
    train.record_child_started(ledger, 'r5cfg2', 111111111, 100.0, row['launch_nonce'],
            launcher_pid=111111111, launcher_create_time=100.0,
            job_scope=_job_scope(row, 111111111, 100.0, 111111111, 100.0), history_path=history)
    _finish_failed(ledger, history, state, row)
    lines = history.read_bytes().splitlines()
    event = json.loads(lines[1])
    event['payload']['row']['why'] = 'altered'
    lines[1] = train._json_bytes(event)
    history.write_bytes(b'\n'.join(lines) + b'\n')
    with pytest.raises(SystemExit):
        train._load_current_ledger(ledger, history)


@pytest.mark.parametrize('crash_stage', ['history_appended', 'ledger_replaced'])
def test_valid_partial_commit_is_archived_and_reconciled_without_new_budget(tmp_path, monkeypatch, crash_stage):
    ledger, history = _init_files(tmp_path)
    anchor, receipt = train._anchor_paths(ledger)
    archive = tmp_path / 'recovery-archive'
    original_write_ledger = train._write_ledger_atomic
    original_write_anchor = train._write_anchor
    if crash_stage == 'history_appended':
        def fail_after_append(path, value):
            if Path(path) == ledger and value.get('history_seq') == 1:
                raise OSError('simulated power loss after history append')
            return original_write_ledger(path, value)
        monkeypatch.setattr(train, '_write_ledger_atomic', fail_after_append)
    else:
        def fail_before_anchor(anchor_path, receipt_path, ledger_path, history_path, value):
            if Path(ledger_path) == ledger and value.get('history_seq') == 1:
                raise OSError('simulated power loss after ledger replace')
            return original_write_anchor(anchor_path, receipt_path, ledger_path, history_path, value)
        monkeypatch.setattr(train, '_write_anchor', fail_before_anchor)
    with pytest.raises(OSError, match='simulated power loss'):
        _reserve(ledger, history, 'r5cfg2')
    monkeypatch.undo()

    result = train.reconcile_budget_state(ledger, history, current_lock=_reconcile_lock_record(),
            anchor_path=anchor, receipt_path=receipt, archive_root=archive)

    state = train._load_current_ledger(ledger, history, anchor_path=anchor, receipt_path=receipt)
    assert result['reconciled'] is True and result['history_seq'] == 1
    assert [row['tag'] for row in state['configs']] == ['cfg1', 'r5cfg2']
    assert state['configs'][-1]['status'] == 'running'
    assert train._cpu_spent(state) == math.ceil(train.ROUND4_CONFIG1['elapsed_s'] * 2) + state['configs'][-1]['cpu_seconds_reserved']
    archived = Path(result['audit_dir'])
    assert (archived / 'recovery-intent.json').is_file()
    assert (archived / 'recovery-complete.json').is_file()
    assert (archived / 'config-ledger.json').is_file()
    assert (archived / 'config-history.jsonl').is_file()


def test_verified_recovery_intent_is_finalized_idempotently_after_completion_receipt_crash(tmp_path, monkeypatch):
    ledger, history = _init_files(tmp_path)
    anchor, receipt = train._anchor_paths(ledger)
    archive = tmp_path / 'recovery-archive'
    original_write_anchor = train._write_anchor

    def fail_after_ledger_replace(anchor_path, receipt_path, ledger_path, history_path, value):
        if Path(ledger_path) == ledger and value.get('history_seq') == 1:
            raise OSError('simulated power loss after ledger replace')
        return original_write_anchor(anchor_path, receipt_path, ledger_path, history_path, value)

    monkeypatch.setattr(train, '_write_anchor', fail_after_ledger_replace)
    with pytest.raises(OSError, match='simulated power loss'):
        _reserve(ledger, history, 'r5cfg2')
    monkeypatch.setattr(train, '_write_anchor', original_write_anchor)

    original_link = os.link

    def fail_receipt_publication(source, target):
        if Path(target).name == 'recovery-complete.json':
            raise OSError('simulated crash during completion publication')
        return original_link(source, target)

    monkeypatch.setattr(os, 'link', fail_receipt_publication)
    with pytest.raises(SystemExit, match='RECOVERY_COMPLETION_PUBLISH_FAILED'):
        train.reconcile_budget_state(ledger, history, current_lock=_reconcile_lock_record(),
                anchor_path=anchor, receipt_path=receipt, archive_root=archive)
    monkeypatch.setattr(os, 'link', original_link)

    intents = list(archive.glob('*/recovery-intent.json'))
    assert len(intents) == 1
    audit_dir = intents[0].parent
    completion_path = audit_dir / 'recovery-complete.json'
    assert not completion_path.exists()
    partial_temps = list(audit_dir.glob('.recovery-complete-*.tmp'))
    assert len(partial_temps) == 1
    files_before_retry = {p: p.read_bytes() for p in (ledger, history, anchor, receipt)}
    state_before_retry = train._load_current_ledger(ledger, history, anchor_path=anchor, receipt_path=receipt)
    spent_before_retry = train._cpu_spent(state_before_retry)

    result = train.reconcile_budget_state(ledger, history, current_lock=_reconcile_lock_record(),
            anchor_path=anchor, receipt_path=receipt, archive_root=archive)

    assert result == {'reconciled': False, 'history_seq': 1,
                      'history_digest': state_before_retry['history_digest'],
                      'intent_finalized': True, 'audit_dir': str(audit_dir)}
    completion = json.loads(completion_path.read_text(encoding='utf-8'))
    assert completion['state'] == 'recovery-complete'
    assert completion['recovered_history_seq'] == state_before_retry['history_seq']
    assert completion['recovered_history_digest'] == state_before_retry['history_digest']
    assert completion['verified_current_sha256'] == {
        'config-ledger.json': hashlib.sha256(files_before_retry[ledger]).hexdigest(),
        'config-history.jsonl': hashlib.sha256(files_before_retry[history]).hexdigest(),
        'config-budget-anchor.json': hashlib.sha256(files_before_retry[anchor]).hexdigest(),
        'config-budget-bootstrap.json': hashlib.sha256(files_before_retry[receipt]).hexdigest()}
    state_after_retry = train._load_current_ledger(ledger, history, anchor_path=anchor, receipt_path=receipt)
    assert {p: p.read_bytes() for p in files_before_retry} == files_before_retry
    assert train._cpu_spent(state_after_retry) == spent_before_retry
    assert partial_temps[0].is_file()
    completion_bytes = completion_path.read_bytes()
    second_retry = train.reconcile_budget_state(ledger, history, current_lock=_reconcile_lock_record(),
            anchor_path=anchor, receipt_path=receipt, archive_root=archive)
    assert second_retry == {'reconciled': False, 'history_seq': 1,
                            'history_digest': state_after_retry['history_digest']}
    assert completion_path.read_bytes() == completion_bytes


def test_truncated_existing_completion_receipt_fails_closed_and_archives_state(tmp_path, monkeypatch):
    ledger, history = _init_files(tmp_path)
    anchor, receipt = train._anchor_paths(ledger)
    archive = tmp_path / 'recovery-archive'
    original_write_anchor = train._write_anchor

    def fail_after_ledger_replace(anchor_path, receipt_path, ledger_path, history_path, value):
        if Path(ledger_path) == ledger and value.get('history_seq') == 1:
            raise OSError('simulated power loss after ledger replace')
        return original_write_anchor(anchor_path, receipt_path, ledger_path, history_path, value)

    monkeypatch.setattr(train, '_write_anchor', fail_after_ledger_replace)
    with pytest.raises(OSError, match='simulated power loss'):
        _reserve(ledger, history, 'r5cfg2')
    monkeypatch.setattr(train, '_write_anchor', original_write_anchor)

    original_link = os.link
    monkeypatch.setattr(os, 'link', lambda source, target: (
        (_ for _ in ()).throw(OSError('simulated publication interruption'))
        if Path(target).name == 'recovery-complete.json' else original_link(source, target)))
    with pytest.raises(SystemExit, match='RECOVERY_COMPLETION_PUBLISH_FAILED'):
        train.reconcile_budget_state(ledger, history, current_lock=_reconcile_lock_record(),
                anchor_path=anchor, receipt_path=receipt, archive_root=archive)
    monkeypatch.setattr(os, 'link', original_link)

    intents = list(archive.glob('*/recovery-intent.json'))
    assert len(intents) == 1
    audit_dir = intents[0].parent
    completion_path = audit_dir / 'recovery-complete.json'
    completion_path.write_bytes(b'{"state":"recovery-complete"')
    state_before = {path: path.read_bytes() for path in (ledger, history, anchor, receipt)}

    with pytest.raises(SystemExit, match='LEDGER_RECONCILE_COMPLETION_INVALID'):
        train.reconcile_budget_state(ledger, history, current_lock=_reconcile_lock_record(),
                anchor_path=anchor, receipt_path=receipt, archive_root=archive)

    assert {path: path.read_bytes() for path in state_before} == state_before
    refusal_receipts = list(archive.glob('*/recovery-refused.json'))
    assert len(refusal_receipts) == 1
    refusal = json.loads(refusal_receipts[0].read_text(encoding='utf-8'))
    assert refusal['reason'] == 'LEDGER_RECONCILE_COMPLETION_INVALID'
    assert completion_path.read_bytes() == b'{"state":"recovery-complete"'


def test_valid_older_completion_is_accepted_after_history_advances(tmp_path, monkeypatch):
    ledger, history = _init_files(tmp_path)
    anchor, receipt = train._anchor_paths(ledger)
    archive = tmp_path / 'recovery-archive'
    original_write_anchor = train._write_anchor

    def fail_after_ledger_replace(anchor_path, receipt_path, ledger_path, history_path, value):
        if Path(ledger_path) == ledger and value.get('history_seq') == 1:
            raise OSError('simulated power loss after ledger replace')
        return original_write_anchor(anchor_path, receipt_path, ledger_path, history_path, value)

    monkeypatch.setattr(train, '_write_anchor', fail_after_ledger_replace)
    with pytest.raises(OSError, match='simulated power loss'):
        _reserve(ledger, history, 'r5cfg2')
    monkeypatch.setattr(train, '_write_anchor', original_write_anchor)
    train.reconcile_budget_state(ledger, history, current_lock=_reconcile_lock_record(),
            anchor_path=anchor, receipt_path=receipt, archive_root=archive)
    old_complete = next(archive.glob('*/recovery-complete.json'))
    completed = json.loads(old_complete.read_text(encoding='utf-8'))
    assert completed['recovered_history_seq'] == 1

    state = train._load_current_ledger(ledger, history, anchor_path=anchor, receipt_path=receipt)
    row = state['configs'][-1]
    _finish_failed(ledger, history, state, row)
    advanced = train._load_current_ledger(ledger, history, anchor_path=anchor, receipt_path=receipt)
    assert advanced['history_seq'] > completed['recovered_history_seq']
    files_before_noop = {path: path.read_bytes() for path in (ledger, history, anchor, receipt)}

    result = train.reconcile_budget_state(ledger, history, current_lock=_reconcile_lock_record(),
            anchor_path=anchor, receipt_path=receipt, archive_root=archive)

    assert result == {'reconciled': False, 'history_seq': advanced['history_seq'],
                      'history_digest': advanced['history_digest']}
    assert {path: path.read_bytes() for path in files_before_noop} == files_before_noop
    assert json.loads(old_complete.read_text(encoding='utf-8')) == completed


def test_malformed_history_is_archived_and_never_reconciled(tmp_path):
    ledger, history = _init_files(tmp_path)
    anchor, receipt = train._anchor_paths(ledger)
    original_ledger = ledger.read_bytes()
    original_anchor = anchor.read_bytes()
    history.write_bytes(b'{bad-json}\n')
    damaged_history = history.read_bytes()
    archive = tmp_path / 'recovery-archive'
    with pytest.raises(SystemExit, match='LEDGER_RECONCILE_HISTORY_INVALID'):
        train.reconcile_budget_state(ledger, history, current_lock=_reconcile_lock_record(),
                anchor_path=anchor, receipt_path=receipt, archive_root=archive)
    refused = list(archive.glob('*/recovery-refused.json'))
    assert len(refused) == 1
    snapshot = refused[0].parent
    assert (snapshot / 'config-ledger.json').read_bytes() == original_ledger
    assert (snapshot / 'config-history.jsonl').read_bytes() == damaged_history
    assert (snapshot / 'config-budget-anchor.json').read_bytes() == original_anchor
    assert ledger.read_bytes() == original_ledger and history.read_bytes() == damaged_history


def test_training_rights_helper_scopes_unique_trainval_members_by_dataset():
    class ScopedService:
        def __init__(self):
            self.calls=[]
        def require_members(self,workspace,dataset,actor,purpose,members):
            self.calls.append((workspace,dataset,actor,purpose,members))
            return [SimpleNamespace(member_id=member,asset_sha256={'member-a':'a'*64,'member-b':'b'*64}[member])
                    for member in members]
    service=ScopedService()
    samples=[{'split':'train','source_member':'member-a','sha256':'a'*64},
             {'split':'validation','source_member':'member-b','sha256':'b'*64},
             {'split':'train','source_member':'member-a','sha256':'a'*64}]
    assert train.verify_trainval_rights(service,'workspace','rights-dataset','steward',samples)==2
    assert service.calls==[('workspace','rights-dataset','steward','local_private_training',
                            ['member-a','member-b'])]


@pytest.mark.parametrize('samples,code',[
    ([{'split':'holdout','source_member':'member-a','sha256':'a'*64}], 'TRAINING_VIEW_SPLIT_BOUNDARY'),
    ([{'split':'train','source_member':'member-a','sha256':'wrong'}], 'RIGHTS_NOT_VERIFIED_FOR_TRAINING_INPUT'),
])
def test_training_rights_helper_rejects_nontrainval_and_hash_mismatch(samples,code):
    class ScopedService:
        def require_members(self,workspace,dataset,actor,purpose,members):
            return [SimpleNamespace(member_id=member,asset_sha256='a'*64) for member in members]
    with pytest.raises(SystemExit,match=code):
        train.verify_trainval_rights(ScopedService(),'workspace','rights-dataset','steward',samples)


def test_plan_run_budget_reserves_remaining_deadline_and_margin():
    budget = train.plan_run_budget(120, 2)
    assert budget == {'cpu_seconds_reserved': 90, 'wall_deadline_seconds': 20.0,
                      'parallelism_bound': train.CPU_PARALLELISM_BOUND}
    with pytest.raises(SystemExit, match='EXPLORATION_CPU_CAP_EXHAUSTED'):
        train.plan_run_budget(train.CPU_GUARD_SECONDS, 2)


def test_reservation_records_hard_cpu_reservation_and_owner_identity(tmp_path):
    ledger, history = _init_files(tmp_path)
    state, row, prior = _reserve(ledger, history, 'r5cfg2')
    assert row['cpu_seconds_reserved'] == min(train.MAX_RUN_CPU_SECONDS,
                                              prior['cpu_remaining_before'] - train.CPU_GUARD_SECONDS)
    assert row['execution_mode'] == 'windows-job-object-kill-on-close-v1'
    assert row['reservation_pid'] == os.getpid()
    assert row['reservation_create_time'] == psutil.Process().create_time()
    with pytest.raises(SystemExit, match='LEDGER_ATTEMPT_IN_PROGRESS'):
        _reserve(ledger, history, 'r5cfg3')


def test_orphan_running_reservation_replays_but_blocks_a_second_tag(tmp_path):
    ledger, history = _init_files(tmp_path)
    _, reserved, _ = _reserve(ledger, history, 'r5cfg2')

    replayed = train._load_current_ledger(ledger, history)
    assert replayed['configs'][-1] == reserved
    assert replayed['configs'][-1]['status'] == 'running'
    with pytest.raises(SystemExit, match='LEDGER_ATTEMPT_IN_PROGRESS'):
        _reserve(ledger, history, 'r5cfg3')
    assert train._load_current_ledger(ledger, history)['configs'][-1]['tag'] == 'r5cfg2'


def test_never_spawned_state_cannot_carry_a_child_birth_time(tmp_path):
    ledger, history = _init_files(tmp_path)
    state, row, _ = _reserve(ledger, history, 'r5cfg2')
    malformed = dict(row, child_create_time=123.0)
    with pytest.raises(SystemExit, match='LEDGER_CHILD_IDENTITY_INVALID'):
        train._validate_ledger({**state, 'configs': [state['configs'][0], malformed]})


def test_explicit_orphan_recovery_requires_death_proof_and_charges_reserved_budget(tmp_path, monkeypatch):
    ledger, history = _init_files(tmp_path)
    state, row, _ = _reserve(ledger, history, 'r5cfg2')
    state, row = train.record_spawn_intent(ledger, 'r5cfg2', history_path=history)
    state, row = train.record_child_started(ledger, 'r5cfg2', 987654321, 100.0, row['launch_nonce'],
            launcher_pid=987654321, launcher_create_time=100.0,
            job_scope=_job_scope(row, 987654321, 100.0, 987654321, 100.0), history_path=history)
    monkeypatch.setattr(train, '_positive_dead_identity', lambda pid, created: 'pid-absent')
    current = _lock_record('round5-config-orphan-recovery')
    current['purpose'] = 'round5-config-orphan-recovery'
    current['owner'] = f"fieldwork-dataset-round5-{current['purpose']}-{os.getpid()}"

    receipt = train.recover_orphan_attempt(ledger, 'r5cfg2', current_lock=current, history_path=history)

    failed = train._load_current_ledger(ledger, history)['configs'][-1]
    assert failed['status'] == 'failed' and failed['error_type'] == 'ProcessLost'
    assert failed['cpu_seconds_charged'] == failed['cpu_seconds_reserved']
    assert receipt['charged_full_reserved_budget'] is True
    assert receipt['owner_proof'] == receipt['child_proof'] == 'pid-absent'


def test_orphan_recovery_refuses_live_or_uninspectable_identity(tmp_path, monkeypatch):
    ledger, history = _init_files(tmp_path)
    state, row, _ = _reserve(ledger, history, 'r5cfg2')
    state, row = train.record_spawn_intent(ledger, 'r5cfg2', history_path=history)
    train.record_child_started(ledger, 'r5cfg2', 987654321, 100.0, row['launch_nonce'],
            launcher_pid=987654321, launcher_create_time=100.0,
            job_scope=_job_scope(row, 987654321, 100.0, 987654321, 100.0), history_path=history)
    monkeypatch.setattr(train, '_positive_dead_identity', lambda pid, created: None if pid == 987654321 else 'pid-absent')
    current = _lock_record('round5-config-orphan-recovery')
    current['purpose'] = 'round5-config-orphan-recovery'
    current['owner'] = f"fieldwork-dataset-round5-{current['purpose']}-{os.getpid()}"
    with pytest.raises(SystemExit, match='ORPHAN_PROCESS_TREE_NOT_PROVEN_DEAD'):
        train.recover_orphan_attempt(ledger, 'r5cfg2', current_lock=current, history_path=history)


def test_orphan_never_spawned_reservation_charges_full_budget(tmp_path, monkeypatch):
    ledger, history = _init_files(tmp_path)
    _, row, _ = _reserve(ledger, history, 'r5cfg2')
    monkeypatch.setattr(train, '_positive_dead_identity', lambda pid, created: 'pid-absent')
    current = _lock_record('round5-config-orphan-recovery')
    current['purpose'] = 'round5-config-orphan-recovery'
    current['owner'] = f"fieldwork-dataset-round5-{current['purpose']}-{os.getpid()}"

    audit = train.recover_orphan_attempt(ledger, 'r5cfg2', current_lock=current, history_path=history)

    failed = train._load_current_ledger(ledger, history)['configs'][-1]
    assert audit['child_proof'] == 'verified-never-spawn-intent-recorded'
    assert failed['status'] == 'failed' and failed['error_type'] == 'ProcessLost'
    assert failed['cpu_seconds_charged'] == row['cpu_seconds_reserved']


def test_spawn_intent_without_child_identity_remains_fail_closed(tmp_path, monkeypatch):
    ledger, history = _init_files(tmp_path)
    train.reserve_configuration(ledger, 'r5cfg2', CFG, 'bounded test',
            lock_record=_lock_record('r5cfg2'), history_path=history)
    train.record_spawn_intent(ledger, 'r5cfg2', history_path=history)
    monkeypatch.setattr(train, '_positive_dead_identity', lambda pid, created: 'pid-absent')
    current = _lock_record('round5-config-orphan-recovery')
    current['purpose'] = 'round5-config-orphan-recovery'
    current['owner'] = f"fieldwork-dataset-round5-{current['purpose']}-{os.getpid()}"
    with pytest.raises(SystemExit, match='ORPHAN_CHILD_IDENTITY_UNCERTAIN'):
        train.recover_orphan_attempt(ledger, 'r5cfg2', current_lock=current, history_path=history)
    assert train._load_current_ledger(ledger, history)['configs'][-1]['status'] == 'running'


def test_malformed_ledger_and_history_refuse_without_reset(tmp_path):
    ledger, history = _init_files(tmp_path)
    ledger.write_text('{broken', encoding='utf-8')
    with pytest.raises(SystemExit, match='LEDGER_MALFORMED'):
        train._load_current_ledger(ledger, history)


@pytest.mark.parametrize('tag', ['../escape', 'two/parts', '..', '.', 'bad tag', 'x' * 65])
def test_tag_must_be_path_safe_before_reservation(tmp_path, tag):
    with pytest.raises(SystemExit, match='TAG_INVALID'):
        train.reserve_configuration(tmp_path / 'ledger.json', tag, CFG, 'invalid path',
                                    lock_record=_lock_record(tag), history_path=tmp_path / 'history.jsonl')


def _pause_owner(pid, create_time, owner, state='paused'):
    return {'schema_version': 1, 'state': state, 'pid': pid, 'create_time': create_time,
            'lock_owner': owner, 'started_utc': '2026-11-01T00:00:00+00:00'}


def _current_lock():
    p = psutil.Process()
    return {'pid': os.getpid(), 'create_time': p.create_time(), 'owner': 'current-lock', 'product': 'fieldwork'}


def test_stale_fieldwork_pause_owner_is_resumed_only_after_exact_death_proof(tmp_path, monkeypatch):
    owner_path, marker_path, archive = tmp_path / 'owner.json', tmp_path / 'model.paused', tmp_path / 'archive'
    old = _pause_owner(87654321, 42.0, 'old-fieldwork-lock')
    owner_path.write_text(json.dumps(old), encoding='utf-8')
    marker_path.write_text(json.dumps({'by': old['lock_owner'], 'paused_utc': 'earlier'}), encoding='utf-8')
    monkeypatch.setattr(r5_host, '_process_identity_state', lambda pid, created: 'absent')
    calls = []
    def supervisor(action):
        calls.append(action)
        marker_path.unlink()
        return 0
    result = r5_host.recover_stale_pause(current_lock=_current_lock(), supervisor=supervisor,
            health=lambda: {'model': {'status': 200}}, owner_path=owner_path, marker_path=marker_path,
            archive_dir=archive)
    assert result == 'resumed-stale-fieldwork-pause'
    assert calls == ['resume-model'] and not owner_path.exists() and not marker_path.exists()
    receipts = list(archive.glob('*.json'))
    assert len(receipts) == 1
    assert json.loads(receipts[0].read_text(encoding='utf-8'))['prior_record'] == old


def test_live_pause_owner_is_never_resumed_or_archived(tmp_path, monkeypatch):
    owner_path, marker_path = tmp_path / 'owner.json', tmp_path / 'model.paused'
    old = _pause_owner(87654321, 42.0, 'live-fieldwork-lock')
    owner_path.write_text(json.dumps(old), encoding='utf-8')
    marker_path.write_text(json.dumps({'by': old['lock_owner']}), encoding='utf-8')
    monkeypatch.setattr(r5_host, '_process_identity_state', lambda pid, created: 'alive')
    calls = []
    with pytest.raises(RuntimeError, match='PAUSE_OWNER_NOT_PROVEN_DEAD'):
        r5_host.recover_stale_pause(current_lock=_current_lock(), supervisor=lambda a: calls.append(a),
                                    health=lambda: {'model': {'status': 200}}, owner_path=owner_path,
                                    marker_path=marker_path, archive_dir=tmp_path / 'archive')
    assert calls == [] and owner_path.exists() and marker_path.exists()


def test_coordinator_pause_marker_is_preserved_on_ownership_mismatch(tmp_path, monkeypatch):
    owner_path, marker_path = tmp_path / 'owner.json', tmp_path / 'model.paused'
    old = _pause_owner(87654321, 42.0, 'old-fieldwork-lock')
    owner_path.write_text(json.dumps(old), encoding='utf-8')
    marker_path.write_text(json.dumps({'by': 'coordinator-owned-pause'}), encoding='utf-8')
    marker_bytes = marker_path.read_bytes()
    monkeypatch.setattr(r5_host, '_process_identity_state', lambda pid, created: 'absent')
    with pytest.raises(RuntimeError, match='FOLIO_PAUSE_OWNERSHIP_MISMATCH'):
        r5_host.recover_stale_pause(current_lock=_current_lock(), supervisor=lambda a: 0,
                                    health=lambda: {'model': {'status': 200}}, owner_path=owner_path,
                                    marker_path=marker_path, archive_dir=tmp_path / 'archive')
    assert owner_path.exists() and marker_path.read_bytes() == marker_bytes


def test_heavy_slot_uses_actual_product_lock_purpose_and_preserves_coordinator_pause(tmp_path, monkeypatch):
    lock_path = tmp_path / 'product-build.lock'
    monkeypatch.setattr(r5_host, 'LOCK', lock_path)
    monkeypatch.setattr(r5_host, 'PAUSE_OWNER', tmp_path / 'pause-owner.json')
    monkeypatch.setattr(r5_host, 'PAUSE_OWNER_ARCHIVE', tmp_path / 'pause-archive')
    coordinator_marker = {'by': 'coordinator-owned-pause'}
    monkeypatch.setattr(r5_host, '_pause_marker', lambda path=None: coordinator_marker)
    monkeypatch.setattr(r5_host, 'model_busy', lambda: pytest.fail('already-paused model must not be queried'))
    monkeypatch.setattr(r5_host, 'folio_evaluations', lambda: [])
    monkeypatch.setattr(r5_host.subprocess, 'check_output', lambda *a, **k: '{"PercentCommittedBytesInUse":20}')
    monkeypatch.setattr(r5_host.shutil, 'disk_usage', lambda path: SimpleNamespace(free=200_000_000_000))
    monkeypatch.setattr(r5_host.psutil, 'virtual_memory', lambda: SimpleNamespace(available=8 * 1024 ** 3))
    helper = ROOT / 'tools/product_lock.py'
    spec = importlib.util.spec_from_file_location('budget_test_product_lock', helper)
    product_lock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product_lock)
    purpose = 'train-r5cfg2'

    with r5_host.heavy_slot(purpose, lambda _: None, data_path=tmp_path):
        owner = product_lock.read_owner(lock_path)
        assert owner['product'] == 'fieldwork'
        assert owner['purpose'] == purpose
        assert owner['pid'] == os.getpid()
        assert coordinator_marker == {'by': 'coordinator-owned-pause'}
    assert not lock_path.exists()
    assert coordinator_marker == {'by': 'coordinator-owned-pause'}


def test_internal_child_cli_rejects_self_parent_forgery_before_scope_or_training(tmp_path):
    cfg = json.dumps(CFG, sort_keys=True)
    with pytest.raises(SystemExit, match='CHILD_PARENT_SELF_FORBIDDEN'):
        train.main(['--_execute-reserved', '--tag', 'r5cfg2', '--config-json', cfg,
                    '--why', 'direct invocation negative', '--parent-pid', str(os.getpid()),
                    '--parent-create-time', str(psutil.Process().create_time()),
                    '--lock-owner', f'fieldwork-dataset-round5-train-r5cfg2-{os.getpid()}',
                    '--child-nonce', 'a' * 64, '--start-gate', str(tmp_path / 'forged-gate.json'),
                    '--child-result', str(tmp_path / 'forged-result.json')])
    assert not (tmp_path / 'forged-result.json').exists()


@pytest.mark.skipif(os.name != 'nt', reason='Windows Job Object membership is the target runtime')
def test_actual_bounded_child_passes_parent_lock_reservation_nonce_and_job_scope(tmp_path):
    helper = ROOT / 'tools/product_lock.py'
    spec = importlib.util.spec_from_file_location('bounded_child_product_lock', helper)
    product_lock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product_lock)
    tag, purpose = 'r5cfg2', 'train-r5cfg2'
    lock_path = tmp_path / 'product-build.lock'
    assert product_lock.acquire('fieldwork', purpose, lock_path)
    ledger, history = _init_files(tmp_path)
    anchor, bootstrap = train._anchor_paths(ledger)
    me = psutil.Process()
    owner = f'fieldwork-dataset-round5-{purpose}-{os.getpid()}'
    identity = {'pid': os.getpid(), 'create_time': me.create_time(), 'owner': owner,
                'product': 'fieldwork', 'purpose': purpose}
    # Keep a separate live process holding a real matching Fieldwork lock. It is
    # a sibling of the bounded child, not its launch ancestor; matching cwd/lock
    # metadata alone must not authorize the internal child entry point.
    unrelated_lock_path = tmp_path / 'unrelated-product-build.lock'
    readiness_path = tmp_path / 'unrelated-lock-ready.json'
    stop_path = tmp_path / 'unrelated-lock-stop'
    helper_code = f"""
import importlib.util, json, pathlib, sys, time
spec = importlib.util.spec_from_file_location('bounded_child_unrelated_lock', {str(helper)!r})
pl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pl)
lock_path = {str(unrelated_lock_path)!r}
ready_path = pathlib.Path({str(readiness_path)!r})
stop_path = pathlib.Path({str(stop_path)!r})
acquired = False
try:
    if not pl.acquire('fieldwork', 'train-r5cfg2', lock_path):
        raise RuntimeError('temporary sibling lock not acquired')
    acquired = True
    ready_path.write_text(json.dumps(pl.read_owner(lock_path)), encoding='utf-8')
    while not stop_path.exists():
        time.sleep(0.02)
finally:
    if acquired:
        pl.release(lock_path)
"""
    unrelated = subprocess.Popen([sys.executable, '-B', '-c', helper_code], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, cwd=str(ROOT))
    try:
        deadline = time.monotonic() + 5
        while not readiness_path.is_file() and unrelated.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if not readiness_path.is_file():
            stderr = unrelated.stderr.read() if unrelated.poll() is not None else ''
            raise AssertionError(f'unrelated lock helper failed to become ready; returncode={unrelated.poll()}; stderr={stderr!r}')
        unrelated_record = json.loads(readiness_path.read_text(encoding='utf-8'))
        unrelated_pid = unrelated_record['pid']
        unrelated_birth = unrelated_record['create_time']
        unrelated_owner = f"fieldwork-dataset-round5-train-r5cfg2-{unrelated_pid}"
        assert type(unrelated_pid) is int and unrelated_pid > 0
        assert isinstance(unrelated_birth, (int, float)) and unrelated_birth > 0
        assert psutil.Process(unrelated_pid).create_time() == unrelated_birth
        assert unrelated_record['product'] == 'fieldwork' and unrelated_record['purpose'] == purpose
        assert product_lock.read_owner(unrelated_lock_path) == unrelated_record
        assert unrelated.poll() is None, 'unrelated lock owner must still be live at the negative check'
        runner = psutil.Process(os.getpid())
        runner_birth = runner.create_time()
        actual_ancestors = psutil.Process(unrelated_pid).parents()
        assert any(parent.pid == os.getpid() and parent.create_time() == runner_birth
                   for parent in actual_ancestors), 'actual helper must remain in this test launch lineage'
        state, row, _ = train.reserve_configuration(ledger, tag, CFG, 'scope-only child test',
            lock_record=identity, history_path=history, anchor_path=anchor, receipt_path=bootstrap)
        state, row = train.record_spawn_intent(ledger, tag, history_path=history,
            anchor_path=anchor, receipt_path=bootstrap)
        nonce = row['launch_nonce']
        gate_path = tmp_path / 'execution-gate.json'
        child_ready_path = tmp_path / 'child-ready.json'
        def on_spawn(pid, create_time, launcher_pid, launcher_create_time, job_scope):
            nonlocal state, row
            state, row = train.record_child_started(ledger, tag, pid, create_time, nonce,
                launcher_pid=launcher_pid, launcher_create_time=launcher_create_time,
                job_scope=job_scope,
                history_path=history, anchor_path=anchor, receipt_path=bootstrap)
        def start_gate(job_scope):
            train._gate_writer(gate_path, {'schema_version': 4, 'tag': tag,
            'config_sha256': hashlib.sha256(train._json_bytes(CFG)).hexdigest(),
            'why_sha256': hashlib.sha256(b'scope-only child test').hexdigest(), 'launch_nonce': nonce,
            'parent_pid': os.getpid(), 'parent_create_time': me.create_time(), 'lock_owner': owner,
            'child_pid': row['child_pid'], 'child_create_time': row['child_create_time'],
            'launcher_pid': row['launcher_pid'], 'launcher_create_time': row['launcher_create_time'],
            'job_scope': job_scope})
        code = f"""
import sys
sys.path.insert(0, {str(ROOT / 'tools')!r})
import r5_train as t
SCOPE_MARKER = 'BOUNDED_CHILD_SCOPE_TEST_MARKER'
t._write_child_ready({str(child_ready_path)!r}, {nonce!r})
try:
    t._verify_child_scope({tag!r}, {CFG!r}, {'scope-only child test'!r}, {nonce!r},
        {unrelated_pid}, {unrelated_birth!r}, {unrelated_owner!r}, {str(gate_path)!r},
        lock_path={str(unrelated_lock_path)!r}, ledger_path={str(ledger)!r}, history_path={str(history)!r},
        anchor_path={str(anchor)!r}, receipt_path={str(bootstrap)!r})
except SystemExit as exc:
    assert str(exc) == 'CHILD_PARENT_NOT_LAUNCH_ANCESTOR', str(exc)
    print('UNRELATED_LIVE_PARENT_REFUSED')
else:
    raise AssertionError('unrelated live parent accepted')
t._wait_for_child_gate({tag!r}, {CFG!r}, {'scope-only child test'!r}, {nonce!r},
    {os.getpid()}, {me.create_time()!r}, {owner!r}, {str(gate_path)!r},
    lock_path={str(lock_path)!r}, ledger_path={str(ledger)!r}, history_path={str(history)!r},
    anchor_path={str(anchor)!r}, receipt_path={str(bootstrap)!r})
print('BOUNDED_CHILD_SCOPE_OK')
"""
        output_path = tmp_path / 'child-output.txt'
        with output_path.open('w+', encoding='utf-8') as output:
            receipt = r5_host.run_bounded_child([sys.executable, '-B', '-c', code], env=dict(os.environ),
                    stdout=output, cpu_budget_seconds=row['cpu_seconds_reserved'], parallelism_bound=3,
                    on_spawn=on_spawn, start_gate=start_gate, poll_seconds=0.05,
                    ready_path=child_ready_path, expected_markers=['BOUNDED_CHILD_SCOPE_TEST_MARKER'],
                    expected_cwd=ROOT, expected_nonce=nonce)
        assert receipt['returncode'] == 0 and not receipt['timed_out']
        assert all(item['exit_proven'] for item in receipt['process_exit_receipts'])
        output = output_path.read_text(encoding='utf-8')
        assert 'UNRELATED_LIVE_PARENT_REFUSED' in output
        assert 'BOUNDED_CHILD_SCOPE_OK' in output
        current = train._load_current_ledger(ledger, history, anchor_path=anchor, receipt_path=bootstrap)
        assert current['configs'][-1]['spawn_state'] == 'spawned'
        assert current['configs'][-1]['child_pid'] == receipt['child_pid']
        assert current['configs'][-1]['child_create_time'] == receipt['child_create_time']
        assert current['configs'][-1]['launcher_pid'] == receipt['launcher_pid']
        assert current['configs'][-1]['launcher_create_time'] == receipt['launcher_create_time']
        assert receipt['child_pid'] != receipt['launcher_pid'], 'Windows venv redirector must bind actual module leaf separately'
        train.finish_attempt(ledger, current, current['configs'][-1], status='failed', elapsed_s=receipt['wall_elapsed_seconds'],
                cpu_seconds_charged=1, fields={'error_type': 'ScopeOnlyTest'}, history_path=history,
                anchor_path=anchor, receipt_path=bootstrap)
    finally:
        try:
            stop_path.write_text('stop', encoding='ascii')
            try:
                unrelated.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Popen owns this exact launch handle; terminate only that handle.
                unrelated.terminate()
                unrelated.wait(timeout=5)
            if 'unrelated_pid' in locals() and 'unrelated_birth' in locals():
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        current_birth = psutil.Process(unrelated_pid).create_time()
                        if current_birth != unrelated_birth:
                            break
                    except psutil.NoSuchProcess:
                        break
                    time.sleep(0.02)
                else:
                    # Stop only the exact authored module process after checking
                    # its birth identity; the Popen handle may belong to venv's launcher.
                    exact_child = psutil.Process(unrelated_pid)
                    if exact_child.create_time() == unrelated_birth:
                        exact_child.terminate()
                        exact_child.wait(timeout=5)
            stderr = unrelated.stderr.read()
            assert unrelated.returncode == 0, stderr
        finally:
            assert product_lock.release(lock_path)


@pytest.mark.skipif(os.name != 'nt', reason='Windows Job Object enforcement is the target runtime')
def test_windows_job_object_enforces_remaining_cpu_deadline_and_kills_child_tree(tmp_path):
    command = [sys.executable, '-c',
               "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); time.sleep(30)"]
    receipt = r5_host.run_bounded_child(command, env=dict(os.environ), stdout=subprocess.DEVNULL,
            cpu_budget_seconds=31, parallelism_bound=2,
            on_spawn=lambda pid, created, launcher_pid, launcher_created, job_scope: None,
            start_gate=lambda job_scope: None, poll_seconds=0.05)
    assert receipt['timed_out'] is True
    assert receipt['job_kill_on_close'] is True
    assert receipt['process_exit_receipts']
    assert all(row['exit_proven'] for row in receipt['process_exit_receipts'])
    assert receipt['wall_elapsed_seconds'] < 5



def test_folio_evaluations_excludes_only_exact_exportworker_module(monkeypatch):
    class FakeProcess:
        def __init__(self, pid, argv, cwd):
            self.info = {'pid': pid, 'name': 'python.exe', 'cmdline': argv}
            self._cwd = cwd

        def cwd(self):
            return self._cwd

    folio_cwd = r'C:\Users\user\portfolio-build\folio'
    processes = [
        FakeProcess(101, ['python.exe', '-m', 'folio.exportworker', '--once'], folio_cwd),
        FakeProcess(102, ['python.exe', '-m', 'folio.exportworker_extra', '--once'], folio_cwd),
        FakeProcess(103, ['python.exe', '-m', 'pytest', 'tests/test_evaluation.py'], folio_cwd),
        FakeProcess(104, ['python.exe', r'C:\Users\user\portfolio-build\folio\tools\evaluate.py'], r'C:\tmp'),
    ]
    monkeypatch.setattr(r5_host.psutil, 'process_iter', lambda _attrs: processes)

    rows = r5_host.folio_evaluations()

    assert [row['pid'] for row in rows] == [102, 103, 104]


def test_model_unknown_state_remains_busy(monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise OSError('unavailable')

    monkeypatch.setattr(r5_host, '_get', unavailable)
    assert r5_host.model_busy() is True



def test_recovered_completion_event_round_trips_cpu_and_exact_process_receipts(tmp_path):
    ledger, history = _init_files(tmp_path)
    state, attempt, _ = _reserve(ledger, history, 'r5cfg2')
    state, attempt = train.record_spawn_intent(ledger, 'r5cfg2', history_path=history)
    nonce = attempt['launch_nonce']
    child_pid, launcher_pid = 910001, 910002
    child_ct, launcher_ct = 1000.25, 1000.20
    scope = {
        'schema_version': 1, 'launch_nonce': nonce,
        'job_object_name': 'Local\\FieldworkTraining-' + nonce,
        'child_pid': child_pid, 'child_create_time': child_ct,
        'launcher_pid': launcher_pid, 'launcher_create_time': launcher_ct,
        'reserved_cpu_seconds': attempt['cpu_seconds_reserved'], 'in_exact_job': True,
        'kill_on_close': True,
        'limit_flags': train.JOB_OBJECT_LIMIT_JOB_TIME | train.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        'cpu_limit_ticks': attempt['cpu_seconds_reserved'] * train.CPU_TIME_TICKS_PER_SECOND,
        'job_scope_nonce': 'b' * 64,
    }
    state, attempt = train.record_child_started(ledger, 'r5cfg2', child_pid, child_ct, nonce,
        launcher_pid=launcher_pid, launcher_create_time=launcher_ct, job_scope=scope, history_path=history)
    recovery = {
        'method': 'recovered-completion-from-verified-child-result', 'recovered_utc': datetime.now(timezone.utc).isoformat(),
        'source_manifest_sha256': 'a' * 64, 'child_result_sha256': 'b' * 64,
        'process_receipt_sha256': 'c' * 64, 'failed_cli_log_sha256': 'd' * 64,
        'pid_birth_death_receipts': [
            {'role': 'reservation_parent', 'pid': attempt['reservation_pid'],
             'create_time': attempt['reservation_create_time'], 'proof': 'pid-absent'},
            {'role': 'actual_training_child', 'pid': child_pid, 'create_time': child_ct, 'proof': 'pid-absent'},
            {'role': 'child_launcher', 'pid': launcher_pid, 'create_time': launcher_ct, 'proof': 'pid-absent'},
        ],
        'process_exit_receipts': [
            {'pid': child_pid, 'create_time': child_ct, 'exit_proven': True},
            {'pid': launcher_pid, 'create_time': launcher_ct, 'exit_proven': True},
        ],
        'child_returncode': 0, 'timed_out': False, 'cpu_limit_reached': False,
        'job_kill_on_close': True, 'observed_cpu_seconds': 3658.078125,
    }
    metrics = {'selected_epoch': 38, 'validation_cross_entropy': 0.43442511558532715,
        'validation_accuracy': 0.8490909090909091, 'validation_macro_f1': 0.8479643101915414,
        'model_digest': 'e' * 64, 'checkpoint_digest': 'f' * 64,
        'peak_rss_bytes': 962195456, 'train_elapsed_s': 1771.2,
        'observed_cpu_seconds': recovery['observed_cpu_seconds'], 'wall_elapsed_s': 1790.062,
        'recovery': recovery}
    train.finish_attempt(ledger, state, attempt, status='complete', elapsed_s=1790.062,
        cpu_seconds_charged=3689, fields=metrics, history_path=history, kind='recovered-completion')

    persisted = train._load_current_ledger(ledger, history)
    completed = persisted['configs'][-1]
    _, _, _, events = train._replay_history_bytes(history.read_bytes())
    assert completed['status'] == 'complete' and completed['cpu_seconds_charged'] == 3689
    assert completed['observed_cpu_seconds'] == recovery['observed_cpu_seconds']
    assert events[-1]['kind'] == 'recovered-completion'
    assert completed['recovery']['child_result_sha256'] == 'b' * 64


def test_recovered_completion_event_refuses_missing_process_death_proof(tmp_path):
    ledger, history = _init_files(tmp_path)
    state, attempt, _ = _reserve(ledger, history, 'r5cfg2')
    attempt.update({'complete': True, 'status': 'complete', 'elapsed_s': 1,
        'cpu_seconds_charged': 1, 'selected_epoch': 1, 'validation_cross_entropy': 0.2,
        'validation_accuracy': 0.8, 'validation_macro_f1': 0.8, 'model_digest': 'e' * 64,
        'checkpoint_digest': 'f' * 64, 'peak_rss_bytes': 1, 'train_elapsed_s': 1,
        'observed_cpu_seconds': 1,
        'recovery': {'method': 'recovered-completion-from-verified-child-result'}})
    train._append_event(history, state, 'recovered-completion', attempt)
    with pytest.raises(SystemExit, match='LEDGER_RECOVERED_COMPLETION_INVALID'):
        train._replay_history_bytes(history.read_bytes())
