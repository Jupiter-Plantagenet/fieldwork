"""Authored bounds and integrity checks for the offline Docker input transport."""
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import uuid

import pytest

import fieldwork.model_volume_staging as staging
from fieldwork.model_volume_staging import (
    STAGE_MANIFEST, STAGER_CODE, MAX_STAGE_TOTAL_BYTES, MODEL_RUN_WRITE_BUDGET_BYTES,
    MAX_STAGE_PROTOCOL_OVERHEAD_BYTES, MODEL_FIXED_TMP_WRITE_BYTES,
    STAGE_ROOT_ENV, StageProgressCounter, collect_stage_inputs, write_stage_tar,
)
from fieldwork.real_model_container import _output_tmpfs_capacity, _wait_for_stage_writer


def test_inventory_and_streamed_tar_bind_exact_source_bytes(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    (root / 'nested').mkdir()
    (root / 'nested' / 'payload.bin').write_bytes(b'authored fixture')
    manifest, records = collect_stage_inputs([('bundle', root)])
    doc = json.loads(manifest)
    assert doc['count'] == 1
    assert doc['files'][0] == {
        'path': 'bundle/nested/payload.bin',
        'bytes': len(b'authored fixture'),
        'sha256': hashlib.sha256(b'authored fixture').hexdigest(),
    }
    stream = io.BytesIO()
    progress = StageProgressCounter()
    write_stage_tar(stream, manifest, records, progress=progress)
    assert progress.snapshot() == len(b'authored fixture')
    with tarfile.open(fileobj=io.BytesIO(stream.getvalue()), mode='r:') as archive:
        assert [m.name for m in archive.getmembers()] == [
            STAGE_MANIFEST, 'bundle/nested/payload.bin']
        assert archive.extractfile('bundle/nested/payload.bin').read() == b'authored fixture'


def test_stage_writer_progress_renews_across_more_than_one_lease_without_sleeping():
    class Clock:
        value = 0.0
        def now(self): return self.value

    class Writer:
        def __init__(self, clock, progress):
            self.clock, self.progress, self.ticks = clock, progress, 0
        def is_alive(self): return self.ticks < 61
        def join(self, timeout=None):
            self.clock.value += timeout
            self.ticks += 1
            if self.ticks % 10 == 0:
                self.progress.record(1024 * 1024)

    clock = Clock()
    progress = StageProgressCounter()
    writer = Writer(clock, progress)
    renewals = []
    _wait_for_stage_writer(writer, progress,
        progress_callback=lambda: renewals.append(clock.value),
        timeout=300, no_progress_timeout=30, poll_interval=1,
        monotonic=clock.now)
    assert clock.value > 45
    assert progress.snapshot() == 6 * 1024 * 1024
    assert renewals == [10.0, 20.0, 30.0, 40.0, 50.0, 60.0]


def test_stage_writer_without_byte_progress_fails_before_45_second_lease():
    class Clock:
        value = 0.0
        def now(self): return self.value

    class StalledWriter:
        def __init__(self, clock): self.clock, self.ticks = clock, 0
        def is_alive(self): return self.ticks < 60
        def join(self, timeout=None):
            self.clock.value += timeout
            self.ticks += 1

    clock = Clock()
    writer = StalledWriter(clock)
    progress = StageProgressCounter()
    renewals = []
    with pytest.raises(TimeoutError, match='MODEL_STAGE_NO_PROGRESS'):
        _wait_for_stage_writer(writer, progress,
            progress_callback=lambda: renewals.append(clock.value),
            timeout=300, no_progress_timeout=30, poll_interval=1,
            monotonic=clock.now)
    assert clock.value == 30
    assert renewals == []


def test_stream_refuses_source_change_after_inventory(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    payload = root / 'x.bin'
    payload.write_bytes(b'before')
    manifest, records = collect_stage_inputs([('input', root)])
    payload.write_bytes(b'after!')
    with pytest.raises(ValueError, match='MODEL_STAGE_SOURCE_CHANGED'):
        write_stage_tar(io.BytesIO(), manifest, records)


def test_stager_program_is_valid_fixed_python_and_limits_prefixes():
    compile(STAGER_CODE, '<fixed-stage-helper>', 'exec')
    assert STAGE_ROOT_ENV == 'FW_STAGE_ROOT=/stage'
    assert "(ROOT/'output').mkdir(mode=0o755,exist_ok=False)" in STAGER_CODE
    assert "name.split('/')[0] not in {'bundle','pixels','input','resume','checkpoint'}" in STAGER_CODE
    assert 'MAX_TOTAL=2*1024*1024*1024-128*1024*1024-32*1024*1024' in STAGER_CODE
    assert MAX_STAGE_TOTAL_BYTES + MODEL_FIXED_TMP_WRITE_BYTES + MAX_STAGE_PROTOCOL_OVERHEAD_BYTES == MODEL_RUN_WRITE_BUDGET_BYTES


def test_fixed_stager_executes_streamed_manifest_tar_without_replaying_first_member(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    payload = b'authored fixed-stager subprocess fixture'
    (source / 'payload.bin').write_bytes(payload)
    manifest, records = collect_stage_inputs([('input', source)])
    stream = io.BytesIO()
    write_stage_tar(stream, manifest, records)

    stage_root = tmp_path / 'stage'
    stage_root.mkdir()
    # Preserve every validation/permissions path while directing this executable
    # fixture to pytest's temporary stage root instead of the production /stage.
    production_guard = "if str(ROOT)!='/stage' or ROOT.is_symlink() or not ROOT.is_dir(): fail()"
    assert production_guard in STAGER_CODE
    code = STAGER_CODE.replace(production_guard,
        "if ROOT.is_symlink() or not ROOT.is_dir(): fail()", 1)
    env = {key:value for key,value in os.environ.items()
           if key in {'PATH','SYSTEMROOT','WINDIR','TEMP','TMP'}}
    env['FW_STAGE_ROOT'] = str(stage_root)
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code],
        input=stream.getvalue(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=20, check=False, env=env)
    assert result.returncode == 0, result.stderr.decode('utf-8', 'replace')[:500]
    assert (stage_root / 'input' / 'payload.bin').read_bytes() == payload
    assert (stage_root / 'output').is_dir()


def test_output_tmpfs_and_export_copies_reserve_from_run_write_budget():
    staged = 512 * 1024 * 1024
    output_cap = _output_tmpfs_capacity(staged)
    assert (staged + MAX_STAGE_PROTOCOL_OVERHEAD_BYTES + MODEL_FIXED_TMP_WRITE_BYTES
            + 2 * output_cap <= MODEL_RUN_WRITE_BUDGET_BYTES)


def test_run_budget_ledger_carries_staging_and_exports_across_children(tmp_path):
    from fieldwork.real_model_container import ModelContainerRunner
    runner = ModelContainerRunner.__new__(ModelContainerRunner)
    runner.registry_dir = tmp_path
    runner._write_budget_scope = str(uuid.uuid4())

    def receipt(nonce):
        return {'schema':'fieldwork.real-model.cleanup/v1','state':'active','nonce':nonce,
            'cid_file':'.model-' + nonce + '.cid','owner_pid':1,'owner_created':1.0,
            'image_id':'sha256:' + 'a' * 64}

    first = receipt('1' * 32)
    first_path = tmp_path / ('.model-' + first['nonce'] + '.cleanup.json')
    first_output_cap = runner._reserve_run_budget(first, 100 * 1024 * 1024, output_tmpfs=True)
    first['write_budget']['stage_started'] = True
    first['write_budget']['stage_complete'] = True
    first['write_budget']['child_started'] = True
    runner._record_child_output(first_path, first, 40 * 1024 * 1024)
    runner._charge_budget_export(first_path, first, 40 * 1024 * 1024)
    runner._finish_run_budget(first)
    ledger = runner._load_budget_ledger(first['budget_scope_sha256'])
    assert ledger['charged_bytes'] == 100 * 1024 * 1024 + 80 * 1024 * 1024 + 128 * 1024 * 1024

    second = receipt('2' * 32)
    second_output_cap = runner._reserve_run_budget(second, 200 * 1024 * 1024, output_tmpfs=True)
    second['write_budget']['stage_started'] = True
    second['write_budget']['stage_complete'] = True
    second['write_budget']['child_started'] = True
    assert second_output_cap < first_output_cap
    runner._record_child_output(tmp_path / ('.model-' + second['nonce'] + '.cleanup.json'), second, 1)
    runner._finish_run_budget(second)
    final = runner._load_budget_ledger(first['budget_scope_sha256'])
    assert final['charged_bytes'] == (100 * 1024 * 1024 + 80 * 1024 * 1024 + 128 * 1024 * 1024
        + 200 * 1024 * 1024 + 1 + 128 * 1024 * 1024)


def test_run_budget_refunds_staging_reservation_when_volume_copy_never_started(tmp_path):
    from fieldwork.real_model_container import ModelContainerRunner
    runner = ModelContainerRunner.__new__(ModelContainerRunner)
    runner.registry_dir = tmp_path
    runner._write_budget_scope = str(uuid.uuid4())
    nonce = '3' * 32
    receipt = {'schema':'fieldwork.real-model.cleanup/v1','state':'active','nonce':nonce,
        'cid_file':'.model-' + nonce + '.cid','owner_pid':1,'owner_created':1.0,
        'image_id':'sha256:' + 'a' * 64}
    runner._reserve_run_budget(receipt, 300 * 1024 * 1024, output_tmpfs=True)
    runner._finish_run_budget(receipt)
    ledger = runner._load_budget_ledger(receipt['budget_scope_sha256'])
    assert ledger['charged_bytes'] == 0
    assert ledger['completed'][0]['staged_bytes'] == 0
    assert ledger['reservations'] == []


def test_run_budget_migrates_prior_v1_rows_without_erasing_charges(tmp_path):
    from fieldwork.real_model_container import ModelContainerRunner
    runner = ModelContainerRunner.__new__(ModelContainerRunner)
    runner.registry_dir = tmp_path
    scope = str(uuid.uuid4())
    digest = hashlib.sha256(scope.encode('ascii')).hexdigest()
    staged = 11 * 1024 * 1024
    exported = 7 * 1024 * 1024
    child_output = 13 * 1024 * 1024
    prior_charge = staged + exported + child_output
    # Exact completed-row shape from model-run-write-budget/v1, before the
    # fixed /tmp and /dev/shm footprint was included in per-run accounting.
    legacy = {'schema':'fieldwork.model-run-write-budget/v1',
        'scope_sha256':digest, 'limit_bytes':MODEL_RUN_WRITE_BUDGET_BYTES,
        'charged_bytes':prior_charge, 'reservations':[],
        'completed':[{'nonce':'4' * 32, 'charged_bytes':prior_charge,
            'staged_bytes':staged, 'exported_bytes':exported,
            'child_output_bytes':child_output}]}
    runner._budget_path(digest).write_text(json.dumps(legacy), encoding='utf-8')

    migrated = runner._load_budget_ledger(digest)
    assert migrated['schema'] == 'fieldwork.model-run-write-budget/v2'
    assert migrated['completed'][0]['staged_bytes'] == staged
    assert migrated['completed'][0]['exported_bytes'] == exported
    assert migrated['completed'][0]['child_output_bytes'] == child_output
    assert migrated['completed'][0]['fixed_tmp_bytes'] == MODEL_FIXED_TMP_WRITE_BYTES
    assert migrated['completed'][0]['charged_bytes'] == prior_charge + MODEL_FIXED_TMP_WRITE_BYTES
    assert migrated['charged_bytes'] == prior_charge + MODEL_FIXED_TMP_WRITE_BYTES


def test_stream_rejects_parent_symlink_swap_outside_source_root(tmp_path):
    root = tmp_path / 'source'
    nested = root / 'nested'
    nested.mkdir(parents=True)
    (nested / 'payload.bin').write_bytes(b'inside')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'payload.bin').write_bytes(b'outside')
    manifest, records = collect_stage_inputs([('input', root)])
    moved = root / 'nested-original'
    nested.rename(moved)
    try:
        nested.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f'directory symlink unavailable: {type(exc).__name__}')
    with pytest.raises(ValueError, match='MODEL_STAGE_SOURCE_ESCAPE'):
        write_stage_tar(io.BytesIO(), manifest, records)


def test_stream_rejects_parent_directory_replacement(tmp_path):
    root = tmp_path / 'source'
    nested = root / 'nested'
    nested.mkdir(parents=True)
    (nested / 'payload.bin').write_bytes(b'original')
    manifest, records = collect_stage_inputs([('input', root)])
    nested.rename(root / 'nested-original')
    nested.mkdir()
    (nested / 'payload.bin').write_bytes(b'replaced')
    with pytest.raises(ValueError, match='MODEL_STAGE_SOURCE_CHANGED'):
        write_stage_tar(io.BytesIO(), manifest, records)


def test_stream_rejects_source_root_replacement(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    (root / 'payload.bin').write_bytes(b'original')
    manifest, records = collect_stage_inputs([('input', root)])
    root.rename(tmp_path / 'source-original')
    root.mkdir()
    (root / 'payload.bin').write_bytes(b'replaced')
    with pytest.raises(ValueError, match='MODEL_STAGE_SOURCE_CHANGED'):
        write_stage_tar(io.BytesIO(), manifest, records)


def test_initial_root_symlink_swap_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    root.mkdir()
    (root / 'payload.bin').write_bytes(b'inside')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'payload.bin').write_bytes(b'outside')
    original = staging._canonical_root

    def swap_before_root_handle(path):
        path.rename(tmp_path / 'source-original')
        try:
            path.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f'directory symlink unavailable: {type(exc).__name__}')
        return original(path)

    monkeypatch.setattr(staging, '_canonical_root', swap_before_root_handle)
    with pytest.raises(ValueError, match='MODEL_STAGE_SOURCE_(REPARSE_REFUSED|ESCAPE)'):
        collect_stage_inputs([('input', root)])


def test_initial_ancestor_symlink_swap_is_rejected(tmp_path, monkeypatch):
    parent = tmp_path / 'parent'
    root = parent / 'source'
    root.mkdir(parents=True)
    (root / 'payload.bin').write_bytes(b'inside')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'source').mkdir()
    (outside / 'source' / 'payload.bin').write_bytes(b'outside')
    original = staging._canonical_root

    def swap_parent_before_root_handle(path):
        parent.rename(tmp_path / 'parent-original')
        try:
            parent.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f'directory symlink unavailable: {type(exc).__name__}')
        return original(path)

    monkeypatch.setattr(staging, '_canonical_root', swap_parent_before_root_handle)
    with pytest.raises(ValueError, match='MODEL_STAGE_SOURCE_ESCAPE'):
        collect_stage_inputs([('input', root)])


def test_inventory_stops_at_file_count_bound_before_hashing_next_file(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    root.mkdir()
    (root / 'a').write_bytes(b'a')
    (root / 'b').write_bytes(b'b')
    calls = []
    original = staging._hash_file

    def counted(path, base, root_identity):
        calls.append(path.name)
        return original(path, base, root_identity)

    monkeypatch.setattr(staging, 'MAX_STAGE_FILES', 1)
    monkeypatch.setattr(staging, '_hash_file', counted)
    with pytest.raises(ValueError, match='MODEL_STAGE_FILE_COUNT_BOUNDS'):
        collect_stage_inputs([('input', root)])
    assert len(calls) == 1


def test_inventory_rejects_hardlinked_files(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    original = tmp_path / 'outside.bin'
    original.write_bytes(b'outside')
    try:
        (root / 'linked.bin').hardlink_to(original)
    except OSError as exc:
        pytest.skip(f'hard links unavailable: {type(exc).__name__}')
    with pytest.raises(ValueError, match='MODEL_STAGE_FILE_BOUNDS'):
        collect_stage_inputs([('input', root)])
