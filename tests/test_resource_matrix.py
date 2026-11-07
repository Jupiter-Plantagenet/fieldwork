"""ML-T-RESOURCE matrix on current source, DEFAULT behaviour first (operator overrides UNSET) and then the
two recorded operator overrides (FIELDWORK_OPERATOR_RAM_OVERRIDE / FIELDWORK_OPERATOR_SPACE_OVERRIDE).

Frozen pass condition: >=6 GiB available RAM, >=12 GiB free disk, projected peak <= free-4 GiB; one heavy
task; heavy child <=2 GiB RSS / 2 threads / 4 h; per-run writes <=2 GiB; block, never silently spill;
20-queued-run cap; stale preflight >5 min rejected.

The host RAM/disk numbers are monkeypatched ONLY as the input of the real decision code
(`worker.preflight`, `api.submit`); the decision code itself is never mocked. Disk-full and timeout cases
use real OS errors / real child processes. The 20-queued cap lives in tests/test_queue_matrix.py.
"""
import errno
import hashlib
import importlib
import json
import subprocess
import sys
import time
import types
import uuid
from types import SimpleNamespace

import pytest

GIB = 1024 ** 3
MIB = 1024 ** 2
RAM_ENV = 'FIELDWORK_OPERATOR_RAM_OVERRIDE'
SPACE_ENV = 'FIELDWORK_OPERATOR_SPACE_OVERRIDE'
HOST_ENV = 'FIELDWORK_HOST_HEAVY_LOCK'


@pytest.fixture(autouse=True)
def default_environment(monkeypatch, restore_reloaded_modules):
    """Every test starts from the DEFAULT frozen behaviour: no override, no portfolio host policy."""
    for name in (RAM_ENV, SPACE_ENV, HOST_ENV):
        monkeypatch.delenv(name, raising=False)
    yield


def host(monkeypatch, ram, free):
    from fieldwork import worker
    monkeypatch.setattr(worker.psutil, 'virtual_memory', lambda: SimpleNamespace(available=ram))
    monkeypatch.setattr(worker.shutil, 'disk_usage', lambda _p: SimpleNamespace(free=free))
    return worker


# ------------------------------------------------------- worker preflight, defaults
def test_defaults_are_the_frozen_thresholds(monkeypatch):
    from fieldwork import worker
    assert worker.MIN_AVAILABLE_RAM_BYTES == 6 * GIB and worker.MIN_FREE_DISK_BYTES == 12 * GIB
    assert worker.REAL_CHILD_MEMORY_LIMIT_BYTES == 2 * GIB
    assert worker.REAL_ADDITIONAL_HEADROOM_BYTES == 4 * GIB
    assert worker.REAL_PROJECTED_PEAK_BYTES == 2 * GIB + 256 * MIB
    assert worker.REAL_REQUIRED_AVAILABLE_RAM_BYTES == worker.REAL_PROJECTED_PEAK_BYTES + 4 * GIB  # peak <= available - 4 GiB


@pytest.mark.parametrize('ram,free,expected', [
    (6 * GIB, 12 * GIB, True), (6 * GIB - 1, 12 * GIB, False), (6 * GIB, 12 * GIB - 1, False),
    (64 * GIB, 12 * GIB - 1, False), (6 * GIB - 1, 400 * GIB, False), (0, 0, False), (64 * GIB, 400 * GIB, True)])
def test_synthetic_gate_boundaries_with_overrides_unset(monkeypatch, ram, free, expected):
    worker = host(monkeypatch, ram, free)
    admitted, detail = worker.preflight()
    assert admitted is expected and detail['admitted'] is expected and detail['code'] == 'RESOURCE_PREFLIGHT'
    assert detail['available_ram_bytes'] == ram and detail['free_disk_bytes'] == free
    assert detail['required_available_ram_bytes'] == 6 * GIB and detail['required_free_disk_bytes'] == 12 * GIB
    assert 'operator_ram_override' not in detail and 'operator_space_override' not in detail


@pytest.mark.parametrize('ram,expected', [(6 * GIB + 256 * MIB, True), (6 * GIB + 256 * MIB - 1, False), (6 * GIB, False), (8 * GIB, True)])
def test_real_run_gate_requires_projected_peak_plus_4gib_headroom(monkeypatch, ram, expected):
    worker = host(monkeypatch, ram, 400 * GIB)
    admitted, detail = worker.preflight(real_runs=True)
    assert admitted is expected
    assert detail['required_available_ram_bytes'] == 6 * GIB + 256 * MIB
    assert detail['projected_peak_ram_bytes'] == 2 * GIB + 256 * MIB
    assert detail['additional_headroom_bytes'] == 4 * GIB
    assert (detail['projected_peak_ram_bytes'] + detail['additional_headroom_bytes'] <= ram) is expected
    assert 'operator_ram_override' not in detail
    # the same RAM satisfies the synthetic-only gate where applicable: the real-run gate is the stricter one
    assert worker.preflight(real_runs=False)[0] is (ram >= 6 * GIB)


def test_disk_gate_for_real_runs_is_unchanged_by_ram_headroom(monkeypatch):
    worker = host(monkeypatch, 64 * GIB, 12 * GIB - 1)
    assert worker.preflight(real_runs=True)[0] is False
    worker = host(monkeypatch, 64 * GIB, 12 * GIB)
    assert worker.preflight(real_runs=True)[0] is True


def test_refused_preflight_never_claims_or_starts_anything(monkeypatch, capsys):
    """worker.execute is refused with exit 23 before it can open a store, claim, or spawn: no silent spill."""
    worker = host(monkeypatch, 1 * GIB, 400 * GIB)
    monkeypatch.setattr(worker, 'worker_store', lambda *a, **k: pytest.fail('claimed after a refused preflight'))
    monkeypatch.setattr(worker.subprocess, 'Popen', lambda *a, **k: pytest.fail('spawned after a refused preflight'))
    assert worker.execute('00000000-0000-4000-8000-000000000000') == 23
    printed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert printed['code'] == 'RESOURCE_PREFLIGHT' and printed['admitted'] is False and printed['available_ram_bytes'] == 1 * GIB


def test_portfolio_host_policy_refusal_blocks_even_with_ample_ram_and_disk(monkeypatch):
    worker = host(monkeypatch, 64 * GIB, 400 * GIB)
    monkeypatch.setenv(HOST_ENV, 'fixture-host-lock')
    monkeypatch.setattr(worker.subprocess, 'run', lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps({'CommittedBytes': 90, 'CommitLimit': 100, 'PercentCommittedBytesInUse': 90})))
    admitted, detail = worker.preflight()
    assert admitted is False and detail['portfolio_host_policy'] is True and detail['host_admitted'] is False


# ---------------------------------------------------- overrides: exact value, recorded
@pytest.mark.parametrize('value', ['', '1', 'true', 'yes', 'Accept-Low-Available-Ram', 'accept-low-available-ram ', ' accept-low-available-ram',
                                   'accept-large-run-writes'])
def test_ram_override_only_acts_on_the_exact_value(monkeypatch, value):
    worker = host(monkeypatch, 1 * GIB, 400 * GIB)
    monkeypatch.setenv(RAM_ENV, value)
    admitted, detail = worker.preflight(real_runs=True)
    assert admitted is False and 'operator_ram_override' not in detail


def test_ram_override_exact_value_waives_only_ram_and_is_recorded(monkeypatch):
    worker = host(monkeypatch, 1 * GIB, 400 * GIB)
    monkeypatch.setenv(RAM_ENV, 'accept-low-available-ram')
    admitted, detail = worker.preflight(real_runs=True)
    assert admitted is True and detail['operator_ram_override'] is True and detail['available_ram_bytes'] == 1 * GIB
    assert detail['required_available_ram_bytes'] == 6 * GIB + 256 * MIB  # the requirement is still reported, just waived
    assert 'operator_space_override' not in detail
    # the RAM override never relaxes free disk
    worker = host(monkeypatch, 1 * GIB, 12 * GIB - 1)
    assert worker.preflight(real_runs=True)[0] is False
    worker = host(monkeypatch, 1 * GIB, 8 * GIB)
    assert worker.preflight()[0] is False


@pytest.mark.parametrize('value', ['', '1', 'true', 'yes', 'Accept-Large-Run-Writes', 'accept-large-run-writes ', 'accept-low-available-ram'])
def test_space_override_only_acts_on_the_exact_value(monkeypatch, value):
    worker = host(monkeypatch, 64 * GIB, 8 * GIB)
    monkeypatch.setenv(SPACE_ENV, value)
    admitted, detail = worker.preflight()
    assert admitted is False and 'operator_space_override' not in detail and detail['required_free_disk_bytes'] == 12 * GIB


def test_space_override_exact_value_lowers_disk_to_a_floor_never_zero_and_is_recorded(monkeypatch):
    monkeypatch.setenv(SPACE_ENV, 'accept-large-run-writes')
    worker = host(monkeypatch, 64 * GIB, 8 * GIB)
    admitted, detail = worker.preflight()
    assert admitted is True and detail['operator_space_override'] is True and detail['required_free_disk_bytes'] == 5 * GIB
    assert host(monkeypatch, 64 * GIB, 5 * GIB - 1).preflight()[0] is False
    assert host(monkeypatch, 64 * GIB, 5 * GIB).preflight()[0] is True
    # the space override never waives RAM
    worker = host(monkeypatch, 1 * GIB, 400 * GIB)
    admitted, detail = worker.preflight()
    assert admitted is False and 'operator_ram_override' not in detail


def test_both_overrides_set_record_both(monkeypatch):
    monkeypatch.setenv(RAM_ENV, 'accept-low-available-ram')
    monkeypatch.setenv(SPACE_ENV, 'accept-large-run-writes')
    worker = host(monkeypatch, 1 * GIB, 6 * GIB)
    admitted, detail = worker.preflight(real_runs=True)
    assert admitted is True and detail['operator_ram_override'] is True and detail['operator_space_override'] is True
    assert host(monkeypatch, 1 * GIB, 5 * GIB - 1).preflight(real_runs=True)[0] is False


# --------------------------------------------------------- API submit gate (live numbers)
def api_client(isolated_store, monkeypatch, ram, free):
    import fieldwork.api as api
    from tests.isolated_api import use_isolated_api
    use_isolated_api(isolated_store, monkeypatch)
    set_api_host(api, monkeypatch, ram, free)
    return api


def set_api_host(api, monkeypatch, ram, free):
    monkeypatch.setattr(api.psutil, 'virtual_memory', lambda: types.SimpleNamespace(available=ram))
    monkeypatch.setattr(api.shutil, 'disk_usage', lambda _p: types.SimpleNamespace(total=500 * GIB, used=0, free=free))


def post_run(api, key):
    from fastapi.testclient import TestClient
    pw = uuid.uuid4().hex
    api.create_account('rm-' + key, pw, 'rm-' + key, 'owner')
    with TestClient(api.app) as c:
        r = c.post('/auth/session', json={'name': 'rm-' + key, 'password': pw})
        h = {'Origin': 'http://127.0.0.1:5102', 'X-CSRF-Token': r.json()['csrf'], 'Idempotency-Key': key}
        response = c.post('/api/v1/workspaces/rm-%s/runs' % key, json={'epochs': 1}, headers=h)
        return response


@pytest.mark.parametrize('ram,free,status', [(6 * GIB, 12 * GIB, 202), (6 * GIB - 1, 12 * GIB, 423), (6 * GIB, 12 * GIB - 1, 423), (1 * GIB, 400 * GIB, 423)])
def test_api_submit_gate_uses_live_numbers_and_creates_no_run_when_refused(isolated_store, monkeypatch, ram, free, status):
    api = api_client(isolated_store, monkeypatch, ram, free)
    response = post_run(api, 'g%d' % status + uuid.uuid4().hex[:4])
    assert response.status_code == status, response.text
    with isolated_store.connect() as c:
        count = c.execute('SELECT count(*) n FROM fw_runs').fetchone()['n']
    assert count == (1 if status == 202 else 0)
    if status == 423:
        assert response.json()['detail'] == 'RESOURCE_PREFLIGHT'


def test_api_submit_space_override_applies_only_for_the_exact_value_and_never_waives_ram(isolated_store, monkeypatch):
    api = api_client(isolated_store, monkeypatch, 64 * GIB, 8 * GIB)
    assert post_run(api, 'sp0' + uuid.uuid4().hex[:4]).status_code == 423
    monkeypatch.setenv(SPACE_ENV, 'yes')
    assert post_run(api, 'sp1' + uuid.uuid4().hex[:4]).status_code == 423
    monkeypatch.setenv(SPACE_ENV, 'accept-large-run-writes')
    assert post_run(api, 'sp2' + uuid.uuid4().hex[:4]).status_code == 202
    set_api_host(api, monkeypatch, 1 * GIB, 400 * GIB)
    assert post_run(api, 'sp3' + uuid.uuid4().hex[:4]).status_code == 423  # space override does not waive RAM


def test_api_submit_gate_honours_only_the_exact_ram_override_and_still_enforces_disk(isolated_store, monkeypatch):
    """Operator ruling 2026-11-03 ("ignore all RAM gates"): the API submit gate waives its 6 GiB RAM check only for
    the exact override value; by default it still refuses, and free disk is never waived by the RAM override."""
    api = api_client(isolated_store, monkeypatch, 1 * GIB, 400 * GIB)
    assert post_run(api, 'ra0' + uuid.uuid4().hex[:4]).status_code == 423  # default: refused
    monkeypatch.setenv(RAM_ENV, 'yes')
    assert post_run(api, 'ra1' + uuid.uuid4().hex[:4]).status_code == 423  # inexact value: refused
    monkeypatch.setenv(RAM_ENV, 'accept-low-available-ram')
    assert post_run(api, 'ra2' + uuid.uuid4().hex[:4]).status_code == 202
    set_api_host(api, monkeypatch, 1 * GIB, 1 * GIB)
    assert post_run(api, 'ra3' + uuid.uuid4().hex[:4]).status_code == 423  # disk still enforced


# ---------------------------------- stale preflight: live recomputation, no cached admission
def test_admission_is_recomputed_from_live_counters_on_every_call_nothing_is_cached(monkeypatch):
    """The product keeps no preflight token/result: every admission decision re-reads live counters, so a
    stale (>5 min) 'admitted' can never be replayed. A preflight that was admitted then flips the moment the
    live counters drop, in the same process, with no intervening wait."""
    from fieldwork import worker
    results = []
    for ram in (64 * GIB, 1 * GIB, 64 * GIB, 6 * GIB - 1, 6 * GIB):
        host(monkeypatch, ram, 400 * GIB)
        results.append(worker.preflight()[0])
    assert results == [True, False, True, False, True]
    assert not [n for n in vars(worker) if 'preflight_cache' in n.lower() or n.lower().startswith('_last_preflight')]


def test_operations_screen_preflight_is_stamped_at_request_time(isolated_store, monkeypatch):
    from fastapi.testclient import TestClient
    from datetime import datetime, timezone
    api = api_client(isolated_store, monkeypatch, 64 * GIB, 400 * GIB)
    import fieldwork.api_screens as screens
    monkeypatch.setattr(screens.psutil, 'virtual_memory', lambda: types.SimpleNamespace(available=64 * GIB))
    monkeypatch.setattr(screens.shutil, 'disk_usage', lambda _p: types.SimpleNamespace(free=400 * GIB))
    pw = uuid.uuid4().hex
    api.create_account('opsu', pw, 'ops-ws', 'owner')
    with TestClient(api.app) as c:
        c.post('/auth/session', json={'name': 'opsu', 'password': pw})
        first = c.get('/api/v1/workspaces/ops-ws/screens/operations').json()['preflight']
        time.sleep(1.1)
        second = c.get('/api/v1/workspaces/ops-ws/screens/operations').json()['preflight']
    parse = lambda s: datetime.fromisoformat(s.replace('Z', '+00:00'))  # noqa: E731
    assert (parse(second['checked_at']) - parse(first['checked_at'])).total_seconds() >= 1.0
    assert abs((datetime.now(timezone.utc) - parse(second['checked_at'])).total_seconds()) < 30
    assert first['admitted'] is True


# ------------------------------------------------ per-run write budget (<= 2 GiB, no spill)
def reload_modules(monkeypatch, value):
    if value is None:
        monkeypatch.delenv(SPACE_ENV, raising=False)
    else:
        monkeypatch.setenv(SPACE_ENV, value)
    from fieldwork import model_volume_staging as staging, real_model_container as container
    importlib.reload(staging)
    importlib.reload(container)
    return staging, container


def bare_runner(container, registry, scope=None):
    runner = container.ModelContainerRunner.__new__(container.ModelContainerRunner)
    runner.registry_dir = registry
    runner._active = set()
    runner._write_budget_scope = scope or str(uuid.uuid4())
    runner.image_id = 'sha256:' + 'c' * 64
    runner.env = {}
    return runner


def one_attempt(runner, container, staged):
    """reserve -> pretend the child ran to its cap -> charge; returns (receipt, charged_after)."""
    receipt = {'nonce': uuid.uuid4().hex, 'schema': container.RECEIPT_SCHEMA}
    runner._reserve_run_budget(receipt, staged, output_tmpfs=True)
    budget = receipt['write_budget']
    budget.update(stage_complete=True, stage_started=True, child_started=True)
    runner._finish_run_budget(receipt)
    scope = receipt['budget_scope_sha256']
    return receipt, runner._load_budget_ledger(scope)


def test_per_run_write_budget_is_2gib_cumulative_across_attempts_and_survives_restart(monkeypatch, tmp_path):
    staging, container = reload_modules(monkeypatch, None)
    assert staging.MODEL_RUN_WRITE_BUDGET_BYTES == 2 * GIB == container.MODEL_RUN_WRITE_BUDGET_BYTES
    scope = str(uuid.uuid4())
    runner = bare_runner(container, tmp_path, scope)
    charged = []
    _, ledger = one_attempt(runner, container, 100 * MIB)
    charged.append(ledger['charged_bytes'])
    assert ledger['limit_bytes'] == 2 * GIB and 0 < charged[0] <= 2 * GIB
    _, ledger = one_attempt(runner, container, 100 * MIB)
    charged.append(ledger['charged_bytes'])
    assert charged[1] > charged[0] and charged[1] <= 2 * GIB
    # a third attempt in the same run scope no longer fits: refused before any container work (no spill)
    with pytest.raises(container.ModelContainerUnavailable) as e:
        runner._reserve_run_budget({'nonce': uuid.uuid4().hex}, 100 * MIB, output_tmpfs=True)
    assert e.value.code == 'MODEL_RUN_WRITE_BUDGET_EXCEEDED'
    # supervisor restart: a NEW runner object reads the same ledger and still refuses
    restarted = bare_runner(container, tmp_path, scope)
    with pytest.raises(container.ModelContainerUnavailable) as e:
        restarted._reserve_run_budget({'nonce': uuid.uuid4().hex}, 100 * MIB, output_tmpfs=True)
    assert e.value.code == 'MODEL_RUN_WRITE_BUDGET_EXCEEDED'
    assert restarted._load_budget_ledger(hashlib.sha256(scope.encode()).hexdigest())['charged_bytes'] == charged[1]
    # another run has its own budget
    other = bare_runner(container, tmp_path)
    one_attempt(other, container, 100 * MIB)


@pytest.mark.parametrize('staged,tmpfs', [(2 * GIB, True), (2 * GIB, False), (int(1.9 * GIB), True), (2 * GIB - 100 * MIB, False)])
def test_a_single_oversized_stage_is_refused_by_the_ledger(monkeypatch, tmp_path, staged, tmpfs):
    _, container = reload_modules(monkeypatch, None)
    runner = bare_runner(container, tmp_path)
    with pytest.raises(container.ModelContainerUnavailable) as e:
        runner._reserve_run_budget({'nonce': uuid.uuid4().hex}, staged, output_tmpfs=tmpfs)
    assert e.value.code == 'MODEL_RUN_WRITE_BUDGET_EXCEEDED'
    assert not [p for p in tmp_path.iterdir() if p.name.startswith('.model-write-budget-')]  # nothing was reserved


def test_budget_override_needs_the_exact_value_and_is_recorded_on_the_receipt(monkeypatch, tmp_path):
    for value in ('true', 'yes', 'Accept-Large-Run-Writes', ''):
        staging, _ = reload_modules(monkeypatch, value)
        assert staging.MODEL_RUN_WRITE_BUDGET_BYTES == 2 * GIB, value
    staging, container = reload_modules(monkeypatch, 'accept-large-run-writes')
    assert staging.MODEL_RUN_WRITE_BUDGET_BYTES == 64 * GIB
    runner = bare_runner(container, tmp_path)
    receipt = {'nonce': uuid.uuid4().hex, 'schema': container.RECEIPT_SCHEMA}
    runner._reserve_run_budget(receipt, 3 * GIB, output_tmpfs=False)  # refused by default, allowed only under the override
    assert receipt['write_budget']['limit_bytes'] == 64 * GIB
    _, container = reload_modules(monkeypatch, None)
    default_runner = bare_runner(container, tmp_path)
    with pytest.raises(container.ModelContainerUnavailable):
        default_runner._reserve_run_budget({'nonce': uuid.uuid4().hex}, 3 * GIB, output_tmpfs=False)


@pytest.mark.parametrize('fsync_call', [1, 2])
def test_disk_full_while_recording_the_budget_fails_closed_and_leaves_no_partial_ledger(monkeypatch, tmp_path, fsync_call):
    _, container = reload_modules(monkeypatch, None)
    runner = bare_runner(container, tmp_path)
    real, count = container.os.fsync, {'n': 0}

    def fsync(fd):
        count['n'] += 1
        if count['n'] == fsync_call:
            raise OSError(errno.ENOSPC, 'No space left on device (injected at fsync)')
        return real(fd)

    monkeypatch.setattr(container.os, 'fsync', fsync)
    receipt = {'nonce': uuid.uuid4().hex, 'schema': container.RECEIPT_SCHEMA}
    with pytest.raises(container.ModelContainerUnavailable) as e:
        runner._reserve_run_budget(receipt, 10 * MIB, output_tmpfs=False)
    assert e.value.code in {'MODEL_RECEIPT_WRITE_FAILED', 'MODEL_RUN_WRITE_LEDGER_WRITE_FAILED'}
    assert not [p for p in tmp_path.iterdir() if p.name.endswith('.writing')]
    assert not [p for p in tmp_path.iterdir() if p.name.startswith('.model-write-budget-')]  # no reservation recorded
    monkeypatch.setattr(container.os, 'fsync', real)
    runner._reserve_run_budget(receipt, 10 * MIB, output_tmpfs=False)  # space returned: reservation succeeds


# ------------------------------------------ heavy child limits (argv of the real container start)
def capture_start(monkeypatch, tmp_path, operation, output_tmpfs):
    _, container = reload_modules(monkeypatch, None)
    runner = bare_runner(container, tmp_path)
    runner.recover_stale = lambda: None
    runner._cleanup = lambda *a, **k: None
    seen = {}

    def popen(argv, **kw):
        seen['argv'] = list(argv)
        raise OSError('no docker in this test')

    monkeypatch.setattr(container.subprocess, 'Popen', popen)
    with pytest.raises(container.ModelContainerUnavailable) as e:
        runner._start(operation, 'fieldwork.real_infer_child' if not output_tmpfs else 'fieldwork.real_train_child', ['--x'], output_tmpfs=output_tmpfs, timeout=90)
    assert e.value.code == 'MODEL_DOCKER_START_FAILED'
    return container, seen['argv']


@pytest.mark.parametrize('operation,tmpfs', [('inference', False), ('training', True)])
def test_heavy_child_container_is_capped_at_2gib_ram_2_cpus_2_threads_no_network(monkeypatch, tmp_path, operation, tmpfs):
    container, argv = capture_start(monkeypatch, tmp_path, operation, tmpfs)
    for flag in ('--memory=2g', '--memory-swap=2g', '--cpus=2', '--pids-limit=64', '--network=none', '--read-only', '--cap-drop=ALL',
                 '--env=OMP_NUM_THREADS=2', '--env=MKL_NUM_THREADS=2', '--ulimit=fsize=2147483648:2147483648', '--ulimit=core=0',
                 '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m', '--shm-size=64m'):
        assert flag in argv, flag
    if tmpfs:
        spec = next(a for a in argv if a.startswith('--tmpfs=' + container.OUTPUT_CONTAINER))
        size = int(spec.split('size=')[1].split(',')[0])
        assert 64 * MIB <= size <= container.MODEL_TMPFS_BYTES
        # output tmpfs + its export copy + protocol overhead + fixed /tmp allowance stay inside the 2 GiB per-run budget
        assert 2 * size + container.MAX_STAGE_PROTOCOL_OVERHEAD_BYTES + container.MODEL_FIXED_TMP_WRITE_BYTES <= 2 * GIB


def test_container_wall_clock_is_capped_at_4_hours(monkeypatch, tmp_path):
    _, container = reload_modules(monkeypatch, None)
    assert container.MAX_WALL_SECONDS == 4 * 3600
    runner = bare_runner(container, tmp_path)
    runner.recover_stale = lambda: pytest.fail('docker state touched before the wall limit was validated')
    for bad in (4 * 3600 + 1, 0, -5):
        with pytest.raises(container.ModelContainerUnavailable) as e:
            runner._start('inference', 'm', [], timeout=bad)
        assert e.value.code == 'MODEL_WALL_LIMIT_INVALID'


def test_container_poll_kills_and_raises_wall_timeout_after_the_limit(monkeypatch, tmp_path):
    _, container = reload_modules(monkeypatch, None)
    killed = []
    process = container.ModelContainerProcess.__new__(container.ModelContainerProcess)
    process.proc = SimpleNamespace(pid=1, poll=lambda: None)
    process.runner = SimpleNamespace()
    process.timeout = 4 * 3600
    process._returncode = None
    process._started = time.monotonic() - (4 * 3600 + 1)
    process.kill = lambda: killed.append('kill')
    process.wait = lambda timeout=None: killed.append('wait')
    with pytest.raises(container.ModelContainerUnavailable) as e:
        process.poll()
    assert e.value.code == 'MODEL_CONTAINER_WALL_TIMEOUT' and killed == ['kill', 'wait']


# ---------------------------------------- run timeout through the real supervisors and DB
def make_running(s):
    from fieldwork.store import ROOT
    meta = json.loads((ROOT / 'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1/state.json').read_text())
    r = s.submit('rt-' + uuid.uuid4().hex[:6], 'a', str(uuid.uuid4()), {'epochs': 1, 'dataset_digest': meta['dataset_digest'], 'scope': 'synthetic-execution-only'})
    return r, s.claim(r['id'], start=False)


def test_supervisor_watch_times_out_kills_the_real_child_and_failure_is_retryable(isolated_store, tmp_path):
    from fieldwork.supervisor import watch, command_key
    s = isolated_store
    r, a = make_running(s)
    rid = r['id']
    s.start(rid, a['attempt'], a['fence'], a['cancel_generation'], a['digest'], restore_generation=a['restore_generation'])
    s.begin_child(rid, a['fence'])
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'])
    try:
        s.register_child(rid, a['fence'], child)
        started = time.monotonic()
        with pytest.raises(TimeoutError) as e:
            watch(s, a, child, tmp_path / 'out', timeout=1)
        assert time.monotonic() - started < 30 and 'timeout' in str(e.value)
        assert child.poll() is not None  # the heavy child is dead, not orphaned
        # the worker's failure path: TimeoutError is an OSError, therefore a retryable infrastructure failure
        assert isinstance(e.value, OSError)
        out = s.fail(rid, a['attempt'], a['fence'], 'WORKER_INFRASTRUCTURE_FAILED', isinstance(e.value, OSError), 'f' * 64,
                     restore_generation=a['restore_generation'], key=command_key(a['attempt'], 'ML-Fail'))
        assert out['state'] == 'interrupted'
        s.release_slot(rid, fence=a['fence'])
        with s.connect() as c:
            assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run'] is None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=20)


def test_real_job_watch_times_out_and_kills_the_child(isolated_store, tmp_path):
    from fieldwork import real_job
    s = isolated_store
    r, a = make_running(s)
    rid = r['id']
    s.start(rid, a['attempt'], a['fence'], a['cancel_generation'], a['digest'], restore_generation=a['restore_generation'])
    s.begin_child(rid, a['fence'])
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'])
    try:
        s.register_child(rid, a['fence'], proc)

        class Child:
            pid = proc.pid
            poll = staticmethod(proc.poll)
            kill = staticmethod(proc.kill)
            wait = staticmethod(proc.wait)

            @staticmethod
            def export_checkpoint(output, epoch, stopped=False):
                return False

        with pytest.raises(TimeoutError, match='real training timeout'):
            real_job._watch(s, a, Child, tmp_path / 'out', lambda: None, 1)
        assert proc.poll() is not None
        assert s.fail(rid, a['attempt'], a['fence'], 'REAL_TIMEOUT', True, 'f' * 64, restore_generation=a['restore_generation'])['state'] == 'interrupted'
        s.release_slot(rid, fence=a['fence'])
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=20)


def test_one_heavy_task_second_claim_is_refused_while_the_first_holds_the_slot(isolated_store):
    s = isolated_store
    first, a = make_running(s)
    second = s.submit('rt-second', 'a', str(uuid.uuid4()), {'epochs': 1, 'scope': 'synthetic-execution-only'})
    from fieldwork.store import Conflict
    try:
        with pytest.raises(Conflict, match='NOT_QUEUED_OR_SLOT_BUSY'):
            s.claim(second['id'])
        assert s.get(second['id'])['state'] == 'queued'
    finally:
        s.release_slot(first['id'], fence=a['fence'])
    b = s.claim(second['id'], start=False)  # slot free again
    assert b['state'] == 'leased'
    s.release_slot(second['id'], fence=b['fence'])
