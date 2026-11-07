import importlib
import json

import pytest

DEFAULT = 2 * 1024 ** 3
OVERRIDE = 64 * 1024 ** 3


def _modules(monkeypatch, value):
    if value is None:
        monkeypatch.delenv('FIELDWORK_OPERATOR_SPACE_OVERRIDE', raising=False)
    else:
        monkeypatch.setenv('FIELDWORK_OPERATOR_SPACE_OVERRIDE', value)
    from fieldwork import model_volume_staging as staging, real_model_container as container
    importlib.reload(staging)
    importlib.reload(container)
    return staging, container


@pytest.fixture(autouse=True)
def _restore(restore_reloaded_modules):
    yield


def test_budget_is_two_gib_unless_the_exact_override_is_set(monkeypatch):
    assert _modules(monkeypatch, None)[0].MODEL_RUN_WRITE_BUDGET_BYTES == DEFAULT
    assert _modules(monkeypatch, 'true')[0].MODEL_RUN_WRITE_BUDGET_BYTES == DEFAULT
    assert _modules(monkeypatch, 'accept-large-run-writes')[0].MODEL_RUN_WRITE_BUDGET_BYTES == OVERRIDE


def test_default_ledger_is_rejected_when_limit_differs_without_override(monkeypatch):
    _, container = _modules(monkeypatch, None)
    assert container._ACCEPTED_BUDGET_LIMITS == {DEFAULT}


def test_override_reads_and_upgrades_a_two_gib_ledger(monkeypatch, tmp_path):
    _, container = _modules(monkeypatch, 'accept-large-run-writes')
    runner = container.ModelContainerRunner.__new__(container.ModelContainerRunner)
    runner.registry_dir = tmp_path
    scope = 'a' * 64
    old = {'schema': 'fieldwork.model-run-write-budget/v2', 'scope_sha256': scope, 'limit_bytes': DEFAULT,
           'charged_bytes': 1670_000_000, 'reservations': [],
           'completed': [{'nonce': 'b' * 32, 'charged_bytes': 1670_000_000, 'staged_bytes': 1_000_000_000,
                          'exported_bytes': 0, 'child_output_bytes': 542_000_000, 'fixed_tmp_bytes': 128_000_000}]}
    old['completed'][0]['charged_bytes'] = 1_000_000_000 + 542_000_000 + 128_000_000
    old['charged_bytes'] = old['completed'][0]['charged_bytes']
    (tmp_path / ('.model-write-budget-' + scope + '.json')).write_text(json.dumps(old), encoding='utf-8')
    ledger = runner._load_budget_ledger(scope)
    assert ledger['limit_bytes'] == OVERRIDE and ledger['charged_bytes'] == old['charged_bytes']


def test_override_lets_a_large_charge_still_fit_a_bundle_stage(monkeypatch):
    _, container = _modules(monkeypatch, 'accept-large-run-writes')
    assert container._output_tmpfs_capacity(500_000_000, 1_900_000_000) >= 64 * 1024 * 1024
    _, container = _modules(monkeypatch, None)
    with pytest.raises(container.ModelContainerUnavailable):
        container._output_tmpfs_capacity(500_000_000, 1_900_000_000)


def test_other_disk_gates_drop_to_the_floor_only_under_the_exact_override(monkeypatch):
    from fieldwork import api_screens, real_retention
    gib = 1024 ** 3
    monkeypatch.delenv('FIELDWORK_OPERATOR_SPACE_OVERRIDE', raising=False)
    importlib.reload(api_screens); importlib.reload(real_retention)
    assert api_screens.REQUIRED_DISK_BYTES == 12 * gib and real_retention.MIN_FREE == 50 * gib
    monkeypatch.setenv('FIELDWORK_OPERATOR_SPACE_OVERRIDE', 'accept-large-run-writes')
    importlib.reload(api_screens); importlib.reload(real_retention)
    assert api_screens.REQUIRED_DISK_BYTES == 5 * gib and real_retention.MIN_FREE == 5 * gib
    monkeypatch.setenv('FIELDWORK_OPERATOR_SPACE_OVERRIDE', 'on')
    importlib.reload(api_screens); importlib.reload(real_retention)
    assert api_screens.REQUIRED_DISK_BYTES == 12 * gib and real_retention.MIN_FREE == 50 * gib
