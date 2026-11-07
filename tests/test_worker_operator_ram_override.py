from types import SimpleNamespace

from fieldwork import worker

LOW = SimpleNamespace(available=1 * 1024 ** 3)
HOST_OK = {'portfolio_host_policy': False, 'host_admitted': True}


def _preflight(monkeypatch, override=None, host=HOST_OK, free=100 * 1024 ** 3):
    monkeypatch.setattr(worker, 'portfolio_host_preflight', lambda: dict(host))
    monkeypatch.setattr(worker.psutil, 'virtual_memory', lambda: LOW)
    monkeypatch.setattr(worker.shutil, 'disk_usage', lambda _p: SimpleNamespace(free=free))
    if override is None:
        monkeypatch.delenv('FIELDWORK_OPERATOR_RAM_OVERRIDE', raising=False)
    else:
        monkeypatch.setenv('FIELDWORK_OPERATOR_RAM_OVERRIDE', override)
    return worker.preflight(real_runs=True)


def test_low_ram_is_refused_by_default(monkeypatch):
    admitted, detail = _preflight(monkeypatch)
    assert admitted is False and 'operator_ram_override' not in detail


def test_exact_operator_override_skips_only_the_ram_comparison_and_is_recorded(monkeypatch):
    admitted, detail = _preflight(monkeypatch, 'accept-low-available-ram')
    assert admitted is True
    assert detail['operator_ram_override'] is True
    assert detail['available_ram_bytes'] == 1 * 1024 ** 3


def test_override_value_must_match_exactly(monkeypatch):
    admitted, _ = _preflight(monkeypatch, '1')
    assert admitted is False


def test_override_waives_commit_gate_but_never_free_disk(monkeypatch):
    commit_refused = {'portfolio_host_policy': True, 'host_admitted': False, 'host_refusal': 'HOST_DISK_OR_COMMIT_GATE'}
    free = lambda _p: SimpleNamespace(free=100 * 1024 ** 3)  # noqa: E731
    monkeypatch.setattr(worker.shutil, 'disk_usage', free)
    assert _preflight(monkeypatch, None, host=commit_refused)[0] is False
    assert _preflight(monkeypatch, 'accept-low-available-ram', host=commit_refused)[0] is True
    assert _preflight(monkeypatch, 'accept-low-available-ram', free=1 * 1024 ** 3)[0] is False
    assert _preflight(monkeypatch, 'accept-low-available-ram', host=commit_refused, free=1 * 1024 ** 3)[0] is False


def _space(monkeypatch, value, free, host=HOST_OK):
    monkeypatch.setenv('FIELDWORK_OPERATOR_RAM_OVERRIDE', 'accept-low-available-ram')
    if value is None:
        monkeypatch.delenv('FIELDWORK_OPERATOR_SPACE_OVERRIDE', raising=False)
    else:
        monkeypatch.setenv('FIELDWORK_OPERATOR_SPACE_OVERRIDE', value)
    monkeypatch.setattr(worker, 'portfolio_host_preflight', lambda: dict(host))
    monkeypatch.setattr(worker.psutil, 'virtual_memory', lambda: LOW)
    monkeypatch.setattr(worker.shutil, 'disk_usage', lambda _p: SimpleNamespace(free=free))
    return worker.preflight(real_runs=True)


def test_space_override_lowers_disk_requirement_to_a_floor_and_is_recorded(monkeypatch):
    assert _space(monkeypatch, None, 8 * 1024 ** 3)[0] is False
    admitted, detail = _space(monkeypatch, 'accept-large-run-writes', 8 * 1024 ** 3)
    assert admitted is True and detail['operator_space_override'] is True
    assert _space(monkeypatch, 'accept-large-run-writes', 1 * 1024 ** 3)[0] is False  # floor, never zero
    assert _space(monkeypatch, 'yes', 8 * 1024 ** 3)[0] is False  # exact value only


def test_space_override_lowers_the_portfolio_host_disk_gate(monkeypatch):
    host = {'portfolio_host_policy': True, 'host_admitted': False, 'host_commit_percent': 40,
            'host_commit_used_bytes': 10, 'host_commit_limit_bytes': 100}
    assert _space(monkeypatch, None, 30 * 1024 ** 3, host)[0] is False
    assert _space(monkeypatch, 'accept-large-run-writes', 30 * 1024 ** 3, host)[0] is True


def test_screen_preflight_and_api_submit_gate_honour_the_exact_ram_override(monkeypatch):
    from fieldwork import api_screens
    monkeypatch.setattr(api_screens.psutil, 'virtual_memory', lambda: LOW)
    monkeypatch.setattr(api_screens.shutil, 'disk_usage', lambda _p: SimpleNamespace(free=100 * 1024 ** 3))
    monkeypatch.delenv('FIELDWORK_OPERATOR_RAM_OVERRIDE', raising=False)
    assert api_screens._preflight()['admitted'] is False
    monkeypatch.setenv('FIELDWORK_OPERATOR_RAM_OVERRIDE', 'yes')
    assert api_screens._preflight()['admitted'] is False
    monkeypatch.setenv('FIELDWORK_OPERATOR_RAM_OVERRIDE', 'accept-low-available-ram')
    view = api_screens._preflight()
    assert view['admitted'] is True and view['operator_ram_override'] is True and view['ram_ok'] is False
    monkeypatch.setattr(api_screens.shutil, 'disk_usage', lambda _p: SimpleNamespace(free=1 * 1024 ** 3))
    assert api_screens._preflight()['admitted'] is False  # disk still enforced
