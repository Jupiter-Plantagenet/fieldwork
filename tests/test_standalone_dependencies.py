"""Regression checks for the helpers distributed with a standalone checkout."""
from pathlib import Path


def test_worker_and_retention_resolve_the_bundled_lock(monkeypatch):
    from fieldwork import real_retention, worker

    monkeypatch.delenv('PORTFOLIO_TOOLS', raising=False)
    root = Path(__file__).resolve().parents[1]
    expected = root / 'tools' / 'product_lock.py'
    assert Path(worker._product_lock().__file__) == expected
    assert Path(real_retention._global_lock_module().__file__) == expected


def test_operator_helper_uses_this_repository():
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    path = root / 'tools' / 'activate_real_worker.py'
    spec = importlib.util.spec_from_file_location('standalone_activation_helper', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    assert helper.ROOT == root
    assert helper.REPO == root


def test_slot_scan_normalizes_windows_and_posix_paths(monkeypatch):
    from types import SimpleNamespace
    from tools import slot_release

    monkeypatch.setattr(slot_release, 'ROOT', Path('C:/workspace/fieldwork'))
    process = SimpleNamespace(info={
        'pid': 123, 'create_time': 42.0,
        'cmdline': ['python', '--out', r'C:\workspace\fieldwork\var\runs\case-1'],
    })
    unrelated = SimpleNamespace(info={
        'pid': 456, 'create_time': 43.0,
        'cmdline': ['python', '--out', 'C:/workspace/fieldwork/var/runs/other'],
    })
    monkeypatch.setattr(slot_release.psutil, 'process_iter', lambda fields: [process, unrelated])
    assert slot_release.launch_scan('case-1') == [{'pid': 123, 'create_time': 42.0}]
