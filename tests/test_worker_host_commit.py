"""Pure tests: the shared host policy may refuse before any lease/claim."""
import json
from types import SimpleNamespace

import pytest

from fieldwork import worker


def sampler(monkeypatch, *, percent=84, used=84, limit=100, free=50_000_000_000):
    monkeypatch.setenv('FIELDWORK_HOST_HEAVY_LOCK', 'fixture-host-lock')
    monkeypatch.setattr(worker.subprocess, 'run', lambda *a, **kw: SimpleNamespace(
        returncode=0, stdout=json.dumps({'CommittedBytes': used, 'CommitLimit': limit,
                                        'PercentCommittedBytesInUse': percent})))
    monkeypatch.setattr(worker.shutil, 'disk_usage', lambda path: SimpleNamespace(free=free))


def test_portfolio_opt_in_preserves_portable_gate(monkeypatch):
    monkeypatch.delenv('FIELDWORK_HOST_HEAVY_LOCK', raising=False)
    monkeypatch.setattr(worker.subprocess, 'run', lambda *a, **kw: pytest.fail('unexpected sampler'))
    assert worker.portfolio_host_preflight(platform_name='nt')['host_admitted'] is True


def test_exact_host_boundary_passes_below_85(monkeypatch):
    sampler(monkeypatch)
    result=worker.portfolio_host_preflight(platform_name='nt')
    assert result['host_admitted'] is True
    assert result['host_free_c_bytes']==50_000_000_000


@pytest.mark.parametrize('percent,used', [(85,85),(84,86),(93,93)])
def test_commit_refusal_even_with_sufficient_disk(monkeypatch,percent,used):
    sampler(monkeypatch,percent=percent,used=used)
    assert worker.portfolio_host_preflight(platform_name='nt')['host_admitted'] is False


def test_free_c_below_global_floor_refuses(monkeypatch):
    sampler(monkeypatch,free=49_999_999_999)
    assert worker.portfolio_host_preflight(platform_name='nt')['host_admitted'] is False


def test_missing_counter_fails_closed(monkeypatch):
    sampler(monkeypatch)
    monkeypatch.setattr(worker.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=0,stdout='{}'))
    assert worker.portfolio_host_preflight(platform_name='nt')['host_admitted'] is False


def test_sampler_timeout_fails_closed(monkeypatch):
    sampler(monkeypatch)
    def timeout(*a,**kw):
        raise worker.subprocess.TimeoutExpired('fixture sampler',15)
    monkeypatch.setattr(worker.subprocess,'run',timeout)
    assert worker.portfolio_host_preflight(platform_name='nt')['host_admitted'] is False


def test_host_refusal_cannot_be_overridden_by_product_ram_gate(monkeypatch):
    monkeypatch.setattr(worker.psutil,'virtual_memory',lambda:SimpleNamespace(available=20*1024**3))
    monkeypatch.setattr(worker.shutil,'disk_usage',lambda path:SimpleNamespace(free=200*1024**3))
    monkeypatch.setattr(worker,'portfolio_host_preflight',lambda:{'host_admitted':False,'portfolio_host_policy':True})
    admitted,detail=worker.preflight(real_runs=True)
    assert admitted is False and detail['admitted'] is False
    assert detail['required_free_disk_bytes']==12*1024**3
