"""Do not bypass live resource admission just to obtain a green test run."""
import pytest,psutil,shutil
from pathlib import Path

@pytest.fixture
def isolated_store():
    import uuid,psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict,make_conninfo
    from fieldwork.store import Store
    live=Store();name='fieldwork_test_'+uuid.uuid4().hex
    with psycopg.connect(live.dsn,autocommit=True) as c:c.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
    try:
        params=conninfo_to_dict(live.dsn);params['dbname']=name
        s=Store(dsn=make_conninfo(**params));s.migrate()
        # Throwaway isolated DB only: apply the authored, otherwise UNAPPLIED 004.
        with s.connect() as c:c.execute((Path(__file__).resolve().parents[1]/'migrations/004_cancel_generation.sql').read_text())
        # ...and the authored round-5 005 (restore generation, receipts, fw_runs guard).
        with s.connect() as c:c.execute((Path(__file__).resolve().parents[1]/'migrations/005_restore_generation_guards.sql').read_text())
        yield s
    finally:
        with psycopg.connect(live.dsn,autocommit=True) as c:
            c.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
            # Request principals provisioned by tests/isolated_api.py (cluster-global roles).
            for role in getattr(locals().get('s'),'extra_roles',[]):
                c.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))

@pytest.fixture(autouse=True)
def resource_admission(request):
    if Path(str(request.fspath)).name in {'test_optimization.py','test_bundle.py','test_replay.py'}:
        available=psutil.virtual_memory().available;free=shutil.disk_usage(Path(__file__).resolve().parents[1]).free
        import os
        # Explicit operator waiver of the RAM threshold only (recorded by the run log); disk is never waived.
        ram_ok=available>=6*1024**3 or os.environ.get('FIELDWORK_OPERATOR_RAM_OVERRIDE')=='accept-low-available-ram'
        if not ram_ok or free<12*1024**3:
            pytest.skip(f'Actual heavy execution blocked: RAM={available} disk={free}; require 6GiB/12GiB. Earlier retained proof logs are separate historical evidence.')


@pytest.fixture
def restore_reloaded_modules():
    """Tests that importlib.reload() env-dependent modules rebind their classes in place; other test files hold the
    originals (e.g. ModelContainerUnavailable). Snapshot each module namespace and put it back afterwards."""
    import importlib
    names = ('fieldwork.model_volume_staging', 'fieldwork.real_model_container', 'fieldwork.api_screens',
             'fieldwork.real_retention')
    saved = {n: dict(importlib.import_module(n).__dict__) for n in names}
    yield
    import sys
    for n, snapshot in saved.items():
        mod = sys.modules[n]
        mod.__dict__.clear()
        mod.__dict__.update(snapshot)
