import types,uuid
import pytest
from fieldwork.data import generate


def test_real_worker_preflight_includes_projected_child_and_host_peak(monkeypatch, tmp_path):
    import fieldwork.worker as worker
    monkeypatch.setattr(worker, 'ROOT', tmp_path)
    monkeypatch.setattr(worker.psutil, 'virtual_memory',
        lambda: types.SimpleNamespace(available=6 * 1024**3))
    monkeypatch.setattr(worker.shutil, 'disk_usage',
        lambda path: types.SimpleNamespace(free=12 * 1024**3))
    admitted, detail = worker.preflight(real_runs=True)
    assert not admitted
    assert detail['projected_child_memory_bytes'] == 2 * 1024**3
    assert detail['bounded_host_staging_export_allowance_bytes'] == 256 * 1024**2
    assert detail['projected_peak_ram_bytes'] == 2 * 1024**3 + 256 * 1024**2
    assert detail['required_available_ram_bytes'] == detail['projected_peak_ram_bytes'] + 4 * 1024**3
    assert worker.preflight(real_runs=False)[0]


def test_worker_spawn_failure_records_failure_and_releases_only_its_slot(isolated_store,monkeypatch,tmp_path):
    import fieldwork.worker as worker
    s=isolated_store;m=generate(tmp_path/'var/images')
    r=s.submit('spawn-fault','fixture','one',{'epochs':1,'dataset_digest':m['digest'],'recipe':'compact-cnn/v1','scope':'synthetic-execution-only'})
    monkeypatch.setattr(worker,'Store',lambda:s);monkeypatch.setattr(worker,'ROOT',tmp_path)
    # Fault-only admission stub: Popen is guaranteed to fail before any model executes.
    monkeypatch.setattr(worker.psutil,'virtual_memory',lambda:types.SimpleNamespace(available=6*1024**3))
    monkeypatch.setattr(worker.shutil,'disk_usage',lambda path:types.SimpleNamespace(free=12*1024**3))
    def fail_spawn(*args,**kwargs):raise OSError('injected create-process denial')
    monkeypatch.setattr(worker.subprocess,'Popen',fail_spawn)
    with pytest.raises(OSError):worker.execute(r['id'])
    assert s.get(r['id'])['state']=='interrupted'
    with s.connect() as c:assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run'] is None


def test_worker_main_contains_per_job_oserror_and_releases_host_lock(monkeypatch,tmp_path,capsys):
    import argparse
    import fieldwork.worker as worker
    run_id=str(uuid.uuid4())
    class StubStore:
        identity_mode='test'
        def migrate(self):pass
        def recover_artifacts(self):pass
        def reconcile_training_slot(self):return None
        def release_own_slot(self):return None
        def next_run(self,blocked):return {'id':run_id,'revision':1}
    class StubLock:
        released=False
        def __init__(self,path):pass
        def acquire(self,purpose):return True
        def release(self):self.released=True;return True
    lock=StubLock(None)
    monkeypatch.setattr(worker,'ROOT',tmp_path)
    monkeypatch.setattr(worker,'parse_args',lambda:argparse.Namespace(
        real_runs=False,once=True,run_id=None,proof_pause_epoch=None))
    monkeypatch.setattr(worker,'worker_store',lambda **kwargs:StubStore())
    monkeypatch.setattr(worker,'operator_paused',lambda:False)
    monkeypatch.setattr(worker,'preflight',lambda **kwargs:(True,{}))
    monkeypatch.setattr(worker,'HostHeavyLock',lambda path:lock)
    def fail_job(*args,**kwargs):raise OSError('private OS diagnostic must not be logged')
    monkeypatch.setattr(worker,'execute',fail_job)

    assert worker.main()==26
    assert lock.released
    output=capsys.readouterr().out
    assert 'RUN_WORKER_INFRASTRUCTURE_FAILED' in output
    assert run_id in output
    assert 'private OS diagnostic' not in output


def test_worker_main_contains_database_privilege_error_after_releasing_lock(monkeypatch,tmp_path,capsys):
    import argparse
    import psycopg
    import fieldwork.worker as worker
    run_id=str(uuid.uuid4())
    class StubStore:
        identity_mode='test'
        def migrate(self):pass
        def recover_artifacts(self):pass
        def reconcile_training_slot(self):return None
        def release_own_slot(self):return None
        def next_run(self,blocked):return {'id':run_id,'revision':1}
    class StubLock:
        released=False
        def __init__(self,path):pass
        def acquire(self,purpose):return True
        def release(self):self.released=True;return True
    lock=StubLock(None)
    monkeypatch.setattr(worker,'ROOT',tmp_path)
    monkeypatch.setattr(worker,'parse_args',lambda:argparse.Namespace(
        real_runs=False,once=True,run_id=None,proof_pause_epoch=None))
    monkeypatch.setattr(worker,'worker_store',lambda **kwargs:StubStore())
    monkeypatch.setattr(worker,'operator_paused',lambda:False)
    monkeypatch.setattr(worker,'preflight',lambda **kwargs:(True,{}))
    monkeypatch.setattr(worker,'HostHeavyLock',lambda path:lock)
    def fail_job(*args,**kwargs):raise psycopg.errors.InsufficientPrivilege('private database detail')
    def checked_backoff(seconds):
        assert lock.released
        assert seconds==30
    monkeypatch.setattr(worker,'execute',fail_job)
    monkeypatch.setattr(worker.time,'sleep',checked_backoff)

    assert worker.main()==26
    assert lock.released
    output=capsys.readouterr().out
    assert 'RUN_WORKER_DATABASE_FAILURE' in output
    assert '42501' in output
    assert 'automatic_reset' in output and 'false' in output
    assert run_id in output
    assert 'private database detail' not in output
