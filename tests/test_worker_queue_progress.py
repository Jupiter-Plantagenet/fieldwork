"""Real PG: a run refused before claim must not head-of-line block the worker loop."""
import sys,uuid
import pytest
import fieldwork.worker as worker
from fieldwork.store import Conflict


@pytest.fixture(autouse=True)
def _private_worker_heartbeat(tmp_path,monkeypatch):
    # The worker publishes var/worker.json under worker_heartbeat.ROOT; never touch a live worker's marker.
    import fieldwork.worker_heartbeat as heartbeat
    monkeypatch.setattr(heartbeat,'ROOT',tmp_path)


def test_loop_skips_run_refused_before_claim(isolated_store,monkeypatch):
    s=isolated_store;w='queue-'+uuid.uuid4().hex
    first=s.submit(w,'a','k1',{'epochs':1,'scope':'synthetic-execution-only'})
    second=s.submit(w,'a','k2',{'epochs':1,'scope':'synthetic-execution-only'})
    blocked,ok=sorted([first['id'],second['id']])
    seen=[]
    def fake_execute(rid):
        seen.append(rid)
        if rid==blocked:raise Conflict('UNTRUSTED_PROFILE_BLOCKED')
        return 0
    class Stop(Exception):pass
    calls={'n':0}
    def fake_sleep(_):
        calls['n']+=1
        if calls['n']>=3:raise Stop()
    monkeypatch.setattr(worker,'Store',lambda:s);monkeypatch.setattr(worker,'execute',fake_execute)
    monkeypatch.setattr(worker,'preflight',lambda **_:(True,{}))  # host resources are not under test here
    monkeypatch.setattr(worker.time,'sleep',fake_sleep);monkeypatch.setattr(sys,'argv',['worker'])
    with pytest.raises(Stop):worker.main()
    # Old loop retried `blocked` forever; now it is skipped and the next queued run is reached.
    assert seen[0]==blocked and ok in seen and seen.count(blocked)==1


def test_worker_respects_shared_host_heavy_lock(isolated_store,monkeypatch,tmp_path):
    import json
    s=isolated_store;w='lock-'+uuid.uuid4().hex
    r=s.submit(w,'a','k1',{'epochs':1,'scope':'synthetic-execution-only'})
    lock=tmp_path/'product-build.lock';lock.mkdir();(lock/'owner').write_text('owner=another-product')
    ran=[]
    monkeypatch.setattr(worker,'Store',lambda:s);monkeypatch.setattr(worker,'execute',lambda rid:ran.append(rid) or 0)
    monkeypatch.setattr(worker,'preflight',lambda **_:(True,{}))
    monkeypatch.setenv('FIELDWORK_HOST_HEAVY_LOCK',str(lock));monkeypatch.setattr(sys,'argv',['worker','--once','--run-id',r['id']])
    assert worker.main()==25 and ran==[] and (lock/'owner').exists()      # busy: never stolen
    (lock/'owner').unlink();lock.rmdir()
    assert worker.main()==0 and ran==[r['id']] and not lock.exists()         # acquired, ran, released own lock


def test_loop_does_not_take_host_lock_when_resource_gate_refuses(isolated_store,monkeypatch,tmp_path):
    s=isolated_store;r=s.submit('gate-'+uuid.uuid4().hex,'a','k1',{'epochs':1,'scope':'synthetic-execution-only'})
    lock=tmp_path/'product-build.lock';acquired=[]
    real=worker.HostHeavyLock.acquire
    monkeypatch.setattr(worker.HostHeavyLock,'acquire',lambda self,p:acquired.append(p) or real(self,p))
    monkeypatch.setattr(worker,'Store',lambda:s);monkeypatch.setattr(worker,'preflight',lambda **_:(False,{'code':'RESOURCE_PREFLIGHT'}))
    monkeypatch.setenv('FIELDWORK_HOST_HEAVY_LOCK',str(lock));monkeypatch.setattr(sys,'argv',['worker','--once','--run-id',r['id']])
    assert worker.main()==23 and acquired==[] and not lock.exists() and s.get(r['id'])['state']=='queued'
