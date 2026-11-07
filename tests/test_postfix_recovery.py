"""FW-03 real isolated PostgreSQL and real killed stdlib processes; no training."""
import json,os,subprocess,sys,time
from pathlib import Path
import pytest
from fieldwork.store import Store,Conflict,ROOT


def completed(s,key='one'):
    r=s.submit('post-failure','fixture',key,{'epochs':1})
    a=s.claim(r['id'])
    # State-machine fixture only: do not claim new optimizer/checkpoint proof.
    with s.connect() as c:c.execute('UPDATE fw_runs SET epoch=1 WHERE id=%s',(r['id'],))
    s.complete(r['id'],a['fence'],a['cancel_generation'],{'best':{'epoch':1}},attempt=a['attempt'])
    return a


def test_training_completion_atomically_establishes_pending_artifact_work(isolated_store):
    s=isolated_store;a=completed(s)
    assert s.get(a['id'])['state']=='succeeded'
    assert s.get(a['id'])['artifact_status']=='pending'
    assert [e['kind'] for e in s.events('post-failure')][-2:]==['succeeded','artifact_pending']


def test_pre_mkdir_failure_is_durable_and_training_survives(isolated_store,tmp_path):
    from fieldwork.artifact_pipeline import finalize_artifacts
    s=isolated_store;a=completed(s);bad=tmp_path/'not-a-directory';bad.write_text('obstruction')
    with pytest.raises(OSError):finalize_artifacts(s,a,bad,ROOT/'var/images',{})
    state=Store(dsn=s.dsn).get(a['id'])
    assert state['state']=='succeeded' and state['artifact_status']=='failed'
    assert state['artifact_result']['code']=='ARTIFACT_PIPELINE_FAILED'


def test_expired_artifact_lease_cannot_publish_even_with_owner_slot(isolated_store):
    s=isolated_store;a=completed(s)
    s.artifact_transition(a['id'],a['fence'],'building',{});s.artifact_transition(a['id'],a['fence'],'inference',{})
    with s.connect() as c:c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second' WHERE id=%s",(a['id'],))
    with pytest.raises(Conflict):s.artifact_transition(a['id'],a['fence'],'verified',{})
    assert s.recover_artifacts()==[] # A still-live owner is never evicted by expiry alone.


@pytest.mark.parametrize('stage',['pending','building'])
def test_real_process_kill_orphan_scan_reclaim_fences_old_worker(isolated_store,tmp_path,stage):
    s=isolated_store;ready=tmp_path/'ready.json'
    # Child loads only store/stdlib, claims its own real owner identity, then dies mid-stage.
    program="""import json,sys,time
from pathlib import Path
from fieldwork.store import Store
s=Store(dsn=sys.argv[1]);r=s.submit('killed','fixture','one',{'epochs':1});a=s.claim(r['id'])
with s.connect() as c:c.execute('UPDATE fw_runs SET epoch=1 WHERE id=%s',(r['id'],))
s.complete(r['id'],a['fence'],a['cancel_generation'],{'best':{'epoch':1}},attempt=a['attempt'])
if sys.argv[3]=='building':s.artifact_transition(r['id'],a['fence'],'building',{})
Path(sys.argv[2]).write_text(json.dumps({'id':r['id'],'fence':a['fence']}))
time.sleep(120)
"""
    p=subprocess.Popen([sys.executable,'-c',program,s.dsn,str(ready),stage],cwd=ROOT)
    try:
        deadline=time.monotonic()+15
        while not ready.exists() and p.poll() is None and time.monotonic()<deadline:time.sleep(.03)
        assert ready.exists();a=json.loads(ready.read_text())
        p.kill();p.wait(timeout=10)
        with s.connect() as c:c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second' WHERE id=%s",(a['id'],))
        assert s.recover_artifacts()==[a['id']]
        current=s.get(a['id']);assert current['state']=='succeeded' and current['artifact_status']=='retry_pending'
        assert current['fence']>a['fence']
        b=s.claim_artifacts(a['id'])
        with pytest.raises(Conflict):s.artifact_transition(a['id'],a['fence'],'building',{})
        with pytest.raises(Conflict):s.release_slot(a['id'],fence=a['fence'])
        s.artifact_transition(b['id'],b['fence'],'building',{})
        s.artifact_transition(b['id'],b['fence'],'failed',{'code':'EXPLICIT_RETRY_FAILURE'})
        assert Store(dsn=s.dsn).get(a['id'])['artifact_result']['code']=='EXPLICIT_RETRY_FAILURE'
        assert [e['kind'] for e in s.events('killed')][-3:]==['artifact_pending','artifact_building','artifact_failed']
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=10)


def test_orphan_scan_never_clears_slot_with_live_registered_child(isolated_store):
    import psutil
    s=isolated_store;a=completed(s)
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])
    try:
        with s.connect() as c:
            c.execute('UPDATE fw_slot SET owner_pid=%s,owner_created=%s,pid=%s,child_created=%s WHERE id=1',(99999999,0,child.pid,psutil.Process(child.pid).create_time()))
            c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second',artifact_owner_pid=99999999,artifact_owner_created=0 WHERE id=%s",(a['id'],))
        assert s.recover_artifacts()==[]
        with s.connect() as c:assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run']==a['id']
        child.kill();child.wait(timeout=10)
        assert s.recover_artifacts()==[a['id']]
    finally:
        if child.poll() is None:child.kill();child.wait(timeout=10)


def test_child_registration_blocks_release_until_waited_exit(isolated_store):
    s=isolated_store;a=completed(s);s.artifact_transition(a['id'],a['fence'],'building',{})
    s.begin_child(a['id'],a['fence'],artifact=True)
    p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])
    try:
        s.register_child(a['id'],a['fence'],p)
        with pytest.raises(Conflict,match='CHILD_EXIT_UNCONFIRMED'):s.release_slot(a['id'],fence=a['fence'])
        p.kill();p.wait(timeout=10)
        s.artifact_transition(a['id'],a['fence'],'failed',{'code':'CONFIRMED_EXIT'})
        s.release_slot(a['id'],fence=a['fence'])
        with s.connect() as c:assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run'] is None
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=10)


def test_ambiguous_spawn_crash_records_failure_without_freeing_unknown_child_slot(isolated_store):
    s=isolated_store;a=completed(s);s.artifact_transition(a['id'],a['fence'],'building',{})
    s.begin_child(a['id'],a['fence'],artifact=True)
    # Simulate committed launch intent with absent owner, unknown process creation.
    # The real kill tests above cover process death at both durable stage edges.
    with s.connect() as c:
        c.execute('UPDATE fw_slot SET owner_pid=99999999,owner_created=0 WHERE id=1')
        c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second',artifact_owner_pid=99999999,artifact_owner_created=0 WHERE id=%s",(a['id'],))
    assert s.recover_artifacts()==[a['id']]
    state=Store(dsn=s.dsn).get(a['id'])
    assert state['state']=='succeeded' and state['artifact_status']=='failed'
    assert state['artifact_result']['code']=='ARTIFACT_CHILD_EXIT_UNCONFIRMED'
    with s.connect() as c:assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run']==a['id']
    with pytest.raises(Conflict):s.claim_artifacts(a['id'])
