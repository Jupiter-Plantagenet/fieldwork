"""Terminal slot crash boundaries: canonical isolated PG + real tiny processes, no ML."""
import hashlib,json,subprocess,sys,time
from pathlib import Path
import psutil,pytest
from fieldwork.store import Store,Conflict,ROOT

PROGRAM = '''import json,sys,time,subprocess
from pathlib import Path
from psycopg.types.json import Jsonb
from fieldwork.store import Store
s=Store(dsn=sys.argv[1]);stage=sys.argv[3];mode=sys.argv[4]
r=s.submit('terminal-slot','fixture','one',{'epochs':1});a=s.claim(r['id'])
with s.connect() as c:c.execute('UPDATE fw_runs SET epoch=1 WHERE id=%s',(r['id'],))
s.complete(r['id'],a['fence'],a['cancel_generation'],{'best':{'epoch':1}},attempt=a['attempt'])
s.artifact_transition(r['id'],a['fence'],'building',{})
s.artifact_transition(r['id'],a['fence'],'inference',{})
s.begin_child(r['id'],a['fence'],artifact=True)
p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])
s.register_child(r['id'],a['fence'],p)
p.kill();p.wait(timeout=10)
detail=json.loads(sys.argv[5])
if mode=='precommit':Path(sys.argv[2]).write_text(json.dumps({'id':r['id'],'fence':a['fence'],'child':p.pid}))
if mode in ('atomic','precommit'):s.artifact_transition(r['id'],a['fence'],stage,detail)
else:
    # Canonical historical commit-before-finally state, not a fake SQL seam.
    with s.connect() as c:
        c.execute('UPDATE fw_runs SET artifact_status=%s,artifact_result=%s,revision=revision+1 WHERE id=%s',(stage,Jsonb(detail),r['id']))
        s.event(c,r,'artifact_'+stage,dict(status=stage,**detail))
Path(sys.argv[2]).write_text(json.dumps({'id':r['id'],'fence':a['fence'],'child':p.pid}))
time.sleep(120)
'''


def evidence(tmp_path):
    import shutil
    folder=tmp_path/'historical-evidence'
    shutil.copytree(ROOT/'evidence/internal-candidate',folder/'bundle')
    receipt=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/fresh-process.json'
    shutil.copyfile(receipt,folder/'fresh-process.json')
    r=json.loads(receipt.read_bytes());manifest=(folder/'bundle/manifest.json').read_bytes()
    detail={'bundle_digest':hashlib.sha256(manifest).hexdigest(),'receipt_digest':r['output_digest'],'model_digest':r['model_digest'],'process_identity':r['process_identity']}
    return folder,detail


def hashes(folder):
    return {str(p.relative_to(folder)):hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.rglob('*') if p.is_file()}


def owner(s,tmp_path,stage,mode):
    folder,detail=evidence(tmp_path);ready=tmp_path/'ready.json'
    p=subprocess.Popen([sys.executable,'-c',PROGRAM,s.dsn,str(ready),stage,mode,json.dumps(detail)],cwd=ROOT)
    try:
        deadline=time.monotonic()+20
        while not ready.exists() and p.poll() is None and time.monotonic()<deadline:time.sleep(.03)
        assert ready.exists(),f'boundary not reached; child exit={p.poll()}'
        a=json.loads(ready.read_text());assert not psutil.pid_exists(a['child'])
        return p,a,folder,detail
    except BaseException:
        if p.poll() is None:p.kill();p.wait(timeout=10)
        raise


def slot(s):
    with s.connect() as c:return c.execute('SELECT * FROM fw_slot WHERE id=1').fetchone()


def kill(p):
    if p.poll() is None:p.kill()
    p.wait(timeout=10)
    assert not psutil.pid_exists(p.pid)


@pytest.mark.parametrize('stage',['failed','verified'])
def test_terminal_commit_has_no_release_crash_window(isolated_store,tmp_path,stage):
    s=isolated_store;p,a,folder,detail=owner(s,tmp_path,stage,'atomic');before=hashes(folder)
    try:
        # Real supervisor is paused after terminal commit, before worker finally.
        assert s.get(a['id'])['artifact_status']==stage
        assert slot(s)['run'] is None
    finally:kill(p)
    restarted=Store(dsn=s.dsn)
    assert restarted.recover_artifacts()==[]
    r=restarted.get(a['id'])
    assert r['state']=='succeeded' and r['artifact_status']==stage
    assert r['artifact_attempts']==1 and r['artifact_result']==detail
    assert hashes(folder)==before
    b=s.submit('terminal-slot','fixture','next',{'epochs':1})
    s.claim(b['id']);s.release_slot(b['id'])


@pytest.mark.parametrize('stage',['failed','verified'])
def test_legacy_terminal_kill_restart_preserves_result_and_evidence(isolated_store,tmp_path,stage):
    s=isolated_store;p,a,folder,detail=owner(s,tmp_path,stage,'legacy')
    before=hashes(folder);kill(p)
    with s.connect() as c:c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second' WHERE id=%s",(a['id'],))
    row=s.get(a['id']);events=s.events('terminal-slot')
    restarted=Store(dsn=s.dsn)
    assert restarted.recover_artifacts()==[a['id']]
    assert slot(s)['run'] is None
    assert s.get(a['id'])==row and s.events('terminal-slot')==events
    assert hashes(folder)==before and row['artifact_result']==detail
    assert restarted.recover_artifacts()==[]
    if stage=='verified':
        with pytest.raises(Conflict):s.claim_artifacts(a['id'])
    else:
        b=s.claim_artifacts(a['id'])
        assert b['artifact_attempts']==2 and b['fence']==a['fence']+1
        with pytest.raises(Conflict):s.artifact_transition(a['id'],a['fence'],'failed',{})
        with pytest.raises(Conflict):s.release_slot(a['id'],fence=a['fence'])
        assert s.recover_artifacts()==[] and slot(s)['fence']==b['fence']
        s.artifact_transition(b['id'],b['fence'],'failed',{})
        b=s.claim_artifacts(a['id']);s.artifact_transition(b['id'],b['fence'],'failed',{})
        with pytest.raises(Conflict,match='ATTEMPT_BUDGET'):s.claim_artifacts(a['id'])


@pytest.mark.parametrize('guard',['unexpired','live_owner','live_child','unknown_child_identity','launching','slot_fence','slot_owner','run_owner_unknown','manual_failure'])
def test_legacy_terminal_retains_uncertain_or_inexact_ownership(isolated_store,tmp_path,guard):
    s=isolated_store;p,a,folder,detail=owner(s,tmp_path,'failed','legacy');kill(p)
    child=None
    try:
        with s.connect() as c:
            if guard!='unexpired':c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second' WHERE id=%s",(a['id'],))
            if guard=='live_owner':
                birth=psutil.Process().create_time()
                c.execute('UPDATE fw_runs SET artifact_owner_pid=%s,artifact_owner_created=%s WHERE id=%s',(psutil.Process().pid,birth,a['id']))
                c.execute('UPDATE fw_slot SET owner_pid=%s,owner_created=%s WHERE id=1',(psutil.Process().pid,birth))
            elif guard in ('live_child','unknown_child_identity'):
                child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])
                birth=psutil.Process(child.pid).create_time() if guard=='live_child' else None
                c.execute('UPDATE fw_slot SET pid=%s,child_created=%s WHERE id=1',(child.pid,birth))
            elif guard=='launching':c.execute('UPDATE fw_slot SET launching=true,pid=NULL,child_created=NULL WHERE id=1')
            elif guard=='slot_fence':c.execute('UPDATE fw_slot SET fence=fence+1 WHERE id=1')
            elif guard=='slot_owner':c.execute('UPDATE fw_slot SET owner_created=owner_created+1 WHERE id=1')
            elif guard=='run_owner_unknown':c.execute('UPDATE fw_runs SET artifact_owner_created=NULL WHERE id=%s',(a['id'],))
            elif guard=='manual_failure':c.execute("UPDATE fw_runs SET artifact_result='{"+'"code":"ARTIFACT_CHILD_EXIT_UNCONFIRMED","automatic_retry":false' + "}'::jsonb WHERE id=%s",(a['id'],))
        prior=slot(s);row=s.get(a['id'])
        assert Store(dsn=s.dsn).recover_artifacts()==[]
        assert slot(s)==prior and s.get(a['id'])==row
    finally:
        if child is not None:kill(child)


def test_pid_reuse_identity_mismatch_is_dead_old_identity(isolated_store,tmp_path):
    s=isolated_store;p,a,folder,detail=owner(s,tmp_path,'verified','legacy');kill(p)
    # Existing PID with a different birth is not the recorded owner/child.
    pid=psutil.Process().pid;old_birth=psutil.Process().create_time()-100
    with s.connect() as c:
        c.execute('UPDATE fw_slot SET owner_pid=%s,owner_created=%s,pid=%s,child_created=%s WHERE id=1',(pid,old_birth,pid,old_birth))
        c.execute("UPDATE fw_runs SET artifact_owner_pid=%s,artifact_owner_created=%s,lease=clock_timestamp()-interval '1 second' WHERE id=%s",(pid,old_birth,a['id']))
    assert s.recover_artifacts()==[a['id']]
    assert slot(s)['run'] is None and psutil.Process(pid).is_running()


def test_waiting_recovery_cannot_evict_newer_slot_fence(isolated_store,tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from psycopg.conninfo import make_conninfo
    s=isolated_store;p,a,folder,detail=owner(s,tmp_path,'verified','legacy');kill(p)
    with s.connect() as c:c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second' WHERE id=%s",(a['id'],))
    scanner=Store(dsn=make_conninfo(s.dsn,application_name='terminal_slot_race'))
    with ThreadPoolExecutor(max_workers=1) as pool:
        with s.connect() as c:
            c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE')
            future=pool.submit(scanner.recover_artifacts)
            deadline=time.monotonic()+10;waiting=False
            while time.monotonic()<deadline:
                with s.connect() as observer:
                    waiting=observer.execute("SELECT count(*) n FROM pg_stat_activity WHERE application_name='terminal_slot_race' AND wait_event_type='Lock'").fetchone()['n']>0
                if waiting:break
                time.sleep(.02)
            assert waiting,'recovery must actually block on the canonical slot row'
            # Replacement fixture commits while the old scan is blocked. Its
            # exact fence differs; even a dead replacement must never be evicted.
            c.execute('UPDATE fw_slot SET fence=fence+1 WHERE id=1')
        assert future.result(timeout=10)==[]
    assert slot(s)['run']==a['id'] and slot(s)['fence']==a['fence']+1


@pytest.mark.parametrize('stage',['failed','verified'])
def test_legacy_terminal_without_registered_child(isolated_store,tmp_path,stage):
    s=isolated_store;p,a,folder,detail=owner(s,tmp_path,stage,'legacy')
    try:
        with s.connect() as c:c.execute('UPDATE fw_slot SET pid=NULL,child_created=NULL WHERE id=1')
    finally:kill(p)
    with s.connect() as c:c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second' WHERE id=%s",(a['id'],))
    row=s.get(a['id'])
    assert Store(dsn=s.dsn).recover_artifacts()==[a['id']]
    assert slot(s)['run'] is None and s.get(a['id'])==row


@pytest.mark.parametrize('stage',['failed','verified'])
def test_kill_inside_terminal_transaction_rolls_back_both_changes(isolated_store,tmp_path,stage):
    s=isolated_store
    # Real PG trigger is only a scheduling barrier, not a SQL/process substitute.
    with s.connect() as c:
        c.execute('''CREATE FUNCTION terminal_commit_barrier() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.run IS NOT NULL AND NEW.run IS NULL THEN PERFORM pg_advisory_xact_lock(873); END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER terminal_commit_barrier BEFORE UPDATE ON fw_slot
        FOR EACH ROW EXECUTE FUNCTION terminal_commit_barrier();''')
    p=None
    try:
        with s.connect() as barrier:
            barrier.execute('SELECT pg_advisory_xact_lock(873)')
            p,a,folder,detail=owner(s,tmp_path,stage,'precommit')
            deadline=time.monotonic()+10;waiting=False
            while time.monotonic()<deadline:
                with s.connect() as observer:
                    waiting=observer.execute("SELECT count(*) n FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE 'UPDATE fw_slot SET run=NULL%'").fetchone()['n']>0
                if waiting:break
                time.sleep(.02)
            assert waiting,'must kill after terminal UPDATE/event and before slot UPDATE/COMMIT'
            kill(p)
        # Neither terminal status nor release committed; restart uses active recovery.
        assert s.get(a['id'])['artifact_status']=='inference'
        assert slot(s)['run']==a['id']
        assert s.events('terminal-slot')[-1]['kind']=='artifact_inference'
        with s.connect() as c:c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second' WHERE id=%s",(a['id'],))
        assert Store(dsn=s.dsn).recover_artifacts()==[a['id']]
        assert slot(s)['run'] is None
    finally:
        if p is not None:kill(p)


@pytest.mark.parametrize('ambiguous',[False,True])
def test_failed_publication_does_not_release_live_or_unknown_child(isolated_store,ambiguous):
    from tests.test_postfix_recovery import completed
    s=isolated_store;a=completed(s);s.begin_child(a['id'],a['fence'],artifact=True)
    child=None
    try:
        if not ambiguous:
            child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])
            s.register_child(a['id'],a['fence'],child)
        s.artifact_transition(a['id'],a['fence'],'failed',{'code':'ARTIFACT_CHILD_EXIT_UNCONFIRMED','automatic_retry':False})
        assert slot(s)['run']==a['id']
        with pytest.raises(Conflict,match='CHILD_EXIT_UNCONFIRMED'):s.release_slot(a['id'],fence=a['fence'])
    finally:
        if child is not None:kill(child)
