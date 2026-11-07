"""Real PG + real processes: the heavy slot is freed only on proven owner/child exit."""
import json,subprocess,sys,uuid
import pytest
from fieldwork.store import ROOT

CLAIMER=r'''
import json,sys,subprocess,time
from fieldwork.store import Store
a=json.loads(sys.argv[1]);s=Store(dsn=a['dsn']);r=s.claim(a['run'])
if a.get('child'):
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(600)'])
    s.begin_child(a['run'],r['fence']);s.register_child(a['run'],r['fence'],child)
    print(json.dumps({'child':child.pid}),flush=True)
elif a.get('launching'):
    s.begin_child(a['run'],r['fence'])
print(json.dumps({'fence':r['fence']}),flush=True)
time.sleep(600) if a.get('hold') else None
'''


def _claim_in_process(s,run,**kw):
    p=subprocess.Popen([sys.executable,'-c',CLAIMER,json.dumps({'dsn':s.dsn,'run':run,**kw})],cwd=ROOT,stdout=subprocess.PIPE,text=True)
    lines=[json.loads(p.stdout.readline())]
    if kw.get('child'):lines.append(json.loads(p.stdout.readline()))
    return p,lines


def _slot(s):
    with s.connect() as c:return c.execute('SELECT * FROM fw_slot WHERE id=1').fetchone()


def _submit(s):
    return s.submit('slot-'+uuid.uuid4().hex,'a',str(uuid.uuid4()),{'epochs':1})


def test_killed_owner_without_child_releases_slot_and_keeps_run_state(isolated_store):
    s=isolated_store;r=_submit(s)
    p,_=_claim_in_process(s,r['id'],hold=True)
    assert s.reconcile_training_slot()=='OWNER_ALIVE' and _slot(s)['run']==r['id']
    p.kill();p.wait(timeout=10)
    before=s.get(r['id'])
    assert s.reconcile_training_slot()=='RELEASED' and _slot(s)['run'] is None
    after=s.get(r['id'])
    assert {k:after[k] for k in ['state','fence','attempt','epoch']}=={k:before[k] for k in ['state','fence','attempt','epoch']}
    assert after['revision']==before['revision']+1  # durable slot_reconciled event has a new revision
    assert [e for e in s.events(r['workspace']) if e['kind']=='slot_reconciled']
    # Queue progresses: another run can now claim the physical slot.
    nxt=_submit(s);assert s.claim(nxt['id'])['state']=='running';s.release_slot(nxt['id'])


def test_live_orphan_child_retains_slot_until_child_exits(isolated_store):
    import psutil
    s=isolated_store;r=_submit(s)
    p,lines=_claim_in_process(s,r['id'],child=True,hold=True)
    child=lines[0]['child']
    p.kill();p.wait(timeout=10)            # owner dies, training child survives (orphan)
    try:
        assert s.reconcile_training_slot()=='CHILD_ALIVE' and _slot(s)['run']==r['id']
    finally:
        psutil.Process(child).kill();psutil.Process(child).wait(timeout=10)
    assert s.reconcile_training_slot()=='RELEASED'


def test_crash_between_spawn_intent_and_registration_is_retained(isolated_store):
    s=isolated_store;r=_submit(s)
    p,_=_claim_in_process(s,r['id'],launching=True,hold=True)
    p.kill();p.wait(timeout=10)
    assert s.reconcile_training_slot()=='CHILD_EXIT_UNCONFIRMED' and _slot(s)['run']==r['id']
    with s.connect() as c:c.execute('UPDATE fw_slot SET owner_created=NULL WHERE id=1')
    assert s.reconcile_training_slot()=='OWNER_IDENTITY_UNKNOWN'
