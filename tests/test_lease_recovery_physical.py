"""Real isolated PostgreSQL and owned tiny CLI processes. Never training or live DB writes.
Only the canonical timing test uses a natural 45s lease; other clocks are scaffolding.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import psutil
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row
import pytest

from fieldwork.lease_recovery import PostgresBackend, scan_once
from fieldwork.store import Conflict, ROOT


@pytest.fixture(autouse=True)
def evidence_folder(tmp_path_factory, monkeypatch):
    # record() needs FWR_EVIDENCE; tools/r5_resume_suite.py sets it for the
    # formal evidence run. For ordinary pytest runs, use a private scratch
    # folder so the tests do not depend on (or write into) the operator's env.
    if not os.environ.get('FWR_EVIDENCE'):
        folder = tmp_path_factory.mktemp('fwr-evidence')
        monkeypatch.setenv('FWR_EVIDENCE', str(folder))


def record(name, value):
    folder = Path(os.environ['FWR_EVIDENCE'])
    with (folder / (name + '.json')).open('x') as f:
        json.dump(value, f, indent=2, default=str)


def backend(s):
    return PostgresBackend(s.connect, ['lease-proof'])


def claim(s):
    r = s.submit('lease-proof', 'fixture', uuid.uuid4().hex, {'epochs': 1})
    return s.claim(r['id'])


def accelerated(s, rid):
    with s.connect() as c:
        c.execute("UPDATE fw_runs SET lease=clock_timestamp()-interval '1 second' WHERE id=%s", (rid,))


def protected(s):
    with s.connect() as c:
        return {table:c.execute(sql.SQL('SELECT * FROM {} ORDER BY 1').format(sql.Identifier(table))).fetchall()
                for table in ['fw_slot', 'fw_attempts', 'fw_checkpoints']}


def authority(tmp_path, dsn):
    p = tmp_path / (uuid.uuid4().hex + '.json')
    p.write_text(json.dumps({'purpose':'fieldwork-training-lease-controller',
        'authority_mode':'trusted-operator-not-least-privilege',
        'dsn':dsn, 'workspaces':['lease-proof']}))
    return p


def launch(s, tmp_path, *, once=False, dsn=None):
    path = authority(tmp_path, dsn or s.dsn)
    log = tmp_path / (uuid.uuid4().hex + '.log')
    output = log.open('w')
    args = [sys.executable, '-m', 'fieldwork.lease_recovery', '--authority-file', str(path), '--interval', '.1']
    if once:args.append('--once')
    p = subprocess.Popen(args, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    return p, path, log, output


def cleanup(handle):
    p, path, log, output = handle
    if p.poll() is None:p.kill()
    p.wait(timeout=10)
    output.close()
    path.unlink(missing_ok=True)
    assert not psutil.pid_exists(p.pid)


def test_canonical_45_second_lease_independent_loop_while_execution_blocked(isolated_store, tmp_path):
    s = isolated_store
    ready = tmp_path / 'worker-blocked.json'
    # Training entrypoint never entered: an actual independent owner parks before it.
    program = '''import json,sys,time
from pathlib import Path
from fieldwork.store import Store
s=Store(dsn=sys.argv[1]);r=s.submit('lease-proof','fixture','canonical',{'epochs':1});a=s.claim(r['id'])
Path(sys.argv[2]).write_text(json.dumps({'id':a['id'],'fence':a['fence'],'torch_imported':'torch' in sys.modules}))
while True:time.sleep(.1)
'''
    owner = subprocess.Popen([sys.executable, '-c', program, s.dsn, str(ready)], cwd=ROOT)
    scanner = None
    try:
        limit = time.monotonic()+10
        while not ready.exists() and owner.poll() is None and time.monotonic()<limit:time.sleep(.02)
        assert ready.exists()
        a = json.loads(ready.read_text());assert not a['torch_imported']
        row = s.get(a['id']);before = protected(s)
        with s.connect() as c:
            seconds = c.execute('SELECT extract(epoch FROM lease-clock_timestamp()) n FROM fw_runs WHERE id=%s', (a['id'],)).fetchone()['n']
        assert 40 < seconds <= 45
        scanner = launch(s, tmp_path)
        limit = time.monotonic()+56
        while time.monotonic()<limit:
            observed = s.get(a['id'])
            if observed['state']=='interrupted':break
            assert scanner[0].poll() is None
            time.sleep(.05)
        assert observed['state']=='interrupted'
        with s.connect() as c:
            lag = float(c.execute("SELECT extract(epoch FROM clock_timestamp()-lease) n FROM fw_runs WHERE id=%s", (a['id'],)).fetchone()['n'])
            events = c.execute("SELECT * FROM fw_events WHERE run=%s AND kind='expired'", (a['id'],)).fetchall()
        assert 0 <= lag <= 10
        assert len(events)==1 and owner.poll() is None
        assert protected(s)==before
        assert observed['fence']==row['fence']+1 and observed['revision']==row['revision']+1
        assert events[0]['payload']['physical_slot']=='RETAINED_NOT_RECONCILED'
        record('canonical-45s', {'lease_seconds_initial':seconds,'observed_mark_lag_seconds':lag,
            'lease_deadline':row['lease'],'owner_still_blocked':True,'torch_imported':False,
            'slot_attempts_checkpoints_unchanged':True,'events':events})
    finally:
        if scanner:
            cleanup(scanner)
            record('canonical-cli-loop', {'stdout':scanner[2].read_text(),'exit_after_owned_kill':scanner[0].returncode})
        if owner.poll() is None:owner.kill()
        owner.wait(timeout=10)
        assert not psutil.pid_exists(owner.pid)


def test_two_independent_once_controllers_one_event_cancel_requested(isolated_store, tmp_path):
    s=isolated_store;a=claim(s);s.cancel('lease-proof',a['id']);accelerated(s,a['id'])
    before=protected(s);handles=[]
    try:
        handles=[launch(s,tmp_path,once=True) for _ in range(2)]
        codes=[h[0].wait(timeout=10) for h in handles]
        assert codes==[0,0]
    finally:
        for h in handles:cleanup(h)
    r=s.get(a['id']);assert r['state']=='cancelled' and protected(s)==before
    with s.connect() as c:
        events=c.execute("SELECT * FROM fw_events WHERE run=%s AND kind='expired'",(a['id'],)).fetchall()
    assert len(events)==1
    record('two-cli-once', {'accelerated_clock_scaffolding':True,'codes':codes,'events':events,
                            'outputs':[h[2].read_text() for h in handles]})


@pytest.mark.parametrize('winner',['renewal','revision','fence','terminal'])
def test_physical_row_lock_and_snapshot_winner(isolated_store,winner):
    s=isolated_store;a=claim(s);accelerated(s,a['id']);b=backend(s)
    candidate=b.candidates('',16)[0]
    with s.connect() as holder:
        pid=holder.execute('SELECT pg_backend_pid() pid').fetchone()['pid']
        holder.execute('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE',(a['id'],))
        # Observe the real physical run lock through an actual blocked contender.
        dsn=make_conninfo(s.dsn,application_name='lc01_lock_'+winner)
        def contender():
            with psycopg.connect(dsn) as c:
                c.execute('SELECT id FROM fw_runs WHERE id=%s FOR UPDATE',(a['id'],))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(contender)
            deadline=time.monotonic()+5;waiting=None
            while time.monotonic()<deadline:
                with s.connect() as observer:
                    waiting=observer.execute("SELECT pid,pg_blocking_pids(pid) blockers,wait_event_type FROM pg_stat_activity WHERE application_name=%s AND wait_event_type='Lock'",('lc01_lock_'+winner,)).fetchone()
                if waiting:break
                time.sleep(.01)
            assert waiting and pid in waiting['blockers']
            started=time.monotonic();assert b.expire(candidate) is None
            skip_elapsed=time.monotonic()-started
            assert skip_elapsed<1
            if winner=='renewal':holder.execute("UPDATE fw_runs SET lease=clock_timestamp()+interval '45 seconds' WHERE id=%s",(a['id'],))
            elif winner=='revision':holder.execute('UPDATE fw_runs SET revision=revision+1 WHERE id=%s',(a['id'],))
            elif winner=='fence':holder.execute('UPDATE fw_runs SET fence=fence+1 WHERE id=%s',(a['id'],))
            else:holder.execute("UPDATE fw_runs SET state='succeeded',revision=revision+1 WHERE id=%s",(a['id'],))
            holder.commit()
            future.result(timeout=5)
    assert b.expire(candidate) is None
    with s.connect() as c:
        count=c.execute("SELECT count(*) n FROM fw_events WHERE run=%s AND kind='expired'",(a['id'],)).fetchone()['n']
    assert count==0
    record('row-lock-'+winner, {'accelerated_clock_scaffolding':True,'holder_pid':pid,
        'blocked_contender':waiting,'skip_locked_elapsed_seconds':skip_elapsed,
        'winner':winner,'stale_candidate_rejected':True,'winner_mutation':'explicit SQL scheduling scaffold, not Store publish/complete'})


def test_expiry_winner_denies_old_heartbeat_complete_and_retains_slot(isolated_store):
    s=isolated_store;a=claim(s);accelerated(s,a['id']);before=protected(s)
    assert backend(s).expire(backend(s).candidates('',16)[0])['state']=='interrupted'
    with pytest.raises(Conflict,match='FENCED'):s.heartbeat(a['id'],a['fence'],a['cancel_generation'],attempt=a['attempt'])
    with pytest.raises(Conflict,match='FENCED'):s.complete(a['id'],a['fence'],a['cancel_generation'],{},attempt=a['attempt'])
    assert protected(s)==before
    record('expiry-winner',{'accelerated_clock_scaffolding':True,'heartbeat_denied':True,
        'complete_denied':True,'publish':'UNRUN: imports torch and requires genuine checkpoint',
        'slot_attempts_checkpoints_unchanged':True})


@pytest.mark.parametrize('child_state',['live','unknown','launching','dead'])
def test_all_physical_slot_states_retained_without_retry(isolated_store,child_state):
    s=isolated_store;a=claim(s)
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])
    try:
        birth=psutil.Process(child.pid).create_time()
        if child_state=='dead':child.kill();child.wait(timeout=10)
        with s.connect() as c:
            c.execute('UPDATE fw_slot SET pid=%s,child_created=%s,launching=%s WHERE id=1',
                      (child.pid,None if child_state=='unknown' else birth,child_state=='launching'))
        accelerated(s,a['id']);before=protected(s)
        result=backend(s).expire(backend(s).candidates('',16)[0])
        assert result['physical_slot']=='RETAINED_NOT_RECONCILED' and result['automatic_retry'] is False
        assert protected(s)==before
        record('physical-retained-'+child_state,{'accelerated_clock_scaffolding':True,'child_state':child_state,
            'slot_attempts_checkpoints_unchanged':True,'result':result})
    finally:
        if child.poll() is None:child.kill()
        child.wait(timeout=10)
        assert not psutil.pid_exists(child.pid)


@pytest.mark.parametrize('operation',['heartbeat','publish','complete','cancel'])
def test_canonical_store_winner_under_actual_blocked_row_lock(isolated_store,tmp_path,operation):
    from fieldwork.store import Store
    s=isolated_store
    source=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'
    metadata=json.loads((source/'state.json').read_text())
    r=s.submit('lease-proof','fixture',uuid.uuid4().hex,
               {'epochs':metadata['epoch'],'dataset_digest':metadata['dataset_digest']})
    a=s.claim(r['id']);accelerated(s,a['id']);b=backend(s)
    candidate=b.candidates('',16)[0]
    worker=Store(dsn=make_conninfo(s.dsn,application_name='lc01-canonical-'+operation))
    worker.blob_root=tmp_path/'private-checkpoints'
    def work():
        if operation=='heartbeat':return worker.heartbeat(a['id'],a['fence'],a['cancel_generation'],attempt=a['attempt'])
        if operation=='publish':return worker.publish(a['id'],a['fence'],a['cancel_generation'],source,
                        {k:metadata[k] for k in ['epoch','train_loss','validation_loss','updates']},attempt=a['attempt'])
        if operation=='complete':return worker.complete(a['id'],a['fence'],a['cancel_generation'],{'best':{'epoch':metadata['epoch']}},attempt=a['attempt'])
        return worker.cancel('lease-proof',a['id'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        with s.connect() as holder:
            holder.execute('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE',(a['id'],))
            holder_pid=holder.execute('SELECT pg_backend_pid() pid').fetchone()['pid']
            holder.execute("UPDATE fw_runs SET lease=clock_timestamp()+interval '45 seconds' WHERE id=%s",(a['id'],))
            if operation=='complete':holder.execute('UPDATE fw_runs SET epoch=%s WHERE id=%s',(metadata['epoch'],a['id']))
            future=pool.submit(work)
            limit=time.monotonic()+15;waiting=None
            while time.monotonic()<limit:
                with s.connect() as observer:
                    waiting=observer.execute("SELECT pid,pg_blocking_pids(pid) blockers,wait_event_type FROM pg_stat_activity WHERE application_name=%s AND wait_event_type='Lock'",('lc01-canonical-'+operation,)).fetchone()
                if waiting:break
                if future.done():future.result()
                time.sleep(.02)
            assert waiting and holder_pid in waiting['blockers']
            assert b.expire(candidate) is None
        future.result(timeout=15)
    assert b.expire(candidate) is None
    current=s.get(a['id'])
    if operation=='publish':assert current['revision']==candidate['revision']+1 and s.checkpoints(a['id'])
    if operation=='complete':assert current['state']=='succeeded'
    if operation=='cancel':assert current['state']=='cancel_requested' and current['fence']==candidate['fence']+1
    if operation=='heartbeat':assert current['revision']==candidate['revision']
    record('canonical-store-winner-'+operation,{'accelerated_clock_scaffolding':True,
        'blocked_worker':waiting,'holder_pid':holder_pid,'actual_Store_method':operation,
        'candidate':candidate,'readback':{k:current[k] for k in ['state','fence','revision','lease']}})


def test_actual_publish_denied_after_controller_expiry(isolated_store,tmp_path):
    s=isolated_store;a=claim(s);accelerated(s,a['id'])
    b=backend(s);assert b.expire(b.candidates('',16)[0])
    source=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'
    metadata=json.loads((source/'state.json').read_text());s.blob_root=tmp_path/'private-checkpoints'
    before=protected(s)
    with pytest.raises(Conflict,match='FENCED'):
        s.publish(a['id'],a['fence'],a['cancel_generation'],source,
                  {k:metadata[k] for k in ['epoch','train_loss','validation_loss','updates']},attempt=a['attempt'])
    assert protected(s)==before
    record('actual-publish-denied',{'actual_Store_publish':True,'real_retained_checkpoint':True,
        'promotion_destination':'private test directory','denied_by':'FENCED_OR_EXPIRED_OR_CANCELLED',
        'database_checkpoints_attempts_slot_unchanged':True,'training_executed':False})


def test_event_failure_rolls_back_and_poison_locked_keyset_wrap_progress(isolated_store):
    s=isolated_store
    # Actual schema rows, no mock SQL. Lexical IDs make bounded progress deterministic.
    with s.connect() as c:
        for rid in ['a-poison','b-locked','c-good','d-good','e-good']:
            c.execute("INSERT INTO fw_runs(id,workspace,actor,idem,digest,config,state,fence,revision,lease) VALUES(%s,'lease-proof','fixture',%s,'fixture','{}','running',1,1,clock_timestamp()-interval '1 second')",(rid,rid))
        c.execute("UPDATE fw_runs SET revision=2147483647 WHERE id='a-poison'")
        c.execute("""CREATE FUNCTION reject_expired_event() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.kind='expired' AND NEW.run='c-good' THEN RAISE EXCEPTION 'fixture event failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_expired_event BEFORE INSERT ON fw_events FOR EACH ROW EXECUTE FUNCTION reject_expired_event();""")
    b=backend(s);before=s.get('c-good')
    candidate=next(r for r in b.candidates('',16) if r['id']=='c-good')
    with pytest.raises(psycopg.errors.RaiseException):b.expire(candidate)
    assert s.get('c-good')==before
    receipts=[]
    with s.connect() as locked:
        locked.execute("SELECT * FROM fw_runs WHERE id='b-locked' FOR UPDATE")
        # Real discovery with deterministic Python scheduling delay (LC-01 scaffold).
        class SlowDiscovery:
            def candidates(self,cursor,batch_size):
                rows=b.candidates(cursor,batch_size);time.sleep(.02);return rows
            def expire(self,candidate):return b.expire(candidate)
        cursor=''
        for _ in range(6):
            receipt=scan_once(SlowDiscovery(),cursor,batch_size=2,budget_seconds=.01)
            receipts.append(receipt);cursor=receipt['cursor']
        assert s.get('d-good')['state']=='interrupted' and s.get('e-good')['state']=='interrupted'
        assert s.get('b-locked')['state']=='running'
    with s.connect() as c:c.execute('DROP TRIGGER reject_expired_event ON fw_events')
    for _ in range(6):
        receipt=scan_once(b,cursor,batch_size=2);receipts.append(receipt);cursor=receipt['cursor']
    assert s.get('b-locked')['state']=='interrupted' and s.get('c-good')['state']=='interrupted'
    assert s.get('a-poison')['revision']==2147483647 and s.get('a-poison')['state']=='running'
    assert any(r['cursor']=='' for r in receipts)
    with s.connect() as c:
        events=c.execute("SELECT run,count(*) n FROM fw_events WHERE kind='expired' GROUP BY run ORDER BY run").fetchall()
    assert len(events)==4 and all(e['n']==1 for e in events)
    record('rollback-backlog-lc01',{'accelerated_clock_scaffolding':True,'discovery_delay_scaffolding_seconds':.02,
        'budget_seconds':.01,'receipts':receipts,'events':events,'event_failure_rolled_back_exact_row':True})


def test_explicit_authority_actual_api_denied_and_fixture_schema_introspected(isolated_store,tmp_path):
    s=isolated_store
    private=json.loads((ROOT/'.local-api.json').read_text())
    api_params=conninfo_to_dict(private['dsn']);role=api_params['user']
    dbname=conninfo_to_dict(s.dsn)['dbname'];assert dbname.startswith('fieldwork_test_')
    api_params['dbname']=dbname;api_dsn=make_conninfo(**api_params)
    # Existing actual role only. Grants/RLS are confined to this disposable database.
    with s.connect() as c:
        flags=c.execute('SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=%s',(role,)).fetchone()
        assert flags and not any(flags.values())
        c.execute('CREATE UNIQUE INDEX fw_runs_tenant_id ON fw_runs(workspace,id)')
        c.execute('ALTER TABLE fw_events ADD CONSTRAINT fw_events_tenant_run FOREIGN KEY(workspace,run) REFERENCES fw_runs(workspace,id)')
        c.execute(sql.SQL('GRANT USAGE ON SCHEMA public TO {}').format(sql.Identifier(role)))
        for table in ['fw_runs','fw_events']:
            c.execute(sql.SQL('ALTER TABLE {} ENABLE ROW LEVEL SECURITY').format(sql.Identifier(table)))
            c.execute(sql.SQL('ALTER TABLE {} FORCE ROW LEVEL SECURITY').format(sql.Identifier(table)))
            c.execute(sql.SQL("CREATE POLICY fw_tenant ON {} USING (workspace=current_setting('fieldwork.workspace',true)) WITH CHECK (workspace=current_setting('fieldwork.workspace',true))").format(sql.Identifier(table)))
            c.execute(sql.SQL('GRANT SELECT,INSERT,UPDATE ON {} TO {}').format(sql.Identifier(table),sql.Identifier(role)))
        info=c.execute("SELECT current_database() db,current_user principal,current_schema() schema,current_setting('search_path') search_path").fetchone()
        rls=c.execute("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname IN ('fw_runs','fw_events') ORDER BY relname").fetchall()
        columns=c.execute("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('fw_runs','fw_events','fw_slot') ORDER BY table_name,ordinal_position").fetchall()
        policies=c.execute("SELECT tablename,policyname,qual,with_check FROM pg_policies WHERE schemaname='public'").fetchall()
        grants=c.execute("SELECT has_table_privilege(%s,'fw_slot','SELECT') slot_select",(role,)).fetchone()
    assert not grants['slot_select'] and all(r['relrowsecurity'] and r['relforcerowsecurity'] for r in rls)
    a=claim(s);accelerated(s,a['id'])
    with psycopg.connect(api_dsn,row_factory=dict_row) as c:
        assert c.execute('SELECT count(*) n FROM fw_runs').fetchone()['n']==0
        c.execute("SELECT set_config('fieldwork.workspace','lease-proof',true)")
        assert c.execute('SELECT count(*) n FROM fw_runs').fetchone()['n']==1
    handle=launch(s,tmp_path,once=True,dsn=api_dsn)
    try:assert handle[0].wait(timeout=10)==2
    finally:cleanup(handle)
    assert s.get(a['id'])['state']=='running'
    good=launch(s,tmp_path,once=True)
    try:assert good[0].wait(timeout=10)==0
    finally:cleanup(good)
    assert s.get(a['id'])['state']=='interrupted'
    record('authority-schema',{'actual_api_principal_used':True,'role_flags':flags,'api_slot_grant':grants,
        'operator':info,'columns':columns,'rls':rls,'policies':policies,'api_output':handle[2].read_text(),
        'operator_output':good[2].read_text(),'qualification':'existing API login, isolated DB subset grants/RLS; no role provisioning or least-privilege certification; trusted default public search_path introspected, not hardened'})
