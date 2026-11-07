"""Focused fail-closed regressions for the reviewed Round-5 launch helpers."""
from datetime import datetime,timezone
import hashlib
import json
import subprocess
import sys
import time
import os
import psutil
import pytest

from tools import retained_kill_replay as replay
from tools import r5_restart_platform as restart


def test_restart_lock_requires_owner_purpose_liveness_and_birth_parent():
    owner={'pid':71,'create_time':100.0,'product':'fieldwork','purpose':'r5 platform-restart'}
    chain=[{'pid':201,'create_time':103.0},{'pid':71,'create_time':100.004}]
    assert restart.restart_lock_matches(owner,(False,'OWNER_ALIVE'),chain)
    assert not restart.restart_lock_matches(owner,(False,'OWNER_ALIVE'),[{'pid':71,'create_time':101.0}])
    assert not restart.restart_lock_matches(owner,(True,'OWNER_PID_ABSENT'),chain)
    assert not restart.restart_lock_matches(owner,(False,'OWNER_UNINSPECTABLE'),chain)
    assert not restart.restart_lock_matches({**owner,'product':'folio'},(False,'OWNER_ALIVE'),chain)
    assert not restart.restart_lock_matches({**owner,'purpose':'model-run'},(False,'OWNER_ALIVE'),chain)
    assert not restart.restart_lock_matches(owner,(False,'OWNER_ALIVE'),[{'pid':202,'create_time':100.0}])


def test_restart_lock_rejects_missing_owner_metadata_and_live_unrelated_holder():
    owner={'pid':71,'create_time':100.0,'product':'fieldwork','purpose':'platform-restart'}
    chain=[{'pid':71,'create_time':100.0}]
    assert not restart.restart_lock_matches({'pid':71,'product':'fieldwork','purpose':'platform-restart'},
        (False,'OWNER_ALIVE'),chain)
    assert not restart.restart_lock_matches({k:v for k,v in owner.items() if k!='purpose'},
        (False,'OWNER_ALIVE'),chain)
    assert not restart.restart_lock_matches(owner,(False,'OWNER_ALIVE'),[{'pid':71}])
    assert not restart.restart_lock_matches({**owner,'purpose':'fieldwork dataset training'},
        (False,'OWNER_ALIVE'),chain)


def test_windows_launcher_lineage_requires_exact_popen_pid_and_birth():
    launch={'pid':10,'create_time':10.0}
    actual_chain=[{'pid':30,'create_time':30.0},{'pid':20,'create_time':20.0},launch]
    assert restart.ancestry_contains(actual_chain,launch['pid'],launch['create_time'])
    assert not restart.ancestry_contains(actual_chain,launch['pid'],11.0)
    assert not restart.ancestry_contains(actual_chain,11,10.0)


def test_legacy_runtime_record_is_audited_only_after_positive_pid_absence(monkeypatch):
    def absent(pid):raise psutil.NoSuchProcess(pid)
    monkeypatch.setattr(restart.psutil,'Process',absent)
    record={'pid':7182,'started':'legacy','command':'old supervisor format'}
    audit=restart._recorded_process_is_expected('worker',record)
    assert audit['schema']=='fieldwork.runtime-legacy-absence-audit.v1'
    assert audit['kind']=='worker' and audit['pid']==7182
    assert audit['absence_proof']=='psutil.NoSuchProcess'
    assert audit['pid_absence_observed_utc'] and len(audit['legacy_record_sha256'])==64


def test_legacy_runtime_record_with_live_pid_is_refused(monkeypatch):
    monkeypatch.setattr(restart.psutil,'Process',lambda pid:object())
    with pytest.raises(RuntimeError,match='RECORDED_PLATFORM_PROCESS_IDENTITY_INCOMPLETE_LIVE:worker'):
        restart._recorded_process_is_expected('worker',{'pid':7182,'started':'legacy'})


def test_legacy_runtime_record_with_uninspectable_pid_is_refused(monkeypatch):
    def denied(pid):raise psutil.AccessDenied(pid=pid)
    monkeypatch.setattr(restart.psutil,'Process',denied)
    with pytest.raises(RuntimeError,match='RECORDED_PLATFORM_PROCESS_UNINSPECTABLE:worker'):
        restart._recorded_process_is_expected('worker',{'pid':7182,'started':'legacy'})


def test_live_python_launcher_tree_is_bound_and_cleaned_by_exact_birth():
    marker='FW_LINEAGE_SCOPE_'+str(time.time_ns())
    code='import time; time.sleep(15)  # '+marker
    process=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    launch=None
    actual=None
    try:
        parent=psutil.Process()
        launch=restart._launch_identity(process,'lineage-test-launcher',parent.pid,parent.create_time())
        for _ in range(40):
            root=restart._same_process(launch['pid'],launch['create_time'])
            if root is None:break
            try:candidates=[root,*root.children(recursive=True)]
            except psutil.Error:candidates=[]
            matches=[]
            for candidate in candidates:
                try:
                    if marker in ' '.join(candidate.cmdline()) and restart.ancestry_contains(
                            restart._process_ancestry(candidate.pid),launch['pid'],launch['create_time']):
                        matches.append(candidate)
                except psutil.Error:pass
            if matches:
                candidate=matches[0]
                actual={'pid':candidate.pid,'create_time':candidate.create_time()}
                break
            time.sleep(.05)
        assert actual is not None,'no marked interpreter remained in the exact Popen lineage'
        assert restart.ancestry_contains(restart._process_ancestry(actual['pid']),launch['pid'],launch['create_time'])
        actual_record={**actual,'role':'lineage-test-process','launch_pid':launch['pid'],
                       'launch_create_time':launch['create_time']}
        actual_handle=psutil.Process(actual['pid'])
        outcomes=restart._cleanup_launched_processes([launch,actual_record],
            {(launch['pid'],launch['create_time']):process},
            {(actual['pid'],actual['create_time']):actual_handle})
        assert outcomes['lineage-test-launcher']['stopped']
        assert outcomes['lineage-test-process']['stopped']
        assert any(item['pid']==actual['pid'] and item['exit_proven']
                   for item in outcomes['lineage-test-launcher']['descendants'])
        assert process.returncode is not None,'Popen wait did not prove launcher root exit'
        assert outcomes['lineage-test-process']['root_exit_proven']
    finally:
        if launch is not None:
            actual_records=[]
            handles={}
            if actual is not None:
                actual_records=[{**actual,'role':'lineage-test-process','launch_pid':launch['pid'],
                                'launch_create_time':launch['create_time']}]
                try:handles[(actual['pid'],actual['create_time'])]=psutil.Process(actual['pid'])
                except psutil.Error:pass
            restart._cleanup_launched_processes([launch,*actual_records],
                {(launch['pid'],launch['create_time']):process},handles)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def test_named_module_leaf_is_selected_inside_venv_launcher_lineage(tmp_path):
    module='fw_scope_fixture_'+str(time.time_ns())
    (tmp_path/(module+'.py')).write_text('import time\ntime.sleep(15)\n',encoding='utf-8')
    env={k:v for k,v in os.environ.items() if k in ('SYSTEMROOT','PATH','TEMP','TMP','USERPROFILE')}
    env.update(PYTHONPATH=str(tmp_path),PYTHONDONTWRITEBYTECODE='1')
    process=subprocess.Popen([sys.executable,'-B','-m',module],cwd=restart.ROOT,env=env,
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    parent=psutil.Process()
    launch=None
    actual=None
    try:
        launch=restart._launch_identity(process,'named-module-launcher',parent.pid,parent.create_time())
        for _ in range(80):
            actual=restart._find_module_process(launch,module)
            if actual is not None:break
            if restart._same_process(launch['pid'],launch['create_time']) is None:break
            time.sleep(.05)
        assert actual is not None,'module process was not uniquely resolved to a leaf in its Popen lineage'
        assert actual['launch_pid']==launch['pid'] and actual['launch_create_time']==launch['create_time']
        assert restart._module_process_live(actual,launch,module)
        proof={'scope':'temporary named module only; no Fieldwork worker/issuer, retained DB, or queue',
               'launch':{k:launch[k] for k in ('pid','create_time','parent_pid','parent_create_time','caller_ancestry_verified')},
               'actual_module':{k:actual[k] for k in ('pid','create_time','parent_pid','parent_create_time','launch_pid','launch_create_time')},
               'ancestry':restart._process_ancestry(actual['pid']),
               'unique_leaf_resolved':True}
        (tmp_path/'named-module-lineage-proof.json').write_text(json.dumps(proof,indent=2),encoding='utf-8')
        actual_record={**actual,'role':'named-module-process'}
        actual_handle=psutil.Process(actual['pid'])
        outcomes=restart._cleanup_launched_processes([launch,actual_record],
            {(launch['pid'],launch['create_time']):process},
            {(actual['pid'],actual['create_time']):actual_handle})
        assert outcomes['named-module-launcher']['stopped']
        assert outcomes['named-module-process']['stopped']
    finally:
        if actual is not None and launch is not None:
            actual_record={**actual,'role':'named-module-process'}
            try:actual_handle=psutil.Process(actual['pid'])
            except psutil.Error:actual_handle=None
            restart._cleanup_launched_processes([launch,actual_record],
                {(launch['pid'],launch['create_time']):process},
                {(actual['pid'],actual['create_time']):actual_handle})
        elif launch is not None:
            restart._cleanup_launched_processes([launch],
                {(launch['pid'],launch['create_time']):process},{})
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def test_cleanup_driver_stops_recorded_module_after_launcher_exit(tmp_path):
    pid_file=tmp_path/'child-pid.txt'
    child_code='import time; time.sleep(30)'
    parent_code=('import subprocess,sys,time; child=subprocess.Popen([sys.executable,"-c",'+
                 repr(child_code)+']); open('+repr(str(pid_file))+',"w").write(str(child.pid)); time.sleep(1)')
    process=subprocess.Popen([sys.executable,'-c',parent_code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    parent=psutil.Process()
    launch=None
    actual_handle=None
    actual=None
    try:
        launch=restart._launch_identity(process,'partial-start-launcher',parent.pid,parent.create_time())
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not pid_file.exists():time.sleep(.02)
        assert pid_file.exists(),'partial startup fixture did not publish child identity'
        child_pid=int(pid_file.read_text(encoding='utf-8'))
        actual_handle=psutil.Process(child_pid)
        actual={'pid':child_pid,'create_time':actual_handle.create_time(),
                'role':'partial-start-process','launch_pid':launch['pid'],
                'launch_create_time':launch['create_time']}
        process.wait(timeout=15)
        assert process.returncode is not None,'launcher exit was not observed before cleanup'
        outcomes=restart._cleanup_launched_processes([launch,actual],
            {(launch['pid'],launch['create_time']):process},
            {(actual['pid'],actual['create_time']):actual_handle})
        assert outcomes['partial-start-launcher']['stopped']
        assert outcomes['partial-start-process']['stopped']
        assert outcomes['partial-start-process']['root_exit_proven']
        assert any(item['pid']==actual['pid'] and item['exit_proven']
                   for item in outcomes['partial-start-launcher']['descendants'])
    finally:
        if launch is not None:
            records=[launch] if actual is None else [launch,actual]
            handles={} if actual_handle is None or actual is None else {(actual['pid'],actual['create_time']):actual_handle}
            restart._cleanup_launched_processes(records,
                {(launch['pid'],launch['create_time']):process},handles)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def test_pause_heartbeat_is_bound_to_fresh_worker_pid_birth_parent_id_and_nonce():
    now=1_798_000_000.0
    beat={'pid':20,'create_time':100.004,'parent_pid':10,'parent_create_time':99.999,
          'worker_id':'fieldwork-retained-r5','pause_nonce_sha256':'nonce-digest',
          'identity':'scoped-worker-v1','operator_paused':True,
          'as_of':datetime.fromtimestamp(now-2,timezone.utc).isoformat()}
    expected=dict(pid=20,create_time=100.0,parent_pid=10,parent_create_time=100.0,
                  worker_id='fieldwork-retained-r5',nonce_sha256='nonce-digest',now=now,max_age=10)
    assert restart.worker_heartbeat_matches(beat,**expected)
    for key,value in [('pid',21),('create_time',101.0),('parent_pid',11),
                      ('parent_create_time',101.0),('worker_id','other'),
                      ('pause_nonce_sha256','old-nonce'),('identity','trusted-operator'),
                      ('operator_paused',False),('as_of',datetime.fromtimestamp(now-20,timezone.utc).isoformat())]:
        assert not restart.worker_heartbeat_matches({**beat,key:value},**expected),key
    assert not restart.worker_heartbeat_matches({},**expected)


def test_issuer_must_rotate_private_password_after_launcher_rotation():
    previous=hashlib.sha256(b'old').hexdigest()
    assert restart.issuer_rotation_matches({'connection':{'password':'new'},'rotated_utc':'later'},
        previous_password_sha256=previous,previous_rotated_utc='before')
    assert not restart.issuer_rotation_matches({'connection':{'password':'old'},'rotated_utc':'later'},
        previous_password_sha256=previous,previous_rotated_utc='before')
    assert not restart.issuer_rotation_matches({'connection':{'password':'new'},'rotated_utc':'before'},
        previous_password_sha256=previous,previous_rotated_utc='before')
    assert not restart.issuer_rotation_matches({},previous_password_sha256=previous,previous_rotated_utc='before')


def test_stale_attempt_probe_requires_both_expected_refusal_codes():
    good={'refused':True,'code':'FENCED_OR_EXPIRED_OR_CANCELLED'}
    assert replay.stale_refusals_proven({'heartbeat':good,'complete':good})
    assert not replay.stale_refusals_proven({'heartbeat':good})
    assert not replay.stale_refusals_proven({'heartbeat':good,'complete':None})
    assert not replay.stale_refusals_proven({'heartbeat':{'refused':True},'complete':good})
    assert not replay.stale_refusals_proven({'heartbeat':{**good,'code':'OTHER'},'complete':good})
    assert not replay.stale_refusals_proven({'heartbeat':{'refused':False,'code':'NO_REFUSAL'},'complete':good})


def test_inference_comparison_rejects_identity_or_length_mismatch_without_zip_truncation():
    left={'input_digest':'i'*64,'model_digest':'m'*64,'classes':['a','b'],
          'logits':[1.0,2.0],'top1':1}
    right={**left,'logits':[1.0,2.0]}
    good=replay.compare_inference_receipts(left,right)
    assert good=={'identity_equal':True,'length_equal':True,'finite':True,'max_abs':0.0,'top1_equal':True}
    short=replay.compare_inference_receipts(left,{**right,'logits':[1.0]})
    assert short['length_equal'] is False and short['max_abs'] is None
    assert replay.compare_inference_receipts(left,{**right,'input_digest':'x'})['identity_equal'] is False
    assert replay.compare_inference_receipts(left,{**right,'model_digest':'x'})['identity_equal'] is False
    assert replay.compare_inference_receipts(left,{**right,'classes':['a']})['identity_equal'] is False
    assert replay.compare_inference_receipts(left,{**right,'logits':[float('nan'),2.0]})['finite'] is False
    assert replay.compare_inference_receipts(left,{k:v for k,v in right.items() if k!='top1'})['top1_equal'] is False


def test_checkpoint_comparison_requires_exact_keys_shapes_and_dtypes():
    good={'model.weight':{'shape':[2,3],'dtype':'torch.float32'},
          'optimizer.exp_avg':{'shape':[2,3],'dtype':'torch.float32'}}
    assert replay.checkpoint_metadata_matches(good,dict(good))
    assert not replay.checkpoint_metadata_matches(good,{'model.weight':good['model.weight']})
    assert not replay.checkpoint_metadata_matches(good,{**good,'optimizer.exp_avg':{'shape':[3,2],'dtype':'torch.float32'}})
    assert not replay.checkpoint_metadata_matches(good,{**good,'optimizer.exp_avg':{'shape':[2,3],'dtype':'torch.float64'}})
    assert not replay.checkpoint_metadata_matches({}, {})
    assert not replay.checkpoint_metadata_matches({'bad':None},{'bad':None})


def test_replay_queue_scope_preserves_preexisting_21_and_two_new_run_ids():
    before=[{'id':f'old-{i:02d}','state':'queued','fence':7,'revision':11} for i in range(21)]
    owned={'new-resume','new-control'}
    good=replay.queue_scope(before,list(before),owned)
    assert good['before']['count']==21 and good['preexisting_after']==good['before']
    assert good['preexisting_ids_preserved'] and good['preexisting_state_digest_unchanged']
    assert good['two_owned_run_ids_are_new'] and good['owned_runs_still_queued_count']==0
    assert good['unexpected_queued_count']==0 and good['unchanged']
    changed=[dict(row) for row in before]
    changed[-1]['fence']=8
    assert not replay.queue_scope(before,changed,owned)['unchanged']
    assert not replay.queue_scope(before,before,{'old-00','new-control'})['two_owned_run_ids_are_new']


def test_replay_scanner_authority_requires_explicit_machine_schema_and_matching_endpoint(tmp_path,monkeypatch):
    for key in list(os.environ):
        if key.upper().startswith('PG'):monkeypatch.delenv(key,raising=False)
    authority={
        'purpose':'fieldwork-training-lease-controller','authority_mode':'scoped-machine-v1',
        'connection':{'host':'127.0.0.1','port':5542,'dbname':'fieldwork','user':'fw_machine','password':'fixture-only','sslmode':'disable'},
        'capability_schema':'fw_lease_cap_v1','capability_version':1,'workspaces':['scope-a']}
    path=tmp_path/'scanner-authority.json';path.write_text(json.dumps(authority),encoding='utf-8')
    operator_dsn='host=127.0.0.1 port=5542 dbname=fieldwork user=operator password=fixture-only'
    assert replay.resolve_scanner_authority(str(path),operator_dsn)==str(path)
    with pytest.raises(RuntimeError,match='SCANNER_AUTHORITY_EXPLICIT_PATH_REQUIRED'):
        replay.resolve_scanner_authority(None,operator_dsn)
    worker=tmp_path/'worker-authority.json'
    worker.write_text(json.dumps({'authority_mode':'scoped-worker-v1','connection':authority['connection']}),encoding='utf-8')
    with pytest.raises(RuntimeError,match='SCANNER_AUTHORITY_MACHINE_SCHEMA_INVALID'):
        replay.resolve_scanner_authority(str(worker),operator_dsn)
    operator=tmp_path/'operator-authority.json'
    operator.write_text(json.dumps({'purpose':'fieldwork-training-lease-controller',
        'authority_mode':'trusted-operator-not-least-privilege','dsn':operator_dsn,'workspaces':['scope-a']}),encoding='utf-8')
    with pytest.raises(RuntimeError,match='SCANNER_AUTHORITY_MACHINE_SCHEMA_INVALID'):
        replay.resolve_scanner_authority(str(operator),operator_dsn)
    with pytest.raises(RuntimeError,match='SCANNER_AUTHORITY_ENDPOINT_MISMATCH'):
        replay.resolve_scanner_authority(str(path),'host=127.0.0.1 port=5543 dbname=fieldwork user=operator')


def test_replay_cleanup_stops_known_descendant_after_launcher_exit(tmp_path,monkeypatch):
    monkeypatch.setattr(replay,'PROCESSES',[])
    monkeypatch.setattr(replay,'REPORT',{})
    monkeypatch.setattr(replay,'DESCENDANT_HANDLES',{})
    monkeypatch.setattr(replay,'CLEANUP_RESULTS',{})
    monkeypatch.setattr(replay,'CAPTURE_OBSERVATIONS',{})
    pid_file=tmp_path/'child-pid.txt'
    child_code='import time; time.sleep(30)'
    parent_code=('import subprocess,sys,time; child=subprocess.Popen([sys.executable,"-c",'+
                 repr(child_code)+']); open('+repr(str(pid_file))+',"w").write(str(child.pid)); time.sleep(3.0)')  # long enough that the first capture happens while the launcher is alive, even under load
    process,record=replay.spawn('launcher-exit-fixture',[sys.executable,'-c',parent_code],cwd=tmp_path,
                                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    child_handle=None
    try:
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not pid_file.exists():
            replay.capture_descendants(record);time.sleep(.02)
        assert pid_file.exists(),'fixture did not publish child PID'
        child_pid=int(pid_file.read_text(encoding='utf-8'))
        child_handle=psutil.Process(child_pid)
        child_create_time=child_handle.create_time()
        captured=replay.capture_descendants(record)
        assert any(item['record']['pid']==child_pid for item in captured)
        original_ancestry=restart.ancestry_contains
        monkeypatch.setattr(restart,'ancestry_contains',lambda *_args:False)
        # Simulate the OS reparenting a still-live, previously proven child as its
        # launcher exits. Its same PID birth remains owned from earlier evidence.
        replay.capture_descendants(record)
        monkeypatch.setattr(restart,'ancestry_contains',original_ancestry)
        process.wait(timeout=15)
        assert process.returncode is not None,'launcher did not exit before cleanup'
        assert replay.stop_tree(process,record)
        receipt=replay.REPORT['cleanup_receipts'][-1]
        assert receipt['root']['exit_proven']
        assert receipt['known_descendant_count']>=1
        assert any(item['pid']==child_pid and abs(item['create_time']-child_create_time)<.01 and item['exit_proven']
                   for item in receipt['descendants'])
        assert all(item['exit_proven'] for item in receipt['descendants'])
    finally:
        if process.poll() is None:
            process.kill();process.wait(timeout=10)
        if child_handle is not None:
            try:
                if child_handle.is_running():child_handle.kill()
                child_handle.wait(timeout=10)
            except psutil.Error:pass


def test_replay_cleanup_receipts_include_already_exited_root_and_return_code(monkeypatch):
    monkeypatch.setattr(replay,'PROCESSES',[])
    monkeypatch.setattr(replay,'REPORT',{})
    monkeypatch.setattr(replay,'DESCENDANT_HANDLES',{})
    monkeypatch.setattr(replay,'CLEANUP_RESULTS',{})
    monkeypatch.setattr(replay,'CAPTURE_OBSERVATIONS',{})
    process,record=replay.spawn('completed-root',[sys.executable,'-c','import time;time.sleep(0.2)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    replay.capture_descendants(record)
    process.wait(timeout=10)
    assert replay.stop_tree(process,record)
    receipt=replay.REPORT['cleanup_receipts'][-1]
    assert receipt['root']['exit_proven'] and receipt['root']['popen_returncode']==0
    assert len(receipt['descendants'])>=receipt['known_descendant_count']
    assert all(item['exit_proven'] for item in receipt['descendants'])


def test_replay_inventory_natural_exit_never_adopts_unknown_live_process(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(replay,'REPORT',{})
    monkeypatch.setattr(replay,'CAPTURE_OBSERVATIONS',{})
    monkeypatch.setattr(replay,'DESCENDANT_HANDLES',{})
    child=SimpleNamespace(pid=234,create_time=lambda:12.5,is_running=lambda:False)
    root=SimpleNamespace(children=lambda recursive:[child])
    monkeypatch.setattr(restart,'_same_process',lambda *args:root)
    monkeypatch.setattr(restart,'_process_ancestry',lambda pid:[])
    assert replay.capture_descendants({'pid':123,'create_time':10.0})==[]
    assert replay.REPORT['inventory_exits'][0]['stage']=='before_ancestry_read'
    child.is_running=lambda:True
    with pytest.raises(RuntimeError,match='OWNED_DESCENDANT_ANCESTRY_MISMATCH'):
        replay.capture_descendants({'pid':123,'create_time':10.0})
    def gone():raise psutil.NoSuchProcess(234)
    child.create_time=gone
    assert replay.capture_descendants({'pid':123,'create_time':10.0})==[]
    assert replay.REPORT['inventory_exits'][-1]['stage']=='before_birth_read'
