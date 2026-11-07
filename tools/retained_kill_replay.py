"""Retained FENCE/REPLAY proof with a PHYSICAL kill (operator tool; prints no credentials).

HTTP submit (existing account) 10 epochs -> worker CLI -> kill the worker process
tree after epoch K is committed (training child mid epoch K+1) -> slot is held by
the dead owner -> the installed scoped scanner (fw_lease_machine_v1 authority)
marks lease expiry -> stale attempt refused -> proven-exit slot reconciliation
-> HTTP resume -> fresh worker replays from checkpoint K -> artifacts/evaluation
-> compare with an uninterrupted control run of the identical config.

Usage: python -m tools.retained_kill_replay <out.json> [K] [authority-file]
"""
import hashlib,json,math,subprocess,sys,time,uuid,os
from pathlib import Path
import httpx,psutil,psycopg
from psycopg.rows import dict_row
from psycopg.conninfo import conninfo_to_dict
from tools import r5_restart_platform as platform_restart
ROOT=Path(__file__).resolve().parents[1]
PY=sys.executable
EP=10
PROCESSES=[]
REPORT={}
DESCENDANT_HANDLES={}
CLEANUP_RESULTS={}
CAPTURE_OBSERVATIONS={}
BASELINE_QUEUE_ROWS=None
OWNED_RUN_IDS=set()


def stale_refusals_proven(value):
    """Require explicit, typed stale-fence refusal receipts for both operations."""
    expected='FENCED_OR_EXPIRED_OR_CANCELLED'
    return (isinstance(value,dict) and
            all(isinstance(value.get(op),dict) and value[op].get('refused') is True and
                value[op].get('code')==expected for op in ('heartbeat','complete')))


def compare_inference_receipts(left,right):
    """Compare full one-image identity and logits without zip truncation."""
    if not isinstance(left,dict) or not isinstance(right,dict):return {'identity_equal':False,'length_equal':False,'max_abs':None,'top1_equal':False}
    identities=('input_digest','model_digest')
    identity_equal=(all(isinstance(left.get(k),str) and left.get(k)==right.get(k) for k in identities) and
                    isinstance(left.get('classes'),list) and bool(left['classes']) and
                    left.get('classes')==right.get('classes'))
    a,b=left.get('logits'),right.get('logits')
    length_equal=isinstance(a,list) and isinstance(b,list) and len(a)==len(b) and len(a)>0
    if not length_equal:return {'identity_equal':identity_equal,'length_equal':False,'max_abs':None,'top1_equal':left.get('top1')==right.get('top1')}
    numeric=all(type(x) in (int,float) and math.isfinite(x) for x in a+b)
    max_abs=max(abs(x-y) for x,y in zip(a,b,strict=True)) if numeric else None
    top1_equal=(type(left.get('top1')) is int and type(right.get('top1')) is int and
                left['top1']==right['top1'])
    return {'identity_equal':identity_equal,'length_equal':True,'finite':numeric,'max_abs':max_abs,
            'top1_equal':top1_equal}


def checkpoint_metadata_matches(a,b):
    """Cheap structural gate used before accepting numerical checkpoint comparison."""
    if not isinstance(a,dict) or not isinstance(b,dict):return False
    if set(a)!=set(b) or not a:return False
    return all(a[k].get('shape')==b[k].get('shape') and a[k].get('dtype')==b[k].get('dtype')
               for k in a if isinstance(a[k],dict) and isinstance(b[k],dict)) and all(
                   isinstance(a[k],dict) and isinstance(b[k],dict) for k in a)


def queue_digest(rows):
    canonical=json.dumps([{'id':str(r['id']),'state':r['state'],'fence':r['fence'],'revision':r['revision']}
                          for r in sorted(rows,key=lambda x:str(x['id']))],
                         sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    return {'count':len(rows),'sha256':hashlib.sha256(canonical).hexdigest()}


def queue_scope(before_rows,after_rows,owned_run_ids):
    before={str(r['id']):{'id':str(r['id']),'state':r['state'],'fence':r['fence'],'revision':r['revision']} for r in before_rows}
    after={str(r['id']):{'id':str(r['id']),'state':r['state'],'fence':r['fence'],'revision':r['revision']} for r in after_rows}
    owned={str(x) for x in owned_run_ids}
    preserved=[after[rid] for rid in before if rid in after]
    new_owned_are_disjoint=(len(owned)==2 and not (owned & set(before)))
    unexpected=set(after)-set(before)-owned
    old_rows_unchanged=(set(after)&set(before)==set(before) and queue_digest(preserved)==queue_digest(before_rows))
    return {'before':queue_digest(before_rows),'preexisting_after':queue_digest(preserved),
            'preexisting_ids_preserved':set(after)&set(before)==set(before),
            'preexisting_state_digest_unchanged':old_rows_unchanged,
            'two_owned_run_ids_are_new':new_owned_are_disjoint,
            'unexpected_queued_count':len(unexpected),'owned_runs_still_queued_count':len(set(after)&owned),
            'unchanged':old_rows_unchanged and new_owned_are_disjoint and not unexpected}


def read_queued_rows(dsn):
    with psycopg.connect(dsn,row_factory=dict_row) as c:
        with c.transaction():
            c.execute('SET TRANSACTION READ ONLY')
            return c.execute("SELECT id::text AS id,state,fence,revision FROM fw_runs WHERE state='queued' ORDER BY id").fetchall()


def resolve_scanner_authority(requested,operator_dsn):
    if not isinstance(requested,str) or not requested:
        raise RuntimeError('SCANNER_AUTHORITY_EXPLICIT_PATH_REQUIRED')
    selected=Path(requested)
    if not selected.is_absolute() or selected.drive.casefold()!='c:':
        raise RuntimeError('SCANNER_AUTHORITY_MUST_BE_ABSOLUTE_C_PATH')
    current=Path(selected.anchor)
    for component in selected.parts[1:]:
        current=current/component
        try:metadata=os.lstat(current)
        except FileNotFoundError:break
        if getattr(metadata,'st_file_attributes',0)&0x400:
            raise RuntimeError('SCANNER_AUTHORITY_REPARSE_POINT_REFUSED')
    if not selected.is_file():raise RuntimeError('SCANNER_AUTHORITY_FILE_MISSING')
    if any(key.upper().startswith('PG') for key in os.environ):
        raise RuntimeError('SCANNER_AUTHORITY_ENVIRONMENT_FORBIDDEN')
    try:
        from fieldwork.scoped_authority import validate
        authority=validate(json.loads(selected.read_text(encoding='utf-8')))
    except Exception as exc:
        raise RuntimeError('SCANNER_AUTHORITY_MACHINE_SCHEMA_INVALID') from exc
    operator=conninfo_to_dict(operator_dsn);connection=authority['connection']
    if (connection['host']!=operator.get('host','127.0.0.1') or
            connection['port']!=int(operator.get('port',5432)) or
            connection['dbname']!=operator.get('dbname')):
        raise RuntimeError('SCANNER_AUTHORITY_ENDPOINT_MISMATCH')
    return str(selected)


def child_environment(**extra):
    env={k:v for k,v in os.environ.items() if k in ('SYSTEMROOT','PATH','TEMP','TMP','USERPROFILE')}
    env['PYTHONDONTWRITEBYTECODE']='1'
    env.update(extra)
    return env


def spawn(role,*args,**kwargs):
    if kwargs.get('env') is None:kwargs['env']=child_environment()
    process=subprocess.Popen(*args,**kwargs)
    identity=psutil.Process(process.pid)
    parent=identity.parent()
    record={'role':role,'pid':process.pid,'create_time':identity.create_time(),
            'parent_pid':parent.pid if parent else None,
            'parent_create_time':parent.create_time() if parent else None,
            'argv_sha256':hashlib.sha256(json.dumps(args[0],separators=(',',':')).encode()).hexdigest()}
    PROCESSES.append({'process':process,'record':record})
    REPORT.setdefault('spawn_provenance',[]).append(record)
    capture_descendants(record)
    return process,record


def capture_descendants(record):
    key=(record['pid'],record['create_time'])
    root=platform_restart._same_process(*key)
    if root is None:return []
    CAPTURE_OBSERVATIONS[key]=CAPTURE_OBSERVATIONS.get(key,0)+1
    try:children=root.children(recursive=True)
    except psutil.NoSuchProcess:return []  # root exited during capture: it has no descendants left to own
    except psutil.Error as exc:raise RuntimeError('OWNED_DESCENDANT_INVENTORY_UNAVAILABLE') from exc
    captured=[]
    for child in children:
        try:created=child.create_time()
        except psutil.NoSuchProcess:
            REPORT.setdefault('inventory_exits',[]).append({'pid':child.pid,'stage':'before_birth_read'})
            continue
        ancestry=platform_restart._process_ancestry(child.pid)
        child_key=(child.pid,created)
        item={'pid':child.pid,'create_time':created,'launch_pid':record['pid'],'launch_create_time':record['create_time']}
        existing=DESCENDANT_HANDLES.setdefault(key,{}).get(child_key)
        # Once a PID birth and its ancestry were captured, a naturally exited
        # launcher can reparent that same process. Keep the earlier proof. A new
        # live PID whose ancestry cannot be tied to this launcher still fails closed.
        if not platform_restart.ancestry_contains(ancestry,*key) and existing is None:
            if not child.is_running():
                REPORT.setdefault('inventory_exits',[]).append({'pid':child.pid,'create_time':created,'stage':'before_ancestry_read'})
                continue
            raise RuntimeError('OWNED_DESCENDANT_ANCESTRY_MISMATCH')
        if existing is not None and existing['record']!=item:
            raise RuntimeError('OWNED_DESCENDANT_IDENTITY_CHANGED')
        if existing is None:
            DESCENDANT_HANDLES[key][child_key]={'record':item,'handle':child}
            REPORT.setdefault('descendant_provenance',[]).append({**item,'ancestry':ancestry})
        captured.append(DESCENDANT_HANDLES[key][child_key])
    return captured


def capture_module_process(role,record,args):
    if not isinstance(args,(list,tuple)) or '-m' not in args:return None
    module=args[list(args).index('-m')+1]
    extra='serve' if module=='fieldwork.worker_identity' and 'serve' in args else None
    actual=platform_restart._find_module_process(record,module,extra)
    if actual is not None:
        REPORT.setdefault('actual_module_processes',{})[role]={k:actual[k] for k in
            ('pid','create_time','parent_pid','parent_create_time','launch_pid','launch_create_time','role')}
    return actual


def stop_tree(process,record):
    key=(record['pid'],record['create_time'])
    if key in CLEANUP_RESULTS:return CLEANUP_RESULTS[key]['stopped']
    if process.pid!=record['pid']:
        result={'stopped':False,'root':{'pid':record['pid'],'create_time':record['create_time']},'descendants':[],'reason':'POPEN_PID_MISMATCH'}
        CLEANUP_RESULTS[key]=result;REPORT.setdefault('cleanup_receipts',[]).append(result);return False
    try:captured=capture_descendants(record)
    except RuntimeError as exc:
        captured=list(DESCENDANT_HANDLES.get(key,{}).values())
        inventory_error=type(exc).__name__
    else:inventory_error=None
    root_process=platform_restart._same_process(*key)
    known=[(x['record'],x['handle']) for x in DESCENDANT_HANDLES.get(key,{}).values()]
    child_receipts=[]
    if root_process is None and not known:
        try:
            if process.poll() is None:process.wait(timeout=15)
            root_exit=process.returncode is not None
        except (OSError,subprocess.TimeoutExpired):root_exit=False
        observed=CAPTURE_OBSERVATIONS.get(key,0)
        done=root_exit and inventory_error is None and observed>0
        child_receipts=[]
    else:
        launch={**record,'role':record['role']+'-launcher'}
        cleanup_receipts=[]
        done=platform_restart._stop_owned_tree(launch,process,known,cleanup_receipts)
        root_exit=process.returncode is not None
        child_receipts=cleanup_receipts[0] if cleanup_receipts else []
        done=bool(done and root_exit and inventory_error is None and all(item['exit_proven'] for item in child_receipts))
    result={'stopped':done,'root':{'pid':record['pid'],'create_time':record['create_time'],
            'popen_returncode':process.returncode,'exit_proven':root_exit},
            'descendants':child_receipts,'known_descendant_count':len(known),
            'descendant_inventory_observations':CAPTURE_OBSERVATIONS.get(key,0),'inventory_error':inventory_error}
    CLEANUP_RESULTS[key]=result;REPORT.setdefault('cleanup_receipts',[]).append(result)
    return done


def cleanup_all():
    all_stopped=True
    for entry in reversed(PROCESSES):
        process=entry['process'];record=entry['record']
        if not stop_tree(process,record):
            all_stopped=False
            REPORT.setdefault('cleanup_failures',[]).append({'role':record['role'],'pid':record['pid'],
                'create_time':record['create_time'],'receipt':CLEANUP_RESULTS.get((record['pid'],record['create_time']))})
    return all_stopped


def record_queue_after(dsn):
    if BASELINE_QUEUE_ROWS is None:return
    try:
        after=read_queued_rows(dsn)
        REPORT['queue_after_cleanup']=queue_digest(after)
        REPORT['queue_scope_after_cleanup']=queue_scope(BASELINE_QUEUE_ROWS,after,OWNED_RUN_IDS)
    except Exception as exc:
        REPORT['queue_after_cleanup_error_type']=type(exc).__name__


def run_child(role,args,*,timeout,cwd,env=None):
    process,record=spawn(role,args,cwd=cwd,env=env or child_environment(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    deadline=time.monotonic()+timeout
    while True:
        try:
            stdout,stderr=process.communicate(timeout=min(.2,max(.01,deadline-time.monotonic())))
            capture_descendants(record);capture_module_process(role,record,args)
            return subprocess.CompletedProcess(args,process.returncode,stdout,stderr),record
        except subprocess.TimeoutExpired:
            capture_descendants(record);capture_module_process(role,record,args)
            if time.monotonic()>=deadline:
                stopped=stop_tree(process,record)
                try:process.communicate(timeout=10)
                except subprocess.TimeoutExpired:pass
                raise RuntimeError('CHILD_TIMEOUT:'+role+':stopped='+str(stopped))

PROBE='''
import json,sys
from fieldwork.store import Store,Conflict
from psycopg import OperationalError
s=Store();rid=sys.argv[1];a=json.loads(sys.argv[2]);out={}
for n,f in [("heartbeat",lambda:s.heartbeat(rid,a["fence"],a["gen"],attempt=a["attempt"])),("complete",lambda:s.complete(rid,a["fence"],a["gen"],{},attempt=a["attempt"]))]:
    try:
        f();out[n]={"refused":False,"code":"NO_REFUSAL"}
    except Conflict as e:
        out[n]={"refused":True,"code":str(e)}
print(json.dumps(out))
'''
COMPARE='''
import sys,json
from safetensors.torch import load_file
a=load_file(sys.argv[1]+"/state.safetensors");b=load_file(sys.argv[2]+"/state.safetensors")
if set(a)!=set(b): print(json.dumps({"keys_equal":False,"structures_equal":False,"tensors_a":len(a),"tensors_b":len(b)})); sys.exit(0)
if not a or any(a[k].shape!=b[k].shape or a[k].dtype!=b[k].dtype for k in a): print(json.dumps({"keys_equal":True,"structures_equal":False,"tensors":len(a)})); sys.exit(0)
mk=[k for k in a if k.startswith("model.")]; ok=[k for k in a if k.startswith("optimizer.")]; rk=[k for k in a if k.startswith("rng.")]
if not mk or not ok or not rk or len(mk)+len(ok)+len(rk)!=len(a): print(json.dumps({"keys_equal":True,"structures_equal":False,"tensors":len(a)})); sys.exit(0)
d=max(float((a[k]-b[k]).abs().max()) for k in mk)
o=max(float((a[k]-b[k]).abs().max()) for k in ok)
r=max(float((a[k]-b[k]).abs().max()) for k in rk)
print(json.dumps({"keys_equal":True,"structures_equal":True,"param_max_abs":d,"optimizer_max_abs":o,"rng_max_abs":r,"tensors":len(a)}))
'''


def run():
    import importlib.util
    helper=ROOT.parent/'tools/product_lock.py'
    spec=importlib.util.spec_from_file_location('portfolio_product_lock',helper)
    lock=importlib.util.module_from_spec(spec);spec.loader.exec_module(lock)
    owner=lock.read_owner()
    if not owner or owner.get('product')!='fieldwork' or 'kill-replay' not in owner.get('purpose','') or lock.owner_gone(owner)[1]!='OWNER_ALIVE':
        raise RuntimeError('ENCLOSING_FIELDWORK_KILL_REPLAY_LOCK_REQUIRED')
    out=sys.argv[1];K=int(sys.argv[2]) if len(sys.argv)>2 else 8
    if not 1<=K<EP:raise RuntimeError('K_MUST_BE_WITHIN_TRAINING_EPOCHS')
    a=json.load(open(ROOT/'.browser-test.json'));op=json.load(open(ROOT/'.local.json'))['dsn']
    def db(q,p=()):
        with psycopg.connect(op,row_factory=dict_row) as c:return c.execute(q,p).fetchall()
    global BASELINE_QUEUE_ROWS
    rep=REPORT;rep.update(K=K,epochs=EP,started=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
    BASELINE_QUEUE_ROWS=read_queued_rows(op)
    baseline_ids={str(row['id']) for row in BASELINE_QUEUE_ROWS}
    rep['preexisting_queue_before']=queue_digest(BASELINE_QUEUE_ROWS)
    rep['preexisting_queue_expected_count']=21
    if len(BASELINE_QUEUE_ROWS)!=21:raise RuntimeError('PREEXISTING_QUEUE_COUNT_CHANGED_BEFORE_REPLAY')
    auth=resolve_scanner_authority(sys.argv[3] if len(sys.argv)>3 else None,op)
    worker_dir=platform_restart._authority_directory()
    worker_authority=worker_dir/'worker-authority.json'
    rep['scanner_authority_selection']='explicit validated C: scoped-machine-v1 authority'
    worker_env=child_environment(FIELDWORK_WORKER_AUTHORITY=str(worker_authority),
                                 FIELDWORK_WORKER_ID='retained-kill-replay-r5')
    # The enclosing coordinator process holds product_lock for this entire proof.
    # Standalone child workers must not try to reacquire that same lock or inherit
    # the live loop's pause marker; the paused live loop itself remains unchanged.
    rep['worker_identity']='scoped-worker-v1';rep['host_lock']='held by enclosing coordinator step'
    c=httpx.Client(base_url='http://127.0.0.1:8102',timeout=30)
    lg=c.post('/auth/session',json={'name':a['name'],'password':a['password']});assert lg.status_code==200
    H={'Origin':'http://127.0.0.1:8102','X-CSRF-Token':lg.json()['csrf']};base='/api/v1/workspaces/'+a['workspace']
    body={'epochs':EP,'batch_size':8,'seed':7,'learning_rate':'0.001'}
    def submit():
        r=c.post(base+'/runs',headers={**H,'Idempotency-Key':str(uuid.uuid4())},json=body);assert r.status_code==202,r.text;return r.json()['id']
    rid=submit();rep['run']=rid
    if rid in baseline_ids:raise RuntimeError('REPLAY_RUN_ID_NOT_NEW')
    OWNED_RUN_IDS.add(rid)
    w,wrec=spawn('faulted-worker',[PY,'-m','fieldwork.worker','--once','--run-id',rid,
                                   '--proof-pause-epoch',str(K+1)],cwd=ROOT,env=worker_env,
                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    deadline=time.time()+600
    # The attempt directory is generated by the claim; locate the marker only
    # under this newly submitted run's owned directory.
    while time.time()<deadline:
        capture_descendants(wrec)
        capture_module_process('faulted-worker',wrec,[PY,'-m','fieldwork.worker'])
        markers=list((ROOT/'var/runs'/rid).glob('*/paused.json'))
        if markers:
            pause_marker=markers[0]
            marker=json.loads(pause_marker.read_text(encoding='utf-8'))
            row=db('SELECT epoch,state FROM fw_runs WHERE id=%s',(rid,))[0]
            checkpoints=db('SELECT epoch FROM fw_checkpoints WHERE run=%s ORDER BY epoch',(rid,))
            if (marker.get('epoch')==K+1 and marker.get('batch')==2 and row['epoch']==K and
                    row['state']=='running' and [x['epoch'] for x in checkpoints]==list(range(1,K+1))):
                child_pid=marker.get('pid')
                pinned=next((v for v in DESCENDANT_HANDLES.get((wrec['pid'],wrec['create_time']),{}).values()
                             if v['record']['pid']==child_pid),None)
                if pinned is None:raise RuntimeError('PAUSED_TRAINING_CHILD_BIRTH_NOT_PROVEN')
                process=platform_restart._same_process(child_pid,pinned['record']['create_time'])
                if process is None:raise RuntimeError('PAUSED_TRAINING_CHILD_EXITED_BEFORE_KILL')
                rep['physical_pause']={'marker':str(pause_marker),'epoch':marker['epoch'],'batch':marker['batch'],
                    'committed_before_pause':[x['epoch'] for x in checkpoints],
                    'child_pid':child_pid,'child_create_time':pinned['record']['create_time'],
                    'ancestry_proven_before_kill':True}
                break
        time.sleep(0.5)
    else:
        row=db('SELECT epoch,state FROM fw_runs WHERE id=%s',(rid,))[0]
        raise RuntimeError('PHYSICAL_PAUSE_MARKER_AND_COMMITTED_K_NOT_OBSERVED')
    rep['epoch_at_kill']=row['epoch'];rep['state_at_kill']=row['state']
    if 'faulted-worker' not in rep.get('actual_module_processes',{}):raise RuntimeError('FAULTED_WORKER_MODULE_LINEAGE_NOT_PROVEN')
    # Review F9: the stale attempt's identity is captured BEFORE the kill (the slot may be gone after).
    pre=db('SELECT attempt,fence,cancel_generation FROM fw_runs WHERE id=%s',(rid,))[0];rep['attempt_at_kill']=pre
    tree=psutil.Process(wrec['pid']);kids=tree.children(recursive=True)
    rep['killed']={'worker_pid':wrec['pid'],'worker_create_time':wrec['create_time'],
                   'children':[{'pid':k.pid,'create_time':k.create_time()} for k in kids]}
    if not stop_tree(w,wrec):raise RuntimeError('FAULTED_WORKER_TREE_CLEANUP_UNVERIFIED')
    w.wait(timeout=30);time.sleep(0.5)
    slot=db('SELECT run,fence,launching FROM fw_slot WHERE id=1')[0];rep['slot_after_kill']=slot
    rep['slot_held_by_killed_run']=slot['run']==rid
    gen=db('SELECT cancel_generation FROM fw_runs WHERE id=%s',(rid,))[0]['cancel_generation']
    lease=db('SELECT lease FROM fw_runs WHERE id=%s',(rid,))[0]['lease'];rep['lease_deadline']=str(lease)
    scanner,scanner_rec=spawn('once-only-scanner',[PY,'-m','fieldwork.lease_recovery','--authority-file',auth,'--interval','2'],cwd=ROOT,env=child_environment(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    t0=time.time()
    while time.time()-t0<120:
        capture_descendants(scanner_rec)
        capture_module_process('once-only-scanner',scanner_rec,[PY,'-m','fieldwork.lease_recovery','--authority-file',auth,'--interval','2'])
        r=db('SELECT state,fence,revision FROM fw_runs WHERE id=%s',(rid,))[0]
        if r['state']=='interrupted':break
        time.sleep(0.25)
    if not stop_tree(scanner,scanner_rec):raise RuntimeError('SCANNER_TREE_CLEANUP_UNVERIFIED')
    scanner.wait(timeout=10)
    ev=db("SELECT created,payload FROM fw_events WHERE run=%s AND kind='expired' ORDER BY seq",(rid,))
    rep['expired_state']=r['state'];rep['expiry_event_lag_seconds']=(ev[0]['created']-lease).total_seconds() if ev else None
    rep['expiry_payload']=ev[0]['payload'] if ev else None
    probe,probe_rec=run_child('stale-attempt-probe',[PY,'-c',PROBE,rid,json.dumps({'fence':pre['fence'],'gen':pre['cancel_generation'],'attempt':pre['attempt']})],timeout=30,cwd=ROOT,env=child_environment())
    rep['stale_probe_scope']='operator Store diagnostic; not a scoped-machine credential probe'
    rep['stale_attempt_refused']=json.loads(probe.stdout.strip().splitlines()[-1]) if probe.returncode==0 else {'process_exit':probe.returncode,'error_tail':probe.stderr[-500:]}
    rec,rec_rec=run_child('slot-reconcile-diagnostic',[PY,'-c','from fieldwork.store import Store;print(Store().reconcile_training_slot())'],timeout=30,cwd=ROOT,env=child_environment())
    rep['slot_reconcile_scope']='operator Store diagnostic; not a scoped-machine proof'
    rep['slot_reconcile']=rec.stdout.strip() or rec.stderr[-400:]
    cp=db('SELECT epoch FROM fw_checkpoints WHERE run=%s ORDER BY epoch',(rid,));rep['committed_before_resume']=[x['epoch'] for x in cp]
    rr=c.post(base+'/runs/'+rid+'/resume',headers=H,json={'replay_epoch':cp[-1]['epoch']+1});rep['resume_http']=rr.status_code
    w2,w2rec=run_child('replay-worker',[PY,'-m','fieldwork.worker','--once','--run-id',rid],cwd=ROOT,env=worker_env,timeout=900)
    rep['resume_worker_exit']=w2.returncode;rep['resume_worker_tail']=(w2.stdout.strip()[-600:]+w2.stderr.strip()[-600:])
    final=db('SELECT state,artifact_status,epoch,fence FROM fw_runs WHERE id=%s',(rid,))[0];rep['final']=final
    cps=db('SELECT epoch,attempt,digest,path FROM fw_checkpoints WHERE run=%s ORDER BY epoch',(rid,))
    rep['checkpoint_epochs']=[x['epoch'] for x in cps];rep['distinct_attempts']=len({x['attempt'] for x in cps})
    rep['epoch_committed_events']=[x['n'] for x in db("SELECT count(*) n FROM fw_events WHERE run=%s AND kind='epoch_committed'",(rid,))][0]
    ctl=submit();rep['control_run']=ctl
    if ctl in baseline_ids or ctl==rid:raise RuntimeError('CONTROL_RUN_ID_NOT_NEW')
    OWNED_RUN_IDS.add(ctl)
    w3,w3rec=run_child('control-worker',[PY,'-m','fieldwork.worker','--once','--run-id',ctl],cwd=ROOT,env=worker_env,timeout=900);rep['control_worker_exit']=w3.returncode
    ccps=db('SELECT epoch,digest,path FROM fw_checkpoints WHERE run=%s ORDER BY epoch',(ctl,))
    cmp,cmp_rec=run_child('checkpoint-tensor-compare',[PY,'-c',COMPARE,cps[-1]['path'],ccps[-1]['path']],cwd=ROOT,timeout=120,env=child_environment())
    rep['replay_vs_control_final_checkpoint']=json.loads(cmp.stdout.strip()) if cmp.returncode==0 else cmp.stderr[-600:]
    evaluation_populations={}
    for run,key in [(rid,'resumed'),(ctl,'control')]:
        ar=c.get(base+'/runs/'+run+'/artifacts');rep[key+'_artifacts_http']=ar.status_code
        e=c.get(base+'/runs/'+run+'/evaluation');rep[key+'_evaluation_http']=e.status_code
        if e.status_code==200:
            payload=e.json();rep[key+'_accuracy']=payload['metrics'].get('accuracy');rep[key+'_evaluation_id']=payload['evaluation_id']
            evaluation_populations[key]=payload.get('population')
        if ar.status_code==200:rep[key+'_receipt']=ar.json()['receipt']
    if 'resumed_receipt' in rep and 'control_receipt' in rep:
        rep['fresh_process_comparison']=compare_inference_receipts(rep['resumed_receipt'],rep['control_receipt'])
        rep['validation_population_equal']=(evaluation_populations.get('resumed') is not None and
            evaluation_populations.get('control') is not None and
            evaluation_populations['resumed']==evaluation_populations['control'])
        rep['validation_population_count']=len(evaluation_populations.get('resumed') or [])
    after_rows=read_queued_rows(op)
    rep['preexisting_queue_scope']=queue_scope(BASELINE_QUEUE_ROWS,after_rows,OWNED_RUN_IDS)
    rep['queue_after_all_owned_runs']=queue_digest(after_rows)
    comparison=rep['replay_vs_control_final_checkpoint']
    comparison=comparison if isinstance(comparison,dict) else {}
    stale=rep['stale_attempt_refused']
    rep['passed']=all((rep['epoch_at_kill']==K,rep['state_at_kill']=='running',rep['slot_held_by_killed_run'],
                       rep.get('physical_pause',{}).get('epoch')==K+1,
                       rep.get('physical_pause',{}).get('batch')==2,
                       rep.get('physical_pause',{}).get('committed_before_pause')==list(range(1,K+1)),
                       rep.get('physical_pause',{}).get('ancestry_proven_before_kill') is True,
                       rep['expired_state']=='interrupted',rep['resume_worker_exit']==0,rep['control_worker_exit']==0,
                       rep['final']['state']=='succeeded',rep['final']['artifact_status']=='verified',
                       rep['checkpoint_epochs']==list(range(1,EP+1)),rep['epoch_committed_events']==EP,rep['distinct_attempts']==2,
                       stale_refusals_proven(stale),
                       rep['expiry_event_lag_seconds'] is not None and 0<=rep['expiry_event_lag_seconds']<=10,
                       rep.get('fresh_process_comparison',{}).get('identity_equal') is True,
                       rep.get('fresh_process_comparison',{}).get('length_equal') is True,
                       rep.get('fresh_process_comparison',{}).get('finite') is True,
                       rep.get('fresh_process_comparison',{}).get('max_abs',float('inf'))<=1e-6,
                       rep.get('fresh_process_comparison',{}).get('top1_equal') is True,
                       rep.get('validation_population_equal') is True,
                       rep.get('preexisting_queue_scope',{}).get('unchanged') is True,
                       rep.get('preexisting_queue_scope',{}).get('owned_runs_still_queued_count')==0,
                       comparison.get('keys_equal') is True,comparison.get('structures_equal') is True,
                       comparison.get('param_max_abs',float('inf'))<=1e-6,comparison.get('optimizer_max_abs',float('inf'))<=1e-6,
                       comparison.get('rng_max_abs',float('inf'))==0))
    if not cleanup_all():raise RuntimeError('OWNED_PROCESS_CLEANUP_UNVERIFIED')
    with Path(out).open('x') as f:f.write(json.dumps(rep,indent=2,default=str))
    print(json.dumps({k:v for k,v in rep.items() if not k.endswith('_receipt')},default=str))
    if not rep['passed']:raise RuntimeError('RETAINED_KILL_REPLAY_ASSERTION_FAILED')


def main():
    failure_error=None
    try:run()
    except BaseException as exc:
        failure_error=exc
    finally:
        cleanup_all()
        try:
            operator=json.loads((ROOT/'.local.json').read_text(encoding='utf-8'))['dsn']
            record_queue_after(operator)
        except Exception as exc:
            REPORT['queue_after_cleanup_error_type']=type(exc).__name__
    if failure_error is not None:
        failure=Path(sys.argv[1]+'.failure.json')
        with failure.open('x') as f:json.dump({**REPORT,'error_type':type(failure_error).__name__},f,indent=2,default=str)
        raise failure_error

if __name__=='__main__':main()
