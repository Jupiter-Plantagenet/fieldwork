"""Dedicated local supervisor for trusted synthetic fixtures. Never accepts user code."""
import argparse,json,os,subprocess,sys,time,uuid,shutil,hashlib,re,math
from pathlib import Path
from datetime import datetime,timezone
import psutil
from .store import Store,ROOT,Conflict,CancelGenerationConflict
from .data import generate,canonical,digest
from .supervisor import command_key
from .worker_heartbeat import effective_worker_id, publish_worker_heartbeat
from .operator_overrides import space_override, required_free_bytes

# Review F3: only refusals that are permanent AND specific to one run revision may skip a
# run; transient ones (slot busy, generation changed, lease lost, ...) back off and retry.
PERMANENT_REFUSALS={'UNTRUSTED_PROFILE_BLOCKED','CHECKPOINT_POINTER_MISMATCH',
    'REAL_POPULATION_BOUNDS','REAL_PROFILE_REFUSED','REAL_PROFILE_IMPLEMENTATION_DIGEST',
    'REAL_PROFILE_FIELDS','REAL_PROFILE_ALLOWLIST','REAL_PROFILE_NONCANONICAL'}


def worker_store(*, real_runs=False):
    """Scoped machine identity when FIELDWORK_WORKER_AUTHORITY names a private authority
    file (fieldwork.worker_identity); otherwise the legacy trusted-operator Store."""
    authority=os.environ.get('FIELDWORK_WORKER_AUTHORITY')
    if authority:
        if real_runs:
            from .real_worker_identity import RealWorkerStore
            return RealWorkerStore(authority)
        from .worker_identity import WorkerStore
        return WorkerStore(authority)
    if real_runs:
        raise RuntimeError('REAL_RUNS_REQUIRE_SCOPED_WORKER_AUTHORITY')
    return Store()


REAL_JOB_REPEAT_FAILURE_LIMIT=3


def _note_real_job_failure(counts,key,limit=REAL_JOB_REPEAT_FAILURE_LIMIT):
    """True once the same (run, revision) has failed `limit` times in this worker process (in-memory; never reset on success)."""
    counts[key]=counts.get(key,0)+1
    return counts[key]>=limit


def _real_job_failure_summary(exc, run_id, model_runner):
    """Return only a bounded classification for an already-failed real job."""
    safe_code=getattr(exc,'safe_failure_code',None)
    if not isinstance(safe_code,str) or not re.fullmatch(r'[A-Z0-9_]{1,120}',safe_code):
        safe_code='REAL_JOB_EXECUTION_FAILED'
    return 26, {'code':'RUN_REAL_JOB_FAILED','run':run_id,'reason':safe_code,
                'cleanup_pending':bool(model_runner.has_unresolved_container)}


def exit_receipt(attempt,child):
    """Canonical record of the observed exit, hashed into ML-AcknowledgeCancel's
    exit_receipt_digest. The registered child pid is the launcher the worker spawned (on
    Windows the venv redirector; its exit takes the interpreter with it, see docs)."""
    return {'attempt':attempt['attempt'],'fence':attempt['fence'],'run':attempt['id'],
            'child_pid':getattr(child,'pid',None),'child_returncode':child.poll() if child is not None else None,
            'owner_pid':os.getpid(),'observed_utc':datetime.now(timezone.utc).isoformat()}
from .artifact_pipeline import finalize_artifacts,verify_inference_receipt


MIN_AVAILABLE_RAM_BYTES=6*1024**3
MIN_FREE_DISK_BYTES=12*1024**3
REAL_CHILD_MEMORY_LIMIT_BYTES=2*1024**3
# Conservative host-side allowance: bundle export buffers at most 66 MiB and a
# checkpoint export at most 34 MiB; input transfer uses 1 MiB stream chunks and
# a 2 MiB manifest bound. This is an admission reserve, not an RSS measurement.
REAL_HOST_STAGING_EXPORT_ALLOWANCE_BYTES=256*1024**2
REAL_ADDITIONAL_HEADROOM_BYTES=4*1024**3
REAL_PROJECTED_PEAK_BYTES=REAL_CHILD_MEMORY_LIMIT_BYTES+REAL_HOST_STAGING_EXPORT_ALLOWANCE_BYTES
REAL_REQUIRED_AVAILABLE_RAM_BYTES=max(MIN_AVAILABLE_RAM_BYTES,
    REAL_PROJECTED_PEAK_BYTES+REAL_ADDITIONAL_HEADROOM_BYTES)


def portfolio_host_preflight(*, platform_name=None):
    """Enforce the Windows coordinator policy before a queued job is claimed.

    The product's portable RAM/disk gates remain separate. The configured host
    lock opts this worker into the shared C: and actual Windows commit policy.
    Failure to obtain those counters never means admission.
    """
    if not os.environ.get('FIELDWORK_HOST_HEAVY_LOCK') or (platform_name or os.name) != 'nt':
        return {'portfolio_host_policy': False, 'host_admitted': True}
    detail={'portfolio_host_policy': True, 'host_admitted': False,
            'host_required_free_c_bytes': 50_000_000_000,
            'host_commit_limit_percent': 85}
    command=('Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | '
             'Select-Object CommittedBytes,CommitLimit,PercentCommittedBytesInUse | ConvertTo-Json -Compress')
    try:
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],
                              capture_output=True,text=True,timeout=15,check=False)
        if result.returncode or len(result.stdout)>2048:
            detail['host_refusal']='HOST_COMMIT_COUNTER_UNAVAILABLE'
            return detail
        counters=json.loads(result.stdout)
        used,limit,percent=(counters[k] for k in ('CommittedBytes','CommitLimit','PercentCommittedBytesInUse'))
        if (any(type(x) not in (int,float) or not math.isfinite(x) for x in (used,limit,percent)) or
                not 0<=used<=limit or limit<=0 or not 0<=percent<=100):
            raise ValueError('HOST_COMMIT_COUNTER_INVALID')
        free_c=shutil.disk_usage('C:/').free
        detail.update(host_commit_used_bytes=used,host_commit_limit_bytes=limit,
                      host_commit_percent=percent,host_free_c_bytes=free_c)
        detail['host_admitted']=free_c>=50_000_000_000 and percent<85 and used/limit<.85
        if not detail['host_admitted']:detail['host_refusal']='HOST_DISK_OR_COMMIT_GATE'
    except (OSError,subprocess.TimeoutExpired,ValueError,TypeError,KeyError):
        detail['host_refusal']='HOST_COMMIT_COUNTER_UNAVAILABLE_OR_INVALID'
    return detail


def preflight(*,real_runs=False):
    host=portfolio_host_preflight()
    available=psutil.virtual_memory().available;free=shutil.disk_usage(ROOT).free
    required_ram=REAL_REQUIRED_AVAILABLE_RAM_BYTES if real_runs else MIN_AVAILABLE_RAM_BYTES
    detail={'code':'RESOURCE_PREFLIGHT','available_ram_bytes':available,'free_disk_bytes':free,
        'minimum_available_ram_bytes':MIN_AVAILABLE_RAM_BYTES,'required_available_ram_bytes':required_ram,
        'required_free_disk_bytes':MIN_FREE_DISK_BYTES}
    if real_runs:
        detail.update({'projected_child_memory_bytes':REAL_CHILD_MEMORY_LIMIT_BYTES,
            'bounded_host_staging_export_allowance_bytes':REAL_HOST_STAGING_EXPORT_ALLOWANCE_BYTES,
            'projected_peak_ram_bytes':REAL_PROJECTED_PEAK_BYTES,
            'additional_headroom_bytes':REAL_ADDITIONAL_HEADROOM_BYTES})
    detail.update(host)
    # Explicit, recorded operator decision: waives every memory gate (available RAM and
    # the Windows commit counter). Free disk (product and C:) is never waived.
    ram_override=os.environ.get('FIELDWORK_OPERATOR_RAM_OVERRIDE')=='accept-low-available-ram'
    space=space_override()
    required_disk=required_free_bytes(MIN_FREE_DISK_BYTES)
    host_ok=host['host_admitted']
    if ram_override:
        detail['operator_ram_override']=True
    if space:
        # Second explicit operator decision: lowers the product and C: free-disk requirements
        # to a small floor and lifts the per-run write budget (see operator_overrides.py).
        detail.update(operator_space_override=True,required_free_disk_bytes=required_disk)
    if (ram_override or space) and host.get('portfolio_host_policy'):
        disk_ok=shutil.disk_usage('C:/').free>=required_free_bytes(50_000_000_000)
        commit_ok=ram_override or (host.get('host_commit_percent',100)<85
            and host.get('host_commit_used_bytes',1)/max(host.get('host_commit_limit_bytes',1),1)<.85)
        host_ok=disk_ok and commit_ok
    admitted=(available>=required_ram or ram_override) and free>=required_disk and host_ok
    detail['admitted']=admitted
    return admitted,detail


def operator_paused():
    """Optional local admission marker; an unreadable marker fails closed.

    It does not cancel or change queued jobs. Operators can keep the scoped
    identity/issuer alive while the coordinator has not granted a heavy window.
    """
    marker=os.environ.get('FIELDWORK_TRAINING_PAUSE_FILE')
    if not marker:return False
    try:Path(marker).stat();return True
    except FileNotFoundError:return False
    except OSError:return True


def supervisor_identity():
    """Identity fields let a launcher bind a fresh pause receipt to this process."""
    process=psutil.Process()
    parent=process.parent()
    nonce=os.environ.get('FIELDWORK_TRAINING_PAUSE_NONCE')
    return {'pid':process.pid,'create_time':process.create_time(),
            'parent_pid':parent.pid if parent else None,
            'parent_create_time':parent.create_time() if parent else None,
            'worker_id':effective_worker_id(process.pid),
            'pause_nonce_sha256':hashlib.sha256(nonce.encode()).hexdigest() if nonce else None}


def execute(run_id, proof_pause_epoch=None):
    admitted,detail=preflight()
    if not admitted:
        print(json.dumps(detail));return 23
    s=worker_store();r=s.get(run_id)
    if r and r['state']=='succeeded' and r['artifact_status'] in ('retry_pending','failed'):
        a=s.claim_artifacts(run_id)
        env={k:v for k,v in os.environ.items() if k in ['SYSTEMROOT','PATH','TEMP','TMP','USERPROFILE']};env['OMP_NUM_THREADS']='2';env['MKL_NUM_THREADS']='2'
        try:finalize_artifacts(s,a,ROOT/'var/runs'/run_id,ROOT/'var/images',env);return 0
        finally:s.release_slot(run_id,fence=a['fence'])
    if not r or r['state']!='queued':raise Conflict('NOT_QUEUED')
    m=generate(ROOT/'var/images');cfg=r['config']
    if cfg.get('scope')!='synthetic-execution-only' or cfg.get('dataset_digest')!=m['digest'] or cfg.get('recipe')!='compact-cnn/v1':raise Conflict('UNTRUSTED_PROFILE_BLOCKED')
    if proof_pause_epoch is not None and (type(proof_pause_epoch) is not int or not 1<=proof_pause_epoch<=int(cfg['epochs'])):
        raise Conflict('PROOF_PAUSE_EPOCH_OUT_OF_RANGE')
    # Claim only if the generation observed at selection is still current.
    worker_id=os.environ.get('FIELDWORK_WORKER_ID','fieldwork-worker-'+str(os.getpid()))
    # ML-Claim (leased). The key binds this selection (run + observed revision) so a retry
    # after a lost response replays the same attempt instead of claiming twice.
    r=s.claim(run_id,expected_cancel_generation=r.get('cancel_generation'),start=False,worker_id=worker_id,key=command_key(worker_id,'ML-Claim',run_id,r['revision']))
    out=ROOT/'var/runs'/run_id/r['attempt'];child=None;log=None
    try:
        out.parent.mkdir(parents=True,exist_ok=True)
        argv=[sys.executable,'-m','fieldwork.ml','--data',str(ROOT/'var/images'),'--out',str(out),'--epochs',str(cfg['epochs']),'--seed',str(cfg.get('seed',42)),'--batch-size',str(cfg.get('batch_size',8)),'--learning-rate',str(cfg.get('learning_rate','.001'))]
        if proof_pause_epoch is not None:argv+=['--pause-epoch',str(proof_pause_epoch)]
        if r['checkpoint']:
            cp=s.resume_checkpoint(run_id,r['epoch'],attempt=r['attempt'])
            if not cp or cp['path']!=r['checkpoint']:raise Conflict('CHECKPOINT_POINTER_MISMATCH')
            argv+=['--resume',r['checkpoint'],'--expected-checkpoint-digest',cp['digest']]
        env={k:v for k,v in os.environ.items() if k in ['SYSTEMROOT','PATH','TEMP','TMP','USERPROFILE']};env['OMP_NUM_THREADS']='2';env['MKL_NUM_THREADS']='2'
        log=(out.parent/(r['attempt']+'.log')).open('w')
        # ML-Start (leased -> running) before any child exists.
        s.start(run_id,r['attempt'],r['fence'],r['cancel_generation'],r['digest'],restore_generation=r.get('restore_generation'),key=command_key(r['attempt'],'ML-Start'))
        r['state']='running'
        s.begin_child(run_id,r['fence'])
        try:child=subprocess.Popen(argv,env=env,stdout=log,stderr=subprocess.STDOUT,cwd=ROOT)
        except BaseException:
            s.child_spawn_failed(run_id,r['fence']);raise
        s.register_child(run_id,r['fence'],child)
        from .supervisor import watch
        watch(s,r,child,out)
        if s.get(run_id)['state']!='succeeded':return 0
        # Training success and artifact verification are separate durable outcomes.
        receipt=finalize_artifacts(s,r,out.parent,ROOT/'var/images',env)
        state=s.get(run_id)
        print(json.dumps({'run':run_id,'training_state':state['state'],'artifact_status':state['artifact_status'],'epoch':state['epoch'],'bundle_digest':receipt['bundle_digest'],'inference_pid':receipt['pid']}));return 0
    except BaseException as exc:
        if child is not None and child.poll() is None:child.kill();child.wait(timeout=10)
        # ML-Fail, fenced by this attempt's fence AND attempt id (review F10): a newer
        # attempt or a cancel/expiry that already moved the run is never overwritten.
        try:s.fail(run_id,r['attempt'],r['fence'],'WORKER_INFRASTRUCTURE_FAILED' if isinstance(exc,OSError) else 'WORKER_FAILED',isinstance(exc,OSError),digest(canonical({'type':type(exc).__name__,'message':str(exc)[:500]})),restore_generation=r.get('restore_generation'),key=command_key(r['attempt'],'ML-Fail'))
        except Conflict:pass
        raise
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:pass
        # Acknowledge only a cancel generation watch() actually observed; otherwise
        # release the slot alone and leave any cancel pending for ML-Expire.
        observed=r.get('observed_cancel_generation')
        try:
            if observed is not None:s.acknowledge_cancel(run_id,r['fence'],observed,exit_receipt=exit_receipt(r,child),key=command_key(r['attempt'],'ML-AcknowledgeCancel'))
            else:s.release_slot(run_id,fence=r['fence'])
        except BaseException as release_error:
            # Review F6: never strand the slot silently. A refused acknowledgement rolls
            # back; fall back to a plain release (no run-state change). If that is refused
            # too (child exit unconfirmed), the slot stays visibly held and the main loop
            # retries release_own_slot() every iteration.
            try:s.release_slot(run_id,fence=r['fence'])
            except BaseException as again:
                print(json.dumps({'code':'SLOT_RELEASE_DEFERRED','run':run_id,'fence':r['fence'],'first':str(release_error),'reason':str(again)}),flush=True)
        if log is not None:log.close()


def _product_lock():
    import importlib.util
    # The shared helper lives in the portfolio root's tools/ (searched upward, so mirrors work).
    path=next((p/'tools'/'product_lock.py' for p in Path(__file__).resolve().parents if (p/'tools'/'product_lock.py').exists()),None)
    if os.environ.get('PORTFOLIO_TOOLS'):path=Path(os.environ['PORTFOLIO_TOOLS'])/'product_lock.py'
    spec=importlib.util.spec_from_file_location('portfolio_product_lock',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class HostHeavyLock:
    """Optional host-wide heavy-task lock shared with sibling products (ML-T-RESOURCE:
    one host heavy task). Enabled by FIELDWORK_HOST_HEAVY_LOCK=<directory path>.
    Uses the shared portfolio helper tools/product_lock.py (review F6): atomic mkdir plus
    an atomically renamed owner record with pid AND process creation time; released only
    by its exact owner; never stolen. A crashed owner's lock is recovered only by
    `product_lock.py recover`, which requires proof that the recorded process is gone."""
    def __init__(self,path):self.path=Path(path) if path else None;self.held=False;self._lock=None
    def acquire(self,purpose):
        if self.path is None:return True
        self._lock=self._lock or _product_lock()
        self.held=self._lock.acquire('fieldwork',purpose,self.path);return self.held
    def release(self):
        if not self.held:return
        try:self._lock.release(self.path)
        finally:self.held=False


def parse_args(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--once',action='store_true');parser.add_argument('--run-id');parser.add_argument('--proof-pause-epoch',type=int);parser.add_argument('--real-runs',action='store_true')
    args=parser.parse_args(argv)
    if args.proof_pause_epoch is not None and (not args.once or not args.run_id):
        parser.error('--proof-pause-epoch requires --once and an explicit --run-id')
    if args.real_runs and args.proof_pause_epoch is not None:
        parser.error('--proof-pause-epoch is synthetic-only')
    return args


def main():
    args=parse_args();s=worker_store(real_runs=args.real_runs);s.migrate()
    process_identity=supervisor_identity()
    lock=HostHeavyLock(os.environ.get('FIELDWORK_HOST_HEAVY_LOCK'))
    model_runner=None
    from .real_model_container import ModelContainerUnavailable
    if args.real_runs:
        from .real_model_container import ModelContainerRunner
        model_image_id=os.environ.get('FIELDWORK_REAL_MODEL_IMAGE_ID','')
        private=ROOT/'.local/real-data/model-private'
        try:model_runner=ModelContainerRunner(model_image_id,private_dir=private)
        except ModelContainerUnavailable as exc:
            print(json.dumps({'code':'REAL_MODEL_CONTAINER_UNAVAILABLE','reason':exc.code}),flush=True)
            return 29
    # (run, revision) pairs refused PERMANENTLY before claim; a resumed/changed run is eligible again.
    blocked=set()
    real_failures={}
    import psycopg
    while True:
        try:
            if model_runner is not None:model_runner.recover_stale()
            # The shared fenced artifact recovery marks an expired attempt retryable.
            # Synthetic selection remains synthetic-only; real artifacts are selected
            # and replayed by the separate real capability below.
            s.recover_artifacts()
            reconciled=s.reconcile_training_slot()
            if reconciled=='RELEASED':print(json.dumps({'code':'SLOT_RECONCILED'}),flush=True)
            held=s.release_own_slot()
            if held not in (None,'RELEASED'):print(json.dumps({'code':'SLOT_HELD','reason':held}),flush=True)
        except ModelContainerUnavailable as exc:
            # Preserve the exact unresolved-container reason and stay alive but
            # idle. The next loop retries only recovery; it cannot claim work
            # while the runner's durable ownership state is ambiguous.
            held='MODEL_CONTAINER_RECOVERY_REQUIRED'
            print(json.dumps({'code':held,'reason':exc.code}),flush=True)
            beat={**process_identity,'as_of':datetime.now(timezone.utc).isoformat(),
                  'profile':'scoped-real-training-and-inference','identity':getattr(s,'identity_mode','trusted-operator'),
                  'held_slot':held,'operator_paused':operator_paused()}
            publish_worker_heartbeat(beat)
            if args.once:return 29
            time.sleep(30);continue
        except (psycopg.OperationalError,subprocess.TimeoutExpired,OSError) as exc:
            # Expired/revoked machine credential or DB unavailable: refuse work, keep beating.
            held='DB_UNAVAILABLE_OR_CREDENTIAL_REFUSED';print(json.dumps({'code':held,'error':type(exc).__name__}),flush=True)
            beat={**process_identity,'as_of':datetime.now(timezone.utc).isoformat(),'identity':getattr(s,'identity_mode','trusted-operator'),'held_slot':held}
            publish_worker_heartbeat(beat)
            if args.once:return 27
            time.sleep(30);continue
        paused=operator_paused()
        heartbeat={**process_identity,'as_of':datetime.now(timezone.utc).isoformat(),'profile':'scoped-real-training-and-inference' if args.real_runs else 'trusted-synthetic-only','hard_isolation':'decoder and model child containers required; host OS/Docker daemon remain trusted' if args.real_runs else 'not certified','identity':getattr(s,'identity_mode','trusted-operator'),'held_slot':held,'operator_paused':paused}
        publish_worker_heartbeat(heartbeat)
        if paused:
            print(json.dumps({'code':'OPERATOR_TRAINING_PAUSED','queued_jobs_unchanged':True}),flush=True)
            if args.once:return 28
            time.sleep(30);continue
        if args.run_id:rid=args.run_id;revision=None
        else:
            r=s.next_real_run(sorted(blocked)) if args.real_runs else s.next_run(sorted(blocked))
            if args.real_runs and not r:r=s.next_real_artifact(sorted(blocked))
            rid,revision=(r['id'],r['revision']) if r else (None,None)
        code=None;database_backoff=0
        if rid:
            admitted,detail=preflight(real_runs=args.real_runs)
            if args.real_runs:
                print(json.dumps({**detail,
                    'event':'RESOURCE_PREFLIGHT_ADMITTED' if admitted else 'RESOURCE_PREFLIGHT_REFUSED'},
                    sort_keys=True),flush=True)
            if not admitted:
                # Do not take the shared host lock just to be refused by the resource gate.
                code=23
            elif not lock.acquire('fieldwork training run '+rid):
                code=25;print(json.dumps({'code':'HOST_HEAVY_LOCK_BUSY'}),flush=True)
            else:
                try:
                    if args.real_runs:model_runner.set_write_budget_scope(rid)
                    if args.real_runs:
                        from . import real_artifact_pipeline
                        selected_run=s.get(rid)
                        if not selected_run:raise Conflict('REAL_RUN_NOT_FOUND')
                        if selected_run and selected_run['state']=='succeeded' and selected_run.get('artifact_status') in ('retry_pending','failed'):
                            code=0 if real_artifact_pipeline.recover_real_artifacts(rid,s,model_runner=model_runner) else 0
                        else:
                            from .real_pixel_decoder import ContainerRealPixelDecoder
                            from .container_decoder import DecoderUnavailable
                            image_id=os.environ.get('FIELDWORK_REAL_PIXEL_IMAGE_ID','')
                            private=ROOT/'.local/real-data/decoder-private'
                            try:decoder=ContainerRealPixelDecoder(image_id,private_dir=private)
                            except (DecoderUnavailable,ValueError) as exc:raise Conflict(getattr(exc,'code','REAL_PIXEL_DECODER_UNAVAILABLE')) from None
                            from .real_job import execute_real,execute_real_inference,execute_real_image_inference,execute_qualified_image_inference
                            scope=selected_run['config'].get('scope')
                            try:
                                if scope=='real-inference/v1':
                                    code=execute_real_inference(rid,s,decoder=decoder,model_runner=model_runner)
                                elif scope=='real-image-inference/v1':
                                    code=execute_real_image_inference(rid,s,decoder=decoder,model_runner=model_runner)
                                elif scope=='qualified-release-image-inference/v1':
                                    code=execute_qualified_image_inference(rid,s,decoder=decoder,model_runner=model_runner)
                                else:
                                    code=execute_real(rid,s,decoder=decoder,model_runner=model_runner,artifact_pipeline=real_artifact_pipeline)
                            except ModelContainerUnavailable:
                                raise
                            except RuntimeError as exc:
                                # Real job functions fence/fail their own attempt and
                                # verify child/container cleanup before raising. Keep
                                # the long-lived scoped worker available for later jobs.
                                code,event=_real_job_failure_summary(exc,rid,model_runner)
                                if not args.run_id and _note_real_job_failure(real_failures,(rid,revision)):
                                    blocked.add((rid,revision));event['blocked_after_repeated_failures']=True
                                print(json.dumps(event),flush=True)
                    else:
                        code=execute(rid,args.proof_pause_epoch) if args.proof_pause_epoch is not None else execute(rid)
                except Conflict as exc:
                    code=24
                    if str(exc) in PERMANENT_REFUSALS:
                        if not args.run_id:blocked.add((rid,revision));print(json.dumps({'code':'RUN_SKIPPED','run':rid,'revision':revision,'reason':str(exc)}),flush=True)
                    else:
                        code=26;print(json.dumps({'code':'RUN_RETRY_LATER','run':rid,'reason':str(exc)}),flush=True)
                except ModelContainerUnavailable as exc:
                    code=26
                    print(json.dumps({'code':'RUN_MODEL_CONTAINER_FAILED','run':rid,
                                      'reason':exc.code,
                                      'cleanup_pending':bool(model_runner and model_runner.has_unresolved_container)}),flush=True)
                except (OSError,subprocess.TimeoutExpired,psycopg.OperationalError) as exc:
                    # A per-job infrastructure failure has already been fenced by
                    # execute_real()/execute() when applicable. Keep the shared
                    # worker process alive for other queued work; expose only the
                    # exception class, never raw OS/driver text.
                    code=26
                    print(json.dumps({'code':'RUN_WORKER_INFRASTRUCTURE_FAILED',
                        'run':rid,'error':type(exc).__name__}),flush=True)
                except psycopg.Error as exc:
                    # Database permission/schema failures must remain visible
                    # without terminating the worker or mutating/requeueing the
                    # fenced run. Back off only after releasing the host lock.
                    code=26;database_backoff=30
                    state=getattr(exc,'sqlstate',None)
                    if not isinstance(state,str) or not re.fullmatch(r'[0-9A-Z]{5}',state):state=None
                    print(json.dumps({'code':'RUN_WORKER_DATABASE_FAILURE','run':rid,
                        'error':type(exc).__name__,'sqlstate':state,'automatic_reset':False,
                        'backoff_seconds':database_backoff}),flush=True)
                finally:
                    if args.real_runs and model_runner:model_runner.clear_write_budget_scope()
                    lock.release()
            if database_backoff:
                time.sleep(database_backoff)
            if args.once:return code
        elif args.once:return 0
        # Back off while resources, the shared host lock or a transient conflict persist.
        time.sleep(30 if code in (23,25) else 5 if code==26 else 2)

if __name__=='__main__':sys.exit(main())
