"""Restart Fieldwork's scoped worker and issuer with training admission paused.

Run only beneath PB/tools/round5_locked_step.py with a purpose containing
``platform-restart``. Partial starts are stopped by exact PID+birth identity; their
logs and a private failure receipt remain for diagnosis.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

import psutil

ROOT=Path(__file__).resolve().parents[1]
WORKER_ID='fieldwork-retained-r5'
IDENTITY='scoped-worker-v1'


def _load_product_lock():
    helper=ROOT.parent/'tools'/'product_lock.py'
    spec=importlib.util.spec_from_file_location('portfolio_product_lock',helper)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_enclosing_lock():
    lock=_load_product_lock()
    owner=lock.read_owner()
    state=lock.owner_gone(owner) if owner else (True,'OWNER_RECORD_MISSING')
    if not restart_lock_matches(owner,state,_process_ancestry(os.getpid())):
        raise RuntimeError('PLATFORM_RESTART_NOT_CHILD_OF_LOCK_OWNER')
    return owner


def ancestry_contains(ancestry, pid, create_time):
    return (type(pid) is int and type(create_time) in (int,float) and
            isinstance(ancestry,(list,tuple)) and any(
                isinstance(item,dict) and type(item.get('pid')) is int and item.get('pid')==pid and
                type(item.get('create_time')) in (int,float) and abs(item['create_time']-create_time)<.01
                for item in ancestry))


def restart_lock_matches(owner, owner_state, ancestry):
    if not isinstance(owner,dict) or not isinstance(owner_state,tuple) or len(owner_state)!=2:return False
    gone,reason=owner_state
    if gone or reason!='OWNER_ALIVE' or owner.get('product')!='fieldwork':return False
    if not isinstance(owner.get('purpose'),str) or 'platform-restart' not in owner['purpose'].split():return False
    return ancestry_contains(ancestry,owner.get('pid'),owner.get('create_time'))


def worker_heartbeat_matches(beat, *, pid, create_time, parent_pid, parent_create_time,
                             worker_id, nonce_sha256, now=None, max_age=60):
    """Pure fail-closed check for a fresh pause heartbeat from this exact launch."""
    try:
        from datetime import datetime
        import math
        now=time.time() if now is None else now
        created=beat['create_time']
        as_of=datetime.fromisoformat(beat['as_of']).timestamp()
        age=now-as_of
        return (type(beat.get('pid')) is int and beat['pid']==pid and
                type(created) in (int,float) and abs(created-create_time)<.01 and
                beat.get('parent_pid')==parent_pid and
                type(beat.get('parent_create_time')) in (int,float) and
                abs(beat['parent_create_time']-parent_create_time)<.01 and
                beat.get('identity')==IDENTITY and beat.get('worker_id')==worker_id and
                beat.get('pause_nonce_sha256')==nonce_sha256 and
                beat.get('operator_paused') is True and math.isfinite(age) and -5<=age<=max_age)
    except (KeyError,TypeError,ValueError,OverflowError):
        return False


def issuer_rotation_matches(authority, *, previous_password_sha256, previous_rotated_utc):
    """Return true only after the issuer changes the private password and timestamp."""
    try:
        password=authority['connection']['password']
        rotated=authority['rotated_utc']
        return (isinstance(password,str) and
                hashlib.sha256(password.encode()).hexdigest()!=previous_password_sha256 and
                isinstance(rotated,str) and rotated!=previous_rotated_utc)
    except (KeyError,TypeError,AttributeError):
        return False


def _same_process(pid, created):
    try:
        process=psutil.Process(pid)
        if abs(process.create_time()-created)>=.01:
            return None
        return process
    except psutil.NoSuchProcess:
        return None


def _process_ancestry(pid, limit=16):
    """Capture a bounded leaf-to-root PID+birth chain; unreadable links fail closed."""
    chain=[]
    try:
        current=psutil.Process(pid)
        for _ in range(limit):
            chain.append({'pid':current.pid,'create_time':current.create_time()})
            parent=current.parent()
            if parent is None:break
            current=parent
    except psutil.Error:
        return []
    return chain


def _recorded_process_is_expected(kind, record):
    pid=record.get('pid')
    if type(pid) is not int or pid<=0:
        raise RuntimeError('RECORDED_PLATFORM_PROCESS_IDENTITY_INCOMPLETE:'+kind)
    incomplete=(type(record.get('create_time')) not in (int,float) or not record.get('identity'))
    if incomplete:
        try:
            psutil.Process(pid)
        except psutil.NoSuchProcess:
            canonical=json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
            return {'schema':'fieldwork.runtime-legacy-absence-audit.v1','kind':kind,'pid':pid,
                    'absence_proof':'psutil.NoSuchProcess','pid_absence_observed_utc':datetime.now(timezone.utc).isoformat(),
                    'legacy_record_sha256':hashlib.sha256(canonical).hexdigest()}
        except psutil.Error as exc:
            raise RuntimeError('RECORDED_PLATFORM_PROCESS_UNINSPECTABLE:'+kind) from exc
        raise RuntimeError('RECORDED_PLATFORM_PROCESS_IDENTITY_INCOMPLETE_LIVE:'+kind)
    process=_same_process(record['pid'],record['create_time'])
    if process is None:
        return False
    try:
        cmdline=process.cmdline()
        cwd=Path(process.cwd()).resolve()
    except psutil.Error as exc:
        raise RuntimeError('RECORDED_PLATFORM_PROCESS_UNINSPECTABLE:'+kind) from exc
    module='fieldwork.worker' if kind=='worker' else 'fieldwork.worker_identity'
    expected=('-m' in cmdline and module in cmdline and cwd==ROOT.resolve())
    if kind=='worker-issuer':
        expected=expected and 'serve' in cmdline
    if not expected or record.get('identity')!=IDENTITY:
        raise RuntimeError('RECORDED_PLATFORM_PROCESS_IDENTITY_MISMATCH:'+kind)
    raise RuntimeError('RECORDED_PLATFORM_PROCESS_STILL_LIVE:'+kind)


def _launch_identity(process, role, parent_pid, parent_create_time):
    created=psutil.Process(process.pid).create_time()
    return {'pid':process.pid,'create_time':created,'parent_pid':parent_pid,
            'parent_create_time':parent_create_time,'identity':IDENTITY,'role':role,
            'caller_ancestry_verified':ancestry_contains(_process_ancestry(process.pid),parent_pid,parent_create_time)}


def _module_process_record(pid, created, launch, module, extra_marker=None):
    process=_same_process(pid,created)
    if process is None:return None
    try:
        parent=process.parent()
        cmd=process.cmdline()
        parent_pid=parent.pid if parent else None
        parent_created=parent.create_time() if parent else None
        ancestry=_process_ancestry(process.pid)
        valid=(Path(process.cwd()).resolve()==ROOT.resolve() and '-m' in cmd and module in cmd and
               ancestry_contains(ancestry,launch['pid'],launch['create_time']))
        if extra_marker is not None:
            valid=valid and extra_marker in cmd
        if not valid or not process.is_running() or process.status()==psutil.STATUS_ZOMBIE:return None
        return {'pid':process.pid,'create_time':process.create_time(),'parent_pid':parent_pid,
                'parent_create_time':parent_created,'identity':IDENTITY,'launch_pid':launch['pid'],
                'launch_create_time':launch['create_time'],'role':module}
    except psutil.Error:
        return None


def _find_module_process(launch, module, extra_marker=None):
    root=_same_process(launch['pid'],launch['create_time'])
    if root is None:return None
    try:candidates=[root,*root.children(recursive=True)]
    except psutil.Error:return None
    matches=[]
    for candidate in candidates:
        result=_module_process_record(candidate.pid,candidate.create_time(),launch,module,extra_marker)
        if result is not None:matches.append(result)
    if not matches:return None
    lineages={(item['pid'],item['create_time']):_process_ancestry(item['pid']) for item in matches}
    leaves=[]
    for item in matches:
        is_parent=any((other['pid'],other['create_time'])!=(item['pid'],item['create_time']) and
                      ancestry_contains(lineages[(other['pid'],other['create_time'])],item['pid'],item['create_time'])
                      for other in matches)
        if not is_parent:leaves.append(item)
    return leaves[0] if len(leaves)==1 else None


def _module_process_live(record, launch, module, extra_marker=None):
    current=_module_process_record(record['pid'],record['create_time'],launch,module,extra_marker)
    return (current is not None and current.get('parent_pid')==record.get('parent_pid') and
            type(current.get('parent_create_time')) in (int,float) and
            abs(current['parent_create_time']-record.get('parent_create_time',0))<.01)


def _stop_owned_tree(record, popen=None, known_descendants=(), cleanup_receipts=None):
    child_receipts=[]
    if cleanup_receipts is not None:cleanup_receipts.append(child_receipts)
    if popen is not None and popen.pid!=record['pid']:
        return False
    process=_same_process(record['pid'],record['create_time'])
    if process is None:
        descendants=[]
        for item,handle in known_descendants:
            if handle is None or handle.pid!=item['pid']:
                return False
            descendants.append((handle,item['create_time']))
        if popen is None:return False
    else:
        try:
            descendants=[(p,p.create_time()) for p in process.children(recursive=True)]
        except psutil.Error:
            return False
        for item,handle in known_descendants:
            if handle is None or handle.pid!=item['pid']:
                return False
            if not any(p.pid==handle.pid and abs(created-item['create_time'])<.01
                       for p,created in descendants):
                descendants.append((handle,item['create_time']))
    if process is None and not descendants:
        # A launcher may have detached a module child before its tree was captured.
        return False
    deadline=time.monotonic()+15
    for child,created in reversed(descendants):
        stopped=_terminate_and_wait(child,created,deadline)
        child_receipts.append({'pid':child.pid,'create_time':created,'exit_proven':stopped})
        if not stopped:return False
    root_exit_proven=False
    if popen is not None:
        try:
            if popen.poll() is None:popen.kill()
            popen.wait(timeout=max(0,deadline-time.monotonic()))
            root_exit_proven=popen.returncode is not None
            if not root_exit_proven:return False
        except (OSError,subprocess.TimeoutExpired):
            return False
    else:
        root_exit_proven=_terminate_and_wait(process,record['create_time'],deadline)
    return root_exit_proven


def _cleanup_launched_processes(launched, launch_handles, process_handles):
    """Clean once per Popen root while also proving each recorded module exit."""
    outcomes={}
    launch_items=[item for item in launched if item['role'].endswith('-launcher')]
    for launch in reversed(launch_items):
        key=(launch['pid'],launch['create_time'])
        handle=launch_handles.get(key)
        actuals=[item for item in launched if (item.get('launch_pid'),item.get('launch_create_time'))==key]
        known=[]
        for item in actuals:
            actual_key=(item['pid'],item['create_time'])
            actual_handle=process_handles.get(actual_key)
            if actual_handle is None:
                actual_handle=_same_process(item['pid'],item['create_time'])
                if actual_handle is not None:process_handles[actual_key]=actual_handle
            known.append((item,actual_handle))
        descendant_receipts=[]
        stopped=_stop_owned_tree(launch,handle,known,descendant_receipts)
        root_exit=bool(handle is not None and handle.returncode is not None)
        child_proofs=descendant_receipts[0] if descendant_receipts else []
        for item in actuals:
            actual_handle=process_handles.get((item['pid'],item['create_time']))
            actual_exit=bool(actual_handle is not None and actual_handle.pid==item['pid'] and
                any(proof['pid']==item['pid'] and abs(proof['create_time']-item['create_time'])<.01 and
                    proof['exit_proven'] for proof in child_proofs))
            outcomes[item['role']]={'stopped':bool(stopped and actual_exit),'popen_returncode':None,
                                    'root_exit_proven':actual_exit}
        outcomes[launch['role']]={'stopped':stopped,'popen_returncode':handle.returncode if handle is not None else None,
                                  'root_exit_proven':root_exit,
                                  'descendants':child_proofs}
    return outcomes


def _terminate_and_wait(process, create_time, deadline):
    """Use the captured process handle for positive exit, not PID disappearance alone."""
    while True:
        try:
            if abs(process.create_time()-create_time)>=.01:return True
            process.kill()
            remaining=deadline-time.monotonic()
            if remaining<=0:return False
            process.wait(timeout=min(.5,remaining))
            return True
        except psutil.NoSuchProcess:
            return True
        except psutil.TimeoutExpired:
            if time.monotonic()>=deadline:return False
        except psutil.Error:
            return False


def _read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _authority_directory():
    """Resolve the private authority directory on C: before opening its contents."""
    pointer=ROOT/'.cache/r5-platform/worker-authority-dir.txt'
    raw=pointer.read_text(encoding='utf-8').strip()
    if re.match(r'^[A-Za-z]:[\\/]',raw) is None or raw[0].casefold()!='c':
        raise RuntimeError('WORKER_AUTHORITY_DIRECTORY_MUST_BE_ABSOLUTE_C_PATH')
    path=Path(os.path.abspath(raw))
    if path.drive.casefold()!='c:':
        raise RuntimeError('WORKER_AUTHORITY_DIRECTORY_MUST_RESOLVE_TO_C')
    if os.name=='nt':
        current=Path(path.anchor)
        for component in path.parts[1:]:
            current=current/component
            try:metadata=os.lstat(current)
            except FileNotFoundError:break
            if getattr(metadata,'st_file_attributes',0)&0x400:
                raise RuntimeError('WORKER_AUTHORITY_DIRECTORY_REPARSE_POINT_REFUSED')
    return path


def _queued_state_snapshot(operator_file):
    """Read-only digest of every queued run's ID, state, fence and revision."""
    import psycopg
    dsn=_read_json(operator_file)['dsn']
    with psycopg.connect(dsn) as connection:
        with connection.transaction():
            connection.execute('SET TRANSACTION READ ONLY')
            rows=connection.execute("SELECT id::text,state,fence,revision FROM fw_runs WHERE state='queued' ORDER BY id").fetchall()
    canonical=json.dumps([{'id':r[0],'state':r[1],'fence':r[2],'revision':r[3]} for r in rows],
                         sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    return {'count':len(rows),'sha256':hashlib.sha256(canonical).hexdigest()}


def _write_failure(stamp, stage, launched, marker, logs, queue_before=None, queue_after=None):
    path=ROOT/'.local/round5-resume'/('platform-restart-failure-'+stamp+'.json')
    path.parent.mkdir(parents=True,exist_ok=True)
    receipt={'stage':stage,'processes':launched,'logs':logs,
             'queued_before':queue_before,'queued_after':queue_after,
             'pause_marker_sha256':hashlib.sha256(marker.read_bytes()).hexdigest() if marker.exists() else None}
    with path.open('x',encoding='utf-8') as out:
        json.dump(receipt,out,indent=2)


def main():
    require_enclosing_lock()
    stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
    authority_dir=_authority_directory()
    authority_file=authority_dir/'worker-authority.json'
    for kind in ('worker','worker-issuer'):
        path=ROOT/'var'/('runtime-'+kind+'.json')
        if path.exists():
            old=_read_json(path)
            legacy_audit=_recorded_process_is_expected(kind,old)
            archive=ROOT/'.local/runtime-archive'/stamp
            archive.mkdir(parents=True,exist_ok=True)
            shutil.copy2(path,archive/path.name)
            if legacy_audit is not None:
                audit_path=archive/(path.stem+'-legacy-absence-audit.json')
                with audit_path.open('x',encoding='utf-8') as out:
                    json.dump(legacy_audit,out,indent=2)

    subprocess.run([sys.executable,'-B','-m','tools.r5p_backup','round5-resume-pre-worker'],cwd=ROOT,check=True)
    from fieldwork.worker_identity import _rotate_file
    rotation=_rotate_file(str(ROOT/'.local.json'),str(authority_file),300)
    authority_before=_read_json(authority_file)
    password_before=hashlib.sha256(authority_before['connection']['password'].encode()).hexdigest()
    rotated_before=authority_before.get('rotated_utc')

    marker=ROOT/'.local/worker-training.pause'
    marker.parent.mkdir(parents=True,exist_ok=True)
    if marker.exists():
        archive=ROOT/'.local/runtime-archive'/stamp
        archive.mkdir(parents=True,exist_ok=True)
        shutil.copy2(marker,archive/'worker-training.pause.previous')
    nonce=secrets.token_urlsafe(32)
    marker.write_text(nonce,encoding='utf-8')
    nonce_digest=hashlib.sha256(nonce.encode()).hexdigest()
    parent=psutil.Process()
    parent_pid=parent.pid
    parent_created=parent.create_time()
    env={k:v for k,v in os.environ.items() if k in ('SYSTEMROOT','PATH','TEMP','TMP','USERPROFILE')}
    env.update(FIELDWORK_WORKER_AUTHORITY=str(authority_file),
             FIELDWORK_HOST_HEAVY_LOCK=str(ROOT.parent/'.cache/product-build.lock'),
             FIELDWORK_WORKER_ID=WORKER_ID,FIELDWORK_TRAINING_PAUSE_FILE=str(marker),
             FIELDWORK_TRAINING_PAUSE_NONCE=nonce,PYTHONDONTWRITEBYTECODE='1')
    flags=subprocess.DETACHED_PROCESS|subprocess.CREATE_NEW_PROCESS_GROUP
    launched=[]
    launch_handles={}
    process_handles={}
    logs=[]
    queue_before=None
    queue_after=None
    stage='worker-start'
    try:
        queue_before=_queued_state_snapshot(ROOT/'.local.json')
        worker_log=ROOT/'var'/('worker-resume-'+stamp+'.log')
        logs.append(str(worker_log.relative_to(ROOT)))
        with worker_log.open('xb') as out:
            process=subprocess.Popen([sys.executable,'-B','-m','fieldwork.worker'],cwd=ROOT,env=env,
                                     stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,
                                     creationflags=flags,close_fds=True)
        worker_launch=_launch_identity(process,'worker-launcher',parent_pid,parent_created)
        worker_launch['log']=str(worker_log.relative_to(ROOT))
        launched.append(worker_launch)
        launch_handles[(worker_launch['pid'],worker_launch['create_time'])]=process
        if not worker_launch['caller_ancestry_verified']:
            raise RuntimeError('Popen_PROCESS_OUTSIDE_CALLER_ANCESTRY:worker')
        worker=None
        for _ in range(180):
            beat=_read_json(ROOT/'var/worker.json') if (ROOT/'var/worker.json').exists() else {}
            if type(beat.get('pid')) is int and type(beat.get('create_time')) in (int,float):
                actual=_module_process_record(beat['pid'],beat['create_time'],worker_launch,'fieldwork.worker')
                if actual and worker_heartbeat_matches(beat,pid=actual['pid'],create_time=actual['create_time'],
                        parent_pid=actual['parent_pid'],parent_create_time=actual['parent_create_time'],
                        worker_id=WORKER_ID,nonce_sha256=nonce_digest,max_age=60):
                    worker={**actual,'role':'worker-process','worker_id':WORKER_ID,
                            'log':worker_launch['log']}
                    launched.append(worker)
                    process_handles[(worker['pid'],worker['create_time'])]=psutil.Process(worker['pid'])
                    break
            if _same_process(worker_launch['pid'],worker_launch['create_time']) is None:
                raise RuntimeError('SCOPED_WORKER_EXITED_BEFORE_PAUSED_HEARTBEAT')
            time.sleep(.5)
        else:
            raise RuntimeError('SCOPED_WORKER_PAUSED_HEARTBEAT_TIMEOUT')

        stage='issuer-start'
        issuer_log=ROOT/'var'/('worker-issuer-resume-'+stamp+'.log')
        logs.append(str(issuer_log.relative_to(ROOT)))
        with issuer_log.open('xb') as out:
            issuer_process=subprocess.Popen([sys.executable,'-B','-m','fieldwork.worker_identity','serve',
                '--authority-file',str(authority_file),'--worker-heartbeat',str(ROOT/'var/worker.json'),
                '--interval','60','--ttl-seconds','300'],cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
                stdout=out,stderr=subprocess.STDOUT,creationflags=flags,close_fds=True)
        issuer_launch=_launch_identity(issuer_process,'issuer-launcher',parent_pid,parent_created)
        issuer_launch['log']=str(issuer_log.relative_to(ROOT))
        launched.append(issuer_launch)
        launch_handles[(issuer_launch['pid'],issuer_launch['create_time'])]=issuer_process
        if not issuer_launch['caller_ancestry_verified']:
            raise RuntimeError('Popen_PROCESS_OUTSIDE_CALLER_ANCESTRY:issuer')
        issuer=None

        stage='issuer-rotation'
        for _ in range(30):
            if _same_process(issuer_launch['pid'],issuer_launch['create_time']) is None:
                raise RuntimeError('WORKER_ISSUER_EXITED_OR_IDENTITY_MISMATCH')
            if issuer is None:
                issuer=_find_module_process(issuer_launch,'fieldwork.worker_identity','serve')
                if issuer is not None:
                    issuer.update(role='issuer-process',log=issuer_launch['log'])
                    launched.append(issuer)
                    process_handles[(issuer['pid'],issuer['create_time'])]=psutil.Process(issuer['pid'])
            current=_read_json(authority_file)
            if issuer is not None and _module_process_live(issuer,issuer_launch,'fieldwork.worker_identity','serve') and issuer_rotation_matches(current,previous_password_sha256=password_before,
                                       previous_rotated_utc=rotated_before):
                beat=_read_json(ROOT/'var/worker.json')
                if not worker_heartbeat_matches(beat,pid=worker['pid'],create_time=worker['create_time'],
                        parent_pid=worker['parent_pid'],parent_create_time=worker['parent_create_time'],worker_id=WORKER_ID,
                        nonce_sha256=nonce_digest,max_age=60):
                    raise RuntimeError('SCOPED_WORKER_PAUSED_HEARTBEAT_STALE_AFTER_ISSUER_START')
                break
            time.sleep(.5)
        else:
            raise RuntimeError('WORKER_ISSUER_ROTATION_NOT_OBSERVED')
        if not _module_process_live(worker,worker_launch,'fieldwork.worker') or not _module_process_live(issuer,issuer_launch,'fieldwork.worker_identity','serve'):
            raise RuntimeError('SCOPED_PLATFORM_PROCESS_DIED_AFTER_START')
        queue_after=_queued_state_snapshot(ROOT/'.local.json')
        if queue_after!=queue_before:
            raise RuntimeError('QUEUED_RUNS_CHANGED_DURING_PAUSED_STARTUP')
        records={kind:{k:item[k] for k in ('pid','create_time','parent_pid','parent_create_time','identity','launch_pid','launch_create_time','log')}
                 for kind,item in [('worker',worker),('worker-issuer',issuer)]}
        for kind,record in records.items():
            (ROOT/'var'/('runtime-'+('worker-issuer' if kind=='worker-issuer' else 'worker')+'.json')).write_text(
                json.dumps({**record,'started_utc':stamp,'training_paused':True,'worker_id':WORKER_ID},indent=2),encoding='utf-8')
        success=ROOT/'.local/round5-resume'/('platform-restart-success-'+stamp+'.json')
        with success.open('x',encoding='utf-8') as out:
            json.dump({'rotation_verified':True,'processes':records,'queued_before':queue_before,
                       'queued_after':queue_after,'queued_unchanged':True,'pause_nonce_printed':False},out,indent=2)
        print(json.dumps({'rotation_verified':True,'processes':{k:{'pid':v['pid'],'identity':v['identity']} for k,v in records.items()},
                          'queued_before':queue_before,'queued_after':queue_after,'queued_unchanged':True,
                          'pause_nonce_printed':False}))
    except BaseException as exc:
        stopped=_cleanup_launched_processes(launched,launch_handles,process_handles)
        _write_failure(stamp,stage,[{**item,'cleanup':stopped.get(item['role'])} for item in launched],marker,logs,queue_before,queue_after)
        raise RuntimeError('PLATFORM_STARTUP_FAILED:'+stage+':'+type(exc).__name__) from exc


if __name__=='__main__':
    main()
