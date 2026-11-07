"""Product-only native restart fallback when process tool transport is unavailable."""
import json,os,subprocess,sys,time,uuid
from pathlib import Path
import httpx,psutil
from fieldwork.store import ROOT
from fieldwork.privacy_lifecycle import _check_c_ancestry
from fieldwork.scoped_authority import check_private


def main():
    env=dict(os.environ)
    # The registry contains public reviewer keys. Trust remains operator selected;
    # the API never receives the dataset steward's signing key or operator DSN.
    registry=ROOT/'var/commons_r5/rights/reviewers.json'
    _check_c_ancestry(registry,allow_missing_leaf=True,allow_missing_parents=True)
    if 'FIELDWORK_RIGHTS_REVIEWERS_FILE' not in env and registry.is_file():
        env['FIELDWORK_RIGHTS_REVIEWERS_FILE']=str(registry)
    var_root=ROOT/'var'
    _check_c_ancestry(var_root,allow_missing_leaf=True)
    var_root.mkdir(exist_ok=True,mode=0o700)
    _check_c_ancestry(var_root);check_private(var_root)
    log_path=var_root/'api-live.log'
    _check_c_ancestry(log_path,allow_missing_leaf=True)
    if log_path.exists():check_private(log_path)
    config_path=var_root/('api-log-config-'+uuid.uuid4().hex+'.json')
    _check_c_ancestry(config_path,allow_missing_leaf=True)
    log_config={'version':1,'disable_existing_loggers':False,
        'formatters':{'fieldwork':{'format':'%(asctime)s %(levelname)s %(name)s %(message)s'}},
        'handlers':{'fieldwork_file':{'class':'fieldwork.privacy_logging.PrivateTimedRotatingFileHandler',
            'filename':str(log_path),'when':'midnight','interval':1,'backupCount':0,
            'encoding':'utf-8','delay':True,'formatter':'fieldwork'}},
        'loggers':{'uvicorn':{'handlers':['fieldwork_file'],'level':'INFO','propagate':False},
            'uvicorn.error':{'handlers':['fieldwork_file'],'level':'INFO','propagate':False},
            'uvicorn.access':{'handlers':['fieldwork_file'],'level':'WARNING','propagate':False}},
        'root':{'handlers':['fieldwork_file'],'level':'WARNING'}}
    with os.fdopen(os.open(config_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w',encoding='utf-8') as stream:
        json.dump(log_config,stream,separators=(',',':'));stream.flush();os.fsync(stream.fileno())
    _check_c_ancestry(config_path);check_private(config_path)
    for c in psutil.net_connections('tcp'):
        if c.status=='LISTEN' and c.laddr.port==8102:
            p=psutil.Process(c.pid)
            cwd=Path(p.cwd())
            try:_check_c_ancestry(cwd)
            except ValueError:raise RuntimeError('Port8102 is not owned by this product; stop denied') from None
            if 'fieldwork.api:app' not in p.cmdline() or cwd.resolve()!=ROOT:raise RuntimeError('Port8102 is not owned by this product; stop denied')
            p.terminate();p.wait(10)
    command=[sys.executable,'-m','uvicorn','fieldwork.api:app','--host','127.0.0.1','--port','8102',
             '--no-access-log','--log-config',str(config_path)]
    process=subprocess.Popen(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        creationflags=subprocess.DETACHED_PROCESS|subprocess.CREATE_NEW_PROCESS_GROUP,close_fds=True)
    receipt={'pid':process.pid,'create_time':psutil.Process(process.pid).create_time(),
             'command':'uvicorn fieldwork.api:app --host 127.0.0.1 --port 8102',
             'log':'var/api-live.log (daily rotation; access log disabled)',
             'log_config':str(config_path.relative_to(ROOT)).replace('\\','/'),'ownership':'fieldwork-only'}
    (ROOT/'var/runtime-api.json').write_text(json.dumps(receipt,indent=2))
    for _ in range(50):
        try:
            response=httpx.get('http://127.0.0.1:8102/health/ready',timeout=1)
            if response.status_code==200:
                listener=next(c.pid for c in psutil.net_connections('tcp') if c.status=='LISTEN' and c.laddr.port==8102)
                receipt.update(launcher_pid=process.pid,pid=listener,create_time=psutil.Process(listener).create_time(),readiness='passed')
                (ROOT/'var/runtime-api.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt));return
        except httpx.HTTPError:pass
        if process.poll() is not None:raise RuntimeError('API startup failed; see private daily logs var/api-live.log.*')
        time.sleep(.1)
    raise RuntimeError('API readiness timeout; see private daily logs var/api-live.log.*')

if __name__=='__main__':main()
