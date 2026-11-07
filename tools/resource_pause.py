"""Temporarily pause only the named local Fieldwork API/UI after a backup."""
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / 'tools'))


def main():
    import product_lock

    lock = product_lock.read_owner() or {}
    ancestors = {(p.pid,p.create_time()) for p in psutil.Process().parents()}
    if (lock.get('product'),lock.get('purpose')) != ('fieldwork','resource-quiescence') or (lock.get('pid'),lock.get('create_time')) not in ancestors:
        raise RuntimeError('ANCESTOR_RESOURCE_QUIESCENCE_LOCK_REQUIRED')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    targets = []
    for kind,port in [('api',8102),('ui',5102)]:
        listeners = {c.pid for c in psutil.net_connections('tcp') if c.status=='LISTEN' and c.laddr.port==port}
        if len(listeners) != 1:
            raise RuntimeError('EXACT_OWNED_LISTENER_REQUIRED')
        process = psutil.Process(listeners.pop())
        cwd = Path(process.cwd()).resolve()
        argv = process.cmdline()
        if kind == 'api':
            valid = cwd==ROOT and 'fieldwork.api:app' in argv
        else:
            valid = cwd in (ROOT, ROOT/'apps/web') and any(
                'vite' in arg.lower() and (cwd/arg).resolve().is_relative_to(ROOT)
                and (cwd/arg).resolve().is_file() for arg in argv)
        if not valid:
            raise RuntimeError('FIELDWORK_LISTENER_IDENTITY_MISMATCH')
        targets.append({'kind':kind,'port':port,'pid':process.pid,'created':process.create_time(),
                        'cwd':str(cwd),'argv':argv})
    # Retained DB snapshot precedes the availability change; never print secrets.
    subprocess.run([sys.executable,'-B','-m','tools.r5p_backup','resource-pause-'+stamp],cwd=ROOT,check=True,timeout=120)
    out = ROOT/'var/activation'/('resource-pause-'+stamp+'.json')
    out.parent.mkdir(parents=True,exist_ok=True)
    receipt = {'at':stamp,'purpose':'temporary commit headroom for Folio model',
               'targets':targets,'completed':False,'resume':'API via activate_real_worker restart-api; UI via recorded local argv/cwd'}
    out.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    for target in targets:
        process = psutil.Process(target['pid'])
        if abs(process.create_time()-target['created'])>=.01 or Path(process.cwd()).resolve()!=Path(target['cwd']) or process.cmdline()!=target['argv']:
            raise RuntimeError('OWNED_LISTENER_CHANGED_BEFORE_PAUSE')
        process.terminate()
        process.wait(15)
        target['exit_proven'] = True
        out.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    receipt['completed'] = True
    out.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps({'status':'paused','ports':[8102,5102],'receipt':str(out),'secret_printed':False}))


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        message = str(exc)
        print(json.dumps({'status':'failed','error_class':type(exc).__name__,'code':message if re.fullmatch('[A-Z0-9_]+',message) else None,'secret_printed':False}))
        raise SystemExit(2)
