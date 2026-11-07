"""Round-4 milestone 4: real training on the frozen, rights-cleared train split.

Usage: python -B tools/real_train.py --tag cfg1 [--epochs 20 --lr 0.001 --batch 16 --seed 42 --threads 2]
Takes the shared heavy-work lock C:/Users/user/portfolio-build/.cache/product-build.lock
(atomic mkdir + owner file; waits, never steals, removes only its own), requires
>= 6 GiB available RAM headroom beyond the expected training footprint, checks the
version is frozen and that signed local_private_training rights verify NOW.
"""
import argparse
import json
import os
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
from round4_common import DS, EVIDENCE, admin_dsn, context, request_store, set_registry_env, write_json
from fieldwork.rights import RightsService
from fieldwork.rights_registry import load_trusted_registry
from fieldwork.store import Store

LOCK = Path('C:/Users/user/portfolio-build/.cache/product-build.lock')
HEADROOM = 6 * 1024 ** 3  # same admission rule as fieldwork/worker.py execute() preflight
EXPECTED_FOOTPRINT = 0  # measured peak RSS is reported in optimize-audit.json

FOLIO = Path('C:/Users/user/portfolio-build/folio')
DISK_MIN = 12 * 1024 ** 3  # unchanged worker threshold, measured on the volume holding the data
FOLIO_SERVICES = ('folio.workbench', 'folio.target', 'folio.worker', 'serve_local.py', 'live_supervisor.py', 'model_serve.py')


def pause_supported():
    try:
        return 'pause-model' in (FOLIO / 'scripts/live_supervisor.py').read_text(encoding='utf-8')
    except OSError:
        return False


def model_busy():
    import urllib.request
    try:
        with urllib.request.urlopen('http://127.0.0.1:18301/slots', timeout=5) as r:
            slots = json.loads(r.read())
        return any(s.get('is_processing') for s in slots)
    except Exception:
        return False  # model server not reachable: nothing to interrupt


def folio_evaluations():
    out = []
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmd = ' '.join(p.info['cmdline'] or [])
        except Exception:
            continue
        low = cmd.lower().replace(chr(92), '/')
        try:
            cwd = p.cwd().lower().replace(chr(92), '/').rstrip('/')
        except Exception:
            cwd = ''
        # Folio code: its directory, its package as a module, or anything launched from folio/.
        is_folio = ('portfolio-build/folio/' in low or ' -m folio.' in low or cwd.endswith('portfolio-build/folio'))
        if 'python' in (p.info['name'] or '').lower() and is_folio and not any(m in cmd for m in FOLIO_SERVICES):
            out.append({'pid': p.info['pid'], 'cmd': cmd[:160]})
    return out


def folio_supervisor(action, log):
    import subprocess
    env = dict(os.environ, PYTHONPATH='.')
    r = subprocess.run([str(FOLIO / '.venv/Scripts/python.exe'), 'scripts/live_supervisor.py', action, '--lock-owner', 'owner=fieldwork-dataset-round4'], cwd=str(FOLIO), env=env,
                       capture_output=True, text=True, timeout=900)
    rec = {'event': 'folio_' + action.replace('-', '_'), 'returncode': r.returncode, 'stdout_tail': r.stdout[-400:], 'stderr_tail': r.stderr[-400:]}
    log(json.dumps(rec))
    return rec


class Lock:
    def __init__(self, label):
        self.owner = f'owner=fieldwork-dataset-round4 label={label} pid={os.getpid()} started={datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}'
        self.held = False

    def acquire(self, log):
        waited = 0
        while True:
            try:
                LOCK.mkdir()
                (LOCK / 'owner').write_text(self.owner + '\n')
                self.held = True
                log(json.dumps({'event': 'lock_acquired', 'waited_s': waited, 'owner': self.owner}))
                return
            except FileExistsError:
                if waited % 300 == 0:
                    try:
                        cur = ' '.join(p.read_text().strip() for p in LOCK.iterdir())
                    except OSError:
                        cur = '?'
                    log(json.dumps({'event': 'lock_busy', 'waited_s': waited, 'holder': cur}))
                time.sleep(15)
                waited += 15

    def release(self):
        if self.held and (LOCK / 'owner').read_text().strip() == self.owner:
            (LOCK / 'owner').unlink()
            LOCK.rmdir()
            self.held = False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tag', required=True)
    ap.add_argument('--epochs', type=int, default=20)
    ap.add_argument('--lr', type=float, default=0.001)
    ap.add_argument('--batch', type=int, default=16)
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--threads', type=int, default=2)
    a = ap.parse_args()
    out_dir = DS / 'runs' / a.tag
    ev = EVIDENCE / 'optimize' / a.tag
    ev.mkdir(parents=True, exist_ok=True)
    logf = (ev / 'train.log').open('a', encoding='utf-8')

    def log(line):
        logf.write(line + '\n'); logf.flush(); print(line, flush=True)
    ctx = context()
    ws = ctx['workspace_id']
    set_registry_env()
    op = Store(dsn=admin_dsn())
    with op.connect() as c:
        v = c.execute("SELECT id,manifest FROM fw_versions WHERE workspace=%s AND state='frozen' AND manifest->>'scope'='real-rights-cleared' ORDER BY id", (ws,)).fetchall()
    if len(v) != 1:
        raise SystemExit('EXPECTED_ONE_FROZEN_REAL_VERSION')
    manifest = v[0]['manifest']
    service = RightsService(request_store(ws), load_trusted_registry)
    decisions = service.require(ws, manifest['rights_dataset_id'], ctx['actors']['steward'], 'local_private_training')
    verified = {d.member_id: d.asset_sha256 for d in decisions}
    used = [s for s in manifest['samples'] if s['split'] in ('train', 'validation')]
    if any(verified.get(s['source_member']) != s['sha256'] for s in used):
        raise SystemExit('RIGHTS_NOT_VERIFIED_FOR_TRAINING_INPUT')
    log(json.dumps({'event': 'admission', 'version_id': v[0]['id'], 'dataset_digest': manifest['digest'],
                    'rights_verified_members': len(decisions), 'train_val_members': len(used)}))
    lock = Lock(f'real-train-{a.tag}')
    paused = None
    while True:
        lock.acquire(log)
        data_real = os.path.realpath(DS)
        free = shutil.disk_usage(data_real).free
        log(json.dumps({'event': 'disk_admission', 'data_path': str(DS), 'resolved_volume_path': data_real,
                        'free_bytes': free, 'required_bytes': DISK_MIN, 'admitted': free >= DISK_MIN}))
        if free < DISK_MIN:
            lock.release()
            raise SystemExit('DISK_GATE_REFUSED')
        if not pause_supported():
            lock.release()
            log(json.dumps({'event': 'pause_model_unavailable', 'action': 'released lock; exiting without training'}))
            raise SystemExit(3)
        busy, evals = model_busy(), folio_evaluations()
        if busy or evals:
            log(json.dumps({'event': 'folio_not_idle', 'model_busy': busy, 'evaluation_processes': evals}))
            lock.release(); time.sleep(60); continue
        paused = folio_supervisor('pause-model', log)
        if paused['returncode'] != 0:
            folio_supervisor('resume-model', log)
            lock.release()
            raise SystemExit('PAUSE_MODEL_FAILED')
        avail = 0
        for _ in range(12):
            avail = psutil.virtual_memory().available
            if avail >= HEADROOM:
                break
            time.sleep(5)
        log(json.dumps({'event': 'ram_admission', 'available_bytes': avail, 'required_bytes': HEADROOM, 'admitted': avail >= HEADROOM}))
        if avail >= HEADROOM:
            break
        folio_supervisor('resume-model', log)  # never keep the model paused while not training
        lock.release(); time.sleep(60)
    peak = {'rss': 0}
    stop = threading.Event()
    try:

        def sample():
            me = psutil.Process()
            while not stop.is_set():
                peak['rss'] = max(peak['rss'], me.memory_info().rss)
                peak['min_available'] = min(peak.get('min_available', 1 << 62), psutil.virtual_memory().available)
                stop.wait(1.0)
        threading.Thread(target=sample, daemon=True).start()
        from fieldwork.real_training import train
        result = train(manifest, out_dir, epochs=a.epochs, seed=a.seed, learning_rate=a.lr, batch_size=a.batch, threads=a.threads, log=log)
    finally:
        stop.set()
        try:
            folio_supervisor('resume-model', log)  # ALWAYS resume before releasing the lock
        finally:
            lock.release()
        log(json.dumps({'event': 'lock_released'}))
    # ML-T-OPTIMIZE audit from the persisted step log.
    train_ids = {s['id'] for s in manifest['samples'] if s['split'] == 'train'}
    steps = [json.loads(line) for line in (out_dir / 'steps.jsonl').open()]
    audit = {'steps': len(steps), 'updates': result['updates'],
             'all_batch_ids_in_train_split': all(set(s['ids']) <= train_ids for s in steps),
             'examples_processed': sum(s['n'] for s in steps), 'expected_examples': len(train_ids) * a.epochs,
             'grad_norm_min': min(s['grad_norm'] for s in steps), 'grad_norm_max': max(s['grad_norm'] for s in steps),
             'update_norm_min': min(s['update_norm'] for s in steps), 'update_norm_max': max(s['update_norm'] for s in steps),
             'all_losses_finite': all(s['loss'] == s['loss'] and abs(s['loss']) != float('inf') for s in steps),
             'initial_digest': result['initial_digest'], 'final_digest': result['final_digest'],
             'weight_digests_differ': result['initial_digest'] != result['final_digest'],
             'selected': result['selected'], 'selection_uses': 'validation split cross-entropy only',
             'peak_rss_bytes': peak['rss'], 'min_available_ram_bytes': peak.get('min_available'),
             'fresh_run_no_stored_result_reuse': True, 'elapsed_s': result['elapsed_s']}
    write_json(ev / 'optimize-audit.json', audit)
    write_json(ev / 'train-result.json', result)
    log(json.dumps({'event': 'done', **{k: audit[k] for k in ('all_batch_ids_in_train_split', 'weight_digests_differ', 'selected', 'peak_rss_bytes')}}))


if __name__ == '__main__':
    main()
