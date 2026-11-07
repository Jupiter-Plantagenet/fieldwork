"""Model-stage-only diagnostic for the failed real training attempt 5a1.

Re-runs the pinned real-model child against a PRESERVED, already-validated staged
input directory and records the container's exit state (ExitCode, OOMKilled, Error),
sampled memory use and the child's typed failure receipt BEFORE cleanup.

This is a diagnostic, not an API-accepted training success: it touches no database,
queue, API, checkpoint lineage or holdout data, and its write budget scope is
ephemeral (it never charges a real run's ledger). It takes the shared host lock and
enforces the unchanged resource gates.

Usage (from the fieldwork dir):
  .venv/Scripts/python -B tools/diag_real_model_stage.py --inputs <real-inputs dir> --epochs 1
"""
import argparse
import json
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
PB = ROOT.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PB / 'tools'))
import product_lock  # noqa: E402
import fieldwork.real_model_container as rmc  # noqa: E402
from fieldwork.real_model_container import ModelContainerRunner  # noqa: E402

# DIAGNOSTIC ONLY (this process): keep the child's stderr in Docker's log store so a
# startup traceback can be read before cleanup. Production keeps --log-driver=none.
_orig_docker = rmc._docker


def _docker_with_logs(*a):
    return _orig_docker(*['--log-driver=json-file' if x == '--log-driver=none' else x for x in a])


rmc._docker = _docker_with_logs

RAM_MIN = 6 * 1024 ** 3
DISK_MIN = 12 * 1024 ** 3
COMMIT_MAX = 0.85
MODEL_IMAGE = 'sha256:41c680046133d0920a217adbfb951b8c77e4cec7e3ea7763646b19c5f4e7dfdc'


def now():
    return datetime.now(timezone.utc).isoformat()


def commit_fraction():
    import ctypes

    class PERF(ctypes.Structure):
        _fields_ = [('cb', ctypes.c_ulong)] + [(n, ctypes.c_size_t) for n in (
            'CommitTotal', 'CommitLimit', 'CommitPeak', 'PhysicalTotal', 'PhysicalAvailable',
            'SystemCache', 'KernelTotal', 'KernelPaged', 'KernelNonpaged', 'PageSize')] + [
            ('HandleCount', ctypes.c_ulong), ('ProcessCount', ctypes.c_ulong), ('ThreadCount', ctypes.c_ulong)]
    perf = PERF()
    perf.cb = ctypes.sizeof(perf)
    if not ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(perf), perf.cb):
        raise OSError('GetPerformanceInfo failed')
    return perf.CommitTotal / perf.CommitLimit


def gates():
    avail = psutil.virtual_memory().available
    free = psutil.disk_usage('C:/').free
    commit = commit_fraction()
    ok = avail >= RAM_MIN and free >= DISK_MIN and commit < COMMIT_MAX
    return ok, {'available_ram_bytes': avail, 'free_disk_bytes': free, 'commit_fraction': round(commit, 4)}


def docker_json(*args):
    r = subprocess.run(['docker', '--context', 'default', *args], capture_output=True, timeout=20)
    return r.returncode, r.stdout.decode('utf-8', 'replace').strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--inputs', required=True, type=Path)
    ap.add_argument('--epochs', type=int, default=1)
    ap.add_argument('--batch-size', type=int, default=16)
    ap.add_argument('--learning-rate', default='0.001')
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--timeout', type=int, default=3000)
    args = ap.parse_args()

    manifest = json.loads((args.inputs / 'inputs.json').read_text(encoding='utf-8'))
    config = {'version_digest': manifest['version_digest'], 'recipe_digest': manifest['recipe_digest'],
              'preprocess_digest': manifest['preprocess_digest'],
              'decoder_image_id': manifest['decoder_image_id'], 'epochs': args.epochs,
              'seed': args.seed, 'batch_size': args.batch_size, 'learning_rate': args.learning_rate}
    tag = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    work = ROOT / '.local/real-data' / f'diag-model-stage-{tag}'
    work.mkdir(parents=True)
    out = work / 'training'
    out.mkdir()
    report = {'schema': 'fieldwork.model-stage-diagnostic/v1', 'started': now(), 'config': {
        k: config[k] for k in ('epochs', 'seed', 'batch_size', 'learning_rate')},
        'inputs': str(args.inputs), 'train_rows': len(manifest['train']),
        'validation_rows': len(manifest['validation']), 'samples': [], 'not_a_training_success': True}

    def save():
        (work / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')

    ok, g = gates()
    report['gate_before'] = g
    if not ok:
        report['result'] = 'REFUSED_RESOURCE_GATE'
        save()
        print(json.dumps(report['gate_before']), 'REFUSED')
        return 3
    if not product_lock.acquire('fieldwork', 'diag-real-model-stage-5a1'):
        report['result'] = 'REFUSED_LOCK_HELD'
        save()
        print('lock held:', product_lock.read_owner())
        return 4
    proc = None
    try:
        runner = ModelContainerRunner(MODEL_IMAGE, private_dir=ROOT / '.local/real-data/model-private')
        proc = runner.start_training(args.inputs, out, config, timeout=args.timeout)
        report['container_id'] = proc.cid
        stop = threading.Event()

        def sample():
            while not stop.wait(5):
                if not proc.cid:
                    continue
                rc, text = docker_json('stats', '--no-stream', '--format', '{{json .}}', proc.cid)
                if rc == 0 and text:
                    try:
                        s = json.loads(text)
                        report['samples'].append({'t': now(), 'mem': s.get('MemUsage'), 'pct': s.get('MemPerc'),
                                                  'cpu': s.get('CPUPerc')})
                    except ValueError:
                        pass
                a, gg = gates()
                if not a:
                    report.setdefault('gate_dips', []).append({'t': now(), **gg})
        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        code = None
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            code = proc.poll()
            if code is not None:
                break
            time.sleep(1)
        stop.set()
        report['poll_returncode'] = code
        report['last_state'] = {k: v for k, v in (proc._last_state or {}).items()
                                if k in ('Status', 'Running', 'OOMKilled', 'ExitCode', 'Error', 'Dead', 'Paused')}
        if proc.cid:
            rc, text = docker_json('inspect', '--format', '{{json .State}}', proc.cid)
            if rc == 0:
                try:
                    st = json.loads(text)
                    report['docker_state'] = {k: st.get(k) for k in ('Status', 'OOMKilled', 'ExitCode', 'Error',
                                                                      'StartedAt', 'FinishedAt')}
                except ValueError:
                    pass
        if proc.cid:
            rc, text = docker_json('logs', '--tail', '40', proc.cid)
            r2 = subprocess.run(['docker', '--context', 'default', 'logs', '--tail', '40', proc.cid],
                                capture_output=True, timeout=20)
            report['container_logs_tail'] = (r2.stdout + r2.stderr).decode('utf-8', 'replace')[-4000:]
        try:
            proc.verify_identity()
            report['child_receipt'] = proc.read_receipt().decode('utf-8', 'replace')[:2000]
        except Exception as exc:  # noqa: BLE001 - diagnostic only
            report['child_receipt_error'] = type(exc).__name__ + ':' + str(getattr(exc, 'code', ''))
        try:
            report['exported'] = sorted(p.name for p in out.rglob('*') if p.is_file())[:50]
        except OSError:
            pass
        report['result'] = 'CHILD_EXITED_%s' % code if code is not None else 'TIMEOUT'
    except BaseException as exc:  # noqa: BLE001
        report['result'] = 'HARNESS_ERROR'
        report['error'] = type(exc).__name__ + ':' + str(getattr(exc, 'code', ''))
        raise
    finally:
        try:
            if proc is not None:
                if proc.poll() is None:
                    proc.kill()
                proc.cleanup()
                report['cleanup'] = 'ok'
        except BaseException as exc:  # noqa: BLE001
            report['cleanup'] = 'FAILED:' + type(exc).__name__ + ':' + str(getattr(exc, 'code', ''))
        report['finished'] = now()
        save()
        product_lock.release()
    print(report.get('result'), json.dumps(report.get('docker_state')), report.get('child_receipt'))
    return 0 if report.get('result') == 'CHILD_EXITED_0' else 1


if __name__ == '__main__':
    sys.exit(main())
