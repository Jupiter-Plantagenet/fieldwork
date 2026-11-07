"""Cold-process real inference benchmark (ML-T-INFERPERF), no DB / API / holdout.

Each sample is a fresh sealed container: stage a one-pixel-file volume + the verified bundle, run
`fieldwork.real_infer_child` on CPU, read the typed receipt, clean up. Timing is wall-clock from the
`start_inference` call to the parsed receipt (container create + volume stage + Python/torch start + inference).
Frozen target: p95 <= 10 s over 30 cold runs. "Warm" is not applicable to this product path (every request
is a new container); that is stated rather than simulated.

  .venv/Scripts/python -B tools/bench_real_inference_cold.py --run <control run id> --n 30
"""
import argparse
import json
import math
import shutil
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / 'tools'))
import product_lock  # noqa: E402
from fieldwork.real_model_container import ModelContainerRunner  # noqa: E402

IMAGE = 'sha256:41c680046133d0920a217adbfb951b8c77e4cec7e3ea7763646b19c5f4e7dfdc'


def pct(values, q):
    s = sorted(values)
    k = max(0, math.ceil(q * len(s)) - 1)  # nearest-rank
    return s[k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run', required=True)
    ap.add_argument('--bundle-digest', required=True)
    ap.add_argument('--n', type=int, default=30)
    args = ap.parse_args()
    run_dir = ROOT / 'var/runs' / args.run
    attempt = next(p for p in run_dir.iterdir() if (p / 'real-inputs').is_dir())
    inputs = attempt / 'real-inputs'
    bundle = next(p for p in run_dir.iterdir() if p.name.startswith('real-artifact-attempt-')) / 'bundle'
    manifest = json.loads((inputs / 'inputs.json').read_text(encoding='utf-8'))
    row = manifest['train'][0]
    entry = {k: row[k] for k in ('id', 'split', 'pixel_file', 'width', 'height', 'decoded_pixel_sha256')}
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    work = ROOT / '.local/real-data' / ('bench-inference-cold-' + stamp)
    pixels = work / 'pixels'
    pixels.mkdir(parents=True)
    shutil.copy2(inputs / row['pixel_file'], pixels / row['pixel_file'])
    report = {'schema': 'fieldwork.inference-cold-benchmark/v1', 'started': datetime.now(timezone.utc).isoformat(),
              'run': args.run, 'bundle_digest': args.bundle_digest, 'image': IMAGE, 'n': args.n,
              'host': {'cpu_count': psutil.cpu_count(), 'total_ram_bytes': psutil.virtual_memory().total,
                       'available_ram_bytes_at_start': psutil.virtual_memory().available},
              'threshold_p95_seconds': 10.0, 'warm': 'not applicable: every product inference request is a new container',
              'ram_gate': 'not enforced (operator instruction)', 'samples': []}
    if not product_lock.acquire('fieldwork', 'bench-inference-cold'):
        print('lock held', product_lock.read_owner())
        return 4
    try:
        runner = ModelContainerRunner(IMAGE, private_dir=ROOT / '.local/real-data/model-private')
        for i in range(args.n):
            t0 = time.perf_counter()
            proc = None
            try:
                proc = runner.start_inference(bundle, pixels, entry, args.bundle_digest, model_image_id=IMAGE, timeout=120)
                deadline = time.monotonic() + 120
                while proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                code = proc.poll()
                ok = code == 0 and json.loads(proc.read_receipt().decode('utf-8')).get('bundle_digest') == args.bundle_digest
                dt = time.perf_counter() - t0
                report['samples'].append({'i': i, 'seconds': round(dt, 3), 'exit': code, 'ok': bool(ok)})
            finally:
                if proc is not None:
                    if proc.poll() is None:
                        proc.kill()
                    proc.cleanup()
    finally:
        product_lock.release()
        shutil.rmtree(pixels, ignore_errors=True)
    secs = [s['seconds'] for s in report['samples'] if s['ok']]
    report['ok_count'] = len(secs)
    if secs:
        report['stats'] = {'min': min(secs), 'p50': pct(secs, .5), 'p95': pct(secs, .95), 'max': max(secs),
                           'mean': round(statistics.mean(secs), 3)}
        report['p95_within_threshold'] = report['stats']['p95'] <= 10.0 and len(secs) == args.n
    report['finished'] = datetime.now(timezone.utc).isoformat()
    (work / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report.get(k) for k in ('ok_count', 'stats', 'p95_within_threshold')}), str(work / 'report.json'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
