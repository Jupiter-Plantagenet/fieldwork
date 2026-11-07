"""Container-integration diagnostic for the real-training pipeline (no DB, no API, no holdout).

Mirrors the worker's sequence against a pinned model image: train -> export result and
checkpoints -> bundle -> verify bundle -> fresh inference, each in its own sealed
container with an EPHEMERAL write-budget scope (never charges a real run's ledger).
Takes the shared host lock. Per the operator's instruction the available-RAM gate is not
enforced; free disk >= 12 GiB and commit < 95% are still required.

  .venv/Scripts/python -B tools/diag_real_pipeline_containers.py --image sha256:<id> \
      --inputs <real-inputs dir with CURRENT recipe/preprocess digests> --epochs 1
"""
import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / 'tools'))
import product_lock  # noqa: E402
import fieldwork.real_model_container as rmc  # noqa: E402
from fieldwork.real_bundle import verify_real_bundle  # noqa: E402
from fieldwork.real_model_container import ModelContainerRunner  # noqa: E402
from tools.diag_real_model_stage import commit_fraction  # noqa: E402

DISK_MIN = 12 * 1024 ** 3
COMMIT_HARD_STOP = 0.95


def now():
    return datetime.now(timezone.utc).isoformat()


def wait_exit(proc, timeout, report, label):
    deadline = time.monotonic() + timeout
    peak = 0
    while time.monotonic() < deadline:
        code = proc.poll()
        if code is not None:
            return code
        if commit_fraction() >= COMMIT_HARD_STOP:
            report.setdefault('aborts', []).append(label + ':COMMIT_HARD_STOP')
            proc.kill()
            return -9
        time.sleep(1)
    proc.kill()
    return -1


def container_logs(proc):
    if not proc.cid:
        return None
    r = subprocess.run(['docker', '--context', 'default', 'logs', '--tail', '30', proc.cid],
                       capture_output=True, timeout=20)
    return (r.stdout + r.stderr).decode('utf-8', 'replace')[-2500:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--image', required=True)
    ap.add_argument('--inputs', required=True, type=Path)
    ap.add_argument('--epochs', type=int, default=1)
    ap.add_argument('--batch-size', type=int, default=16)
    ap.add_argument('--timeout', type=int, default=3000)
    args = ap.parse_args()
    manifest = json.loads((args.inputs / 'inputs.json').read_text(encoding='utf-8'))
    config = {'version_digest': manifest['version_digest'], 'recipe_digest': manifest['recipe_digest'],
              'preprocess_digest': manifest['preprocess_digest'],
              'decoder_image_id': manifest['decoder_image_id'], 'epochs': args.epochs, 'seed': 42,
              'batch_size': args.batch_size, 'learning_rate': '0.001'}
    work = ROOT / '.local/real-data' / ('diag-pipeline-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    work.mkdir(parents=True)
    out, folder = work / 'training', work / 'artifact'
    out.mkdir()
    folder.mkdir()
    bundle = folder / 'bundle'
    report = {'schema': 'fieldwork.pipeline-container-diagnostic/v1', 'started': now(), 'image': args.image,
              'epochs': args.epochs, 'stages': {}, 'ram_gate': 'NOT ENFORCED (operator instruction)',
              'not_a_training_success': True}

    def save():
        (work / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')

    vm, free, commit = psutil.virtual_memory().available, psutil.disk_usage('C:/').free, commit_fraction()
    report['resources_before'] = {'available_ram_bytes': vm, 'free_disk_bytes': free, 'commit_fraction': round(commit, 4)}
    if free < DISK_MIN or commit >= COMMIT_HARD_STOP:
        report['result'] = 'REFUSED_DISK_OR_COMMIT'
        save()
        print('REFUSED', report['resources_before'])
        return 3
    if not product_lock.acquire('fieldwork', 'diag-real-pipeline-containers'):
        report['result'] = 'REFUSED_LOCK_HELD'
        save()
        print('lock held', product_lock.read_owner())
        return 4
    proc = None
    try:
        runner = ModelContainerRunner(args.image, private_dir=ROOT / '.local/real-data/model-private')

        # 1. training
        t0 = time.monotonic()
        proc = runner.start_training(args.inputs, out, config, timeout=args.timeout)
        code = wait_exit(proc, args.timeout, report, 'train')
        st = {'exit': code, 'seconds': round(time.monotonic() - t0, 1)}
        report['stages']['train'] = st
        if code != 0:
            st['child_receipt'] = _receipt(proc)
            st['logs'] = container_logs(proc)
            raise RuntimeError('train child exit %r' % code)
        proc.export_training_result(out)
        result = json.loads((out / 'result.json').read_text(encoding='utf-8'))
        for row in result['history']:
            proc.export_checkpoint(out, row['epoch'], stopped=True)
        proc.cleanup()
        proc = None
        sel = result['selected']
        st['selected'] = {k: sel[k] for k in ('epoch', 'validation_loss', 'checkpoint_digest')}
        st['history'] = [{k: r[k] for k in ('epoch', 'train_loss', 'validation_loss', 'validation_accuracy')}
                         for r in result['history']]
        ck_dir = out / ('epoch-%d' % sel['epoch'])

        # 2. bundle
        t0 = time.monotonic()
        rights = sorted({r['source_sha256'] for r in manifest['train'] + manifest['validation']})
        proc = runner.start_bundle(args.inputs, ck_dir, folder, expected_checkpoint_digest=sel['checkpoint_digest'],
                                   version_id=manifest['version_id'], version_digest=manifest['version_digest'],
                                   classes=manifest['classes'], rights_decision_digests=rights,
                                   model_image_id=args.image)
        code = wait_exit(proc, 900, report, 'bundle')
        st = report['stages']['bundle'] = {'exit': code, 'seconds': round(time.monotonic() - t0, 1)}
        if code != 0:
            st['child_receipt'] = _receipt(proc)
            st['logs'] = container_logs(proc)
            raise RuntimeError('bundle child exit %r' % code)
        receipt = json.loads(proc.read_receipt().decode('ascii'))
        proc.export_bundle(bundle)
        proc.cleanup()
        proc = None
        verify_real_bundle(bundle, expected_digest=receipt['bundle_digest'],
                           expected_lineage={'version_id': manifest['version_id'],
                                             'dataset_digest': manifest['version_digest'],
                                             'checkpoint_digest': sel['checkpoint_digest'],
                                             'recipe_digest': manifest['recipe_digest'],
                                             'preprocess_digest': manifest['preprocess_digest'],
                                             'decoder_image_id': manifest['decoder_image_id'],
                                             'model_image_id': args.image})
        st['bundle_digest'] = receipt['bundle_digest']
        st['host_verify'] = 'passed'

        # 3. fresh inference on one TRAIN image (functional proof only)
        sample = manifest['train'][0]
        entry = {k: sample[k] for k in ('id', 'split', 'pixel_file', 'width', 'height', 'decoded_pixel_sha256')}
        t0 = time.monotonic()
        proc = runner.start_inference(bundle, args.inputs, entry, receipt['bundle_digest'],
                                      model_image_id=args.image, timeout=120)
        code = wait_exit(proc, 120, report, 'inference')
        st = report['stages']['inference'] = {'exit': code, 'seconds': round(time.monotonic() - t0, 1)}
        if code != 0:
            st['logs'] = container_logs(proc)
            raise RuntimeError('inference child exit %r' % code)
        inf = json.loads(proc.read_receipt().decode('utf-8'))
        proc.cleanup()
        proc = None
        st['top1'] = inf.get('top1')
        st['logits_len'] = len(inf.get('logits', []))
        st['bundle_digest_bound'] = inf.get('bundle_digest') == receipt['bundle_digest'] if 'bundle_digest' in inf else None
        report['result'] = 'PIPELINE_OK'
    except BaseException as exc:  # noqa: BLE001
        report['result'] = 'FAILED'
        report['error'] = type(exc).__name__ + ':' + str(getattr(exc, 'code', '') or exc)[:200]
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
    print(report['result'], report.get('error'), json.dumps(report['stages'])[:1500])
    return 0 if report['result'] == 'PIPELINE_OK' else 1


def _receipt(proc):
    try:
        proc.verify_identity()
        return proc.read_receipt().decode('utf-8', 'replace')[:500]
    except Exception as exc:  # noqa: BLE001
        return 'unreadable:' + str(getattr(exc, 'code', type(exc).__name__))


if __name__ == '__main__':
    sys.exit(main())
