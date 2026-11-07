"""ML-T-REPLAY comparison: an uninterrupted control run vs a run killed after committed epoch K and resumed.

Compares what the frozen condition names: committed epoch history (no duplicates, replay epoch only), checkpoint digests,
final parameters (max abs diff <= 1e-6 over every tensor), and the bundle's evaluation predictions on the same pinned
samples (top-1 identical, max abs logit diff <= 1e-6). Any disagreement fails the envelope.

  .venv/Scripts/python -B tools/compare_replay_runs.py --control <run> --replayed <run> --out <json>
"""
import argparse
import json
import sys
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from safetensors.numpy import load_file

ROOT = Path(__file__).resolve().parents[1]
PARAM_TOL = 1e-6
LOGIT_TOL = 1e-6


def bundle_dir(run):
    base = ROOT / 'var/runs' / run
    cands = sorted(p for p in base.iterdir() if p.name.startswith('real-artifact-attempt-') and (p / 'bundle' / 'model.safetensors').is_file())
    if not cands:
        raise SystemExit('NO_BUNDLE_FOR_' + run)
    return cands[-1] / 'bundle'


def predictions(path):
    rows = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        r = json.loads(line)
        rows[r['id']] = r
    return rows


def run_rows(run):
    local = json.loads((ROOT / '.local.json').read_text(encoding='utf-8'))
    p = conninfo_to_dict(local['dsn'])
    p['connect_timeout'] = 3
    with psycopg.connect(**p, row_factory=dict_row) as c:
        r = c.execute('SELECT id,state,epoch,fence,artifact_status,config FROM public.fw_runs WHERE id=%s', (run,)).fetchone()
        ev = c.execute("SELECT seq,kind,payload FROM public.fw_events WHERE run=%s AND kind='epoch_committed' ORDER BY seq", (run,)).fetchall()
    return r, ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--control', required=True)
    ap.add_argument('--replayed', required=True)
    ap.add_argument('--killed-after-epoch', type=int, required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    cr, cev = run_rows(a.control)
    rr, rev = run_rows(a.replayed)
    report = {'schema': 'fieldwork.replay-comparison/v1', 'control': a.control, 'replayed': a.replayed,
              'killed_after_epoch': a.killed_after_epoch, 'tolerances': {'param_max_abs': PARAM_TOL, 'logit_max_abs': LOGIT_TOL}}
    c_epochs = [e['payload']['epoch'] for e in cev]
    r_epochs = [e['payload']['epoch'] for e in rev]
    k = a.killed_after_epoch
    cfg_keys = ('epochs', 'batch_size', 'learning_rate', 'seed', 'version_id', 'version_revision')
    report['config_equal'] = all(cr['config'].get(x) == rr['config'].get(x) for x in cfg_keys)
    report['epoch_history'] = {'control': c_epochs, 'replayed': r_epochs,
                               'no_duplicate_committed_epochs': len(set(r_epochs)) == len(r_epochs),
                               'control_complete': c_epochs == list(range(1, len(c_epochs) + 1)),
                               'replayed_rows_are_replay_epochs_only_after_kill': sorted(set(r_epochs)) == sorted(set(c_epochs)) and
                               [e for e in r_epochs if e <= k] == list(range(1, k + 1))}
    # epochs committed before the kill are the shared prefix; every replayed epoch row must match the control's epoch row
    def metrics(ev):
        return {e['payload']['epoch']: {x: e['payload'].get(x) for x in ('train_loss', 'validation_loss', 'updates', 'manifest_digest')} for e in ev}
    cm, rm = metrics(cev), metrics(rev)
    report['epoch_rows_equal_after_kill'] = {str(e): cm.get(e) == rm.get(e) for e in rm if e > k}
    report['epoch_rows_equal_before_kill'] = {str(e): cm.get(e) == rm.get(e) for e in rm if e <= k}
    cb, rb = bundle_dir(a.control), bundle_dir(a.replayed)
    ct, rt = load_file(str(cb / 'model.safetensors')), load_file(str(rb / 'model.safetensors'))
    report['param_keys_equal'] = sorted(ct) == sorted(rt)
    worst = 0.0
    bad = []
    for name in sorted(ct):
        if name not in rt or ct[name].shape != rt[name].shape:
            bad.append(name)
            continue
        d = float(abs(ct[name].astype('float64') - rt[name].astype('float64')).max()) if ct[name].size else 0.0
        worst = max(worst, d)
    report['param_max_abs_diff'] = worst
    report['param_mismatch_names'] = bad
    cp, rp = predictions(cb / 'evaluation/predictions.jsonl'), predictions(rb / 'evaluation/predictions.jsonl')
    report['prediction_ids_equal'] = sorted(cp) == sorted(rp)
    top1_disagree, worst_logit = [], 0.0
    for i in sorted(set(cp) & set(rp)):
        lc, lr = cp[i].get('logits'), rp[i].get('logits')
        if lc is None or lr is None:
            if cp[i].get('status') != rp[i].get('status'):
                top1_disagree.append(i)
            continue
        if lc.index(max(lc)) != lr.index(max(lr)):
            top1_disagree.append(i)
        worst_logit = max(worst_logit, max(abs(x - y) for x, y in zip(lc, lr)))
    report['predictions'] = {'n_control': len(cp), 'n_replayed': len(rp), 'top1_disagreements': len(top1_disagree),
                             'logit_max_abs_diff': worst_logit}
    report['bundle_model_digest_equal'] = (json.loads((cb / 'manifest.json').read_text()).get('model_digest') ==
                                           json.loads((rb / 'manifest.json').read_text()).get('model_digest')) if (cb / 'manifest.json').is_file() else None
    ok = (report['config_equal'] and report['epoch_history']['no_duplicate_committed_epochs'] and report['param_keys_equal'] and not bad
          and worst <= PARAM_TOL and report['prediction_ids_equal'] and not top1_disagree and worst_logit <= LOGIT_TOL
          and all(report['epoch_rows_equal_after_kill'].values()) and all(report['epoch_rows_equal_before_kill'].values()))
    report['within_frozen_envelope'] = bool(ok)
    Path(a.out).write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k2: report[k2] for k2 in ('config_equal', 'param_max_abs_diff', 'predictions', 'within_frozen_envelope')}))
    return 0 if ok else 3


if __name__ == '__main__':
    sys.exit(main())
