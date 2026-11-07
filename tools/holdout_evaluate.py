"""Round-4 milestone 4b: validation metrics, then (only if validation-feasible) the
single steward-locked holdout evaluation with the prespecified usefulness gate.

Usage: python -B tools/holdout_evaluate.py --tag cfg1 [--validation-only]
Per-item holdout rows are written ONLY to var/datasets/tf_flowers/holdout-sealed/
(steward area). Evidence directories receive aggregates and digests.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import torch
from round4_common import DS, EVIDENCE, ROOT, admin_dsn, context, write_json
from safetensors.torch import save_file
from fieldwork import holdout
from fieldwork.data import canonical, digest
from fieldwork.metrics import evaluate
from fieldwork.real_training import center, load_resized, load_selected, to_tensor
from fieldwork.store import Store

SPEC = EVIDENCE / 'useful/usefulness-spec.json'
SPEC_SHA = '8355402170d8040df61b318e647d6d3ea98df1b71f87568a7ea41d3e1e610566'
VERIFIER = ROOT / 'tools/verify_population_metrics.py'
EVALUATOR = 'fieldwork.metrics.evaluate metric-spec/v1 + tools/verify_population_metrics.py (stdlib)'


def population(manifest, split):
    members = [{'id': s['id'], 'label': s['label'], 'sha256': s['sha256'], 'group': s['group']}
               for s in sorted(manifest['samples'], key=lambda s: s['id']) if s['split'] == split]
    return members, hashlib.sha256(canonical(members)).hexdigest()


def predict(net, manifest, split, model_digest):
    rows = []
    files = {s['id']: s['file'] for s in manifest['samples'] if s['split'] == split}
    members, _ = population(manifest, split)
    torch.set_num_threads(2)
    with torch.inference_mode():
        for m in members:
            try:
                raw = Path(files[m['id']]).read_bytes()
                if hashlib.sha256(raw).hexdigest() != m['sha256']:
                    rows.append(dict(m, model=model_digest, status='missing', logits=[])); continue
                arr = center(load_resized(files[m['id']]))
            except Exception:
                rows.append(dict(m, model=model_digest, status='decode_failed', logits=[])); continue
            try:
                logits = net(to_tensor([arr]))[0].tolist()
                rows.append(dict(m, model=model_digest, status='ok', logits=logits))
            except Exception:
                rows.append(dict(m, model=model_digest, status='inference_failed', logits=[]))
    for r in rows:
        r.pop('group', None)
    return members, rows


def run_verifier(directory, members, pd, rows, model_digest, service):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'population.json').write_bytes(canonical({'classes': 5, 'population_digest': pd, 'members': members}))
    (directory / 'predictions.jsonl').write_bytes(b''.join(canonical(r) + b'\n' for r in rows))
    (directory / 'service-metrics.json').write_bytes(canonical(service))
    p = subprocess.run([sys.executable, '-I', '-B', str(VERIFIER), str(directory / 'population.json'), str(directory / 'predictions.jsonl'),
                        model_digest, str(directory / 'service-metrics.json')], capture_output=True, text=True, timeout=600)
    (directory / 'independent-report.json').write_text(p.stdout)
    rep = json.loads(p.stdout)
    return p.returncode, rep


def aggregate(m):
    return {k: m[k] for k in ('n', 'ok', 'accuracy', 'coverage', 'macro_f1', 'recall', 'precision', 'f1', 'support', 'matrix',
                              'wilson_accuracy', 'group_support', 'group_accuracy_interval', 'cross_entropy', 'disposition_counts', 'status')}


def gate(m, spec):
    t = spec['thresholds']
    checks = {
        'top1_accuracy': [m['accuracy'], m['accuracy'] is not None and m['accuracy'] >= t['top1_accuracy_min']],
        'macro_f1': [m['macro_f1'], m['macro_f1'] is not None and m['macro_f1'] >= t['macro_f1_min']],
        'per_class_recall': [m['recall'], all(r is not None and r >= t['per_class_recall_min'] for r in m['recall'])],
        'wilson95_lower': [m['wilson_accuracy'][0], m['wilson_accuracy'][0] >= t['wilson95_accuracy_lower_min']],
        'samples_per_class': [m['support'], all(s >= t['holdout_samples_per_class_min'] for s in m['support'])],
        'groups_per_class': [m['group_support'], all(g >= t['holdout_groups_per_class_min'] for g in m['group_support'])],
        'coverage': [m['coverage'], m['coverage'] == t['prediction_coverage_required']],
    }
    return checks, all(v[1] for v in checks.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tag', required=True)
    ap.add_argument('--validation-only', action='store_true')
    a = ap.parse_args()
    if hashlib.sha256(SPEC.read_bytes()).hexdigest() != SPEC_SHA:
        raise SystemExit('USEFULNESS_SPEC_CHANGED')
    spec = json.loads(SPEC.read_text())
    ctx = context()
    ws = ctx['workspace_id']
    steward = ctx['actors']['steward']
    op = Store(dsn=admin_dsn())
    with op.connect() as c:
        c.execute(holdout.HOLDOUT_SCHEMA)
        v = c.execute("SELECT id,manifest FROM fw_versions WHERE workspace=%s AND state='frozen' AND manifest->>'scope'='real-rights-cleared'", (ws,)).fetchone()
    manifest = v['manifest']
    result = json.loads((EVIDENCE / 'optimize' / a.tag / 'train-result.json').read_text())
    if result['dataset_digest'] != manifest['digest']:
        raise SystemExit('CANDIDATE_LINEAGE')
    sel = result['selected']
    net = load_selected(sel['path'], sel['checkpoint_digest'])
    cand = DS / 'candidates' / a.tag
    cand.mkdir(parents=True, exist_ok=True)
    save_file(net.state_dict(), str(cand / 'model.safetensors'))
    model_digest = hashlib.sha256((cand / 'model.safetensors').read_bytes()).hexdigest()

    # Validation (exploratory, researcher-visible) with independent verification.
    vmembers, vpd = population(manifest, 'validation')
    _, vrows = predict(net, manifest, 'validation', model_digest)
    vservice = evaluate(vmembers, [dict(r) for r in vrows], 5, model_digest)
    vcode, vrep = run_verifier(EVIDENCE / 'metrics' / a.tag / 'validation', vmembers, vpd, vrows, model_digest, vservice)
    val = {'tag': a.tag, 'model_digest': model_digest, 'checkpoint_digest': sel['checkpoint_digest'], 'selected_epoch': sel['epoch'],
           'population_digest': vpd, 'service': aggregate(vservice), 'verifier_exit': vcode,
           'verifier_population_digest_matches': vrep['population_digest_matches'], 'verifier_service_differences': vrep.get('service_differences')}
    write_json(EVIDENCE / 'metrics' / a.tag / 'validation-summary.json', val)
    print(json.dumps({'validation_accuracy': vservice['accuracy'], 'validation_macro_f1': vservice['macro_f1'], 'verifier_exit': vcode,
                      'differences': vrep.get('service_differences')}))
    feasible = vservice['accuracy'] is not None and vservice['accuracy'] >= 0.70
    if a.validation_only or not feasible:
        write_json(EVIDENCE / 'useful' / f'{a.tag}-holdout-not-consumed.json',
                   {'tag': a.tag, 'validation_accuracy': vservice['accuracy'], 'validation_feasible': feasible,
                    'holdout_consumed': False, 'reason': 'validation-only request' if a.validation_only else 'validation feasibility gate (>=0.70) not met; holdout not consumed'})
        return

    hmembers, hpd = population(manifest, 'holdout')
    plan = holdout.authorize(op, ws, steward, version_id=v['id'], version_digest=manifest['digest'], population_digest=hpd,
                             population_count=len(hmembers), model_digest=model_digest, checkpoint_digest=sel['checkpoint_digest'],
                             evaluator=EVALUATOR, spec_sha256=SPEC_SHA)
    protections = {}
    for name, actor, md in [('researcher_consume', ctx['actors']['researcher'], model_digest), ('model_swap', steward, '0' * 64)]:
        try:
            holdout.consume(op, ws, actor, plan, md)
            protections[name] = 'UNEXPECTED_ALLOW'
        except holdout.HoldoutRefused as exc:
            protections[name] = exc.code
    with op.connect() as c:
        protections['state_after_refusals'] = c.execute('SELECT state,exposures FROM fw_holdout_plans WHERE plan_id=%s', (plan,)).fetchone()
    exposed = holdout.consume(op, ws, steward, plan, model_digest)  # exposure recorded BEFORE any holdout byte is read
    members, rows = predict(net, manifest, 'holdout', model_digest)
    service = evaluate(hmembers, [dict(r) for r in rows], 5, model_digest)
    sealed = DS / 'holdout-sealed' / plan
    hcode, hrep = run_verifier(sealed, hmembers, hpd, rows, model_digest, service)
    checks, passed = gate(service, spec)
    res = {'plan_id': plan, 'state': exposed['state'], 'exposures': exposed['exposures'], 'consumed_utc': exposed['consumed_utc'],
           'model_digest': model_digest, 'checkpoint_digest': sel['checkpoint_digest'], 'version_digest': manifest['digest'],
           'population_digest': hpd, 'population_count': len(hmembers), 'usefulness_spec_sha256': SPEC_SHA,
           'metrics': aggregate(service), 'verifier_exit': hcode, 'verifier_population_digest_matches': hrep['population_digest_matches'],
           'verifier_service_differences': hrep.get('service_differences'),
           'sealed_files_sha256': {f: hashlib.sha256((sealed / f).read_bytes()).hexdigest() for f in ('population.json', 'predictions.jsonl', 'service-metrics.json', 'independent-report.json')},
           'gate_checks': checks, 'useful_model_gate_passed': passed, 'protections': protections}
    rb = canonical(json.loads(json.dumps(res, default=str)))
    holdout.record_result(op, ws, plan, digest(rb), json.loads(rb))
    write_json(EVIDENCE / 'useful' / f'{a.tag}-holdout-result.json', json.loads(rb))
    write_json(EVIDENCE / 'holdout' / f'{a.tag}-plan-and-protections.json', {k: res[k] for k in ('plan_id', 'state', 'exposures', 'consumed_utc', 'model_digest', 'population_digest', 'protections')})
    print(json.dumps({'useful_model_gate_passed': passed, 'checks': checks, 'verifier_exit': hcode}, default=str, indent=1))


if __name__ == '__main__':
    main()
