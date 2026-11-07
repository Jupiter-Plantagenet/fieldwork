"""Round-5 milestone 6: freeze candidate + usefulness spec, then ONE steward-locked evaluation
of the new protected population `commons-r5`.

freeze --tag T : candidate chosen by the prespecified rule over the config ledger (highest
                 validation top-1, ties lower validation CE); writes candidate-lock.json and
                 usefulness-spec-r5.json (thresholds copied verbatim from the round-4 spec and
                 asserted equal) and records both digests BEFORE any authorization.
evaluate       : host protocol; feasibility gate (validation top-1 >= 0.70); authorize plan
                 on the child version + new population digest; researcher/model-swap refusals;
                 steward consume (exposure recorded before any protected byte is read);
                 predict; production metrics + independent stdlib verifier (incl. 2,000-
                 resample group bootstrap); gate; result retained whether pass or fail.
                 Per-item rows go ONLY to the steward area; evidence gets aggregates/digests.
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

import torch
from round5_common import C5, EVIDENCE, R4_EVIDENCE, ROOT, STEWARD, admin_dsn, context, write_json, set_registry_env
from r5_host import heavy_slot
from r5_train import LEDGER, VERIFIER, aggregate, predict, run_verifier
from fieldwork import holdout
from fieldwork import residual_recipe as rr
from fieldwork.data import canonical, digest
from fieldwork.metrics import evaluate
from fieldwork.protected_population import population_members
from fieldwork.store import Store

NEW_TAG = 'commons-r5'
SPEC = EVIDENCE / 'useful/usefulness-spec-r5.json'
LOCKF = EVIDENCE / 'useful/candidate-lock.json'
FREEZE = EVIDENCE / 'useful/freeze-record.json'
R4_SPEC = R4_EVIDENCE / 'useful/usefulness-spec.json'


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def freeze(tag):
    if FREEZE.exists():
        raise SystemExit('ALREADY_FROZEN')
    led = json.loads(LEDGER.read_text())
    r5 = [c for c in led['configs'] if c.get('round') == 5 and c.get('complete')]
    best = max(r5, key=lambda c: (c['validation_accuracy'], -c['validation_cross_entropy']))
    if best['tag'] != tag:
        raise SystemExit(f'RULE_SELECTS_{best["tag"]}_NOT_{tag}')
    seal = json.loads((EVIDENCE / 'holdout/r5-seal.json').read_text())
    val = json.loads((EVIDENCE / 'metrics' / tag / 'validation-summary.json').read_text())
    result = json.loads((EVIDENCE / 'optimize' / tag / 'train-result.json').read_text())
    model_file = C5 / 'candidates' / tag / 'model.safetensors'
    if hashlib.sha256(model_file.read_bytes()).hexdigest() != val['model_digest']:
        raise SystemExit('CANDIDATE_BYTES_CHANGED')
    r4 = json.loads(R4_SPEC.read_text())
    spec = {'schema': 'fieldwork.usefulness-spec/v1', 'test_id': 'ML-T-USEFUL', 'round': 5,
            'frozen_utc': now(),
            'frozen_note': 'Frozen after validation-only selection and BEFORE the commons-r5 protected plan is authorized. Thresholds are copied '
                           'verbatim from the round-4 spec (sha256 8355402170d8040df61b318e647d6d3ea98df1b71f87568a7ea41d3e1e610566) and are unchanged.',
            'population': {'tag': NEW_TAG, 'version_id': seal['version_id'], 'version_digest': seal['version_digest'],
                           'population_digest': seal['population_digest'], 'population_count': seal['population_count'], 'seal_digest': seal['seal_digest']},
            'metric_spec': r4['metric_spec'], 'thresholds': r4['thresholds'], 'also_reported_not_gating': r4['also_reported_not_gating'],
            'candidate_selection': 'Validation only. Within a run: lowest complete validation CE checkpoint (ties earliest). Across round-5 configs: '
                                   'highest validation top-1 (ties lower validation CE). Cap 6 complete configs in total (round 4 used 1).',
            'feasibility_gate': 'protected population consumed only if validation top-1 >= 0.70',
            'one_shot': 'consumed at most once, for the single locked candidate',
            'failure_policy': r4['failure_policy'], 'comparison': r4['comparison']}
    if spec['thresholds'] != r4['thresholds']:
        raise SystemExit('THRESHOLDS_CHANGED')
    lock = {'tag': tag, 'recipe': rr.RECIPE, 'model_digest': val['model_digest'], 'checkpoint_digest': val['checkpoint_digest'],
            'checkpoint_path': result['selected']['path'], 'selected_epoch': result['selected']['epoch'], 'config': result['config'],
            'dataset_digest': result['dataset_digest'], 'validation_accuracy': val['service']['accuracy'],
            'validation_macro_f1': val['service']['macro_f1'], 'validation_cross_entropy': val['service']['cross_entropy'],
            'ledger_sha256': hashlib.sha256(LEDGER.read_bytes()).hexdigest(), 'frozen_utc': now()}
    write_json(SPEC, spec)
    write_json(LOCKF, lock)
    rec = {'usefulness_spec_sha256': hashlib.sha256(SPEC.read_bytes()).hexdigest(), 'candidate_lock_sha256': hashlib.sha256(LOCKF.read_bytes()).hexdigest(),
           'verifier_sha256': hashlib.sha256(VERIFIER.read_bytes()).hexdigest(), 'frozen_utc': now(), 'plan_authorized': False}
    write_json(FREEZE, rec)
    print(json.dumps({'lock': lock, 'freeze': rec}, indent=1))


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


def evaluate_once():
    set_registry_env()
    fr = json.loads(FREEZE.read_text())
    if hashlib.sha256(SPEC.read_bytes()).hexdigest() != fr['usefulness_spec_sha256'] or hashlib.sha256(LOCKF.read_bytes()).hexdigest() != fr['candidate_lock_sha256']:
        raise SystemExit('FROZEN_SPEC_OR_CANDIDATE_CHANGED')
    if hashlib.sha256(VERIFIER.read_bytes()).hexdigest() != fr['verifier_sha256']:
        raise SystemExit('VERIFIER_CHANGED')
    spec, lock = json.loads(SPEC.read_text()), json.loads(LOCKF.read_text())
    if lock['validation_accuracy'] is None or lock['validation_accuracy'] < 0.70:
        write_json(EVIDENCE / 'useful/r5-holdout-not-consumed.json', {'reason': 'validation feasibility gate not met', 'validation_accuracy': lock['validation_accuracy']})
        raise SystemExit('FEASIBILITY_GATE_NOT_MET')
    ctx = context()
    ws = ctx['workspace_id']
    steward = ctx['actors']['steward']
    op = Store(dsn=admin_dsn())
    logf = (EVIDENCE / 'holdout/r5-final-evaluation.log').open('a', encoding='utf-8')

    def log(line):
        logf.write(line + '\n'); logf.flush(); print(line, flush=True)
    evaluator = (f'fieldwork.metrics.evaluate metric-spec/v1 + tools/verify_population_metrics.py sha256={fr["verifier_sha256"]} '
                 f'(stdlib, incl. group bootstrap 2000/seed42) + residual_recipe eval preprocess')
    with heavy_slot('final-holdout-eval-commons-r5', log, data_path=C5):
        net = rr.load_model(lock['checkpoint_path'], lock['checkpoint_digest'])
        from safetensors.torch import save_file
        check = C5 / 'candidates' / (lock['tag'] + '-reexport-check.safetensors')
        save_file(net.state_dict(), str(check))
        if hashlib.sha256(check.read_bytes()).hexdigest() != lock['model_digest']:
            raise SystemExit('MODEL_DIGEST_MISMATCH')
        check.unlink()
        plan = holdout.authorize(op, ws, steward, version_id=spec['population']['version_id'], version_digest=spec['population']['version_digest'],
                                 population_digest=spec['population']['population_digest'], population_count=spec['population']['population_count'],
                                 model_digest=lock['model_digest'], checkpoint_digest=lock['checkpoint_digest'], evaluator=evaluator,
                                 spec_sha256=fr['usefulness_spec_sha256'])
        fr.update(plan_authorized=True, plan_id=plan, plan_authorized_utc=now())
        write_json(FREEZE, fr)
        prot = {}
        for name, actor, md in [('researcher_consume', ctx['actors']['researcher'], lock['model_digest']), ('reviewer_consume', ctx['actors']['reviewer'], lock['model_digest']),
                                ('model_swap', steward, '0' * 64)]:
            try:
                holdout.consume(op, ws, actor, plan, md)
                prot[name] = 'UNEXPECTED_ALLOW'
            except holdout.HoldoutRefused as exc:
                prot[name] = exc.code
        with op.connect() as c:
            st = c.execute('SELECT state,exposures FROM fw_holdout_plans WHERE plan_id=%s', (plan,)).fetchone()
            prot['state_after_refusals'] = dict(st)
        exposed = holdout.consume(op, ws, steward, plan, lock['model_digest'])   # exposure BEFORE any protected byte is read
        log(json.dumps({'event': 'exposure_recorded', 'plan_id': plan, 'state': exposed['state'], 'exposures': exposed['exposures']}))
        with op.connect() as c:
            fm = c.execute('SELECT manifest FROM fw_versions WHERE workspace=%s AND id=%s AND state=%s', (ws, spec['population']['version_id'], 'frozen')).fetchone()['manifest']
        if fm['digest'] != spec['population']['version_digest']:
            raise SystemExit('VERSION_DIGEST_MISMATCH')
        members, pd = population_members(fm, NEW_TAG)
        if pd != spec['population']['population_digest'] or len(members) != spec['population']['population_count']:
            raise SystemExit('POPULATION_DIGEST_MISMATCH')
        rows = [s for s in fm['samples'] if s['split'] == 'holdout' and s.get('holdout_population') == NEW_TAG]
        torch.set_num_threads(2)
        _, recs = predict(net, rows, lock['model_digest'])
        service = evaluate(members, [dict(r) for r in recs], 5, lock['model_digest'])
        sealed = STEWARD / 'sealed' / ('plan-' + plan)
        code, rep = run_verifier(sealed, members, pd, recs, lock['model_digest'], service)
        checks, passed = gate(service, spec)
    sealed_files = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(sealed.iterdir())}
    res = {'plan_id': plan, 'state': exposed['state'], 'exposures': exposed['exposures'], 'model_digest': lock['model_digest'],
           'checkpoint_digest': lock['checkpoint_digest'], 'candidate_tag': lock['tag'], 'recipe': lock['recipe'],
           'version_digest': spec['population']['version_digest'], 'population_tag': NEW_TAG, 'population_digest': pd, 'population_count': len(members),
           'usefulness_spec_sha256': fr['usefulness_spec_sha256'], 'candidate_lock_sha256': fr['candidate_lock_sha256'], 'evaluator': evaluator,
           'metrics': aggregate(service), 'verifier_exit': code, 'verifier_population_digest_matches': rep['population_digest_matches'],
           'verifier_service_differences': rep.get('service_differences'), 'verifier_group_bootstrap': rep.get('group_bootstrap'),
           'verifier_metrics': {k: rep[k] for k in ('accuracy', 'macro_f1', 'recall', 'wilson_accuracy', 'coverage', 'support')},
           'sealed_files_sha256': sealed_files, 'gate_checks': checks, 'useful_model_gate_passed': passed, 'protections': prot}
    rb = canonical(json.loads(json.dumps(res, default=str)))
    holdout.record_result(op, ws, plan, digest(rb), json.loads(rb))
    write_json(EVIDENCE / 'useful/r5-holdout-result.json', json.loads(rb))
    (EVIDENCE / 'useful/r5-holdout-result.sha256').write_text(digest(rb) + '\n')
    with op.connect() as c:
        stored = c.execute('SELECT state,exposures,result_sha256 FROM fw_holdout_plans WHERE plan_id=%s', (plan,)).fetchone()
    write_json(EVIDENCE / 'holdout/r5-plan-and-protections.json', {'plan_id': plan, 'stored': dict(stored), 'protections': prot,
               'evaluator': evaluator, 'per_item_location': 'steward area only (commons_r5/steward-sealed/sealed/plan-*/)'})
    print(json.dumps({'useful_model_gate_passed': passed, 'checks': checks, 'verifier_exit': code,
                      'differences': rep.get('service_differences'), 'group_bootstrap': rep.get('group_bootstrap')}, default=str, indent=1))


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('action', choices=['freeze', 'evaluate'])
    ap.add_argument('--tag')
    a = ap.parse_args()
    freeze(a.tag) if a.action == 'freeze' else evaluate_once()
