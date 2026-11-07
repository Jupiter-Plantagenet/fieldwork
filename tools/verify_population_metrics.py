"""ML-T-METRICS independent verifier. Python stdlib ONLY; imports nothing from fieldwork.

Usage:
  python -I -B verify_population_metrics.py POPULATION.json PREDICTIONS.jsonl MODEL_DIGEST [SERVICE_METRICS.json]
  python -I -B verify_population_metrics.py --fixtures

POPULATION.json: {"classes": K, "population_digest": hex, "members": [{"id","label","sha256","group"}...]}
PREDICTIONS.jsonl: one {"id","label","sha256","model","status","logits"} per line.
It recomputes the population digest, joins both directions, rejects duplicate/extra/
wrong-model/wrong-label rows, builds integer counts with plain loops, computes
metric-spec/v1 ratios and a Wilson 95% interval, and (optionally) compares against
the service report: integer fields exactly equal, ratios within 1e-12.

Round 5 addition: when every member carries a `group`, it also computes the fixed-seed
group bootstrap (2,000 group resamples with replacement, seed 42, groups in sorted order,
nearest-rank 2.5/97.5 percentiles = draws[49]/draws[1949]) with its own loops, and the
per-class group supports; if the service report carries `group_accuracy_interval` /
`group_support` they are compared too (bounds within 1e-12, supports exactly).
"""
import hashlib
import json
import math
import sys

STATUSES = ('ok', 'missing', 'decode_failed', 'inference_failed')
Z = 1.959963984540054


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def population_digest(members):
    return hashlib.sha256(canonical(sorted(members, key=lambda m: m['id']))).hexdigest()


def compute(population, records, k, model):
    truth = {}
    for p in population:
        if p['id'] in truth:
            raise ValueError('DUPLICATE_POPULATION_ID')
        truth[p['id']] = p
    seen = set()
    matrix = [[0] * k for _ in range(k)]
    support = [0] * k
    disp = {s: 0 for s in STATUSES}
    nonok = []
    losses = []
    for r in records:
        i = r.get('id')
        if i in seen:
            raise ValueError('DUPLICATE_RECORD ' + str(i))
        if i not in truth:
            raise ValueError('EXTRA_RECORD ' + str(i))
        seen.add(i)
        t = truth[i]
        if r.get('label') != t['label'] or r.get('sha256') != t['sha256']:
            raise ValueError('IDENTITY_MISMATCH ' + i)
        if r.get('model') != model:
            raise ValueError('WRONG_MODEL ' + i)
        if r.get('status') not in STATUSES:
            raise ValueError('BAD_STATUS ' + i)
        a = t['label']
        support[a] += 1
        disp[r['status']] += 1
        if r['status'] != 'ok':
            nonok.append(i)
            continue
        lg = r['logits']
        if len(lg) != k or any(not isinstance(x, (int, float)) or not math.isfinite(x) for x in lg):
            raise ValueError('BAD_LOGITS ' + i)
        b = 0
        for j in range(1, k):
            if lg[j] > lg[b]:
                b = j
        matrix[a][b] += 1
        mx = max(lg)
        losses.append(mx + math.log(math.fsum(math.exp(x - mx) for x in lg)) - lg[a])
    if seen != set(truth):
        raise ValueError('MISSING_DISPOSITION %d' % len(set(truth) - seen))
    n = len(truth)
    ok = disp['ok']
    if n != ok + disp['missing'] + disp['decode_failed'] + disp['inference_failed']:
        raise ValueError('N_RECONCILE')
    correct = sum(matrix[j][j] for j in range(k))
    pred = [sum(matrix[a][b] for a in range(k)) for b in range(k)]
    recall, precision, f1, reasons = [], [], [], {'recall': [], 'precision': [], 'f1': []}
    for j in range(k):
        recall.append(matrix[j][j] / support[j] if support[j] else None)
        reasons['recall'].append(None if support[j] else 'no_true_support')
        precision.append(matrix[j][j] / pred[j] if pred[j] else None)
        reasons['precision'].append(None if pred[j] else 'no_predicted_support')
        den = support[j] + pred[j]
        f1.append(2 * matrix[j][j] / den if den else None)
        reasons['f1'].append(None if den else 'no_true_or_predicted_support')
    macro = sum(f1) / k if all(support) else None
    reasons['macro_f1'] = None if all(support) else 'missing_planned_class_support'
    acc = correct / n if n else None
    wilson = None
    if n:
        center = (acc + Z * Z / (2 * n)) / (1 + Z * Z / n)
        half = Z * math.sqrt(acc * (1 - acc) / n + Z * Z / (4 * n * n)) / (1 + Z * Z / n)
        wilson = [max(0.0, center - half), min(1.0, center + half)]
    return {'n': n, 'ok': ok, 'disposition_counts': disp, 'matrix': matrix, 'support': support, 'predicted_support': pred,
            'accuracy': acc, 'coverage': ok / n if n else None, 'recall': recall, 'precision': precision, 'f1': f1,
            'macro_f1': macro, 'cross_entropy': (math.fsum(losses) / ok) if ok else None, 'wilson_accuracy': wilson,
            'null_reasons': reasons, 'nonok_ids': sorted(nonok),
            'status': 'complete' if n and ok == n else 'incomplete'}


def group_bootstrap(population, records, k, replicates=2000, seed=42):
    import random
    if not population or not all(isinstance(p.get('group'), str) and p['group'] for p in population):
        return None
    truth = {p['id']: p for p in population}
    correct = set()
    for r in records:
        if r.get('status') != 'ok':
            continue
        lg = r['logits']
        b = 0
        for j in range(1, k):
            if lg[j] > lg[b]:
                b = j
        if b == truth[r['id']]['label']:
            correct.add(r['id'])
    groups = sorted({p['group'] for p in population})
    tally = {}
    for g in groups:
        hit = n = 0
        for p in population:
            if p['group'] == g:
                n += 1
                hit += 1 if p['id'] in correct else 0
        tally[g] = (hit, n)
    rng = random.Random(seed)
    draws = []
    for _ in range(replicates):
        hit = n = 0
        for __ in groups:
            h, m = tally[rng.choice(groups)]
            hit += h
            n += m
        draws.append(hit / n)
    draws.sort()
    support = []
    for c in range(k):
        support.append(len({p['group'] for p in population if p['label'] == c}))
    return {'lower': draws[int(0.025 * replicates) - 1], 'upper': draws[int(0.975 * replicates) - 1], 'replicates': replicates,
            'seed': seed, 'groups': len(groups), 'group_support': support, 'method': 'group-bootstrap/nearest-rank-v1 (independent stdlib)'}


def compare(mine, service):
    diffs = []
    for key in ('n', 'ok', 'matrix', 'support'):
        if mine[key] != service.get(key):
            diffs.append(key)
    if mine['disposition_counts'] != service.get('disposition_counts'):
        diffs.append('disposition_counts')
    for key in ('accuracy', 'coverage', 'macro_f1', 'cross_entropy'):
        a, b = mine[key], service.get(key)
        if (a is None) != (b is None) or (a is not None and abs(a - b) > 1e-12):
            diffs.append(key)
    for key in ('recall', 'precision', 'f1', 'wilson_accuracy'):
        for a, b in zip(mine[key] or [], service.get(key) or []):
            if (a is None) != (b is None) or (a is not None and abs(a - b) > 1e-12):
                diffs.append(key)
                break
    gb, sg = mine.get('group_bootstrap'), service.get('group_accuracy_interval')
    if gb is not None and sg is not None:
        if abs(gb['lower'] - sg['lower']) > 1e-12 or abs(gb['upper'] - sg['upper']) > 1e-12 or gb['replicates'] != sg['replicates']:
            diffs.append('group_accuracy_interval')
        if service.get('group_support') is not None and gb['group_support'] != service['group_support']:
            diffs.append('group_support')
    return diffs


def fixtures():
    pop = [{'id': f'f{i}', 'label': i % 3, 'sha256': '0' * 64, 'group': f'g{i}'} for i in range(6)]
    model = 'm' * 64

    def rec(i, status='ok', logits=None):
        p = pop[i]
        return {'id': p['id'], 'label': p['label'], 'sha256': p['sha256'], 'model': model, 'status': status,
                'logits': logits if logits is not None else [1.0 if j == p['label'] else 0.0 for j in range(3)]}
    out = {}
    full = compute(pop, [rec(i) for i in range(6)], 3, model)
    out['all_correct'] = full['accuracy'] == 1.0 and full['status'] == 'complete'
    r = compute(pop, [rec(0, 'missing', []), rec(1, 'decode_failed', []), rec(2, 'inference_failed', [])] + [rec(i) for i in range(3, 6)], 3, model)
    out['missing_counts_wrong'] = r['accuracy'] == 0.5 and r['coverage'] == 0.5 and r['n'] == 6 and r['status'] == 'incomplete'
    zero = compute([p for p in pop if p['label'] != 2], [rec(i) for i in range(6) if pop[i]['label'] != 2], 3, model)
    out['zero_support_null_with_reason'] = zero['recall'][2] is None and zero['null_reasons']['recall'][2] == 'no_true_support' and zero['macro_f1'] is None
    for name, recs in [('duplicate_rejected', [rec(0), rec(0)] + [rec(i) for i in range(1, 6)]),
                       ('extra_rejected', [rec(i) for i in range(6)] + [dict(rec(0), id='zz')]),
                       ('missing_disposition_rejected', [rec(i) for i in range(5)]),
                       ('wrong_model_rejected', [dict(rec(0), model='x' * 64)] + [rec(i) for i in range(1, 6)]),
                       ('wrong_label_rejected', [dict(rec(0), label=1)] + [rec(i) for i in range(1, 6)]),
                       ('nonfinite_rejected', [rec(0, logits=[float('nan'), 0.0, 0.0])] + [rec(i) for i in range(1, 6)])]:
        try:
            compute(pop, recs, 3, model)
            out[name] = False
        except ValueError:
            out[name] = True
    tie = compute(pop[:1], [rec(0, logits=[0.5, 0.5, 0.5])], 3, model)
    out['tie_lowest_index'] = tie['matrix'][0][0] == 1
    return out


def main(argv):
    if argv[1:] == ['--fixtures']:
        res = fixtures()
        print(json.dumps({'fixtures': res, 'all_pass': all(res.values())}, indent=1))
        return 0 if all(res.values()) else 1
    pop_doc = json.load(open(argv[1], encoding='utf-8'))
    records = [json.loads(line) for line in open(argv[2], encoding='utf-8') if line.strip()]
    model = argv[3]
    members = pop_doc['members']
    pd = population_digest(members)
    report = {'population_digest_recomputed': pd, 'population_digest_matches': pd == pop_doc['population_digest']}
    report.update(compute(members, records, pop_doc['classes'], model))
    report['group_bootstrap'] = group_bootstrap(members, records, pop_doc['classes'])
    if len(argv) > 4:
        service = json.load(open(argv[4], encoding='utf-8'))
        report['service_differences'] = compare(report, service)
        report['service_agreement'] = not report['service_differences']
    print(json.dumps(report, indent=1))
    return 0 if report['population_digest_matches'] and not report.get('service_differences') else 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
