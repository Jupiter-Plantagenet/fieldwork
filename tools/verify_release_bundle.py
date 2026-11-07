"""Independent qualified-release bundle verifier. Python stdlib ONLY (imports nothing from fieldwork).

Usage: python -I -B verify_release_bundle.py BUNDLE_DIR EXPECTED_MANIFEST_SHA256

Checks: trusted manifest digest; exact recursive inventory (no extra/missing files, no
symlinks); per-file SHA-256/bytes; size caps; purpose `qualified_release`; safetensors
header parsed with struct/json against architecture.json key/dtype/shape set, contiguous
offsets, parameter budget, all F32 values finite; lineage model digest = file digest =
attestation digest; attestation is aggregate-only (whitelisted keys, passed=true);
evaluation evidence is the VALIDATION population named in lineage, recomputed with plain
loops (via the stdlib metric verifier loaded by path) and compared with the saved service
metrics and independent report; rights review flags exclude images/holdout members.
"""
import hashlib
import importlib.util
import json
import math
import struct
import sys
from pathlib import Path

REQUIRED = {'manifest.json', 'model.safetensors', 'architecture.json', 'preprocess.json', 'classes.json', 'lineage.json', 'environment-lock.json',
            'README.md', 'evaluation/population.json', 'evaluation/predictions.jsonl', 'evaluation/metrics.json',
            'evaluation/independent-report.json', 'evaluation/final-acceptance-attestation.json', 'rights/review.json', 'rights/notices.txt',
            'rights/LICENSE-tf_flowers.txt', 'rights/sbom.json'}
ATTEST_KEYS = {'schema', 'scope', 'test_id', 'plan_id', 'candidate_model_digest', 'usefulness_spec_sha256', 'plan_result_sha256',
               'independent_report_sha256', 'passed', 'population', 'aggregate', 'steward'}
AGG_KEYS = {'n', 'accuracy', 'macro_f1', 'recall', 'wilson95_accuracy', 'group_bootstrap95_accuracy', 'coverage', 'support', 'group_support'}
DT = {'F32': 4, 'I64': 8}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load_json(p, limit=2 * 1024 * 1024):
    p = Path(p)
    if p.is_symlink() or p.stat().st_size > limit:
        raise ValueError('JSON_SIZE_OR_SYMLINK ' + p.name)

    def pairs(kv):
        d = {}
        for k, v in kv:
            if k in d:
                raise ValueError('DUPLICATE_KEY')
            d[k] = v
        return d
    return json.loads(p.read_bytes(), object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError('NONFINITE')))


def check(bundle, expected):
    b = Path(bundle)
    rep = {}
    if b.is_symlink() or sha(b / 'manifest.json') != expected:
        raise ValueError('TRUSTED_MANIFEST_DIGEST')
    m = load_json(b / 'manifest.json')
    if set(m) != {'schema', 'purpose', 'scope', 'evidence_scope', 'recipe', 'files'} or m['purpose'] != 'qualified_release' \
            or m['evidence_scope'] != 'validation_only+aggregate_attestation':
        raise ValueError('MANIFEST_SCHEMA_PURPOSE')
    entries = list(b.rglob('*'))
    if any(e.is_symlink() for e in entries):
        raise ValueError('SYMLINK')
    actual = {e.relative_to(b).as_posix() for e in entries if e.is_file()}
    if actual != REQUIRED or set(m['files']) != REQUIRED - {'manifest.json'}:
        raise ValueError('INVENTORY extra=%s missing=%s' % (sorted(actual - REQUIRED), sorted(REQUIRED - actual)))
    total = 0
    for name, e in m['files'].items():
        size = (b / name).stat().st_size
        total += size
        if e != {'sha256': sha(b / name), 'bytes': size}:
            raise ValueError('FILE_DIGEST ' + name)
    if total > 64 * 1024 * 1024 or (b / 'model.safetensors').stat().st_size > 32 * 1024 * 1024:
        raise ValueError('SIZE_CAP')
    arch = load_json(b / 'architecture.json')
    lineage = load_json(b / 'lineage.json')
    att = load_json(b / 'evaluation/final-acceptance-attestation.json')
    # safetensors header + finiteness
    raw = (b / 'model.safetensors').read_bytes()
    n = struct.unpack('<Q', raw[:8])[0]
    if n > 256 * 1024 or n > len(raw) - 8:
        raise ValueError('TENSOR_HEADER_SIZE')
    header = json.loads(raw[8:8 + n])
    header.pop('__metadata__', None)
    expect = {k[len('model.'):]: v for k, v in arch['state_keys'].items()}
    if set(header) != set(expect):
        raise ValueError('TENSOR_KEYS')
    ranges, params, nonfinite = [], 0, 0
    payload = raw[8 + n:]
    for k, e in header.items():
        dt, shape = expect[k]
        if e['dtype'] != dt or e['shape'] != shape:
            raise ValueError('TENSOR_SHAPE ' + k)
        cnt = math.prod(shape)
        a, z = e['data_offsets']
        if z - a != cnt * DT[dt]:
            raise ValueError('TENSOR_OFFSETS')
        ranges.append((a, z))
        if dt == 'F32':
            params += cnt if not (k.endswith('running_mean') or k.endswith('running_var')) else 0
            nonfinite += sum(1 for (x,) in struct.iter_unpack('<f', payload[a:z]) if not math.isfinite(x))
    end = 0
    for a, z in sorted(ranges):
        if a != end:
            raise ValueError('TENSOR_GAP')
        end = z
    if end != len(payload) or nonfinite or params > 2_000_000 or params != arch['parameters']:
        raise ValueError('TENSOR_PAYLOAD_OR_BUDGET')
    rep['tensors'] = {'count': len(header), 'parameters': params, 'nonfinite': nonfinite}
    md = sha(b / 'model.safetensors')
    if lineage['model_digest'] != md or att['candidate_model_digest'] != md:
        raise ValueError('MODEL_IDENTITY')
    if set(att) != ATTEST_KEYS or set(att['aggregate']) != AGG_KEYS or att['passed'] is not True or att['test_id'] != 'ML-T-USEFUL':
        raise ValueError('ATTESTATION_SCOPE')
    for k in ('recall', 'support', 'group_support'):
        if len(att['aggregate'][k]) != 5:
            raise ValueError('ATTESTATION_AGGREGATE_SHAPE')
    classes = load_json(b / 'classes.json')
    if [c['index'] for c in classes] != [0, 1, 2, 3, 4] or len({c['id'] for c in classes}) != 5:
        raise ValueError('CLASS_MAP')
    # Validation-only evidence, recomputed independently.
    spec = importlib.util.spec_from_file_location('vpm', str(Path(__file__).with_name('verify_population_metrics.py')))
    vpm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vpm)
    pop = load_json(b / 'evaluation/population.json')
    if vpm.population_digest(pop['members']) != pop['population_digest'] or pop['population_digest'] != lineage['validation_population_digest']:
        raise ValueError('VALIDATION_POPULATION_IDENTITY')
    if (b / 'evaluation/predictions.jsonl').stat().st_size > 8 * 1024 * 1024:
        raise ValueError('PREDICTIONS_SIZE')
    recs = [json.loads(line) for line in (b / 'evaluation/predictions.jsonl').read_text(encoding='utf-8').splitlines() if line]
    mine = vpm.compute(pop['members'], recs, 5, md)
    mine['group_bootstrap'] = vpm.group_bootstrap(pop['members'], recs, 5)
    svc = load_json(b / 'evaluation/metrics.json')
    ind = load_json(b / 'evaluation/independent-report.json')
    d1 = vpm.compare(mine, svc)
    d2 = [k for k in ('n', 'ok', 'matrix', 'support') if mine[k] != ind.get(k)] + \
         [k for k in ('accuracy', 'macro_f1', 'coverage') if abs(mine[k] - ind[k]) > 1e-12]
    if d1 or d2:
        raise ValueError('EVALUATION_EVIDENCE_MISMATCH %s %s' % (d1, d2))
    rep['validation'] = {'n': mine['n'], 'accuracy': mine['accuracy'], 'macro_f1': mine['macro_f1'], 'service_differences': d1, 'independent_differences': d2}
    rv = load_json(b / 'rights/review.json')
    if rv.get('images_included') is not False or rv.get('holdout_members_included') is not False or rv.get('protected_population_members_included') is not False:
        raise ValueError('RIGHTS_SCOPE')
    rep['ok'] = True
    return rep


if __name__ == '__main__':
    try:
        r = check(sys.argv[1], sys.argv[2])
        print(json.dumps(r, indent=1))
        sys.exit(0)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)[:300]}))
        sys.exit(2)
