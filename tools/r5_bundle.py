"""Round-5 milestone 7: qualified-release bundle (blueprint section 8) -- ONLY if the frozen
usefulness gate passed on the commons-r5 protected plan.

build   : refuses unless r5-holdout-result.json says useful_model_gate_passed and the stored
          plan result digest matches. Re-verifies signed model_bundle rights for every
          train/validation member (fieldwork.export_rights.attach). Writes:
            manifest.json, model.safetensors, architecture.json, preprocess.json, classes.json,
            lineage.json, environment-lock.json, README.md,
            evaluation/{population.json,predictions.jsonl,metrics.json,independent-report.json}  (VALIDATION only),
            evaluation/final-acceptance-attestation.json  (steward-approved AGGREGATE only),
            rights/{review.json,notices.txt,LICENSE-tf_flowers.txt,sbom.json}
verify  : tools/verify_release_bundle.py (stdlib) in a fresh `-I` process + a steward-side scan
          that no protected sample id / digest / member / path occurs anywhere in the bundle
          bytes (reports a count only) + fresh-process inference equality vs the original run.
"""
import hashlib
import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from round5_common import (C5, EVIDENCE, R4_MANIFESTS, ROOT, STEWARD, STEWARD_LABEL, admin_dsn, context, request_store, set_registry_env,
                           write_json)
from fieldwork import residual_recipe as rr
from fieldwork.data import canonical, digest
from fieldwork.export_rights import attach
from fieldwork.intake import TAXONOMY
from fieldwork.rights import RightsService
from fieldwork.rights_registry import load_trusted_registry
from fieldwork.store import Store

OUT = C5 / 'release'
NEW_TAG = 'commons-r5'


def build():
    res = json.loads((EVIDENCE / 'useful/r5-holdout-result.json').read_text())
    if res['useful_model_gate_passed'] is not True:
        raise SystemExit('QUALIFIED_RELEASE_BLOCKED: usefulness gate did not pass')
    ctx = context()
    ws = ctx['workspace_id']
    op = Store(dsn=admin_dsn())
    with op.connect() as c:
        plan = c.execute('SELECT state,result_sha256,candidate_model_digest,usefulness_spec_sha256 FROM fw_holdout_plans WHERE plan_id=%s', (res['plan_id'],)).fetchone()
    if plan['state'] != 'consumed' or plan['result_sha256'] != (EVIDENCE / 'useful/r5-holdout-result.sha256').read_text().strip() \
            or plan['candidate_model_digest'] != res['model_digest']:
        raise SystemExit('PLAN_RESULT_MISMATCH')
    lock = json.loads((EVIDENCE / 'useful/candidate-lock.json').read_text())
    tag = lock['tag']
    out = OUT / f'{tag}-qualified'
    if out.exists():
        raise SystemExit('BUNDLE_EXISTS')
    (out / 'evaluation').mkdir(parents=True)
    (out / 'rights').mkdir()
    shutil.copyfile(C5 / 'candidates' / tag / 'model.safetensors', out / 'model.safetensors')
    if hashlib.sha256((out / 'model.safetensors').read_bytes()).hexdigest() != res['model_digest']:
        raise SystemExit('MODEL_BYTES')
    vdir = EVIDENCE / 'metrics' / tag / 'validation'
    for f in ('population.json', 'predictions.jsonl', 'independent-report.json'):
        shutil.copyfile(vdir / f, out / 'evaluation' / f)
    shutil.copyfile(vdir / 'service-metrics.json', out / 'evaluation/metrics.json')
    net = rr.build(float(lock['config']['dropout']))
    result = json.loads((EVIDENCE / 'optimize' / tag / 'train-result.json').read_text())
    payloads = {
        'architecture.json': {'schema': 1, 'id': rr.RECIPE, 'dropout': lock['config']['dropout'], 'parameters': sum(p.numel() for p in net.parameters()),
                              'state_keys': {k: v for k, v in rr.state_spec(net).items()}},
        'preprocess.json': {'schema': rr.PREPROCESS['schema'], 'eval': rr.PREPROCESS['eval'], 'eval_identical_to': rr.PREPROCESS['eval_identical_to']},
        'classes.json': [{'index': t['index'], 'id': t['id'], 'name': t['name']} for t in TAXONOMY],
        'lineage.json': {'dataset_digest': lock['dataset_digest'], 'version_id': json.loads((EVIDENCE / 'holdout/r5-seal.json').read_text())['version_id'],
                         'checkpoint_digest': lock['checkpoint_digest'], 'epoch': lock['selected_epoch'], 'model_digest': res['model_digest'],
                         'recipe': rr.RECIPE, 'config': lock['config'], 'train_result_sha256': hashlib.sha256((EVIDENCE / 'optimize' / tag / 'train-result.json').read_bytes()).hexdigest(),
                         'initial_weight_digest': result['initial_digest'], 'initialisation': 'from recorded seed; no transfer/pretrained weights',
                         'validation_population_digest': json.loads((vdir / 'population.json').read_text())['population_digest']},
        'environment-lock.json': {'python': platform.python_version(), 'platform': platform.platform(),
                                  **{p: importlib.metadata.version(p) for p in ('torch', 'numpy', 'pillow', 'safetensors')}, 'device': 'cpu', 'threads': 2},
        'evaluation/final-acceptance-attestation.json': {
            'schema': 'fieldwork.final-acceptance-attestation/v1', 'scope': 'aggregate only; no protected ids, labels, per-item outputs, media or paths',
            'test_id': 'ML-T-USEFUL', 'plan_id': res['plan_id'], 'candidate_model_digest': res['model_digest'], 'usefulness_spec_sha256': res['usefulness_spec_sha256'],
            'plan_result_sha256': plan['result_sha256'], 'independent_report_sha256': res['sealed_files_sha256']['independent-report.json'],
            'passed': True, 'population': 'commons-r5 protected population (Wikimedia Commons CC0/PD/CC BY photographs; double blind AI annotation)',
            'aggregate': {'n': res['metrics']['n'], 'accuracy': res['metrics']['accuracy'], 'macro_f1': res['metrics']['macro_f1'],
                          'recall': res['metrics']['recall'], 'wilson95_accuracy': res['metrics']['wilson_accuracy'],
                          'group_bootstrap95_accuracy': res['metrics']['group_accuracy_interval'], 'coverage': res['metrics']['coverage'],
                          'support': res['metrics']['support'], 'group_support': res['metrics']['group_support']},
            'steward': STEWARD_LABEL},
    }
    for name, value in payloads.items():
        (out / name).write_bytes(canonical(value))
    set_registry_env()
    service = RightsService(request_store(ws), load_trusted_registry)
    with op.connect() as c:
        v1 = c.execute("SELECT manifest FROM fw_versions WHERE workspace=%s AND id='01a0f1aa-90cd-4875-9060-8c8f0204520b'", (ws,)).fetchone()['manifest']
    stage = C5 / 'release' / f'{tag}-rights-stage'
    shutil.rmtree(stage, ignore_errors=True)
    review = attach(stage, service=service, workspace=ws, dataset=ctx['rights_dataset_eligible'], actor=ctx['actors']['steward'], version_manifest=v1,
                    rights_manifest=json.loads((R4_MANIFESTS / 'rights-manifest.json').read_text(encoding='utf-8')),
                    license_raw=(R4_MANIFESTS / 'LICENSE.txt').read_bytes(), steward_label=STEWARD_LABEL)
    shutil.copyfile(stage / 'rights/ATTRIBUTION.txt', out / 'rights/notices.txt')
    shutil.copyfile(stage / 'rights/LICENSE.txt', out / 'rights/LICENSE-tf_flowers.txt')
    review = dict(review, protected_population_members_included=False, commons_r5_assets_included=False,
                  note='Commons protected-holdout images are neither included nor used for training; only an aggregate attestation is included.')
    (out / 'rights/review.json').write_bytes(canonical(review))
    sbom = {'schema': 'fieldwork.sbom/v1-minimal', 'generated_from': 'importlib.metadata of the evaluation venv',
            'components': sorted(({'name': d.metadata['Name'], 'version': d.version, 'license': (d.metadata.get('License-Expression') or d.metadata.get('License') or '')[:80]}
                                  for d in importlib.metadata.distributions()), key=lambda x: x['name'].lower()),
            'model_weights': {'origin': 'trained locally from a recorded seed', 'pretrained_or_transfer_weights': None},
            'vulnerability_review': 'not performed in this lane (ML-T-RIGHTS SBOM/vulnerability clause remains open)'}
    (out / 'rights/sbom.json').write_bytes(canonical(sbom))
    (out / 'README.md').write_text(
        '# Fieldwork qualified-release bundle (small-residual/v1)\n\n'
        'Purpose: qualified_release. Five-class flower classifier (Daisy, Dandelion, Rose, Sunflower, Tulip), CPU float32.\n'
        'Entrypoint (no auto-executed hooks): `python -I -B tools/r5_bundle_infer.py --bundle <dir> --image <file> --expected-bundle-digest <sha256>`.\n'
        'Probabilities are not calibrated confidence, botanical certainty or out-of-distribution detection.\n'
        'Evaluation files are VALIDATION-only per-item evidence. The final protected-holdout result is an aggregate attestation only.\n'
        'Rights: tf_flowers CC BY 2.0 attribution in rights/notices.txt. Reviews were by an AI steward (not human, not legal advice).\n', encoding='utf-8')
    files = {p.relative_to(out).as_posix(): {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size}
             for p in sorted(out.rglob('*')) if p.is_file()}
    manifest = {'schema': 1, 'purpose': 'qualified_release', 'scope': 'real-rights-cleared', 'evidence_scope': 'validation_only+aggregate_attestation',
                'recipe': rr.RECIPE, 'files': files}
    (out / 'manifest.json').write_bytes(canonical(manifest))
    shutil.rmtree(stage, ignore_errors=True)
    bundle_digest = hashlib.sha256((out / 'manifest.json').read_bytes()).hexdigest()
    write_json(EVIDENCE / 'bundle/bundle-build.json', {'bundle': str(out), 'bundle_manifest_sha256': bundle_digest, 'files': files, 'rights_review': review})
    print(json.dumps({'bundle_manifest_sha256': bundle_digest, 'files': len(files)}, indent=1))


def verify():
    b = json.loads((EVIDENCE / 'bundle/bundle-build.json').read_text())
    out, bd = Path(b['bundle']), b['bundle_manifest_sha256']
    rep = {}
    p = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/verify_release_bundle.py'), str(out), bd], capture_output=True, text=True, timeout=600)
    rep['independent_verifier'] = {'exit': p.returncode, 'report': json.loads(p.stdout) if p.stdout.strip().startswith('{') else p.stdout[-800:], 'stderr': p.stderr[-400:]}
    # Steward-side holdout scan: every protected id/digest/member/path string must be absent (count only reported).
    sealed = json.loads((STEWARD / 'sealed/version-v2.json').read_text())
    needles = set()
    for s in sealed['samples']:
        if s['split'] == 'holdout':
            needles |= {s['id'], s['sha256'], s['source_member'], s['file'], Path(s['file']).name}
    blob = b''.join(f.read_bytes() for f in sorted(out.rglob('*')) if f.is_file())
    hits = sum(1 for n in needles if n.encode() in blob)
    rep['protected_scan'] = {'protected_strings_checked': len(needles), 'occurrences_in_bundle': hits,
                             'scope': 'all holdout members (consumed round-4 + commons-r5): ids, raw sha256, source members, paths, file names'}
    # Fresh-process inference vs original run (validation member = newly supplied rights-approved image for the bundle process).
    pop = json.loads((out / 'evaluation/population.json').read_text())
    recs = {json.loads(l)['id']: json.loads(l) for l in (out / 'evaluation/predictions.jsonl').read_text().splitlines() if l}
    with Store(dsn=admin_dsn()).connect() as c:
        ws = context()['workspace_id']
        pick = pop['members'][0]
        path = c.execute('SELECT media_path FROM fw_samples WHERE workspace=%s AND sample_id=%s', (ws, pick['id'])).fetchone()['media_path']
    q = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/r5_bundle_infer.py'), '--bundle', str(out), '--image', path,
                        '--expected-bundle-digest', bd], capture_output=True, text=True, timeout=300)
    receipt = json.loads(q.stdout)
    orig = recs[pick['id']]['logits']
    diff = max(abs(a - b) for a, b in zip(orig, receipt['logits']))
    rep['fresh_process_inference'] = {'exit': q.returncode, 'receipt': receipt, 'original_logits': orig, 'max_abs_logit_diff': diff,
                                      'top1_equal': max(range(5), key=lambda i: orig[i]) == receipt['top1'], 'within_1e-6': diff <= 1e-6,
                                      'parent_pid': __import__('os').getpid()}
    # Candidate cannot be promoted in place / tampered bundle refused.
    tam = C5 / 'release' / 'tamper-test'
    shutil.rmtree(tam, ignore_errors=True)
    shutil.copytree(out, tam)
    (tam / 'evaluation/extra-holdout.jsonl').write_text('{}\n')
    t = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/verify_release_bundle.py'), str(tam), bd], capture_output=True, text=True, timeout=600)
    rep['tamper_extra_file_rejected'] = t.returncode != 0
    shutil.rmtree(tam, ignore_errors=True)
    rep['pass'] = (p.returncode == 0 and hits == 0 and q.returncode == 0 and diff <= 1e-6 and rep['fresh_process_inference']['top1_equal']
                   and rep['tamper_extra_file_rejected'])
    write_json(EVIDENCE / 'bundle/bundle-verification.json', rep)
    print(json.dumps({k: (v if k != 'fresh_process_inference' else {x: v[x] for x in ('max_abs_logit_diff', 'top1_equal', 'exit')}) for k, v in rep.items()
                      if k != 'independent_verifier'} | {'independent_verifier_exit': p.returncode}, indent=1))


if __name__ == '__main__':
    {'build': build, 'verify': verify}[sys.argv[1]]()
