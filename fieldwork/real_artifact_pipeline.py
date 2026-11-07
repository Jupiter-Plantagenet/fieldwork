"""Private real-data bundle publication and fresh-process inference."""
from __future__ import annotations
import base64, json, re, subprocess, threading
from pathlib import Path
from .data import canonical, digest
from .real_bundle import verify_real_bundle
from .store import ROOT, Conflict
from .supervisor import command_key


def _fresh_bundle_rights(store, attempt, samples):
    evidence = store.real_artifact_rights(attempt['id'], attempt['fence'])
    if (type(evidence) is not dict or evidence.get('version_id') != attempt['config']['version_id']
            or evidence.get('version_digest') != attempt['config']['version_digest']):
        raise Conflict('REAL_BUNDLE_RIGHTS_BINDING')
    rows = evidence.get('rights')
    if type(rows) is not list:
        raise Conflict('REAL_BUNDLE_RIGHTS_SCOPE')
    expected = {}
    for sample in samples:
        prior = expected.get(sample['source_member'])
        if prior and prior.get('source_sha256') != sample.get('source_sha256'):
            raise Conflict('REAL_BUNDLE_MEMBER_ASSET_AMBIGUOUS')
        expected[sample['source_member']] = sample
    if {r.get('source_member') for r in rows} != set(expected):
        raise Conflict('REAL_BUNDLE_RIGHTS_SCOPE')
    from .rights_decision import ExpectedFacts, verify_decision, DecisionRejected
    from .rights_registry import load_trusted_registry
    verified = []
    for row in rows:
        member = row.get('source_member')
        sample = expected.get(member)
        if sample is None or row.get('sample_id') not in {s['id'] for s in samples if s['source_member'] == member}:
            raise Conflict('REAL_BUNDLE_RIGHTS_SCOPE')
        try:
            facts = ExpectedFacts(**row['rights_facts'])
            decision = verify_decision(base64.b64decode(row['rights_envelope_b64'], validate=True),
                registry=load_trusted_registry(), expected=facts)
        except (DecisionRejected, KeyError, TypeError, ValueError):
            raise Conflict('REAL_BUNDLE_RIGHTS_REVOKED_OR_INVALID') from None
        if (facts.workspace_id != attempt['config']['workspace']
                or facts.dataset_id != attempt['config']['dataset_id'] or facts.purpose != 'model_bundle'
                or facts.member_id != row.get('source_member')
                or facts.asset_sha256 != row.get('asset_sha256')):
            raise Conflict('REAL_BUNDLE_RIGHTS_BINDING')
        if (row.get('source_member') != sample.get('source_member')
                or row.get('asset_sha256') != sample.get('source_sha256')):
            raise Conflict('REAL_BUNDLE_RIGHTS_ASSET_MISMATCH')
        verified.append({**row, 'decision_digest': decision.decision_digest})
    return verified


def finalize_real_artifacts(store, attempt, output, input_dir, input_binding, *, decoder=None,
                            model_runner=None, rights_check=None):
    """Build a distinct private-real bundle; no synthetic verifier or route is reused."""
    run_id, fence = attempt['id'], attempt['fence']
    output, input_dir = Path(output), Path(input_dir)
    stop = threading.Event()
    renewer = None
    child = None
    folder = ROOT / 'var/runs' / run_id / ('real-artifact-attempt-' + str(fence))
    bundle = folder / 'bundle'

    def renew():
        while not stop.wait(5):
            try: store.artifact_heartbeat(run_id, fence)
            except BaseException: return

    try:
        store.artifact_transition(run_id, fence, 'building', {'code': 'REAL_BUNDLE_BUILDING'})
        folder.mkdir(parents=True, exist_ok=False)
        renewer = threading.Thread(target=renew, daemon=True); renewer.start()
        train_rows = json.loads((input_dir / 'inputs.json').read_text(encoding='utf-8'))['train']
        val_rows = json.loads((input_dir / 'inputs.json').read_text(encoding='utf-8'))['validation']
        rows = train_rows + val_rows
        if rights_check is not None: rights_check()
        verified = _fresh_bundle_rights(store, attempt, rows)
        run = store.get(run_id)
        if run['state'] != 'succeeded' or run['config'].get('scope') != 'real-training/v1':
            raise Conflict('REAL_RUN_FENCED')
        result = run.get('result') or {}
        selected = result.get('selected') or {}
        epoch = selected.get('epoch')
        if type(epoch) is not int:
            raise Conflict('REAL_SELECTED_CHECKPOINT_REQUIRED')
        checkpoint = store.resume_checkpoint(run_id, epoch, attempt=attempt['attempt'])
        if not checkpoint:
            raise Conflict('REAL_SELECTED_CHECKPOINT_REQUIRED')
        if model_runner is None or model_runner.image_id != attempt['config']['model_image_id']:
            raise Conflict('REAL_MODEL_CONTAINER_REQUIRED')
        store.begin_child(run_id, fence, artifact=True)
        try:
            child = model_runner.start_bundle(input_dir, checkpoint['path'], folder,
                expected_checkpoint_digest=checkpoint['digest'],
                version_id=attempt['config']['version_id'],
                version_digest=attempt['config']['version_digest'],
                classes=input_binding['classes'],
                rights_decision_digests=[r['decision_digest'] for r in verified],
                model_image_id=attempt['config']['model_image_id'])
        except BaseException:
            store.child_spawn_failed(run_id, fence)
            raise
        store.register_child(run_id, fence, child)
        status = child.wait(timeout=MAX_BUNDLE_SECONDS)
        if status != 0:
            raise Conflict('REAL_BUNDLE_CHILD_FAILED')
        child_receipt = json.loads(child.read_receipt().decode('ascii'))
        if (type(child_receipt) is not dict or child_receipt.get('schema') != 'fieldwork.real-bundle-child/v1'
                or not isinstance(child_receipt.get('bundle_digest'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', child_receipt['bundle_digest'])):
            raise Conflict('REAL_BUNDLE_CHILD_RECEIPT_INVALID')
        child.export_bundle(bundle)
        child.cleanup(); child = None
        bundle_digest = child_receipt['bundle_digest']
        verify_real_bundle(bundle, expected_digest=bundle_digest,
            expected_lineage={'version_id': attempt['config']['version_id'],
                              'dataset_digest': attempt['config']['version_digest'],
                              'checkpoint_digest': checkpoint['digest'],
                              'recipe_digest': attempt['config']['recipe_digest'],
                              'preprocess_digest': attempt['config']['preprocess_digest'],
                              'decoder_image_id': attempt['config']['decoder_image_id'],
                              'model_image_id': attempt['config']['model_image_id']})
        store.artifact_transition(run_id, fence, 'inference',
            {'code': 'REAL_FRESH_INFERENCE_PENDING', 'bundle_digest': bundle_digest,
             'checkpoint_digest': checkpoint['digest']})
        sample = val_rows[0]
        inference_entry = {k: sample[k] for k in
            ('id', 'split', 'pixel_file', 'width', 'height', 'decoded_pixel_sha256')}
        store.begin_child(run_id, fence, artifact=True)
        try:
            child = model_runner.start_inference(bundle, input_dir, inference_entry, bundle_digest,
                model_image_id=attempt['config']['model_image_id'], timeout=60)
        except BaseException:
            store.child_spawn_failed(run_id, fence); raise
        store.register_child(run_id, fence, child)
        status = child.wait(timeout=60)
        if status != 0:
            raise Conflict('REAL_FRESH_INFERENCE_FAILED')
        stdout = child.read_receipt()
        child.cleanup(); child = None
        receipt = json.loads(stdout.decode('utf-8'))
        try:
            from .real_bundle import verify_real_inference_receipt
            verify_real_inference_receipt(receipt, bundle=bundle, expected_bundle_digest=bundle_digest,
                sample_id=sample['id'], sample_split='validation',
                pixel_digest=sample['decoded_pixel_sha256'])
        except (ValueError, TypeError, KeyError):
            raise Conflict('REAL_INFERENCE_RECEIPT_MISMATCH')
        predictions = [json.loads(line) for line in (bundle / 'evaluation/predictions.jsonl').read_text().splitlines() if line]
        expected = next((x for x in predictions if x['id'] == sample['id']), None)
        if not expected or len(receipt.get('logits', [])) != 5 or max(
                abs(a - b) for a, b in zip(receipt['logits'], expected['logits'], strict=True)) > 1e-6:
            raise Conflict('REAL_FRESH_INFERENCE_LOGIT_MISMATCH')
        # Rights and attempt scope are checked again at the commit boundary.
        if rights_check is not None: rights_check()
        verified = _fresh_bundle_rights(store, attempt, rows)
        store.artifact_transition(run_id, fence, 'verified', {
            'code': 'REAL_PRIVATE_BUNDLE_VERIFIED', 'bundle_digest': bundle_digest,
            'checkpoint_digest': checkpoint['digest'], 'receipt_digest': receipt['receipt_digest'],
            'model_digest': receipt['model_digest'], 'process_identity': receipt['process_identity'],
            'artifact_directory': folder.name, 'scope': 'real-training/v1',
            'evidence_scope': 'validation_only', 'public_export_authorized': False,
            'rights_members': len(verified)})
        return receipt
    except BaseException:
        if child is not None and child.poll() is None:
            child.kill()
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired: pass
        if child is not None:
            child.cleanup()
        try: store.artifact_transition(run_id, fence, 'failed', {'code': 'REAL_ARTIFACT_PIPELINE_FAILED'})
        except Conflict: pass
        raise
    finally:
        stop.set()
        if renewer is not None: renewer.join(timeout=10)
        if child is not None and child.poll() is None:
            child.kill()
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired: pass


MAX_BUNDLE_SECONDS = 4 * 60 * 60


def recover_real_artifacts(run_id, store, *, model_runner=None):
    """Replay a failed private-real bundle attempt from immutable input arrays."""
    attempt = store.claim_real_artifacts(run_id)
    if not attempt or attempt.get('state') != 'succeeded' or attempt.get('config', {}).get('scope') != 'real-training/v1':
        raise Conflict('REAL_ARTIFACT_NOT_RETRYABLE')
    if not isinstance(attempt.get('attempt'), str):
        raise Conflict('REAL_ARTIFACT_TRAIN_ATTEMPT_REQUIRED')
    attempt_root = ROOT / 'var/runs' / run_id / attempt['attempt']
    output = attempt_root / 'training'
    input_dir = attempt_root / 'real-inputs'
    try:
        input_binding = json.loads((input_dir / 'inputs.json').read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError):
        raise Conflict('REAL_ARTIFACT_INPUTS_UNAVAILABLE') from None
    return finalize_real_artifacts(store, attempt, output, input_dir, input_binding,
                                   model_runner=model_runner)

