"""Separate closed verifier for private real-data candidate bundles."""
from __future__ import annotations
import hashlib, json, math, re
from pathlib import Path
from .data import canonical, digest
from .metrics import evaluate
from .real_run_profile import (PREPROCESS_DESCRIPTOR, PREPROCESS_DIGEST, RECIPE_DIGEST)

FILES = {'architecture.json', 'preprocess.json', 'classes.json', 'lineage.json',
         'model.safetensors', 'rights/review.json', 'evaluation/population.json',
         'evaluation/metrics.json', 'evaluation/independent-report.json',
         'evaluation/predictions.jsonl'}
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024


def metrics_agree(value, wanted):
    """Metric equality for independently recomputed reports.

    Floats may differ by summation order only (<=1e-12, the tolerance bundle.py and
    test_full_metrics already use); every other field, type and key set is exact.
    """
    if isinstance(wanted, float):
        return type(value) in (int, float) and math.isfinite(value) and abs(value - wanted) <= 1e-12
    if isinstance(wanted, dict):
        return (isinstance(value, dict) and value.keys() == wanted.keys()
                and all(metrics_agree(value[k], v) for k, v in wanted.items()))
    if isinstance(wanted, list):
        return (isinstance(value, list) and len(value) == len(wanted)
                and all(metrics_agree(a, b) for a, b in zip(value, wanted)))
    return type(value) is type(wanted) and value == wanted


def _read_json(path):
    value = json.loads(Path(path).read_text(encoding='utf-8'))
    if type(value) not in (dict, list): raise ValueError('REAL_BUNDLE_JSON')
    return value


def build(checkpoint, input_dir, out, *, expected_checkpoint_digest, version_id,
          version_digest, classes, rights_decision_digests, model_image_id):
    import torch
    from safetensors.torch import load_file, save_file
    from .ml import model, validate_checkpoint, write_bytes
    if not isinstance(model_image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', model_image_id):
        raise ValueError('REAL_MODEL_IMAGE_ID')
    checkpoint, input_dir, out = Path(checkpoint), Path(input_dir), Path(out)
    validate_checkpoint(checkpoint, expected_digest=expected_checkpoint_digest)
    inputs = _read_json(input_dir / 'inputs.json')
    if inputs.get('version_id') != version_id or inputs.get('version_digest') != version_digest:
        raise ValueError('REAL_BUNDLE_DATASET_BINDING')
    if type(classes) is not list or len(classes) != 5 or len(set(classes)) != 5:
        raise ValueError('REAL_BUNDLE_CLASSES')
    rows = inputs.get('validation')
    if type(rows) is not list or not rows or len(rows) > 100_000:
        raise ValueError('REAL_BUNDLE_VALIDATION_POPULATION')
    meta = _read_json(checkpoint / 'state.json')
    if meta.get('dataset_digest') != version_digest:
        raise ValueError('REAL_BUNDLE_CHECKPOINT_BINDING')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'evaluation').mkdir()
    (out / 'rights').mkdir()
    tensors = load_file(str(checkpoint / 'state.safetensors'), device='cpu')
    net = model()
    net.load_state_dict({k: tensors['model.' + k] for k in net.state_dict()}, strict=True)
    net.eval()
    save_file(net.state_dict(), str(out / 'model.safetensors'))
    model_digest = digest((out / 'model.safetensors').read_bytes())
    from .real_train_child import _inside_file, center, tensor
    arrays = [_inside_file(input_dir, row) for row in rows]
    logits_out = []
    torch.set_num_threads(2)
    with torch.inference_mode():
        for start in range(0, len(arrays), 64):
            logits_out.extend(net(tensor([center(a) for a in arrays[start:start + 64]])).tolist())
    population = [{'id': row['id'], 'label': row['label'],
                   'sha256': row.get('raw_sha256', row.get('sha256'))} for row in rows]
    # Inputs are redacted staging records; attach only the frozen source digests
    # supplied by the capability, never filesystem paths or raw bytes.
    for pop, row in zip(population, rows, strict=True):
        source_digest = row.get('source_sha256')
        if source_digest:
            pop['sha256'] = source_digest
    predictions = [dict(id=row['id'], label=row['label'], sha256=population[i]['sha256'],
                        model=model_digest, status='ok', logits=logits_out[i])
                   for i, row in enumerate(rows)]
    metrics = evaluate(population, predictions, 5, model_digest)
    from tools.verify_metrics import verify as independent
    report = independent(population, predictions, 5, model_digest)
    if metrics != report:
        # Independent cross entropy may use a numerically equivalent summation.
        if set(metrics) != set(report) or any(
                abs(metrics[k] - report[k]) > 1e-12 if isinstance(metrics[k], float)
                else metrics[k] != report[k] for k in metrics):
            raise ValueError('REAL_BUNDLE_INDEPENDENT_METRICS')
    payloads = {
        'architecture.json': {'schema': 1, 'id': 'compact-cnn/real-v1'},
        'preprocess.json': PREPROCESS_DESCRIPTOR,
        'classes.json': classes,
        'lineage.json': {'scope': 'real-training/v1', 'version_id': version_id,
            'dataset_digest': version_digest, 'checkpoint_digest': expected_checkpoint_digest,
            'epoch': meta['epoch'], 'model_digest': model_digest,
            'recipe_digest': inputs['recipe_digest'],
            'preprocess_digest': inputs['preprocess_digest'],
            'decoder_image_id': inputs['decoder_image_id'],
            'model_image_id': model_image_id},
        'rights/review.json': {'scope': 'real-rights-cleared', 'purpose': 'model_bundle',
            'decision_digests_sha256': digest(canonical(sorted(rights_decision_digests))),
            'public_export_authorized': False},
        'evaluation/population.json': population,
        'evaluation/metrics.json': metrics,
        'evaluation/independent-report.json': report,
    }
    for name, value in payloads.items(): write_bytes(out / name, canonical(value))
    write_bytes(out / 'evaluation/predictions.jsonl',
                b''.join(canonical(record) + b'\n' for record in predictions))
    inventory = {name: {'sha256': digest((out / name).read_bytes()),
                        'bytes': (out / name).stat().st_size} for name in sorted(FILES)}
    manifest = {'schema': 1, 'purpose': 'private_real_candidate',
                'scope': 'real-training/v1', 'evidence_scope': 'validation_only', 'files': inventory}
    write_bytes(out / 'manifest.json', canonical(manifest))
    expected_bundle = digest(canonical(manifest))
    verify_real_bundle(out, expected_digest=expected_bundle,
                       expected_lineage={'version_id': version_id, 'dataset_digest': version_digest,
                                         'checkpoint_digest': expected_checkpoint_digest})
    return manifest


def verify_real_bundle(path, *, expected_digest, expected_lineage=None):
    path = Path(path)
    if path.is_symlink() or not expected_digest:
        raise ValueError('REAL_BUNDLE_TRUSTED_DIGEST_REQUIRED')
    manifest = _read_json(path / 'manifest.json')
    if (set(manifest) != {'schema', 'purpose', 'scope', 'evidence_scope', 'files'}
            or manifest['schema'] != 1 or manifest['purpose'] != 'private_real_candidate'
            or manifest['scope'] != 'real-training/v1' or manifest['evidence_scope'] != 'validation_only'
            or set(manifest['files']) != FILES
            or digest((path / 'manifest.json').read_bytes()) != expected_digest):
        raise ValueError('REAL_BUNDLE_MANIFEST')
    actual = {p.relative_to(path).as_posix() for p in path.rglob('*') if p.is_file()}
    if actual != FILES | {'manifest.json'} or any(p.is_symlink() for p in path.rglob('*')):
        raise ValueError('REAL_BUNDLE_INVENTORY')
    total = 0
    for name, record in manifest['files'].items():
        size = (path / name).stat().st_size; total += size
        if (set(record) != {'sha256', 'bytes'} or size != record['bytes'] or size > MAX_FILE
                or digest((path / name).read_bytes()) != record['sha256']):
            raise ValueError('REAL_BUNDLE_FILE_DIGEST')
    if total > MAX_TOTAL: raise ValueError('REAL_BUNDLE_TOTAL_SIZE')
    lineage = _read_json(path / 'lineage.json')
    if (set(lineage) != {'scope','version_id','dataset_digest','checkpoint_digest','epoch',
                         'model_digest','recipe_digest','preprocess_digest','decoder_image_id',
                         'model_image_id'}
            or lineage['scope'] != 'real-training/v1'
            or _read_json(path / 'preprocess.json') != PREPROCESS_DESCRIPTOR
            or lineage['model_digest'] != digest((path / 'model.safetensors').read_bytes())):
        raise ValueError('REAL_BUNDLE_LINEAGE_SCHEMA')
    for key in ('dataset_digest','checkpoint_digest','model_digest','recipe_digest','preprocess_digest'):
        if not isinstance(lineage[key], str) or len(lineage[key]) != 64:
            raise ValueError('REAL_BUNDLE_LINEAGE_DIGEST')
    if lineage['recipe_digest'] != RECIPE_DIGEST or lineage['preprocess_digest'] != PREPROCESS_DIGEST:
        raise ValueError('REAL_BUNDLE_IMPLEMENTATION_DIGEST')
    if (not isinstance(lineage['decoder_image_id'], str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', lineage['decoder_image_id'])):
        raise ValueError('REAL_BUNDLE_DECODER_ID')
    if (not isinstance(lineage['model_image_id'], str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', lineage['model_image_id'])):
        raise ValueError('REAL_BUNDLE_MODEL_IMAGE_ID')
    if expected_lineage and any(lineage.get(k) != v for k, v in expected_lineage.items()):
        raise ValueError('REAL_BUNDLE_LINEAGE')
    classes = _read_json(path / 'classes.json')
    if type(classes) is not list or len(classes) != 5 or len(set(classes)) != 5:
        raise ValueError('REAL_BUNDLE_CLASSES')
    from .safe_codec import tensor_header, MODEL_SHAPES
    tensor_header(path / 'model.safetensors', {k: ('F32', shape) for k, shape in MODEL_SHAPES.items()})
    population = _read_json(path / 'evaluation/population.json')
    if type(population) is not list or not population or any(
            type(row) is not dict or set(row) != {'id', 'label', 'sha256'}
            or type(row['label']) is not int or not 0 <= row['label'] < 5
            or not isinstance(row['sha256'], str) or len(row['sha256']) != 64 for row in population):
        raise ValueError('REAL_BUNDLE_POPULATION')
    predictions = [json.loads(line) for line in (path / 'evaluation/predictions.jsonl').read_text().splitlines() if line]
    measured = evaluate(population, predictions, 5, lineage['model_digest'])
    from tools.verify_metrics import verify as independent
    independently_measured = independent(population, predictions, 5, lineage['model_digest'])
    saved = _read_json(path / 'evaluation/metrics.json')
    report = _read_json(path / 'evaluation/independent-report.json')
    if (measured != saved or not metrics_agree(report, saved)
            or not metrics_agree(independently_measured, saved)):
        raise ValueError('REAL_BUNDLE_METRIC_RECOMPUTE')
    import struct
    tensor_path = path / 'model.safetensors'
    raw = tensor_path.read_bytes()
    header_length = struct.unpack('<Q', raw[:8])[0]
    tensor_bytes = raw[8 + header_length:]
    for entry in tensor_header(tensor_path, {k: ('F32', shape) for k, shape in MODEL_SHAPES.items()}).values():
        start, stop = entry['data_offsets']
        if any(not math.isfinite(value[0]) for value in struct.iter_unpack('<f', tensor_bytes[start:stop])):
            raise ValueError('REAL_BUNDLE_TENSOR')
    return manifest


def verify_real_inference_receipt(receipt, *, bundle, expected_bundle_digest,
                                 sample_id, sample_split, pixel_digest,
                                 expected_scope='real-inference/v1'):
    import uuid
    if type(receipt) is not dict or set(receipt) != {
        'schema','scope','pid','process_identity','bundle_digest','model_digest','version_id',
        'version_digest','sample_id','sample_split','pixel_digest','logits','probabilities',
        'top1','classes','public_export_authorized','receipt_digest'}:
        raise ValueError('REAL_INFERENCE_RECEIPT_SCHEMA')
    body = {k: v for k, v in receipt.items() if k != 'receipt_digest'}
    allowed_split = {'train', 'validation'} if expected_scope == 'real-inference/v1' else {'upload'}
    if (expected_scope not in {'real-inference/v1', 'real-image-inference/v1'}
            or receipt['schema'] != 'fieldwork.real-inference-receipt/v1'
            or receipt['scope'] != expected_scope
            or type(receipt['pid']) is not int or receipt['pid'] <= 0
            or receipt['bundle_digest'] != expected_bundle_digest
            or receipt['sample_id'] != sample_id or receipt['sample_split'] != sample_split
            or sample_split not in allowed_split or receipt['pixel_digest'] != pixel_digest
            or receipt['public_export_authorized'] is not False
            or receipt['receipt_digest'] != digest(canonical(body))):
        raise ValueError('REAL_INFERENCE_RECEIPT_BINDING')
    try: uuid.UUID(receipt['process_identity'])
    except (ValueError, TypeError, AttributeError): raise ValueError('REAL_INFERENCE_PROCESS_ID') from None
    logits, probs = receipt['logits'], receipt['probabilities']
    if (type(logits) is not list or len(logits) != 5 or type(probs) is not list or len(probs) != 5
            or any(type(x) not in (int,float) or not math.isfinite(x) for x in logits + probs)):
        raise ValueError('REAL_INFERENCE_NUMERICS')
    peak = max(logits); denominator = sum(math.exp(x - peak) for x in logits)
    expected_probs = [math.exp(x - peak) / denominator for x in logits]
    if (type(receipt['top1']) is not int or receipt['top1'] != max(range(5), key=lambda i: logits[i])
            or any(abs(a-b) > 1e-6 for a,b in zip(probs, expected_probs, strict=True))
            or receipt['classes'] != _read_json(Path(bundle) / 'classes.json')):
        raise ValueError('REAL_INFERENCE_NUMERICS')
    return receipt

