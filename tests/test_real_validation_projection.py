import json

from fieldwork.data import canonical, digest
from fieldwork import api_screens
from starlette.responses import Response


def _bundle(tmp_path):
    metrics = {
        'n': 2, 'ok': 1, 'accuracy': 0.0, 'coverage': 0.5,
        'matrix': [[0, 1, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0],
                   [0, 0, 0, 0, 0], [0, 0, 0, 0, 0]],
        'cells': {'0:0': [], '0:1': ['validation-a'], '0:2': [], '0:3': [], '0:4': []},
        'missing': ['validation-b'], 'missing_by_class': [['validation-b'], [], [], [], []],
        'support': [2, 0, 0, 0, 0], 'precision': [None, 0.0, None, None, None],
        'recall': [0.0, None, None, None, None], 'f1': [None] * 5,
        'macro_f1': None, 'cross_entropy': 1.0, 'status': 'incomplete',
        'disposition_counts': {'ok': 1, 'missing': 0, 'decode_failed': 0, 'inference_failed': 1},
        'null_reasons': {}, 'cross_entropy_complete': False,
    }
    predictions = [
        {'id': 'validation-a', 'label': 0, 'sha256': 'a' * 64, 'model': 'b' * 64,
         'status': 'ok', 'logits': [0.0, 1.0, -1.0, -1.0, -1.0]},
        {'id': 'validation-b', 'label': 0, 'sha256': 'c' * 64, 'model': 'b' * 64,
         'status': 'inference_failed'},
    ]
    files = {
        'evaluation/metrics.json': canonical(metrics),
        'evaluation/independent-report.json': canonical(metrics),
        'evaluation/predictions.jsonl': b''.join(canonical(row) + b'\n' for row in predictions),
        'classes.json': canonical(['A', 'B', 'C', 'D', 'E']),
    }
    manifest = {'files': {name: {'bytes': len(data), 'sha256': digest(data)} for name, data in files.items()}}
    for name, data in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return tmp_path, manifest, metrics


def test_real_validation_returns_only_verified_aggregate_fields(monkeypatch, tmp_path):
    bundle, manifest, _ = _bundle(tmp_path)
    monkeypatch.setattr(api_screens, '_real_validation_bundle', lambda *_: (
        bundle, manifest, {'artifact_result': {'bundle_digest': 'd' * 64}}))

    response = Response()
    body = api_screens.real_validation('workspace', 'run', response, {'name': 'reader'})

    assert body['scope'] == 'real-training/v1'
    assert body['split'] == 'validation'
    assert body['evidence_scope'] == 'validation_only'
    assert body['independent_metrics_match'] is True
    assert body['metrics']['n'] == 2
    assert body['metrics']['matrix'][0][1] == 1
    assert response.headers['cache-control'] == 'no-store'
    assert 'cells' not in body['metrics']
    assert not {'population', 'predictions', 'holdout', 'labels', 'sample_ids'} & body.keys()


def test_real_validation_slice_pages_only_requested_validation_members(monkeypatch, tmp_path):
    bundle, manifest, _ = _bundle(tmp_path)
    monkeypatch.setattr(api_screens, '_real_validation_bundle', lambda *_: (
        bundle, manifest, {'artifact_result': {'bundle_digest': 'd' * 64}}))

    body = api_screens.real_validation_slice('workspace', 'run', Response(), actual=0, predicted=1,
        bucket='cell', offset=0, limit=1, user={'name': 'reader'})

    assert body['split'] == 'validation'
    assert body['members'] == [{'sample_id': 'validation-a', 'actual': 0, 'predicted': 1, 'status': 'ok'}]
    assert body['next_offset'] is None
    assert body['membership_digest'] == digest(canonical(['validation-a']))
    assert all('logits' not in item and 'sha256' not in item for item in body['members'])


def test_real_validation_missing_slice_never_returns_scores(monkeypatch, tmp_path):
    bundle, manifest, _ = _bundle(tmp_path)
    monkeypatch.setattr(api_screens, '_real_validation_bundle', lambda *_: (
        bundle, manifest, {'artifact_result': {'bundle_digest': 'd' * 64}}))

    body = api_screens.real_validation_slice('workspace', 'run', Response(), actual=0, predicted=None,
        bucket='missing', offset=0, limit=10, user={'name': 'reader'})

    assert body['members'] == [{'sample_id': 'validation-b', 'actual': 0, 'predicted': None, 'status': 'inference_failed'}]

