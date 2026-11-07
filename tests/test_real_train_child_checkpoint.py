import hashlib
import json

import numpy as np
import pytest

from fieldwork import real_train_child
from fieldwork.ml import validate_checkpoint
from fieldwork.real_run_profile import PREPROCESS_DIGEST, RECIPE_DIGEST

D = 'a' * 64


def _fixture(root, n_train=6, n_val=5):
    rng = np.random.default_rng(7)
    rows = {'train': [], 'validation': []}
    for split, count in (('train', n_train), ('validation', n_val)):
        for i in range(count):
            raw = rng.integers(0, 256, size=144 * 144 * 3, dtype=np.uint8).tobytes()
            name = f'{split}-{i}.rgb'
            (root / name).write_bytes(raw)
            rows[split].append({
                'id': f'{split}-{i}', 'label': i % 5, 'split': split, 'pixel_file': name,
                'width': 144, 'height': 144, 'source_member': f'm/{split}-{i}',
                'source_sha256': D,
                'decoded_pixel_sha256': hashlib.sha256(b'RGB8|144|144|' + raw).hexdigest()})
    manifest = {'schema': 'fieldwork.real-pixel-input/v1', 'version_id': 'v', 'version_digest': D,
                'recipe': 'compact-cnn/real-v1', 'recipe_digest': RECIPE_DIGEST,
                'preprocess': 'short-edge144-rgb-v1', 'preprocess_digest': PREPROCESS_DIGEST,
                'decoder_image_id': 'sha256:' + 'd' * 64,
                'classes': ['a', 'b', 'c', 'd', 'e'], **rows}
    (root / 'inputs.json').write_text(json.dumps(manifest), encoding='utf-8')
    return manifest


def test_real_child_epoch_checkpoint_passes_its_own_validator(tmp_path):
    inputs, out = tmp_path / 'in', tmp_path / 'out'
    inputs.mkdir()
    manifest = _fixture(inputs)
    result = real_train_child.train(
        inputs, out, epochs=1, seed=42, batch_size=4, learning_rate=0.001,
        expected_dataset_digest=manifest['version_digest'],
        expected_recipe_digest=manifest['recipe_digest'],
        expected_preprocess_digest=manifest['preprocess_digest'],
        expected_decoder_image_id=manifest['decoder_image_id'], threads=1)

    row = result['history'][0]
    validate_checkpoint(out / 'epoch-1', expected_digest=row['checkpoint_digest'])
    state = json.loads((out / 'epoch-1' / 'state.json').read_text(encoding='utf-8'))
    assert 'validation_accuracy' not in state
    assert 'validation_accuracy' in row


def test_real_bundle_build_creates_every_bundle_directory(tmp_path):
    from fieldwork import real_bundle
    inputs, out, bundle = tmp_path / 'in', tmp_path / 'out', tmp_path / 'bundle'
    inputs.mkdir()
    manifest = _fixture(inputs)
    result = real_train_child.train(
        inputs, out, epochs=1, seed=42, batch_size=4, learning_rate=0.001,
        expected_dataset_digest=manifest['version_digest'],
        expected_recipe_digest=manifest['recipe_digest'],
        expected_preprocess_digest=manifest['preprocess_digest'],
        expected_decoder_image_id=manifest['decoder_image_id'], threads=1)
    digest = result['history'][0]['checkpoint_digest']

    real_bundle.build(out / 'epoch-1', inputs, bundle, expected_checkpoint_digest=digest,
                      version_id=manifest['version_id'], version_digest=manifest['version_digest'],
                      classes=manifest['classes'], rights_decision_digests=['f' * 64],
                      model_image_id='sha256:' + 'e' * 64)

    assert (bundle / 'rights' / 'review.json').is_file()
    assert (bundle / 'evaluation' / 'metrics.json').is_file()


def test_real_child_resume_from_epoch_checkpoint_matches_uninterrupted_run(tmp_path):
    inputs = tmp_path / 'in'
    inputs.mkdir()
    manifest = _fixture(inputs)
    common = dict(seed=42, batch_size=4, learning_rate=0.001,
                  expected_dataset_digest=manifest['version_digest'],
                  expected_recipe_digest=manifest['recipe_digest'],
                  expected_preprocess_digest=manifest['preprocess_digest'],
                  expected_decoder_image_id=manifest['decoder_image_id'], threads=1)
    straight = real_train_child.train(inputs, tmp_path / 'straight', epochs=2, **common)
    first = real_train_child.train(inputs, tmp_path / 'first', epochs=1, **common)
    resumed = real_train_child.train(
        inputs, tmp_path / 'resumed', epochs=2, resume=tmp_path / 'first' / 'epoch-1',
        expected_checkpoint_digest=first['history'][0]['checkpoint_digest'], **common)

    assert resumed['final_digest'] == straight['final_digest']
    assert [r['epoch'] for r in resumed['history']] == [2]
    assert resumed['history'][0]['weight_digest'] == straight['history'][1]['weight_digest']
