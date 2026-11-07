"""Pure authored-fixture checks for the additive real-run source contracts."""
import hashlib
import json
from pathlib import Path

import pytest

from fieldwork.real_pixel_decoder import (ContainerRealPixelDecoder, PIXEL_DECODER_VERSION,
                                           RESULT_SCHEMA)
from fieldwork.real_pixels import validate_rgb8
from fieldwork.real_run_profile import (PREPROCESS_DIGEST, RECIPE_DIGEST, REAL_TRAIN_SCOPE,
    MAX_REAL_SAMPLES, inference_config, training_config, validate_inference_config,
    validate_training_config)
from fieldwork.real_train_child import _inside_file, augment


def training_config_fixture(**overrides):
    values = dict(version_id='v1', version_revision=4, version_digest='a' * 64,
        workspace='workspace', dataset_id='dataset', actor='researcher',
        recipe_digest=RECIPE_DIGEST, preprocess_digest=PREPROCESS_DIGEST,
        decoder_image_id='sha256:' + 'd' * 64, model_image_id='sha256:' + 'e' * 64,
        epochs=3, batch_size=4,
        learning_rate='0.001', weight_decay='0.0001', seed=91, idempotency_key='request-1')
    values.update(overrides)
    return training_config(**values)


def test_real_training_profile_is_closed_and_binds_exact_source():
    config = training_config_fixture()
    assert config['scope'] == REAL_TRAIN_SCOPE
    assert config['dataset_digest'] == config['version_digest']
    assert 'media_path' not in config and 'sample_ids' not in config and 'python' not in config
    assert validate_training_config(config, workspace='workspace') == config
    with pytest.raises(ValueError):
        validate_training_config({**config, 'source_path': 'C:/private/image.jpg'})
    with pytest.raises(ValueError):
        training_config_fixture(decoder_image_id='latest')
    with pytest.raises(ValueError):
        validate_training_config({**config, 'scope': 'synthetic-execution-only'})


def test_training_profile_canonicalizes_fixed_weight_decay():
    config = training_config_fixture(weight_decay='0.00010')
    assert config['weight_decay'] == '0.0001'
    assert validate_training_config(config)['weight_decay'] == '0.0001'


def test_real_attempt_input_and_output_directories_are_distinct():
    from fieldwork.real_job import _attempt_paths
    root, inputs, output = _attempt_paths('run-1', {'attempt': 'attempt-1'})
    assert inputs == root / 'real-inputs'
    assert output == root / 'training'
    assert inputs != output
    assert MAX_REAL_SAMPLES == 10_000


def test_enqueue_population_bound_is_checked_before_rights_lookup():
    from fastapi import HTTPException
    from fieldwork.real_runs_api import _recheck_members

    class RightsMustNotBeCalled:
        MAX_EXPLICIT_MEMBERS = 20_000
        def require_members(self, *args, **kwargs):
            raise AssertionError('oversized population must be rejected first')

    manifest = {'samples': [{'id': f'sample-{i}', 'split': 'train',
                             'source_member': f'member-{i}', 'sha256': 'a' * 64}
                            for i in range(MAX_REAL_SAMPLES + 1)]}
    with pytest.raises(HTTPException) as exc:
        _recheck_members(RightsMustNotBeCalled(), 'workspace', 'dataset', 'actor',
                         manifest, {'train', 'validation'})
    assert exc.value.status_code == 413
    assert exc.value.detail == 'REAL_POPULATION_BOUNDS'


def test_worker_migration_pins_current_recipe_and_population_bound():
    sql = (Path(__file__).resolve().parents[1] / 'migrations' /
           '007_real_run_worker.sql').read_text(encoding='utf-8')
    # 007/009 are immutable and pin the digests of the source they shipped with; forward
    # migration 020 re-pins the validator to the CURRENT source digests (old ones stay accepted).
    root = Path(__file__).resolve().parents[1] / 'migrations'
    rotation = (root / '020_real_digest_rotation.sql').read_text(encoding='utf-8')
    assert "p_config->>'recipe_digest'='22ad675cf61ef7bb3b315563652addf47fa7669667488777a15399c25f9a24fa'" in sql
    assert RECIPE_DIGEST in rotation and PREPROCESS_DIGEST in rotation
    assert 'IF expected_count<1 OR expected_count>10000 THEN' in sql
    assert '(SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_config))=22' in sql
    assert '(SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_config))=16' in sql
    assert "p_config->>'model_image_id' ~ '^sha256:[0-9a-f]{64}$'" in sql
    assert "t.config->>'model_image_id'=p_config->>'model_image_id'" in sql


def test_real_inference_profile_rejects_holdout_and_unknown_fields():
    fields = dict(workspace='workspace', actor='researcher', run_id='run-1', version_id='v1',
        version_digest='a' * 64, sample_id='sample-1', sample_split='validation',
        bundle_digest='b' * 64, preprocess_digest=PREPROCESS_DIGEST,
        decoder_image_id='sha256:' + 'd' * 64, model_image_id='sha256:' + 'e' * 64,
        idempotency_key='request-2')
    config = inference_config(**fields)
    assert validate_inference_config(config, workspace='workspace') == config
    with pytest.raises(ValueError):
        inference_config(**{**fields, 'sample_split': 'holdout'})
    with pytest.raises(ValueError):
        validate_inference_config({**config, 'path': 'image.jpg'})


def test_rgb8_asset_digest_shape_and_child_loader_are_strict(tmp_path):
    width = height = 144
    raw = bytes(width * height * 3)
    pixel_digest = hashlib.sha256(b'RGB8|144|144|' + raw).hexdigest()
    assert validate_rgb8(width, height, raw, pixel_digest) == pixel_digest
    file_path = tmp_path / 'pixel.rgb'
    file_path.write_bytes(raw)
    row = {'pixel_file': 'pixel.rgb', 'width': width, 'height': height,
           'decoded_pixel_sha256': pixel_digest}
    array = _inside_file(tmp_path, row)
    assert array.shape == (144, 144, 3)
    with pytest.raises(ValueError):
        validate_rgb8(144, 145, raw, pixel_digest)
    with pytest.raises(ValueError):
        _inside_file(tmp_path, {**row, 'pixel_file': '../pixel.rgb'})


def test_stateless_train_augmentation_is_deterministic_and_bounded():
    import numpy as np
    array = np.arange(144 * 160 * 3, dtype=np.uint8).reshape((144, 160, 3))
    a = augment(array, 42, 2, 'sample-a', 0)
    b = augment(array, 42, 2, 'sample-a', 0)
    c = augment(array, 42, 2, 'sample-a', 1)
    assert a.shape == (128, 128, 3)
    assert np.array_equal(a, b)
    assert not np.array_equal(a, c)


def test_pixel_decoder_output_is_input_bound_and_bounded():
    source = b'authored synthetic input bytes'
    payload = bytes(144 * 144 * 3)
    pixel_digest = hashlib.sha256(b'RGB8|144|144|' + payload).hexdigest()
    canonical_digest = 'f' * 64
    result = {'ok': True, 'format': 'PNG', 'width': 144, 'height': 144,
              'pixel_sha256': pixel_digest, 'canonical_pixel_sha256': canonical_digest,
              'decoder': PIXEL_DECODER_VERSION}
    envelope = {'schema': RESULT_SCHEMA, 'input_sha256': hashlib.sha256(source).hexdigest(),
                'input_bytes': len(source), 'result': result, 'payload_bytes': len(payload)}
    parsed, pixels = ContainerRealPixelDecoder._decode_result(
        json.dumps(envelope, separators=(',', ':')).encode() + b'\n' + payload, source)
    assert parsed == result and pixels == payload
    with pytest.raises(Exception):
        ContainerRealPixelDecoder._decode_result(
            json.dumps({**envelope, 'input_sha256': '0' * 64}).encode() + b'\n' + payload, source)

