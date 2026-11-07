"""Closed, immutable profile for real-data run submissions.

The profile deliberately contains no sample IDs, filesystem paths, URLs, import
paths, or shell fragments. The scoped worker resolves the frozen manifest and
materializes train/validation members server-side.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .data import canonical, digest

REAL_TRAIN_SCOPE = 'real-training/v1'
REAL_INFER_SCOPE = 'real-inference/v1'
REAL_IMAGE_INFER_SCOPE = 'real-image-inference/v1'
QUALIFIED_IMAGE_INFER_SCOPE = 'qualified-release-image-inference/v1'
REAL_DATASET_SCOPE = 'real-rights-cleared'
RECIPE_ID = 'compact-cnn/real-v1'
PREPROCESS_ID = 'short-edge144-rgb-v1'
MAX_REAL_SAMPLES = 10_000
PROFILE_SCHEMA = 'fieldwork.real-run-profile/v1'
RECIPE_DESCRIPTOR = {
    'id': RECIPE_ID,
    'architecture': 'repository-compact-cnn-v1',
    'optimizer': {'name': 'AdamW', 'betas': [0.9, 0.999], 'eps': 1e-8,
                  'weight_decay': 0.0001, 'scheduler': None, 'amp': None},
    'epochs': 'complete-epoch-checkpoint',
    'selection': 'minimum-validation-cross-entropy-ties-earliest',
}
PREPROCESS_DESCRIPTOR = {
    'id': PREPROCESS_ID,
    'decode': 'exif-transpose-rgb8-alpha-white-canonical-identity-then-model-resize',
    'protected_identity': 'full-resolution-intake-rgb8-sha256-v1',
    'resize': 'short-edge-144-bilinear-antialias',
    'validation_inference': 'center-128',
    'train': 'stateless-random-square-area-0.8-1.0-resize-128-horizontal-flip-0.5',
    'seed': 'sha256(run_seed|epoch|sample_id|occurrence)',
    'scale': 'float32-divide-255',
}
_SOURCE_ROOT = Path(__file__).resolve().parent


def _source_digest(files):
    inventory = {}
    for name in files:
        path = _SOURCE_ROOT / name
        inventory[name] = digest(path.read_bytes())
    return digest(canonical(inventory))


RECIPE_DIGEST = digest(canonical({'descriptor': RECIPE_DESCRIPTOR,
    'source_digest': _source_digest(('ml.py', 'real_train_child.py'))}))
PREPROCESS_DIGEST = digest(canonical({'descriptor': PREPROCESS_DESCRIPTOR,
    'source_digest': _source_digest(('container_real_pixels.py', 'real_pixel_decoder.py',
                                     'real_pixels.py', 'real_train_child.py'))}))
LEGACY_PREPROCESS_DIGEST = 'e5b19df9fa39a01dd178e78d5efbd12a899983fad22ed3c7ff8d52643bc5ba44'
SUPPORTED_PREPROCESS_DIGESTS = frozenset({PREPROCESS_DIGEST, LEGACY_PREPROCESS_DIGEST})
_HEX = re.compile(r'^[0-9a-f]{64}$')
_VERSION = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')


def profile_digest(config: dict[str, Any]) -> str:
    return digest(canonical(config))


def training_config(*, version_id: str, version_revision: int, version_digest: str,
                    workspace: str, dataset_id: str, actor: str, recipe_digest: str,
                    preprocess_digest: str, decoder_image_id: str, model_image_id: str,
                    epochs: int, batch_size: int,
                    learning_rate: str, weight_decay: str, seed: int,
                    idempotency_key: str) -> dict[str, Any]:
    """Create the exact public config allowlist, with strict numeric bounds."""
    if not isinstance(version_id, str) or not _VERSION.fullmatch(version_id):
        raise ValueError('REAL_VERSION_ID')
    for name, value in (('version_digest', version_digest), ('recipe_digest', recipe_digest),
                        ('preprocess_digest', preprocess_digest)):
        if not isinstance(value, str) or not _HEX.fullmatch(value):
            raise ValueError('REAL_' + name.upper())
    if type(version_revision) is not int or version_revision < 1:
        raise ValueError('REAL_VERSION_REVISION')
    if not isinstance(decoder_image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', decoder_image_id):
        raise ValueError('REAL_PIXEL_IMAGE_PIN_REQUIRED')
    if not isinstance(model_image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', model_image_id):
        raise ValueError('REAL_MODEL_IMAGE_PIN_REQUIRED')
    if type(epochs) is not int or not 1 <= epochs <= 100:
        raise ValueError('REAL_EPOCHS')
    if type(batch_size) is not int or not 1 <= batch_size <= 32:
        raise ValueError('REAL_BATCH_SIZE')
    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF:
        raise ValueError('REAL_SEED')
    if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 128:
        raise ValueError('REAL_IDEMPOTENCY_KEY')
    # Parse as decimal and bound without accepting exponent/NaN syntax.
    if not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.[0-9]{1,8})?', learning_rate or ''):
        raise ValueError('REAL_LEARNING_RATE')
    if not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.[0-9]{1,8})?', weight_decay or ''):
        raise ValueError('REAL_WEIGHT_DECAY')
    lr = float(learning_rate)
    wd = float(weight_decay)
    if not 1e-5 <= lr <= .1 or wd != .0001:
        raise ValueError('REAL_OPTIMIZER_BOUNDS')
    return {
        'profile_schema': PROFILE_SCHEMA,
        'scope': REAL_TRAIN_SCOPE,
        'operation': 'train',
        'workspace': workspace,
        'actor': actor,
        'version_id': version_id,
        'version_revision': version_revision,
        'version_digest': version_digest,
        'dataset_id': dataset_id,
        'dataset_digest': version_digest,
        'recipe': RECIPE_ID,
        'recipe_digest': recipe_digest,
        'preprocess': PREPROCESS_ID,
        'preprocess_digest': preprocess_digest,
        'decoder_image_id': decoder_image_id,
        'model_image_id': model_image_id,
        'epochs': epochs,
        'batch_size': batch_size,
        'learning_rate': learning_rate,
        'weight_decay': '0.0001',
        'seed': seed,
        'idempotency_key': idempotency_key,
    }


def validate_training_config(config: Any, *, workspace: str | None = None) -> dict[str, Any]:
    """Worker-side closed-shape check; never accepts caller-supplied paths/code."""
    required = {'profile_schema', 'scope', 'operation', 'workspace', 'actor', 'version_id',
                'version_revision', 'version_digest', 'dataset_id', 'dataset_digest',
                'recipe', 'recipe_digest', 'preprocess', 'preprocess_digest', 'epochs',
                'decoder_image_id', 'model_image_id', 'batch_size', 'learning_rate', 'weight_decay', 'seed', 'idempotency_key'}
    if type(config) is not dict or set(config) != required:
        raise ValueError('REAL_PROFILE_FIELDS')
    if config['profile_schema'] != PROFILE_SCHEMA or config['scope'] != REAL_TRAIN_SCOPE or config['operation'] != 'train':
        raise ValueError('REAL_PROFILE_SCOPE')
    if workspace is not None and config['workspace'] != workspace:
        raise ValueError('REAL_PROFILE_WORKSPACE')
    if config['recipe'] != RECIPE_ID or config['preprocess'] != PREPROCESS_ID:
        raise ValueError('REAL_PROFILE_ALLOWLIST')
    if config['recipe_digest'] != RECIPE_DIGEST or config['preprocess_digest'] not in SUPPORTED_PREPROCESS_DIGESTS:
        raise ValueError('REAL_PROFILE_IMPLEMENTATION_DIGEST')
    if config['dataset_digest'] != config['version_digest']:
        raise ValueError('REAL_PROFILE_DIGEST_BINDING')
    # Reuse constructor validation to enforce all bounds and canonical fields.
    validated = training_config(**{k: config[k] for k in (
        'version_id', 'version_revision', 'version_digest', 'workspace', 'dataset_id', 'actor',
        'recipe_digest', 'preprocess_digest', 'decoder_image_id', 'model_image_id',
        'epochs', 'batch_size', 'learning_rate',
        'weight_decay', 'seed', 'idempotency_key')})
    if validated != config:
        raise ValueError('REAL_PROFILE_NONCANONICAL')
    return config


def inference_config(*, workspace: str, actor: str, run_id: str, version_id: str,
                     version_digest: str, sample_id: str, sample_split: str,
                     bundle_digest: str, preprocess_digest: str, decoder_image_id: str,
                     model_image_id: str,
                     idempotency_key: str) -> dict[str, Any]:
    """Queue fresh inference only for an explicitly nonprotected sample."""
    if sample_split not in {'train', 'validation'}:
        raise ValueError('REAL_INFERENCE_SPLIT')
    if not all(isinstance(v, str) and _HEX.fullmatch(v) for v in
               (version_digest, bundle_digest, preprocess_digest)):
        raise ValueError('REAL_INFERENCE_DIGEST')
    if not isinstance(sample_id, str) or not _VERSION.fullmatch(sample_id):
        raise ValueError('REAL_SAMPLE_ID')
    if not isinstance(run_id, str) or not _VERSION.fullmatch(run_id):
        raise ValueError('REAL_RUN_ID')
    if not isinstance(version_id, str) or not _VERSION.fullmatch(version_id):
        raise ValueError('REAL_VERSION_ID')
    if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 128:
        raise ValueError('REAL_IDEMPOTENCY_KEY')
    if not isinstance(decoder_image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', decoder_image_id):
        raise ValueError('REAL_PIXEL_IMAGE_PIN_REQUIRED')
    if not isinstance(model_image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', model_image_id):
        raise ValueError('REAL_MODEL_IMAGE_PIN_REQUIRED')
    return {
        'profile_schema': PROFILE_SCHEMA, 'scope': REAL_INFER_SCOPE,
        'operation': 'infer', 'workspace': workspace, 'actor': actor,
        'run_id': run_id, 'version_id': version_id, 'version_digest': version_digest,
        'sample_id': sample_id, 'sample_split': sample_split,
        'bundle_digest': bundle_digest, 'preprocess': PREPROCESS_ID,
        'preprocess_digest': preprocess_digest, 'decoder_image_id': decoder_image_id,
        'model_image_id': model_image_id,
        'idempotency_key': idempotency_key,
    }


def validate_inference_config(config: Any, *, workspace: str | None = None) -> dict[str, Any]:
    required = {'profile_schema', 'scope', 'operation', 'workspace', 'actor', 'run_id',
                'version_id', 'version_digest', 'sample_id', 'sample_split', 'bundle_digest',
                'preprocess', 'preprocess_digest', 'decoder_image_id', 'model_image_id', 'idempotency_key'}
    if type(config) is not dict or set(config) != required:
        raise ValueError('REAL_INFERENCE_FIELDS')
    if (config['profile_schema'] != PROFILE_SCHEMA or config['scope'] != REAL_INFER_SCOPE
            or config['operation'] != 'infer' or config['preprocess'] != PREPROCESS_ID
            or config['preprocess_digest'] not in SUPPORTED_PREPROCESS_DIGESTS
            or config['sample_split'] not in {'train', 'validation'}):
        raise ValueError('REAL_INFERENCE_PROFILE')
    if workspace is not None and config['workspace'] != workspace:
        raise ValueError('REAL_PROFILE_WORKSPACE')
    for key in ('version_digest', 'bundle_digest'):
        if not isinstance(config[key], str) or not _HEX.fullmatch(config[key]):
            raise ValueError('REAL_INFERENCE_DIGEST')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', config['decoder_image_id']):
        raise ValueError('REAL_PIXEL_IMAGE_PIN_REQUIRED')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', config['model_image_id']):
        raise ValueError('REAL_MODEL_IMAGE_PIN_REQUIRED')
    if not isinstance(config['idempotency_key'], str) or not 1 <= len(config['idempotency_key']) <= 128:
        raise ValueError('REAL_IDEMPOTENCY_KEY')
    for key in ('run_id', 'version_id', 'sample_id'):
        if not isinstance(config[key], str) or not _VERSION.fullmatch(config[key]):
            raise ValueError('REAL_INFERENCE_OBJECT_ID')
    return config


def image_inference_config(*, workspace: str, actor: str, run_id: str, version_id: str,
                           version_digest: str, dataset_id: str, member_id: str,
                           asset_sha256: str, asset_bytes: int, input_id: str,
                           bundle_digest: str, preprocess_digest: str,
                           decoder_image_id: str, model_image_id: str,
                           idempotency_key: str) -> dict[str, Any]:
    """Closed profile for one server-staged, rights-registered fresh image."""
    for key, value in (('version_digest', version_digest), ('asset_sha256', asset_sha256),
                       ('bundle_digest', bundle_digest), ('preprocess_digest', preprocess_digest)):
        if not isinstance(value, str) or not _HEX.fullmatch(value):
            raise ValueError('REAL_IMAGE_INFERENCE_DIGEST')
    if type(asset_bytes) is not int or not 1 <= asset_bytes <= 20 * 1024 * 1024:
        raise ValueError('REAL_IMAGE_INFERENCE_SIZE')
    for key, value in (('run_id', run_id), ('version_id', version_id)):
        if not isinstance(value, str) or not _VERSION.fullmatch(value):
            raise ValueError('REAL_IMAGE_INFERENCE_OBJECT_ID')
    if not isinstance(input_id, str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', input_id):
        raise ValueError('REAL_IMAGE_INPUT_ID')
    if not isinstance(dataset_id, str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', dataset_id):
        raise ValueError('REAL_IMAGE_DATASET_ID')
    if not isinstance(member_id, str) or not 1 <= len(member_id) <= 512 or any(ord(ch) < 32 for ch in member_id):
        raise ValueError('REAL_IMAGE_MEMBER_ID')
    for key, value in (('decoder_image_id', decoder_image_id), ('model_image_id', model_image_id)):
        if not isinstance(value, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
            raise ValueError('REAL_IMAGE_PIN_REQUIRED')
    if preprocess_digest not in SUPPORTED_PREPROCESS_DIGESTS:
        raise ValueError('REAL_IMAGE_PREPROCESS_BINDING')
    if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 128:
        raise ValueError('REAL_IDEMPOTENCY_KEY')
    return {'profile_schema': PROFILE_SCHEMA, 'scope': REAL_IMAGE_INFER_SCOPE,
        'operation': 'infer-image', 'workspace': workspace, 'actor': actor,
        'run_id': run_id, 'version_id': version_id, 'version_digest': version_digest,
        'dataset_id': dataset_id, 'member_id': member_id, 'asset_sha256': asset_sha256,
        'asset_bytes': asset_bytes, 'input_id': input_id, 'sample_split': 'upload',
        'bundle_digest': bundle_digest, 'preprocess': PREPROCESS_ID,
        'preprocess_digest': preprocess_digest, 'decoder_image_id': decoder_image_id,
        'model_image_id': model_image_id, 'idempotency_key': idempotency_key}


def validate_image_inference_config(config: Any, *, workspace: str | None = None) -> dict[str, Any]:
    required = {'profile_schema','scope','operation','workspace','actor','run_id','version_id',
        'version_digest','dataset_id','member_id','asset_sha256','asset_bytes','input_id',
        'sample_split','bundle_digest','preprocess','preprocess_digest','decoder_image_id',
        'model_image_id','idempotency_key'}
    if type(config) is not dict or set(config) != required:
        raise ValueError('REAL_IMAGE_INFERENCE_FIELDS')
    if (config['profile_schema'] != PROFILE_SCHEMA or config['scope'] != REAL_IMAGE_INFER_SCOPE
            or config['operation'] != 'infer-image' or config['sample_split'] != 'upload'
            or config['preprocess'] != PREPROCESS_ID):
        raise ValueError('REAL_IMAGE_INFERENCE_PROFILE')
    if workspace is not None and config['workspace'] != workspace:
        raise ValueError('REAL_PROFILE_WORKSPACE')
    expected = image_inference_config(**{k: config[k] for k in (
        'workspace','actor','run_id','version_id','version_digest','dataset_id','member_id',
        'asset_sha256','asset_bytes','input_id','bundle_digest','preprocess_digest',
        'decoder_image_id','model_image_id','idempotency_key')})
    if expected != config:
        raise ValueError('REAL_IMAGE_INFERENCE_NONCANONICAL')
    return config


def qualified_image_inference_config(*, workspace: str, actor: str, release_id: str,
        plan_id: str, plan_result_sha256: str, result_record_sha256: str,
        model_digest: str, bundle_digest: str, version_id: str, version_digest: str,
        dataset_id: str, member_id: str, asset_sha256: str, asset_bytes: int,
        input_id: str, preprocess_digest: str, decoder_image_id: str,
        model_image_id: str, idempotency_key: str) -> dict[str, Any]:
    """Closed queue profile bound to the one fixed qualified release registry entry."""
    from .qualified_release import (RELEASE_ID, PLAN_ID, PLAN_RESULT_SHA256,
        RESULT_RECORD_SHA256, MODEL_SHA256, MANIFEST_SHA256, VERSION_ID,
        VERSION_DIGEST, DATASET_ID, WORKSPACE, PREPROCESS_SHA256)
    if (release_id != RELEASE_ID or plan_id != PLAN_ID
            or plan_result_sha256 != PLAN_RESULT_SHA256
            or result_record_sha256 != RESULT_RECORD_SHA256
            or model_digest != MODEL_SHA256 or bundle_digest != MANIFEST_SHA256
            or version_id != VERSION_ID or version_digest != VERSION_DIGEST
            or dataset_id != DATASET_ID or workspace != WORKSPACE
            or preprocess_digest != PREPROCESS_SHA256):
        raise ValueError('QUALIFIED_RELEASE_REGISTRY_BINDING')
    if not isinstance(member_id, str) or not 1 <= len(member_id) <= 512 or any(ord(c) < 32 for c in member_id):
        raise ValueError('QUALIFIED_IMAGE_MEMBER')
    if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', input_id):
        raise ValueError('QUALIFIED_IMAGE_INPUT_ID')
    if type(asset_bytes) is not int or not 1 <= asset_bytes <= 5 * 1024 * 1024:
        raise ValueError('QUALIFIED_IMAGE_BYTES')
    for key, value in (('plan_result_sha256', plan_result_sha256),
        ('result_record_sha256', result_record_sha256), ('model_digest', model_digest),
        ('bundle_digest', bundle_digest), ('version_digest', version_digest),
        ('asset_sha256', asset_sha256)):
        if not isinstance(value, str) or not _HEX.fullmatch(value):
            raise ValueError('QUALIFIED_IMAGE_' + key.upper())
    for pin in (decoder_image_id, model_image_id):
        if not isinstance(pin, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', pin):
            raise ValueError('QUALIFIED_IMAGE_PIN_REQUIRED')
    if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 128:
        raise ValueError('REAL_IDEMPOTENCY_KEY')
    return {'profile_schema': PROFILE_SCHEMA, 'scope': QUALIFIED_IMAGE_INFER_SCOPE,
        'operation': 'infer-qualified-image', 'workspace': workspace, 'actor': actor,
        'release_id': release_id, 'plan_id': plan_id,
        'plan_result_sha256': plan_result_sha256, 'result_record_sha256': result_record_sha256,
        'model_digest': model_digest, 'bundle_digest': bundle_digest,
        'version_id': version_id, 'version_digest': version_digest,
        'dataset_id': dataset_id, 'member_id': member_id, 'asset_sha256': asset_sha256,
        'asset_bytes': asset_bytes, 'input_id': input_id, 'sample_split': 'upload',
        'preprocess': PREPROCESS_ID, 'preprocess_digest': preprocess_digest,
        'decoder_image_id': decoder_image_id, 'model_image_id': model_image_id,
        'idempotency_key': idempotency_key}


def validate_qualified_image_inference_config(config: Any, *, workspace: str | None = None) -> dict[str, Any]:
    required = {'profile_schema','scope','operation','workspace','actor','release_id','plan_id',
        'plan_result_sha256','result_record_sha256','model_digest','bundle_digest','version_id',
        'version_digest','dataset_id','member_id','asset_sha256','asset_bytes','input_id',
        'sample_split','preprocess','preprocess_digest','decoder_image_id','model_image_id','idempotency_key'}
    if type(config) is not dict or set(config) != required:
        raise ValueError('QUALIFIED_IMAGE_FIELDS')
    if (config['profile_schema'] != PROFILE_SCHEMA or config['scope'] != QUALIFIED_IMAGE_INFER_SCOPE
            or config['operation'] != 'infer-qualified-image' or config['sample_split'] != 'upload'
            or config['preprocess'] != PREPROCESS_ID):
        raise ValueError('QUALIFIED_IMAGE_PROFILE')
    if workspace is not None and config['workspace'] != workspace:
        raise ValueError('REAL_PROFILE_WORKSPACE')
    expected = qualified_image_inference_config(**{k: config[k] for k in (
        'workspace','actor','release_id','plan_id','plan_result_sha256','result_record_sha256',
        'model_digest','bundle_digest','version_id','version_digest','dataset_id','member_id',
        'asset_sha256','asset_bytes','input_id','preprocess_digest','decoder_image_id',
        'model_image_id','idempotency_key')})
    if expected != config:
        raise ValueError('QUALIFIED_IMAGE_NONCANONICAL')
    return config

