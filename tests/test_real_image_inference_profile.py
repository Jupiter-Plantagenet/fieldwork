from __future__ import annotations

import copy
import uuid

import pytest

from fieldwork.real_run_profile import (PREPROCESS_DIGEST, REAL_IMAGE_INFER_SCOPE,
    image_inference_config, validate_image_inference_config)
from fieldwork.real_runs_api import _real_inference_actor
from fastapi import HTTPException
from fieldwork.rights_store import RightsRepository


def profile():
    return image_inference_config(workspace='ws', actor='reviewer-1', run_id='training-run',
        version_id='frozen-v1', version_digest='a' * 64,
        dataset_id=str(uuid.uuid4()), member_id='registered-member-1',
        asset_sha256='b' * 64, asset_bytes=1024, input_id=str(uuid.uuid4()),
        bundle_digest='c' * 64, preprocess_digest=PREPROCESS_DIGEST,
        decoder_image_id='sha256:' + 'd' * 64, model_image_id='sha256:' + 'e' * 64,
        idempotency_key='fresh-image-1')


def test_image_inference_profile_is_closed_and_server_bound():
    config = profile()
    assert config['scope'] == REAL_IMAGE_INFER_SCOPE
    assert config['operation'] == 'infer-image'
    assert config['sample_split'] == 'upload'
    assert validate_image_inference_config(config, workspace='ws') == config
    with pytest.raises(ValueError, match='FIELDS'):
        validate_image_inference_config({**config, 'media_path': 'C:/private/image.png'})


@pytest.mark.parametrize('field,value', [
    ('sample_split', 'holdout'),
    ('input_id', 'path/to/image'),
    ('asset_bytes', 20 * 1024 * 1024 + 1),
    ('decoder_image_id', 'latest'),
    ('member_id', ''),
])
def test_image_profile_rejects_scope_or_binding_changes(field, value):
    changed = copy.deepcopy(profile())
    changed[field] = value
    with pytest.raises(ValueError):
        validate_image_inference_config(changed)


@pytest.mark.parametrize('role', ['owner', 'researcher', 'reviewer'])
def test_image_inference_role_allowlist(role):
    user = {'name': 'current-account', 'workspace': 'ws', 'role': role}
    assert _real_inference_actor(user) is user


@pytest.mark.parametrize('role', ['viewer', 'holdout_steward', 'admin', None])
def test_image_inference_rejects_roles_without_consuming_anything(role):
    with pytest.raises(HTTPException) as error:
        _real_inference_actor({'name': 'current-account', 'workspace': 'ws', 'role': role})
    assert error.value.status_code == 403
    assert error.value.detail == 'ROLE'


def test_reviewer_read_only_admission_does_not_grant_training_or_bundle_control():
    class Row:
        def fetchone(self):
            return {'role': 'reviewer'}

    class Connection:
        def execute(self, *_args):
            return Row()

    repository = RightsRepository(Connection())
    assert repository.authorize('ws', 'reviewer-1', 'read_only_real_inference')
    assert not repository.authorize('ws', 'reviewer-1', 'local_private_training')
    assert not repository.authorize('ws', 'reviewer-1', 'model_bundle')
