"""Focused source-contract and route behavior tests for the real-data API boundary.

They use authored fixtures only and do not read heldout data or require PostgreSQL.
"""
import copy
from pathlib import Path
from contextlib import contextmanager
from hashlib import sha256
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fieldwork.real_api import InitialSplitPlanRequest, RealDraftRequest, _inside_root, _read_verified_media, create_router
from fieldwork import annotations


def test_media_path_must_resolve_inside_operator_media_root(tmp_path):
    media = tmp_path / 'media'
    media.mkdir()
    image = media / 'a.jpg'
    image.write_bytes(b'image')
    assert _inside_root(image, media) == image.resolve()

    outside = tmp_path / 'outside.jpg'
    outside.write_bytes(b'image')
    with pytest.raises(HTTPException) as error:
        _inside_root(outside, media)
    assert error.value.status_code == 404


def test_media_read_is_bounded_and_digest_pinned(tmp_path):
    image = tmp_path / 'image.jpg'
    content = b'valid image bytes'
    image.write_bytes(content)
    assert _read_verified_media(image, sha256(content).hexdigest(), len(content)) == content

    with pytest.raises(HTTPException) as error:
        _read_verified_media(image, '0' * 64, len(content))
    assert error.value.status_code == 409
    with pytest.raises(HTTPException) as error:
        _read_verified_media(image, sha256(content).hexdigest(), len(content) + 1)
    assert error.value.status_code == 413


def test_protected_holdout_sample_is_not_retrievable_from_media_route(tmp_path):
    class EmptyConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, *_args):
            return SimpleNamespace(fetchone=lambda: None)

    class RequestStore:
        def connect(self):
            return EmptyConnection()

    class Rights:
        called = False

        def require(self, *_args):
            self.called = True
            return []

    user = {'name': 'researcher', 'workspace': str(uuid4()), 'csrf': 'test'}
    rights = Rights()
    app = FastAPI()
    app.include_router(create_router(store=RequestStore(), session_dependency=lambda: user,
                                     writer_dependency=lambda: user, rights_service=rights,
                                     media_root=tmp_path, upload_root=tmp_path / 'uploads'))
    with TestClient(app) as client:
        response = client.get(f"/api/v1/workspaces/{user['workspace']}/real/samples/{uuid4()}/media")
    assert response.status_code == 404
    assert rights.called is False


def test_migration_sets_tenant_rls_and_separate_steward_authority():
    migration = Path(__file__).parents[1] / 'migrations' / '006_real_data_api.sql'
    sql = migration.read_text(encoding='utf-8')
    assert "ALTER TABLE %I ENABLE ROW LEVEL SECURITY" in sql
    assert "ALTER TABLE %I FORCE ROW LEVEL SECURITY" in sql
    assert "workspace=current_setting(''fieldwork.workspace'',true)" in sql
    assert 'fw_holdout_stewards' in sql
    assert "SELECT role FROM fw_accounts" not in sql  # no owner-role steward shortcut


def test_migration_removes_api_temp_privilege_for_search_path_safety():
    migration = Path(__file__).parents[1] / 'migrations' / '006_real_data_api.sql'
    sql = migration.read_text(encoding='utf-8')
    assert 'REVOKE TEMP ON DATABASE %I FROM PUBLIC' in sql
    assert 'REVOKE TEMP ON DATABASE %I FROM fieldwork_api' in sql
    assert 'GRANT TEMP ON DATABASE %I TO fieldwork_api' not in sql
    assert 'FIELDWORK_API_TEMP_PRIVILEGE_REMAINS' in sql


def test_api_never_returns_holdout_members_or_accepts_client_filesystem_paths():
    source = Path(__file__).parents[1] / 'fieldwork' / 'real_api.py'
    code = source.read_text(encoding='utf-8')
    assert "request.stream()" in code
    assert "population_members" in code
    assert "holdout_rows_returned': 0" in code
    assert "member->>'sha256'=s.raw_sha256" in code
    assert "member->>'pixel_sha256'=s.pixel_sha256" in code
    assert "archive_path" in code  # value is generated from upload_root, never request data
    assert "request.query_params.get('path')" not in code


def test_real_draft_request_accepts_only_one_server_owned_source():
    parent = RealDraftRequest(parent_version_id='version-1', parent_version_digest='a' * 64)
    intake = RealDraftRequest(intake_id=uuid4())
    assert parent.parent_version_id == 'version-1'
    assert intake.intake_id is not None
    with pytest.raises(ValueError):
        RealDraftRequest()
    with pytest.raises(ValueError):
        RealDraftRequest(intake_id=uuid4(), parent_version_id='version-1', parent_version_digest='a' * 64)
    with pytest.raises(ValueError):
        RealDraftRequest(parent_version_id='version-1')
    with pytest.raises(ValueError):
        RealDraftRequest(intake_id=uuid4(), samples=[])


def test_real_version_projection_redacts_protected_members_paths_and_quarantine():
    v = {'state': 'frozen', 'manifest': {
        'scope': 'real-rights-cleared', 'digest': 'b' * 64,
        'samples': [
            {'id': 'train-id', 'split': 'train', 'label': 1, 'file': 'C:/private/train.jpg'},
            {'id': 'held-id', 'split': 'holdout', 'label': 4, 'file': 'C:/private/held.jpg'},
            {'id': 'flagged-id', 'split': 'train', 'label': 2, 'protected': True, 'file': 'C:/private/flagged.jpg'},
        ],
        'quarantine': [{'members': ['held-id'], 'member_sources': ['private/member.jpg'], 'extra_claims': [4]}],
        'group_audit': {'status': 'complete', 'audit_complete': True,
            'edges': [{'left': 'held-id', 'right': 'train-id', 'kind': 'raw_equal',
                       'detail': {'raw_sha256': 'c' * 64}},
                      {'left': 'flagged-id', 'right': 'train-id', 'kind': 'same_source_photo_id',
                       'detail': {'source_photo_id': 987654}}],
            'missing_feature_samples': ['held-id', 'flagged-id']},
    }}
    stored_manifest = copy.deepcopy(v['manifest'])
    projected = annotations.view(v, [])
    assert [s['id'] for s in projected['manifest']['samples']] == ['train-id']
    assert all('file' not in s for s in projected['manifest']['samples'])
    assert 'quarantine' not in projected['manifest']
    assert 'group_audit' not in projected['manifest']
    assert v['manifest'] == stored_manifest


def test_holdout_reuse_guard_is_workspace_wide_not_version_scoped():
    source = Path(__file__).parents[1] / 'fieldwork' / 'real_api.py'
    code = source.read_text(encoding='utf-8')
    assert "workspace_id + ':holdout-population:' + body.population_digest" in code
    assert 'AND population_digest=%s AND (exposures>0 OR consumed_utc IS NOT NULL)' in code
    assert 'version_id=%s AND population_digest=%s AND (exposures>0' not in code
    assert "workspace_id + ':holdout-content-identity'" in code
    assert 'overlaps_exposed_population(version[\'manifest\'], body.population_tag, history)' in code
    assert 'LEFT JOIN fw_versions v' in code
    assert 'p.exposures>0 OR p.consumed_utc IS NOT NULL' in code
    assert "if message.startswith('REAL_FREEZE_BLOCKED:')" in code
    assert "message = 'REAL_FREEZE_BLOCKED'" in code


def test_initial_split_request_contains_only_revision_fence():
    assert InitialSplitPlanRequest(revision=3).revision == 3
    with pytest.raises(ValueError):
        InitialSplitPlanRequest(revision=3, sample_ids=['caller-controlled'])
    source = Path(__file__).parents[1] / 'fieldwork' / 'real_api.py'
    code = source.read_text(encoding='utf-8')
    assert "'/api/v1/workspaces/{workspace_id}/real/versions/{version_id}/split-plan'" in code
    assert 'assign_initial_splits(version[\'manifest\'], rows, source_digest)' in code
    assert 'protected_holdout_created' not in code
