"""Authenticated real-run control routes.

These routes queue only immutable, rights-reviewed versions. They never accept
member lists, file paths, image bytes, model code, or a request-selected recipe.
Holdout members and all holdout aggregates remain outside the response surface.
"""
from __future__ import annotations

import os
import uuid
import math
import hashlib
import hmac
import tempfile
import re
from decimal import Decimal
from pathlib import Path
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, ConfigDict, Field

from .data import canonical, digest
from .real_run_profile import (PREPROCESS_DIGEST, RECIPE_DIGEST, REAL_INFER_SCOPE,
                               REAL_TRAIN_SCOPE, MAX_REAL_SAMPLES, training_config,
                               inference_config, image_inference_config,
                               REAL_IMAGE_INFER_SCOPE, QUALIFIED_IMAGE_INFER_SCOPE,
                               qualified_image_inference_config)
from .rights_decision import DecisionRejected


class RealTrainRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    version_id: str = Field(min_length=1, max_length=128)
    version_revision: int = Field(ge=1, le=2_147_483_647)
    epochs: int = Field(default=20, ge=1, le=100)
    batch_size: int = Field(default=16, ge=1, le=32)
    # JSON carries numbers/strings, not Python Decimal instances. Keep the
    # numeric bound while accepting the public JSON representation.
    learning_rate: Decimal = Field(default=Decimal('0.001'), strict=False,
                                  ge=Decimal('0.00001'), le=Decimal('0.1'))
    seed: int = Field(default=42, ge=0, le=4_294_967_295)


class RealInferenceRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    run_id: str = Field(min_length=1, max_length=128)
    sample_id: str = Field(min_length=1, max_length=128)


class RealCancelRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_revision: int = Field(ge=1, le=2_147_483_647)
    reason: str = Field(min_length=1, max_length=2000)


class RealResumeRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    replay_epoch: int = Field(ge=1, le=100)


def _public_run(row):
    """A bounded status projection, never the raw config/result/checkpoint paths."""
    public = {'id': row['id'], 'state': row['state'], 'revision': row['revision'],
            'epoch': row['epoch'], 'scope': row['config'].get('scope'),
            'artifact_status': row.get('artifact_status', 'not_started'),
            'cancel_generation': row.get('cancel_generation'),
            'version_id': row['config'].get('version_id')}
    if public['scope'] == REAL_INFER_SCOPE and row['state'] == 'succeeded':
        prediction = (row.get('result') or {}).get('prediction')
        if type(prediction) is dict and set(prediction) == {'classes', 'probabilities', 'top1'}:
            classes, probabilities, top1 = (prediction[k] for k in ('classes', 'probabilities', 'top1'))
            if (type(classes) is list and len(classes) == 5
                    and all(type(c) is str and 1 <= len(c) <= 200 for c in classes)
                    and type(probabilities) is list and len(probabilities) == 5
                    and all(type(p) in (int, float) and math.isfinite(p) and 0 <= p <= 1
                            for p in probabilities)
                    and abs(sum(probabilities) - 1) <= 1e-6
                    and type(top1) is int and 0 <= top1 < 5
                    and top1 == max(range(5), key=lambda i: probabilities[i])):
                public['prediction'] = {'classes': classes, 'probabilities': probabilities, 'top1': top1}
    elif public['scope'] == REAL_IMAGE_INFER_SCOPE and row['state'] == 'succeeded':
        prediction = (row.get('result') or {}).get('prediction')
        if type(prediction) is dict and set(prediction) == {'classes', 'probabilities', 'top1'}:
            classes, probabilities, top1 = (prediction[k] for k in ('classes', 'probabilities', 'top1'))
            if (type(classes) is list and len(classes) == 5
                    and all(type(c) is str and 1 <= len(c) <= 200 for c in classes)
                    and type(probabilities) is list and len(probabilities) == 5
                    and all(type(p) in (int, float) and math.isfinite(p) and 0 <= p <= 1 for p in probabilities)
                    and abs(sum(probabilities) - 1) <= 1e-6
                    and type(top1) is int and 0 <= top1 < 5
                    and top1 == max(range(5), key=lambda i: probabilities[i])):
                public['prediction'] = {'classes': classes, 'probabilities': probabilities, 'top1': top1}
    elif public['scope'] == QUALIFIED_IMAGE_INFER_SCOPE and row['state'] == 'succeeded':
        prediction = (row.get('result') or {}).get('prediction')
        if type(prediction) is dict and set(prediction) == {'classes', 'probabilities', 'top1'}:
            classes, probabilities, top1 = (prediction[k] for k in ('classes', 'probabilities', 'top1'))
            if (classes == ['Daisy','Dandelion','Rose','Sunflower','Tulip']
                    and type(probabilities) is list and len(probabilities) == 5
                    and all(type(p) in (int, float) and math.isfinite(p) and 0 <= p <= 1 for p in probabilities)
                    and abs(sum(probabilities) - 1) <= 1e-6
                    and type(top1) is int and 0 <= top1 < 5
                    and top1 == max(range(5), key=lambda i: probabilities[i])):
                public['prediction'] = {'classes': classes, 'probabilities': probabilities, 'top1': top1}
    return public


def _manifest_valid(row, workspace, expected_revision):
    if not row or row['state'] != 'frozen' or row['revision'] != expected_revision:
        raise HTTPException(409, 'FROZEN_VERSION_REVISION_MISMATCH')
    manifest = row['manifest']
    if type(manifest) is not dict or manifest.get('scope') != 'real-rights-cleared':
        raise HTTPException(409, 'REAL_FROZEN_VERSION_REQUIRED')
    claimed = manifest.get('digest')
    check = dict(manifest)
    check.pop('digest', None)
    if not isinstance(claimed, str) or digest(canonical(check)) != claimed:
        raise HTTPException(409, 'FROZEN_VERSION_DIGEST_MISMATCH')
    if manifest.get('version_id') != row['id']:
        raise HTTPException(409, 'FROZEN_VERSION_BINDING')
    dataset = manifest.get('rights_dataset_id')
    if not isinstance(dataset, str) or not dataset:
        raise HTTPException(409, 'REAL_RIGHTS_DATASET_REQUIRED')
    samples = manifest.get('samples')
    if type(samples) is not list or not samples:
        raise HTTPException(409, 'REAL_VERSION_EMPTY')
    return manifest, dataset


def _admission_error(exc):
    code = str(exc).splitlines()[0].strip()
    if code in {'QUEUE_FULL', 'WORKSPACE_RUN_LIMIT'}:
        raise HTTPException(423, code) from None
    if code == 'WORKSPACE_EPOCH_LIMIT':
        raise HTTPException(422, code) from None
    raise exc


def _require_inference_bundle_available(store, workspace, source_run_id):
    """Fail closed if retention has reserved, archived, or quarantined a bundle."""
    try:
        from .real_retention import bundle_inference_blocked, RetentionSchemaRequired
        blocked = bundle_inference_blocked(store, workspace, source_run_id)
    except HTTPException:
        raise
    except Exception as exc:
        if type(exc).__name__ == 'RetentionSchemaRequired':
            raise HTTPException(503, 'REAL_BUNDLE_RETENTION_UNAVAILABLE') from None
        raise HTTPException(503, 'REAL_BUNDLE_RETENTION_UNAVAILABLE') from None
    if blocked:
        raise HTTPException(423, 'REAL_BUNDLE_RETENTION_LOCKED')


def _real_inference_actor(user):
    """Require a live workspace role allowed to use an already verified model."""
    if type(user) is not dict or user.get('role') not in {'owner', 'researcher', 'reviewer'}:
        raise HTTPException(403, 'ROLE')
    return user


def _recheck_members(rights_service, workspace, dataset_id, actor, manifest, splits):
    selected = [s for s in manifest['samples'] if s.get('split') in splits]
    # Do not return rows, counts, IDs, or class support in an error or success.
    if not selected or any(type(s) is not dict for s in selected):
        raise HTTPException(409, 'REAL_TRAINING_POPULATION_REQUIRED')
    if len(selected) > MAX_REAL_SAMPLES:
        raise HTTPException(413, 'REAL_POPULATION_BOUNDS')
    member_ids = list(dict.fromkeys(s.get('source_member') for s in selected))
    if any(type(m) is not str or not m for m in member_ids):
        raise HTTPException(409, 'REAL_RIGHTS_BINDING_INVALID')
    if len(member_ids) > rights_service.MAX_EXPLICIT_MEMBERS:
        raise HTTPException(413, 'REAL_RIGHTS_BATCH_LIMIT')
    try:
        decisions = rights_service.require_members(workspace, dataset_id, actor,
                                                  'local_private_training', member_ids)
    except DecisionRejected:
        raise HTTPException(403, 'REAL_RIGHTS_NOT_READY') from None
    verified = {d.member_id: d.asset_sha256 for d in decisions}
    if any(verified.get(s['source_member']) != s.get('sha256') for s in selected):
        raise HTTPException(403, 'REAL_RIGHTS_ASSET_MISMATCH')
    return selected


def create_router(*, store, session_dependency: Callable, writer_dependency: Callable,
                  rights_service) -> APIRouter:
    """Create an unmounted router over the request principal Store.

    `store` is the authenticated request Store, not a worker/operator connection.
    Runtime integration must use the same transaction-local workspace setting and
    role grants as the existing API. The queue is `fw_runs`; the scoped worker's
    separate real capability selects only the explicit real profile.
    """
    router = APIRouter()

    def scoped(workspace_id: str, user=Depends(session_dependency)):
        if workspace_id != user['workspace']:
            raise HTTPException(404, 'OBJECT_OR_MEMBERSHIP')
        return user

    def writer(workspace_id: str, user=Depends(writer_dependency)):
        if workspace_id != user['workspace']:
            raise HTTPException(404, 'OBJECT_OR_MEMBERSHIP')
        return user

    def inference_actor(workspace_id: str, request: Request, user=Depends(session_dependency)):
        """Fresh session role plus CSRF scope for the two inference selectors."""
        if workspace_id != user['workspace']:
            raise HTTPException(404, 'OBJECT_OR_MEMBERSHIP')
        user = _real_inference_actor(user)
        if request.headers.get('origin') not in {'http://127.0.0.1:5102', 'http://127.0.0.1:8102'} or not hmac.compare_digest(
                request.headers.get('x-csrf-token', ''), user.get('csrf', '')):
            raise HTTPException(403, 'CSRF_OR_ORIGIN')
        return user

    @router.get('/api/v1/workspaces/{workspace_id}/real/runs')
    def list_runs(workspace_id: str, limit: int = Query(default=50,ge=1,le=100),
                  after: str = Query(default='',max_length=128), user=Depends(scoped)):
        with store.connect() as c:
            rows=c.execute('''SELECT id,config,state,revision,epoch,artifact_status,cancel_generation
                FROM fw_runs WHERE workspace=%s AND id>%s
                AND config->>'scope' IN ('real-training/v1','real-inference/v1','real-image-inference/v1','qualified-release-image-inference/v1')
                AND (%s OR config->>'scope'<>'qualified-release-image-inference/v1')
                ORDER BY id LIMIT %s''',(workspace_id,after,user.get('role') in {'owner','researcher','reviewer'},limit+1)).fetchall()
        return {'items':[_public_run(row) for row in rows[:limit]],
                'next_cursor':rows[limit-1]['id'] if len(rows)>limit else None}

    @router.post('/api/v1/workspaces/{workspace_id}/real/runs', status_code=202)
    def enqueue_training(workspace_id: str, body: RealTrainRequest, request: Request,
                         user=Depends(writer)):
        key = request.headers.get('Idempotency-Key', '')
        if not 1 <= len(key) <= 128:
            raise HTTPException(422, 'IDEMPOTENCY_KEY_REQUIRED')
        with store.connect() as c:
            version = c.execute('''SELECT id,state,revision,manifest FROM fw_versions
                WHERE workspace=%s AND id=%s''', (workspace_id, body.version_id)).fetchone()
        manifest, dataset_id = _manifest_valid(version, workspace_id, body.version_revision)
        _recheck_members(rights_service, workspace_id, dataset_id, user['name'], manifest,
                         {'train', 'validation'})
        decoder_image_id = os.environ.get('FIELDWORK_REAL_PIXEL_IMAGE_ID', '')
        if not decoder_image_id:
            raise HTTPException(423, 'REAL_PIXEL_DECODER_NOT_PROVISIONED')
        model_image_id = os.environ.get('FIELDWORK_REAL_MODEL_IMAGE_ID', '')
        if not model_image_id:
            raise HTTPException(423, 'REAL_MODEL_IMAGE_NOT_PROVISIONED')
        try:
            config = training_config(
                version_id=version['id'], version_revision=version['revision'],
                version_digest=manifest['digest'], workspace=workspace_id,
                dataset_id=dataset_id, actor=user['name'], recipe_digest=RECIPE_DIGEST,
                preprocess_digest=PREPROCESS_DIGEST, decoder_image_id=decoder_image_id,
                model_image_id=model_image_id,
                epochs=body.epochs,
                batch_size=body.batch_size, learning_rate=format(body.learning_rate, 'f'),
                weight_decay='0.0001', seed=body.seed,
                idempotency_key=key)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        try:
            row = store.submit(workspace_id, user['name'], key, config)
        except Exception as exc:
            _admission_error(exc)
        return _public_run(row)

    @router.get('/api/v1/workspaces/{workspace_id}/real/runs/{run_id}')
    def run_status(workspace_id: str, run_id: str, user=Depends(scoped)):
        row = store.get(run_id, workspace_id)
        if not row or row['config'].get('scope') not in {REAL_TRAIN_SCOPE, REAL_INFER_SCOPE, REAL_IMAGE_INFER_SCOPE, QUALIFIED_IMAGE_INFER_SCOPE}:
            raise HTTPException(404, 'OBJECT')
        if row['config'].get('scope') == QUALIFIED_IMAGE_INFER_SCOPE and user.get('role') not in {'owner','researcher','reviewer'}:
            raise HTTPException(403, 'ROLE')
        return {'run': _public_run(row)}

    @router.post('/api/v1/workspaces/{workspace_id}/real/runs/{run_id}/cancel')
    def cancel_run(workspace_id: str, run_id: str, body: RealCancelRequest,
                   request: Request, user=Depends(inference_actor)):
        key = request.headers.get('Idempotency-Key', '')
        try:
            if len(key) != 36 or str(uuid.UUID(key)) != key.lower():
                raise ValueError()
        except ValueError:
            raise HTTPException(422, 'IDEMPOTENCY_KEY_REQUIRED') from None
        if request.headers.get('If-Match') != f'"{body.expected_revision}"':
            raise HTTPException(428 if not request.headers.get('If-Match') else 422,
                                'IF_MATCH_EXPECTED_REVISION_REQUIRED')
        row = store.get(run_id, workspace_id)
        if not row or row['config'].get('scope') not in {REAL_TRAIN_SCOPE, REAL_INFER_SCOPE, REAL_IMAGE_INFER_SCOPE, QUALIFIED_IMAGE_INFER_SCOPE}:
            raise HTTPException(404, 'OBJECT')
        if user['role'] == 'reviewer' and (row['config'].get('scope') == REAL_TRAIN_SCOPE
                                         or row.get('actor') != user['name']):
            raise HTTPException(403, 'ROLE')
        status, payload = store.cancel_command(workspace_id, user['name'], key,
                                               run_id, body.expected_revision, body.reason)
        if row['config'].get('scope') == QUALIFIED_IMAGE_INFER_SCOPE:
            terminal = store.get(run_id, workspace_id)
            if terminal and terminal['state'] == 'cancelled':
                from .qualified_release import archive_qualified_upload
                archive_qualified_upload(terminal['config']['input_id'], terminal['config']['asset_sha256'])
        from fastapi.responses import Response
        return Response(payload, status_code=status, media_type='application/json')

    @router.post('/api/v1/workspaces/{workspace_id}/real/runs/{run_id}/resume', status_code=202)
    def resume_run(workspace_id: str, run_id: str, body: RealResumeRequest,
                   user=Depends(writer)):
        row = store.get(run_id, workspace_id)
        if not row or row['config'].get('scope') != REAL_TRAIN_SCOPE:
            raise HTTPException(404, 'OBJECT')
        if body.replay_epoch > row['config'].get('epochs', 0):
            raise HTTPException(422, 'REPLAY_EPOCH_OUT_OF_RANGE')
        try:
            store.resume(workspace_id, run_id, body.replay_epoch)
        except Exception as exc:
            code = str(exc).splitlines()[0].strip()
            if code in {'WORKSPACE_RUN_LIMIT', 'WORKSPACE_EPOCH_LIMIT'}:
                _admission_error(exc)
            raise HTTPException(409, 'REAL_RUN_NOT_RESUMABLE') from None
        return {'state': 'queued', 'replay_epoch': body.replay_epoch}

    @router.post('/api/v1/workspaces/{workspace_id}/real/inferences', status_code=202)
    def enqueue_inference(workspace_id: str, body: RealInferenceRequest,
                          request: Request, user=Depends(inference_actor)):
        raise HTTPException(403, 'QUALIFIED_RELEASE_REQUIRED')

    @router.post('/api/v1/workspaces/{workspace_id}/real/inferences/image', status_code=202)
    async def enqueue_image_inference(workspace_id: str, request: Request,
            run_id: str = Query(min_length=1, max_length=128),
            dataset_id: str = Query(min_length=36, max_length=36),
            member_id: str = Query(min_length=1, max_length=512),
            user=Depends(inference_actor)):
        raise HTTPException(403, 'QUALIFIED_RELEASE_REQUIRED')

    @router.post('/api/v1/workspaces/{workspace_id}/qualified-releases/{release_id}/inferences/image', status_code=202)
    async def enqueue_qualified_image_inference(workspace_id: str, release_id: str, request: Request,
            member_id: str = Query(min_length=1, max_length=512),
            user=Depends(inference_actor)):
        """Queue one licensed fresh image against the exact R5 qualified release."""
        from .qualified_release import registered_release, require_consumed_plan, PREPROCESS_SHA256
        content_type = request.headers.get('content-type', '').split(';', 1)[0].strip().lower()
        if content_type not in {'image/jpeg', 'image/png', 'image/webp'}:
            raise HTTPException(415, 'REAL_IMAGE_FORMAT')
        key = request.headers.get('Idempotency-Key', '')
        if not 1 <= len(key) <= 128:
            raise HTTPException(422, 'IDEMPOTENCY_KEY_REQUIRED')
        release = registered_release(release_id, workspace_id)
        if not release or not require_consumed_plan(store, release):
            raise HTTPException(404, 'QUALIFIED_RELEASE_NOT_AVAILABLE')
        decoder_image_id = os.environ.get('FIELDWORK_REAL_PIXEL_IMAGE_ID', '')
        model_image_id = os.environ.get('FIELDWORK_QUALIFIED_MODEL_IMAGE_ID', '')
        if not decoder_image_id or not model_image_id or model_image_id != os.environ.get('FIELDWORK_REAL_MODEL_IMAGE_ID', ''):
            raise HTTPException(423, 'QUALIFIED_MODEL_RUNTIME_NOT_PROVISIONED')
        # The fixed r5 source lock is part of the model image. Never accept an image
        # id, executable, path or recipe from the browser.
        upload_root = Path(__file__).resolve().parents[1] / '.local' / 'real-inference-uploads'
        upload_root.mkdir(parents=True, exist_ok=True)
        upload_key = str(uuid.uuid4())
        final_path = upload_root / (upload_key + '.img')
        fd, temp_name = tempfile.mkstemp(prefix='.upload-', suffix='.part', dir=upload_root)
        sha = hashlib.sha256(); size = 0
        try:
            with os.fdopen(fd, 'wb') as stream:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > 5 * 1024 * 1024:
                        raise HTTPException(413, 'REAL_IMAGE_SIZE_LIMIT')
                    sha.update(chunk); stream.write(chunk)
                if size < 1:
                    raise HTTPException(422, 'REAL_IMAGE_EMPTY')
                stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
        asset_sha = sha.hexdigest()
        try:
            rights_service.require_real_inference_members(workspace_id, release['dataset_id'],
                user['name'], member_id, asset_sha, size)
        except DecisionRejected:
            Path(temp_name).unlink(missing_ok=True)
            raise HTTPException(403, 'REAL_IMAGE_RIGHTS_NOT_READY') from None
        try:
            with store.connect() as c:
                version = c.execute('''SELECT id,state,revision,manifest FROM fw_versions
                    WHERE workspace=%s AND id=%s''', (workspace_id, release['version_id'])).fetchone()
            if (not version or version['state'] != 'frozen'
                    or version['manifest'].get('digest') != release['version_digest']
                    or version['manifest'].get('rights_dataset_id') != release['dataset_id']):
                raise HTTPException(409, 'QUALIFIED_RELEASE_VERSION_BINDING')
            config = qualified_image_inference_config(workspace=workspace_id, actor=user['name'],
                release_id=release['release_id'], plan_id=release['plan_id'],
                plan_result_sha256=release['plan_result_sha256'],
                result_record_sha256=release['result_record_sha256'],
                model_digest=release['model_digest'], bundle_digest=release['manifest_sha256'],
                version_id=release['version_id'], version_digest=release['version_digest'],
                dataset_id=release['dataset_id'], member_id=member_id, asset_sha256=asset_sha,
                asset_bytes=size, input_id=upload_key,
                preprocess_digest=PREPROCESS_SHA256,
                decoder_image_id=decoder_image_id, model_image_id=model_image_id,
                idempotency_key=key)
        except HTTPException:
            Path(temp_name).unlink(missing_ok=True)
            raise
        except ValueError as exc:
            Path(temp_name).unlink(missing_ok=True)
            raise HTTPException(422, str(exc)) from None
        from psycopg.types.json import Jsonb
        config_digest = digest(canonical(config)); rid = str(uuid.uuid4())
        try:
            with store.connect() as c:
                c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))', (workspace_id,))
                prior = c.execute('SELECT * FROM fw_runs WHERE workspace=%s AND actor=%s AND idem=%s',
                                  (workspace_id, user['name'], key)).fetchone()
                if prior:
                    prior_config, candidate_config = dict(prior['config']), dict(config)
                    prior_config.pop('input_id', None); candidate_config.pop('input_id', None)
                    if prior_config != candidate_config:
                        Path(temp_name).unlink(missing_ok=True)
                        raise HTTPException(409, 'IDEMPOTENCY_CONFLICT')
                    if prior['state'] in {'succeeded','failed','cancelled'}:
                        Path(temp_name).unlink(missing_ok=True)
                        from .qualified_release import archive_qualified_upload
                        archive_qualified_upload(prior['config']['input_id'], prior['config']['asset_sha256'])
                        return _public_run(prior)
                    saved = c.execute('SELECT input_id FROM fw_real_image_inputs WHERE workspace=%s AND run=%s',
                                      (workspace_id, prior['id'])).fetchone()
                    if not saved or not (upload_root / (str(saved['input_id']) + '.img')).is_file():
                        Path(temp_name).unlink(missing_ok=True)
                        raise HTTPException(503, 'REAL_IMAGE_INPUT_UNAVAILABLE')
                    Path(temp_name).unlink(missing_ok=True)
                    return _public_run(prior)
                if c.execute("SELECT count(*) AS n FROM fw_runs WHERE workspace=%s AND state='queued'", (workspace_id,)).fetchone()['n'] >= 20:
                    Path(temp_name).unlink(missing_ok=True)
                    raise HTTPException(423, 'QUEUE_FULL')
                os.replace(temp_name, final_path)
                c.execute('INSERT INTO fw_runs(id,workspace,actor,idem,digest,config) VALUES(%s,%s,%s,%s,%s,%s)',
                    (rid, workspace_id, user['name'], key, config_digest, Jsonb(config)))
                row = c.execute('SELECT * FROM fw_runs WHERE id=%s', (rid,)).fetchone()
                c.execute('''INSERT INTO fw_real_image_inputs(workspace,run,input_id,dataset_id,member_id,
                             asset_sha256,asset_bytes,upload_key) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (workspace_id, rid, upload_key, release['dataset_id'], member_id, asset_sha, size, upload_key))
                store.event(c, row, 'queued', {'state':'queued','scope':'qualified-release-image-inference/v1'})
        except HTTPException:
            raise
        except Exception as exc:
            _admission_error(exc)
        return _public_run(row)

    return router

