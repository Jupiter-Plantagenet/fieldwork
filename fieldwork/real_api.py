"""Real-data API routes mounted by ``fieldwork.api``.

This module intentionally owns no identity stack, database credentials, registry
loader, decoder, or worker. It receives the existing request-scoped Store and auth
dependencies from the application. Intake only queues a server-staged archive;
an independently scoped intake worker must process it. Freeze rechecks rights at
the point of use. Holdout routes require an explicit operator-assigned DB steward
record; account role ``owner`` is never sufficient.
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from psycopg.types.json import Jsonb

from . import annotations
from .dataset_versions import freeze_real
from .rights_decision import DecisionRejected

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEDIA_BYTES = 24 * 1024 * 1024
MEDIA_TYPES = {'.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp'}


def _inside_root(path: str | Path, root: str | Path) -> Path:
    """Resolve an operator-recorded path; reject traversal and reparse points."""
    root_path = Path(root).absolute()
    target_path = Path(path).absolute()
    try:
        lexical = target_path.relative_to(root_path)
    except (ValueError, OSError):
        raise HTTPException(404, 'MEDIA_NOT_FOUND') from None
    # Windows symlinks/junctions and POSIX symlinks both appear as reparse
    # points/symlinks in lstat. Check every path component before resolving.
    current = root_path
    for part in ('.', *lexical.parts):
        current = current if part == '.' else current / part
        try:
            info = current.lstat()
        except OSError:
            raise HTTPException(404, 'MEDIA_NOT_FOUND') from None
        attrs = getattr(info, 'st_file_attributes', 0)
        reparse = bool(attrs & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))
        if current.is_symlink() or reparse:
            raise HTTPException(404, 'MEDIA_NOT_FOUND') from None
    try:
        base = root_path.resolve(strict=True)
        target = target_path.resolve(strict=True)
        target.relative_to(base)
    except (ValueError, OSError):
        raise HTTPException(404, 'MEDIA_NOT_FOUND') from None
    if not target.is_file():
        raise HTTPException(404, 'MEDIA_NOT_FOUND')
    return target


def _read_verified_media(path: Path, expected_sha256: str, expected_bytes: int) -> bytes:
    """Bound the read and detect catalog/path replacement around the open."""
    try:
        before = path.stat()
        if before.st_size != expected_bytes or expected_bytes > MAX_MEDIA_BYTES:
            raise HTTPException(413, 'MEDIA_TOO_LARGE')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise HTTPException(409, 'MEDIA_CHANGED')
            chunks = []
            total = 0
            while True:
                block = os.read(fd, min(1024 * 1024, MAX_MEDIA_BYTES + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > MAX_MEDIA_BYTES or total > expected_bytes:
                    raise HTTPException(413, 'MEDIA_TOO_LARGE')
            data = b''.join(chunks)
            after = path.stat()
            if (after.st_dev, after.st_ino, after.st_size) != (opened.st_dev, opened.st_ino, total):
                raise HTTPException(409, 'MEDIA_CHANGED')
        finally:
            os.close(fd)
    except HTTPException:
        raise
    except OSError:
        raise HTTPException(404, 'MEDIA_NOT_FOUND') from None
    if total != expected_bytes or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise HTTPException(409, 'MEDIA_DIGEST_MISMATCH')
    return data


async def _stage_upload(request: Request, upload_root: Path) -> tuple[Path, str, int]:
    """Stream a bounded upload to a server-generated path; never accept a path/URL."""
    upload_root.mkdir(parents=True, exist_ok=True)
    intake_id = uuid.uuid4()
    partial = upload_root / ('.' + intake_id.hex + '.uploading')
    final = upload_root / (intake_id.hex + '.archive')
    digest = hashlib.sha256()
    size = 0
    try:
        with partial.open('xb') as stream:
            async for chunk in request.stream():
                if not chunk:
                    continue
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise HTTPException(413, 'ARCHIVE_TOO_LARGE')
                digest.update(chunk)
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if size == 0:
            raise HTTPException(422, 'EMPTY_ARCHIVE')
        # The target name is random and created only after the complete body is durable.
        os.replace(partial, final)
        return final, digest.hexdigest(), size
    except BaseException:
        try:
            partial.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class FreezeRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revision: int = Field(ge=1, le=2_147_483_647)


class HoldoutPlanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    version_id: str = Field(min_length=1, max_length=128)
    version_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    population_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    population_count: int = Field(gt=0, le=2_000_000)
    population_tag: str = Field(min_length=1, max_length=120)
    candidate_model_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    candidate_checkpoint_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    evaluator: str = Field(min_length=1, max_length=200)
    usefulness_spec_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')


class InvalidatePlanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    reason: str = Field(min_length=10, max_length=2000)


class RealDraftRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    intake_id: uuid.UUID | None = None
    parent_version_id: str | None = Field(default=None, min_length=1, max_length=128)
    parent_version_digest: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')

    @model_validator(mode='after')
    def one_server_owned_source(self):
        intake_source = self.intake_id is not None
        parent_source = self.parent_version_id is not None
        if intake_source == parent_source:
            raise ValueError('EXACTLY_ONE_REAL_DRAFT_SOURCE_REQUIRED')
        if parent_source != (self.parent_version_digest is not None):
            raise ValueError('PARENT_VERSION_DIGEST_REQUIRED')
        return self


class InitialSplitPlanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    revision: int = Field(ge=1, le=2_147_483_647)


def create_router(*, store, session_dependency: Callable, writer_dependency: Callable,
                  rights_service, media_root: str | Path, upload_root: str | Path) -> APIRouter:
    """Build real-data routes using the app's existing auth and request Store.

    ``store`` must be the request principal Store (never an operator Store). The
    app middleware must set ``fieldwork.workspace`` from the authenticated route;
    all SQL here also filters by the authenticated workspace. The rights service
    must be the existing RightsService backed by the operator-controlled public
    reviewer registry. Upload processing is intentionally queued, not run inline.
    """
    router = APIRouter()
    media_base = Path(media_root)
    upload_base = Path(upload_root)

    def workspace_user(workspace_id: str, user=Depends(session_dependency)):
        if workspace_id != user['workspace']:
            raise HTTPException(404, 'OBJECT_OR_MEMBERSHIP')
        return user

    def writer(workspace_id: str, user=Depends(writer_dependency)):
        if workspace_id != user['workspace']:
            raise HTTPException(404, 'OBJECT_OR_MEMBERSHIP')
        return user

    def steward(workspace_id: str, request: Request, user=Depends(session_dependency)):
        if workspace_id != user['workspace']:
            raise HTTPException(404, 'OBJECT_OR_MEMBERSHIP')
        if request.headers.get('origin') not in ['http://127.0.0.1:5102', 'http://127.0.0.1:8102']:
            raise HTTPException(403, 'CSRF_OR_ORIGIN')
        import hmac
        if not hmac.compare_digest(request.headers.get('x-csrf-token', ''), user['csrf']):
            raise HTTPException(403, 'CSRF_OR_ORIGIN')
        # Explicit, operator-provisioned assignment. `owner` is not a shortcut.
        with store.connect() as c:
            assigned = c.execute('''SELECT reviewer_id,key_id FROM fw_holdout_stewards
                WHERE workspace=%s AND actor=%s''', (workspace_id, user['name'])).fetchone()
        if not assigned:
            raise HTTPException(403, 'HOLDOUT_STEWARD_REQUIRED')
        # The DB assignment is the authority; the public registry lookup ensures
        # its named rights reviewer key remains present and workspace-scoped.
        # Removing a reviewer key therefore revokes subsequent steward requests.
        try:
            trusted = rights_service.registry_provider().get((assigned['reviewer_id'], assigned['key_id']))
        except DecisionRejected:
            trusted = None
        if not trusted or workspace_id not in trusted.workspace_ids:
            raise HTTPException(403, 'HOLDOUT_REVIEWER_NOT_TRUSTED')
        return user

    @router.post('/api/v1/workspaces/{workspace_id}/real/intakes', status_code=202)
    async def enqueue_intake(workspace_id: str, request: Request, dataset_id: str,
                             user=Depends(writer)):
        # A fresh inventory-wide rights verification is required before queueing.
        # It discloses no member list and is repeated by the intake worker per asset.
        try:
            rights_service.require(workspace_id, dataset_id, user['name'], 'local_private_training')
        except DecisionRejected as exc:
            raise HTTPException(403, 'RIGHTS_NOT_READY') from None
        archive, archive_sha, archive_bytes = await _stage_upload(request, upload_base)
        intake_id = uuid.uuid4()
        try:
            with store.connect() as c:
                c.execute('''INSERT INTO fw_real_intake_queue
                    (workspace,intake_id,actor,rights_dataset_id,archive_path,archive_sha256,archive_bytes)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(workspace,archive_sha256) DO NOTHING''',
                          (workspace_id, intake_id, user['name'], dataset_id, str(archive), archive_sha, archive_bytes))
                row = c.execute('''SELECT intake_id,state,actor,rights_dataset_id FROM fw_real_intake_queue
                    WHERE workspace=%s AND archive_sha256=%s''', (workspace_id, archive_sha)).fetchone()
                if not row or row['actor'] != user['name'] or row['rights_dataset_id'] != dataset_id:
                    raise HTTPException(409, 'ARCHIVE_ALREADY_QUEUED')
        except BaseException:
            # Preserve a file once a queue row commits; remove only this unreferenced
            # upload on failure. A concurrent identical submission owns its own path.
            with store.connect() as c:
                referenced = c.execute('SELECT 1 FROM fw_real_intake_queue WHERE archive_path=%s', (str(archive),)).fetchone()
            if not referenced:
                archive.unlink(missing_ok=True)
            raise
        if str(row['intake_id']) != str(intake_id):
            # An identical archive was already queued. Keep only its original
            # server-staged path and avoid retaining this duplicate upload.
            archive.unlink(missing_ok=True)
        return {'intake_id': str(row['intake_id']), 'state': row['state'], 'status_url': f'/api/v1/workspaces/{workspace_id}/real/intakes/{row["intake_id"]}'}

    @router.get('/api/v1/workspaces/{workspace_id}/real/intakes/{intake_id}')
    def intake_status(workspace_id: str, intake_id: uuid.UUID, user=Depends(workspace_user)):
        with store.connect() as c:
            row = c.execute('''SELECT intake_id,state,result_batch_id,result_sha256,created_utc,finished_utc
                FROM fw_real_intake_queue WHERE workspace=%s AND intake_id=%s AND actor=%s''',
                (workspace_id, intake_id, user['name'])).fetchone()
            if not row:
                raise HTTPException(404, 'OBJECT')
            row = dict(row)
            row['detail'] = _intake_detail(c, workspace_id, row) if row['result_batch_id'] else None
        return row

    @router.get('/api/v1/workspaces/{workspace_id}/real/intakes')
    def list_intakes(workspace_id: str, user=Depends(workspace_user)):
        """Return the actor's intake receipts only; no archive paths or members."""
        with store.connect() as c:
            rows = c.execute('''SELECT intake_id,state,result_batch_id,result_sha256,
                    created_utc,finished_utc,rights_dataset_id
                FROM fw_real_intake_queue WHERE workspace=%s AND actor=%s
                ORDER BY created_utc DESC,intake_id LIMIT 50''',
                (workspace_id, user['name'])).fetchall()
        return {'items': rows}

    @router.post('/api/v1/workspaces/{workspace_id}/real/versions', status_code=201)
    def create_real_draft(workspace_id: str, body: RealDraftRequest, user=Depends(writer)):
        """Create a real working draft from an accepted intake or frozen real parent.

        The browser selects one server-owned receipt/version identifier. It never
        supplies members, labels, split assignments, source paths or media paths.
        """
        from .real_versions import child_draft_manifest, intake_draft_manifest
        if body.intake_id is not None:
            with store.connect() as c:
                grouping_ready = c.execute('''SELECT
                    to_regclass('public.fw_sample_perceptual_features') IS NOT NULL AS feature_table,
                    EXISTS (SELECT 1 FROM pg_catalog.pg_proc p
                        JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                        WHERE n.nspname='fw_intake_cap_v1' AND p.proname='publish_sample_phash'
                          AND p.pronargs=6
                          AND pg_catalog.oidvectortypes(p.proargtypes)='text, uuid, text, text, text, text'
                          AND pg_catalog.has_function_privilege('fieldwork_intake_worker',p.oid,'EXECUTE'))
                        AS feature_capability,
                    CASE WHEN to_regclass('public.fw_sample_perceptual_features') IS NOT NULL
                         THEN has_table_privilege(current_user,'public.fw_sample_perceptual_features','SELECT')
                         ELSE false END AS feature_read''').fetchone()
                if not all(grouping_ready.values()):
                    raise HTTPException(503, 'REAL_GROUP_AUDIT_NOT_PROVISIONED')
                intake = c.execute('''SELECT q.intake_id,q.result_batch_id,q.result_sha256,b.rights_dataset_id
                    FROM fw_real_intake_queue q JOIN fw_intake_batches b
                      ON b.workspace=q.workspace AND b.batch_id=q.result_batch_id
                    WHERE q.workspace=%s AND q.intake_id=%s AND q.actor=%s AND q.state='complete'
                      AND q.result_batch_id IS NOT NULL AND b.state='complete'
                      AND b.source_intake_id=q.intake_id AND b.report_sha256=q.result_sha256''',
                    (workspace_id, body.intake_id, user['name'])).fetchone()
                if not intake:
                    raise HTTPException(409, 'ACCEPTED_INTAKE_REQUIRED')
                samples = c.execute('''SELECT s.sample_id,s.raw_sha256,s.raw_bytes,s.pixel_sha256,
                        s.media_path,s.source_member,s.source_label,s.rights_dataset_id,
                        pf.algorithm AS phash_algorithm,pf.hash_hex AS phash_hex,
                        pf.raw_sha256 AS phash_raw_sha256,pf.pixel_sha256 AS phash_pixel_sha256,
                        pf.decoder AS phash_decoder
                    FROM fw_intake_members m JOIN fw_samples s
                      ON s.workspace=m.workspace AND s.sample_id=m.sample_id
                    LEFT JOIN fw_sample_perceptual_features pf
                      ON pf.workspace=s.workspace AND pf.sample_id=s.sample_id
                     AND pf.algorithm='phash-dct64/v1'
                    WHERE m.workspace=%s AND m.batch_id=%s AND m.disposition='accepted'
                      AND s.first_batch=%s
                    ORDER BY m.ordinal''',
                    (workspace_id, intake['result_batch_id'], intake['result_batch_id'])).fetchall()
                claims = c.execute('''SELECT linked.sample_id,dup.claimed_label AS label,
                        dup.member AS source_member
                    FROM fw_intake_members dup JOIN fw_samples linked
                      ON linked.workspace=dup.workspace AND linked.sample_id=dup.linked_sample_id
                     AND linked.first_batch=dup.batch_id
                    WHERE dup.workspace=%s AND dup.batch_id=%s
                      AND dup.disposition='duplicate' AND dup.claimed_label IS NOT NULL
                    ORDER BY dup.ordinal''',
                    (workspace_id, intake['result_batch_id'])).fetchall()
            if not samples:
                raise HTTPException(409, 'ACCEPTED_INTAKE_HAS_NO_NEW_SAMPLES')
            try:
                decisions = rights_service.require(workspace_id, intake['rights_dataset_id'],
                                                   user['name'], 'local_private_training')
            except DecisionRejected:
                raise HTTPException(403, 'REAL_DRAFT_RIGHTS_REQUIRED') from None
            verified = {d.member_id: d.asset_sha256 for d in decisions}
            if any(row['rights_dataset_id'] != intake['rights_dataset_id']
                   or verified.get(row['source_member']) != row['raw_sha256'] for row in samples):
                raise HTTPException(423, 'REAL_DRAFT_RIGHTS_CHANGED')
            try:
                manifest = intake_draft_manifest(batch_id=str(intake['result_batch_id']),
                    rights_dataset_id=intake['rights_dataset_id'], samples=samples,
                    label_claims=claims)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
            return annotations.create(store, workspace_id, user['name'], manifest)

        with store.connect() as c:
            parent_row = c.execute('''SELECT id,parent_digest,manifest FROM fw_versions
                WHERE workspace=%s AND id=%s AND state='frozen'
                  AND manifest->>'scope'='real-rights-cleared' ''',
                (workspace_id, body.parent_version_id)).fetchone()
        if not parent_row or parent_row['manifest'].get('digest') != body.parent_version_digest:
            raise HTTPException(409, 'FROZEN_REAL_PARENT_DIGEST_MISMATCH')
        try:
            manifest = child_draft_manifest(parent_row['manifest'], parent_row['id'])
        except ValueError:
            raise HTTPException(409, 'FROZEN_REAL_PARENT_REQUIRED') from None
        return annotations.create(store, workspace_id, user['name'], manifest,
                                  parent_digest=parent_row['manifest']['digest'])

    @router.post('/api/v1/workspaces/{workspace_id}/real/versions/{version_id}/split-plan')
    def assign_initial_split_plan(workspace_id: str, version_id: str, body: InitialSplitPlanRequest,
                                  user=Depends(writer)):
        """Assign a deterministic candidate split to every server-owned pool sample.

        This path accepts no IDs, labels, member lists, paths, or seed from the
        client. It is parentless and never creates a holdout population.
        """
        from .real_splits import SplitPlanRejected, assign_initial_splits
        with store.connect() as c:
            try:
                version = annotations.locked(c, workspace_id, version_id, body.revision)
            except annotations.Rejection:
                raise
            if version['state'] == 'frozen':
                raise annotations.Rejection(409, 'FROZEN_VERSION')
            rows = annotations.proposals(c, workspace_id, version_id)
            source_digest = annotations.version_digest(version, rows)
            try:
                manifest = assign_initial_splits(version['manifest'], rows, source_digest)
            except SplitPlanRejected as exc:
                raise annotations.Rejection(423, str(exc)) from None
            c.execute('''UPDATE fw_versions SET manifest=%s,state='draft',revision=revision+1,
                reviewed_digest=NULL,reviewer=NULL,review_reason=NULL
                WHERE workspace=%s AND id=%s''', (Jsonb(manifest), workspace_id, version_id))
            updated = annotations.locked(c, workspace_id, version_id)
            return annotations.view(updated, rows)

    @router.get('/api/v1/workspaces/{workspace_id}/real/samples/{sample_id}/media')
    def gated_media(workspace_id: str, sample_id: uuid.UUID, user=Depends(workspace_user)):
        with store.connect() as c:
            sample = c.execute('''SELECT raw_sha256,raw_bytes,media_path,format,rights_dataset_id,source_member
                FROM fw_samples s WHERE workspace=%s AND sample_id=%s
                AND NOT EXISTS (
                  SELECT 1 FROM fw_versions v
                  CROSS JOIN LATERAL jsonb_array_elements(v.manifest->'samples') member
                  WHERE v.workspace=s.workspace AND v.state='frozen'
                    AND (member->>'split'='holdout' OR member ? 'holdout_population'
                         OR member->>'protected'='true')
                    AND (member->>'id'=s.sample_id::text
                         OR member->>'sha256'=s.raw_sha256
                         OR member->>'pixel_sha256'=s.pixel_sha256)
                )''', (workspace_id, sample_id)).fetchone()
        if not sample or not sample['rights_dataset_id']:
            raise HTTPException(404, 'OBJECT')
        try:
            decisions = rights_service.require(workspace_id, sample['rights_dataset_id'], user['name'], 'private_thumbnail_ui')
        except DecisionRejected:
            raise HTTPException(403, 'MEDIA_RIGHTS_REQUIRED') from None
        decision = next((d for d in decisions if d.member_id == sample['source_member']), None)
        if not decision or decision.asset_sha256 != sample['raw_sha256']:
            raise HTTPException(403, 'MEDIA_RIGHTS_REQUIRED')
        path = _inside_root(sample['media_path'], media_base)
        content_type = MEDIA_TYPES.get(path.suffix.lower())
        if not content_type or sample['format'].lower() not in {'jpeg', 'jpg', 'png', 'webp'}:
            raise HTTPException(415, 'MEDIA_TYPE')
        format_type = {'jpeg': 'image/jpeg', 'jpg': 'image/jpeg', 'png': 'image/png', 'webp': 'image/webp'}[sample['format'].lower()]
        if content_type != format_type:
            raise HTTPException(415, 'MEDIA_TYPE')
        data = _read_verified_media(path, sample['raw_sha256'], sample['raw_bytes'])
        return Response(data, media_type=content_type, headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})

    @router.post('/api/v1/workspaces/{workspace_id}/real/versions/{version_id}/freeze')
    def freeze(workspace_id: str, version_id: str, body: FreezeRequest, user=Depends(writer)):
        try:
            with store.connect() as c:
                row = c.execute('SELECT parent_digest,manifest FROM fw_versions WHERE workspace=%s AND id=%s',
                                (workspace_id, version_id)).fetchone()
                if not row:
                    raise annotations.Rejection(404, 'OBJECT')
                manifest = row['manifest']
                parent_id = manifest.get('parent_version_id')
                if parent_id:
                    parent_row = c.execute('''SELECT manifest FROM fw_versions WHERE workspace=%s AND id=%s
                        AND state='frozen' ''', (workspace_id, parent_id)).fetchone()
                    if (not parent_row or parent_row['manifest'].get('digest') != manifest.get('parent_version_digest')
                            or row['parent_digest'] != parent_row['manifest'].get('digest')):
                        raise annotations.Rejection(423, 'PARENT_FROZEN_VERSION_REQUIRED')
                    prior_tags = {s.get('holdout_population') for s in parent_row['manifest'].get('samples', [])
                                  if s.get('holdout_population')}
                    current_tags = {s.get('holdout_population') for s in manifest.get('samples', [])
                                    if s.get('split') == 'holdout' and s.get('holdout_population')}
                    new_tags = current_tags - prior_tags
                    if len(new_tags) > 1:
                        raise annotations.Rejection(423, 'EXACT_NEW_HOLDOUT_POPULATION_REQUIRED')
                    parent_manifest = parent_row['manifest']
                    new_tag = next(iter(new_tags)) if new_tags else None
                else:
                    parent_manifest = None
                    new_tag = None
            if parent_manifest is not None:
                from .protected_population import freeze_annotated_child, freeze_child
                if new_tag is None:
                    result = freeze_annotated_child(store, workspace_id, version_id, body.revision,
                                      rights_service=rights_service, actor=user['name'], parent_manifest=parent_manifest)
                else:
                    result = freeze_child(store, workspace_id, version_id, body.revision,
                                      rights_service=rights_service, actor=user['name'],
                                      parent_manifest=parent_manifest, new_tag=new_tag)
            else:
                result = freeze_real(store, workspace_id, version_id, body.revision,
                                     rights_service=rights_service, actor=user['name'])
        except annotations.Rejection as exc:
            message = str(exc)
            # Freeze helpers may include protected sample/group identifiers in
            # diagnostic details. The API returns only a stable refusal code.
            if message.startswith('REAL_FREEZE_BLOCKED:'):
                message = 'REAL_FREEZE_BLOCKED'
            raise HTTPException(exc.status, message) from None
        except DecisionRejected:
            raise HTTPException(403, 'REAL_FREEZE_RIGHTS_REQUIRED') from None
        return result

    @router.post('/api/v1/workspaces/{workspace_id}/real/holdout/plans', status_code=201)
    def authorize_holdout(workspace_id: str, body: HoldoutPlanRequest, user=Depends(steward)):
        # Assignment is checked before looking up the frozen version. The exact
        # digest must name the current frozen real version; no holdout rows/media
        # or count are returned by this control-plane endpoint.
        with store.connect() as c:
            version = c.execute('''SELECT manifest FROM fw_versions WHERE workspace=%s AND id=%s AND state='frozen'
                AND manifest->>'scope'='real-rights-cleared' ''', (workspace_id, body.version_id)).fetchone()
            if not version or version['manifest'].get('digest') != body.version_digest:
                raise HTTPException(409, 'FROZEN_VERSION_DIGEST_MISMATCH')
            from .protected_population import (PopulationHistoryIncomplete, overlaps_exposed_population,
                                               population_members)
            try:
                members, population_digest = population_members(version['manifest'], body.population_tag)
            except Exception:
                raise HTTPException(422, 'PROTECTED_POPULATION_UNAVAILABLE') from None
            if not members or len(members) != body.population_count or population_digest != body.population_digest:
                raise HTTPException(409, 'PROTECTED_POPULATION_MISMATCH')
            # Serialize all workspace admissions because candidates can share
            # content while having different labels, row IDs, groups or plan
            # digests. Keep the digest lock as well for existing clients.
            c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                      (workspace_id + ':holdout-content-identity',))
            c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                      (workspace_id + ':holdout-population:' + body.population_digest,))
            # Retain the old evaluation-digest guard byte-for-byte in meaning;
            # it complements, but does not replace, content identity matching.
            exposed = c.execute('''SELECT 1 FROM fw_holdout_plans WHERE workspace=%s
                AND population_digest=%s AND (exposures>0 OR consumed_utc IS NOT NULL)
                LIMIT 1''', (workspace_id, body.population_digest)).fetchone()
            if exposed:
                raise HTTPException(409, 'HOLDOUT_POPULATION_ALREADY_CONSUMED')
            history = c.execute('''SELECT p.population_digest,v.manifest,v.state
                FROM fw_holdout_plans p LEFT JOIN fw_versions v
                  ON v.workspace=p.workspace AND v.id=p.version_id
                WHERE p.workspace=%s AND (p.exposures>0 OR p.consumed_utc IS NOT NULL)''',
                (workspace_id,)).fetchall()
            try:
                reused = overlaps_exposed_population(version['manifest'], body.population_tag, history)
            except PopulationHistoryIncomplete:
                raise HTTPException(409, 'HOLDOUT_CONTENT_HISTORY_UNAVAILABLE') from None
            if reused:
                raise HTTPException(409, 'HOLDOUT_CONTENT_ALREADY_EXPOSED')
            existing = c.execute('''SELECT plan_id FROM fw_holdout_plans WHERE workspace=%s AND version_id=%s
                AND state<>'invalidated' ''', (workspace_id, body.version_id)).fetchone()
            if existing:
                raise HTTPException(409, 'LIVE_HOLDOUT_PLAN_EXISTS')
            plan_id = uuid.uuid4()
            try:
                c.execute('''INSERT INTO fw_holdout_plans(workspace,plan_id,version_id,version_digest,population_digest,
                    population_count,candidate_model_digest,candidate_checkpoint_digest,evaluator,usefulness_spec_sha256,
                    steward,state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'authorized')''',
                    (workspace_id, plan_id, body.version_id, body.version_digest, body.population_digest,
                     body.population_count, body.candidate_model_digest, body.candidate_checkpoint_digest,
                     body.evaluator, body.usefulness_spec_sha256, user['name']))
            except Exception as exc:
                # Do not expose database details; a concurrent steward request can
                # win the unique live-plan constraint after the read above.
                if getattr(exc, 'sqlstate', None) == '23505':
                    raise HTTPException(409, 'LIVE_HOLDOUT_PLAN_EXISTS') from None
                raise
        # No sample identifiers, labels, paths, support or media leave this handler.
        return {'plan_id': str(plan_id), 'state': 'authorized', 'holdout_rows_returned': 0}

    @router.get('/api/v1/workspaces/{workspace_id}/real/holdout/plans')
    def list_holdout_plans(workspace_id: str, version_id: str, user=Depends(steward)):
        """Steward-only, aggregate-only holdout plan control projection."""
        with store.connect() as c:
            version = c.execute('''SELECT id,revision,manifest FROM fw_versions
                WHERE workspace=%s AND id=%s AND state='frozen'
                  AND manifest->>'scope'='real-rights-cleared' ''', (workspace_id, version_id)).fetchone()
            if not version:
                raise HTTPException(404, 'FROZEN_REAL_VERSION_REQUIRED')
            manifest = version['manifest']
            from .protected_population import population_members, population_support
            tags = sorted({s.get('holdout_population') for s in manifest.get('samples', [])
                           if s.get('split') == 'holdout' and isinstance(s.get('holdout_population'), str)})
            populations = []
            for tag in tags:
                members, pop_digest = population_members(manifest, tag)
                populations.append({'tag': tag, 'digest': pop_digest, 'count': len(members),
                                    'support': population_support(manifest, tag)})
            plans = c.execute('''SELECT plan_id,version_digest,population_digest,population_count,
                candidate_model_digest,candidate_checkpoint_digest,evaluator,usefulness_spec_sha256,
                steward,state,authorized_utc,consumed_utc,exposures,invalidated_reason,result_sha256
                FROM fw_holdout_plans WHERE workspace=%s AND version_id=%s ORDER BY authorized_utc DESC''',
                (workspace_id, version_id)).fetchall()
        # Only aggregate population support and receipt metadata cross this
        # boundary. Per-item IDs, paths, labels, and media are never returned.
        return {'version': {'id': version['id'], 'revision': version['revision'],
                            'digest': manifest.get('digest')},
                'populations': populations, 'plans': [dict(p) for p in plans],
                'holdout_rows_returned': 0}

    @router.post('/api/v1/workspaces/{workspace_id}/real/holdout/plans/{plan_id}/invalidate')
    def invalidate_holdout_plan(workspace_id: str, plan_id: uuid.UUID,
                                body: InvalidatePlanRequest, user=Depends(steward)):
        reason = body.reason.strip()
        if len(reason) < 10:
            raise HTTPException(422, 'INVALIDATION_REASON_REQUIRED')
        with store.connect() as c:
            row = c.execute('''SELECT state,steward,exposures FROM fw_holdout_plans
                WHERE workspace=%s AND plan_id=%s FOR UPDATE''', (workspace_id, plan_id)).fetchone()
            if not row:
                raise HTTPException(404, 'PLAN_NOT_FOUND')
            if row['steward'] != user['name']:
                raise HTTPException(403, 'PLAN_STEWARD_MISMATCH')
            if row['state'] == 'invalidated':
                return {'plan_id': str(plan_id), 'state': 'invalidated', 'already_invalidated': True}
            c.execute('''UPDATE fw_holdout_plans SET state='invalidated',invalidated_reason=%s
                WHERE workspace=%s AND plan_id=%s''', (reason, workspace_id, plan_id))
        return {'plan_id': str(plan_id), 'state': 'invalidated',
                'was_consumed': row['state'] == 'consumed', 'exposures': row['exposures']}

    return router


INTAKE_DETAIL_MEMBER_CAP = 500
_REASON_CODE = re.compile(r'[A-Z0-9_:]{1,96}')


def _intake_detail(c, workspace_id, row):
    """Aggregate dispositions plus NON-accepted members (name, disposition, reason code) of one intake.

    Never returns accepted members, sample ids (own or linked), digests, labels or split information, so a
    duplicate of a protected sample is indistinguishable from any other duplicate.
    """
    batch = c.execute('''SELECT state,source_total,accepted,rejected,duplicate,noop FROM fw_intake_batches
        WHERE workspace=%s AND batch_id=%s AND source_intake_id=%s''',
        (workspace_id, row['result_batch_id'], row['intake_id'])).fetchone()
    if not batch:
        return None
    members = c.execute('''SELECT member,disposition,reason FROM fw_intake_members
        WHERE workspace=%s AND batch_id=%s AND disposition<>'accepted' ORDER BY ordinal LIMIT %s''',
        (workspace_id, row['result_batch_id'], INTAKE_DETAIL_MEMBER_CAP + 1)).fetchall()
    shown = members[:INTAKE_DETAIL_MEMBER_CAP]
    return {'batch_state': batch['state'], 'source_total': batch['source_total'], 'accepted': batch['accepted'],
            'rejected': batch['rejected'], 'duplicate': batch['duplicate'], 'noop': batch['noop'],
            'new_sample_ids': batch['accepted'], 'non_accepted_truncated': len(members) > INTAKE_DETAIL_MEMBER_CAP,
            'non_accepted': [{'member': m['member'][:512], 'disposition': m['disposition'],
                              'reason': m['reason'] if _REASON_CODE.fullmatch(m['reason'] or '') else 'UNSPECIFIED'}
                             for m in shown]}
