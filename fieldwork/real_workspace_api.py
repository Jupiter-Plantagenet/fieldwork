"""Workspace settings and verified private real-artifact delivery routes."""
from __future__ import annotations

import io
import json
import os
import re
import uuid
import zipfile
from datetime import timedelta
from pathlib import Path
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from psycopg.types.json import Jsonb

from .rights_decision import DecisionRejected
from .store import ROOT
from .data import canonical, digest


class WorkspaceSettingsRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int = Field(ge=1, le=2_147_483_647)
    retention_days: int = Field(ge=30, le=3650)
    max_concurrent_runs: int = Field(ge=1, le=16)
    max_epochs: int = Field(ge=1, le=100)


class MembershipRoleRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    role: str = Field(pattern=r'^(owner|researcher|reviewer|viewer)$')


class PrivacyHoldRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    legal_hold: bool
    pinned: bool
    reason_code: str = Field(pattern=r'^(rights_review|legal_obligation|release_evidence|correction)$')


class WorkspaceDeleteRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int = Field(ge=1, le=2_147_483_647)


def create_router(*, store, session_dependency: Callable, rights_service) -> APIRouter:
    router = APIRouter()
    # Seed only the fixed, source-pinned R5 registry entry. Existing local registry
    # bytes are never repaired; any drift disables release delivery.
    from .qualified_release import initialize_registry
    initialize_registry()

    def scoped(workspace_id: str, user=Depends(session_dependency)):
        if workspace_id != user['workspace']:
            raise HTTPException(404, 'OBJECT_OR_MEMBERSHIP')
        return user

    def owner(workspace_id: str, request: Request, user=Depends(session_dependency)):
        if workspace_id != user['workspace']:
            raise HTTPException(404, 'OBJECT_OR_MEMBERSHIP')
        _csrf(request, user)
        if user.get('role') != 'owner':
            raise HTTPException(403, 'OWNER_REQUIRED')
        return user

    @router.get('/api/v1/workspaces/{workspace_id}/real/support-diagnostics')
    def support_diagnostics(workspace_id: str, user=Depends(scoped)):
        """Download an allowlisted, workspace-scoped operational summary.

        Never serialize database rows or session data here. This endpoint is
        intentionally available to every authenticated workspace read actor.
        """
        count_cap = 100_000
        run_states = ('queued', 'leased', 'running', 'cancel_requested', 'interrupted',
                      'succeeded', 'failed', 'cancelled')
        version_states = ('draft', 'frozen', 'superseded', 'archived')
        try:
            with store.connect() as c:
                settings = c.execute('''SELECT retention_days,max_concurrent_runs,max_epochs
                    FROM fw_workspace_settings WHERE workspace=%s''', (workspace_id,)).fetchone()
                runs = c.execute('''SELECT state,count(*) AS n FROM fw_runs
                    WHERE workspace=%s GROUP BY state''', (workspace_id,)).fetchall()
                versions = c.execute('''SELECT state,count(*) AS n FROM fw_versions
                    WHERE workspace=%s GROUP BY state''', (workspace_id,)).fetchall()
        except Exception:
            raise HTTPException(503, 'SUPPORT_DIAGNOSTICS_UNAVAILABLE') from None

        def bounded_counts(rows, allowed):
            counts = {state: 0 for state in allowed}
            counts['other'] = 0
            truncated = False
            for row in rows:
                label = row.get('state') if isinstance(row, dict) else row['state']
                count = row.get('n') if isinstance(row, dict) else row['n']
                # State values are mapped to a fixed vocabulary; database text
                # can never be reflected into the export.
                label = label if label in allowed else 'other'
                total = counts[label] + int(count)
                if total > count_cap:
                    truncated = True
                counts[label] = min(total, count_cap)
            return counts, truncated

        run_counts, runs_truncated = bounded_counts(runs, run_states)
        version_counts, versions_truncated = bounded_counts(versions, version_states)
        diagnostics = {
            'schema': 'fieldwork.support-diagnostics/v1',
            'api': {'contract': 'v1'},
            'policy': {'read_only': True, 'scope': 'authenticated_workspace',
                       'contents': 'redacted_aggregate_diagnostics'},
            'capabilities': {'support_diagnostics': True, 'run_state_summary': True,
                             'version_state_summary': True},
            'resource_limits': {
                'retention_days': settings['retention_days'] if settings else None,
                'max_concurrent_runs': settings['max_concurrent_runs'] if settings else None,
                'max_epochs': settings['max_epochs'] if settings else None,
                'aggregate_count_cap': count_cap,
            },
            'workspace_summary': {
                'runs_by_state': run_counts,
                'versions_by_state': version_counts,
                'counts_capped': runs_truncated or versions_truncated,
            },
        }
        payload = json.dumps(diagnostics, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        return Response(payload, media_type='application/json', headers={
            'Content-Disposition': 'attachment; filename="fieldwork-support-diagnostics.json"',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
        })

    @router.get('/api/v1/workspaces/{workspace_id}/real/settings')
    def get_settings(workspace_id: str, user=Depends(scoped)):
        with store.connect() as c:
            retention_enforced = c.execute("SELECT to_regclass('public.fw_real_artifact_retention') IS NOT NULL AS ready").fetchone()['ready']
            privacy_schema = c.execute("""SELECT to_regclass('public.fw_privacy_objects') IS NOT NULL AS objects,
                to_regclass('public.fw_privacy_scanner_status') IS NOT NULL AS status""").fetchone()
            settings = c.execute('''SELECT revision,retention_days,max_concurrent_runs,max_epochs,updated_utc
                FROM fw_workspace_settings WHERE workspace=%s''', (workspace_id,)).fetchone()
            members = c.execute('''SELECT name,role FROM fw_accounts WHERE workspace=%s ORDER BY role,name''',
                                (workspace_id,)).fetchall()
            audit = c.execute('''SELECT actor,event_type,revision,detail,at_utc FROM fw_workspace_settings_events
                WHERE workspace=%s AND at_utc>=clock_timestamp()-interval '90 days' ORDER BY seq DESC LIMIT 20''', (workspace_id,)).fetchall()
            owner_count = sum(m['role'] == 'owner' for m in members)
            scanner = None
            if privacy_schema['status']:
                scanner = c.execute('''SELECT last_started_utc,last_success_utc,last_lag_seconds,
                    last_error_code,passes,archived_objects,updated_utc,scheduler_heartbeat_utc,
                    (scheduler_heartbeat_utc>=clock_timestamp()-interval '30 minutes') AS active
                    FROM fw_privacy_scanner_status WHERE id=true''').fetchone()
        if not settings:
            settings = {'revision': 1, 'retention_days': 180, 'max_concurrent_runs': 2,
                        'max_epochs': 100, 'updated_utc': None}
        if not privacy_schema['objects'] or not privacy_schema['status']:
            scanner_view = {'state': 'pending_migration', 'active': False,
                            'last_success_utc': None, 'lag_seconds': None}
        elif not scanner or not scanner['last_success_utc']:
            scanner_view = {'state': 'no_successful_pass',
                            'active': bool(scanner and scanner['active']),
                            'heartbeat_utc': scanner['scheduler_heartbeat_utc'] if scanner else None,
                            'last_success_utc': None, 'lag_seconds': scanner['last_lag_seconds'] if scanner else None,
                            'last_error_code': scanner['last_error_code'] if scanner else None,
                            'passes': scanner['passes'] if scanner else 0}
        else:
            scanner_view = {'state': 'last_pass_recorded', 'active': bool(scanner['active']),
                            'last_success_utc': scanner['last_success_utc'],
                            'lag_seconds': scanner['last_lag_seconds'],
                            'heartbeat_utc': scanner['scheduler_heartbeat_utc'],
                            'last_error_code': scanner['last_error_code'],
                            'passes': scanner['passes'], 'archived_objects': scanner['archived_objects']}
        return {'settings': dict(settings), 'members': [dict(m) for m in members],
                'owner_count': owner_count, 'roles_editable': user.get('role') == 'owner',
                'retention_enforced': bool(retention_enforced),
                'retention_scanner': scanner_view,
                'privacy_policy': {'fresh_inference_input_hours': 24, 'abandoned_staging_hours': 24,
                    'application_log_days': 30, 'event_replay_days': 7, 'audit_days': 90,
                    'unpinned_artifact_days': 180, 'workspace_live_access_days_after_delete': 7,
                    'backup_expiry_days': 30, 'preservation': 'private_archive_and_tombstone'},
                'privacy_coverage': {'fresh_inputs':'scheduled_private_archive_and_worker_fence',
                    'staged_intake':'scheduled_private_archive_and_worker_expiry',
                    'application_logs':'scheduled_private_daily_api_logs_and_sanitized_intake_error_codes; other_console_streams_unmanaged',
                    'event_replay':'existing_seven_day_access_window',
                    'audit':'ninety_day_read_window; bytes_preserved',
                    'verified_bundles':'scheduled_private_archive_at_workspace_retention',
                    'dataset_media':'180_day_unpinned_archive; protected_or_holdout_members_of_frozen_versions_and_held_or_pinned_excluded',
                    'backups':'local_r5p_snapshots_archived_after_30d; external_backup_30d_expiry_and_restore_ledger_apply_required'},
                'audit': [dict(e) for e in audit]}

    @router.put('/api/v1/workspaces/{workspace_id}/real/settings')
    def update_settings(workspace_id: str, body: WorkspaceSettingsRequest, request: Request,
                        user=Depends(owner)):
        with store.connect() as c:
            c.execute('''INSERT INTO fw_workspace_settings(workspace,revision,retention_days,
                max_concurrent_runs,max_epochs) VALUES(%s,1,180,2,100)
                ON CONFLICT(workspace) DO NOTHING''', (workspace_id,))
            current = c.execute('''SELECT revision,retention_days FROM fw_workspace_settings
                WHERE workspace=%s FOR UPDATE''', (workspace_id,)).fetchone()
            if current['revision'] != body.expected_revision:
                raise HTTPException(409, 'SETTINGS_REVISION_CONFLICT')
            # Keep evidence retention monotonic; no record deletion is exposed.
            updated = c.execute('''UPDATE fw_workspace_settings SET revision=revision+1,
                retention_days=%s,max_concurrent_runs=%s,max_epochs=%s,updated_utc=clock_timestamp()
                WHERE workspace=%s RETURNING revision,retention_days,max_concurrent_runs,max_epochs,updated_utc''',
                (max(current['retention_days'], body.retention_days), body.max_concurrent_runs,
                 body.max_epochs, workspace_id)).fetchone()
            c.execute('''INSERT INTO fw_workspace_settings_events(workspace,actor,event_type,revision,detail)
                VALUES(%s,%s,'settings.updated',%s,%s)''',
                (workspace_id, user['name'], updated['revision'], Jsonb({
                    'retention_days': updated['retention_days'],
                    'max_concurrent_runs': updated['max_concurrent_runs'],
                    'max_epochs': updated['max_epochs']})))
        return {'settings': dict(updated), 'saved': True}

    @router.put('/api/v1/workspaces/{workspace_id}/real/privacy/fresh-inputs/{input_id}/hold')
    def update_privacy_hold(workspace_id: str, input_id: str, body: PrivacyHoldRequest,
                            request: Request, user=Depends(owner)):
        if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', input_id):
            raise HTTPException(404, 'PRIVACY_OBJECT_NOT_FOUND')
        with store.connect() as c:
            ready = c.execute("SELECT to_regclass('public.fw_privacy_objects') IS NOT NULL AS ready").fetchone()['ready']
            if not ready:
                raise HTTPException(503, 'PRIVACY_LIFECYCLE_SCHEMA_REQUIRED')
            source = c.execute('''SELECT i.workspace,i.input_id,i.created_utc,r.config->>'scope' AS scope
                FROM fw_real_image_inputs i JOIN fw_runs r ON r.id=i.run AND r.workspace=i.workspace
                WHERE i.workspace=%s AND i.input_id=%s''', (workspace_id, input_id)).fetchone()
            if not source or source['scope'] not in ('real-image-inference/v1','qualified-release-image-inference/v1'):
                raise HTTPException(404, 'PRIVACY_OBJECT_NOT_FOUND')
            upload_root = (ROOT / '.local' / 'real-inference-uploads'
                if source['scope'] == 'qualified-release-image-inference/v1'
                else ROOT / '.local' / 'real-data' / 'uploads')
            c.execute('''INSERT INTO fw_privacy_objects(object_kind,workspace,object_key,source_path,
                created_utc,expires_utc) VALUES('fresh_inference_input',%s,%s,%s,%s,%s+interval '24 hours')
                ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                (workspace_id,input_id,str(upload_root/(input_id+'.img')),source['created_utc'],source['created_utc']))
            changed = c.execute('''UPDATE fw_privacy_objects SET legal_hold=%s,pinned=%s,
                updated_utc=clock_timestamp() WHERE object_kind='fresh_inference_input'
                  AND workspace=%s AND object_key=%s AND state IN ('active','held')
                RETURNING state''', (body.legal_hold,body.pinned,workspace_id,input_id)).fetchone()
            if not changed:
                raise HTTPException(409, 'PRIVACY_OBJECT_ALREADY_ARCHIVED')
            c.execute('''INSERT INTO fw_workspace_settings_events(workspace,actor,event_type,detail)
                VALUES(%s,%s,'privacy.hold_changed',%s)''',
                (workspace_id,user['name'],Jsonb({'object_kind':'fresh_inference_input',
                    'object_id_sha256':digest(input_id.encode()),'legal_hold':body.legal_hold,
                    'pinned':body.pinned,'reason_code':body.reason_code})))
        return {'object_kind':'fresh_inference_input','input_id':input_id,
                'legal_hold':body.legal_hold,'pinned':body.pinned,'state':changed['state']}

    @router.put('/api/v1/workspaces/{workspace_id}/real/privacy/intakes/{intake_id}/hold')
    def update_intake_hold(workspace_id: str, intake_id: str, body: PrivacyHoldRequest,
                           request: Request, user=Depends(owner)):
        if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', intake_id):
            raise HTTPException(404,'PRIVACY_OBJECT_NOT_FOUND')
        with store.connect() as c:
            ready=c.execute("SELECT to_regclass('public.fw_privacy_objects') IS NOT NULL AS ready").fetchone()['ready']
            if not ready:raise HTTPException(503,'PRIVACY_LIFECYCLE_SCHEMA_REQUIRED')
            queue=c.execute('''SELECT workspace,intake_id,archive_path,created_utc FROM fw_real_intake_queue
                WHERE workspace=%s AND intake_id=%s''',(workspace_id,intake_id)).fetchone()
            if not queue:raise HTTPException(404,'PRIVACY_OBJECT_NOT_FOUND')
            c.execute('''INSERT INTO fw_privacy_objects(object_kind,workspace,object_key,source_path,
                created_utc,expires_utc) VALUES('abandoned_staging',%s,%s,%s,%s,%s+interval '24 hours')
                ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                (workspace_id,intake_id,queue['archive_path'],queue['created_utc'],queue['created_utc']))
            changed=c.execute('''UPDATE fw_privacy_objects SET legal_hold=%s,pinned=%s,
                updated_utc=clock_timestamp() WHERE object_kind='abandoned_staging' AND workspace=%s
                  AND object_key=%s AND state IN ('active','held') RETURNING state''',
                (body.legal_hold,body.pinned,workspace_id,intake_id)).fetchone()
            if not changed:raise HTTPException(409,'PRIVACY_OBJECT_ALREADY_ARCHIVED')
            c.execute('''INSERT INTO fw_workspace_settings_events(workspace,actor,event_type,detail)
                VALUES(%s,%s,'privacy.hold_changed',%s)''',
                (workspace_id,user['name'],Jsonb({'object_kind':'abandoned_staging',
                    'object_id_sha256':digest(intake_id.encode()),'legal_hold':body.legal_hold,
                    'pinned':body.pinned,'reason_code':body.reason_code})))
        return {'object_kind':'abandoned_staging','intake_id':intake_id,
                'legal_hold':body.legal_hold,'pinned':body.pinned,'state':changed['state']}

    @router.put('/api/v1/workspaces/{workspace_id}/real/privacy/dataset-samples/{sample_id}/hold')
    def update_dataset_hold(workspace_id: str, sample_id: str, body: PrivacyHoldRequest,
                            request: Request, user=Depends(owner)):
        if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',sample_id):
            raise HTTPException(404,'PRIVACY_OBJECT_NOT_FOUND')
        with store.connect() as c:
            ready=c.execute("SELECT to_regclass('public.fw_privacy_objects') IS NOT NULL AS ready").fetchone()['ready']
            if not ready:raise HTTPException(503,'PRIVACY_LIFECYCLE_SCHEMA_REQUIRED')
            sample=c.execute('''SELECT sample_id,media_path,created_utc FROM fw_samples
                WHERE workspace=%s AND sample_id=%s''',(workspace_id,sample_id)).fetchone()
            if not sample:raise HTTPException(404,'PRIVACY_OBJECT_NOT_FOUND')
            c.execute('''INSERT INTO fw_privacy_objects(object_kind,workspace,object_key,source_path,
                created_utc,expires_utc) VALUES('dataset_artifact',%s,%s,%s,%s,%s+interval '180 days')
                ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                (workspace_id,sample_id,sample['media_path'],sample['created_utc'],sample['created_utc']))
            changed=c.execute('''UPDATE fw_privacy_objects SET legal_hold=%s,pinned=%s,
                updated_utc=clock_timestamp() WHERE object_kind='dataset_artifact' AND workspace=%s
                  AND object_key=%s AND state IN ('active','held') RETURNING state''',
                (body.legal_hold,body.pinned,workspace_id,sample_id)).fetchone()
            if not changed:raise HTTPException(409,'PRIVACY_OBJECT_ALREADY_ARCHIVED')
            c.execute('''INSERT INTO fw_workspace_settings_events(workspace,actor,event_type,detail)
                VALUES(%s,%s,'privacy.hold_changed',%s)''',
                (workspace_id,user['name'],Jsonb({'object_kind':'dataset_artifact',
                    'object_id_sha256':digest(sample_id.encode()),'legal_hold':body.legal_hold,
                    'pinned':body.pinned,'reason_code':body.reason_code})))
        return {'object_kind':'dataset_artifact','sample_id':sample_id,
                'legal_hold':body.legal_hold,'pinned':body.pinned,'state':changed['state']}

    @router.put('/api/v1/workspaces/{workspace_id}/real/runs/{run_id}/privacy/hold')
    def update_run_artifact_hold(workspace_id: str, run_id: str, body: PrivacyHoldRequest,
                                 request: Request, user=Depends(owner)):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',run_id):
            raise HTTPException(404,'PRIVACY_OBJECT_NOT_FOUND')
        with store.connect() as c:
            ready=c.execute("SELECT to_regclass('public.fw_privacy_objects') IS NOT NULL AS ready").fetchone()['ready']
            if not ready:raise HTTPException(503,'PRIVACY_LIFECYCLE_SCHEMA_REQUIRED')
            run=c.execute('''SELECT r.id,r.workspace,r.config,coalesce(
                    (SELECT min(e.created) FROM fw_events e WHERE e.run=r.id),clock_timestamp()) AS created
                FROM fw_runs r WHERE r.workspace=%s AND r.id=%s''',(workspace_id,run_id)).fetchone()
            if not run:raise HTTPException(404,'PRIVACY_OBJECT_NOT_FOUND')
            c.execute('''INSERT INTO fw_privacy_objects(object_kind,workspace,object_key,source_path,
                created_utc,expires_utc) VALUES('run_artifact',%s,%s,%s,%s,%s+interval '180 days')
                ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                (workspace_id,run_id,'run-artifact:'+run_id,run['created'],run['created']))
            changed=c.execute('''UPDATE fw_privacy_objects SET legal_hold=%s,pinned=%s,
                updated_utc=clock_timestamp() WHERE object_kind='run_artifact' AND workspace=%s
                  AND object_key=%s AND state IN ('active','held') RETURNING state''',
                (body.legal_hold,body.pinned,workspace_id,run_id)).fetchone()
            checkpoints=c.execute('''UPDATE fw_privacy_objects SET legal_hold=%s,pinned=%s,
                updated_utc=clock_timestamp() WHERE object_kind='run_artifact' AND workspace=%s
                  AND split_part(object_key,':',1)=%s AND object_key<>%s AND state IN ('active','held')''',
                (body.legal_hold,body.pinned,workspace_id,run_id,run_id)).rowcount
            c.execute('''INSERT INTO fw_workspace_settings_events(workspace,actor,event_type,detail)
                VALUES(%s,%s,'privacy.hold_changed',%s)''',
                (workspace_id,user['name'],Jsonb({'object_kind':'run_artifact',
                    'object_id_sha256':digest(run_id.encode()),'legal_hold':body.legal_hold,
                    'pinned':body.pinned,'reason_code':body.reason_code,
                    'checkpoint_rows_changed':checkpoints})))
        return {'object_kind':'run_artifact','run_id':run_id,'legal_hold':body.legal_hold,
                'pinned':body.pinned,'state':changed['state'],'checkpoint_rows_changed':checkpoints}

    @router.post('/api/v1/workspaces/{workspace_id}/real/workspace-deletion')
    def request_workspace_deletion(workspace_id: str, body: WorkspaceDeleteRequest,
                                   request: Request, user=Depends(owner)):
        """Revoke every workspace session now, fence new work, and retain bytes in archive."""
        from .privacy_lifecycle import reconcile_deletion_intents
        try:
            reconcile_deletion_intents(store,max_items=1,workspace=workspace_id)
        except Exception:
            # A prior unresolved owner intent stays fail-closed; do not replace it.
            raise HTTPException(503,'PRIVACY_DELETION_RECONCILIATION_PENDING') from None
        with store.connect() as c:
            ready = c.execute("SELECT to_regclass('public.fw_privacy_workspace_tombstones') IS NOT NULL AS ready").fetchone()['ready']
            if not ready:
                raise HTTPException(503, 'PRIVACY_LIFECYCLE_SCHEMA_REQUIRED')
            c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                      ('fieldwork-workspace-delete:' + workspace_id,))
            settings = c.execute('''SELECT revision FROM fw_workspace_settings
                WHERE workspace=%s FOR UPDATE''', (workspace_id,)).fetchone()
            if not settings or settings['revision'] != body.expected_revision:
                raise HTTPException(409, 'SETTINGS_REVISION_CONFLICT')
            prior = c.execute('''SELECT request_id,deleted_utc,archive_due_utc,state
                FROM fw_privacy_workspace_tombstones WHERE workspace=%s''', (workspace_id,)).fetchone()
            if prior:
                raise HTTPException(409, 'WORKSPACE_DELETION_ALREADY_REQUESTED')
            active = c.execute('''SELECT id FROM fw_runs WHERE workspace=%s
                AND state IN ('queued','leased','running','cancel_requested')
                ORDER BY id''', (workspace_id,)).fetchall()
            if not c.execute("SELECT to_regprocedure('public.fw_privacy_restore_generation_v1()') IS NOT NULL AS ready").fetchone()['ready']:
                raise HTTPException(503,'RESTORE_GENERATION_SCHEMA_REQUIRED')
            generation=c.execute('SELECT public.fw_privacy_restore_generation_v1()::text AS value').fetchone()['value']
            if not generation:raise HTTPException(503,'RESTORE_GENERATION_SCHEMA_REQUIRED')
            request_id = str(uuid.uuid4())
            deleted = c.execute('SELECT clock_timestamp() AS at').fetchone()['at']
            due = deleted + timedelta(days=7)
            c.execute('''UPDATE fw_workspace_settings SET revision=revision+1,updated_utc=clock_timestamp()
                WHERE workspace=%s''', (workspace_id,))
            c.execute('''DELETE FROM fw_sessions WHERE name IN
                (SELECT name FROM fw_accounts WHERE workspace=%s)''', (workspace_id,))
            c.execute('''INSERT INTO fw_workspace_settings_events(workspace,actor,event_type,revision,detail)
                VALUES(%s,%s,'privacy.workspace_deletion_requested',%s,%s)''',
                (workspace_id,user['name'],body.expected_revision+1,Jsonb({
                    'request_id':request_id,'archive_due_utc':due.isoformat(),
                    'session_revocation':'immediate','retained_archive':'private'})))
            c.execute('''INSERT INTO fw_privacy_workspace_tombstones(workspace,request_id,requested_by,
                expected_settings_revision,deleted_utc,archive_due_utc)
                VALUES(%s,%s,%s,%s,%s,%s)''',
                (workspace_id,request_id,user['name'],body.expected_revision,deleted,due))
            from .privacy_lifecycle import append_deletion_tombstone,PrivacyDeletionLedgerError
            try:
                append_deletion_tombstone(workspace_id,request_id,deleted,
                    requested_by=user['name'],expected_revision=body.expected_revision,
                    restore_generation=generation)
            except PrivacyDeletionLedgerError:
                raise HTTPException(503,'PRIVACY_DELETION_LEDGER_UNAVAILABLE') from None
        from .privacy_lifecycle import set_deletion_intent_state,cancel_deleted_run
        try:set_deletion_intent_state(workspace_id,request_id,'committed')
        except Exception:
            # The committed DB tombstone remains authoritative; the worker will
            # promote this prepared marker before processing deletion archives.
            pass
        # Invoke the existing fenced cancellation transition for every active
        # run. A recurring worker retries failures from the tombstone journal.
        cancel_results=[]
        for row in active:
            try:
                cancel_results.append(cancel_deleted_run(store,workspace_id,row['id']))
            except Exception:
                cancel_results.append('pending')
        return {'request_id':request_id,'state':'revoked','access_revoked':True,
                'sessions_revoked':True,'active_runs_cancelled':sum(v in ('cancelled','cancel_requested') for v in cancel_results),
                'active_runs_pending':sum(v=='pending' for v in cancel_results),
                'archive_due_utc':due,'preservation':'private_archive_and_tombstone'}

    @router.put('/api/v1/workspaces/{workspace_id}/real/settings/members/{member_name}')
    def update_member_role(workspace_id: str, member_name: str, body: MembershipRoleRequest,
                           request: Request, user=Depends(owner)):
        if not re.fullmatch(r'[A-Za-z0-9_.@+-]{1,100}', member_name):
            raise HTTPException(404, 'MEMBER_NOT_FOUND')
        with store.connect() as c:
            c.execute('SELECT pg_advisory_xact_lock(hashtext(%s))', ('fieldwork-members:' + workspace_id,))
            target = c.execute('SELECT role FROM fw_accounts WHERE workspace=%s AND name=%s FOR UPDATE',
                               (workspace_id, member_name)).fetchone()
            if not target:
                raise HTTPException(404, 'MEMBER_NOT_FOUND')
            owners = c.execute("SELECT count(*) AS n FROM fw_accounts WHERE workspace=%s AND role='owner'",
                               (workspace_id,)).fetchone()['n']
            if target['role'] == 'owner' and body.role != 'owner' and owners <= 1:
                raise HTTPException(409, 'LAST_OWNER_REQUIRED')
            if target['role'] == body.role:
                return {'member': member_name, 'role': body.role, 'sessions_revoked': False}
            c.execute('UPDATE fw_accounts SET role=%s WHERE workspace=%s AND name=%s',
                      (body.role, workspace_id, member_name))
            c.execute('''INSERT INTO fw_workspace_settings_events(workspace,actor,event_type,detail)
                VALUES(%s,%s,'membership.role_changed',%s)''',
                (workspace_id, user['name'], Jsonb({'member': member_name,
                 'from': target['role'], 'to': body.role,
                 'session_revocation': 'issued_role_mismatch'})))
        return {'member': member_name, 'role': body.role, 'sessions_revoked': True}

    @router.get('/api/v1/workspaces/{workspace_id}/qualified-releases')
    def list_qualified_releases(workspace_id: str, user=Depends(scoped)):
        from .qualified_release import registered_release, require_consumed_plan
        release = registered_release('flowers-r5-small-residual-v1', workspace_id)
        if not release or not require_consumed_plan(store, release):
            return {'items': []}
        att = release['attestation']
        return {'items': [{
            'release_id': release['release_id'], 'purpose': 'qualified_release',
            'recipe': 'small-residual/v1', 'bundle_digest': release['manifest_sha256'],
            'model_digest': release['model_digest'], 'version_id': release['version_id'],
            'version_digest': release['version_digest'], 'plan_id': release['plan_id'],
            'plan_result_sha256': release['plan_result_sha256'],
            'aggregate': att['aggregate'], 'public_export_authorized': False,
            'download_allowed': user.get('role') in ('owner', 'researcher'),
            'inference_allowed': (user.get('role') in ('owner', 'researcher', 'reviewer')
                and bool(os.environ.get('FIELDWORK_REAL_PIXEL_IMAGE_ID'))
                and bool(os.environ.get('FIELDWORK_QUALIFIED_MODEL_IMAGE_ID'))
                and os.environ.get('FIELDWORK_QUALIFIED_MODEL_IMAGE_ID') == os.environ.get('FIELDWORK_REAL_MODEL_IMAGE_ID')),
        }]}

    @router.get('/api/v1/workspaces/{workspace_id}/qualified-releases/{release_id}/download')
    def download_qualified_release(workspace_id: str, release_id: str, user=Depends(scoped)):
        if user.get('role') not in ('owner', 'researcher'):
            raise HTTPException(403, 'BUNDLE_DOWNLOAD_ROLE_REQUIRED')
        from .qualified_release import registered_release, require_consumed_plan
        release = registered_release(release_id, workspace_id)
        if not release or not require_consumed_plan(store, release):
            raise HTTPException(404, 'QUALIFIED_RELEASE_NOT_AVAILABLE')
        # Recheck current model-bundle rights against the frozen version at point of
        # delivery. Only its ordinary train/validation population is materialized.
        try:
            with store.connect() as c:
                version = c.execute('''SELECT manifest,state FROM fw_versions
                    WHERE workspace=%s AND id=%s''', (workspace_id, release['version_id'])).fetchone()
            if not version or version['state'] != 'frozen' or version['manifest'].get('digest') != release['version_digest']:
                raise HTTPException(409, 'QUALIFIED_RELEASE_VERSION_BINDING')
            dataset = version['manifest'].get('rights_dataset_id')
            if not isinstance(dataset, str):
                raise HTTPException(403, 'QUALIFIED_RELEASE_RIGHTS_NOT_READY')
            rights_service.require(workspace_id, dataset, user['name'], 'model_bundle')
        except DecisionRejected:
            raise HTTPException(403, 'QUALIFIED_RELEASE_RIGHTS_NOT_READY') from None
        from .qualified_release import sha256
        bundle = release['bundle']
        manifest = release['manifest']
        manifest_bytes = (bundle / 'manifest.json').read_bytes()
        if sha256(bundle / 'manifest.json') != release['manifest_sha256']:
            raise HTTPException(409, 'QUALIFIED_RELEASE_INTEGRITY')
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            contents = {'manifest.json': manifest_bytes}
            for name, record in manifest['files'].items():
                contents[name] = _read_bound_file(bundle / name, record['bytes'], record['sha256'])
            for name, data in sorted(contents.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o600 << 16
                archive.writestr(info, data)
        payload = out.getvalue()
        if len(payload) > 64 * 1024 * 1024:
            raise HTTPException(413, 'BUNDLE_DOWNLOAD_LIMIT')
        return Response(payload, media_type='application/zip',
                        headers={'Content-Disposition': 'attachment; filename="fieldwork-flowers-r5-qualified.zip"',
                                 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})

    @router.get('/api/v1/workspaces/{workspace_id}/real/runs/{run_id}/bundle')
    def inspect_bundle(workspace_id: str, run_id: str, user=Depends(scoped)):
        with store.connect() as c:
            _lock_artifact(c, workspace_id, run_id)
            run = _real_training_run(store, workspace_id, run_id)
            retention = _retention_status(store, workspace_id, run_id)
            if retention['state'] in ('archived', 'recovery_required', 'recovered', 'prepared'):
                _require_bundle_rights(workspace_id, run, user['name'], rights_service)
                return {'run_id': run_id, 'bundle_digest': run['artifact_result'].get('bundle_digest'),
                        'manifest': retention['manifest'], 'lineage': retention['lineage'],
                        'scope': 'private-real-validation-only',
                        'download_allowed': False, 'expired': True,
                        'retention': _public_retention(retention),
                        'public_export_authorized': False}

            bundle, manifest = _verified_bundle(run, workspace_id, user['name'], rights_service,
                                                store=store, allow_expired=True)
            return {'run_id': run_id, 'bundle_digest': run['artifact_result'].get('bundle_digest'),
                    'manifest': manifest, 'lineage': _safe_lineage(bundle),
                    'scope': 'private-real-validation-only',
                    'download_allowed': False,
                    'download_blocker': 'QUALIFIED_RELEASE_REQUIRED',
                    'expired': retention['expired'], 'retention': _public_retention(retention),
                    'public_export_authorized': False}

    @router.get('/api/v1/workspaces/{workspace_id}/real/runs/{run_id}/bundle/download')
    def download_bundle(workspace_id: str, run_id: str, user=Depends(scoped)):
        # A verified private candidate is not a qualified release.
        if user.get('role') not in ('owner', 'researcher'):
            raise HTTPException(403, 'BUNDLE_DOWNLOAD_ROLE_REQUIRED')
        raise HTTPException(403, 'QUALIFIED_RELEASE_REQUIRED')

    return router




def _csrf(request, user):
    import hmac
    if (request.headers.get('origin') not in ('http://127.0.0.1:5102', 'http://127.0.0.1:8102')
            or not hmac.compare_digest(request.headers.get('x-csrf-token', ''), user.get('csrf', ''))):
        raise HTTPException(403, 'CSRF_OR_ORIGIN')


def _real_training_run(store, workspace_id, run_id):
    run = store.get(run_id, workspace_id)
    if (not run or run['config'].get('scope') != 'real-training/v1'
            or run['state'] != 'succeeded' or run.get('artifact_status') != 'verified'):
        raise HTTPException(404, 'VERIFIED_REAL_BUNDLE_REQUIRED')
    return run


def _verified_bundle(run, workspace_id, actor, rights_service, *, store, allow_expired=False):
    from .real_bundle import verify_real_bundle
    retention = _retention_status(store, workspace_id, run['id'])
    if retention['state'] in ('archived', 'recovery_required', 'recovered', 'prepared'):
        raise HTTPException(410, 'REAL_BUNDLE_EXPIRED_ARCHIVED')
    if retention['expired'] and not allow_expired:
        raise HTTPException(410, 'REAL_BUNDLE_EXPIRED')
    result = run.get('artifact_result') or {}
    leaf, expected = result.get('artifact_directory'), result.get('bundle_digest')
    if (not isinstance(leaf, str) or not re.fullmatch(r'real-artifact-attempt-[0-9]{1,12}', leaf)
            or not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected)):
        raise HTTPException(409, 'REAL_BUNDLE_RECEIPT_INVALID')
    run_root = ROOT / 'var' / 'runs' / run['id']
    bundle = run_root / leaf / 'bundle'
    try:
        _reject_reparse_components(run_root, bundle)
        base = run_root.resolve(strict=True)
        resolved = bundle.resolve(strict=True)
        resolved.relative_to(base)
        manifest = verify_real_bundle(bundle, expected_digest=expected,
            expected_lineage={'version_id': run['config']['version_id'],
                              'dataset_digest': run['config']['version_digest'],
                              'model_image_id': run['config']['model_image_id']})
    except Exception:
        raise HTTPException(409, 'REAL_BUNDLE_INTEGRITY') from None
    _require_bundle_rights(workspace_id, run, actor, rights_service)
    return bundle, manifest


def _require_bundle_rights(workspace_id, run, actor, rights_service):
    try:
        rights_service.require(workspace_id, run['config']['dataset_id'], actor, 'model_bundle')
    except DecisionRejected:
        raise HTTPException(403, 'REAL_BUNDLE_RIGHTS_NOT_READY') from None


def _lock_artifact(connection, workspace_id, run_id):
    # The lock is held while the bundle is verified on other connections (rights check over every dataset
    # member can take >10 s under load). The API role's 10 s idle-in-transaction limit would kill this idle
    # holder and turn the read into a 500, so lift it for this transaction only; the role default is unchanged.
    connection.execute("SET LOCAL idle_in_transaction_session_timeout = '180s'")
    # Readers only need to exclude the retention archiver (exclusive lock in real_retention and the
    # migration-011 inference trigger); a shared lock keeps that guarantee without queueing concurrent
    # readers of the same run behind each other's slow verification (which hit the 5 s statement timeout).
    connection.execute('SELECT pg_advisory_xact_lock_shared(hashtextextended(%s,0))',
                       ('fieldwork-artifact-retention:' + workspace_id + ':' + run_id,))


def _retention_status(store, workspace_id, run_id):
    """Current workspace policy and the database-recorded artifact_verified anchor."""
    try:
        with store.connect() as c:
            saved = c.execute('''SELECT state,expires_at,archived_at,archive_tree_sha256,
                    manifest_snapshot,lineage_snapshot,retention_days,verified_at
                FROM fw_real_artifact_retention WHERE workspace=%s AND run=%s''',
                (workspace_id, run_id)).fetchone()
            if saved:
                row = dict(saved)
                return {**row, 'expired': True, 'manifest': row['manifest_snapshot'],
                        'lineage': row['lineage_snapshot']}
            policy = c.execute('''SELECT coalesce(s.retention_days,180) AS days,
                    e.created AS verified_at,
                    e.created + make_interval(days=>coalesce(s.retention_days,180)) AS expires_at,
                    e.payload->>'bundle_digest' AS bundle_digest
                FROM fw_runs r
                LEFT JOIN fw_workspace_settings s ON s.workspace=r.workspace
                JOIN LATERAL (SELECT created,payload FROM fw_events
                    WHERE run=r.id AND kind='artifact_verified'
                      AND payload->>'bundle_digest'=r.artifact_result->>'bundle_digest'
                    ORDER BY seq DESC LIMIT 1) e ON true
                WHERE r.workspace=%s AND r.id=%s AND r.config->>'scope'='real-training/v1'
                  AND r.artifact_status='verified' ''', (workspace_id, run_id)).fetchone()
            if not policy:
                raise HTTPException(409, 'REAL_RETENTION_VERIFICATION_ANCHOR_REQUIRED')
            row = dict(policy)
            row['state'] = 'active'
            row['expired'] = row['expires_at'] <= _database_now(store)
            row['archive_tree_sha256'] = None
            row['archived_at'] = None
            return row
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, 'REAL_RETENTION_SCHEMA_REQUIRED') from None


def _database_now(store):
    with store.connect() as c:
        return c.execute('SELECT clock_timestamp() AS now').fetchone()['now']


def _public_retention(row):
    def iso(value): return value.isoformat() if hasattr(value, 'isoformat') else value
    return {'state': row['state'], 'retention_days': row['retention_days'] if 'retention_days' in row else row['days'],
            'verified_at': iso(row['verified_at']), 'expires_at': iso(row['expires_at']),
            'archived_at': iso(row.get('archived_at')),
            'archive_sha256': row.get('archive_tree_sha256')}


def _reject_reparse_components(root: Path, target: Path):
    root_abs, target_abs = root.absolute(), target.absolute()
    try:
        parts = target_abs.relative_to(root_abs).parts
    except ValueError:
        raise ValueError('BUNDLE_PATH') from None
    current = root_abs
    for part in ('.', *parts):
        if part != '.':
            current = current / part
        info = current.lstat()
        if current.is_symlink() or getattr(info, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
            raise ValueError('BUNDLE_REPARSE_POINT')
    for path in target.rglob('*'):
        info = path.lstat()
        if path.is_symlink() or getattr(info, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
            raise ValueError('BUNDLE_REPARSE_POINT')


def _safe_lineage(bundle):
    value = json.loads((bundle / 'lineage.json').read_text(encoding='utf-8'))
    allowed = ('scope', 'version_id', 'dataset_digest', 'checkpoint_digest', 'epoch',
               'model_digest', 'recipe_digest', 'preprocess_digest', 'model_image_id')
    return {key: value[key] for key in allowed}


def _read_bound_file(path: Path, expected_bytes: int, expected_sha256: str) -> bytes:
    """Read one verified member without following links and pin bytes to receipt."""
    try:
        before = path.stat()
        if before.st_size != expected_bytes or expected_bytes > 32 * 1024 * 1024:
            raise ValueError('BUNDLE_SIZE')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('BUNDLE_CHANGED')
            chunks, total = [], 0
            while True:
                block = os.read(fd, min(1024 * 1024, expected_bytes + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > expected_bytes:
                    raise ValueError('BUNDLE_SIZE')
            data = b''.join(chunks)
            after = path.stat()
            if (after.st_dev, after.st_ino, after.st_size) != (opened.st_dev, opened.st_ino, total):
                raise ValueError('BUNDLE_CHANGED')
        finally:
            os.close(fd)
    except OSError:
        raise HTTPException(409, 'REAL_BUNDLE_INTEGRITY') from None
    if total != expected_bytes or digest(data) != expected_sha256:
        raise HTTPException(409, 'REAL_BUNDLE_INTEGRITY')
    return data
