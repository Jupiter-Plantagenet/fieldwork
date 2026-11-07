"""Explicit opt-in real-training capability layered over the scoped worker API.

This module does not connect as an operator or apply schema. Its fixed SQL calls
are installed by migrations/007_real_run_worker.sql and return only approved
train/validation inputs for a current, fenced real-data attempt.
"""
from __future__ import annotations

import json

import psycopg
from psycopg.types.json import Jsonb

from .artifact_state import alive, identity
from .worker_identity import WorkerStore
from .worker_heartbeat import refresh_worker_heartbeat_after_progress
from .store import Conflict

SCHEMA = 'fw_real_worker_cap_v1'


class RealWorkerStore(WorkerStore):
    """Scoped worker with separate, fixed real-training/inference calls.

    Existing WorkerStore methods and the synthetic-only SQL functions are left
    intact. This class never exposes a generic SQL surface to the child process.
    """

    def _call_real(self, name: str, *args):
        placeholders = ','.join(['%s'] * len(args))
        statement = f'SELECT {SCHEMA}.{name}({placeholders}) AS v'
        try:
            with self.connect() as conn:
                return conn.execute(statement, args).fetchone()['v']
        except psycopg.errors.RaiseException as exc:
            code = exc.diag.message_primary or 'REAL_WORKER_CAPABILITY_REFUSED'
            detail = {}
            try:
                detail = json.loads(exc.diag.message_detail or '{}')
            except (TypeError, ValueError):
                pass
            if code.startswith('CANCEL_GENERATION') or code == 'WRONG_GENERATION':
                from .store import CancelGenerationConflict
                raise CancelGenerationConflict(code, detail.get('state'), detail.get('current_generation')) from None
            raise Conflict(code) from None

    def _refresh_liveness_after_progress(self, path=None):
        """Refresh issuer liveness after a successful fenced lease/progress call.

        The issuer stops rotating the scoped login password when this marker goes
        stale. Long jobs therefore refresh it from their existing progress callbacks,
        without a background thread that could outlive job progress. Bind the update
        to this process birth, scoped worker identity and exact real-worker profile.
        """
        try:
            refresh_worker_heartbeat_after_progress(path)
        except OSError:
            # A DB lease without a fresh physical-worker marker would let the issuer
            # stop password rotation during an active run; fail the progress callback
            # closed so the existing fenced recovery path handles it.
            raise OSError('WORKER_HEARTBEAT_REFRESH_FAILED') from None

    def heartbeat(self, rid, fence, cancel_generation, *, attempt=None,
                  restore_generation=None, key=None, actor=None):
        result = super().heartbeat(rid, fence, cancel_generation, attempt=attempt,
                                   restore_generation=restore_generation, key=key, actor=actor)
        self._refresh_liveness_after_progress()
        return result

    def artifact_heartbeat(self, rid, fence):
        super().artifact_heartbeat(rid, fence)
        self._refresh_liveness_after_progress()

    def next_real_run(self, blocked=()):
        """Select one queued, frozen-version-bound training or inference run."""
        return self._call_real('next_real_run', [f'{rid}@{rev}' for rid, rev in blocked])

    def claim_real(self, rid, *, start=True, worker_id=None, key=None):
        """Claim a real-data run using the same slot, fence and generation protocol."""
        pid, created = identity()
        run = self._call_real('claim_real', rid, worker_id or 'worker', pid, created, key)
        self._tokens[run['attempt']] = run.pop('credential')
        if start:
            started = self.start(rid, run['attempt'], run['fence'], run['cancel_generation'],
                                 run['digest'], restore_generation=run['restore_generation'])
            run.update(state=started['state'], revision=started['revision'])
        return run

    def next_real_artifact(self, blocked=()):
        """Select a retryable real-training artifact without exposing other runs."""
        return self._call_real('next_real_artifact', [f'{rid}@{rev}' for rid, rev in blocked])

    def claim_real_artifacts(self, rid):
        """Claim a real-training artifact retry under the shared fenced slot."""
        pid, created = identity()
        return self._call_real('claim_real_artifacts', rid, pid, created)

    def real_inputs(self, rid, attempt, fence, cancel_generation, restore_generation):
        """Fetch only train/validation rows after validating the live attempt fence."""
        token = self._token(attempt)
        if not token:
            raise Conflict('CREDENTIAL_EXPIRED_OR_INVALID')
        return self._call_real('real_inputs', token, rid, attempt, fence,
                               cancel_generation, restore_generation)

    def real_member_rights(self, rid, attempt, fence, cancel_generation,
                           restore_generation, sample_id):
        """Recheck current local-training rights for exactly one train/validation sample."""
        token = self._token(attempt)
        if not token:
            raise Conflict('CREDENTIAL_EXPIRED_OR_INVALID')
        return self._call_real('real_member_rights', token, rid, attempt, fence,
                               cancel_generation, restore_generation, sample_id)

    def real_bundle_rights(self, rid, attempt, fence, cancel_generation, restore_generation):
        """Fetch fresh model_bundle rights for the train/validation artifact population."""
        token = self._token(attempt)
        if not token:
            raise Conflict('CREDENTIAL_EXPIRED_OR_INVALID')
        return self._call_real('real_bundle_rights', token, rid, attempt, fence,
                               cancel_generation, restore_generation)

    def real_artifact_rights(self, rid, fence):
        """Recheck bundle rights under the live succeeded-run artifact slot fence."""
        pid, created = identity()
        return self._call_real('real_artifact_rights', rid, fence, pid, created)

    def real_inference_input(self, rid, attempt, fence, cancel_generation, restore_generation):
        """Fetch one authorized train/validation sample and a verified bundle leaf."""
        token = self._token(attempt)
        if not token:
            raise Conflict('CREDENTIAL_EXPIRED_OR_INVALID')
        return self._call_real('real_inference_input', token, rid, attempt, fence,
                               cancel_generation, restore_generation)

    def real_image_inference_input(self, rid, attempt, fence, cancel_generation,
                                   restore_generation, pixel_digest=None):
        """Fetch one private upload locator plus current rights/holdout facts."""
        token = self._token(attempt)
        if not token:
            raise Conflict('CREDENTIAL_EXPIRED_OR_INVALID')
        return self._call_real('real_image_inference_input', token, rid, attempt, fence,
                               cancel_generation, restore_generation, pixel_digest)

    def qualified_image_inference_input(self, rid, attempt, fence, cancel_generation,
                                        restore_generation, pixel_digest=None):
        """Read the fixed-registry R5 release/input binding through migration012."""
        token = self._token(attempt)
        if not token:
            raise Conflict('CREDENTIAL_EXPIRED_OR_INVALID')
        return self._call_real('qualified_image_inference_input', token, rid, attempt, fence,
                               cancel_generation, restore_generation, pixel_digest)

    def complete_real_inference(self, rid, attempt, fence, cancel_generation,
                                restore_generation, receipt):
        """Complete inference with a redacted database receipt and release the slot."""
        token = self._token(attempt)
        if not token:
            raise Conflict('CREDENTIAL_EXPIRED_OR_INVALID')
        slot = self._call('slot_status')
        pid, created = identity()
        child_exited = not slot['launching'] and not alive(slot['pid'], slot['child_created'])
        result = self._call_real('complete_real_inference', token, rid, attempt, fence,
                                 cancel_generation, restore_generation, Jsonb(receipt),
                                 pid, created, child_exited)
        self._tokens.pop(attempt, None)
        return result

    def complete_real_image_inference(self, rid, attempt, fence, cancel_generation,
                                      restore_generation, receipt, pixel_digest, rights_digests):
        """Commit only the exact signed decision envelopes just verified by worker."""
        token = self._token(attempt)
        if not token:
            raise Conflict('CREDENTIAL_EXPIRED_OR_INVALID')
        if type(rights_digests) is not dict or set(rights_digests) != {'training', 'bundle'}:
            raise Conflict('REAL_IMAGE_RIGHTS_BINDING')
        slot = self._call('slot_status')
        pid, created = identity()
        child_exited = not slot['launching'] and not alive(slot['pid'], slot['child_created'])
        result = self._call_real('complete_real_image_inference', token, rid, attempt, fence,
            cancel_generation, restore_generation, Jsonb(receipt), pid, created, child_exited,
            pixel_digest, rights_digests['training'], rights_digests['bundle'])
        self._tokens.pop(attempt, None)
        return result

    def complete_qualified_image_inference(self, rid, attempt, fence, cancel_generation,
            restore_generation, receipt, pixel_digest, rights_digests):
        """Commit a redacted prediction after the qualified child and rights checks."""
        token = self._token(attempt)
        if not token:
            raise Conflict('CREDENTIAL_EXPIRED_OR_INVALID')
        if type(rights_digests) is not dict or set(rights_digests) != {'training', 'bundle'}:
            raise Conflict('QUALIFIED_IMAGE_RIGHTS_BINDING')
        slot = self._call('slot_status')
        pid, created = identity()
        child_exited = not slot['launching'] and not alive(slot['pid'], slot['child_created'])
        result = self._call_real('complete_qualified_image_inference', token, rid, attempt, fence,
            cancel_generation, restore_generation, Jsonb(receipt), pid, created, child_exited,
            pixel_digest, rights_digests['training'], rights_digests['bundle'])
        self._tokens.pop(attempt, None)
        return result

    def bundle_inference_blocked(self, workspace, source_run_id):
        """Read the retention journal through a fixed scoped SQL capability."""
        return bool(self._call_real('bundle_inference_blocked', workspace, source_run_id))
