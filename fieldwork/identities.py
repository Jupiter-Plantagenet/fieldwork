"""Canonical ml-contracts identities and the ML event envelope (schema_version 1.0).

Identities that the store does not persist as UUID columns are derived with
UUIDv5 from immutable, already-unique keys, so they are stable across reads,
restarts and restores and never need a backfill:

* workspace_id   - the workspace text itself when it is a UUID, else uuid5.
* evaluation_id  - (workspace, run, split, canonical evaluation digest). The
                   digest pins the immutable evaluation bytes, so a changed
                   evaluation can never reuse an identity.
* slice_id       - (evaluation_id, canonical predicate).
* checkpoint_id  - (run, epoch): the fw_checkpoints primary key, written once.
* correlation_id - the producing command's recorded correlation id when the
                   payload carries one; otherwise derived from event_id and
                   marked `correlation_derived: true` (no request correlation
                   was recorded for that event).
"""
import uuid
from datetime import timezone
from .data import canonical

NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, 'urn:fieldwork:ml-contracts:identity:v1')
SCHEMA_VERSION = '1.0'

RUN_KINDS = {'queued', 'claimed', 'started', 'cancel_requested', 'cancelled', 'expired', 'failed',
             'succeeded', 'resume_requested', 'interrupted', 'slot_reconciled', 'restore_fenced'}
# ml-contracts ML-Run state enum. An envelope `state` is always one of these.
RUN_STATES = {'queued', 'leased', 'running', 'interrupted', 'cancel_requested', 'cancelled',
              'succeeded', 'failed'}
# State implied by an event kind when the payload does not record one. Legacy (pre-ML-Start)
# `claimed` events moved the run straight to running; new ones record state 'leased'.
KIND_STATE = {'queued': 'queued', 'claimed': 'running', 'started': 'running',
              'resume_requested': 'queued', 'cancel_requested': 'cancel_requested',
              'cancelled': 'cancelled', 'failed': 'failed', 'succeeded': 'succeeded',
              'interrupted': 'interrupted'}


def _derive(*parts):
    return str(uuid.uuid5(NAMESPACE, canonical([str(p) for p in parts]).decode()))


def _uuid_or_none(value):
    try:
        return str(uuid.UUID(str(value))) if value is not None else None
    except ValueError:
        return None


def _canonical_identity(value):
    """Only canonical lowercase hyphenated non-v5 UUID text is its own identity.

    Review F7: 'ABC..', '{abc..}' and 'urn:uuid:abc..' must not alias 'abc..', and a text
    equal to a derived (v5) id must not alias the name it was derived from, so every
    other spelling (including any v5 text) is derived instead.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return value if str(parsed) == value and parsed.version != 5 else None


def workspace_id(workspace):
    return _canonical_identity(workspace) or _derive('workspace', workspace)


def run_uuid(run):
    return _canonical_identity(run) or _derive('run', run)


def bundle_id(workspace, run, bundle_digest=None, fence=None):
    return _derive('bundle', workspace, run, bundle_digest or ('fence', fence))


def evaluation_id(workspace, run, evaluation_digest, split='validation'):
    return _derive('evaluation', workspace, run, split, evaluation_digest)


def slice_id(evaluation, predicate):
    return _derive('slice', evaluation, canonical(predicate).decode())


def checkpoint_id(run, epoch):
    return _derive('checkpoint', run, int(epoch))


def envelope(row, workspace):
    """Return the contract envelope for one public fw_events row.

    Existing transport keys are kept by callers; this only computes the
    contract fields. Unknown kinds map to ML-RunChanged with the raw kind as
    state, so no event is dropped or silently renamed.
    """
    payload = row.get('payload') or {}
    kind = row.get('kind') or ''
    event_id = str(row['event_id'])
    run = row.get('run')
    correlation = _uuid_or_none(payload.get('correlation_id')) if isinstance(payload, dict) else None
    created = row['created']
    if hasattr(created, 'astimezone'):
        occurred = created.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    else:
        occurred = str(created)
    revision = row.get('object_revision')
    base = {'schema_version': SCHEMA_VERSION, 'event_id': event_id,
            'workspace_id': workspace_id(workspace), 'sequence': str(row['seq']),
            'occurred_at': occurred, 'revision': revision if revision is not None else 0,
            'revision_legacy': revision is None,
            'correlation_id': correlation or _derive('correlation', event_id),
            'correlation_derived': correlation is None}
    if kind == 'epoch_committed' and run is not None:
        epoch = payload.get('epoch')
        cp = checkpoint_id(run, epoch)
        return {**base, 'type': 'ML-CheckpointCommitted', 'object_id': cp, 'checkpoint_id': cp,
                'run_id': run_uuid(run), 'epoch': epoch,
                'manifest_digest': payload.get('manifest_digest')}
    if kind.startswith('artifact_') and run is not None:
        status = payload.get('status') or kind[len('artifact_'):]
        evaluation = _uuid_or_none(payload.get('evaluation_id'))
        if evaluation is not None:
            # Only an evaluation that exists (verified, digest-bound) is ML-EvaluationChanged;
            # its id is the one GET .../evaluation returns, recorded at commit time.
            return {**base, 'type': 'ML-EvaluationChanged', 'object_id': evaluation,
                    'evaluation_id': evaluation, 'run_id': run_uuid(run), 'status': status,
                    'records_digest': payload.get('records_digest')}
        bundle = bundle_id(workspace, run, payload.get('bundle_digest'), payload.get('fence'))
        return {**base, 'type': 'ML-BundleChanged', 'object_id': bundle, 'bundle_id': bundle,
                'run_id': run_uuid(run), 'status': status}
    state = payload.get('state') if isinstance(payload, dict) else None
    if state not in RUN_STATES:
        state = KIND_STATE.get(kind)
    return {**base, 'type': 'ML-RunChanged', 'object_id': run_uuid(run) if run else None,
            'run_id': run_uuid(run) if run else None, 'state': state, 'kind': row.get('kind'),
            'attempt_id': _uuid_or_none(payload.get('attempt')), 'fence': payload.get('fence')}
