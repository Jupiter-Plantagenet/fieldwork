"""Append-only follow-up notes on immutable validation slices, never relabels.

Uses the existing tenant-scoped fw_events transaction/outbox, not a new schema.
The command lock serializes response-loss retries across all runs for one actor.
Receipts must be retained beyond SSE replay expiry, as for existing commands.
"""
import uuid
from psycopg.types.json import Jsonb
from .annotations import Rejection
from .data import canonical, digest
from .store import Conflict

KIND = 'evaluation_flag'


def create(store, workspace, run_id, actor, key, command, evidence):
    request_digest = digest(canonical(dict(command, run_id=run_id)))
    scope = canonical([workspace, actor, 'ML-Flag', key]).decode()
    with store.connect() as c:
        c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))', (scope,))
        prior = c.execute("SELECT payload FROM fw_events WHERE workspace=%s AND kind=%s AND payload->>'actor'=%s AND payload->>'key'=%s ORDER BY seq LIMIT 1",
                          (workspace, KIND, actor, key)).fetchone()
        if prior:
            if prior['payload']['request_digest'] != request_digest:
                raise Conflict('IDEMPOTENCY_CONFLICT')
            return prior['payload']['response_body']
        run = c.execute('SELECT * FROM fw_runs WHERE id=%s AND workspace=%s FOR SHARE', (run_id, workspace)).fetchone()
        if not run:
            raise Rejection(404, 'OBJECT')
        if run['revision'] != command['expected_revision']:
            raise Rejection(412, 'STALE_REVISION')
        ev = evidence()
        if digest(canonical(ev)) != command['evaluation_digest']:
            raise Rejection(412, 'EVALUATION_CHANGED')
        if command['bucket'] == 'cell':
            ids = ev['metrics']['cells'][f"{command['actual']}:{command['predicted']}"]
        else:
            ids = [s['id'] for s in ev['population'] if s['label'] == command['actual'] and s['id'] in ev['metrics']['missing']]
        ids = sorted(ids)
        if digest(canonical(ids)) != command['slice_digest']:
            raise Rejection(412, 'SLICE_CHANGED')
        if not ids:
            raise Rejection(422, 'EMPTY_SLICE')
        flag = dict(id=str(uuid.uuid4()), run_id=run_id, actor=actor, reason=command['reason'],
                    predicate={k: command[k] for k in ('actual', 'predicted', 'bucket')},
                    sample_ids=ids, slice_digest=command['slice_digest'], evaluation_digest=command['evaluation_digest'])
        body = canonical(dict(flag_id=flag['id'], evaluation_mutated=False, flag=flag)).decode()
        payload = dict(command='ML-Flag', actor=actor, key=key, request_digest=request_digest,
                       response_body=body, flag=flag)
        c.execute('INSERT INTO fw_events(workspace,run,kind,payload,object_revision) VALUES(%s,%s,%s,%s,%s)',
                  (workspace, run_id, KIND, Jsonb(payload), run['revision']))
        # Separate public projection, committed atomically with the private
        # receipt. Correlation is independent of the secret command key.
        public = dict(command='ML-Flag', flag_id=flag['id'],
                      evaluation_digest=command['evaluation_digest'], correlation_id=str(uuid.uuid4()))
        c.execute('INSERT INTO fw_events(workspace,run,kind,payload,object_revision) VALUES(%s,%s,%s,%s,%s)',
                  (workspace, run_id, 'ML-DataChanged', Jsonb(public), run['revision']))
        return body


def list_flags(store, workspace, run_id):
    if not store.get(run_id, workspace):
        raise Rejection(404, 'OBJECT')
    with store.connect() as c:
        rows = c.execute("SELECT payload->'flag' AS flag FROM fw_events WHERE workspace=%s AND run=%s AND kind=%s ORDER BY seq", (workspace, run_id, KIND)).fetchall()
        return [r['flag'] for r in rows]
