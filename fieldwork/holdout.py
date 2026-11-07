"""Sealed holdout governance: steward lock, atomic exposure, result retention.

States: authorized -> consumed (first credential/byte access, atomic, irreversible)
-> invalidated (post-exposure tuning). A retry must present the SAME locked model
digest; a different model is refused (MODEL_SWAP). Failure after consumption never
restores `authorized`. Results are retained whether the gate passes or fails.
Only the steward role may authorize or consume; researchers have no path here.
"""
import uuid

from psycopg.types.json import Jsonb

HOLDOUT_SCHEMA = '''
CREATE TABLE IF NOT EXISTS fw_holdout_plans(
  workspace text NOT NULL, plan_id uuid NOT NULL, version_id text NOT NULL, version_digest text NOT NULL,
  population_digest text NOT NULL, population_count int NOT NULL, candidate_model_digest text NOT NULL,
  candidate_checkpoint_digest text NOT NULL, evaluator text NOT NULL, usefulness_spec_sha256 text NOT NULL,
  steward text NOT NULL, state text NOT NULL CHECK (state IN ('authorized','consumed','invalidated')),
  authorized_utc timestamptz NOT NULL DEFAULT clock_timestamp(), consumed_utc timestamptz, exposures int NOT NULL DEFAULT 0,
  invalidated_reason text, result_sha256 text, result jsonb,
  PRIMARY KEY(workspace,plan_id));
CREATE UNIQUE INDEX IF NOT EXISTS fw_holdout_one_live_plan ON fw_holdout_plans(workspace,version_id) WHERE state<>'invalidated';
CREATE TABLE IF NOT EXISTS fw_holdout_exposures(
  workspace text NOT NULL, plan_id uuid NOT NULL, seq int NOT NULL, actor text NOT NULL, model_digest text NOT NULL,
  at_utc timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(workspace,plan_id,seq));
'''


class HoldoutRefused(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _role(c, workspace, actor):
    from .rights_registry import load_trusted_registry
    from .rights_decision import DecisionRejected

    # Operator callers also need the transaction-local tenant for FORCE RLS.
    # Account ownership never implies authority to expose a protected population.
    c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (workspace,))
    if not c.execute("SELECT to_regclass('public.fw_holdout_stewards') AS relation").fetchone()['relation']:
        raise HoldoutRefused('STEWARD_ASSIGNMENT_SCHEMA_REQUIRED')
    r = c.execute('''SELECT s.reviewer_id,s.key_id FROM fw_holdout_stewards s
        JOIN fw_accounts a ON a.workspace=s.workspace AND a.name=s.actor
        WHERE s.workspace=%s AND s.actor=%s''', (workspace, actor)).fetchone()
    if not r:
        raise HoldoutRefused('STEWARD_ROLE_REQUIRED')
    try:
        trusted = load_trusted_registry().get((r['reviewer_id'], r['key_id']))
    except DecisionRejected:
        trusted = None
    if not trusted or workspace not in trusted.workspace_ids:
        raise HoldoutRefused('STEWARD_KEY_NOT_TRUSTED')


def authorize(store, workspace, actor, *, version_id, version_digest, population_digest, population_count,
              model_digest, checkpoint_digest, evaluator, spec_sha256):
    with store.connect() as c:
        _role(c, workspace, actor)
        pid = str(uuid.uuid4())
        c.execute('''INSERT INTO fw_holdout_plans(workspace,plan_id,version_id,version_digest,population_digest,population_count,
            candidate_model_digest,candidate_checkpoint_digest,evaluator,usefulness_spec_sha256,steward,state)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'authorized')''',
                  (workspace, pid, version_id, version_digest, population_digest, population_count, model_digest,
                   checkpoint_digest, evaluator, spec_sha256, actor))
        return pid


def consume(store, workspace, actor, plan_id, model_digest):
    """Record exposure BEFORE any holdout byte is read. Irreversible."""
    with store.connect() as c:
        _role(c, workspace, actor)
        p = c.execute('SELECT * FROM fw_holdout_plans WHERE workspace=%s AND plan_id=%s FOR UPDATE', (workspace, plan_id)).fetchone()
        if not p:
            raise HoldoutRefused('NO_PLAN')
        if p['steward'] != actor:
            raise HoldoutRefused('PLAN_STEWARD_MISMATCH')
        if p['state'] == 'invalidated':
            raise HoldoutRefused('PLAN_INVALIDATED')
        if p['candidate_model_digest'] != model_digest:
            raise HoldoutRefused('MODEL_SWAP')
        seq = p['exposures'] + 1
        c.execute("UPDATE fw_holdout_plans SET state='consumed',consumed_utc=coalesce(consumed_utc,clock_timestamp()),exposures=%s WHERE workspace=%s AND plan_id=%s",
                  (seq, workspace, plan_id))
        c.execute('INSERT INTO fw_holdout_exposures(workspace,plan_id,seq,actor,model_digest) VALUES(%s,%s,%s,%s,%s)',
                  (workspace, plan_id, seq, actor, model_digest))
        return dict(c.execute('SELECT * FROM fw_holdout_plans WHERE workspace=%s AND plan_id=%s', (workspace, plan_id)).fetchone())


def record_result(store, workspace, plan_id, result_sha256, result):
    with store.connect() as c:
        c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (workspace,))
        c.execute('UPDATE fw_holdout_plans SET result_sha256=%s,result=%s WHERE workspace=%s AND plan_id=%s AND state=%s',
                  (result_sha256, Jsonb(result), workspace, plan_id, 'consumed'))


def invalidate_for_tuning(store, workspace, plan_id, reason):
    with store.connect() as c:
        c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (workspace,))
        c.execute("UPDATE fw_holdout_plans SET state='invalidated',invalidated_reason=%s WHERE workspace=%s AND plan_id=%s AND state='consumed'",
                  (reason, workspace, plan_id))
