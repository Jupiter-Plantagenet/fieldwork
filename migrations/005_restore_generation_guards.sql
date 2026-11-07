-- 005: restore generation, ML-Start/attempt lineage columns, internal-command receipts and
-- the fw_runs authority guard (round 5). EXPAND-ONLY: adds a table, nullable columns, a
-- receipts table and a trigger. No column is dropped, retyped or backfilled; existing rows
-- keep every value. Apply with tools/activate_round5.py (backup + restored-copy rehearsal
-- first). Application code never performs this DDL.
--
-- fw_control.restore_generation (ml-contracts ML-Attempt.restore_generation:uuid) is the
-- deployment epoch. Every attempt records the generation current at claim; every fenced
-- worker write requires the attempt's generation to equal the current one. A restore
-- (Store.restore_fence) issues a new generation and raises fence_floor above every fence
-- the lost lineage could have issued, so pre-restore fences and attempts can never recur.
--
-- fw_runs_guard (review F5): the browser request principal holds only column UPDATE on
-- state/fence/revision/cancel_generation and may perform only browser transitions:
--   cancel   queued|interrupted -> cancelled, leased|running -> cancel_requested
--            (fence +1, cancel_generation +1, revision +1)
--   resume   interrupted -> queued (fence/generation unchanged)
-- Every non-owner principal (API, worker and controller capability definers) is held to
-- monotonic fence, revision and cancel_generation; identity columns are immutable.
-- Superusers and the table owner (operator migrations/restore tooling) are trusted.
BEGIN;
CREATE TABLE IF NOT EXISTS fw_control(
    id int PRIMARY KEY CHECK (id=1),
    restore_generation uuid NOT NULL,
    fence_floor int NOT NULL DEFAULT 0 CHECK (fence_floor>=0),
    restored_at timestamptz,
    restore_source text,
    updated timestamptz NOT NULL DEFAULT now());
INSERT INTO fw_control(id,restore_generation) VALUES(1,gen_random_uuid()) ON CONFLICT (id) DO NOTHING;
ALTER TABLE fw_attempts ADD COLUMN IF NOT EXISTS restore_generation uuid;
ALTER TABLE fw_attempts ADD COLUMN IF NOT EXISTS worker_id text;
ALTER TABLE fw_attempts ADD COLUMN IF NOT EXISTS started_at timestamptz;
ALTER TABLE fw_attempts ADD COLUMN IF NOT EXISTS ended_at timestamptz;
ALTER TABLE fw_attempts ADD COLUMN IF NOT EXISTS exit_receipt_digest text
    CONSTRAINT fw_attempts_exit_receipt_hex CHECK (exit_receipt_digest IS NULL OR exit_receipt_digest ~ '^[0-9a-f]{64}$');
CREATE TABLE IF NOT EXISTS fw_command_receipts(
    workspace text NOT NULL,
    actor text NOT NULL,
    command text NOT NULL,
    key text NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    status int NOT NULL,
    response jsonb NOT NULL,
    run text,
    created timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(workspace,actor,command,key));
CREATE OR REPLACE FUNCTION public.fw_runs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $guard$
DECLARE trusted boolean; definer boolean; cancel_move boolean; resume_move boolean;
BEGIN
    SELECT r.rolsuper OR r.oid=c.relowner INTO trusted
      FROM pg_catalog.pg_roles r, pg_catalog.pg_class c
     WHERE r.rolname=current_user AND c.oid=TG_RELID;
    IF coalesce(trusted,false) THEN RETURN NEW; END IF;
    -- Capability definers (worker / lease controller) own functions in their fixed schemas.
    SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                   WHERE n.nspname IN ('fw_worker_cap_v1','fw_lease_cap_v1')
                     AND p.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)) INTO definer;
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'queued' OR NEW.fence<>0 OR NEW.epoch<>0 OR NEW.revision<>1 OR NEW.lease IS NOT NULL
           OR NEW.attempt IS NOT NULL OR NEW.checkpoint IS NOT NULL OR NEW.result IS NOT NULL
           OR coalesce(NEW.cancel_generation,0)<>0 OR NEW.artifact_status<>'not_started' THEN
            RAISE EXCEPTION 'FW_RUN_GUARD_INSERT' USING ERRCODE='42501';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id<>OLD.id OR NEW.workspace<>OLD.workspace OR NEW.actor<>OLD.actor OR NEW.idem<>OLD.idem
       OR NEW.digest<>OLD.digest OR NEW.config<>OLD.config THEN
        RAISE EXCEPTION 'FW_RUN_GUARD_IDENTITY' USING ERRCODE='42501';
    END IF;
    IF NEW.fence<OLD.fence OR NEW.revision<OLD.revision
       OR (OLD.cancel_generation IS NOT NULL AND (NEW.cancel_generation IS NULL OR NEW.cancel_generation<OLD.cancel_generation)) THEN
        RAISE EXCEPTION 'FW_RUN_GUARD_MONOTONIC' USING ERRCODE='42501';
    END IF;
    IF coalesce(definer,false) THEN RETURN NEW; END IF;
    -- Request principal: browser transitions only.
    IF NEW.lease IS DISTINCT FROM OLD.lease OR NEW.attempt IS DISTINCT FROM OLD.attempt OR NEW.epoch<>OLD.epoch
       OR NEW.checkpoint IS DISTINCT FROM OLD.checkpoint OR NEW.result IS DISTINCT FROM OLD.result
       OR NEW.artifact_status<>OLD.artifact_status OR NEW.artifact_result IS DISTINCT FROM OLD.artifact_result
       OR NEW.artifact_attempts<>OLD.artifact_attempts THEN
        RAISE EXCEPTION 'FW_RUN_GUARD_EXECUTION_COLUMNS' USING ERRCODE='42501';
    END IF;
    cancel_move := ((OLD.state IN ('queued','interrupted') AND NEW.state='cancelled')
                    OR (OLD.state IN ('leased','running') AND NEW.state='cancel_requested'))
                   AND NEW.fence=OLD.fence+1 AND NEW.revision=OLD.revision+1
                   AND NEW.cancel_generation=coalesce(OLD.cancel_generation,0)+1;
    resume_move := OLD.state='interrupted' AND NEW.state='queued' AND NEW.fence=OLD.fence
                   AND NEW.revision=OLD.revision+1 AND NEW.cancel_generation IS NOT DISTINCT FROM OLD.cancel_generation;
    IF NOT (cancel_move OR resume_move) THEN
        RAISE EXCEPTION 'FW_RUN_GUARD_TRANSITION % -> %',OLD.state,NEW.state USING ERRCODE='42501';
    END IF;
    RETURN NEW;
END $guard$;
REVOKE ALL ON FUNCTION public.fw_runs_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS fw_runs_guard ON fw_runs;
CREATE TRIGGER fw_runs_guard BEFORE INSERT OR UPDATE ON fw_runs FOR EACH ROW EXECUTE FUNCTION public.fw_runs_guard();
COMMIT;
