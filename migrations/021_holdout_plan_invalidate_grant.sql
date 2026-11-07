-- Written 2026-11-03 by the leak/isolation matrix lane; reviewed and applied to the retained database by the completion
-- pass under the operator's standing build authorization (tools/apply_migration_021.py: verified backup, scratch
-- rehearsal, then apply). Never apply from application code.
--
-- Defect: POST /api/v1/workspaces/{ws}/real/holdout/plans/{plan_id}/invalidate (fieldwork/real_api.py,
-- invalidate_holdout_plan) runs `SELECT ... FOR UPDATE` and `UPDATE fw_holdout_plans SET state='invalidated'` as the
-- nonowner request principal `fieldwork_api`, but migration 006 granted it only SELECT,INSERT on fw_holdout_plans and
-- no later migration adds UPDATE. The route therefore fails with `permission denied for table fw_holdout_plans`
-- (an unhandled 500) for every steward, so post-exposure invalidation is reachable only through the operator tools.
--
-- Fix: the narrowest grant (two columns) plus a transition guard so that the request principal can ONLY move a plan to
-- `invalidated` with a reason. It can never restore `authorized`, edit digests/model/exposure counters/results, or
-- un-invalidate. Operator and worker-definer paths are unaffected (the guard acts on session_user fieldwork_api only).
BEGIN;

DO $preflight$
BEGIN
  IF to_regclass('public.fw_holdout_plans') IS NULL OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fieldwork_api') THEN
    RAISE EXCEPTION '021_HOLDOUT_PLAN_PREREQUISITES_REQUIRED';
  END IF;
  IF has_table_privilege('fieldwork_api','public.fw_holdout_plans','UPDATE') THEN
    RAISE EXCEPTION '021_UNEXPECTED_TABLE_LEVEL_UPDATE';
  END IF;
END
$preflight$;

CREATE FUNCTION public.fw_holdout_plan_api_guard_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
  IF session_user <> 'fieldwork_api' THEN
    RETURN NEW;
  END IF;
  IF OLD.state NOT IN ('authorized','consumed') OR NEW.state <> 'invalidated'
     OR NEW.invalidated_reason IS NULL OR pg_catalog.length(pg_catalog.btrim(NEW.invalidated_reason)) < 10
     OR NEW.workspace IS DISTINCT FROM OLD.workspace OR NEW.plan_id IS DISTINCT FROM OLD.plan_id
     OR NEW.version_id IS DISTINCT FROM OLD.version_id OR NEW.version_digest IS DISTINCT FROM OLD.version_digest
     OR NEW.population_digest IS DISTINCT FROM OLD.population_digest
     OR NEW.population_count IS DISTINCT FROM OLD.population_count
     OR NEW.candidate_model_digest IS DISTINCT FROM OLD.candidate_model_digest
     OR NEW.candidate_checkpoint_digest IS DISTINCT FROM OLD.candidate_checkpoint_digest
     OR NEW.evaluator IS DISTINCT FROM OLD.evaluator
     OR NEW.usefulness_spec_sha256 IS DISTINCT FROM OLD.usefulness_spec_sha256
     OR NEW.steward IS DISTINCT FROM OLD.steward OR NEW.authorized_utc IS DISTINCT FROM OLD.authorized_utc
     OR NEW.consumed_utc IS DISTINCT FROM OLD.consumed_utc OR NEW.exposures IS DISTINCT FROM OLD.exposures
     OR NEW.result_sha256 IS DISTINCT FROM OLD.result_sha256 OR NEW.result IS DISTINCT FROM OLD.result THEN
    RAISE EXCEPTION 'FW_HOLDOUT_PLAN_API_TRANSITION' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END
$guard$;
REVOKE ALL ON FUNCTION public.fw_holdout_plan_api_guard_v1() FROM PUBLIC;

CREATE TRIGGER fw_holdout_plan_api_guard BEFORE UPDATE ON public.fw_holdout_plans
  FOR EACH ROW EXECUTE FUNCTION public.fw_holdout_plan_api_guard_v1();

GRANT UPDATE (state, invalidated_reason) ON public.fw_holdout_plans TO fieldwork_api;

COMMIT;
