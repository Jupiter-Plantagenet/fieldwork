-- Verified real artifact retention is archive-only. Apply only through the
-- documented backup/rehearsal lane; this migration has not been applied here.
BEGIN;

CREATE TABLE public.fw_real_artifact_retention (
  workspace text NOT NULL,
  run text NOT NULL REFERENCES public.fw_runs(id),
  source_leaf text NOT NULL CHECK (source_leaf ~ '^real-artifact-attempt-[0-9]{1,12}$'),
  bundle_digest text NOT NULL CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
  verified_at timestamptz NOT NULL,
  retention_days integer NOT NULL CHECK (retention_days BETWEEN 30 AND 3650),
  expires_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('prepared','archived','recovery_required','recovered')),
  source_relpath text NOT NULL CHECK (source_relpath ~ '^var/runs/[0-9a-f-]{36}/real-artifact-attempt-[0-9]{1,12}/bundle$'),
  archive_relpath text NOT NULL CHECK (archive_relpath ~ '^\.local/real-artifact-archive/[0-9a-f]{64}/[0-9a-f]{64}/real-artifact-attempt-[0-9]{1,12}/bundle$'),
  archive_tree_sha256 text CHECK (archive_tree_sha256 IS NULL OR archive_tree_sha256 ~ '^[0-9a-f]{64}$'),
  manifest_snapshot jsonb NOT NULL CHECK (jsonb_typeof(manifest_snapshot)='object'),
  lineage_snapshot jsonb NOT NULL CHECK (jsonb_typeof(lineage_snapshot)='object'),
  last_error text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  archived_at timestamptz,
  recovered_at timestamptz,
  PRIMARY KEY(workspace,run),
  CHECK (expires_at=verified_at+make_interval(days=>retention_days)),
  CHECK (state NOT IN ('prepared','archived','recovered') OR archive_tree_sha256 IS NOT NULL),
  CHECK ((state IN ('archived','recovered')) = (archived_at IS NOT NULL))
);
CREATE INDEX fw_real_artifact_retention_pending
  ON public.fw_real_artifact_retention(state,expires_at,run)
  WHERE state IN ('prepared','recovery_required');

ALTER TABLE public.fw_real_artifact_retention ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fw_real_artifact_retention FORCE ROW LEVEL SECURITY;
CREATE POLICY fw_retention_api_read ON public.fw_real_artifact_retention
  FOR SELECT TO fieldwork_api
  USING (workspace=current_setting('fieldwork.workspace',true));
CREATE POLICY fw_retention_worker_read ON public.fw_real_artifact_retention
  FOR SELECT TO fieldwork_real_worker_definer
  USING (fw_worker_cap_v1.allowed(workspace));
REVOKE ALL ON public.fw_real_artifact_retention FROM PUBLIC;
GRANT SELECT ON public.fw_real_artifact_retention TO fieldwork_api,fieldwork_real_worker_definer;

CREATE FUNCTION fw_real_worker_cap_v1.bundle_inference_blocked(p_workspace text,p_run text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT CASE WHEN fw_worker_cap_v1.allowed(p_workspace)
    THEN EXISTS (SELECT 1 FROM public.fw_real_artifact_retention a
      WHERE a.workspace=p_workspace AND a.run=p_run)
    ELSE true END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.bundle_inference_blocked(text,text)
  OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.bundle_inference_blocked(text,text) FROM PUBLIC;
DO $grant_existing_scoped_logins$
DECLARE principal_name text;
BEGIN
  -- Existing non-inheriting scoped logins need only this fixed capability.
  -- No public-table privilege is granted to any login.
  FOR principal_name IN SELECT principal FROM fw_worker_cap_v1.scope LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.bundle_inference_blocked(text,text) TO %I',
                   principal_name);
  END LOOP;
END
$grant_existing_scoped_logins$;

-- Serialize new inference against a retention reservation. An inference already
-- queued/running is checked by the scanner before it creates the reservation.
CREATE FUNCTION public.fw_real_inference_retention_fence_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $fn$
DECLARE source_run text; source_row public.fw_runs;
BEGIN
  IF NEW.config->>'scope' NOT IN ('real-inference/v1','real-image-inference/v1') THEN
    RETURN NEW;
  END IF;
  source_run := NEW.config->>'run_id';
  IF source_run IS NULL THEN
    RAISE EXCEPTION 'REAL_INFERENCE_SOURCE_REQUIRED' USING ERRCODE='P0001';
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
    'fieldwork-artifact-retention:' || NEW.workspace || ':' || source_run,0));
  SELECT * INTO source_row FROM public.fw_runs
    WHERE workspace=NEW.workspace AND id=source_run FOR SHARE;
  IF NOT FOUND OR source_row.state<>'succeeded' OR source_row.artifact_status<>'verified'
     OR source_row.config->>'scope'<>'real-training/v1'
     OR source_row.artifact_result->>'bundle_digest' IS DISTINCT FROM NEW.config->>'bundle_digest' THEN
    RAISE EXCEPTION 'REAL_INFERENCE_SOURCE_NOT_AVAILABLE' USING ERRCODE='P0001';
  END IF;
  IF EXISTS (SELECT 1 FROM public.fw_real_artifact_retention a
      WHERE a.workspace=NEW.workspace AND a.run=source_run) THEN
    RAISE EXCEPTION 'REAL_BUNDLE_EXPIRED_ARCHIVED' USING ERRCODE='P0001';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION public.fw_real_inference_retention_fence_v1() FROM PUBLIC;
CREATE TRIGGER trg_real_inference_retention_fence_v1
  BEFORE INSERT ON public.fw_runs FOR EACH ROW
  EXECUTE FUNCTION public.fw_real_inference_retention_fence_v1();

-- Scoped workers can read only their workspace's journal. A restrictive policy
-- hides inference rows whose source bundle is reserved/archived/recovered from
-- the existing fixed real-worker capability, including already queued work.
CREATE POLICY fw_real_worker_retention_fence ON public.fw_runs
  AS RESTRICTIVE FOR SELECT TO fieldwork_real_worker_definer
  USING (config->>'scope' NOT IN ('real-inference/v1','real-image-inference/v1') OR NOT EXISTS (
    SELECT 1 FROM public.fw_real_artifact_retention a
      WHERE a.workspace=fw_runs.workspace AND a.run=fw_runs.config->>'run_id'));

COMMENT ON TABLE public.fw_real_artifact_retention IS
  'Archive-only retention journal for verified real bundles. Run/event/result lineage is immutable; any ledger row prevents model reuse, including operator recovery copies.';
COMMIT;
