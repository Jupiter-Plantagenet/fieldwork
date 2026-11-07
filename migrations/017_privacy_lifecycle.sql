-- Fieldwork privacy lifecycle ledger and worker access fence.
-- Source only: back up and rehearse before coordinator applies this migration.
BEGIN;

CREATE TABLE public.fw_privacy_objects (
  object_kind text NOT NULL CHECK (object_kind IN ('fresh_inference_input','abandoned_staging','workspace_deleted_blob','application_log','dataset_artifact','run_artifact','filesystem_staging','backup_artifact')),
  workspace text NOT NULL,
  object_key text NOT NULL,
  source_path text NOT NULL,
  created_utc timestamptz NOT NULL,
  expires_utc timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','archived','held','recovery_required')),
  legal_hold boolean NOT NULL DEFAULT false,
  pinned boolean NOT NULL DEFAULT false,
  live_bytes_retired boolean NOT NULL DEFAULT false,
  shared_live boolean NOT NULL DEFAULT false,
  expected_sha256 text CHECK (expected_sha256 IS NULL OR expected_sha256 ~ '^[0-9a-f]{64}$'),
  expected_bytes bigint CHECK (expected_bytes IS NULL OR expected_bytes >= 0),
  archive_path text,
  content_sha256 text CHECK (content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{64}$'),
  content_bytes bigint CHECK (content_bytes IS NULL OR content_bytes >= 0),
  last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{1,64}$'),
  updated_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(object_kind,workspace,object_key),
  -- Opaque directory moves retain the pre-existing verified digest but do not
  -- inspect members to derive a byte count; content_bytes is intentionally NULL there.
  CHECK ((state='archived')=(archive_path IS NOT NULL AND content_sha256 IS NOT NULL))
);
CREATE INDEX fw_privacy_objects_due ON public.fw_privacy_objects(expires_utc,workspace,object_kind)
  WHERE state='active' AND NOT legal_hold AND NOT pinned;
ALTER TABLE public.fw_privacy_objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY fw_privacy_api_read ON public.fw_privacy_objects FOR SELECT TO fieldwork_api
  USING (workspace=current_setting('fieldwork.workspace',true));
CREATE POLICY fw_privacy_api_insert ON public.fw_privacy_objects FOR INSERT TO fieldwork_api
  WITH CHECK (workspace=current_setting('fieldwork.workspace',true)
    AND object_kind IN ('fresh_inference_input','abandoned_staging','dataset_artifact','run_artifact'));
CREATE POLICY fw_privacy_api_update ON public.fw_privacy_objects FOR UPDATE TO fieldwork_api
  USING (workspace=current_setting('fieldwork.workspace',true)
    AND object_kind IN ('fresh_inference_input','abandoned_staging','dataset_artifact','run_artifact'))
  WITH CHECK (workspace=current_setting('fieldwork.workspace',true)
    AND object_kind IN ('fresh_inference_input','abandoned_staging','dataset_artifact','run_artifact'));
REVOKE ALL ON public.fw_privacy_objects FROM PUBLIC;
GRANT SELECT,INSERT ON public.fw_privacy_objects TO fieldwork_api;
GRANT UPDATE (legal_hold,pinned,updated_utc) ON public.fw_privacy_objects TO fieldwork_api;

CREATE TABLE public.fw_privacy_workspace_tombstones (
  workspace text PRIMARY KEY,
  request_id uuid NOT NULL UNIQUE,
  requested_by text NOT NULL,
  expected_settings_revision integer NOT NULL CHECK(expected_settings_revision>0),
  deleted_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  archive_due_utc timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'revoked' CHECK(state IN ('revoked','archiving','archived','recovery_required')),
  archived_objects bigint NOT NULL DEFAULT 0 CHECK(archived_objects>=0),
  last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{1,64}$'),
  updated_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(archive_due_utc=deleted_utc+interval '7 days')
);
CREATE TABLE public.fw_privacy_workspace_bundle_scan (
  workspace text NOT NULL,
  run text NOT NULL,
  after_relative_path text NOT NULL DEFAULT '',
  complete boolean NOT NULL DEFAULT false,
  last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{1,64}$'),
  updated_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(workspace,run)
);
REVOKE ALL ON public.fw_privacy_workspace_bundle_scan FROM PUBLIC,fieldwork_api,
  fieldwork_real_worker_definer,fieldwork_intake_worker;
ALTER TABLE public.fw_privacy_workspace_tombstones ENABLE ROW LEVEL SECURITY;
CREATE POLICY fw_privacy_tombstone_api_read ON public.fw_privacy_workspace_tombstones
  FOR SELECT TO fieldwork_api USING(workspace=current_setting('fieldwork.workspace',true));
CREATE POLICY fw_privacy_tombstone_api_insert ON public.fw_privacy_workspace_tombstones
  FOR INSERT TO fieldwork_api WITH CHECK(workspace=current_setting('fieldwork.workspace',true));
REVOKE ALL ON public.fw_privacy_workspace_tombstones FROM PUBLIC;
GRANT SELECT,INSERT ON public.fw_privacy_workspace_tombstones TO fieldwork_api;
CREATE POLICY fw_privacy_tombstone_worker_read ON public.fw_privacy_workspace_tombstones
  FOR SELECT TO fieldwork_real_worker_definer
  USING(fw_worker_cap_v1.allowed(workspace));
GRANT SELECT ON public.fw_privacy_workspace_tombstones TO fieldwork_real_worker_definer;

CREATE FUNCTION public.fw_privacy_workspace_deleted_v1(p_workspace text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT EXISTS(SELECT 1 FROM public.fw_privacy_workspace_tombstones t WHERE t.workspace=p_workspace)
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_workspace_deleted_v1(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fw_privacy_workspace_deleted_v1(text) TO fieldwork_real_worker_definer;
GRANT EXECUTE ON FUNCTION public.fw_privacy_workspace_deleted_v1(text) TO fieldwork_intake_worker;
GRANT EXECUTE ON FUNCTION public.fw_privacy_workspace_deleted_v1(text) TO fieldwork_api;

CREATE FUNCTION public.fw_privacy_restore_generation_v1() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT restore_generation FROM public.fw_control WHERE id=1
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_restore_generation_v1() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fw_privacy_restore_generation_v1() TO fieldwork_api;

-- Defend against requests whose session check raced with the tombstone commit.
-- Restrictive workspace RLS applies at each later SQL statement, not just login.
DO $privacy_api_fences$
DECLARE rel text;
BEGIN
  FOREACH rel IN ARRAY ARRAY['fw_runs','fw_events','fw_versions','fw_proposals','fw_samples',
    'fw_intake_batches','fw_intake_members','fw_real_intake_queue','fw_real_image_inputs',
    'fw_workspace_settings','fw_workspace_settings_events','fw_rights_datasets',
    'fw_rights_assets','fw_rights_decisions'] LOOP
    IF to_regclass('public.'||rel) IS NOT NULL THEN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',rel);
      EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',rel);
      EXECUTE format('CREATE POLICY %I ON public.%I AS RESTRICTIVE FOR ALL TO fieldwork_api
        USING (NOT public.fw_privacy_workspace_deleted_v1(workspace))
        WITH CHECK (NOT public.fw_privacy_workspace_deleted_v1(workspace))',
        'fw_privacy_tombstone_'||rel,rel);
    END IF;
  END LOOP;
END
$privacy_api_fences$;

CREATE FUNCTION public.fw_privacy_input_blocked_v1(p_workspace text,p_input text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT EXISTS(SELECT 1 FROM public.fw_privacy_objects p
    WHERE p.object_kind='fresh_inference_input' AND p.workspace=p_workspace
      AND p.object_key=p_input AND p.state IN ('archived','held','recovery_required'))
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_input_blocked_v1(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fw_privacy_input_blocked_v1(text,text) TO fieldwork_real_worker_definer;

CREATE FUNCTION public.fw_privacy_sample_blocked_v1(p_workspace text,p_sample text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT EXISTS(SELECT 1 FROM public.fw_privacy_objects p
    WHERE p.object_kind='dataset_artifact' AND p.workspace=p_workspace
      AND p.object_key=p_sample AND p.state IN ('archived','held','recovery_required'))
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_sample_blocked_v1(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fw_privacy_sample_blocked_v1(text,text) TO fieldwork_api,fieldwork_real_worker_definer;

-- Exact per-sample protection is recorded as a monotonic bit. Existing frozen
-- manifests are projected in SQL; no sealed member, label, path, or manifest is
-- returned to Python. train/validation/pool are ordinary retention classes;
-- holdout, explicit protected membership, and unknown splits remain protected.
ALTER TABLE public.fw_samples ADD COLUMN privacy_protected boolean NOT NULL DEFAULT false;
CREATE FUNCTION public.fw_privacy_sample_protection_guard_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF OLD.privacy_protected AND NOT NEW.privacy_protected THEN
    RAISE EXCEPTION 'PRIVACY_PROTECTION_IMMUTABLE' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_sample_protection_guard_v1() FROM PUBLIC;
CREATE TRIGGER trg_privacy_sample_protection_guard_v1 BEFORE UPDATE OF privacy_protected
  ON public.fw_samples FOR EACH ROW EXECUTE FUNCTION public.fw_privacy_sample_protection_guard_v1();

CREATE FUNCTION public.fw_privacy_seal_version_members_v1(p_workspace text,p_version text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE version_manifest jsonb;
BEGIN
  IF session_user='fieldwork_api' AND
     current_setting('fieldwork.workspace',true) IS DISTINCT FROM p_workspace THEN
    RAISE EXCEPTION 'WORKSPACE_SCOPE_REQUIRED' USING ERRCODE='42501';
  END IF;
  SELECT manifest INTO version_manifest FROM public.fw_versions
    WHERE workspace=p_workspace AND id=p_version AND state='frozen' FOR SHARE;
  IF NOT FOUND OR version_manifest->>'scope'<>'real-rights-cleared' THEN
    RAISE EXCEPTION 'FROZEN_REAL_VERSION_REQUIRED' USING ERRCODE='42501';
  END IF;
  UPDATE public.fw_samples s SET privacy_protected=true
    WHERE s.workspace=p_workspace AND EXISTS (
      SELECT 1 FROM jsonb_path_query(version_manifest,'$.samples[*]') AS member(item)
      WHERE member.item->>'id'=s.sample_id::text
        AND (coalesce(member.item->>'split','') NOT IN ('train','validation','pool')
          OR member.item->>'protected'='true' OR member.item ? 'holdout_population'));
END
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_seal_version_members_v1(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fw_privacy_seal_version_members_v1(text,text) TO fieldwork_api;

-- Conservative metadata-only backfill: any frozen version that marks a sample
-- protected keeps it protected even if another version places it in a normal split.
UPDATE public.fw_samples s SET privacy_protected=true
  WHERE EXISTS (
    SELECT 1 FROM public.fw_versions v,
      LATERAL jsonb_path_query(v.manifest,'$.samples[*]') AS member(item)
    WHERE v.workspace=s.workspace AND v.state='frozen'
      AND member.item->>'id'=s.sample_id::text
      AND (coalesce(member.item->>'split','') NOT IN ('train','validation','pool')
        OR member.item->>'protected'='true' OR member.item ? 'holdout_population'));

CREATE FUNCTION public.fw_privacy_checkpoint_blocked_v1(p_run text,p_epoch integer) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT EXISTS(SELECT 1 FROM public.fw_privacy_objects p JOIN public.fw_runs r
    ON r.workspace=p.workspace WHERE p.object_kind='run_artifact'
      AND p.object_key=p_run||':'||p_epoch::text AND r.id=p_run
      AND p.state IN ('archived','held','recovery_required'))
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_checkpoint_blocked_v1(text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fw_privacy_checkpoint_blocked_v1(text,integer) TO fieldwork_real_worker_definer;

CREATE FUNCTION public.fw_privacy_run_delete_fence_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $fn$
DECLARE deletion_cancel boolean;
BEGIN
  IF NEW.config->>'scope' IN ('real-training/v1','real-inference/v1','real-image-inference/v1','qualified-release-image-inference/v1')
     AND NEW.state IN ('queued','leased','running','cancel_requested')
     AND public.fw_privacy_workspace_deleted_v1(NEW.workspace) THEN
    deletion_cancel := TG_OP='UPDATE'
      AND current_setting('fieldwork.privacy_delete_cancel',true)=NEW.workspace||':'||NEW.id
      AND ((OLD.state IN ('queued','interrupted') AND NEW.state='cancelled')
        OR (OLD.state IN ('leased','running') AND NEW.state='cancel_requested'))
      AND NEW.fence=OLD.fence+1 AND NEW.revision=OLD.revision+1
      AND NEW.cancel_generation=coalesce(OLD.cancel_generation,0)+1;
    IF TG_OP<>'UPDATE' OR NOT deletion_cancel THEN
      RAISE EXCEPTION 'WORKSPACE_PRIVACY_TOMBSTONED' USING ERRCODE='P0001';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_run_delete_fence_v1() FROM PUBLIC;
CREATE TRIGGER trg_privacy_run_delete_fence_v1 BEFORE INSERT OR UPDATE OF state,config ON public.fw_runs
  FOR EACH ROW EXECUTE FUNCTION public.fw_privacy_run_delete_fence_v1();

CREATE FUNCTION public.fw_privacy_revoke_workspace_workers_v1() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,fw_worker_cap_v1 AS $fn$
BEGIN
  -- The scoped model stores a principal's workspace set in one array row.
  -- Remove only the deleted workspace and advance its version fence so other
  -- workspaces assigned to the same worker retain their authority.
  UPDATE fw_worker_cap_v1.scope
    SET workspaces=array_remove(workspaces,NEW.workspace),version=version+1
    WHERE NEW.workspace=ANY(workspaces);
  DELETE FROM public.fw_intake_worker_scopes WHERE workspace=NEW.workspace;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_revoke_workspace_workers_v1() FROM PUBLIC;
CREATE TRIGGER trg_privacy_revoke_workspace_workers_v1
  AFTER INSERT ON public.fw_privacy_workspace_tombstones
  FOR EACH ROW EXECUTE FUNCTION public.fw_privacy_revoke_workspace_workers_v1();

-- Internal cancellation remains possible after workspace RLS denial, but only
-- for an already tombstoned workspace. No table grants are widened.
CREATE FUNCTION public.fw_privacy_cancel_deleted_run_v1(p_workspace text,p_run text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE r public.fw_runs; next_state text; next_generation integer;
BEGIN
  IF session_user='fieldwork_api' AND
     current_setting('fieldwork.workspace',true) IS DISTINCT FROM p_workspace THEN
    RAISE EXCEPTION 'WORKSPACE_SCOPE_REQUIRED' USING ERRCODE='42501';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM public.fw_privacy_workspace_tombstones t
      WHERE t.workspace=p_workspace) THEN
    RAISE EXCEPTION 'WORKSPACE_NOT_TOMBSTONED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO r FROM public.fw_runs WHERE workspace=p_workspace AND id=p_run FOR UPDATE;
  IF NOT FOUND THEN RETURN 'not_found'; END IF;
  IF r.state IN ('succeeded','failed','cancelled','cancel_requested') THEN RETURN r.state; END IF;
  IF r.state NOT IN ('queued','interrupted','leased','running') THEN
    RAISE EXCEPTION 'WORKSPACE_CANCEL_STATE_INVALID' USING ERRCODE='P0001';
  END IF;
  next_state := CASE WHEN r.state IN ('leased','running') THEN 'cancel_requested' ELSE 'cancelled' END;
  next_generation := coalesce(r.cancel_generation,0)+1;
  PERFORM set_config('fieldwork.privacy_delete_cancel',p_workspace||':'||p_run,true);
  UPDATE public.fw_runs SET state=next_state,fence=fence+1,revision=revision+1,
      cancel_generation=next_generation
    WHERE workspace=p_workspace AND id=p_run RETURNING * INTO r;
  INSERT INTO public.fw_events(workspace,run,kind,payload,object_revision)
    VALUES(p_workspace,p_run,next_state,
      jsonb_build_object('state',next_state,'actor','workspace-deletion',
        'reason','workspace_tombstoned','cancel_generation',next_generation),r.revision);
  RETURN next_state;
END
$fn$;
REVOKE ALL ON FUNCTION public.fw_privacy_cancel_deleted_run_v1(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fw_privacy_cancel_deleted_run_v1(text,text) TO fieldwork_api;

CREATE POLICY fw_real_worker_samples_privacy_delete ON public.fw_samples
  AS RESTRICTIVE FOR SELECT TO fieldwork_real_worker_definer
  USING (NOT public.fw_privacy_workspace_deleted_v1(workspace));
CREATE POLICY fw_sample_media_privacy_expiry ON public.fw_samples
  AS RESTRICTIVE FOR SELECT TO fieldwork_api,fieldwork_real_worker_definer
  USING (NOT public.fw_privacy_sample_blocked_v1(workspace,sample_id::text));
CREATE POLICY fw_checkpoint_privacy_expiry ON public.fw_checkpoints
  AS RESTRICTIVE FOR SELECT TO fieldwork_real_worker_definer
  USING (NOT public.fw_privacy_checkpoint_blocked_v1(run,epoch));
CREATE POLICY fw_real_image_inputs_privacy_delete ON public.fw_real_image_inputs
  AS RESTRICTIVE FOR SELECT TO fieldwork_real_worker_definer
  USING (NOT public.fw_privacy_workspace_deleted_v1(workspace));

CREATE TABLE public.fw_privacy_scanner_status (
  id boolean PRIMARY KEY DEFAULT true CHECK(id),
  last_started_utc timestamptz,
  last_success_utc timestamptz,
  last_lag_seconds integer CHECK(last_lag_seconds IS NULL OR last_lag_seconds>=0),
  last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{1,64}$'),
  scheduler_heartbeat_utc timestamptz,
  scheduler_instance text CHECK(scheduler_instance IS NULL OR scheduler_instance ~ '^[0-9a-f-]{36}$'),
  passes bigint NOT NULL DEFAULT 0 CHECK(passes>=0),
  archived_objects bigint NOT NULL DEFAULT 0 CHECK(archived_objects>=0),
  updated_utc timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO public.fw_privacy_scanner_status(id) VALUES(true);
ALTER TABLE public.fw_privacy_scanner_status ENABLE ROW LEVEL SECURITY;
CREATE POLICY fw_privacy_status_api_read ON public.fw_privacy_scanner_status FOR SELECT TO fieldwork_api USING(true);
REVOKE ALL ON public.fw_privacy_scanner_status FROM PUBLIC;
GRANT SELECT ON public.fw_privacy_scanner_status TO fieldwork_api;

-- The default for new workspace artifact-retention policy is 180 days.
ALTER TABLE public.fw_workspace_settings ALTER COLUMN retention_days SET DEFAULT 180;
WITH upgraded AS (
  UPDATE public.fw_workspace_settings s SET retention_days=180,revision=revision+1,
    updated_utc=clock_timestamp()
  WHERE s.retention_days<180 AND NOT EXISTS (SELECT 1 FROM public.fw_workspace_settings_events e
    WHERE e.workspace=s.workspace AND e.event_type='settings.updated'
      AND e.detail ? 'retention_days')
  RETURNING workspace,revision
)
INSERT INTO public.fw_workspace_settings_events(workspace,actor,event_type,revision,detail)
SELECT workspace,'privacy-lifecycle','settings.updated',revision,
  '{"retention_days":180,"reason":"default_policy_180d"}'::jsonb FROM upgraded;
CREATE POLICY fw_workspace_audit_privacy_expiry ON public.fw_workspace_settings_events
  AS RESTRICTIVE FOR SELECT TO fieldwork_api USING (at_utc>=clock_timestamp()-interval '90 days');
ALTER TABLE public.fw_workspace_settings_events DROP CONSTRAINT fw_workspace_settings_events_event_type_check;
ALTER TABLE public.fw_workspace_settings_events ADD CONSTRAINT fw_workspace_settings_events_event_type_check
  CHECK(event_type IN ('settings.updated','membership.role_changed','privacy.hold_changed','privacy.workspace_deletion_requested'));
GRANT INSERT ON public.fw_workspace_settings_events TO fieldwork_api;
GRANT USAGE,SELECT ON SEQUENCE public.fw_workspace_settings_events_seq_seq TO fieldwork_api;

-- Existing fresh image rows remain in the database for audit/lineage, while the
-- real worker loses access after the 24-hour input window. The archive copy is
-- private and does not re-enable inference.
CREATE POLICY fw_real_image_inputs_privacy_expiry ON public.fw_real_image_inputs
  AS RESTRICTIVE FOR SELECT TO fieldwork_real_worker_definer
  USING (created_utc >= clock_timestamp()-interval '24 hours'
    AND NOT public.fw_privacy_input_blocked_v1(workspace,input_id::text)
    AND NOT public.fw_privacy_workspace_deleted_v1(workspace));

-- Intake uploads are private staging only. A queue item older than 24 hours
-- cannot be newly claimed or finalized by the intake worker; its bytes and
-- append-only receipt remain in the private archive/journal.
CREATE POLICY fw_intake_queue_privacy_expiry ON public.fw_real_intake_queue
  AS RESTRICTIVE FOR SELECT TO fieldwork_intake_worker
  USING (created_utc >= clock_timestamp()-interval '24 hours'
    AND NOT public.fw_privacy_workspace_deleted_v1(workspace));

COMMIT;
