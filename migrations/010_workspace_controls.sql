-- Owner-managed workspace settings and append-only authorization audit.
-- This migration is intentionally retained/unapplied until the coordinator
-- backs up and rehearses it. It creates no default settings implicitly.
CREATE TABLE fw_workspace_settings (
  workspace text PRIMARY KEY,
  revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
  retention_days integer NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 30 AND 3650),
  max_concurrent_runs integer NOT NULL DEFAULT 2 CHECK (max_concurrent_runs BETWEEN 1 AND 16),
  max_epochs integer NOT NULL DEFAULT 100 CHECK (max_epochs BETWEEN 1 AND 100),
  updated_utc timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE fw_workspace_settings_events (
  workspace text NOT NULL,
  seq bigint GENERATED ALWAYS AS IDENTITY,
  actor text NOT NULL,
  event_type text NOT NULL CHECK (event_type IN ('settings.updated','membership.role_changed')),
  revision integer,
  detail jsonb NOT NULL,
  at_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace, seq)
);

ALTER TABLE fw_workspace_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE fw_workspace_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY fw_workspace_settings_tenant ON fw_workspace_settings
  USING (workspace=current_setting('fieldwork.workspace',true))
  WITH CHECK (workspace=current_setting('fieldwork.workspace',true));
ALTER TABLE fw_workspace_settings_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE fw_workspace_settings_events FORCE ROW LEVEL SECURITY;
CREATE POLICY fw_workspace_settings_events_tenant ON fw_workspace_settings_events
  USING (workspace=current_setting('fieldwork.workspace',true))
  WITH CHECK (workspace=current_setting('fieldwork.workspace',true));

REVOKE ALL ON fw_workspace_settings,fw_workspace_settings_events FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON fw_workspace_settings TO fieldwork_api;
GRANT SELECT,INSERT ON fw_workspace_settings_events TO fieldwork_api;
GRANT USAGE,SELECT ON SEQUENCE fw_workspace_settings_events_seq_seq TO fieldwork_api;
GRANT SELECT ON fw_accounts TO fieldwork_api;
GRANT UPDATE (role) ON fw_accounts TO fieldwork_api;

-- Admission controls apply at insertion and inactive-to-active transitions. Store.submit uses
-- the same workspace advisory lock and checks idempotency before INSERT; this
-- function repeats that check so a racing idempotent replay is never rejected
-- merely because capacity filled after the first request.
CREATE FUNCTION fw_workspace_run_admission_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $fn$
DECLARE policy_row public.fw_workspace_settings; active_count integer; prior boolean;
        run_scope text; epoch_limit integer;
BEGIN
  run_scope := NEW.config->>'scope';
  IF run_scope IS NULL OR run_scope NOT IN ('real-training/v1','real-inference/v1','real-image-inference/v1') THEN
    RETURN NEW;
  END IF;
  IF TG_OP='UPDATE' THEN
    IF NEW.state NOT IN ('queued','leased','running','cancel_requested')
       OR OLD.state IN ('queued','leased','running','cancel_requested') THEN
      RETURN NEW;
    END IF;
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.workspace,0));
  IF TG_OP='INSERT' THEN
    SELECT EXISTS(SELECT 1 FROM public.fw_runs r
      WHERE r.workspace=NEW.workspace AND r.actor=NEW.actor AND r.idem=NEW.idem) INTO prior;
    IF prior THEN RETURN NEW; END IF;
  END IF;
  SELECT * INTO policy_row FROM public.fw_workspace_settings WHERE workspace=NEW.workspace;
  IF NOT FOUND THEN
    policy_row.max_concurrent_runs := 2;
    policy_row.max_epochs := 100;
  END IF;
  IF run_scope='real-training/v1' THEN
    epoch_limit := nullif(NEW.config->>'epochs','')::integer;
    IF epoch_limit IS NULL OR epoch_limit > policy_row.max_epochs THEN
      RAISE EXCEPTION 'WORKSPACE_EPOCH_LIMIT' USING ERRCODE='P0001';
    END IF;
  END IF;
  SELECT count(*) INTO active_count FROM public.fw_runs r
    WHERE r.workspace=NEW.workspace AND r.config->>'scope' IN
      ('real-training/v1','real-inference/v1','real-image-inference/v1')
      AND r.state IN ('queued','leased','running','cancel_requested');
  IF active_count >= policy_row.max_concurrent_runs THEN
    RAISE EXCEPTION 'WORKSPACE_RUN_LIMIT' USING ERRCODE='P0001';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION fw_workspace_run_admission_v1() FROM PUBLIC;
CREATE TRIGGER trg_workspace_run_admission_v1
  BEFORE INSERT OR UPDATE OF state ON fw_runs
  FOR EACH ROW EXECUTE FUNCTION fw_workspace_run_admission_v1();
