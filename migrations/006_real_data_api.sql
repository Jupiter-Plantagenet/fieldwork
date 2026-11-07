-- 006: real-data API queues and separately assigned holdout stewards.
-- Additive only. Migration is operator-applied after 003/004/005 prerequisites;
-- the API never installs or repairs this schema.
BEGIN;

-- Runtime code uses unqualified relations only with the product schema on its
-- search path. Neither the API nor the worker needs temporary relations.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
-- TEMP is database-level and inherited from PUBLIC by default. Remove that
-- shadowing path; this also means any unrelated caller needing temp tables
-- must receive a deliberate named grant instead of inheriting it implicitly.
DO $temp_acl$
BEGIN
  EXECUTE format('REVOKE TEMP ON DATABASE %I FROM PUBLIC',current_database());
  EXECUTE format('REVOKE TEMP ON DATABASE %I FROM fieldwork_api',current_database());
END
$temp_acl$;
DO $temp_assert$
BEGIN
  IF has_database_privilege('fieldwork_api',current_database(),'TEMP') THEN
    RAISE EXCEPTION 'FIELDWORK_API_TEMP_PRIVILEGE_REMAINS';
  END IF;
END
$temp_assert$;

-- Retained equivalent of fieldwork.intake.INTAKE_SCHEMA. These relations are
-- versioned here; application startup must not apply DDL from Python constants.
CREATE TABLE fw_intake_batches (
  workspace text NOT NULL, batch_id uuid NOT NULL, source_intake_id uuid,
  archive_name text NOT NULL,
  archive_sha256 text NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'), archive_bytes bigint NOT NULL CHECK (archive_bytes>0),
  rights_dataset_id text, policy text NOT NULL, decoder text, actor text NOT NULL,
  state text NOT NULL CHECK (state IN ('staging','complete','rejected','interrupted')), reason text,
  source_total integer, accepted integer, rejected integer, duplicate integer, noop integer, report_sha256 text,
  started_utc timestamptz NOT NULL DEFAULT clock_timestamp(), finished_utc timestamptz,
  PRIMARY KEY(workspace,batch_id),
  CHECK (state<>'complete' OR source_total=accepted+rejected+duplicate+noop)
);
CREATE TABLE fw_samples (
  workspace text NOT NULL, sample_id uuid NOT NULL, raw_sha256 text NOT NULL CHECK (raw_sha256 ~ '^[0-9a-f]{64}$'),
  raw_bytes bigint NOT NULL CHECK (raw_bytes>0), pixel_sha256 text NOT NULL CHECK (pixel_sha256 ~ '^[0-9a-f]{64}$'),
  width integer NOT NULL CHECK (width>0), height integer NOT NULL CHECK (height>0), format text NOT NULL, decoder text NOT NULL,
  media_path text NOT NULL, source_member text NOT NULL, source_label integer, rights_dataset_id text,
  first_batch uuid NOT NULL, created_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(workspace,sample_id), UNIQUE(workspace,raw_sha256)
);
CREATE INDEX fw_samples_pixel ON fw_samples(workspace,pixel_sha256);
CREATE TABLE fw_intake_members (
  workspace text NOT NULL, batch_id uuid NOT NULL, ordinal integer NOT NULL, member text NOT NULL,
  disposition text NOT NULL CHECK (disposition IN ('accepted','rejected','duplicate','noop')),
  reason text NOT NULL CHECK (length(reason)>0), raw_sha256 text, pixel_sha256 text, sample_id uuid, linked_sample_id uuid,
  claimed_label integer,
  PRIMARY KEY(workspace,batch_id,ordinal),
  FOREIGN KEY(workspace,batch_id) REFERENCES fw_intake_batches(workspace,batch_id),
  CHECK ((disposition='accepted')=(sample_id IS NOT NULL)),
  CHECK (disposition<>'duplicate' OR linked_sample_id IS NOT NULL)
);

-- An API request may queue a bounded, private archive for the isolated intake
-- worker. It never grants the API principal writes to the image/rights catalog.
CREATE TABLE fw_real_intake_queue (
  workspace text NOT NULL,
  intake_id uuid NOT NULL,
  actor text NOT NULL,
  rights_dataset_id text NOT NULL,
  archive_path text NOT NULL,
  archive_sha256 text NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'),
  archive_bytes bigint NOT NULL CHECK (archive_bytes > 0),
  state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','complete','rejected','interrupted')),
  lease_fence bigint NOT NULL DEFAULT 0 CHECK (lease_fence>=0),
  lease_owner text,
  lease_until timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts>=0),
  last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{1,64}$'),
  result_worker_id text,
  result_fence bigint,
  result_batch_id uuid,
  result_sha256 text CHECK (result_sha256 IS NULL OR result_sha256 ~ '^[0-9a-f]{64}$'),
  created_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  finished_utc timestamptz,
  PRIMARY KEY (workspace,intake_id),
  UNIQUE (workspace,archive_sha256),
  FOREIGN KEY (workspace,result_batch_id) REFERENCES fw_intake_batches(workspace,batch_id),
  CHECK ((state='running')=(lease_owner IS NOT NULL AND lease_until IS NOT NULL)),
  CHECK ((result_batch_id IS NULL)=(result_sha256 IS NULL)),
  CHECK ((result_worker_id IS NULL)=(result_fence IS NULL))
);
ALTER TABLE fw_intake_batches ADD CONSTRAINT fw_intake_batches_queue_fk
  FOREIGN KEY (workspace,source_intake_id) REFERENCES fw_real_intake_queue(workspace,intake_id);

-- The NOLOGIN capability is enabled only by the reviewed operator provisioner.
-- It receives no database-wide authority and no role memberships.
DO $role$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fieldwork_intake_worker') THEN
    RAISE EXCEPTION 'INTAKE_WORKER_ROLE_ALREADY_EXISTS';
  END IF;
  EXECUTE 'CREATE ROLE fieldwork_intake_worker NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT';
END
$role$;

CREATE TABLE fw_intake_worker_scopes (
  worker_login text NOT NULL,
  workspace text NOT NULL,
  assigned_by text NOT NULL,
  assigned_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (worker_login,workspace)
);
REVOKE ALL ON fw_intake_worker_scopes FROM PUBLIC;

CREATE SCHEMA fw_intake_cap_v1;
REVOKE ALL ON SCHEMA fw_intake_cap_v1 FROM PUBLIC;
GRANT USAGE ON SCHEMA fw_intake_cap_v1 TO fieldwork_intake_worker;
CREATE FUNCTION fw_intake_cap_v1.stamp_queue_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE intake text;
BEGIN
  IF NEW.state<>'staging' OR NEW.finished_utc IS NOT NULL OR NEW.report_sha256 IS NOT NULL THEN
    RAISE EXCEPTION 'FW_INTAKE_BATCH_INSERT_STAGING_REQUIRED' USING ERRCODE='42501';
  END IF;
  intake := current_setting('fieldwork.intake_id',true);
  IF session_user='fieldwork_intake_worker' AND (intake IS NULL OR intake='') THEN
    RAISE EXCEPTION 'FW_INTAKE_SOURCE_IDENTITY_REQUIRED' USING ERRCODE='42501';
  END IF;
  IF intake IS NOT NULL AND intake<>'' THEN
    IF NEW.source_intake_id IS NOT NULL AND NEW.source_intake_id::text<>intake THEN
      RAISE EXCEPTION 'FW_INTAKE_SOURCE_IDENTITY' USING ERRCODE='42501';
    END IF;
    NEW.source_intake_id := intake::uuid;
  END IF;
  RETURN NEW;
END
$fn$;
CREATE TRIGGER fw_intake_batch_queue_identity BEFORE INSERT ON fw_intake_batches
  FOR EACH ROW EXECUTE FUNCTION fw_intake_cap_v1.stamp_queue_identity();
CREATE FUNCTION fw_intake_cap_v1.batch_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
  IF NEW.workspace<>OLD.workspace OR NEW.batch_id<>OLD.batch_id OR NEW.source_intake_id IS DISTINCT FROM OLD.source_intake_id
     OR NEW.archive_name<>OLD.archive_name OR NEW.archive_sha256<>OLD.archive_sha256 OR NEW.archive_bytes<>OLD.archive_bytes
     OR NEW.rights_dataset_id IS DISTINCT FROM OLD.rights_dataset_id OR NEW.policy<>OLD.policy OR NEW.actor<>OLD.actor
     OR NEW.started_utc<>OLD.started_utc THEN
    RAISE EXCEPTION 'FW_INTAKE_BATCH_IDENTITY' USING ERRCODE='42501';
  END IF;
  IF OLD.state<>'staging' OR NEW.state NOT IN ('complete','rejected','interrupted') THEN
    RAISE EXCEPTION 'FW_INTAKE_BATCH_TRANSITION' USING ERRCODE='42501';
  END IF;
  IF NEW.state IN ('complete','rejected') AND
     ((NEW.decoder IS NULL AND coalesce(NEW.source_total,0)>0 AND NEW.reason IS NULL)
      OR NEW.source_total IS NULL OR NEW.accepted IS NULL OR NEW.rejected IS NULL
      OR NEW.duplicate IS NULL OR NEW.noop IS NULL OR NEW.report_sha256 IS NULL
      OR NEW.report_sha256 !~ '^[0-9a-f]{64}$'
      OR NEW.finished_utc IS NULL) THEN
    RAISE EXCEPTION 'FW_INTAKE_BATCH_RESULT' USING ERRCODE='23514';
  END IF;
  IF NEW.state='interrupted' AND (NEW.finished_utc IS NULL OR NEW.report_sha256 IS NOT NULL) THEN
    RAISE EXCEPTION 'FW_INTAKE_BATCH_INTERRUPTED' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE TRIGGER fw_intake_batch_guard BEFORE UPDATE ON fw_intake_batches
  FOR EACH ROW EXECUTE FUNCTION fw_intake_cap_v1.batch_guard();
REVOKE ALL ON FUNCTION fw_intake_cap_v1.batch_guard() FROM PUBLIC;
CREATE INDEX fw_intake_batches_source ON fw_intake_batches(workspace,source_intake_id,state,finished_utc);
CREATE UNIQUE INDEX fw_intake_one_terminal_batch ON fw_intake_batches(workspace,source_intake_id)
  WHERE source_intake_id IS NOT NULL AND state IN ('complete','rejected');
CREATE FUNCTION fw_intake_cap_v1.workspace_allowed(p_workspace text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT EXISTS (SELECT 1 FROM public.fw_intake_worker_scopes s
    WHERE s.worker_login=session_user AND s.workspace=p_workspace)
$fn$;
CREATE FUNCTION fw_intake_cap_v1.my_workspaces() RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT coalesce(array_agg(s.workspace ORDER BY s.workspace),ARRAY[]::text[])
  FROM public.fw_intake_worker_scopes s WHERE s.worker_login=session_user
$fn$;
CREATE FUNCTION fw_intake_cap_v1.actor_allowed(p_workspace text,p_actor text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT fw_intake_cap_v1.workspace_allowed(p_workspace) AND EXISTS (
    SELECT 1 FROM public.fw_accounts a WHERE a.workspace=p_workspace AND a.name=p_actor
      AND a.role IN ('owner','researcher'))
$fn$;
CREATE FUNCTION fw_intake_cap_v1.lock_actor(p_workspace text,p_actor text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE ok boolean;
BEGIN
  IF NOT fw_intake_cap_v1.workspace_allowed(p_workspace) THEN RETURN false; END IF;
  SELECT role IN ('owner','researcher') INTO ok FROM public.fw_accounts
    WHERE workspace=p_workspace AND name=p_actor FOR SHARE;
  RETURN coalesce(ok,false);
END
$fn$;
CREATE FUNCTION fw_intake_cap_v1.lock_rights(p_workspace text,p_dataset text,p_member text,
                                                p_sha256 text,p_bytes bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE ok boolean;
BEGIN
  IF NOT fw_intake_cap_v1.workspace_allowed(p_workspace) THEN RETURN false; END IF;
  SELECT state='authenticated' INTO ok FROM public.fw_rights_datasets
    WHERE workspace=p_workspace AND dataset_id=p_dataset FOR SHARE;
  IF NOT coalesce(ok,false) THEN RETURN false; END IF;
  SELECT rights_state='reviewed' AND asset_sha256=p_sha256 AND asset_bytes=p_bytes INTO ok
    FROM public.fw_rights_assets
    WHERE workspace=p_workspace AND dataset_id=p_dataset AND member_id=p_member FOR SHARE;
  IF NOT coalesce(ok,false) THEN RETURN false; END IF;
  PERFORM 1 FROM public.fw_rights_decisions
    WHERE workspace=p_workspace AND dataset_id=p_dataset AND member_id=p_member
      AND purpose='local_private_training' FOR SHARE;
  RETURN FOUND;
END
$fn$;
REVOKE ALL ON FUNCTION fw_intake_cap_v1.workspace_allowed(text),fw_intake_cap_v1.my_workspaces(),
  fw_intake_cap_v1.actor_allowed(text,text),fw_intake_cap_v1.lock_actor(text,text),
  fw_intake_cap_v1.lock_rights(text,text,text,text,bigint),
  fw_intake_cap_v1.stamp_queue_identity(),fw_intake_cap_v1.batch_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fw_intake_cap_v1.workspace_allowed(text),fw_intake_cap_v1.my_workspaces(),
  fw_intake_cap_v1.actor_allowed(text,text),fw_intake_cap_v1.lock_actor(text,text),
  fw_intake_cap_v1.lock_rights(text,text,text,text,bigint)
  TO fieldwork_intake_worker;

CREATE OR REPLACE FUNCTION fw_real_intake_queue_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.state<>'queued' OR NEW.lease_fence<>0 OR NEW.attempts<>0 OR NEW.lease_owner IS NOT NULL
       OR NEW.lease_until IS NOT NULL OR NEW.result_batch_id IS NOT NULL OR NEW.result_sha256 IS NOT NULL
       OR NEW.result_worker_id IS NOT NULL OR NEW.result_fence IS NOT NULL THEN
      RAISE EXCEPTION 'FW_INTAKE_QUEUE_INSERT_GUARD' USING ERRCODE='42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.fw_accounts a WHERE a.workspace=NEW.workspace
                   AND a.name=NEW.actor AND a.role IN ('owner','researcher')) THEN
      RAISE EXCEPTION 'FW_INTAKE_QUEUE_ACTOR' USING ERRCODE='42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.workspace<>OLD.workspace OR NEW.intake_id<>OLD.intake_id OR NEW.actor<>OLD.actor
     OR NEW.rights_dataset_id<>OLD.rights_dataset_id OR NEW.archive_path<>OLD.archive_path
     OR NEW.archive_sha256<>OLD.archive_sha256 OR NEW.archive_bytes<>OLD.archive_bytes
     OR NEW.created_utc<>OLD.created_utc THEN
    RAISE EXCEPTION 'FW_INTAKE_QUEUE_IDENTITY' USING ERRCODE='42501';
  END IF;
  IF NEW.lease_fence<OLD.lease_fence OR NEW.attempts<OLD.attempts THEN
    RAISE EXCEPTION 'FW_INTAKE_QUEUE_FENCE_ROLLBACK' USING ERRCODE='42501';
  END IF;
  IF OLD.state IN ('complete','rejected','interrupted') THEN
    RAISE EXCEPTION 'FW_INTAKE_QUEUE_TERMINAL' USING ERRCODE='42501';
  END IF;
  IF NEW.state='running' THEN
    IF NEW.lease_owner IS NULL OR NEW.lease_until IS NULL OR NEW.lease_until<=clock_timestamp()
       OR (NEW.lease_fence=OLD.lease_fence AND (OLD.state<>'running' OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
            OR NEW.attempts<>OLD.attempts OR NEW.lease_until<=OLD.lease_until))
       OR (NEW.lease_fence>OLD.lease_fence AND
           (NEW.attempts<>OLD.attempts+1 OR NEW.lease_fence<>OLD.lease_fence+1
            OR (OLD.state='running' AND OLD.lease_until>clock_timestamp()))) THEN
      RAISE EXCEPTION 'FW_INTAKE_QUEUE_CLAIM_GUARD' USING ERRCODE='42501';
    END IF;
  ELSIF NEW.state='queued' THEN
    IF OLD.state<>'running' OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
       OR NEW.lease_fence<>OLD.lease_fence OR NEW.attempts<>OLD.attempts THEN
      RAISE EXCEPTION 'FW_INTAKE_QUEUE_REQUEUE_GUARD' USING ERRCODE='42501';
    END IF;
  ELSE
    IF OLD.state<>'running' OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
       OR OLD.lease_until IS NULL OR OLD.lease_until<=clock_timestamp()
       OR NEW.lease_fence<>OLD.lease_fence OR NEW.attempts<>OLD.attempts
       OR NEW.result_worker_id IS DISTINCT FROM OLD.lease_owner OR NEW.result_fence IS DISTINCT FROM OLD.lease_fence
       OR (NEW.result_batch_id IS NULL AND NEW.last_error_code IS NULL) THEN
      RAISE EXCEPTION 'FW_INTAKE_QUEUE_COMPLETE_GUARD' USING ERRCODE='42501';
    END IF;
    IF NEW.result_batch_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM public.fw_intake_batches b
      WHERE b.workspace=NEW.workspace AND b.batch_id=NEW.result_batch_id
        AND b.source_intake_id=NEW.intake_id
        AND b.archive_sha256=NEW.archive_sha256 AND b.archive_bytes=NEW.archive_bytes
        AND b.actor=NEW.actor AND b.rights_dataset_id=NEW.rights_dataset_id
        AND b.report_sha256=NEW.result_sha256
        AND ((NEW.state='complete' AND b.state='complete') OR (NEW.state='rejected' AND b.state='rejected'))
    ) THEN
      RAISE EXCEPTION 'FW_INTAKE_QUEUE_RESULT_BINDING' USING ERRCODE='42501';
    END IF;
  END IF;
  RETURN NEW;
END
$guard$;
CREATE TRIGGER fw_real_intake_queue_guard BEFORE INSERT OR UPDATE ON fw_real_intake_queue
  FOR EACH ROW EXECUTE FUNCTION fw_real_intake_queue_guard();
REVOKE ALL ON FUNCTION public.fw_real_intake_queue_guard() FROM PUBLIC;

-- A steward is an explicit, operator-managed assignment. Account role `owner`
-- never implies holdout authority. reviewer/key identifiers bind the assignment
-- to the external public-key registry record without storing any secret key.
CREATE TABLE fw_holdout_stewards (
  workspace text NOT NULL,
  actor text NOT NULL,
  reviewer_id text NOT NULL CHECK (reviewer_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  key_id text NOT NULL CHECK (key_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  assigned_by text NOT NULL,
  assigned_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace,actor)
);

CREATE TABLE fw_holdout_plans (
  workspace text NOT NULL,
  plan_id uuid NOT NULL,
  version_id text NOT NULL,
  version_digest text NOT NULL CHECK (version_digest ~ '^[0-9a-f]{64}$'),
  population_digest text NOT NULL CHECK (population_digest ~ '^[0-9a-f]{64}$'),
  population_count integer NOT NULL CHECK (population_count > 0),
  candidate_model_digest text NOT NULL CHECK (candidate_model_digest ~ '^[0-9a-f]{64}$'),
  candidate_checkpoint_digest text NOT NULL CHECK (candidate_checkpoint_digest ~ '^[0-9a-f]{64}$'),
  evaluator text NOT NULL,
  usefulness_spec_sha256 text NOT NULL CHECK (usefulness_spec_sha256 ~ '^[0-9a-f]{64}$'),
  steward text NOT NULL,
  state text NOT NULL CHECK (state IN ('authorized','consumed','invalidated')),
  authorized_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  consumed_utc timestamptz,
  exposures integer NOT NULL DEFAULT 0 CHECK (exposures >= 0),
  invalidated_reason text,
  result_sha256 text CHECK (result_sha256 IS NULL OR result_sha256 ~ '^[0-9a-f]{64}$'),
  result jsonb,
  PRIMARY KEY (workspace,plan_id)
);
CREATE UNIQUE INDEX fw_holdout_one_live_plan ON fw_holdout_plans(workspace,version_id) WHERE state <> 'invalidated';

CREATE TABLE fw_holdout_exposures (
  workspace text NOT NULL,
  plan_id uuid NOT NULL,
  seq integer NOT NULL CHECK (seq > 0),
  actor text NOT NULL,
  model_digest text NOT NULL CHECK (model_digest ~ '^[0-9a-f]{64}$'),
  at_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace,plan_id,seq),
  FOREIGN KEY (workspace,plan_id) REFERENCES fw_holdout_plans(workspace,plan_id)
);

DO $rls$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['fw_intake_batches','fw_samples','fw_intake_members','fw_real_intake_queue','fw_holdout_stewards','fw_holdout_plans','fw_holdout_exposures'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY fw_real_data_tenant ON %I USING (workspace=current_setting(''fieldwork.workspace'',true)) WITH CHECK (workspace=current_setting(''fieldwork.workspace'',true))', t);
  END LOOP;
END
$rls$;

-- Restrictive workspace allow-list for the worker capability. This is in addition
-- to each table's transaction-local tenant policy and applies only to the worker.
DO $worker_rls$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['fw_intake_batches','fw_samples','fw_intake_members','fw_real_intake_queue',
                           'fw_rights_datasets','fw_rights_assets','fw_rights_decisions'] LOOP
    EXECUTE format('CREATE POLICY fw_intake_worker_scope ON %I AS RESTRICTIVE FOR ALL TO fieldwork_intake_worker USING (workspace=current_setting(''fieldwork.workspace'',true) AND fw_intake_cap_v1.workspace_allowed(workspace)) WITH CHECK (workspace=current_setting(''fieldwork.workspace'',true) AND fw_intake_cap_v1.workspace_allowed(workspace))', t);
  END LOOP;
END
$worker_rls$;


REVOKE ALL ON fw_real_intake_queue,fw_holdout_stewards,fw_holdout_plans,fw_holdout_exposures FROM PUBLIC;
GRANT SELECT,INSERT ON fw_real_intake_queue TO fieldwork_api;
GRANT SELECT ON fw_intake_batches,fw_samples,fw_intake_members TO fieldwork_api;
GRANT SELECT ON fw_rights_datasets,fw_rights_assets TO fieldwork_api;
GRANT SELECT,INSERT,UPDATE ON fw_rights_decisions TO fieldwork_api;
GRANT SELECT ON fw_holdout_stewards TO fieldwork_api;
GRANT SELECT,INSERT ON fw_holdout_plans,fw_holdout_exposures TO fieldwork_api;
GRANT USAGE ON SCHEMA public TO fieldwork_api;
GRANT USAGE ON SCHEMA public TO fieldwork_intake_worker;
GRANT SELECT,UPDATE ON fw_real_intake_queue TO fieldwork_intake_worker;
GRANT SELECT,INSERT ON fw_intake_batches TO fieldwork_intake_worker;
GRANT SELECT,INSERT ON fw_samples TO fieldwork_intake_worker;
GRANT INSERT ON fw_intake_members TO fieldwork_intake_worker;
GRANT SELECT ON fw_rights_datasets,fw_rights_assets,fw_rights_decisions TO fieldwork_intake_worker;
REVOKE ALL ON fw_real_intake_queue,fw_intake_batches,fw_samples,fw_intake_members,
  fw_rights_datasets,fw_rights_assets,fw_rights_decisions,fw_accounts FROM PUBLIC;
REVOKE UPDATE ON fw_real_intake_queue FROM fieldwork_intake_worker;
REVOKE UPDATE ON fw_intake_batches FROM fieldwork_intake_worker;
GRANT UPDATE (state,lease_fence,lease_owner,lease_until,attempts,last_error_code,result_worker_id,result_fence,
  result_batch_id,result_sha256,finished_utc) ON fw_real_intake_queue TO fieldwork_intake_worker;
REVOKE UPDATE ON fw_intake_batches FROM fieldwork_intake_worker;
GRANT UPDATE (state,reason,decoder,source_total,accepted,rejected,duplicate,noop,report_sha256,finished_utc)
  ON fw_intake_batches TO fieldwork_intake_worker;
ALTER ROLE fieldwork_intake_worker SET statement_timeout='3700000ms';
ALTER ROLE fieldwork_intake_worker SET idle_in_transaction_session_timeout='3700000ms';
COMMIT;
