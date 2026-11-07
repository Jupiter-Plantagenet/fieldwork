-- Explicit, bounded real-training worker capability. This migration is source-only;
-- it never provisions a login or applies itself from application startup.
-- Prerequisites: 003/004/005/006 and the retained fw_versions/fw_runs tables.
BEGIN;

DO $preflight$
BEGIN
  IF to_regclass('public.fw_runs') IS NULL OR to_regclass('public.fw_attempts') IS NULL
     OR to_regclass('public.fw_slot') IS NULL OR to_regclass('public.fw_control') IS NULL
     OR to_regclass('public.fw_versions') IS NULL OR to_regclass('fw_worker_cap_v1.scope') IS NULL THEN
    RAISE EXCEPTION 'FW_REAL_WORKER_PREREQUISITES_REQUIRED';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fieldwork_real_worker_definer') THEN
    RAISE EXCEPTION 'FW_REAL_WORKER_DEFINER_ALREADY_EXISTS';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='fw_real_worker_cap_v1') THEN
    RAISE EXCEPTION 'FW_REAL_WORKER_SCHEMA_ALREADY_EXISTS';
  END IF;
END
$preflight$;

-- Extend the existing execution-authority trigger's definer recognition to this
-- fixed NOLOGIN capability owner. This is additive: old migration bytes and the
-- synthetic worker function definitions remain unchanged.
CREATE OR REPLACE FUNCTION public.fw_runs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $guard$
DECLARE trusted boolean; definer boolean; cancel_move boolean; resume_move boolean;
BEGIN
  SELECT r.rolsuper OR r.oid=c.relowner INTO trusted
    FROM pg_catalog.pg_roles r, pg_catalog.pg_class c
    WHERE r.rolname=current_user AND c.oid=TG_RELID;
  IF coalesce(trusted,false) THEN RETURN NEW; END IF;
  SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname IN ('fw_worker_cap_v1','fw_lease_cap_v1','fw_real_worker_cap_v1')
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
END
$guard$;

CREATE ROLE fieldwork_real_worker_definer NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
CREATE SCHEMA fw_real_worker_cap_v1;
REVOKE ALL ON SCHEMA fw_real_worker_cap_v1 FROM PUBLIC;
GRANT USAGE ON SCHEMA fw_real_worker_cap_v1 TO fieldwork_real_worker_definer;
GRANT CREATE ON SCHEMA fw_real_worker_cap_v1 TO fieldwork_real_worker_definer;

-- Narrow privileges for the definer. Workspaces remain bounded by the registered
-- scoped-worker identity, and all worker entry points repeat the run/profile checks.
GRANT USAGE ON SCHEMA public,fw_worker_cap_v1 TO fieldwork_real_worker_definer;
GRANT SELECT ON fw_worker_cap_v1.scope,public.fw_runs,public.fw_accounts,public.fw_versions,
  public.fw_control,public.fw_attempts TO fieldwork_real_worker_definer;
GRANT SELECT ON public.fw_samples,public.fw_rights_datasets,public.fw_rights_assets,
  public.fw_rights_decisions TO fieldwork_real_worker_definer;
GRANT INSERT,SELECT ON public.fw_attempts TO fieldwork_real_worker_definer;
GRANT UPDATE (ended_at) ON public.fw_attempts TO fieldwork_real_worker_definer;
GRANT INSERT ON public.fw_events TO fieldwork_real_worker_definer;
GRANT UPDATE (state,fence,attempt,cancel_generation,lease,revision,result,artifact_status,artifact_result,
  artifact_attempts,artifact_owner_pid,artifact_owner_created)
  ON public.fw_runs TO fieldwork_real_worker_definer;
GRANT SELECT ON public.fw_slot TO fieldwork_real_worker_definer;
GRANT UPDATE (run,fence,owner_pid,owner_created,pid,child_created,launching)
  ON public.fw_slot TO fieldwork_real_worker_definer;
GRANT USAGE ON SEQUENCE public.fw_events_seq_seq TO fieldwork_real_worker_definer;
GRANT SELECT,INSERT,DELETE ON fw_worker_cap_v1.credentials TO fieldwork_real_worker_definer;
GRANT EXECUTE ON FUNCTION fw_worker_cap_v1.allowed(text),fw_worker_cap_v1.hash_token(text),
  fw_worker_cap_v1.deny(text,text,integer),
  fw_worker_cap_v1.artifact_lock(text,integer,integer,double precision,boolean)
  TO fieldwork_real_worker_definer;

-- RLS policies are scoped to this fixed NOLOGIN definer and the same registered
-- workspace allowlist used by the synthetic worker capability.
CREATE POLICY fw_real_worker_runs ON public.fw_runs TO fieldwork_real_worker_definer
  USING (fw_worker_cap_v1.allowed(workspace)) WITH CHECK (fw_worker_cap_v1.allowed(workspace));
CREATE POLICY fw_real_worker_versions ON public.fw_versions TO fieldwork_real_worker_definer
  USING (fw_worker_cap_v1.allowed(workspace)) WITH CHECK (fw_worker_cap_v1.allowed(workspace));
CREATE POLICY fw_real_worker_attempts ON public.fw_attempts TO fieldwork_real_worker_definer
  USING (EXISTS (SELECT 1 FROM public.fw_runs r WHERE r.id=run AND fw_worker_cap_v1.allowed(r.workspace)))
  WITH CHECK (EXISTS (SELECT 1 FROM public.fw_runs r WHERE r.id=run AND fw_worker_cap_v1.allowed(r.workspace)));
CREATE POLICY fw_real_worker_events ON public.fw_events TO fieldwork_real_worker_definer
  USING (fw_worker_cap_v1.allowed(workspace)) WITH CHECK (fw_worker_cap_v1.allowed(workspace));
CREATE POLICY fw_real_worker_samples ON public.fw_samples TO fieldwork_real_worker_definer
  USING (fw_worker_cap_v1.allowed(workspace)) WITH CHECK (fw_worker_cap_v1.allowed(workspace));
CREATE POLICY fw_real_worker_rights_datasets ON public.fw_rights_datasets TO fieldwork_real_worker_definer
  USING (fw_worker_cap_v1.allowed(workspace)) WITH CHECK (fw_worker_cap_v1.allowed(workspace));
CREATE POLICY fw_real_worker_rights_assets ON public.fw_rights_assets TO fieldwork_real_worker_definer
  USING (fw_worker_cap_v1.allowed(workspace)) WITH CHECK (fw_worker_cap_v1.allowed(workspace));
CREATE POLICY fw_real_worker_rights_decisions ON public.fw_rights_decisions TO fieldwork_real_worker_definer
  USING (fw_worker_cap_v1.allowed(workspace)) WITH CHECK (fw_worker_cap_v1.allowed(workspace));

CREATE FUNCTION fw_real_worker_cap_v1.profile_ok(p_config jsonb,p_workspace text,p_actor text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT (CASE WHEN coalesce(pg_catalog.jsonb_typeof(p_config),'')<>'object' THEN false ELSE
    p_config->>'profile_schema'='fieldwork.real-run-profile/v1'
     AND p_config->>'scope'='real-training/v1' AND p_config->>'operation'='train'
     AND p_config->>'workspace'=p_workspace AND p_config->>'actor'=p_actor
     AND p_config->>'recipe'='compact-cnn/real-v1'
     AND p_config->>'preprocess'='short-edge144-rgb-v1'
     AND p_config->>'dataset_digest'=p_config->>'version_digest'
     AND (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_config))=22
     AND p_config ?& ARRAY['version_id','version_digest','dataset_id','recipe_digest','preprocess_digest',
                            'version_revision','epochs','batch_size','learning_rate','weight_decay','seed','idempotency_key','decoder_image_id','model_image_id']
     AND (p_config-ARRAY['profile_schema','scope','operation','workspace','actor','version_id','version_revision',
          'version_digest','dataset_id','dataset_digest','recipe','recipe_digest','preprocess','preprocess_digest',
          'decoder_image_id','model_image_id','epochs','batch_size','learning_rate','weight_decay','seed','idempotency_key'])='{}'::jsonb
     AND p_config->>'version_digest' ~ '^[0-9a-f]{64}$'
     AND p_config->>'recipe_digest'='22ad675cf61ef7bb3b315563652addf47fa7669667488777a15399c25f9a24fa'
     AND p_config->>'preprocess_digest'='e5b19df9fa39a01dd178e78d5efbd12a899983fad22ed3c7ff8d52643bc5ba44'
     AND p_config->>'decoder_image_id' ~ '^sha256:[0-9a-f]{64}$'
     AND p_config->>'model_image_id' ~ '^sha256:[0-9a-f]{64}$'
     AND p_config->>'version_id' ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     AND p_config->>'dataset_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     AND p_config->>'version_revision' ~ '^[1-9][0-9]*$'
     AND p_config->>'epochs' ~ '^(?:[1-9]|[1-9][0-9]|100)$'
     AND p_config->>'batch_size' ~ '^([1-9]|[12][0-9]|3[0-2])$'
     AND CASE WHEN p_config->>'learning_rate' ~ '^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,8})?$'
              THEN (p_config->>'learning_rate')::numeric BETWEEN 0.00001 AND 0.1 ELSE false END
     AND CASE WHEN p_config->>'weight_decay' ~ '^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,8})?$'
              THEN (p_config->>'weight_decay')::numeric BETWEEN 0 AND 0.1 ELSE false END
     AND p_config->>'weight_decay'='0.0001'
     AND CASE WHEN p_config->>'seed' ~ '^(?:0|[1-9][0-9]{0,9})$'
              THEN (p_config->>'seed')::numeric BETWEEN 0 AND 4294967295 ELSE false END
     AND EXISTS (SELECT 1 FROM public.fw_accounts a WHERE a.workspace=p_workspace
                  AND a.name=p_actor AND a.role IN ('owner','researcher'))
  END) IS TRUE
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.profile_ok(jsonb,text,text) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.profile_ok(jsonb,text,text) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.inference_profile_ok(p_config jsonb,p_workspace text,p_actor text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT (CASE WHEN coalesce(pg_catalog.jsonb_typeof(p_config),'')<>'object' THEN false ELSE
    p_config->>'profile_schema'='fieldwork.real-run-profile/v1'
     AND p_config->>'scope'='real-inference/v1' AND p_config->>'operation'='infer'
     AND p_config->>'workspace'=p_workspace AND p_config->>'actor'=p_actor
     AND p_config->>'preprocess'='short-edge144-rgb-v1'
     AND (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_config))=16
     AND (p_config-ARRAY['profile_schema','scope','operation','workspace','actor','run_id','version_id',
          'version_digest','sample_id','sample_split','bundle_digest','preprocess','preprocess_digest','decoder_image_id','model_image_id','idempotency_key'])='{}'::jsonb
     AND p_config ?& ARRAY['run_id','version_id','version_digest','sample_id','sample_split','bundle_digest',
                           'preprocess_digest','decoder_image_id','model_image_id','idempotency_key']
     AND p_config->>'version_id' ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     AND p_config->>'run_id' ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     AND p_config->>'sample_id' ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     AND p_config->>'sample_split' IN ('train','validation')
     AND p_config->>'version_digest' ~ '^[0-9a-f]{64}$'
     AND p_config->>'bundle_digest' ~ '^[0-9a-f]{64}$'
     AND p_config->>'preprocess_digest'='e5b19df9fa39a01dd178e78d5efbd12a899983fad22ed3c7ff8d52643bc5ba44'
     AND p_config->>'decoder_image_id' ~ '^sha256:[0-9a-f]{64}$'
     AND p_config->>'model_image_id' ~ '^sha256:[0-9a-f]{64}$'
     AND EXISTS (SELECT 1 FROM public.fw_accounts a WHERE a.workspace=p_workspace
                  AND a.name=p_actor AND a.role IN ('owner','researcher'))
     AND EXISTS (SELECT 1 FROM public.fw_runs t WHERE t.id=p_config->>'run_id'
       AND t.workspace=p_workspace AND t.state='succeeded' AND t.artifact_status='verified'
       AND t.config->>'scope'='real-training/v1' AND t.config->>'version_id'=p_config->>'version_id'
       AND t.config->>'version_digest'=p_config->>'version_digest'
       AND t.config->>'preprocess_digest'=p_config->>'preprocess_digest'
       AND t.config->>'decoder_image_id'=p_config->>'decoder_image_id'
       AND t.config->>'model_image_id'=p_config->>'model_image_id'
       AND t.artifact_result->>'bundle_digest'=p_config->>'bundle_digest'
       AND EXISTS (SELECT 1 FROM public.fw_versions v
         WHERE v.workspace=p_workspace AND v.id=p_config->>'version_id' AND v.state='frozen'
           AND v.revision::text=(t.config->>'version_revision')
           AND v.manifest->>'scope'='real-rights-cleared'
           AND v.manifest->>'digest'=p_config->>'version_digest'
           AND v.manifest->>'rights_dataset_id'=t.config->>'dataset_id'
           AND EXISTS (SELECT 1 FROM jsonb_path_query(v.manifest,
             '$.samples[*] ? (@.split == "train" || @.split == "validation")') AS nonprotected(item)
             WHERE item->>'id'=p_config->>'sample_id' AND item->>'split'=p_config->>'sample_split')))
  END) IS TRUE
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.inference_profile_ok(jsonb,text,text) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.inference_profile_ok(jsonb,text,text) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.next_real_run(p_skip text[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT pg_catalog.jsonb_build_object('id',r.id,'revision',r.revision)
  FROM public.fw_runs r
  WHERE fw_worker_cap_v1.allowed(r.workspace)
    AND r.state='queued'
    AND ((fw_real_worker_cap_v1.profile_ok(r.config,r.workspace,r.actor)
      AND EXISTS (SELECT 1 FROM public.fw_versions v
        WHERE v.workspace=r.workspace AND v.id=r.config->>'version_id' AND v.state='frozen'
          AND v.revision::text=(r.config->>'version_revision')
          AND v.manifest->>'scope'='real-rights-cleared'
          AND v.manifest->>'digest'=r.config->>'version_digest'
          AND v.manifest->>'rights_dataset_id'=r.config->>'dataset_id'))
      OR fw_real_worker_cap_v1.inference_profile_ok(r.config,r.workspace,r.actor))
    AND NOT ((r.id||'@'||r.revision)=ANY(coalesce(p_skip,'{}')))
  ORDER BY r.id LIMIT 1
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.next_real_run(text[]) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.next_real_run(text[]) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.claim_real(
  p_run text,p_worker text,p_owner_pid integer,p_owner_created double precision,p_key text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; sl record; ctl record; aid text; new_fence int; gen int; token text;
BEGIN
  SELECT * INTO ctl FROM public.fw_control WHERE id=1;
  IF NOT FOUND OR ctl.restore_generation IS NULL THEN
    PERFORM fw_worker_cap_v1.deny('RESTORE_GENERATION_SCHEMA_REQUIRED',NULL,NULL);
  END IF;
  SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
  SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
  IF NOT FOUND OR r.state<>'queued' OR sl.run IS NOT NULL THEN
    PERFORM fw_worker_cap_v1.deny('NOT_QUEUED_OR_SLOT_BUSY',r.state,NULL);
  END IF;
  IF NOT (fw_real_worker_cap_v1.profile_ok(r.config,r.workspace,r.actor)
      OR fw_real_worker_cap_v1.inference_profile_ok(r.config,r.workspace,r.actor)) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_PROFILE_REFUSED',r.state,NULL);
  END IF;
  IF r.config->>'scope'='real-training/v1' AND NOT EXISTS (SELECT 1 FROM public.fw_versions v WHERE v.workspace=r.workspace
      AND v.id=r.config->>'version_id' AND v.state='frozen'
      AND v.revision::text=(r.config->>'version_revision')
      AND v.manifest->>'scope'='real-rights-cleared'
      AND v.manifest->>'digest'=r.config->>'version_digest'
      AND v.manifest->>'rights_dataset_id'=r.config->>'dataset_id') THEN
    PERFORM fw_worker_cap_v1.deny('FROZEN_VERSION_BINDING_CHANGED',r.state,NULL);
  END IF;
  IF r.config->>'scope'='real-inference/v1'
      AND NOT fw_real_worker_cap_v1.inference_profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_BINDING_CHANGED',r.state,NULL);
  END IF;
  IF r.cancel_generation IS NULL THEN PERFORM fw_worker_cap_v1.deny('CANCEL_GENERATION_UNVERIFIABLE',r.state,NULL); END IF;
  gen := r.cancel_generation;
  aid := pg_catalog.gen_random_uuid()::text;
  new_fence := GREATEST(r.fence,ctl.fence_floor)+1;
  INSERT INTO public.fw_attempts(id,run,fence,cancel_generation,restore_generation,worker_id)
    VALUES(aid,p_run,new_fence,gen,ctl.restore_generation,session_user||':'||coalesce(p_worker,'worker'));
  UPDATE public.fw_slot SET run=p_run,fence=new_fence,owner_pid=p_owner_pid,owner_created=p_owner_created,
    pid=NULL,child_created=NULL,launching=false WHERE id=1;
  UPDATE public.fw_runs SET state='leased',fence=new_fence,attempt=aid,cancel_generation=gen,
    lease=pg_catalog.clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=p_run RETURNING * INTO r;
  INSERT INTO public.fw_events(workspace,run,kind,payload,object_revision)
    VALUES(r.workspace,r.id,'claimed',pg_catalog.jsonb_build_object('state','leased','attempt',aid,'fence',new_fence,
      'cancel_generation',gen,'restore_generation',ctl.restore_generation,'worker',session_user,'scope',r.config->>'scope'),r.revision);
  token := pg_catalog.gen_random_uuid()::text||pg_catalog.gen_random_uuid()::text;
  INSERT INTO fw_worker_cap_v1.credentials(token_hash,principal,run,attempt,expires_at)
    VALUES(fw_worker_cap_v1.hash_token(token),session_user,p_run,aid,pg_catalog.clock_timestamp()+interval '300 seconds');
  RETURN pg_catalog.to_jsonb(r)||pg_catalog.jsonb_build_object('restore_generation',ctl.restore_generation,'credential',token);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.claim_real(text,text,integer,double precision,text) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.claim_real(text,text,integer,double precision,text) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.next_real_artifact(p_skip text[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT pg_catalog.jsonb_build_object('id',r.id,'revision',r.revision)
  FROM public.fw_runs r
  WHERE fw_worker_cap_v1.allowed(r.workspace) AND r.state='succeeded'
    AND r.artifact_status IN ('retry_pending','failed') AND r.artifact_attempts<3
    AND fw_real_worker_cap_v1.profile_ok(r.config,r.workspace,r.actor)
    AND EXISTS (SELECT 1 FROM public.fw_versions v
      WHERE v.workspace=r.workspace AND v.id=r.config->>'version_id' AND v.state='frozen'
        AND v.revision::text=(r.config->>'version_revision')
        AND v.manifest->>'scope'='real-rights-cleared'
        AND v.manifest->>'digest'=r.config->>'version_digest'
        AND v.manifest->>'rights_dataset_id'=r.config->>'dataset_id')
    AND NOT ((r.id||'@'||r.revision)=ANY(coalesce(p_skip,'{}')))
  ORDER BY r.id LIMIT 1
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.next_real_artifact(text[]) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.next_real_artifact(text[]) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.claim_real_artifacts(p_run text,p_owner_pid integer,p_owner_created double precision)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE sl record; r public.fw_runs; new_fence integer;
BEGIN
  SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
  SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
  IF NOT FOUND OR r.state<>'succeeded' OR r.artifact_status NOT IN ('retry_pending','failed')
      OR r.artifact_attempts>=3 OR sl.run IS NOT NULL THEN
    PERFORM fw_worker_cap_v1.deny('ARTIFACT_NOT_RETRYABLE_OR_SLOT_BUSY',r.state,NULL);
  END IF;
  IF NOT fw_real_worker_cap_v1.profile_ok(r.config,r.workspace,r.actor)
      OR NOT EXISTS (SELECT 1 FROM public.fw_versions v WHERE v.workspace=r.workspace
        AND v.id=r.config->>'version_id' AND v.state='frozen'
        AND v.revision::text=(r.config->>'version_revision')
        AND v.manifest->>'scope'='real-rights-cleared'
        AND v.manifest->>'digest'=r.config->>'version_digest'
        AND v.manifest->>'rights_dataset_id'=r.config->>'dataset_id') THEN
    PERFORM fw_worker_cap_v1.deny('REAL_ARTIFACT_BINDING_CHANGED',r.state,NULL);
  END IF;
  new_fence := r.fence+1;
  UPDATE public.fw_slot SET run=p_run,fence=new_fence,owner_pid=p_owner_pid,owner_created=p_owner_created,
    pid=NULL,child_created=NULL,launching=false WHERE id=1;
  UPDATE public.fw_runs SET fence=new_fence,artifact_status='pending',
    artifact_result='{"code":"ARTIFACT_RETRY_PENDING"}'::jsonb,artifact_attempts=artifact_attempts+1,
    artifact_owner_pid=p_owner_pid,artifact_owner_created=p_owner_created,
    lease=pg_catalog.clock_timestamp()+interval '45 seconds',revision=revision+1
    WHERE id=p_run RETURNING * INTO r;
  INSERT INTO public.fw_events(workspace,run,kind,payload,object_revision)
    VALUES(r.workspace,r.id,'artifact_pending',pg_catalog.jsonb_build_object('code','ARTIFACT_RETRY_PENDING',
      'fence',new_fence,'scope','real-training/v1'),r.revision);
  RETURN pg_catalog.to_jsonb(r);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.claim_real_artifacts(text,integer,double precision) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.claim_real_artifacts(text,integer,double precision) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.real_inputs(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; v public.fw_versions; samples jsonb; expected_count integer; returned_count integer;
BEGIN
  SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace);
  IF NOT FOUND OR r.state<>'running' OR r.attempt IS DISTINCT FROM p_attempt OR r.fence<>p_fence
      OR r.cancel_generation IS DISTINCT FROM p_generation OR r.lease<=pg_catalog.clock_timestamp() THEN
    PERFORM fw_worker_cap_v1.deny('FENCED_OR_EXPIRED_OR_CANCELLED',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM fw_worker_cap_v1.credentials c
      WHERE c.token_hash=fw_worker_cap_v1.hash_token(p_token) AND c.principal=session_user
        AND c.run=p_run AND c.attempt=p_attempt AND c.expires_at>pg_catalog.clock_timestamp()) THEN
    PERFORM fw_worker_cap_v1.deny('CREDENTIAL_EXPIRED_OR_INVALID',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.fw_control ctl WHERE ctl.id=1 AND ctl.restore_generation=p_restore)
     OR NOT EXISTS (SELECT 1 FROM public.fw_attempts a WHERE a.id=p_attempt AND a.restore_generation=p_restore) THEN
    PERFORM fw_worker_cap_v1.deny('RESTORE_GENERATION_FENCED',r.state,NULL);
  END IF;
  IF NOT fw_real_worker_cap_v1.profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_PROFILE_REFUSED',r.state,NULL);
  END IF;
  SELECT * INTO v FROM public.fw_versions WHERE workspace=r.workspace AND id=r.config->>'version_id'
      AND state='frozen' AND revision::text=(r.config->>'version_revision')
      AND manifest->>'scope'='real-rights-cleared'
      AND manifest->>'digest'=r.config->>'version_digest'
      AND manifest->>'rights_dataset_id'=r.config->>'dataset_id';
  IF NOT FOUND OR v.manifest->>'digest'<>r.config->>'version_digest' THEN
    PERFORM fw_worker_cap_v1.deny('FROZEN_VERSION_BINDING_CHANGED',r.state,NULL);
  END IF;
  SELECT count(*)::integer INTO expected_count FROM jsonb_path_query(v.manifest,
      '$.samples[*] ? (@.split == "train" || @.split == "validation")');
  IF expected_count<1 OR expected_count>10000 THEN
    PERFORM fw_worker_cap_v1.deny('REAL_POPULATION_BOUNDS',r.state,NULL);
  END IF;
  WITH selected AS (
    SELECT item FROM jsonb_path_query(v.manifest,
      '$.samples[*] ? (@.split == "train" || @.split == "validation")') AS selected_items(item)
  ), joined AS (
    SELECT selected.item,fs.media_path,fs.raw_bytes,fs.format,ra.asset_sha256,ra.asset_bytes,
      ra.canonical_license,ra.license_text,ra.source_evidence,ra.attribution,rd.envelope
    FROM selected
    JOIN public.fw_samples fs ON fs.workspace=r.workspace AND fs.sample_id::text=selected.item->>'id'
      AND fs.raw_sha256=selected.item->>'sha256'
    JOIN public.fw_rights_datasets d ON d.workspace=r.workspace AND d.dataset_id=r.config->>'dataset_id'
      AND d.state='authenticated'
    JOIN public.fw_rights_assets ra ON ra.workspace=r.workspace AND ra.dataset_id=d.dataset_id
      AND ra.member_id=selected.item->>'source_member' AND ra.rights_state='reviewed'
      AND ra.asset_sha256=selected.item->>'sha256' AND ra.asset_bytes=fs.raw_bytes
    JOIN public.fw_rights_decisions rd ON rd.workspace=ra.workspace AND rd.dataset_id=ra.dataset_id
      AND rd.member_id=ra.member_id AND rd.purpose='local_private_training'
  )
  SELECT count(*)::integer,
    coalesce(jsonb_agg(jsonb_build_object('id',item->'id','split',item->'split','group',item->'group',
      'source_member',item->'source_member','sha256',item->'sha256','pixel_sha256',item->'pixel_sha256',
      'label',item->'label')||jsonb_build_object(
      'media_path',media_path,'raw_bytes',raw_bytes,'format',format,
      'rights_envelope_b64',pg_catalog.encode(envelope,'base64'),
      'rights_facts',jsonb_build_object('member_id',item->>'source_member','asset_sha256',asset_sha256,
        'asset_bytes',asset_bytes,'canonical_license_sha256',pg_catalog.encode(pg_catalog.sha256(canonical_license),'hex'),
        'license_text_sha256',pg_catalog.encode(pg_catalog.sha256(license_text),'hex'),
        'source_evidence_sha256',pg_catalog.encode(pg_catalog.sha256(source_evidence),'hex'),
        'attribution_sha256',pg_catalog.encode(pg_catalog.sha256(attribution),'hex'),
        'dataset_id',r.config->>'dataset_id','workspace_id',r.workspace,'purpose','local_private_training'))
      ORDER BY item->>'id'),'[]'::jsonb)
    INTO returned_count,samples FROM joined;
  IF returned_count<>expected_count THEN
    PERFORM fw_worker_cap_v1.deny('REAL_RIGHTS_BINDING_CHANGED',r.state,NULL);
  END IF;
  IF pg_catalog.jsonb_typeof(v.manifest->'classes')<>'array'
      OR pg_catalog.jsonb_array_length(v.manifest->'classes')<>5 THEN
    PERFORM fw_worker_cap_v1.deny('REAL_CLASS_BINDING_CHANGED',r.state,NULL);
  END IF;
  RETURN jsonb_build_object('version_id',v.id,'version_revision',v.revision,
    'version_digest',v.manifest->>'digest','dataset_id',r.config->>'dataset_id',
    'actor_authorized',true,'classes',v.manifest->'classes',
    'samples',samples);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.real_member_rights(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid,p_sample_id text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; v public.fw_versions; picked jsonb;
BEGIN
  SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace);
  IF NOT FOUND OR r.state<>'running' OR r.attempt IS DISTINCT FROM p_attempt OR r.fence<>p_fence
      OR r.cancel_generation IS DISTINCT FROM p_generation OR r.lease<=pg_catalog.clock_timestamp() THEN
    PERFORM fw_worker_cap_v1.deny('FENCED_OR_EXPIRED_OR_CANCELLED',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM fw_worker_cap_v1.credentials c
      WHERE c.token_hash=fw_worker_cap_v1.hash_token(p_token) AND c.principal=session_user
        AND c.run=p_run AND c.attempt=p_attempt AND c.expires_at>pg_catalog.clock_timestamp()) THEN
    PERFORM fw_worker_cap_v1.deny('CREDENTIAL_EXPIRED_OR_INVALID',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.fw_control ctl WHERE ctl.id=1 AND ctl.restore_generation=p_restore)
     OR NOT EXISTS (SELECT 1 FROM public.fw_attempts a WHERE a.id=p_attempt AND a.restore_generation=p_restore) THEN
    PERFORM fw_worker_cap_v1.deny('RESTORE_GENERATION_FENCED',r.state,NULL);
  END IF;
  IF NOT fw_real_worker_cap_v1.profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_PROFILE_REFUSED',r.state,NULL);
  END IF;
  SELECT * INTO v FROM public.fw_versions WHERE workspace=r.workspace AND id=r.config->>'version_id'
      AND state='frozen' AND revision::text=(r.config->>'version_revision')
      AND manifest->>'scope'='real-rights-cleared'
      AND manifest->>'digest'=r.config->>'version_digest'
      AND manifest->>'rights_dataset_id'=r.config->>'dataset_id';
  IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('FROZEN_VERSION_BINDING_CHANGED',r.state,NULL); END IF;
  WITH selected AS (
    SELECT item FROM jsonb_path_query(v.manifest,
      '$.samples[*] ? (@.split == "train" || @.split == "validation")') AS selected_items(item)
    WHERE item->>'id'=p_sample_id
  )
  SELECT jsonb_build_object('sample_id',selected.item->>'id','split',selected.item->>'split',
    'source_member',selected.item->>'source_member','sha256',selected.item->>'sha256',
    'asset_bytes',ra.asset_bytes,'rights_envelope_b64',pg_catalog.encode(rd.envelope,'base64'),
    'rights_facts',jsonb_build_object('member_id',selected.item->>'source_member','asset_sha256',ra.asset_sha256,
      'asset_bytes',ra.asset_bytes,'canonical_license_sha256',pg_catalog.encode(pg_catalog.sha256(ra.canonical_license),'hex'),
      'license_text_sha256',pg_catalog.encode(pg_catalog.sha256(ra.license_text),'hex'),
      'source_evidence_sha256',pg_catalog.encode(pg_catalog.sha256(ra.source_evidence),'hex'),
      'attribution_sha256',pg_catalog.encode(pg_catalog.sha256(ra.attribution),'hex'),
      'dataset_id',r.config->>'dataset_id','workspace_id',r.workspace,'purpose','local_private_training'))
  INTO picked
  FROM selected
  JOIN public.fw_samples fs ON fs.workspace=r.workspace AND fs.sample_id::text=selected.item->>'id'
    AND fs.raw_sha256=selected.item->>'sha256'
  JOIN public.fw_rights_datasets d ON d.workspace=r.workspace AND d.dataset_id=r.config->>'dataset_id'
    AND d.state='authenticated'
  JOIN public.fw_rights_assets ra ON ra.workspace=r.workspace AND ra.dataset_id=d.dataset_id
    AND ra.member_id=selected.item->>'source_member' AND ra.rights_state='reviewed'
    AND ra.asset_sha256=selected.item->>'sha256' AND ra.asset_bytes=fs.raw_bytes
  JOIN public.fw_rights_decisions rd ON rd.workspace=ra.workspace AND rd.dataset_id=ra.dataset_id
    AND rd.member_id=ra.member_id AND rd.purpose='local_private_training';
  IF picked IS NULL THEN PERFORM fw_worker_cap_v1.deny('REAL_RIGHTS_BINDING_CHANGED',r.state,NULL); END IF;
  RETURN picked;
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.real_member_rights(text,text,text,integer,integer,uuid,text) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.real_member_rights(text,text,text,integer,integer,uuid,text) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.real_bundle_rights(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; v public.fw_versions; rights_rows jsonb; expected_count integer; returned_count integer;
BEGIN
  SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace);
  IF NOT FOUND OR r.state<>'running' OR r.attempt IS DISTINCT FROM p_attempt OR r.fence<>p_fence
      OR r.cancel_generation IS DISTINCT FROM p_generation OR r.lease<=pg_catalog.clock_timestamp() THEN
    PERFORM fw_worker_cap_v1.deny('FENCED_OR_EXPIRED_OR_CANCELLED',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM fw_worker_cap_v1.credentials c
      WHERE c.token_hash=fw_worker_cap_v1.hash_token(p_token) AND c.principal=session_user
        AND c.run=p_run AND c.attempt=p_attempt AND c.expires_at>pg_catalog.clock_timestamp()) THEN
    PERFORM fw_worker_cap_v1.deny('CREDENTIAL_EXPIRED_OR_INVALID',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.fw_control ctl WHERE ctl.id=1 AND ctl.restore_generation=p_restore)
     OR NOT EXISTS (SELECT 1 FROM public.fw_attempts a WHERE a.id=p_attempt AND a.restore_generation=p_restore) THEN
    PERFORM fw_worker_cap_v1.deny('RESTORE_GENERATION_FENCED',r.state,NULL);
  END IF;
  IF NOT fw_real_worker_cap_v1.profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_PROFILE_REFUSED',r.state,NULL);
  END IF;
  SELECT * INTO v FROM public.fw_versions WHERE workspace=r.workspace AND id=r.config->>'version_id'
      AND state='frozen' AND revision::text=(r.config->>'version_revision')
      AND manifest->>'scope'='real-rights-cleared'
      AND manifest->>'digest'=r.config->>'version_digest'
      AND manifest->>'rights_dataset_id'=r.config->>'dataset_id';
  IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('FROZEN_VERSION_BINDING_CHANGED',r.state,NULL); END IF;
  WITH selected AS (
    SELECT item FROM jsonb_path_query(v.manifest,
      '$.samples[*] ? (@.split == "train" || @.split == "validation")') AS selected_items(item)
  ), joined AS (
    SELECT selected.item,ra.asset_sha256,ra.asset_bytes,ra.canonical_license,ra.license_text,
      ra.source_evidence,ra.attribution,rd.envelope
    FROM selected
    JOIN public.fw_samples fs ON fs.workspace=r.workspace AND fs.sample_id::text=selected.item->>'id'
      AND fs.raw_sha256=selected.item->>'sha256'
    JOIN public.fw_rights_datasets d ON d.workspace=r.workspace AND d.dataset_id=r.config->>'dataset_id'
      AND d.state='authenticated'
    JOIN public.fw_rights_assets ra ON ra.workspace=r.workspace AND ra.dataset_id=d.dataset_id
      AND ra.member_id=selected.item->>'source_member' AND ra.rights_state='reviewed'
      AND ra.asset_sha256=selected.item->>'sha256' AND ra.asset_bytes=fs.raw_bytes
    JOIN public.fw_rights_decisions rd ON rd.workspace=ra.workspace AND rd.dataset_id=ra.dataset_id
      AND rd.member_id=ra.member_id AND rd.purpose='model_bundle'
  )
  SELECT count(*)::integer,
    coalesce(jsonb_agg(jsonb_build_object('sample_id',item->>'id','source_member',item->>'source_member',
      'asset_sha256',asset_sha256,'asset_bytes',asset_bytes,
      'rights_envelope_b64',pg_catalog.encode(envelope,'base64'),
      'rights_facts',jsonb_build_object('member_id',item->>'source_member','asset_sha256',asset_sha256,
        'asset_bytes',asset_bytes,'canonical_license_sha256',pg_catalog.encode(pg_catalog.sha256(canonical_license),'hex'),
        'license_text_sha256',pg_catalog.encode(pg_catalog.sha256(license_text),'hex'),
        'source_evidence_sha256',pg_catalog.encode(pg_catalog.sha256(source_evidence),'hex'),
        'attribution_sha256',pg_catalog.encode(pg_catalog.sha256(attribution),'hex'),
        'dataset_id',r.config->>'dataset_id','workspace_id',r.workspace,'purpose','model_bundle'))
      ORDER BY item->>'id'),'[]'::jsonb)
    INTO returned_count,rights_rows FROM joined;
  SELECT count(*)::integer INTO expected_count FROM jsonb_path_query(v.manifest,
      '$.samples[*] ? (@.split == "train" || @.split == "validation")');
  IF expected_count<1 OR returned_count<>expected_count THEN
    PERFORM fw_worker_cap_v1.deny('REAL_BUNDLE_RIGHTS_NOT_READY',r.state,NULL);
  END IF;
  RETURN jsonb_build_object('version_id',v.id,'version_digest',v.manifest->>'digest',
    'actor_authorized',true,'rights',rights_rows);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.real_bundle_rights(text,text,text,integer,integer,uuid) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.real_bundle_rights(text,text,text,integer,integer,uuid) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.real_artifact_rights(
  p_run text,p_fence integer,p_owner_pid integer,p_owner_created double precision)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; v public.fw_versions; rights_rows jsonb; expected_count integer; returned_count integer;
BEGIN
  r := fw_worker_cap_v1.artifact_lock(p_run,p_fence,p_owner_pid,p_owner_created,false);
  IF r.artifact_status NOT IN ('pending','building','inference') THEN
    PERFORM fw_worker_cap_v1.deny('REAL_ARTIFACT_NOT_ACTIVE',r.state,NULL);
  END IF;
  IF NOT fw_real_worker_cap_v1.profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_ARTIFACT_BINDING_CHANGED',r.state,NULL);
  END IF;
  SELECT * INTO v FROM public.fw_versions WHERE workspace=r.workspace AND id=r.config->>'version_id'
      AND state='frozen' AND revision::text=(r.config->>'version_revision')
      AND manifest->>'scope'='real-rights-cleared'
      AND manifest->>'digest'=r.config->>'version_digest'
      AND manifest->>'rights_dataset_id'=r.config->>'dataset_id';
  IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('FROZEN_VERSION_BINDING_CHANGED',r.state,NULL); END IF;
  WITH selected AS (
    SELECT DISTINCT ON (item->>'source_member') item
    FROM jsonb_path_query(v.manifest,
      '$.samples[*] ? (@.split == "train" || @.split == "validation")') AS selected_items(item)
    ORDER BY item->>'source_member',item->>'id'
  ), joined AS (
    SELECT selected.item,ra.asset_sha256,ra.asset_bytes,ra.canonical_license,ra.license_text,
      ra.source_evidence,ra.attribution,rd.envelope
    FROM selected
    JOIN public.fw_samples fs ON fs.workspace=r.workspace AND fs.sample_id::text=selected.item->>'id'
      AND fs.raw_sha256=selected.item->>'sha256'
    JOIN public.fw_rights_datasets d ON d.workspace=r.workspace AND d.dataset_id=r.config->>'dataset_id'
      AND d.state='authenticated'
    JOIN public.fw_rights_assets ra ON ra.workspace=r.workspace AND ra.dataset_id=d.dataset_id
      AND ra.member_id=selected.item->>'source_member' AND ra.rights_state='reviewed'
      AND ra.asset_sha256=selected.item->>'sha256' AND ra.asset_bytes=fs.raw_bytes
    JOIN public.fw_rights_decisions rd ON rd.workspace=ra.workspace AND rd.dataset_id=ra.dataset_id
      AND rd.member_id=ra.member_id AND rd.purpose='model_bundle'
  )
  SELECT count(*)::integer,
    coalesce(jsonb_agg(jsonb_build_object('sample_id',item->>'id','source_member',item->>'source_member',
      'asset_sha256',asset_sha256,'asset_bytes',asset_bytes,
      'rights_envelope_b64',pg_catalog.encode(envelope,'base64'),
      'rights_facts',jsonb_build_object('member_id',item->>'source_member','asset_sha256',asset_sha256,
        'asset_bytes',asset_bytes,'canonical_license_sha256',pg_catalog.encode(pg_catalog.sha256(canonical_license),'hex'),
        'license_text_sha256',pg_catalog.encode(pg_catalog.sha256(license_text),'hex'),
        'source_evidence_sha256',pg_catalog.encode(pg_catalog.sha256(source_evidence),'hex'),
        'attribution_sha256',pg_catalog.encode(pg_catalog.sha256(attribution),'hex'),
        'dataset_id',r.config->>'dataset_id','workspace_id',r.workspace,'purpose','model_bundle'))
      ORDER BY item->>'id'),'[]'::jsonb)
    INTO returned_count,rights_rows FROM joined;
  SELECT count(DISTINCT item->>'source_member')::integer INTO expected_count
    FROM jsonb_path_query(v.manifest,'$.samples[*] ? (@.split == "train" || @.split == "validation")') AS items(item);
  IF expected_count<1 OR expected_count>10000 OR returned_count<>expected_count THEN
    PERFORM fw_worker_cap_v1.deny('REAL_BUNDLE_RIGHTS_NOT_READY',r.state,NULL);
  END IF;
  RETURN jsonb_build_object('version_id',v.id,'version_digest',v.manifest->>'digest',
    'actor_authorized',true,'rights',rights_rows);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.real_artifact_rights(text,integer,integer,double precision) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.real_artifact_rights(text,integer,integer,double precision) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.real_inference_input(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; source_run public.fw_runs; v public.fw_versions; picked jsonb;
BEGIN
  SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace);
  IF NOT FOUND OR r.state<>'running' OR r.attempt IS DISTINCT FROM p_attempt OR r.fence<>p_fence
      OR r.cancel_generation IS DISTINCT FROM p_generation OR r.lease<=pg_catalog.clock_timestamp() THEN
    PERFORM fw_worker_cap_v1.deny('FENCED_OR_EXPIRED_OR_CANCELLED',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM fw_worker_cap_v1.credentials c
      WHERE c.token_hash=fw_worker_cap_v1.hash_token(p_token) AND c.principal=session_user
        AND c.run=p_run AND c.attempt=p_attempt AND c.expires_at>pg_catalog.clock_timestamp()) THEN
    PERFORM fw_worker_cap_v1.deny('CREDENTIAL_EXPIRED_OR_INVALID',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.fw_control ctl WHERE ctl.id=1 AND ctl.restore_generation=p_restore)
     OR NOT EXISTS (SELECT 1 FROM public.fw_attempts a WHERE a.id=p_attempt AND a.restore_generation=p_restore) THEN
    PERFORM fw_worker_cap_v1.deny('RESTORE_GENERATION_FENCED',r.state,NULL);
  END IF;
  IF NOT fw_real_worker_cap_v1.inference_profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_BINDING_CHANGED',r.state,NULL);
  END IF;
  SELECT * INTO source_run FROM public.fw_runs WHERE id=r.config->>'run_id'
    AND workspace=r.workspace AND state='succeeded' AND artifact_status='verified'
    AND artifact_result->>'bundle_digest'=r.config->>'bundle_digest'
    AND config->>'version_id'=r.config->>'version_id'
    AND config->>'version_digest'=r.config->>'version_digest';
  IF NOT FOUND OR coalesce(source_run.artifact_result->>'artifact_directory','') !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' THEN
    PERFORM fw_worker_cap_v1.deny('VERIFIED_REAL_BUNDLE_REQUIRED',r.state,NULL);
  END IF;
  SELECT * INTO v FROM public.fw_versions WHERE workspace=r.workspace AND id=r.config->>'version_id'
      AND state='frozen' AND revision::text=(source_run.config->>'version_revision')
      AND manifest->>'scope'='real-rights-cleared'
      AND manifest->>'digest'=r.config->>'version_digest'
      AND manifest->>'rights_dataset_id'=source_run.config->>'dataset_id';
  IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('FROZEN_VERSION_BINDING_CHANGED',r.state,NULL); END IF;
  WITH selected AS (
    SELECT item FROM jsonb_path_query(v.manifest,
      '$.samples[*] ? (@.split == "train" || @.split == "validation")') AS selected_items(item)
    WHERE item->>'id'=r.config->>'sample_id' AND item->>'split'=r.config->>'sample_split'
  ), joined AS (
    SELECT selected.item,fs.media_path,fs.raw_bytes,fs.format,ra.asset_sha256,ra.asset_bytes,
      ra.canonical_license,ra.license_text,ra.source_evidence,ra.attribution,
      train.envelope AS training_envelope,bundle.envelope AS bundle_envelope
    FROM selected
    JOIN public.fw_samples fs ON fs.workspace=r.workspace AND fs.sample_id::text=selected.item->>'id'
      AND fs.raw_sha256=selected.item->>'sha256'
    JOIN public.fw_rights_datasets d ON d.workspace=r.workspace AND d.dataset_id=source_run.config->>'dataset_id'
      AND d.state='authenticated'
    JOIN public.fw_rights_assets ra ON ra.workspace=r.workspace AND ra.dataset_id=d.dataset_id
      AND ra.member_id=selected.item->>'source_member' AND ra.rights_state='reviewed'
      AND ra.asset_sha256=selected.item->>'sha256' AND ra.asset_bytes=fs.raw_bytes
    JOIN public.fw_rights_decisions train ON train.workspace=ra.workspace AND train.dataset_id=ra.dataset_id
      AND train.member_id=ra.member_id AND train.purpose='local_private_training'
    JOIN public.fw_rights_decisions bundle ON bundle.workspace=ra.workspace AND bundle.dataset_id=ra.dataset_id
      AND bundle.member_id=ra.member_id AND bundle.purpose='model_bundle'
  )
  SELECT jsonb_build_object('id',item->'id','split',item->'split','group',item->'group',
    'source_member',item->'source_member','sha256',item->'sha256','pixel_sha256',item->'pixel_sha256',
    'label',item->'label')||jsonb_build_object('media_path',media_path,'raw_bytes',raw_bytes,'format',format,
    'training_rights_envelope_b64',pg_catalog.encode(training_envelope,'base64'),
    'bundle_rights_envelope_b64',pg_catalog.encode(bundle_envelope,'base64'),
    'training_rights_facts',jsonb_build_object('member_id',item->>'source_member','asset_sha256',asset_sha256,
      'asset_bytes',asset_bytes,'canonical_license_sha256',pg_catalog.encode(pg_catalog.sha256(canonical_license),'hex'),
      'license_text_sha256',pg_catalog.encode(pg_catalog.sha256(license_text),'hex'),
      'source_evidence_sha256',pg_catalog.encode(pg_catalog.sha256(source_evidence),'hex'),
      'attribution_sha256',pg_catalog.encode(pg_catalog.sha256(attribution),'hex'),
      'dataset_id',source_run.config->>'dataset_id','workspace_id',r.workspace,'purpose','local_private_training'),
    'bundle_rights_facts',jsonb_build_object('member_id',item->>'source_member','asset_sha256',asset_sha256,
      'asset_bytes',asset_bytes,'canonical_license_sha256',pg_catalog.encode(pg_catalog.sha256(canonical_license),'hex'),
      'license_text_sha256',pg_catalog.encode(pg_catalog.sha256(license_text),'hex'),
      'source_evidence_sha256',pg_catalog.encode(pg_catalog.sha256(source_evidence),'hex'),
      'attribution_sha256',pg_catalog.encode(pg_catalog.sha256(attribution),'hex'),
      'dataset_id',source_run.config->>'dataset_id','workspace_id',r.workspace,'purpose','model_bundle'))
  INTO picked FROM joined;
  IF picked IS NULL THEN PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_RIGHTS_NOT_READY',r.state,NULL); END IF;
  RETURN jsonb_build_object('version_id',v.id,'version_digest',v.manifest->>'digest',
    'dataset_id',source_run.config->>'dataset_id',
    'bundle_digest',r.config->>'bundle_digest','artifact_directory',source_run.artifact_result->>'artifact_directory',
    'actor_authorized',true,'sample',picked);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.complete_real_inference(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid,
  p_receipt jsonb,p_owner_pid integer,p_owner_created double precision,p_child_exited boolean)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; sl record; receipt_digest text; resp jsonb;
  prediction jsonb; probability_sum numeric; prediction_top1 integer; probability_top1 integer;
BEGIN
  SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
  SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
  IF NOT FOUND OR r.state<>'running' OR r.attempt IS DISTINCT FROM p_attempt OR r.fence<>p_fence
      OR r.cancel_generation IS DISTINCT FROM p_generation OR r.lease<=pg_catalog.clock_timestamp() THEN
    PERFORM fw_worker_cap_v1.deny('FENCED_OR_EXPIRED_OR_CANCELLED',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM fw_worker_cap_v1.credentials c
      WHERE c.token_hash=fw_worker_cap_v1.hash_token(p_token) AND c.principal=session_user
        AND c.run=p_run AND c.attempt=p_attempt AND c.expires_at>pg_catalog.clock_timestamp()) THEN
    PERFORM fw_worker_cap_v1.deny('CREDENTIAL_EXPIRED_OR_INVALID',r.state,NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.fw_control ctl WHERE ctl.id=1 AND ctl.restore_generation=p_restore)
     OR NOT EXISTS (SELECT 1 FROM public.fw_attempts a WHERE a.id=p_attempt AND a.restore_generation=p_restore) THEN
    PERFORM fw_worker_cap_v1.deny('RESTORE_GENERATION_FENCED',r.state,NULL);
  END IF;
  IF NOT fw_real_worker_cap_v1.inference_profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_BINDING_CHANGED',r.state,NULL);
  END IF;
  PERFORM fw_real_worker_cap_v1.real_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore);
  IF sl.run IS DISTINCT FROM p_run OR sl.fence IS DISTINCT FROM p_fence OR sl.owner_pid IS DISTINCT FROM p_owner_pid
      OR sl.owner_created IS DISTINCT FROM p_owner_created OR sl.launching OR NOT p_child_exited THEN
    PERFORM fw_worker_cap_v1.deny('CHILD_EXIT_OR_OWNER_UNCONFIRMED',r.state,NULL);
  END IF;
  IF pg_catalog.jsonb_typeof(p_receipt)<>'object' OR pg_catalog.octet_length(p_receipt::text)>16384 THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_RECEIPT_INVALID',r.state,NULL);
  END IF;
  IF (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_receipt))<>5
      OR NOT (p_receipt ?& ARRAY['receipt_digest','bundle_digest','version_digest','sample_split','prediction'])
      OR (p_receipt-ARRAY['receipt_digest','bundle_digest','version_digest','sample_split','prediction'])<>'{}'::jsonb
      OR pg_catalog.jsonb_typeof(p_receipt->'receipt_digest')<>'string'
      OR p_receipt->>'receipt_digest' !~ '^[0-9a-f]{64}$'
      OR p_receipt->>'bundle_digest' IS DISTINCT FROM r.config->>'bundle_digest'
      OR p_receipt->>'version_digest' IS DISTINCT FROM r.config->>'version_digest'
      OR p_receipt->>'sample_split' IS DISTINCT FROM r.config->>'sample_split' THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_RECEIPT_INVALID',r.state,NULL);
  END IF;
  prediction := p_receipt->'prediction';
  IF pg_catalog.jsonb_typeof(prediction)<>'object' THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_PREDICTION_INVALID',r.state,NULL);
  END IF;
  IF (SELECT count(*) FROM pg_catalog.jsonb_object_keys(prediction))<>3
      OR NOT (prediction ?& ARRAY['classes','probabilities','top1'])
      OR (prediction-ARRAY['classes','probabilities','top1'])<>'{}'::jsonb THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_PREDICTION_INVALID',r.state,NULL);
  END IF;
  IF pg_catalog.jsonb_typeof(prediction->'classes')<>'array' THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_CLASSES_INVALID',r.state,NULL);
  END IF;
  IF pg_catalog.jsonb_array_length(prediction->'classes')<>5 THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_CLASSES_INVALID',r.state,NULL);
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(prediction->'classes') AS item(value)
      WHERE pg_catalog.jsonb_typeof(value)<>'string' OR value#>>'{}'=''
        OR pg_catalog.char_length(value#>>'{}')>200 OR pg_catalog.octet_length(value#>>'{}')>800
        OR value#>>'{}' ~ '[[:cntrl:]]') THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_CLASSES_INVALID',r.state,NULL);
  END IF;
  IF (SELECT count(DISTINCT value#>>'{}') FROM pg_catalog.jsonb_array_elements(prediction->'classes') AS item(value))<>5 THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_CLASSES_INVALID',r.state,NULL);
  END IF;
  IF pg_catalog.jsonb_typeof(prediction->'probabilities')<>'array' THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_PROBABILITIES_INVALID',r.state,NULL);
  END IF;
  IF pg_catalog.jsonb_array_length(prediction->'probabilities')<>5 THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_PROBABILITIES_INVALID',r.state,NULL);
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(prediction->'probabilities') AS item(value)
      WHERE CASE WHEN pg_catalog.jsonb_typeof(value)='number'
        THEN (value#>>'{}')::numeric BETWEEN 0 AND 1 ELSE false END IS NOT TRUE) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_PROBABILITIES_INVALID',r.state,NULL);
  END IF;
  IF pg_catalog.jsonb_typeof(prediction->'top1')<>'number'
      OR prediction->>'top1' !~ '^[0-4]$' THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_TOP1_INVALID',r.state,NULL);
  END IF;
  SELECT sum((value#>>'{}')::numeric) INTO probability_sum
    FROM pg_catalog.jsonb_array_elements(prediction->'probabilities') AS item(value);
  SELECT ordinality-1 INTO probability_top1
    FROM pg_catalog.jsonb_array_elements(prediction->'probabilities') WITH ORDINALITY AS item(value,ordinality)
    ORDER BY (value#>>'{}')::numeric DESC,ordinality ASC LIMIT 1;
  prediction_top1 := (prediction->>'top1')::integer;
  IF abs(probability_sum-1)>0.0001 OR probability_top1<>prediction_top1 THEN
    PERFORM fw_worker_cap_v1.deny('REAL_INFERENCE_PREDICTION_INVALID',r.state,NULL);
  END IF;
  receipt_digest := fw_worker_cap_v1.hash_token(p_receipt::text);
  UPDATE public.fw_runs SET state='succeeded',result=pg_catalog.jsonb_build_object(
    'receipt_digest',p_receipt->>'receipt_digest','bundle_digest',p_receipt->>'bundle_digest',
    'version_digest',p_receipt->>'version_digest','sample_split',p_receipt->>'sample_split',
    'prediction',prediction),
    artifact_status='verified',artifact_result=pg_catalog.jsonb_build_object('code','REAL_INFERENCE_RECEIPT_RECORDED','receipt_digest',receipt_digest),
    lease=NULL,revision=revision+1 WHERE id=p_run RETURNING * INTO r;
  UPDATE public.fw_attempts SET ended_at=pg_catalog.clock_timestamp() WHERE id=p_attempt;
  DELETE FROM fw_worker_cap_v1.credentials WHERE attempt=p_attempt AND principal=session_user;
  UPDATE public.fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL,launching=false WHERE id=1;
  INSERT INTO public.fw_events(workspace,run,kind,payload,object_revision)
    VALUES(r.workspace,r.id,'succeeded',pg_catalog.jsonb_build_object('state','succeeded','attempt',p_attempt,
      'fence',p_fence,'scope','real-inference/v1','receipt_digest',receipt_digest),r.revision);
  resp := pg_catalog.jsonb_build_object('state','succeeded','revision',r.revision,'receipt_digest',receipt_digest);
  RETURN resp;
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.complete_real_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.complete_real_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean) FROM PUBLIC;

-- Existing worker logins receive only these explicit fixed function calls. Later
-- provisioning adds the same grants in worker_identity.py when this schema exists.
DO $grant$
DECLARE principal text;
BEGIN
  FOR principal IN SELECT s.principal FROM fw_worker_cap_v1.scope AS s LOOP
    EXECUTE format('GRANT USAGE ON SCHEMA fw_real_worker_cap_v1 TO %I',principal);
    EXECUTE format('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.next_real_run(text[]), fw_real_worker_cap_v1.claim_real(text,text,integer,double precision,text), fw_real_worker_cap_v1.next_real_artifact(text[]), fw_real_worker_cap_v1.claim_real_artifacts(text,integer,double precision), fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid), fw_real_worker_cap_v1.real_member_rights(text,text,text,integer,integer,uuid,text), fw_real_worker_cap_v1.real_bundle_rights(text,text,text,integer,integer,uuid), fw_real_worker_cap_v1.real_artifact_rights(text,integer,integer,double precision), fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid), fw_real_worker_cap_v1.complete_real_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean) TO %I',principal);
  END LOOP;
END
$grant$;

REVOKE CREATE ON SCHEMA fw_real_worker_cap_v1 FROM fieldwork_real_worker_definer;

COMMIT;
