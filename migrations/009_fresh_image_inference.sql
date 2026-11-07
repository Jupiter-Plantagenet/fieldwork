-- Fresh, rights-bound image inference. Source only: never apply from application code.
-- Prerequisite is the immutable 007 worker capability. Migration 010 separately
-- adds workspace admission for this closed scope. This forward migration keeps the original train/validation
-- inference profile intact and adds a distinct, closed upload profile.
BEGIN;

CREATE TABLE public.fw_real_image_inputs (
  workspace text NOT NULL,
  run text NOT NULL REFERENCES public.fw_runs(id),
  input_id uuid NOT NULL,
  dataset_id uuid NOT NULL,
  member_id text NOT NULL CHECK (char_length(member_id) BETWEEN 1 AND 512),
  asset_sha256 text NOT NULL CHECK (asset_sha256 ~ '^[0-9a-f]{64}$'),
  asset_bytes bigint NOT NULL CHECK (asset_bytes BETWEEN 1 AND 20971520),
  upload_key uuid NOT NULL UNIQUE,
  created_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace,run),
  UNIQUE (workspace,input_id),
  CHECK (input_id=upload_key)
);
ALTER TABLE public.fw_real_image_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fw_real_image_inputs FORCE ROW LEVEL SECURITY;
CREATE POLICY fw_real_image_inputs_api ON public.fw_real_image_inputs TO fieldwork_api
  USING (workspace=current_setting('fieldwork.workspace',true))
  WITH CHECK (workspace=current_setting('fieldwork.workspace',true));
CREATE POLICY fw_real_image_inputs_worker ON public.fw_real_image_inputs TO fieldwork_real_worker_definer
  USING (fw_worker_cap_v1.allowed(workspace))
  WITH CHECK (fw_worker_cap_v1.allowed(workspace));
REVOKE ALL ON public.fw_real_image_inputs FROM PUBLIC;
GRANT SELECT,INSERT ON public.fw_real_image_inputs TO fieldwork_api;
GRANT SELECT ON public.fw_real_image_inputs TO fieldwork_real_worker_definer;

CREATE FUNCTION fw_real_worker_cap_v1.image_inference_profile_ok(p_config jsonb,p_workspace text,p_actor text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT (CASE WHEN coalesce(pg_catalog.jsonb_typeof(p_config),'')<>'object' THEN false ELSE
    p_config->>'profile_schema'='fieldwork.real-run-profile/v1'
    AND p_config->>'scope'='real-image-inference/v1'
    AND p_config->>'operation'='infer-image'
    AND p_config->>'workspace'=p_workspace AND p_config->>'actor'=p_actor
    AND p_config->>'preprocess'='short-edge144-rgb-v1'
    AND p_config->>'sample_split'='upload'
    AND (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_config))=20
    AND (p_config-ARRAY['profile_schema','scope','operation','workspace','actor','run_id','version_id',
      'version_digest','dataset_id','member_id','asset_sha256','asset_bytes','input_id','sample_split',
      'bundle_digest','preprocess','preprocess_digest','decoder_image_id','model_image_id','idempotency_key'])='{}'::jsonb
    AND p_config ?& ARRAY['run_id','version_id','version_digest','dataset_id','member_id','asset_sha256',
      'asset_bytes','input_id','sample_split','bundle_digest','preprocess_digest','decoder_image_id',
      'model_image_id','idempotency_key']
    AND p_config->>'run_id' ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
    AND p_config->>'version_id' ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
    AND p_config->>'version_digest' ~ '^[0-9a-f]{64}$'
    AND p_config->>'bundle_digest' ~ '^[0-9a-f]{64}$'
    AND p_config->>'asset_sha256' ~ '^[0-9a-f]{64}$'
    AND p_config->>'dataset_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND p_config->>'input_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND p_config->>'asset_bytes' ~ '^[1-9][0-9]{0,7}$'
    AND (p_config->>'asset_bytes')::bigint BETWEEN 1 AND 20971520
    AND pg_catalog.char_length(p_config->>'member_id') BETWEEN 1 AND 512
    AND p_config->>'preprocess_digest' IN (
      'e5b19df9fa39a01dd178e78d5efbd12a899983fad22ed3c7ff8d52643bc5ba44',
      '1392785edc35eef504d62e4d9b90bb6aa438127d52e83869853b4eb8ebd34d92')
    AND p_config->>'decoder_image_id' ~ '^sha256:[0-9a-f]{64}$'
    AND p_config->>'model_image_id' ~ '^sha256:[0-9a-f]{64}$'
    AND pg_catalog.char_length(p_config->>'idempotency_key') BETWEEN 1 AND 128
    AND EXISTS (SELECT 1 FROM public.fw_accounts a WHERE a.workspace=p_workspace
      AND a.name=p_actor AND a.role IN ('owner','researcher','reviewer'))
    AND EXISTS (SELECT 1 FROM public.fw_runs t WHERE t.id=p_config->>'run_id'
      AND t.workspace=p_workspace AND t.state='succeeded' AND t.artifact_status='verified'
      AND t.config->>'scope'='real-training/v1'
      AND t.config->>'version_id'=p_config->>'version_id'
      AND t.config->>'version_digest'=p_config->>'version_digest'
      AND t.config->>'dataset_id'=p_config->>'dataset_id'
      AND t.config->>'preprocess_digest'=p_config->>'preprocess_digest'
      AND t.config->>'decoder_image_id'=p_config->>'decoder_image_id'
      AND t.config->>'model_image_id'=p_config->>'model_image_id'
      AND t.artifact_result->>'bundle_digest'=p_config->>'bundle_digest'
      AND EXISTS (SELECT 1 FROM public.fw_versions v WHERE v.workspace=p_workspace
        AND v.id=p_config->>'version_id' AND v.state='frozen'
        AND v.revision::text=t.config->>'version_revision'
        AND v.manifest->>'digest'=p_config->>'version_digest'
        AND v.manifest->>'rights_dataset_id'=p_config->>'dataset_id'))
    AND EXISTS (SELECT 1 FROM public.fw_real_image_inputs i
      WHERE i.workspace=p_workspace AND i.run=(SELECT r.id FROM public.fw_runs r
        WHERE r.workspace=p_workspace AND r.actor=p_actor AND r.config=p_config LIMIT 1)
        AND i.input_id::text=p_config->>'input_id'
        AND i.dataset_id::text=p_config->>'dataset_id' AND i.member_id=p_config->>'member_id'
        AND i.asset_sha256=p_config->>'asset_sha256'
        AND i.asset_bytes=(p_config->>'asset_bytes')::bigint)
    AND EXISTS (SELECT 1 FROM public.fw_rights_datasets d WHERE d.workspace=p_workspace
      AND d.dataset_id::text=p_config->>'dataset_id' AND d.state='authenticated')
    AND EXISTS (SELECT 1 FROM public.fw_rights_assets a WHERE a.workspace=p_workspace
      AND a.dataset_id::text=p_config->>'dataset_id' AND a.member_id=p_config->>'member_id'
      AND a.rights_state='reviewed' AND a.asset_sha256=p_config->>'asset_sha256'
      AND a.asset_bytes=(p_config->>'asset_bytes')::bigint)
    AND EXISTS (SELECT 1 FROM public.fw_rights_decisions d WHERE d.workspace=p_workspace
      AND d.dataset_id::text=p_config->>'dataset_id' AND d.member_id=p_config->>'member_id'
      AND d.purpose='local_private_training')
    AND EXISTS (SELECT 1 FROM public.fw_rights_decisions d WHERE d.workspace=p_workspace
      AND d.dataset_id::text=p_config->>'dataset_id' AND d.member_id=p_config->>'member_id'
      AND d.purpose='model_bundle')
    AND NOT EXISTS (SELECT 1 FROM public.fw_versions v,
      LATERAL jsonb_path_query(v.manifest,'$.samples[*]') q(item)
      WHERE v.workspace=p_workspace AND v.state='frozen'
        AND q.item->>'split' NOT IN ('train','validation')
        AND (q.item->>'source_member'=p_config->>'member_id'
          OR q.item->>'sha256'=p_config->>'asset_sha256'))
  END) IS TRUE
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.image_inference_profile_ok(jsonb,text,text) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.image_inference_profile_ok(jsonb,text,text) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.real_image_inference_input(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid,
  p_pixel_digest text DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; source_run public.fw_runs; v public.fw_versions; i public.fw_real_image_inputs;
  a public.fw_rights_assets; train bytea; bundle bytea; protected boolean; picked jsonb;
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
     OR NOT EXISTS (SELECT 1 FROM public.fw_attempts x WHERE x.id=p_attempt AND x.restore_generation=p_restore) THEN
    PERFORM fw_worker_cap_v1.deny('RESTORE_GENERATION_FENCED',r.state,NULL);
  END IF;
  IF p_pixel_digest IS NOT NULL AND p_pixel_digest !~ '^[0-9a-f]{64}$' THEN
    PERFORM fw_worker_cap_v1.deny('REAL_IMAGE_PIXEL_IDENTITY_INVALID',r.state,NULL);
  END IF;
  IF NOT fw_real_worker_cap_v1.image_inference_profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_IMAGE_INFERENCE_BINDING_CHANGED',r.state,NULL);
  END IF;
  SELECT * INTO source_run FROM public.fw_runs WHERE id=r.config->>'run_id'
    AND workspace=r.workspace AND state='succeeded' AND artifact_status='verified'
    AND artifact_result->>'bundle_digest'=r.config->>'bundle_digest';
  SELECT * INTO v FROM public.fw_versions WHERE workspace=r.workspace AND id=r.config->>'version_id'
    AND state='frozen' AND revision::text=source_run.config->>'version_revision'
    AND manifest->>'digest'=r.config->>'version_digest'
    AND manifest->>'rights_dataset_id'=r.config->>'dataset_id';
  SELECT * INTO i FROM public.fw_real_image_inputs WHERE workspace=r.workspace AND run=p_run
    AND input_id::text=r.config->>'input_id' AND upload_key::text=r.config->>'input_id'
    AND dataset_id::text=r.config->>'dataset_id' AND member_id=r.config->>'member_id'
    AND asset_sha256=r.config->>'asset_sha256' AND asset_bytes=(r.config->>'asset_bytes')::bigint;
  SELECT * INTO a FROM public.fw_rights_assets WHERE workspace=r.workspace
    AND dataset_id=i.dataset_id AND member_id=i.member_id AND rights_state='reviewed'
    AND asset_sha256=i.asset_sha256 AND asset_bytes=i.asset_bytes;
  SELECT envelope INTO train FROM public.fw_rights_decisions WHERE workspace=r.workspace
    AND dataset_id=i.dataset_id AND member_id=i.member_id AND purpose='local_private_training';
  SELECT envelope INTO bundle FROM public.fw_rights_decisions WHERE workspace=r.workspace
    AND dataset_id=i.dataset_id AND member_id=i.member_id AND purpose='model_bundle';
  IF source_run.id IS NULL OR v.id IS NULL OR i.run IS NULL OR a.member_id IS NULL
       OR train IS NULL OR bundle IS NULL THEN
    PERFORM fw_worker_cap_v1.deny('REAL_IMAGE_RIGHTS_NOT_READY',r.state,NULL);
  END IF;
  SELECT EXISTS (SELECT 1 FROM public.fw_versions fv,
    LATERAL jsonb_path_query(fv.manifest,'$.samples[*]') q(item)
    WHERE fv.workspace=r.workspace AND fv.state='frozen'
      AND q.item->>'split' NOT IN ('train','validation')
      AND (q.item->>'source_member'=i.member_id OR q.item->>'sha256'=i.asset_sha256
        OR (p_pixel_digest IS NOT NULL AND q.item->>'pixel_sha256'=p_pixel_digest))) INTO protected;
  IF protected THEN PERFORM fw_worker_cap_v1.deny('REAL_IMAGE_PROTECTED_INPUT',r.state,NULL); END IF;
  picked := jsonb_build_object('id',r.config->>'input_id','split','upload',
    'source_member',i.member_id,'sha256',i.asset_sha256,'raw_bytes',i.asset_bytes,
    'training_rights_envelope_b64',pg_catalog.encode(train,'base64'),
    'bundle_rights_envelope_b64',pg_catalog.encode(bundle,'base64'),
    'training_rights_facts',jsonb_build_object('member_id',i.member_id,'asset_sha256',a.asset_sha256,
      'asset_bytes',a.asset_bytes,'canonical_license_sha256',pg_catalog.encode(pg_catalog.sha256(a.canonical_license),'hex'),
      'license_text_sha256',pg_catalog.encode(pg_catalog.sha256(a.license_text),'hex'),
      'source_evidence_sha256',pg_catalog.encode(pg_catalog.sha256(a.source_evidence),'hex'),
      'attribution_sha256',pg_catalog.encode(pg_catalog.sha256(a.attribution),'hex'),
      'dataset_id',i.dataset_id,'workspace_id',r.workspace,'purpose','local_private_training'),
    'bundle_rights_facts',jsonb_build_object('member_id',i.member_id,'asset_sha256',a.asset_sha256,
      'asset_bytes',a.asset_bytes,'canonical_license_sha256',pg_catalog.encode(pg_catalog.sha256(a.canonical_license),'hex'),
      'license_text_sha256',pg_catalog.encode(pg_catalog.sha256(a.license_text),'hex'),
      'source_evidence_sha256',pg_catalog.encode(pg_catalog.sha256(a.source_evidence),'hex'),
      'attribution_sha256',pg_catalog.encode(pg_catalog.sha256(a.attribution),'hex'),
      'dataset_id',i.dataset_id,'workspace_id',r.workspace,'purpose','model_bundle'));
  RETURN jsonb_build_object('version_id',v.id,'version_digest',v.manifest->>'digest',
    'dataset_id',i.dataset_id,'bundle_digest',r.config->>'bundle_digest',
    'artifact_directory',source_run.artifact_result->>'artifact_directory','upload_key',i.upload_key,
    'actor_authorized',true,'protected_match',false,'sample',picked);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.real_image_inference_input(text,text,text,integer,integer,uuid,text) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.real_image_inference_input(text,text,text,integer,integer,uuid,text) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.complete_real_image_inference(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid,
  p_receipt jsonb,p_owner_pid integer,p_owner_created double precision,p_child_exited boolean,
  p_protected_pixel_digest text,p_training_rights_digest text,p_bundle_rights_digest text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; train bytea; bundle bytea;
BEGIN
  SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
  IF NOT FOUND OR r.config->>'scope'<>'real-image-inference/v1'
      OR NOT fw_real_worker_cap_v1.image_inference_profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('REAL_IMAGE_INFERENCE_BINDING_CHANGED',r.state,NULL);
  END IF;
  IF p_protected_pixel_digest IS NULL OR p_protected_pixel_digest !~ '^[0-9a-f]{64}$'
      OR p_training_rights_digest IS NULL OR p_training_rights_digest !~ '^[0-9a-f]{64}$'
      OR p_bundle_rights_digest IS NULL OR p_bundle_rights_digest !~ '^[0-9a-f]{64}$' THEN
    PERFORM fw_worker_cap_v1.deny('REAL_IMAGE_RIGHTS_BINDING',r.state,NULL);
  END IF;
  PERFORM fw_real_worker_cap_v1.real_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,p_protected_pixel_digest);
  PERFORM 1 FROM public.fw_rights_datasets WHERE workspace=r.workspace
    AND dataset_id::text=r.config->>'dataset_id' AND state='authenticated' FOR SHARE;
  IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('REAL_IMAGE_RIGHTS_CHANGED',r.state,NULL); END IF;
  PERFORM 1 FROM public.fw_rights_assets WHERE workspace=r.workspace
    AND dataset_id::text=r.config->>'dataset_id' AND member_id=r.config->>'member_id'
    AND rights_state='reviewed' AND asset_sha256=r.config->>'asset_sha256'
    AND asset_bytes=(r.config->>'asset_bytes')::bigint FOR SHARE;
  IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('REAL_IMAGE_RIGHTS_CHANGED',r.state,NULL); END IF;
  SELECT envelope INTO train FROM public.fw_rights_decisions WHERE workspace=r.workspace
    AND dataset_id::text=r.config->>'dataset_id' AND member_id=r.config->>'member_id'
    AND purpose='local_private_training' FOR SHARE;
  SELECT envelope INTO bundle FROM public.fw_rights_decisions WHERE workspace=r.workspace
    AND dataset_id::text=r.config->>'dataset_id' AND member_id=r.config->>'member_id'
    AND purpose='model_bundle' FOR SHARE;
  IF train IS NULL OR bundle IS NULL
      OR pg_catalog.encode(pg_catalog.sha256(train),'hex')<>p_training_rights_digest
      OR pg_catalog.encode(pg_catalog.sha256(bundle),'hex')<>p_bundle_rights_digest THEN
    PERFORM fw_worker_cap_v1.deny('REAL_IMAGE_RIGHTS_CHANGED',r.state,NULL);
  END IF;
  RETURN fw_real_worker_cap_v1.complete_real_inference(p_token,p_run,p_attempt,p_fence,
    p_generation,p_restore,p_receipt,p_owner_pid,p_owner_created,p_child_exited);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.complete_real_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text) OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.complete_real_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text) FROM PUBLIC;

-- Extend only the image-specific admission branch at existing fixed capability
-- boundaries. CREATE OR REPLACE preserves function owners and explicit ACLs.
DO $patch$
DECLARE definition text; pattern text; replacement text; patched text; proc regprocedure;
BEGIN
  pattern := 'fw_real_worker_cap_v1[.]inference_profile_ok\(r[.]config,\s*r[.]workspace,\s*r[.]actor\)';
  replacement := '(fw_real_worker_cap_v1.inference_profile_ok(r.config,r.workspace,r.actor) OR fw_real_worker_cap_v1.image_inference_profile_ok(r.config,r.workspace,r.actor))';
  FOREACH proc IN ARRAY ARRAY[
    'fw_real_worker_cap_v1.next_real_run(text[])'::regprocedure,
    'fw_real_worker_cap_v1.claim_real(text,text,integer,double precision,text)'::regprocedure,
    'fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid)'::regprocedure,
    'fw_real_worker_cap_v1.complete_real_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean)'::regprocedure
  ] LOOP
    definition := pg_catalog.pg_get_functiondef(proc);
    patched := pg_catalog.regexp_replace(definition,pattern,replacement,'g');
    IF patched=definition THEN RAISE EXCEPTION 'FW009_PROFILE_PATCH_NOT_FOUND %',proc; END IF;
    -- The existing one-sample helper dispatches to the new private upload
    -- capability only for the fresh-image scope; old manifest inference remains
    -- byte-for-byte in its original branch.
    IF proc='fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid)'::regprocedure THEN
      definition := patched;
      patched := pg_catalog.regexp_replace(patched,
        'BEGIN[[:space:]]+SELECT \* INTO r FROM public[.]fw_runs WHERE id=p_run',
        'BEGIN IF fw_real_worker_cap_v1.image_inference_profile_ok((SELECT config FROM public.fw_runs WHERE id=p_run), (SELECT workspace FROM public.fw_runs WHERE id=p_run), (SELECT actor FROM public.fw_runs WHERE id=p_run)) THEN RETURN fw_real_worker_cap_v1.real_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,NULL); END IF; SELECT * INTO r FROM public.fw_runs WHERE id=p_run');
      IF patched=definition THEN RAISE EXCEPTION 'FW009_INPUT_DISPATCH_PATCH_NOT_FOUND'; END IF;
    END IF;
    -- Correct the public event scope while preserving the prior exact result
    -- validation, child-exit fence, completion and legacy inference behavior.
    IF proc='fw_real_worker_cap_v1.complete_real_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean)'::regprocedure THEN
      patched := replace(patched,'''scope'',''real-inference/v1''','''scope'',r.config->>''scope''');
    END IF;
    EXECUTE patched;
  END LOOP;

  -- The 007 recipe digest remains unchanged. Accept its historic preprocessing
  -- digest as well as the current one so previously recorded run lineage remains
  -- interpretable; new submissions always bind the current source digest.
  pattern := 'p_config->>''preprocess_digest''\s*=\s*''e5b19df9fa39a01dd178e78d5efbd12a899983fad22ed3c7ff8d52643bc5ba44''';
  replacement := 'p_config->>''preprocess_digest'' IN (''e5b19df9fa39a01dd178e78d5efbd12a899983fad22ed3c7ff8d52643bc5ba44'',''1392785edc35eef504d62e4d9b90bb6aa438127d52e83869853b4eb8ebd34d92'')';
  proc := 'fw_real_worker_cap_v1.profile_ok(jsonb,text,text)'::regprocedure;
  definition := pg_catalog.pg_get_functiondef(proc);
  patched := pg_catalog.regexp_replace(definition,pattern,replacement,'g');
  IF patched=definition THEN RAISE EXCEPTION 'FW009_TRAINING_PREPROCESS_PATCH_NOT_FOUND'; END IF;
  EXECUTE patched;

  proc := 'fw_real_worker_cap_v1.inference_profile_ok(jsonb,text,text)'::regprocedure;
  definition := pg_catalog.pg_get_functiondef(proc);
  patched := pg_catalog.regexp_replace(definition,pattern,replacement,'g');
  IF patched=definition THEN RAISE EXCEPTION 'FW009_INFERENCE_PREPROCESS_PATCH_NOT_FOUND'; END IF;
  pattern := 'a[.]role IN \(''owner'',''researcher''\)';
  replacement := 'a.role IN (''owner'',''researcher'',''reviewer'')';
  patched := pg_catalog.regexp_replace(patched,pattern,replacement,'g');
  IF position('reviewer' in patched)=0 THEN RAISE EXCEPTION 'FW009_INFERENCE_REVIEWER_PATCH_NOT_FOUND'; END IF;
  EXECUTE patched;
END
$patch$;

DO $grant$
DECLARE principal text;
BEGIN
  FOR principal IN SELECT s.principal FROM fw_worker_cap_v1.scope AS s LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.real_image_inference_input(text,text,text,integer,integer,uuid,text) TO %I',principal);
    EXECUTE format('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.complete_real_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text) TO %I',principal);
  END LOOP;
END
$grant$;

COMMIT;
