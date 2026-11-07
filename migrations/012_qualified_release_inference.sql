-- Qualified R5 model delivery and inference. Forward-only; do not edit/apply
-- 007-011. This scope is bound to the fixed local operator registry and the
-- exact consumed plan/result/model digests. It does not resolve a run-owned
-- private candidate bundle.
BEGIN;

DO $preflight$
BEGIN
  IF to_regclass('public.fw_runs') IS NULL OR to_regclass('public.fw_real_image_inputs') IS NULL
     OR to_regclass('public.fw_holdout_plans') IS NULL OR to_regnamespace('fw_real_worker_cap_v1') IS NULL
     OR to_regprocedure('fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid)') IS NULL
     OR to_regprocedure('fw_real_worker_cap_v1.complete_real_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean)') IS NULL
     OR to_regprocedure('public.fw_workspace_run_admission_v1()') IS NULL THEN
    RAISE EXCEPTION 'FW012_PREREQUISITES_REQUIRED';
  END IF;
END
$preflight$;

-- Allow the existing worker definer to read only the consumed-plan identity
-- columns required for point-of-use binding. Existing tenant policy remains;
-- this added policy is limited to its registered workspace allowlist.
GRANT SELECT (workspace,plan_id,version_id,version_digest,candidate_model_digest,
              state,consumed_utc,exposures,result_sha256)
  ON public.fw_holdout_plans TO fieldwork_real_worker_definer;
CREATE POLICY fw_real_worker_qualified_plan ON public.fw_holdout_plans
  TO fieldwork_real_worker_definer USING (fw_worker_cap_v1.allowed(workspace));

CREATE FUNCTION fw_real_worker_cap_v1.qualified_image_profile_ok(
    p_config jsonb,p_workspace text,p_actor text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT (CASE WHEN coalesce(pg_catalog.jsonb_typeof(p_config),'')<>'object' THEN false ELSE
    p_config->>'profile_schema'='fieldwork.real-run-profile/v1'
    AND p_config->>'scope'='qualified-release-image-inference/v1'
    AND p_config->>'operation'='infer-qualified-image'
    AND p_config->>'workspace'=p_workspace AND p_config->>'actor'=p_actor
    AND p_workspace='814830e3-55a0-4925-ad37-5d3dac7d4df8'
    AND p_config->>'release_id'='flowers-r5-small-residual-v1'
    AND p_config->>'plan_id'='9252ee17-1e80-4159-8dbf-b3f77d2bb674'
    AND p_config->>'plan_result_sha256'='6686d29ef0d2b6aa792bdc06508a84d3fdf9e4caa3a7b16165aae1b10cb4256c'
    AND p_config->>'result_record_sha256'='55d321a06bde245735126ecde5ff1047f779d8d8429591d84b9015a77cbaac6d'
    AND p_config->>'model_digest'='c5b41d6a12cd2473abac7628ca23aa3abe6afad8304e21164fece14d58c16bde'
    AND p_config->>'bundle_digest'='cf5c88be9addebcf1ade349710494464611e14e1627d44351116ce7a55b6742d'
    AND p_config->>'version_id'='553eec3b-7173-442a-b99d-995ca63c18a5'
    AND p_config->>'version_digest'='a298b6e702310a224370b21213edfb0925e005dd176ed98f177f31ad844c58f8'
    AND p_config->>'dataset_id'='0ad2719a-2319-418b-b072-ba8ce310a997'
    AND p_config->>'sample_split'='upload'
    AND p_config->>'preprocess'='short-edge144-rgb-v1'
    AND p_config->>'preprocess_digest'='865d7ea9790301672bbbbe61f73fa4653878f17c8eec4814ae75a80c51c59d76'
    AND (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_config))=24
    AND (p_config-ARRAY['profile_schema','scope','operation','workspace','actor','release_id','plan_id',
      'plan_result_sha256','result_record_sha256','model_digest','bundle_digest','version_id','version_digest',
      'dataset_id','member_id','asset_sha256','asset_bytes','input_id','sample_split','preprocess',
      'preprocess_digest','decoder_image_id','model_image_id','idempotency_key'])='{}'::jsonb
    AND p_config ?& ARRAY['release_id','plan_id','plan_result_sha256','result_record_sha256','model_digest',
      'bundle_digest','version_id','version_digest','dataset_id','member_id','asset_sha256','asset_bytes',
      'input_id','sample_split','preprocess','preprocess_digest','decoder_image_id','model_image_id','idempotency_key']
    AND p_config->>'version_digest' ~ '^[0-9a-f]{64}$'
    AND p_config->>'plan_result_sha256' ~ '^[0-9a-f]{64}$'
    AND p_config->>'result_record_sha256' ~ '^[0-9a-f]{64}$'
    AND p_config->>'model_digest' ~ '^[0-9a-f]{64}$'
    AND p_config->>'bundle_digest' ~ '^[0-9a-f]{64}$'
    AND p_config->>'asset_sha256' ~ '^[0-9a-f]{64}$'
    AND p_config->>'dataset_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND p_config->>'input_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND p_config->>'asset_bytes' ~ '^[1-9][0-9]{0,7}$'
    AND (p_config->>'asset_bytes')::bigint BETWEEN 1 AND 5242880
    AND pg_catalog.char_length(p_config->>'member_id') BETWEEN 1 AND 512
    AND p_config->>'decoder_image_id' ~ '^sha256:[0-9a-f]{64}$'
    AND p_config->>'model_image_id' ~ '^sha256:[0-9a-f]{64}$'
    AND pg_catalog.char_length(p_config->>'idempotency_key') BETWEEN 1 AND 128
    AND EXISTS (SELECT 1 FROM public.fw_accounts a WHERE a.workspace=p_workspace
      AND a.name=p_actor AND a.role IN ('owner','researcher','reviewer'))
    AND EXISTS (SELECT 1 FROM public.fw_holdout_plans hp WHERE hp.workspace=p_workspace
      AND hp.plan_id::text=p_config->>'plan_id' AND hp.state='consumed'
      AND hp.consumed_utc IS NOT NULL AND hp.exposures>=1
      AND hp.result_sha256=p_config->>'plan_result_sha256'
      AND hp.candidate_model_digest=p_config->>'model_digest'
      AND hp.version_id=p_config->>'version_id' AND hp.version_digest=p_config->>'version_digest')
    AND EXISTS (SELECT 1 FROM public.fw_versions v WHERE v.workspace=p_workspace
      AND v.id::text=p_config->>'version_id' AND v.state='frozen'
      AND v.manifest->>'scope'='real-rights-cleared'
      AND v.manifest->>'digest'=p_config->>'version_digest'
      AND v.manifest->>'rights_dataset_id'=p_config->>'dataset_id')
    AND EXISTS (SELECT 1 FROM public.fw_real_image_inputs i WHERE i.workspace=p_workspace
      AND i.run=(SELECT r.id FROM public.fw_runs r WHERE r.workspace=p_workspace AND r.actor=p_actor AND r.config=p_config LIMIT 1)
      AND i.input_id::text=p_config->>'input_id' AND i.upload_key::text=p_config->>'input_id'
      AND i.dataset_id::text=p_config->>'dataset_id' AND i.member_id=p_config->>'member_id'
      AND i.asset_sha256=p_config->>'asset_sha256' AND i.asset_bytes=(p_config->>'asset_bytes')::bigint)
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
  END) IS TRUE
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.qualified_image_profile_ok(jsonb,text,text)
  OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.qualified_image_profile_ok(jsonb,text,text) FROM PUBLIC;

-- Ordinary candidate inference is no longer a worker-selectable capability.
-- Existing rows remain readable as historical metadata, while only the separate
-- fixed qualified profile below can enter the inference child/complete path.
CREATE OR REPLACE FUNCTION fw_real_worker_cap_v1.inference_profile_ok(
    p_config jsonb,p_workspace text,p_actor text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT false
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.inference_profile_ok(jsonb,text,text)
  OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.inference_profile_ok(jsonb,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION fw_real_worker_cap_v1.image_inference_profile_ok(
    p_config jsonb,p_workspace text,p_actor text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT false
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.image_inference_profile_ok(jsonb,text,text)
  OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.image_inference_profile_ok(jsonb,text,text) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.qualified_image_inference_input(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid,
  p_pixel_digest text DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; i public.fw_real_image_inputs; a public.fw_rights_assets;
  train bytea; bundle bytea; protected boolean; picked jsonb;
  plan_id_value text; plan_result_value text; plan_model_value text;
  version_row public.fw_versions;
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
    PERFORM fw_worker_cap_v1.deny('QUALIFIED_PIXEL_IDENTITY_INVALID',r.state,NULL);
  END IF;
  IF NOT fw_real_worker_cap_v1.qualified_image_profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('QUALIFIED_IMAGE_INFERENCE_BINDING_CHANGED',r.state,NULL);
  END IF;
  SELECT plan_id::text,result_sha256,candidate_model_digest
    INTO plan_id_value,plan_result_value,plan_model_value
    FROM public.fw_holdout_plans WHERE workspace=r.workspace
    AND plan_id::text=r.config->>'plan_id' AND state='consumed' AND consumed_utc IS NOT NULL
    AND exposures>=1 AND result_sha256=r.config->>'plan_result_sha256'
    AND candidate_model_digest=r.config->>'model_digest'
    AND version_id=r.config->>'version_id' AND version_digest=r.config->>'version_digest';
  SELECT * INTO version_row FROM public.fw_versions WHERE workspace=r.workspace
    AND id::text=r.config->>'version_id' AND state='frozen'
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
  IF plan_id_value IS NULL OR version_row.id IS NULL OR i.run IS NULL OR a.member_id IS NULL
       OR train IS NULL OR bundle IS NULL THEN
    PERFORM fw_worker_cap_v1.deny('QUALIFIED_IMAGE_RIGHTS_NOT_READY',r.state,NULL);
  END IF;
  -- Membership is evaluated inside the definer and only a generic denial leaves
  -- it. No protected identifiers, labels, paths or aggregate are returned.
  SELECT EXISTS (SELECT 1 FROM public.fw_versions fv,
    LATERAL jsonb_path_query(fv.manifest,'$.samples[*]') q(item)
    WHERE fv.workspace=r.workspace AND fv.state='frozen'
      AND q.item->>'split' NOT IN ('train','validation')
      AND (q.item->>'source_member'=i.member_id OR q.item->>'sha256'=i.asset_sha256
        OR (p_pixel_digest IS NOT NULL AND q.item->>'pixel_sha256'=p_pixel_digest))) INTO protected;
  IF protected THEN PERFORM fw_worker_cap_v1.deny('OBJECT',r.state,NULL); END IF;
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
  RETURN jsonb_build_object('release_id',r.config->>'release_id','plan_id',plan_id_value,
    'plan_result_sha256',plan_result_value,'result_record_sha256',r.config->>'result_record_sha256',
    'model_digest',plan_model_value,'bundle_digest',r.config->>'bundle_digest',
    'version_id',version_row.id,'version_digest',version_row.manifest->>'digest',
    'dataset_id',i.dataset_id,'upload_key',i.upload_key,'actor_authorized',true,
    'protected_match',false,'sample',picked);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)
  OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text) FROM PUBLIC;

CREATE FUNCTION fw_real_worker_cap_v1.complete_qualified_image_inference(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid,
  p_receipt jsonb,p_owner_pid integer,p_owner_created double precision,p_child_exited boolean,
  p_protected_pixel_digest text,p_training_rights_digest text,p_bundle_rights_digest text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; train bytea; bundle bytea; compatible_receipt jsonb;
BEGIN
  SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
  IF NOT FOUND OR r.config->>'scope'<>'qualified-release-image-inference/v1'
      OR NOT fw_real_worker_cap_v1.qualified_image_profile_ok(r.config,r.workspace,r.actor) THEN
    PERFORM fw_worker_cap_v1.deny('QUALIFIED_IMAGE_INFERENCE_BINDING_CHANGED',r.state,NULL);
  END IF;
  IF p_protected_pixel_digest IS NULL OR p_protected_pixel_digest !~ '^[0-9a-f]{64}$'
      OR p_training_rights_digest IS NULL OR p_training_rights_digest !~ '^[0-9a-f]{64}$'
      OR p_bundle_rights_digest IS NULL OR p_bundle_rights_digest !~ '^[0-9a-f]{64}$' THEN
    PERFORM fw_worker_cap_v1.deny('QUALIFIED_IMAGE_RIGHTS_BINDING',r.state,NULL);
  END IF;
  IF pg_catalog.jsonb_typeof(p_receipt)<>'object'
      OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_receipt))<>8
      OR NOT (p_receipt ?& ARRAY['receipt_digest','release_id','plan_id','bundle_digest',
        'model_digest','sample_split','prediction','public_export_authorized'])
      OR (p_receipt-ARRAY['receipt_digest','release_id','plan_id','bundle_digest','model_digest',
        'sample_split','prediction','public_export_authorized'])<>'{}'::jsonb
      OR p_receipt->>'release_id' IS DISTINCT FROM r.config->>'release_id'
      OR p_receipt->>'plan_id' IS DISTINCT FROM r.config->>'plan_id'
      OR p_receipt->>'bundle_digest' IS DISTINCT FROM r.config->>'bundle_digest'
      OR p_receipt->>'model_digest' IS DISTINCT FROM r.config->>'model_digest'
      OR p_receipt->>'sample_split' IS DISTINCT FROM 'upload'
      OR pg_catalog.jsonb_typeof(p_receipt->'public_export_authorized')<>'boolean'
      OR p_receipt->'public_export_authorized'<>'false'::jsonb
      OR pg_catalog.jsonb_typeof(p_receipt->'prediction')<>'object'
      OR pg_catalog.jsonb_typeof(p_receipt->'receipt_digest')<>'string'
      OR p_receipt->>'receipt_digest' IS NULL
      OR p_receipt->>'receipt_digest' !~ '^[0-9a-f]{64}$' THEN
    PERFORM fw_worker_cap_v1.deny('QUALIFIED_INFERENCE_RECEIPT_INVALID',r.state,NULL);
  END IF;
  PERFORM fw_real_worker_cap_v1.qualified_image_inference_input(
    p_token,p_run,p_attempt,p_fence,p_generation,p_restore,p_protected_pixel_digest);
  PERFORM 1 FROM public.fw_rights_datasets WHERE workspace=r.workspace
    AND dataset_id::text=r.config->>'dataset_id' AND state='authenticated' FOR SHARE;
  IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('QUALIFIED_IMAGE_RIGHTS_CHANGED',r.state,NULL); END IF;
  PERFORM 1 FROM public.fw_rights_assets WHERE workspace=r.workspace
    AND dataset_id::text=r.config->>'dataset_id' AND member_id=r.config->>'member_id'
    AND rights_state='reviewed' AND asset_sha256=r.config->>'asset_sha256'
    AND asset_bytes=(r.config->>'asset_bytes')::bigint FOR SHARE;
  IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('QUALIFIED_IMAGE_RIGHTS_CHANGED',r.state,NULL); END IF;
  SELECT envelope INTO train FROM public.fw_rights_decisions WHERE workspace=r.workspace
    AND dataset_id::text=r.config->>'dataset_id' AND member_id=r.config->>'member_id'
    AND purpose='local_private_training' FOR SHARE;
  SELECT envelope INTO bundle FROM public.fw_rights_decisions WHERE workspace=r.workspace
    AND dataset_id::text=r.config->>'dataset_id' AND member_id=r.config->>'member_id'
    AND purpose='model_bundle' FOR SHARE;
  IF train IS NULL OR bundle IS NULL
      OR pg_catalog.encode(pg_catalog.sha256(train),'hex')<>p_training_rights_digest
      OR pg_catalog.encode(pg_catalog.sha256(bundle),'hex')<>p_bundle_rights_digest THEN
    PERFORM fw_worker_cap_v1.deny('QUALIFIED_IMAGE_RIGHTS_CHANGED',r.state,NULL);
  END IF;
  compatible_receipt := pg_catalog.jsonb_build_object(
    'receipt_digest',p_receipt->>'receipt_digest',
    'bundle_digest',r.config->>'bundle_digest',
    'version_digest',r.config->>'version_digest',
    'sample_split','upload', 'prediction',p_receipt->'prediction');
  RETURN fw_real_worker_cap_v1.complete_real_inference(p_token,p_run,p_attempt,p_fence,
    p_generation,p_restore,compatible_receipt,p_owner_pid,p_owner_created,p_child_exited);
END
$fn$;
ALTER FUNCTION fw_real_worker_cap_v1.complete_qualified_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text)
  OWNER TO fieldwork_real_worker_definer;
REVOKE ALL ON FUNCTION fw_real_worker_cap_v1.complete_qualified_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text) FROM PUBLIC;

-- Extend only the fixed profile branches at the existing capability boundaries.
DO $patch$
DECLARE definition text; patched text; pattern text; replacement text; proc regprocedure;
BEGIN
  pattern := 'fw_real_worker_cap_v1[.]image_inference_profile_ok\(r[.]config,\s*r[.]workspace,\s*r[.]actor\)';
  replacement := '(fw_real_worker_cap_v1.image_inference_profile_ok(r.config,r.workspace,r.actor) OR fw_real_worker_cap_v1.qualified_image_profile_ok(r.config,r.workspace,r.actor))';
  FOREACH proc IN ARRAY ARRAY[
    'fw_real_worker_cap_v1.next_real_run(text[])'::regprocedure,
    'fw_real_worker_cap_v1.claim_real(text,text,integer,double precision,text)'::regprocedure,
    'fw_real_worker_cap_v1.complete_real_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean)'::regprocedure
  ] LOOP
    definition := pg_catalog.pg_get_functiondef(proc);
    patched := pg_catalog.regexp_replace(definition,pattern,replacement,'g');
    IF patched=definition THEN RAISE EXCEPTION 'FW012_PROFILE_PATCH_NOT_FOUND %',proc; END IF;
    IF proc='fw_real_worker_cap_v1.complete_real_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean)'::regprocedure THEN
      definition := patched;
      patched := replace(patched,
        '''fence'',p_fence,''scope'',''real-inference/v1'',''receipt_digest''',
        '''fence'',p_fence,''scope'',r.config->>''scope'',''receipt_digest''');
      -- Migration 009 already converted this event to the dynamic run scope.
      -- Accept only that exact current form when the legacy literal is absent;
      -- refuse any third/unrecognized definition instead of skipping drift.
      IF position('''fence'',p_fence,''scope'',r.config->>''scope'',''receipt_digest''' in patched)=0 THEN
        RAISE EXCEPTION 'FW012_COMPLETION_SCOPE_EVENT_PATCH_NOT_FOUND';
      END IF;
    END IF;
    EXECUTE patched;
  END LOOP;

  proc := 'fw_real_worker_cap_v1.real_inference_input(text,text,text,integer,integer,uuid)'::regprocedure;
  definition := pg_catalog.pg_get_functiondef(proc);
  patched := replace(definition,
    'BEGIN IF fw_real_worker_cap_v1.image_inference_profile_ok((SELECT config FROM public.fw_runs WHERE id=p_run), (SELECT workspace FROM public.fw_runs WHERE id=p_run), (SELECT actor FROM public.fw_runs WHERE id=p_run)) THEN RETURN fw_real_worker_cap_v1.real_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,NULL); END IF; SELECT * INTO r FROM public.fw_runs WHERE id=p_run',
    'BEGIN IF fw_real_worker_cap_v1.qualified_image_profile_ok((SELECT config FROM public.fw_runs WHERE id=p_run), (SELECT workspace FROM public.fw_runs WHERE id=p_run), (SELECT actor FROM public.fw_runs WHERE id=p_run)) THEN RETURN fw_real_worker_cap_v1.qualified_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,NULL); END IF; IF fw_real_worker_cap_v1.image_inference_profile_ok((SELECT config FROM public.fw_runs WHERE id=p_run), (SELECT workspace FROM public.fw_runs WHERE id=p_run), (SELECT actor FROM public.fw_runs WHERE id=p_run)) THEN RETURN fw_real_worker_cap_v1.real_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,NULL); END IF; SELECT * INTO r FROM public.fw_runs WHERE id=p_run');
  IF patched=definition THEN RAISE EXCEPTION 'FW012_INPUT_DISPATCH_PATCH_NOT_FOUND'; END IF;
  EXECUTE patched;
END
$patch$;

-- Preserve the existing workspace admission and quota behavior while including
-- the new scope in both INSERT/update limits and active-run counts.
CREATE OR REPLACE FUNCTION public.fw_workspace_run_admission_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $fn$
DECLARE policy_row public.fw_workspace_settings; active_count integer; prior boolean;
        run_scope text; epoch_limit integer;
BEGIN
  run_scope := NEW.config->>'scope';
  IF run_scope IS NULL OR run_scope NOT IN ('real-training/v1','real-inference/v1',
      'real-image-inference/v1','qualified-release-image-inference/v1') THEN RETURN NEW; END IF;
  IF TG_OP='UPDATE' AND (NEW.state NOT IN ('queued','leased','running','cancel_requested')
       OR OLD.state IN ('queued','leased','running','cancel_requested')) THEN RETURN NEW; END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.workspace,0));
  IF TG_OP='INSERT' THEN
    SELECT EXISTS(SELECT 1 FROM public.fw_runs r WHERE r.workspace=NEW.workspace
      AND r.actor=NEW.actor AND r.idem=NEW.idem) INTO prior;
    IF prior THEN RETURN NEW; END IF;
  END IF;
  SELECT * INTO policy_row FROM public.fw_workspace_settings WHERE workspace=NEW.workspace;
  IF NOT FOUND THEN policy_row.max_concurrent_runs:=2; policy_row.max_epochs:=100; END IF;
  IF run_scope='real-training/v1' THEN
    epoch_limit:=nullif(NEW.config->>'epochs','')::integer;
    IF epoch_limit IS NULL OR epoch_limit>policy_row.max_epochs THEN
      RAISE EXCEPTION 'WORKSPACE_EPOCH_LIMIT' USING ERRCODE='P0001';
    END IF;
  END IF;
  SELECT count(*) INTO active_count FROM public.fw_runs r WHERE r.workspace=NEW.workspace
    AND r.config->>'scope' IN ('real-training/v1','real-inference/v1','real-image-inference/v1','qualified-release-image-inference/v1')
    AND r.state IN ('queued','leased','running','cancel_requested');
  IF active_count>=policy_row.max_concurrent_runs THEN
    RAISE EXCEPTION 'WORKSPACE_RUN_LIMIT' USING ERRCODE='P0001';
  END IF;
  RETURN NEW;
END
$fn$;

DO $grant$
DECLARE principal text;
BEGIN
  FOR principal IN SELECT s.principal FROM fw_worker_cap_v1.scope AS s LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text) TO %I',principal);
    EXECUTE format('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.complete_qualified_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text) TO %I',principal);
  END LOOP;
END
$grant$;

COMMIT;
