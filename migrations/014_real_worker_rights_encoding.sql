-- Forward-only repair for live 007/012 capability runtime defects.
-- Migration 007/012 bytes remain unchanged. Rights facts, signatures, membership,
-- frozen-version, plan, split and fence checks are retained exactly; only explicit
-- text/UUID comparison and PostgreSQL base64 line-wrapping are corrected.
BEGIN;

CREATE OR REPLACE FUNCTION fw_real_worker_cap_v1.real_inputs(
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
      'rights_envelope_b64',pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(envelope,'base64'),pg_catalog.chr(10),''),pg_catalog.chr(13),''),
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

CREATE OR REPLACE FUNCTION fw_real_worker_cap_v1.qualified_image_inference_input(
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
    AND dataset_id=i.dataset_id::text AND member_id=i.member_id AND rights_state='reviewed'
    AND asset_sha256=i.asset_sha256 AND asset_bytes=i.asset_bytes;
  SELECT envelope INTO train FROM public.fw_rights_decisions WHERE workspace=r.workspace
    AND dataset_id=i.dataset_id::text AND member_id=i.member_id AND purpose='local_private_training';
  SELECT envelope INTO bundle FROM public.fw_rights_decisions WHERE workspace=r.workspace
    AND dataset_id=i.dataset_id::text AND member_id=i.member_id AND purpose='model_bundle';
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
    'training_rights_envelope_b64',pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(train,'base64'),pg_catalog.chr(10),''),pg_catalog.chr(13),''),
    'bundle_rights_envelope_b64',pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(bundle,'base64'),pg_catalog.chr(10),''),pg_catalog.chr(13),''),
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

COMMIT;
