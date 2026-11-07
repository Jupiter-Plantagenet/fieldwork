-- Forward-only repair for strict Python decoders consuming signed rights envelopes.
-- The three training/bundle functions preserve 007. real_inference_input preserves
-- the applied 009 image and 012 qualified dispatch/profile extensions. Only base64
-- line wrapping is removed; rights, scope, plan, lease, token, split, fence, owner,
-- ACL, and profile checks are retained.
BEGIN;

CREATE OR REPLACE FUNCTION fw_real_worker_cap_v1.real_member_rights(
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
    'asset_bytes',ra.asset_bytes,'rights_envelope_b64',pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(rd.envelope,'base64'),pg_catalog.chr(10),''),pg_catalog.chr(13),''),
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

CREATE OR REPLACE FUNCTION fw_real_worker_cap_v1.real_bundle_rights(
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
      'rights_envelope_b64',pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(envelope,'base64'),pg_catalog.chr(10),''),pg_catalog.chr(13),''),
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

CREATE OR REPLACE FUNCTION fw_real_worker_cap_v1.real_artifact_rights(
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
      'rights_envelope_b64',pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(envelope,'base64'),pg_catalog.chr(10),''),pg_catalog.chr(13),''),
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

CREATE OR REPLACE FUNCTION fw_real_worker_cap_v1.real_inference_input(
  p_token text,p_run text,p_attempt text,p_fence integer,p_generation integer,p_restore uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE r public.fw_runs; source_run public.fw_runs; v public.fw_versions; picked jsonb;
BEGIN IF fw_real_worker_cap_v1.qualified_image_profile_ok((SELECT config FROM public.fw_runs WHERE id=p_run), (SELECT workspace FROM public.fw_runs WHERE id=p_run), (SELECT actor FROM public.fw_runs WHERE id=p_run)) THEN RETURN fw_real_worker_cap_v1.qualified_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,NULL); END IF; IF fw_real_worker_cap_v1.image_inference_profile_ok((SELECT config FROM public.fw_runs WHERE id=p_run), (SELECT workspace FROM public.fw_runs WHERE id=p_run), (SELECT actor FROM public.fw_runs WHERE id=p_run)) THEN RETURN fw_real_worker_cap_v1.real_image_inference_input(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,NULL); END IF; SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace);
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
  IF NOT (fw_real_worker_cap_v1.inference_profile_ok(r.config,r.workspace,r.actor) OR fw_real_worker_cap_v1.image_inference_profile_ok(r.config,r.workspace,r.actor)) THEN
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
    'training_rights_envelope_b64',pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(training_envelope,'base64'),pg_catalog.chr(10),''),pg_catalog.chr(13),''),
    'bundle_rights_envelope_b64',pg_catalog.replace(pg_catalog.replace(pg_catalog.encode(bundle_envelope,'base64'),pg_catalog.chr(10),''),pg_catalog.chr(13),''),
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

COMMIT;
