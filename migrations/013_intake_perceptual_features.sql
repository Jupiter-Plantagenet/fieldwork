-- Persist only fixed-decoder features produced for samples accepted by the
-- currently fenced real-intake job. Existing sample/version rows are untouched.
BEGIN;

CREATE TABLE public.fw_sample_perceptual_features (
  workspace text NOT NULL,
  sample_id uuid NOT NULL,
  algorithm text NOT NULL CHECK (algorithm='phash-dct64/v1'),
  hash_hex text NOT NULL CHECK (hash_hex ~ '^[0-9a-f]{16}$'),
  raw_sha256 text NOT NULL CHECK (raw_sha256 ~ '^[0-9a-f]{64}$'),
  pixel_sha256 text NOT NULL CHECK (pixel_sha256 ~ '^[0-9a-f]{64}$'),
  decoder text NOT NULL CHECK (decoder='fieldwork.decode/v2 pillow-13.0.0 numpy-2.5.4 exif-transpose rgb8 alpha-on-white phash-dct64/v1'),
  created_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace,sample_id,algorithm),
  FOREIGN KEY (workspace,sample_id) REFERENCES public.fw_samples(workspace,sample_id)
);

ALTER TABLE public.fw_sample_perceptual_features ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fw_sample_perceptual_features FORCE ROW LEVEL SECURITY;
CREATE POLICY fw_perceptual_feature_tenant ON public.fw_sample_perceptual_features
  USING (workspace=current_setting('fieldwork.workspace',true))
  WITH CHECK (workspace=current_setting('fieldwork.workspace',true));
CREATE POLICY fw_perceptual_feature_worker_scope ON public.fw_sample_perceptual_features
  AS RESTRICTIVE FOR SELECT TO fieldwork_intake_worker
  USING (workspace=current_setting('fieldwork.workspace',true)
         AND fw_intake_cap_v1.workspace_allowed(workspace));

CREATE FUNCTION fw_intake_cap_v1.publish_sample_phash(
  p_workspace text, p_sample_id uuid, p_raw_sha256 text, p_pixel_sha256 text,
  p_hash_hex text, p_decoder text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE
  v_intake_id uuid;
BEGIN
  IF session_user<>'fieldwork_intake_worker'
     OR NOT fw_intake_cap_v1.workspace_allowed(p_workspace)
     OR current_setting('fieldwork.workspace',true) IS DISTINCT FROM p_workspace THEN
    RAISE EXCEPTION 'FW_PHASH_CAPABILITY' USING ERRCODE='42501';
  END IF;
  v_intake_id := nullif(current_setting('fieldwork.intake_id',true),'')::uuid;
  IF v_intake_id IS NULL
     OR p_workspace IS NULL OR p_sample_id IS NULL
     OR p_decoder IS NULL OR p_hash_hex IS NULL
     OR p_raw_sha256 IS NULL OR p_pixel_sha256 IS NULL
     OR p_decoder<>'fieldwork.decode/v2 pillow-13.0.0 numpy-2.5.4 exif-transpose rgb8 alpha-on-white phash-dct64/v1'
     OR p_hash_hex !~ '^[0-9a-f]{16}$'
     OR p_raw_sha256 !~ '^[0-9a-f]{64}$'
     OR p_pixel_sha256 !~ '^[0-9a-f]{64}$'
     OR NOT EXISTS (
       SELECT 1
       FROM public.fw_real_intake_queue q
       JOIN public.fw_intake_batches b ON b.workspace=q.workspace
       JOIN public.fw_samples s ON s.workspace=b.workspace AND s.first_batch=b.batch_id
       WHERE q.workspace=p_workspace AND q.intake_id=v_intake_id AND q.state='running'
         AND q.lease_until>clock_timestamp()
         AND b.source_intake_id=q.intake_id AND b.state='staging'
         AND s.sample_id=p_sample_id AND s.raw_sha256=p_raw_sha256
         AND s.pixel_sha256=p_pixel_sha256
     ) THEN
    RAISE EXCEPTION 'FW_PHASH_BINDING_OR_LEASE' USING ERRCODE='42501';
  END IF;
  INSERT INTO public.fw_sample_perceptual_features
    (workspace,sample_id,algorithm,hash_hex,raw_sha256,pixel_sha256,decoder)
  VALUES (p_workspace,p_sample_id,'phash-dct64/v1',p_hash_hex,p_raw_sha256,p_pixel_sha256,p_decoder);
END
$fn$;
REVOKE ALL ON FUNCTION fw_intake_cap_v1.publish_sample_phash(text,uuid,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fw_intake_cap_v1.publish_sample_phash(text,uuid,text,text,text,text)
  TO fieldwork_intake_worker;
GRANT USAGE ON SCHEMA fw_intake_cap_v1 TO fieldwork_intake_worker;
GRANT SELECT ON public.fw_sample_perceptual_features TO fieldwork_api;
-- The worker checks whether a canonical sample already has a feature before
-- entering the narrow repair path. Its SELECT remains tenant- and capability-
-- restricted by both policies above; it receives no direct write privilege.
GRANT SELECT ON public.fw_sample_perceptual_features TO fieldwork_intake_worker;
REVOKE ALL ON public.fw_sample_perceptual_features FROM PUBLIC;

-- Narrow repair path for an old canonical sample that is re-submitted with the
-- exact same raw member under a current rights-reviewed intake lease. The
-- application worker additionally verifies the signed member rights decision
-- before calling this function; this function binds that call to the current
-- queue/batch and the immutable canonical row. It cannot target pixel-only
-- duplicates or caller-selected media paths.
CREATE FUNCTION fw_intake_cap_v1.repair_sample_phash(
  p_workspace text, p_sample_id uuid, p_raw_sha256 text, p_raw_bytes bigint,
  p_pixel_sha256 text, p_hash_hex text, p_decoder text,
  p_source_member text, p_rights_dataset_id text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE
  v_intake_id uuid;
BEGIN
  IF session_user<>'fieldwork_intake_worker'
     OR NOT fw_intake_cap_v1.workspace_allowed(p_workspace)
     OR current_setting('fieldwork.workspace',true) IS DISTINCT FROM p_workspace THEN
    RAISE EXCEPTION 'FW_PHASH_CAPABILITY' USING ERRCODE='42501';
  END IF;
  v_intake_id := nullif(current_setting('fieldwork.intake_id',true),'')::uuid;
  IF v_intake_id IS NULL OR p_sample_id IS NULL OR p_raw_sha256 IS NULL
     OR p_raw_bytes IS NULL OR p_pixel_sha256 IS NULL OR p_hash_hex IS NULL
     OR p_decoder IS NULL OR p_source_member IS NULL OR p_rights_dataset_id IS NULL
     OR p_decoder<>'fieldwork.decode/v2 pillow-13.0.0 numpy-2.5.4 exif-transpose rgb8 alpha-on-white phash-dct64/v1'
     OR p_raw_sha256 !~ '^[0-9a-f]{64}$' OR p_pixel_sha256 !~ '^[0-9a-f]{64}$'
     OR p_hash_hex !~ '^[0-9a-f]{16}$'
     OR NOT EXISTS (
       SELECT 1
       FROM public.fw_real_intake_queue q
       JOIN public.fw_intake_batches b ON b.workspace=q.workspace
       JOIN public.fw_samples s ON s.workspace=q.workspace
       WHERE q.workspace=p_workspace AND q.intake_id=v_intake_id
         AND q.state='running' AND q.lease_until>clock_timestamp()
         AND b.source_intake_id=q.intake_id AND b.state='staging'
         AND b.archive_sha256=q.archive_sha256 AND b.archive_bytes=q.archive_bytes
         AND b.actor=q.actor AND b.rights_dataset_id=q.rights_dataset_id
         AND q.rights_dataset_id=p_rights_dataset_id
         AND s.sample_id=p_sample_id AND s.raw_sha256=p_raw_sha256
         AND s.raw_bytes=p_raw_bytes AND s.pixel_sha256=p_pixel_sha256
         AND s.source_member=p_source_member
         AND s.rights_dataset_id=p_rights_dataset_id
         AND NOT EXISTS (
           SELECT 1 FROM public.fw_sample_perceptual_features f
           WHERE f.workspace=s.workspace AND f.sample_id=s.sample_id
             AND f.algorithm='phash-dct64/v1')
     ) THEN
    RAISE EXCEPTION 'FW_PHASH_REPAIR_BINDING_OR_LEASE' USING ERRCODE='42501';
  END IF;
  INSERT INTO public.fw_sample_perceptual_features
    (workspace,sample_id,algorithm,hash_hex,raw_sha256,pixel_sha256,decoder)
  VALUES (p_workspace,p_sample_id,'phash-dct64/v1',p_hash_hex,p_raw_sha256,p_pixel_sha256,p_decoder);
END
$fn$;
REVOKE ALL ON FUNCTION fw_intake_cap_v1.repair_sample_phash(text,uuid,text,bigint,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fw_intake_cap_v1.repair_sample_phash(text,uuid,text,bigint,text,text,text,text,text)
  TO fieldwork_intake_worker;

CREATE FUNCTION fw_intake_cap_v1.reject_perceptual_feature_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
  RAISE EXCEPTION 'FW_PERCEPTUAL_FEATURE_IMMUTABLE' USING ERRCODE='42501';
END
$fn$;
CREATE TRIGGER fw_perceptual_feature_immutable
  BEFORE UPDATE OR DELETE ON public.fw_sample_perceptual_features
  FOR EACH ROW EXECUTE FUNCTION fw_intake_cap_v1.reject_perceptual_feature_mutation();
REVOKE ALL ON FUNCTION fw_intake_cap_v1.reject_perceptual_feature_mutation() FROM PUBLIC;

COMMIT;
