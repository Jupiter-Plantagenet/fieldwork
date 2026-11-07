-- A completed batch may contain only pre-decode refusals (bad names, archive
-- members or unsupported files). Such a batch has a complete hashed report but
-- no decoder invocation. Require a decoder for accepted images; retain every
-- identity, terminal-result, counter and report requirement from migration 006.
-- Applied migration 006 is immutable and is not rewritten.
BEGIN;
CREATE OR REPLACE FUNCTION fw_intake_cap_v1.batch_guard() RETURNS trigger
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
     ((NEW.decoder IS NULL AND coalesce(NEW.accepted,0)>0)
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
REVOKE ALL ON FUNCTION fw_intake_cap_v1.batch_guard() FROM PUBLIC;
COMMIT;
