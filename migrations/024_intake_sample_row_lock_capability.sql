-- 2026-11-03 completion pass. Narrow UPDATE privilege required by the intake worker's duplicate lookup
-- (fieldwork/intake.py: SELECT ... FROM fw_samples ... FOR UPDATE). Row-locking clauses need UPDATE privilege on at
-- least one column; fieldwork_intake_worker only had SELECT,INSERT (migration 006), so every intake that met an
-- already-imported image failed with INSUFFICIENTPRIVILEGE. Same pattern as migration 015: one inert capability
-- column, UPDATE granted on that column only, and an unconditional trigger rejecting every update of it.
-- Business columns, table ACLs and RLS stay unchanged.
BEGIN;

DO $preflight$
BEGIN
  IF pg_catalog.to_regrole('fieldwork_intake_worker') IS NULL OR pg_catalog.to_regclass('public.fw_samples') IS NULL THEN
    RAISE EXCEPTION 'FW024_PREREQUISITES_MISSING';
  END IF;
  IF pg_catalog.to_regprocedure('public.fw015_reject_row_lock_capability_mutation()') IS NULL THEN
    RAISE EXCEPTION 'FW024_REQUIRES_015_GUARD';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='fw_samples' AND column_name='row_lock_capability') THEN
    RAISE EXCEPTION 'FW024_CAPABILITY_COLUMN_ALREADY_EXISTS';
  END IF;
  IF has_table_privilege('fieldwork_intake_worker','public.fw_samples','UPDATE') THEN
    RAISE EXCEPTION 'FW024_UNEXPECTED_TABLE_LEVEL_UPDATE';
  END IF;
END
$preflight$;

ALTER TABLE public.fw_samples ADD COLUMN row_lock_capability boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN public.fw_samples.row_lock_capability IS
  'Inert capability column for the intake worker''s FOR UPDATE duplicate lookup; all updates are rejected.';

GRANT EXECUTE ON FUNCTION public.fw015_reject_row_lock_capability_mutation() TO fieldwork_intake_worker;
GRANT UPDATE (row_lock_capability) ON public.fw_samples TO fieldwork_intake_worker;

CREATE TRIGGER fw024_reject_row_lock_capability
  BEFORE UPDATE OF row_lock_capability ON public.fw_samples
  FOR EACH ROW EXECUTE FUNCTION public.fw015_reject_row_lock_capability_mutation();

COMMIT;
