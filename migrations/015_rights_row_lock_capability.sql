-- Narrow UPDATE privilege required by SELECT ... FOR SHARE in migration 012.
-- The capability columns are inert, and an unconditional trigger rejects every
-- attempt to update them. Business columns, table ACLs, and RLS stay unchanged.
BEGIN;

DO $preflight$
DECLARE t text;
BEGIN
  IF pg_catalog.to_regrole('fieldwork_real_worker_definer') IS NULL THEN
    RAISE EXCEPTION 'FW015_DEFINER_ROLE_MISSING';
  END IF;
  FOREACH t IN ARRAY ARRAY['fw_rights_datasets','fw_rights_assets','fw_rights_decisions'] LOOP
    IF pg_catalog.to_regclass('public.'||t) IS NULL THEN
      RAISE EXCEPTION 'FW015_RIGHTS_TABLE_MISSING';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name=t AND column_name='row_lock_capability') THEN
      RAISE EXCEPTION 'FW015_CAPABILITY_COLUMN_ALREADY_EXISTS';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_trigger tr
        WHERE tr.tgrelid=pg_catalog.to_regclass('public.'||t)
          AND NOT tr.tgisinternal AND tr.tgname='fw015_reject_row_lock_capability') THEN
      RAISE EXCEPTION 'FW015_GUARD_TRIGGER_ALREADY_EXISTS';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c
        WHERE c.oid=pg_catalog.to_regclass('public.'||t)
          AND c.relrowsecurity AND c.relforcerowsecurity) THEN
      RAISE EXCEPTION 'FW015_RIGHTS_RLS_POSTURE_CHANGED';
    END IF;
  END LOOP;
  IF pg_catalog.to_regprocedure('public.fw015_reject_row_lock_capability_mutation()') IS NOT NULL THEN
    RAISE EXCEPTION 'FW015_GUARD_FUNCTION_ALREADY_EXISTS';
  END IF;
END
$preflight$;

ALTER TABLE public.fw_rights_datasets
  ADD COLUMN row_lock_capability boolean NOT NULL DEFAULT false;
ALTER TABLE public.fw_rights_assets
  ADD COLUMN row_lock_capability boolean NOT NULL DEFAULT false;
ALTER TABLE public.fw_rights_decisions
  ADD COLUMN row_lock_capability boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN public.fw_rights_datasets.row_lock_capability IS
  'Inert capability column for scoped FOR SHARE privilege; all updates are rejected.';
COMMENT ON COLUMN public.fw_rights_assets.row_lock_capability IS
  'Inert capability column for scoped FOR SHARE privilege; all updates are rejected.';
COMMENT ON COLUMN public.fw_rights_decisions.row_lock_capability IS
  'Inert capability column for scoped FOR SHARE privilege; all updates are rejected.';

CREATE FUNCTION public.fw015_reject_row_lock_capability_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
  RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='FW015_ROW_LOCK_CAPABILITY_IMMUTABLE';
END
$guard$;
ALTER FUNCTION public.fw015_reject_row_lock_capability_mutation() OWNER TO fieldwork;
REVOKE ALL ON FUNCTION public.fw015_reject_row_lock_capability_mutation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fw015_reject_row_lock_capability_mutation()
  TO fieldwork_real_worker_definer;

GRANT UPDATE (row_lock_capability) ON public.fw_rights_datasets
  TO fieldwork_real_worker_definer;
GRANT UPDATE (row_lock_capability) ON public.fw_rights_assets
  TO fieldwork_real_worker_definer;
GRANT UPDATE (row_lock_capability) ON public.fw_rights_decisions
  TO fieldwork_real_worker_definer;

CREATE TRIGGER fw015_reject_row_lock_capability
  BEFORE UPDATE OF row_lock_capability ON public.fw_rights_datasets
  FOR EACH ROW EXECUTE FUNCTION public.fw015_reject_row_lock_capability_mutation();
CREATE TRIGGER fw015_reject_row_lock_capability
  BEFORE UPDATE OF row_lock_capability ON public.fw_rights_assets
  FOR EACH ROW EXECUTE FUNCTION public.fw015_reject_row_lock_capability_mutation();
CREATE TRIGGER fw015_reject_row_lock_capability
  BEFORE UPDATE OF row_lock_capability ON public.fw_rights_decisions
  FOR EACH ROW EXECUTE FUNCTION public.fw015_reject_row_lock_capability_mutation();

COMMIT;
