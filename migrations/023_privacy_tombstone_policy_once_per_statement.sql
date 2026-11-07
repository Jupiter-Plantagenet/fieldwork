-- 2026-11-03 completion pass. Performance only: the same rows are visible and writable as before.
--
-- Migration 017 created one RESTRICTIVE policy per table for fieldwork_api:
--     NOT public.fw_privacy_workspace_deleted_v1(workspace)
-- The function is SECURITY DEFINER with its own search_path, so PostgreSQL cannot inline it and calls it once per
-- row; a rights check over a 3,659-member dataset paid ~7,300 calls per request. Rewrite the predicate so that
-- for a row in the request's own workspace (the only rows the tenant policy lets fieldwork_api see) the tombstone
-- is read once per statement through an uncorrelated scalar subquery, and keep the original per-row call for any
-- other row. For every row both branches return exactly what the 017 predicate returned, because in the first
-- branch workspace = current_setting('fieldwork.workspace', true).
BEGIN;

DO $preflight$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM pg_policies
   WHERE schemaname='public' AND policyname LIKE 'fw_privacy_tombstone_fw_%' AND permissive='RESTRICTIVE'
     AND roles=ARRAY['fieldwork_api']::name[];
  IF n = 0 THEN
    RAISE EXCEPTION '023_PRIVACY_TOMBSTONE_POLICIES_REQUIRED';
  END IF;
END
$preflight$;

DO $rewrite$
DECLARE rel text;
DECLARE pred text := $p$(CASE WHEN workspace = current_setting('fieldwork.workspace', true)
      THEN NOT (SELECT public.fw_privacy_workspace_deleted_v1(current_setting('fieldwork.workspace', true)))
      ELSE NOT public.fw_privacy_workspace_deleted_v1(workspace) END)$p$;
BEGIN
  FOREACH rel IN ARRAY ARRAY['fw_runs','fw_events','fw_versions','fw_proposals','fw_samples',
    'fw_intake_batches','fw_intake_members','fw_real_intake_queue','fw_real_image_inputs',
    'fw_workspace_settings','fw_workspace_settings_events','fw_rights_datasets',
    'fw_rights_assets','fw_rights_decisions'] LOOP
    IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=rel
               AND policyname='fw_privacy_tombstone_'||rel) THEN
      EXECUTE format('DROP POLICY %I ON public.%I', 'fw_privacy_tombstone_'||rel, rel);
      EXECUTE format('CREATE POLICY %I ON public.%I AS RESTRICTIVE FOR ALL TO fieldwork_api USING %s WITH CHECK %s',
        'fw_privacy_tombstone_'||rel, rel, pred, pred);
    END IF;
  END LOOP;
END
$rewrite$;

COMMIT;
