BEGIN;

-- Migration 017 added a privacy tombstone trigger to fw_runs. The legacy
-- security-definer start function is owned by fw_worker_v1_definer, which must
-- be allowed to call the narrow boolean guard while the trigger runs. Grant
-- only this function to that NOLOGIN definer; do not grant it to the scoped
-- login or add any table privileges.
DO $preflight$
DECLARE
  role_ok boolean;
  start_owner text;
  guard_owner text;
  guard_secdef boolean;
  guard_config text[];
  guard_public_execute boolean;
BEGIN
  SELECT (NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
          AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication
          AND NOT r.rolinherit)
    INTO role_ok
    FROM pg_catalog.pg_roles r
   WHERE r.rolname='fw_worker_v1_definer';
  IF role_ok IS DISTINCT FROM true THEN
    RAISE EXCEPTION '018_EXPECTED_NOLOGIN_WORKER_DEFINER';
  END IF;

  SELECT pg_catalog.pg_get_userbyid(p.proowner)
    INTO start_owner
    FROM pg_catalog.pg_proc p
   WHERE p.oid=pg_catalog.to_regprocedure(
     'fw_worker_cap_v1.start(text,text,text,integer,integer,text,uuid,text)');
  IF start_owner IS DISTINCT FROM 'fw_worker_v1_definer' THEN
    RAISE EXCEPTION '018_WORKER_START_OWNER_MISMATCH';
  END IF;

  SELECT pg_catalog.pg_get_userbyid(p.proowner),p.prosecdef,p.proconfig,
         EXISTS (
           SELECT 1
             FROM pg_catalog.aclexplode(COALESCE(
               p.proacl,pg_catalog.acldefault('f',p.proowner))) a
            WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
    INTO guard_owner,guard_secdef,guard_config,guard_public_execute
    FROM pg_catalog.pg_proc p
   WHERE p.oid=pg_catalog.to_regprocedure('public.fw_privacy_workspace_deleted_v1(text)');
  IF guard_owner IS DISTINCT FROM 'fieldwork' OR guard_secdef IS DISTINCT FROM true
     OR guard_config IS DISTINCT FROM ARRAY['search_path=pg_catalog, public']::text[]
     OR guard_public_execute IS DISTINCT FROM false THEN
    RAISE EXCEPTION '018_PRIVACY_GUARD_IDENTITY_MISMATCH';
  END IF;

  IF pg_catalog.has_function_privilege('fw_worker_v1_definer',
       'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') THEN
    RAISE EXCEPTION '018_PRIVACY_GUARD_GRANT_ALREADY_PRESENT';
  END IF;
  IF NOT pg_catalog.has_function_privilege('fieldwork_real_worker_definer',
       'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
     OR NOT pg_catalog.has_function_privilege('fieldwork_api',
       'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') THEN
    RAISE EXCEPTION '018_EXISTING_PRIVACY_GUARDS_DRIFTED';
  END IF;
END
$preflight$;

GRANT EXECUTE ON FUNCTION public.fw_privacy_workspace_deleted_v1(text)
  TO fw_worker_v1_definer;

DO $postcheck$
BEGIN
  IF NOT pg_catalog.has_function_privilege('fw_worker_v1_definer',
       'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
     OR NOT pg_catalog.has_function_privilege('fieldwork_real_worker_definer',
       'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
     OR NOT pg_catalog.has_function_privilege('fieldwork_api',
       'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
     OR EXISTS (
       SELECT 1 FROM pg_catalog.aclexplode((
         SELECT COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))
           FROM pg_catalog.pg_proc p
          WHERE p.oid=pg_catalog.to_regprocedure('public.fw_privacy_workspace_deleted_v1(text)')))
        WHERE grantee=0 AND privilege_type='EXECUTE') THEN
    RAISE EXCEPTION '018_PRIVACY_GUARD_POSTCONDITION_FAILED';
  END IF;
END
$postcheck$;

COMMIT;
