BEGIN;

DO $migration$
DECLARE
    lease_owner_oid oid;
    lease_login_oid oid;
    lease_owner_login boolean;
    helper_owner text;
    helper_secdef boolean;
    helper_config text[];
    lease_source text;
    trigger_source text;
    guard_grantees text[];
    expire_acl text[];
BEGIN
    SELECT oid,rolcanlogin INTO lease_owner_oid,lease_owner_login
      FROM pg_catalog.pg_roles WHERE rolname='fw_lease_machine_v1_owner';
    SELECT oid INTO lease_login_oid
      FROM pg_catalog.pg_roles WHERE rolname='fw_lease_machine_v1';
    IF lease_owner_oid IS NULL OR lease_login_oid IS NULL OR lease_owner_login THEN
        RAISE EXCEPTION '019_LEASE_CAPABILITY_ROLE_PRECONDITION';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles r
        WHERE r.oid IN (lease_owner_oid,lease_login_oid)
          AND (r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole
               OR r.rolreplication)
    ) THEN
        RAISE EXCEPTION '019_LEASE_CAPABILITY_ROLE_FLAGS_PRECONDITION';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members m
        WHERE m.roleid IN (lease_owner_oid,lease_login_oid)
           OR m.member IN (lease_owner_oid,lease_login_oid)
    ) THEN
        RAISE EXCEPTION '019_LEASE_CAPABILITY_MEMBERSHIP_PRECONDITION';
    END IF;

    SELECT p.prosrc INTO lease_source
      FROM pg_catalog.pg_proc p
      WHERE p.oid='fw_lease_cap_v1.expire(text,integer,integer,text)'::regprocedure
        AND pg_catalog.pg_get_userbyid(p.proowner)='fw_lease_machine_v1_owner'
        AND p.prosecdef
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[];
    IF lease_source IS NULL
       OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(lease_source,'UTF8')),'hex')
          <> '6cc6b7bc1dfabb6dd7ce3d26a4206e7a063031f936f6d01087731ad1bdf2f306'
       OR NOT pg_catalog.has_function_privilege('fw_lease_machine_v1',
          'fw_lease_cap_v1.expire(text,integer,integer,text)','EXECUTE') THEN
        RAISE EXCEPTION '019_LEASE_EXPIRE_SOURCE_OR_ACL_PRECONDITION';
    END IF;

    SELECT pg_catalog.array_agg(entry ORDER BY entry) INTO expire_acl
      FROM (
        SELECT (COALESCE(grantee.rolname::text,'PUBLIC') || ':' || acl.privilege_type || ':' ||
                grantor.rolname::text || ':' || acl.is_grantable::text) AS entry
        FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
        LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
        JOIN pg_catalog.pg_roles grantor ON grantor.oid=acl.grantor
        WHERE p.oid='fw_lease_cap_v1.expire(text,integer,integer,text)'::regprocedure
      ) grants;
    IF expire_acl IS DISTINCT FROM ARRAY[
          'fw_lease_machine_v1:EXECUTE:fw_lease_machine_v1_owner:false',
          'fw_lease_machine_v1_owner:EXECUTE:fw_lease_machine_v1_owner:false'
       ]::text[] THEN
        RAISE EXCEPTION '019_LEASE_EXPIRE_ACL_PRECONDITION';
    END IF;

    SELECT pg_catalog.pg_get_userbyid(p.proowner),p.prosecdef,p.proconfig
      INTO helper_owner,helper_secdef,helper_config
      FROM pg_catalog.pg_proc p
      WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure;
    IF helper_owner<>'fieldwork' OR NOT helper_secdef
       OR helper_config<>ARRAY['search_path=pg_catalog, public']::text[] THEN
        RAISE EXCEPTION '019_PRIVACY_GUARD_SOURCE_PRECONDITION';
    END IF;

    SELECT p.prosrc INTO trigger_source
      FROM pg_catalog.pg_proc p
      WHERE p.oid='public.fw_privacy_run_delete_fence_v1()'::regprocedure
        AND pg_catalog.pg_get_userbyid(p.proowner)='fieldwork'
        AND NOT p.prosecdef
        AND p.proconfig=ARRAY['search_path=pg_catalog, public']::text[];
    IF trigger_source IS NULL
       OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(trigger_source,'UTF8')),'hex')
          <> '4ffdadc0c5557bdca9f055a2bf079251f3f79121a4c270d8276769951d856701' THEN
        RAISE EXCEPTION '019_PRIVACY_TRIGGER_SOURCE_PRECONDITION';
    END IF;

    IF pg_catalog.has_function_privilege('fw_lease_machine_v1_owner',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR pg_catalog.has_function_privilege('fw_lease_machine_v1',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR EXISTS (
          SELECT 1 FROM pg_catalog.aclexplode((
              SELECT p.proacl FROM pg_catalog.pg_proc p
              WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure
          )) acl
          WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       ) THEN
        RAISE EXCEPTION '019_LEASE_PRIVILEGE_ALREADY_PRESENT_OR_PUBLIC';
    END IF;

    SELECT pg_catalog.array_agg(r.rolname::text ORDER BY r.rolname::text)
      INTO guard_grantees
      FROM pg_catalog.pg_proc p
      CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
      JOIN pg_catalog.pg_roles r ON r.oid=acl.grantee
      WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure
        AND acl.privilege_type='EXECUTE'
        AND NOT acl.is_grantable
        AND acl.grantor=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='fieldwork');
    IF guard_grantees IS DISTINCT FROM ARRAY[
          'fieldwork','fieldwork_api','fieldwork_intake_worker',
          'fieldwork_real_worker_definer','fw_worker_v1_definer'
       ]::text[] THEN
        RAISE EXCEPTION '019_PRIVACY_GUARD_ACL_PRECONDITION';
    END IF;

    IF NOT pg_catalog.has_function_privilege('fw_worker_v1_definer',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR NOT pg_catalog.has_function_privilege('fieldwork_real_worker_definer',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR NOT pg_catalog.has_function_privilege('fieldwork_intake_worker',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR NOT pg_catalog.has_function_privilege('fieldwork_api',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') THEN
        RAISE EXCEPTION '019_EXISTING_PRIVACY_GUARD_GRANT_DRIFT';
    END IF;
END
$migration$;

GRANT EXECUTE ON FUNCTION public.fw_privacy_workspace_deleted_v1(text)
  TO fw_lease_machine_v1_owner;

DO $postcondition$
DECLARE
    guard_grantees text[];
BEGIN
    SELECT pg_catalog.array_agg(r.rolname::text ORDER BY r.rolname::text)
      INTO guard_grantees
      FROM pg_catalog.pg_proc p
      CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
      JOIN pg_catalog.pg_roles r ON r.oid=acl.grantee
      WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure
        AND acl.privilege_type='EXECUTE'
        AND NOT acl.is_grantable
        AND acl.grantor=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='fieldwork');
    IF NOT pg_catalog.has_function_privilege('fw_lease_machine_v1_owner',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR pg_catalog.has_function_privilege('fw_lease_machine_v1',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR EXISTS (
          SELECT 1 FROM pg_catalog.aclexplode((
              SELECT p.proacl FROM pg_catalog.pg_proc p
              WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure
          )) acl
          WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
       )
       OR NOT pg_catalog.has_function_privilege('fw_worker_v1_definer',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR NOT pg_catalog.has_function_privilege('fieldwork_real_worker_definer',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR NOT pg_catalog.has_function_privilege('fieldwork_intake_worker',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR NOT pg_catalog.has_function_privilege('fieldwork_api',
          'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE')
       OR guard_grantees IS DISTINCT FROM ARRAY[
          'fieldwork','fieldwork_api','fieldwork_intake_worker',
          'fieldwork_real_worker_definer','fw_lease_machine_v1_owner',
          'fw_worker_v1_definer'
       ]::text[] THEN
        RAISE EXCEPTION '019_PRIVACY_GUARD_GRANT_POSTCONDITION';
    END IF;
END
$postcondition$;

COMMIT;
