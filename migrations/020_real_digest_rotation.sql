-- Real-training digest rotation. Source only: never apply from application code.
-- The recipe and preprocess digests are hashes of ml.py / real_train_child.py (see
-- fieldwork/real_run_profile.py). Correcting the real child's checkpoint metadata
-- (validation_accuracy removed from state.json) therefore rotates both digests.
-- 007/009 are immutable. This forward migration makes the one closed profile
-- validator accept the new digests while still accepting the previous ones, so run
-- lineage recorded under the earlier source stays interpretable. New submissions
-- always bind the current source digests (checked application-side).
BEGIN;

DO $patch$
DECLARE
  proc regprocedure := 'fw_real_worker_cap_v1.profile_ok(jsonb,text,text)'::regprocedure;
  old_recipe CONSTANT text := '22ad675cf61ef7bb3b315563652addf47fa7669667488777a15399c25f9a24fa';
  new_recipe CONSTANT text := '2bc6eee5631d951824a152712743256b75de189c1fcb1189228a228a087089dd';
  old_pre    CONSTANT text := '''e5b19df9fa39a01dd178e78d5efbd12a899983fad22ed3c7ff8d52643bc5ba44'',''1392785edc35eef504d62e4d9b90bb6aa438127d52e83869853b4eb8ebd34d92''';
  new_pre    CONSTANT text := 'bfce6777c4753267c0aa9cfdf4c02b49b2f42c0007bf8f6621fb7af66d6a1fd0';
  definition text;
  patched text;
  owner_before text;
  acl_before text;
BEGIN
  SELECT pg_catalog.pg_get_userbyid(p.proowner), COALESCE(p.proacl::text,'')
    INTO owner_before, acl_before FROM pg_catalog.pg_proc p WHERE p.oid=proc;
  IF owner_before IS DISTINCT FROM 'fieldwork_real_worker_definer' THEN
    RAISE EXCEPTION '020_PROFILE_OK_OWNER_PRECONDITION';
  END IF;

  definition := pg_catalog.pg_get_functiondef(proc);
  patched := replace(definition,
    'p_config->>''recipe_digest''=''' || old_recipe || '''',
    'p_config->>''recipe_digest'' IN (''' || old_recipe || ''',''' || new_recipe || ''')');
  IF patched=definition THEN RAISE EXCEPTION '020_RECIPE_PIN_NOT_FOUND'; END IF;

  definition := patched;
  patched := replace(definition,
    'p_config->>''preprocess_digest'' IN (' || old_pre || ')',
    'p_config->>''preprocess_digest'' IN (' || old_pre || ',''' || new_pre || ''')');
  IF patched=definition THEN RAISE EXCEPTION '020_PREPROCESS_PIN_NOT_FOUND'; END IF;

  EXECUTE patched;

  -- CREATE OR REPLACE must preserve owner and ACL, and keep exactly the new shape.
  IF pg_catalog.pg_get_userbyid((SELECT proowner FROM pg_catalog.pg_proc WHERE oid=proc)) IS DISTINCT FROM owner_before
     OR COALESCE((SELECT proacl::text FROM pg_catalog.pg_proc WHERE oid=proc),'') IS DISTINCT FROM acl_before THEN
    RAISE EXCEPTION '020_PROFILE_OK_OWNER_OR_ACL_CHANGED';
  END IF;
  IF position(new_recipe in pg_catalog.pg_get_functiondef(proc))=0
     OR position(new_pre in pg_catalog.pg_get_functiondef(proc))=0
     OR position(old_recipe in pg_catalog.pg_get_functiondef(proc))=0 THEN
    RAISE EXCEPTION '020_PROFILE_OK_POSTCONDITION';
  END IF;
END
$patch$;

COMMIT;
