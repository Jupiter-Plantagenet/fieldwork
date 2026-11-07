-- Compatibility migration for the retained round-4/5 dataset database.
-- The live app receives this table through migration 006 instead.
-- Operator-only: take the shared lock and back up that database before applying.
-- No account, key, assignment or authorization is implicitly enrolled here.
BEGIN;
CREATE TABLE fw_holdout_stewards (
  workspace text NOT NULL,
  actor text NOT NULL,
  reviewer_id text NOT NULL CHECK (reviewer_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  key_id text NOT NULL CHECK (key_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  assigned_by text NOT NULL,
  assigned_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace,actor)
);
ALTER TABLE fw_holdout_stewards ENABLE ROW LEVEL SECURITY;
ALTER TABLE fw_holdout_stewards FORCE ROW LEVEL SECURITY;
CREATE POLICY fw_holdout_steward_tenant ON fw_holdout_stewards
  USING (workspace=current_setting('fieldwork.workspace',true))
  WITH CHECK (workspace=current_setting('fieldwork.workspace',true));
REVOKE ALL ON fw_holdout_stewards FROM PUBLIC;
REVOKE ALL ON fw_holdout_stewards FROM fieldwork_api;
GRANT SELECT ON fw_holdout_stewards TO fieldwork_api;
COMMIT;
