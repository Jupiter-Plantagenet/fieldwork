-- UNAPPLIED additive migration. No auto-install, seed approval, role or old-table changes.
-- Independently authenticated acquisition/rights operator alone may write datasets/assets.
-- API later needs SELECT on datasets/assets; SELECT,INSERT,UPDATE on decisions only.
-- Those grants/owner selection require separate operator authority; none are made here.
BEGIN;
CREATE TABLE fw_rights_datasets (
    workspace text NOT NULL,
    dataset_id text NOT NULL CHECK (dataset_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    acquisition_sha256 text NOT NULL CHECK (acquisition_sha256 ~ '^[0-9a-f]{64}$'),
    member_count bigint NOT NULL CHECK (member_count > 0),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','authenticated','conflicting')),
    PRIMARY KEY(workspace,dataset_id)
);
CREATE TABLE fw_rights_assets (
    workspace text NOT NULL,
    dataset_id text NOT NULL,
    member_id text NOT NULL CHECK (length(member_id) BETWEEN 1 AND 512),
    asset_sha256 text NOT NULL CHECK (asset_sha256 ~ '^[0-9a-f]{64}$'),
    asset_bytes bigint NOT NULL CHECK (asset_bytes > 0),
    canonical_license bytea,
    license_text bytea,
    source_evidence bytea,
    attribution bytea,
    rights_state text NOT NULL DEFAULT 'pending' CHECK (rights_state IN ('pending','unknown','conflicting','reviewed')),
    PRIMARY KEY(workspace,dataset_id,member_id),
    FOREIGN KEY(workspace,dataset_id) REFERENCES fw_rights_datasets(workspace,dataset_id)
);
CREATE TABLE fw_rights_decisions (
    workspace text NOT NULL,
    dataset_id text NOT NULL,
    member_id text NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('local_private_training','private_thumbnail_ui','model_bundle','image_export','public_commercial_portfolio')),
    envelope bytea NOT NULL CHECK (octet_length(envelope) <= 16384),
    last_result text NOT NULL,
    received_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(workspace,dataset_id,member_id,purpose),
    FOREIGN KEY(workspace,dataset_id,member_id) REFERENCES fw_rights_assets(workspace,dataset_id,member_id)
);
ALTER TABLE fw_rights_datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE fw_rights_datasets FORCE ROW LEVEL SECURITY;
CREATE POLICY fw_rights_tenant ON fw_rights_datasets USING (workspace=current_setting('fieldwork.workspace',true)) WITH CHECK (workspace=current_setting('fieldwork.workspace',true));
ALTER TABLE fw_rights_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE fw_rights_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY fw_rights_tenant ON fw_rights_assets USING (workspace=current_setting('fieldwork.workspace',true)) WITH CHECK (workspace=current_setting('fieldwork.workspace',true));
ALTER TABLE fw_rights_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE fw_rights_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY fw_rights_tenant ON fw_rights_decisions USING (workspace=current_setting('fieldwork.workspace',true)) WITH CHECK (workspace=current_setting('fieldwork.workspace',true));
REVOKE ALL ON fw_rights_datasets,fw_rights_assets,fw_rights_decisions FROM PUBLIC;
COMMIT;
