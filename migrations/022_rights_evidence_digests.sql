-- 2026-11-03 completion pass. Performance only; no privilege, policy or data change.
--
-- Every bundle/validation read re-verifies the signed rights decision of every dataset member (RightsService.require).
-- The expected facts include the SHA-256 of four evidence documents per member. The license text alone is ~35 KB
-- per row (127 MB across 3,659 members, identical bytes), so hashing it on every request cost ~0.4 s of database
-- time. Store the digests as generated columns: PostgreSQL recomputes them on every INSERT/UPDATE of the source
-- column, so they can never disagree with the bytes. Readers still verify every member's signature against them.
-- The application falls back to hashing in the query when these columns are absent.
BEGIN;

DO $preflight$
BEGIN
  IF to_regclass('public.fw_rights_assets') IS NULL THEN
    RAISE EXCEPTION '022_RIGHTS_ASSETS_REQUIRED';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='fw_rights_assets'
             AND column_name IN ('canonical_license_sha256','license_text_sha256','source_evidence_sha256','attribution_sha256')) THEN
    RAISE EXCEPTION '022_ALREADY_APPLIED';
  END IF;
END
$preflight$;

ALTER TABLE public.fw_rights_assets
  ADD COLUMN canonical_license_sha256 text GENERATED ALWAYS AS (encode(sha256(canonical_license),'hex')) STORED,
  ADD COLUMN license_text_sha256 text GENERATED ALWAYS AS (encode(sha256(license_text),'hex')) STORED,
  ADD COLUMN source_evidence_sha256 text GENERATED ALWAYS AS (encode(sha256(source_evidence),'hex')) STORED,
  ADD COLUMN attribution_sha256 text GENERATED ALWAYS AS (encode(sha256(attribution),'hex')) STORED;

COMMIT;
