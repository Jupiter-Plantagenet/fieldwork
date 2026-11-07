-- UNAPPLIED additive migration: explicit cancellation generation (ML-Run.cancel_generation;
-- generation issued to each ML-Attempt at claim). Authored only. It has NOT been applied to
-- any retained database; Store.migrate() deliberately does not run it and application code
-- never performs this DDL or any repair. Apply it (by separate operator authority) BEFORE
-- starting API/worker code that contains the generation protocol; until then that code
-- fails closed with CANCEL_GENERATION_SCHEMA_REQUIRED (no cancel receipt, no claim).
--
-- Existing rows deliberately keep NULL, meaning "legacy row, generation unknown":
--   * worker heartbeat/checkpoint/complete against a NULL run is refused
--     (CANCEL_GENERATION_UNVERIFIABLE) and a cancel acknowledgement cannot name it;
--   * a queued legacy run is issued generation 0 when next claimed, and a non-terminal
--     legacy run that is cancelled records generation 1 (no generation-tracked cancel can
--     precede either: cancelling queued/interrupted is terminal and cancel_requested never
--     returns to queued/running).
-- The column is added WITHOUT a default first so existing rows are not backfilled, then the
-- default applies to new rows only. No backfill, history rewrite, role, grant or RLS change.
-- The API role's existing table-level fw_runs UPDATE covers the new column; scoped
-- controller column grants (state,fence,revision) are intentionally unchanged because lease
-- expiry never changes the generation.
BEGIN;
ALTER TABLE fw_runs ADD COLUMN cancel_generation int
    CONSTRAINT fw_runs_cancel_generation_nonnegative CHECK (cancel_generation IS NULL OR cancel_generation >= 0);
ALTER TABLE fw_runs ALTER COLUMN cancel_generation SET DEFAULT 0;
ALTER TABLE fw_attempts ADD COLUMN cancel_generation int
    CONSTRAINT fw_attempts_cancel_generation_nonnegative CHECK (cancel_generation IS NULL OR cancel_generation >= 0);
COMMIT;
