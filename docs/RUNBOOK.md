# Fieldwork operator runbook and walkthrough (2026-11-03)

Every command below was exercised during the 2026-11-02/03 completion pass on this host (Windows 11, Docker Desktop/WSL2).

## 1. Start the stack after a reboot

1. **Start Docker Desktop.**
2. **Start the databases:** `docker start fieldwork-postgres fieldwork-pg-verify`. They have no restart policy.
3. **Start the API** from `fieldwork/`:
   - command: `.venv/Scripts/python.exe -m uvicorn fieldwork.api:app --host 127.0.0.1 --port 8102 --no-access-log`;
   - env: `FIELDWORK_REAL_PIXEL_IMAGE_ID`, `FIELDWORK_REAL_MODEL_IMAGE_ID`, `FIELDWORK_QUALIFIED_MODEL_IMAGE_ID` and `FIELDWORK_RIGHTS_REVIEWERS_FILE=var/commons_r5/rights/reviewers.json`;
   - optional operator overrides: `FIELDWORK_OPERATOR_RAM_OVERRIDE=accept-low-available-ram` and `FIELDWORK_OPERATOR_SPACE_OVERRIDE=accept-large-run-writes`.
4. **Start the UI:** in `apps/web`, run `npm run dev -- --host 127.0.0.1 --port 5102 --strictPort`.
5. **Start the training worker:**
   - command: `.venv/Scripts/python.exe -m fieldwork.worker --real-runs`;
   - env: `FIELDWORK_WORKER_AUTHORITY` (from `tools/activate_real_worker.py`), `FIELDWORK_HOST_HEAVY_LOCK=<repo>/.cache/fieldwork-heavy.lock`, the image ids, the rights registry and optionally the overrides.
6. **Start the credential issuer immediately after the worker.** The worker's database password lives 5 minutes, and the issuer renews it while the worker heartbeat is live:
   - command: `.venv/Scripts/python.exe -m fieldwork.worker_identity serve --operator-file .local.json --authority-file <authority dir>/worker-authority.json --worker-heartbeat var/worker.json --interval 30 --ttl-seconds 300`;
   - `<authority dir>` is listed in `.cache/r5-platform/worker-authority-dir.txt`.
7. **Start the intake worker** with the reviewed v2 profile, as an absolute path: `.venv/Scripts/python.exe -m fieldwork.newintake_worker --authority-file <abs>/.local/real-data/activation-backups/decoder-v2-20261102T001157Z/intake-authority.v2.json`.
8. **If the worker logs `DB_UNAVAILABLE_OR_CREDENTIAL_REFUSED`:**
   1. stop the worker;
   2. run `tools/refresh_scoped_worker_credential.py` under the shared `fieldwork-real-activation` lock;
   3. start the worker, then the issuer.

Run only one heavy job at a time. Don't start a training run, load test or full test suite while Windows memory commit is above about 85 %.

## 2. Walkthrough: the real flow in the UI (`http://127.0.0.1:5102`)

1. **Getting started:** the panel on Research workspace (also the header button) links every step.
2. **Dataset explorer:** queue an image archive against a rights-reviewed dataset. The intake panel shows counts (source total, accepted, rejected, duplicate, noop, new sample ids) and a reason per non-accepted file.
3. **Dataset versions / Split integrity:** draft, review, assign the split, freeze. Holdout groups cannot migrate.
4. **Configure training:** pick the frozen version, epochs, batch, lr and seed, then submit. **Runs & workers** shows the queued, leased and running states.
5. **Training run:** committed epoch checkpoints with digests, attempts with fences, and the artifact verification receipt (process identity, receipt, model and bundle digests).
6. **Recover training:**
   - When it applies: after a crash, lease expiry or killed worker, the run shows `interrupted` with its checkpoint boundary.
   - What to do: click **Resume at epoch N** to replay from the next epoch.
   - Note: cancel is final and cannot be resumed.
7. **Evaluation results / Error investigation:** the validation confusion matrix. Clicking a cell opens that exact pair's members.
8. **Model artifacts:** the verified private bundle (download refused: a candidate is not a release) and the qualified release download.
9. **Inference playground:** a fresh-process inference with the qualified release on a registered image.
10. **Workspace & access settings:** retention policy, members, privacy holds, support diagnostics.

## 3. Recovering a killed or crashed run (operator)

1. **Restarting the worker cleans up** the orphaned model container and volume (`ModelContainerRunner.recover_stale`).
2. **Recover the dead owner's lock:** `tools/product_lock.py recover`, with `PORTFOLIO_PRODUCT_LOCK` pointed at the Fieldwork lock.
3. **Expire the lease:** the scoped lease machine (`.local/real-data/expire_killed_training_run_once.py <run>`) moves the run `running → interrupted` and advances the fence.
4. **Release the slot:** `Store().reconcile_training_slot()` returns `RELEASED` once owner and child exit are proven.
5. **Resume** through the UI or `POST …/real/runs/{id}/resume {"replay_epoch": N}`.

This was proven bit-identical in `docs/real-host-crash-replay-20261103.md`.

## 4. Backup and restore

1. **Back up:** `tools/restore_proof.py --backup-only --out <C: private dir>`. It writes a digest-manifested backup: DB dump, roles, checkpoints, verified bundles, dataset media, reviewer registry and privacy deletion ledger.
2. **Copy it to the external volume.**
3. **Restore:** `tools/restore_proof.py --from-backup <external dir> --out <C: dir>`. It verifies every file digest first and refuses a corrupted backup. It then restores into a brand-new empty PostgreSQL container, verifies tables, blobs and tenant controls, and fences leases before any worker starts.
4. **Measured:** RTO 108 s, in `docs/acceptance-status-final-20261103.md`.

## 5. Schema migrations

Use `tools/apply_migration_0xx.py --rehearse` (scratch restore), inspect the receipt, then `--apply` (verified backup first). Migrations 020–024 were applied this way; receipts are under `.local/migration-0xx/`.

## 6. Tests

Run `tools/r5_resume_suite.py light [--tests …]` (isolated mirror + `fieldwork-pg-verify`), plus the `startup` and `diagnosis` stages. Never run bare pytest against the live database.
