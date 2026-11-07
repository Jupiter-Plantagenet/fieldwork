# Real queued training: first end-to-end success (2026-11-02)

Run `52374741-86c5-469b-aaba-184ce2b7b80a` (frozen version `01a0f1aa-…`, revision 3, 2 epochs, batch 16, lr 0.001, seed 42)
went API → queue → scoped worker → pinned model container → committed epoch checkpoints → verified private bundle →
fresh container inference, on the retained `fieldwork` database.

| Item | Value |
|---|---|
| Terminal state | `succeeded`, artifact status `verified` (`REAL_PRIVATE_BUNDLE_VERIFIED`), fence 1, no retries |
| Epoch 1 | train loss 1.3798, val loss 1.2498, val acc 0.4091, checkpoint `17e9450a…67bc` |
| Epoch 2 (selected, min val CE) | train loss 1.2200, val loss 1.1820, val acc 0.4782, checkpoint `e51e6817…25d7` |
| Updates | 320 |
| Bundle digest | `e1175bff9314e9a23402d25841d5c7cfdf77d7b00239cd5377113abae70a8123` (3,108 rights members, `public_export_authorized=false`, evidence scope `validation_only`) |
| Model image | `sha256:41c680046133d0920a217adbfb951b8c77e4cec7e3ea7763646b19c5f4e7dfdc` (`fieldwork-real-model:20261102-fix-tmpfs-ckpt-bundle-01`) |
| Pixel image | unchanged `sha256:b42e39dfea7a…` |

Validation accuracy here is a pipeline check of a 2-epoch config. It is not the quality evaluation: the USEFUL gate
and the single held-out evaluation belong to the round-5 dataset lane (`dataset-delivery-round5.md`).
Epoch 1's checkpoint digest equals the earlier standalone container diagnostic's digest, i.e. the run is deterministic
across separate processes.

## Why attempt `5a1…` failed and what changed

Found by running the model stage with container logs enabled (the production runner uses `--log-driver=none`):

1. **Output tmpfs ownership.** The staged volume pre-creates `output/` as root 0755; Docker 29.6.1 makes a tmpfs mounted
   over an existing directory inherit its owner/mode, so UID 65532 could not create `/workspace/output/tmp`
   (`PermissionError`, exit 1 at startup). Fix: `mode=1777` on the output tmpfs (`real_model_container.py`).
2. **Checkpoint metadata.** `real_train_child` wrote `validation_accuracy` into `state.json`; `validate_checkpoint` pins the
   exact key set, so the child failed its own check after epoch 1. Fix: keep it in the history row only.
3. **Bundle directory.** `real_bundle.build` never created `rights/`. Fix: create it.
4. **Metrics comparison.** `real_bundle` demanded bit-exact float equality between `evaluate` and the independent verifier
   (different summation order). Fix: shared `metrics_agree` (1e-12 on floats, exact elsewhere), as `bundle.py` and
   `test_full_metrics.py` already do; also used by the validation API screen.
5. **Decoder stall.** A Docker start stall during staging permanently failed run `e5725945…` (staging ≈ 50 min). Fix:
   bounded retry (4 attempts, backoff) for transient decoder codes only; failure codes now carry a safe detail
   (`REAL_WORKER_FAILED_<code or class name>`).
6. **Worker loop.** Repeated failures of one (run, revision) are blocked after 3 (was an endless 5 s loop).

Each fix has a failing-test-first test (`tests/test_real_train_child_checkpoint.py` incl. resume-equivalence,
`test_real_job_decoder_resilience.py`, `test_real_child_failure_reporting.py`).

## Digest rotation

`RECIPE_DIGEST` / `PREPROCESS_DIGEST` hash `ml.py` / `real_train_child.py`, so fix 2 rotated both
(recipe `22ad675c…` → `2bc6eee5…`, preprocess `1392785e…` → `bfce6777…`). Migration
`020_real_digest_rotation.sql` re-pins the one validator (`fw_real_worker_cap_v1.profile_ok`), keeping the old digests
accepted. Scratch rehearsal and live apply (`tools/apply_digest_rotation_020.py`): PASS, owner/ACL preserved, run counts
unchanged, backups `.local/backups/fieldwork-pre-020-*.dump` (rehearsal `…T121142Z`, live `…T121226Z`), receipts
`.local/digest-rotation-020/`. 003–019 untouched. Model image rebuilt only (`--only model`); source lock updated for the
two changed files.

## Independent review of these changes (fresh read-only reviewer, simulated AI)

Verdict **APPROVE WITH NITS**, no blocking defect. It independently verified: all 22 hashes in `ops/real-model-source-lock.json`
match current bytes; the computed digests equal the migration's literals; the migration replaces exactly the intended
literals and preserves owner/ACL/search_path; tolerance in `metrics_agree` cannot launder tampering (saved metrics stay
exact-recomputed from hash-bound predictions); `mode=1777` adds no exposure. Dispositions:

- Decode retry lacked lease renewal at the three inference sites: **fixed** (renewer passed; test added).
- `_note_real_job_failure` docstring said "consecutive": **corrected** (in-memory count per worker process, never reset on success).
- **Known limitation, not changed:** DB `profile_ok` accepts old and new digests, but `real_bundle.verify_real_bundle` requires the
  *current* source digests, so a bundle trained under `22ad…`/`1392…` is accepted by the DB yet fails `REAL_BUNDLE_IMPLEMENTATION_DIGEST`
  at verification. Migration 020's header comment ("stays interpretable") therefore overstates; it is applied, so its bytes are
  frozen and this note is the correction. No bundle exists under the old digests. Every future edit to `ml.py` /
  `real_train_child.py` needs another migration (021) and a model-image rebuild.
- RAM override also waives the fail-closed `HOST_COMMIT_COUNTER_UNAVAILABLE_OR_INVALID` branch and applies to non-real preflight;
  the API submit gate still wants 6 GiB, so the gates are inconsistent. Operator-instructed; recorded in preflight.
- `apply_digest_rotation_020.py --apply` does not require a prior rehearsal receipt and verifies backups by TOC only
  (restore was exercised in `--rehearse`); the post-commit counts check assumes no concurrent run-state change. Accepted
  for this one-time apply.
- `REAL_PIXEL_CONTAINER_FAILED` is retried (a poison image burns 4 bounded attempts). Accepted.

## Operator decisions recorded

- **RAM gates waived on the operator's instruction** ("ignore all RAM gates"), via an explicit opt-in
  `FIELDWORK_OPERATOR_RAM_OVERRIDE=accept-low-available-ram`, which waives available RAM and the Windows commit gate;
  free disk is never waived. The worker's preflight records `operator_ram_override: true`. Default behaviour unchanged.
  Commit reached 87% at claim time and training completed.
- **Detached processes keep disappearing** (API and workers started through the WMI detached entry died minutes later with no
  log line; same as Codex's round-5 notes). Cause not identified. The API and worker were run as tracked foreground tasks
  (`var/activation/fieldwork-api-foreground-*.out.log`, `…worker-foreground-*.out.log`); they are not persistent across
  this session and nothing was installed (no service, scheduled task or Run key).

## Changed files

SHA-256 list: `real-training-success-sha256-20261102.json`.

## Not claimed

Independent review of these changes, the kill/replay proof on the real dataset, and ID reconciliation are still pending.
