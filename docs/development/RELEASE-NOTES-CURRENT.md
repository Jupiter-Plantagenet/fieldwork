# Fieldwork — current release handoff

**Validation date:** October 26, 2026 (UTC). **Disposition: local synthetic implementation milestone; NOT a qualified release.**

## Training lease controller packet — pending independent review

`fieldwork/lease_recovery.py` adds a separate, stdlib orchestration CLI (existing
psycopg is loaded only for database execution). It is **not activated**. No worker,
Store, artifact-state, terminal-attestation, accepted-evidence or production gate
code was changed. No original acceptance status is promoted.

- Default start-to-start interval 2s; allowed interval `(0,5]` seconds; batch 1–32
  (default16), 1s per-pass processing budget, DB connection timeout1s, statement
  timeout250ms, lock timeout50ms, per-row transactions and `SKIP LOCKED`.
- Keyset progress advances past failing candidates and wraps after the tail.
  Exact run/workspace/fence/revision/state plus DB-clock expiry guard the locked
  transition: running→interrupted, cancel_requested→cancelled. Fence/revision and
  one expired event are in the same transaction; renewal without revision change
  is protected by the lease recheck. No queued job, attempt, checkpoint, evidence,
  artifact field or result is reset. Existing worker write guards are unchanged.
- **Physical policy is retain-all.** No process is inspected/killed and no slot is
  cleared, including a provably dead process. Events/CLI report
  `RETAINED_NOT_RECONCILED` / `LOGICAL_EXPIRY_IS_NOT_PHYSICAL_EXIT` and no automatic
  retry. This intentionally defers training physical reconciliation, rather than
  misapplying the reviewed artifact-specific proof. No slot lock is acquired;
  existing slot-first/run locking remains unchanged.
- Authority is an explicit private `--authority-file`, never the default Store,
  browser credential or HTTP endpoint. Its JSON must contain `dsn`, an explicit
  nonempty `workspaces` list (no wildcard),
  `purpose: fieldwork-training-lease-controller`, and
  `authority_mode: trusted-operator-not-least-privilege`. The existing request role
  is rejected because it lacks fw_slot SELECT. This capability check is **not**
  least-privilege certification; operator DSNs remain powerful. File ACLs and
  trusted operators are prerequisites. No role provisioning, DDL or live install
  was performed. A narrow principal/security-definer deployment requires a
  separately reviewed design and disposable-only provisioning proof first.

Future isolated-only invocation (NOT an activation instruction):
` .venv/Scripts/python -m fieldwork.lease_recovery --authority-file <private-isolated-controller.json> --once `
Omit `--once` for independent looping. No automatic training launch is present.

Evidence: `evidence/lease-recovery/0c91e684f94c45d78d1a852f62abb50a/`.
Four vertical RED/GREEN cycles exercise pure orchestration/options and the SQL
call protocol. The SQL protocol test uses a clearly labelled recording double;
it is **not** a real transaction, renewal, contention, expiry or rollback proof.
RAM is too close to the 512MiB reserve plus 256MiB aggregate fixture cap for
conservative PG/process admission; resource measurements and monitored pure-run
exits are retained there. No full suite/browser/model/build ran.

**Still BLOCKED:** actual 45s lease / ≤10s marking wall test with blocked owner,
two independent scanner processes/one event, heartbeat and stale publish/complete
races, actual PostgreSQL rollback/barriers/new-fence/terminal-state tests, killed
tiny-owner proof, unknown physical retention against PostgreSQL, and affected
terminal-slot/FW-02 reruns. Throughput/timing under backlog, prolonged DB outage or
repeated discovery timeout is unproven; bounded options are not an unconditional
latency guarantee. Pure checks cannot close these acceptance criteria. Fresh
parent independent review and admitted reruns are required before any activation.

## Scoped residual-finding follow-up — October 26, 2026, 12:17 UTC

**This section supersedes the earlier validation snapshot below for FW-02-POST-API / FW-03-POST-FAILURE only. No original acceptance gate is promoted.** Current source aggregate: `eb3e8e94a3f97cfa2f0730c3264dd9bfb36254f7a6084f9e8b169966c27e62ad`; exact inventory: `evidence/postfix-validation/suite-source-after.json`.

- **FW-02-POST-API:** all evaluation, records/predictions, slices and artifacts reads now share bounded read-once manifest/inventory/payload/receipt verification against the accepted DB digest. Parsed JSON and response bytes come from the hashed snapshot, not reopened paths. Selected checkpoint/dataset provenance and fresh-process identity are checked. Missing/unverified stages fail closed. Standalone `bundle.build` requires an explicit checkpoint anchor. Genuine retained candidates are used as explicitly anchored isolated test fixtures; this is not new model proof.
- **FW-03-POST-FAILURE:** training completion atomically stores `succeeded` plus artifact `pending`. Guarded setup includes mkdir/import/build failures. Artifact leases, PID+creation-time owners, fences, attempt-specific output directories, child registration, bounded retries and dispatcher orphan scans are implemented. Real stdlib worker processes were killed in both pending and building stages against isolated PostgreSQL; recovery, stale-fence/expired-lease denial, durable explicit failure and live-child slot retention pass. Artifact retries remain subject to the unchanged heavy resource gate.
- **Remaining launch ambiguity:** death after committed spawn intent but before child PID registration cannot prove child exit. Recovery durably records `ARTIFACT_CHILD_EXIT_UNCONFIRMED`, retains the host slot and denies automatic retry. Operator physical-exit reconciliation or a platform-owned spawn containment protocol remains required. No blanket crash/power-loss or process-tree certification is claimed.
- **Focused checks:** 21 passed, 0 skipped/failed. **Whole backend suite:** 67 passed, 5 resource-skipped, 0 failures/errors; 72 collected, 39.078s. Commands, RED evidence, JUnit and disposition are under `evidence/postfix-validation/` and numbered logs 55–57. The initial follow-up suite's historical-proof expectation failure is retained under `first-suite-legacy-denial/`; it was corrected to use an isolated accepted fixture, not by relabeling live data.
- **No new training ran.** RAM remains below the unchanged 6GiB gate; full current training/bundle/inference/worker/replay proof is still skipped. At 2026-10-26T12:16:56.763972+00:00 available RAM was 1432821760 bytes. No unrelated app was stopped and no admission limit was weakened. Full gate passes remain **0**; all 29 acceptance IDs / 15 screen IDs and their original criteria are preserved.
- Only the product API was restarted (current listener PID 55716). Existing sign-in and authenticated session readback, readiness and UI GET returned 200; localhost redirect remains 307 to 127.0.0.1. Unverified historical proof endpoints now correctly return 409; files/records remain intact and are not automatically attested. Existing proof-panel/browser results are historical, not rerun browser acceptance after this stricter behavior. No frontend, accounts, credential guide or redirect code was changed. The first follow-up baseline's 32 accounts and 62 runs remained unchanged across the suite runs (new fixture rows are separate); schema expansion adds owner/lease fields. No isolated test databases remain and the live host slot is empty.

## Historical parent snapshot and provenance

- Repository: `C:/Users/user/portfolio-build/fieldwork`.
- Git HEAD: `06b89c98a40208cfb12d2850a1cb6133f07d99e4`; the working tree contains substantive pre-existing uncommitted implementation. No commit was made.
- Validated source/test/frontend/lock aggregate SHA-256: `ca7b2f4daf827affeb5f842fa41ae51a4e439976bd2f7a44d9400778ed61062c`.
- `evidence/parent-validation/source-baseline.json` and `source-final.json` contain the exact relative-path/raw-byte digest inventory and hashing algorithm. They are identical. Documentation, evidence, generated outputs, credentials and Python bytecode are excluded. This is a source snapshot identity, not a signature or release attestation.
- This task changed only the README, this missing release-note file, `evidence/acceptance.json`, and new artifacts under `evidence/parent-validation/`. No core implementation, tests, input blueprints, resource thresholds or training settings were edited.
- All earlier numbered logs, old `current-suite.xml`, root browser results and training/inference reports are **historical**. The successful earlier queued-worker run predates later FW-01/02/03 hardening; it is not current hardened-worker success.

## Executed commands and actual results

Commands below ran from the repository root unless another working directory is specified. Raw command arrays, timestamps, durations and exit codes are in the corresponding `*-result.json` files.

| Check | Actual command | Result | Current evidence |
|---|---|---|---|
| Backend whole suite | `.venv/Scripts/python -m pytest tests -v -s -ra --basetemp=evidence/parent-validation/pytest-tmp --junitxml=evidence/parent-validation/pytest.xml` | **51 passed, 5 skipped, 0 failures, 0 errors; 56 collected; 27.67s; exit 0** | `evidence/parent-validation/suite.log`, `pytest.xml` |
| Frontend typecheck/build | `npm run build` in `apps/web` (`tsc --noEmit && vite build`) | **exit 0**; 16 modules, JS 262.06kB / gzip80.15kB; no reported warnings | `evidence/parent-validation/build.log` |
| Browser suite | `node node_modules/@playwright/test/cli.js test` in `apps/web` | **3 passed, 0 skipped/failed/flaky; 7.1s; exit 0** | `evidence/parent-validation/browser.log`, `browser-outputs/browser-results.json` |
| Dependency consistency | `.venv/Scripts/python -m pip check` | **exit 0; No broken requirements found** | `evidence/parent-validation/pip-check.log` |
| Database readiness | `docker exec fieldwork-postgres pg_isready -U fieldwork -d fieldwork` | accepting connections | Live tool observation; loopback readiness in `state-final.json` |
| Scope reconciliation | `.venv/Scripts/python evidence/parent-validation/reconcile_handoff.py` | exact **29 acceptance IDs**, **15 screen IDs**, verbatim original pass conditions; **0 status promotions** | `evidence/parent-validation/reconciliation.json` |

The final browser runs used installed **Microsoft Edge155.0.4283.62** (headless `msedge` channel), Playwright1.64.1 and Nodev26.7.0 on Windows; see `evidence/parent-validation/browser-environment.json` and `environment.json`. This single-browser result does not satisfy the original multi-browser matrix.

The retained validation wrapper can reproduce the checks without changing source or gates:

```bash
.venv/Scripts/python evidence/parent-validation/validate.py suite
.venv/Scripts/python evidence/parent-validation/validate.py build
.venv/Scripts/python evidence/parent-validation/validate.py browser
.venv/Scripts/python evidence/parent-validation/validate.py pip-check
```

These runners use the existing warm local environment and private fixture prerequisites. They are not a clean-host recipe. Archive the parent-validation directory before rerunning if preserving this exact validation record. Test-written root evidence files are captured under the owned `*-outputs/` directories and the original root bytes restored. Existing test code still creates new uniquely named fixture accounts/runs and generated local outputs; it does not reset the existing accounts/records.

### API binary freshness correction

The initial live API process was created at 10:28:13 UTC, before current `api.py` (10:37:09) and `events.py` (10:38:15). Initial passing tests against that process were **not accepted as the final live-binary validation**; they are retained in `evidence/parent-validation/pre-api-refresh/`.

Executed `.venv/Scripts/python -m tools.restart_api`, whose ownership check restricts termination to the Fieldwork listener on 8102 with this repository as its working directory. Readiness succeeded. The final whole suite and browser suite were then rerun against the refreshed API. `evidence/parent-validation/api-restart.log` records listener PID **46008**, launcher PID **48292**, created at 11:45:24 UTC, after all backend source timestamps. No sibling application or workload was stopped. API runtime/log files under ignored `var/` changed as ordinary service effects, not source edits.

## Actual resource admission and skipped work

Unchanged admission: **6,442,450,944 bytes available RAM (6GiB)** and **12,884,901,888 bytes free disk (12GiB)**. No resource mock, threshold reduction, host cleanup or unrelated-process termination was used to admit heavy execution.

At 11:46:32 UTC the host measured **1,634,332,672 bytes available RAM** and **47,019,229,184 bytes free disk**. RAM fails; disk passes. Measurements at test time also failed RAM:

| Skipped test | Actual reported reason |
|---|---|
| `tests/test_bundle.py::test_candidate_safe_inventory_and_actual_fresh_process` | RAM676626432 / disk47045128192 bytes; requires6GiB/12GiB |
| `tests/test_live_worker_api.py::test_live_http_queue_worker_checkpoint_evaluation_fresh_inference` | RAM1387278336 / disk47044481024 bytes; real queue lane blocked |
| `tests/test_optimization.py::test_actual_optimizer_checkpoint_restores_exact_epoch` | RAM1402839040 / disk47044448256 bytes; requires6GiB/12GiB |
| `tests/test_replay.py::test_kill_restart_epoch9_replay_and_stale_publication` | RAM1429250048 / disk47044448256 bytes; requires6GiB/12GiB |
| `tests/test_worker.py::test_separate_worker_executes_queued_run_and_persists_bundle` | Separate worker returned the resource-blocked outcome; actual training did not execute |

The final suite includes both direct worker and live HTTP queued-lane tests. **The current hardened HTTP → queue → worker → new training/checkpoints → evaluation → fresh inference lane was NOT executed successfully.** Do not count skipped work as passed; do not substitute the historical success. A later trusted-fixture rerun is required when admission naturally permits. No flowers or weights were acquired.

## Reconciled implemented subsets

These are current regressions/observations, not full release-gate passes:

- **Annotation/review/freeze:** persisted fixture draft proposals, separate-actor proposal/version digest review, stale revision denial, review invalidation, immutable child freeze and unchanged parent. Current Edge browser exercises this flow at390px. Natural-image intake/rights/split review are not implied.
- **Tenant DB boundary:** requests use the dedicated non-owner, NOSUPERUSER/NOBYPASSRLS API role. FORCE RLS and transaction-local tenant scope/default deny are implemented. Reused-connection isolation and composite foreign-key denials pass against real isolated PostgreSQL databases. Admin/controller access remains separate. This is not a full pooled/load/security certification.
- **Sessions:** successful login replaces the presented old cookie; 12h absolute/30m idle expiration and account role/workspace-change invalidation are implemented/tested. Logout revokes sessions/streams. Cookies remain loopback-development HTTP, not secure HTTPS; this is not production authentication.
- **SSE:** polling and authorized SSE coexist. Durable event IDs/string sequence cursors/object revisions, Last-Event-ID replay, seven-day replay expiry410/resnapshot and workspace denial regressions pass. Refreshed live HTTP logout revocation closed in **0.265 seconds**: `evidence/parent-validation/suite-outputs/live-sse.json`. Full client duplicate/out-of-order/reconnect/offline and membership-role matrix remain incomplete.
- **Metrics/slices:** precision/null reasons, all disposition denominators/missing buckets, Wilson accuracy, seeded group-bootstrap intervals and expiring predicate/evaluation-bound slice cursors are now tested on fixtures. This does not qualify model usefulness.
- **FW-01/02/03 hardening:** controller-owned checkpoint copies, trusted external digest requirements, bounded JSON/tensor headers and lineage rejection, cross-file bundle evidence reconciliation, durable artifact stages and API manifest/receipt trust anchors pass current regressions. Some tests intentionally use retained proof outputs; fresh heavy execution remains skipped.
- **Concurrency/queue:** four real PostgreSQL barrier orderings for checkpoint/completion versus cancellation pass. Repeat cancellation cannot certify unknown physical exit. Accepted-idempotency replay precedes new resource admission and the atomic queued cap is20 per workspace. These do not certify OS descendant isolation or host-wide scheduling.
- **Restore/migration:** current same-volume DB/blob restore to an isolated database preserved25 checkpoints and verified97 files /11984906 bytes. Repeated expansion migration on a restored private historical snapshot preserves24 original runs/81 events. No live database reset occurred. These are not external-volume encrypted disaster recovery, restored inference, restore-generation credential or full rollback/mixed-binary acceptance.

## Original release scope remains open

`evidence/acceptance.json` embeds each original `ml-contracts.json` acceptance record verbatim under `original_contract`, including its exact `pass_condition`, and every original screen definition. The normative input was not modified. Current classification remains **18 partial /11 blocked /0 full acceptance passes**. Screen route coverage does not establish original action/state acceptance.

Every one of the following29 IDs remains unpassed; the register gives current observations and the remaining assertion for each:

- Functional/data: `ML-T-FLOW`, `ML-T-INTAKE`, `ML-T-VERSION`, `ML-T-SPLIT`, `ML-T-HOLDOUT`, `ML-T-OPTIMIZE`, `ML-T-USEFUL`, `ML-T-METRICS`, `ML-T-CELL`.
- Control/safety/package: `ML-T-QUEUE`, `ML-T-FENCE`, `ML-T-ATOMIC`, `ML-T-REPLAY`, `ML-T-CANCEL`, `ML-T-SAFE`, `ML-T-TENANT`, `ML-T-BUNDLE`.
- UX/browser/operations: `ML-T-UX`, `ML-T-BROWSER`, `ML-T-CAPACITY`, `ML-T-INFERPERF`, `ML-T-RESOURCE`, `ML-T-RESTORE`, `ML-T-MIGRATE`.
- Reproduction/governance: `ML-T-CLEAN`, `ML-T-RIGHTS`, `ML-T-EVENTS`, `ML-T-PRIVACY`, `ML-T-DELIVERY`.

Highest-priority missing gates: asset-level flower rights/acquisition and group/support review; unseen holdout/steward protocol/usefulness; admitted current hardened heavy-lane proof; second recipe/full original preprocessing; OS memory/CPU/filesystem/network/credential/process-tree isolation; all crash/disk-full/power-loss/GC edges; host-wide budgets and expiring preflight; external encrypted/empty-host restore and revoked old workers; mixed-binary migration/rollback; original capacity/30-process inference populations; full browser/manual accessibility matrix; retention/deletion/backup tombstones; qualified export/inference/settings; clean independent reproduction and independent rights/security/release approvals. No partial fixture population upgrades any gate.

## Final process/data state and operator precautions

- UI remains loopback `127.0.0.1:5102`, PID48172; API remains loopback `127.0.0.1:8102`, listener PID46008; dedicated PostgreSQL remains loopback port5542.
- API readiness and UI GET returned200. `GET http://localhost:5102/?parent-validation=1` still returns307 to `http://127.0.0.1:5102/?parent-validation=1`; canonical-host redirect preserved. Private credential guide/accounts were neither printed nor edited.
- Heavy slot is empty, with no observed dedicated persistent Fieldwork worker supervisor. The old `var/worker.json` heartbeat is not proof of a running worker. No automatic worker was started to consume pre-existing queued jobs.
- Live database has12 queued,1 persisted running (expired lease),13 succeeded and36 cancelled rows at the final recorded sample. The expired running row `fcf43251-75b7-4800-9a33-50a34d9c4306` already existed before validation; it was not repaired/expired to manufacture a clean state. No automatic five-second expiry scanner is claimed.
- All **24 original account rows and48 original run rows** were byte-content-equivalent at comparison time. The two backend runs added8 uniquely generated fixture accounts and14 fixture run rows. Existing account/session credentials were not reset; normal test browser logins/idle timestamps and new annotation drafts/reviews are expected side effects.
- Isolated test/restore/migration databases were dropped by their runners; final remaining matching test databases:0. Same-volume backup dumps remain under ignored private `var/backup-rehearsals/`; they can contain secrets and must never be served, published or added to evidence archives.
- No untrusted input, arbitrary upload, paid API, public deployment, commit, flower download or pretrained-weight acquisition was performed. Do not run an unfiltered worker over pre-existing queues; use only an explicitly selected trusted synthetic fixture when resources permit.

Detailed current machine/listener/package observations: `evidence/parent-validation/environment.json`, `state-final.json`, `process-details.json`. No test failed in the final reruns, so there is no failure trace requiring a source fix from this task.
