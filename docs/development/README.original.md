# Fieldwork — local visual ML workbench

**Current handoff:** `RELEASE-NOTES-CURRENT.md` and `evidence/acceptance.json` distinguish executed work, current resource skips, and unpassed release gates. All 29 original acceptance IDs and 15 screen IDs remain in scope. No full release or human/security/rights signoff is claimed.

**Working local implementation, not a qualified ML release.** React/TypeScript preserves the supplied 15 Fieldwork route IDs and original visual tokens/compositions. FastAPI uses a dedicated PostgreSQL database. CPU PyTorch genuinely trains an initialized compact CNN; no corpus or pretrained weights were downloaded.

## Training lease controller packet — pending independent review

`fieldwork/lease_recovery.py` adds a separate, stdlib orchestration CLI (existing
psycopg is loaded only for database execution). It is **not activated**. No worker,
Store, artifact-state, terminal-attestation, accepted-evidence or production gate
code was changed. No original acceptance status is promoted.

- Target start-to-start interval 2s; allowed interval `(0,5]` seconds; batch 1–32
  (default16), 1s **soft** pass budget, DB connection timeout1s, statement
  timeout250ms, lock timeout50ms, per-row transactions and `SKIP LOCKED`.
  LC-01 guarantees one row attempt after nonempty successful discovery, even
  when discovery exhausts that budget. Later rows obey the elapsed-budget
  cutoff; the cursor advances only over attempted rows. Discovery, connections,
  commits, scheduling and an in-flight attempt may overrun the target interval
  and soft budget. Neither is an end-to-end hard deadline.
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
Those initial measurements blocked PG/process execution at that time; they are
historical, not current admission or PostgreSQL proof.

LC-01 fix-cycle evidence:
`evidence/lease-recovery/lc01-8287ccccd5c3484ab65afee3f038f228/`.
Deterministic pure RED catches successful discovery at/eclipsing the budget;
the minimal first-attempt fix is GREEN. Actual disposable PostgreSQL and CLI
proofs observe a canonical 45s lease marked 0.124807s after its deadline while
the independent owner remains blocked before training (no torch import in that
proof). Separate receipts cover two CLI contenders/one event, cancellation,
physical row locks, canonical heartbeat/publish/complete/cancel winners,
expiry-winner denials, per-row event rollback, poison/locked-row/keyset progress,
retain-all slots and actual API-login rejection. Accelerated clocks and explicit
SQL scheduling scaffolds are labelled; this is not a universal throughput bound.
Terminal-slot and FW-02 light regressions ran only with disposable databases.
The principal proof uses the existing API login against isolated subset RLS/grants;
it is not full deployment provisioning, least-privilege or search-path hardening.

**Still BLOCKED:** activation and full ML-T-FENCE acceptance. Throughput/timing
under arbitrary backlog, prolonged DB outage or repeated discovery timeout remain
unproven. No dead-slot reconciliation or full physical recovery is claimed.
Fresh parent independent source review and admitted reruns remain required.

## Scoped residual-finding follow-up — October 26, 2026, 12:17 UTC

**This section supersedes the earlier validation snapshot below for FW-02-POST-API / FW-03-POST-FAILURE only. No original acceptance gate is promoted.** Current source aggregate: `eb3e8e94a3f97cfa2f0730c3264dd9bfb36254f7a6084f9e8b169966c27e62ad`; exact inventory: `evidence/postfix-validation/suite-source-after.json`.

- **FW-02-POST-API:** all evaluation, records/predictions, slices and artifacts reads now share bounded read-once manifest/inventory/payload/receipt verification against the accepted DB digest. Parsed JSON and response bytes come from the hashed snapshot, not reopened paths. Selected checkpoint/dataset provenance and fresh-process identity are checked. Missing/unverified stages fail closed. Standalone `bundle.build` requires an explicit checkpoint anchor. Genuine retained candidates are used as explicitly anchored isolated test fixtures; this is not new model proof.
- **FW-03-POST-FAILURE:** training completion atomically stores `succeeded` plus artifact `pending`. Guarded setup includes mkdir/import/build failures. Artifact leases, PID+creation-time owners, fences, attempt-specific output directories, child registration, bounded retries and dispatcher orphan scans are implemented. Real stdlib worker processes were killed in both pending and building stages against isolated PostgreSQL; recovery, stale-fence/expired-lease denial, durable explicit failure and live-child slot retention pass. Artifact retries remain subject to the unchanged heavy resource gate.
- **Remaining launch ambiguity:** death after committed spawn intent but before child PID registration cannot prove child exit. Recovery durably records `ARTIFACT_CHILD_EXIT_UNCONFIRMED`, retains the host slot and denies automatic retry. Operator physical-exit reconciliation or a platform-owned spawn containment protocol remains required. No blanket crash/power-loss or process-tree certification is claimed.
- **Focused checks:** 21 passed, 0 skipped/failed. **Whole backend suite:** 67 passed, 5 resource-skipped, 0 failures/errors; 72 collected, 39.078s. Commands, RED evidence, JUnit and disposition are under `evidence/postfix-validation/` and numbered logs 55–57. The initial follow-up suite's historical-proof expectation failure is retained under `first-suite-legacy-denial/`; it was corrected to use an isolated accepted fixture, not by relabeling live data.
- **No new training ran.** RAM remains below the unchanged 6GiB gate; full current training/bundle/inference/worker/replay proof is still skipped. At 2026-10-26T12:16:56.763972+00:00 available RAM was 1432821760 bytes. No unrelated app was stopped and no admission limit was weakened. Full gate passes remain **0**; all 29 acceptance IDs / 15 screen IDs and their original criteria are preserved.
- Only the product API was restarted (current listener PID 55716). Existing sign-in and authenticated session readback, readiness and UI GET returned 200; localhost redirect remains 307 to 127.0.0.1. Unverified historical proof endpoints now correctly return 409; files/records remain intact and are not automatically attested. Existing proof-panel/browser results are historical, not rerun browser acceptance after this stricter behavior. No frontend, accounts, credential guide or redirect code was changed. The first follow-up baseline's 32 accounts and 62 runs remained unchanged across the suite runs (new fixture rows are separate); schema expansion adds owner/lease fields. No isolated test databases remain and the live host slot is empty.

## Historical parent validation (2026-10-26)

Current source/test/frontend/lock snapshot SHA-256: `ca7b2f4daf827affeb5f842fa41ae51a4e439976bd2f7a44d9400778ed61062c` (inventory and hashing procedure: `evidence/parent-validation/source-final.json`). This is the working-tree snapshot, not merely Git HEAD; documentation and evidence are excluded.

- Backend whole suite: **51 passed, 5 resource-skipped, 0 failures/errors**, 56 collected, 27.67 seconds. Raw log/JUnit: `evidence/parent-validation/suite.log`, `evidence/parent-validation/pytest.xml`.
- Current Edge browser suite: **3 passed, 0 skipped/failed**, 7.1 seconds. Includes all 15 route reloads, synthetic annotation proposal → independent review → immutable child freeze at 390px, and mobile overflow checks. See `evidence/parent-validation/browser.log` and `browser-outputs/browser-results.json` in that directory.
- `npm run build` (TypeScript check + Vite production build) and project-venv `pip check` both exited 0; no broken requirements. Logs are in `evidence/parent-validation/`.
- Only the Fieldwork API was restarted because its old process predated current SSE source. The final backend/browser reruns used the refreshed API; earlier validation is explicitly archived under `evidence/parent-validation/pre-api-refresh/`.
- **No original release gate is promoted:** all 29 remain partial/blocked and every original pass condition is retained verbatim in `evidence/acceptance.json`. Earlier numbered reports and training outputs are historical, not current runtime proof.

## Retained execution evidence (historical, not rerun training)

- Real 128×128, 32/64/128-channel CNN + AdamW optimization on **45 author-generated geometric RGB images**: 30 train, 10 exploratory validation, 5 sealed fixture members. This is **execution proof only**, not flower usefulness or final holdout acceptance.
- Committed epochs 1–8; real OS child killed during epoch 9 after batch 2. Old heartbeat/checkpoint/completion rejected after server lease expiry/fence revocation. Fresh process restored model, optimizer slots, Python/Torch RNG and sampler state, replayed epochs 9–10. Final parameters and validation logits matched uninterrupted control exactly (max absolute errors **0.0**); 40 committed updates, no duplicated epoch metrics.
- Safe data-only internal candidate (safetensors/JSON), exact inventory and tamper rejection. A separate CPU process performed actual inference; logits matched the originating run within 1e-6. Ordinary browser inference and candidate download remain denied.
- Standalone stdlib metric implementation independently recomputes raw validation outputs. All 25 confusion cells, including empty cells and one-item pagination, reconcile exact IDs/counts/digests through the API.
- Session cookies, scrypt passwords, server-derived roles/workspaces, CSRF+Origin checks, idempotency conflict tests, protected holdout-media and cross-workspace denials.
- Real Edge browser exercised all 15 routes with reload, dataset inspection, actual training/evaluation history, exact cell drilldown, configuration submission and mobile overflow check. This **does not** establish complete annotation/review/holdout/release workflows or a manual accessibility audit.

Raw results: `evidence/05-replay-green.log`, `evidence/critical-proof/test_kill_restart_epoch9_repla0/replay-diff.json`, `evidence/06-bundle-green.log`, `evidence/bundle-proof/test_candidate_safe_inventory_0/fresh-process.json`, `evidence/12-cells-green.log`, `evidence/08-browser-green.log`.

## Current blocking condition

The real loopback HTTP API → PostgreSQL queue → separate worker → two training epochs/checkpoints → evaluation → fresh inference path **did execute** during an admitted window: `evidence/23-live-api-worker.log`, `evidence/live-api-worker.json`. It used generated geometric images, not flowers. FW-01/FW-02/FW-03 hardening was added afterward with isolated negative regressions; subsequent whole-worker reruns have been resource-blocked. Do not transfer the earlier success to an unexecuted later binary.

The unchanged admission threshold is **6 GiB available RAM / 12 GiB free disk** (6,442,450,944 / 12,884,901,888 bytes). The parent sample at 2026-10-26 11:46:32 UTC measured **1,634,332,672 bytes available RAM / 47,019,229,184 bytes free disk**: RAM blocked. The final suite skipped fresh optimization, kill/replay, bundle/fresh inference, direct worker and live HTTP queued-worker execution. `evidence/parent-validation/state-final.json` and `pytest.xml` are the current observations; older `current-suite.xml` and numbered logs are historical. A resource skip is not runtime success. Do not close unrelated workloads or change sibling services to clear the gate.

## Local setup (Windows 11, bash)

All commands run from this repository root, `C:/Users/user/portfolio-build/fieldwork`. Python 3.12.10 was discovered with `py -0p`; the global Python 3.14.7 is intentionally not used.

```bash
py -3.12 -m venv .venv
.venv/Scripts/python -m pip install --no-cache-dir 'torch==2.14.1+cpu' --index-url https://download.pytorch.org/whl/cpu
.venv/Scripts/python -m pip install --no-cache-dir -r requirements-api.lock
.venv/Scripts/python -m pip check
```

`requirements.lock` records every installed Python version; `requirements-api.lock` excludes only torch so its wheel comes from the explicit CPU index. These are exact-version locks, **not yet hashed wheel locks or a clean-host reproduction certificate**. Source/license/CVE review remains incomplete.

PostgreSQL uses an existing locally available image pinned by digest, but a **new dedicated container and volume**, never a sibling DB:

```bash
.venv/Scripts/python tools/bootstrap.py
# If the already-created container exists instead:
docker start fieldwork-postgres
docker exec fieldwork-postgres pg_isready -U fieldwork -d fieldwork
```

Bootstrap creates a random DB secret in ignored `.local.json`, bound to `127.0.0.1:5542`; never paste this file into chat/logs. Container: `fieldwork-postgres`; volume: `fieldwork-pgdata`; image: `postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777` (PostgreSQL 16 Alpine). Docker volume is product-local by name, not stored in the source tree. No global PostgreSQL service, SQLite fallback or external DB is used.

Provision the dedicated non-superuser/non-BYPASSRLS API login and expansion schema before starting the API. Existing account credentials and original manifests are not reset. Keep `.local-api.json`, `.local.json`, `.local-cursors.json` and private DB snapshots outside any served root and out of version control:

```bash
.venv/Scripts/python -m fieldwork.db_security
```

Create your own local account (password prompt is masked):

```bash
.venv/Scripts/python -m fieldwork.api
```

Start API and UI in separate terminals:

```bash
.venv/Scripts/python -m uvicorn fieldwork.api:app --host 127.0.0.1 --port 8102
```

```bash
cd apps/web
npm ci --no-audit --no-fund
npm run dev
```

Open `http://127.0.0.1:5102`. Vite proxies `/auth`, `/api`, `/health` to API port 8102. Everything binds loopback only. For startup probes:

```bash
curl --fail http://127.0.0.1:8102/health/ready
curl --fail http://127.0.0.1:5102/
```

The owner account CLI creates workspace `synthetic-lab`; its empty run list is honest. To inspect the already-executed proof, tests use a separately generated local proof-reviewer account and its actual proof workspace. **Do not print** ignored `.browser-test.json` (it contains generated test credentials). `python -m tools.expose_proof` reconciles real retained outputs into that workspace without claiming a new training run. It is an evidence-import helper, not synthetic result generation.

## Execute actual work when admission clears

Only trusted author-generated fixture jobs are supported. Native OS hard memory/process/network isolation is **not certified**; do not enable untrusted intake or arbitrary uploads.

```bash
# Process one explicitly chosen queued run, then exit:
.venv/Scripts/python -m fieldwork.worker --once --run-id RUN_UUID
# Or run a dedicated supervisor poll loop:
.venv/Scripts/python -m fieldwork.worker
```

The worker checks current 6 GiB RAM / 12 GiB disk admission; exit code 23 means blocked, not success. It owns the PostgreSQL heavy slot until child exit is confirmed; receives only allowlisted configs; child training/inference processes receive no database/session secret in their environment. This is **not** OS filesystem/credential/network isolation: a same-user process can still read files. Full containment, host-wide coordination across other projects, scheduler expiry scanning, hard write/RSS caps and process-tree quarantine remain release work.

Direct proof commands (trusted fixture test lane only, same admission gates):

```bash
.venv/Scripts/python -m pytest tests/test_optimization.py tests/test_replay.py tests/test_bundle.py -v -s --basetemp=evidence/reproduction
.venv/Scripts/python -m pytest tests/test_worker.py -v -s
```

Do not overwrite `evidence/critical-proof` or `evidence/bundle-proof` with a later run. They are retained historical proof inputs for current evidence-inspection tests. `evidence/internal-candidate` is an intact byte-reconciled copy of the originally verified candidate; the original negative test deliberately corrupted its own candidate after verifying inference. `evidence/candidate-retention.json` explains reconstruction and reconciles every byte to the original manifest/receipt. Future bundle tests now corrupt a separate copy.

For a trusted fixture only, fresh-process CLI:

```bash
.venv/Scripts/python -m fieldwork.infer --bundle evidence/internal-candidate --image evidence/bundle-proof/test_candidate_safe_inventory_0/images/SYN-0-6.png --expected-bundle-digest 0878328362ed5748b5c256e298b7eb98efda9af83c4043702585d122b08483cf
```

That CLI executes a real CPU process and emits an internal receipt. It does not qualify a model, clear rights or permit arbitrary-model uploads. No training occurs on the input image.

## Tests and build

```bash
.venv/Scripts/python -m pytest tests -v -s -ra --basetemp=evidence/suite --junitxml=evidence/suite.xml
cd apps/web
npm run build
node node_modules/@playwright/test/cli.js test
```

Browser tests require the two servers, installed local Edge, retained proof data and `.browser-test.json` produced by `python -m tools.expose_proof`. Passwords are generated locally and never included in test stdout. Browser traces are disabled because request-body traces can retain credentials. Screenshots and JSON test results are under `evidence/`. `npm ci` replays the committed package lock; `tools/bootstrap.py --frontend` is **initial version discovery only**, not a reproducible reinstall command.

Tests retain one vertical RED→GREEN log pair per feature slice. A skipped heavy test is not a passed runtime criterion. Metadata/security tests use the real dedicated PostgreSQL server, not SQLite or a fake repository. Some inspection tests intentionally depend on retained successful proof artifacts; clean-empty-host execution is a separate **unpassed** release gate.

## Missing release gates / deliberate differences

- Flower asset-level acquisition/rights clearance, natural-image duplicate review, minimum supports, final unseen holdout usefulness and steward exposure protocol: **blocked, never waived**.
- Trusted-fixture annotation proposals, independent digest-bound proposal/version review, stale-revision rejection and immutable child freeze **are implemented** in PostgreSQL/API/UI. The exact R5 `small-residual/v1` candidate now has a separate qualified-release download and fresh-image inference source path. It is available only when migration 012, the pinned qualified model image, consumed-plan row and current signed rights checks are all ready. Internal compact-CNN candidates remain inspection-only and are rejected by both ordinary inference selectors. The runtime contract and source SHA256 manifest are in `docs/qualified-release-runtime-20261102.md` and `docs/qualified-release-runtime.sha256`.
- Fixture preprocessing resizes to 144×144 then center crops 128; no random train augmentation. This is an explicit synthetic execution profile, **not** the full blueprint's natural-image preprocessing/augmentation contract.
- HTTP requests use a dedicated **non-owner, non-superuser, non-BYPASSRLS API principal**; FORCE RLS, request-local default-deny tenant scope, reused-connection isolation and composite-FK denial regressions pass. Admin/controller credentials remain separate. Sessions enforce 12h absolute and 30m idle expiry, replace the presented old cookie on successful login, and reject changed role/workspace or logout. Loopback cookies still lack secure HTTPS; full command/role/worker-capability security acceptance and independent review remain unpassed. This is not production authentication or a general pooled-connection/load certification.
- Real PostgreSQL barrier-controlled cancel-first/publication-first regressions for checkpoint and completion now pass; repeated cancellation cannot certify unknown physical exit. Every file-sync/commit crash edge, disk-full, power-loss durability, orphan GC, process-tree quarantine, restore-generation revocation and independent-volume backup restore remain unverified. Current same-volume dump/blob restore uses an isolated DB and preserves live data; expansion migration is repeatable on a restored historical snapshot. Neither is full disaster recovery/rollback acceptance.
- Bounded data-only JSON/tensor headers, exact inventory/shapes, controller digest anchors, promoted checkpoint copies, cross-file evaluation consistency and separately durable artifact stages are implemented and tested. OS hard memory/CPU/tree limits, restricted filesystem identity, separate network-denial tests and full hostile parser qualification remain incomplete. No untrusted job should be enabled.
- Authorized **SSE and polling both exist**: durable event IDs, string sequence cursors/object revisions, seven-day replay filtering, expired cursor 410/resnapshot and live logout revocation are currently tested. The refreshed API closed a revoked stream in 0.265 seconds. Complete duplicate/out-of-order client reconciliation, reconnect/offline UX and full role/membership matrix remain unpassed. Live 6GiB/12GiB admission, idempotency-before-admission replay and atomic 20-queued-per-workspace cap exist; signed expiring preflight/reservations and full host resource budgets remain incomplete.
- Precision/null reasons, disposition denominators, missing buckets, Wilson accuracy and deterministic group-bootstrap intervals plus predicate-bound expiring slice cursors are implemented/tested on fixtures. They do not establish natural-image usefulness or the complete evaluation/release contract.
- The 15 routes and **three current Edge tests** are not a manual keyboard/screen-reader/browser matrix, accessibility certification, load/performance result, clean independent rebuild or independent release review.

Full ID-by-ID truth: `evidence/acceptance.json`. Local source only; no paid APIs, public remote, public deployment, flower download or pretrained weights. Original mockup/input files and sibling projects were not edited.
