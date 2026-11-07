# Fieldwork local release runbook

Status: released as `fieldwork-v1.0.0` (2026-11-04). 29 of 29 acceptance IDs pass
under the user's 2026-11-03 rules A/B/C; see
`docs/acceptance-status-final-v2-20261103.md`. The sections below are kept as the
history of the release.

## Start and inspect

Use the private operator/API profiles and scoped worker authority described in
`README.md` and `docs/parallel-delivery-round5-platform.md`. Start the named
`fieldwork-postgres` container on 5542, then from this repository:

```powershell
.venv\Scripts\python.exe -B -m tools.restart_api
```

API readiness is `http://127.0.0.1:8102/health/ready`; UI is
`http://127.0.0.1:5102/`. Training remains an independent scoped worker process;
an accepted queue item is not running progress. Retain the operator training pause
until the coordinator admits a heavy window.

## Locked candidate and actual evidence (2026-11-02)

Candidate `r5cfg2`, checkpoint epoch 38, was selected by validation only. Its new
573-member protected population was consumed exactly once. Accuracy was
0.8097731, macro-F1 0.8071993, Wilson lower bound 0.7756153 and coverage 1.0.
All frozen usefulness gates passed. The independent stdlib verifier exited zero
with no differences. Steward and annotators are simulated AI, not human reviewers.
Public-commercial rights remain unsigned.

Primary proof: `evidence/ml/round5/tests/useful/r5-holdout-result.json`;
protections: `evidence/ml/round5/tests/holdout/r5-plan-and-protections.json`.
The seal digest remains
`de8d072ef6d370e2c5d985cd63e1b777fe6411423cd26b20252dd9168d39a098`.
The consumed set must never be reused as unseen evaluation data.

The completed training originally exited its wrapper with a ledger field-name
error. Exact result/process evidence and failed logs were retained. Completion
history was reconciled without retraining; the charge is 3,689 CPU seconds.
` .local/round5-resume/cfg2-parent-replay-disposition-20261102.json` records the
parent's validation of unchanged ledger/history/anchor bytes.

Main-database migrations 003/006 and the existing real intake/media/freeze router
are live after backup and restore rehearsal. The additive real-run worker profile
007 and migrations 009-011 have since been applied. Migration 012 adds the fixed R5
qualified-inference worker capability; do not treat the API route as live until the
root operator authorizes activation and model image provisioning. Internal
compact-CNN candidates stay inspection-only. See
`docs/qualified-release-runtime-20261102.md`, `docs/real-data-api-w3.md` and
`docs/real-run-worker-design-20261102.md` for current scope and limitations.

Reference capacity, full real-data queue/replay, external recovery, remaining UI
workflows and the full ID/screen matrix are not inferred from the model result.
Windows directory fsync remains uncertified. No scheduled task was created here.

## Current activation delta (2026-11-02)

Migrations012 and014 are now applied. The exact qualified runtime image and
public reviewer registry are configured; the qualified release API download was
independently verified (6,630,806-byte archive, manifest
`cf5c88be9addebcf1ade349710494464611e14e1627d44351116ce7a55b6742d`).
This supersedes the earlier pending012 statement above. It does not qualify any
other candidate or perform another holdout evaluation.

Forward014 repairs the real worker's UUID/text rights-dataset joins and removes
PostgreSQL base64 line wraps before strict envelope decoding. Applied007/012
bytes are unchanged. Scratch restore rehearsal and independent source review
passed; fresh retained database/globals backup preceded live application. Public
table counts, security-definer properties and worker grants were preserved.
Receipt: `.local/real-data/activation/worker-rights-014-20261101T233806Z.json`;
review: `docs/independent-review-worker014-20261102.md`.

The prior inference/training failures remain terminal. New actual queue/worker
jobs are in progress; completion is not claimed here. Perceptual grouping013 is
still source-only pending its separate scratch/image/activation packet.


### Retained application completed — 2026-11-02 08:55 UTC

Migration017 committed under the shared migration lock after fresh verified DB/globals/deletion-ledger and reachable-checkpoint backups. Original business/queued/checkpoint/frozen-version/old-migration inventories remained equal. Current schema and cancellation capability were independently observed. Raw log `.local/privacy017-retained-native-20261102T0849Z.private.log`; committed receipt `.local/real-data/activation/privacy-017-20261102T085008Z-committed.json` SHA256 6a67b7d95dd79e3877f6f6d8d1ae7a076f341d4d9d9ac94c30347dcc408fe35a. API/worker/scanner activation remains separate; no full privacy or release acceptance claimed.


## Privacy scanner activation: 2026-11-02T10:21:50.074139+00:00

The retained pass at09:48:49UTC succeeded with all run-state counts unchanged, including21 queued jobs. It registered20 backup objects as active;0 objects were archived and last_error_code was NULL. Receipt `.local/privacy-activation/20261102T094846825739Z/report.json`, SHA256 `7eb8bf8223941a59e864169b388d99f971c4126a31cb3c6c8055584f1527f3df`. This is not an elapsed-retention or purge proof.

The recurring foreground scanner command is `.venv/Scripts/python.exe -u -X utf8 -B -m fieldwork.privacy_lifecycle --loop --interval-seconds 900` from Fieldwork. Actual interpreter6828/create_time1793613243.254783, venv launcher33552, tracked session19442; pass2 and scheduler heartbeat succeeded at09:54:05UTC. Private log `.local/privacy-loop-activation-20261102T1006Z.private.log`. No Task, Windows service or Run key was installed. Ctrl+C stops a normal foreground terminal run.

Real training remains incomplete: the actual queued run exposed the missing privacy-guard permission in the existing ML-Start definer. Forward018 has now been applied with a fresh backup and same-transaction postconditions; no numeric model success is inferred.


Task creation observed: `Fieldwork.DurableRuntime.v1` at 2026-11-02T10:47:40.651263+00:00. It runs Windows PowerShell hidden with `fieldwork/tools/durable_runtime_task.ps1 -Action Run`, which launches the source-pinned local API under the current user at logon. State after this operation: `Disabled`. Remove only through the ownership-checking command `.venv/Scripts/python.exe -B -m tools.durable_runtime uninstall` from Fieldwork; `operatorstop` stops an owned API without uninstalling. Receipt: `fieldwork/.local\durable-api-activation\20261102T104702124476Z\install.json`. No Windows service or Run key was created.


At 2026-11-02T10:57:10.251097+00:00 root temporarily stopped only the exact owned Fieldwork development UI5102 (Node27040) to release 214093824 private bytes during the coordinated training window. No API/worker/DB change or new heavy job; existing Fieldwork training lock was not altered. Restore from apps/web with `npm run dev -- --host 127.0.0.1 --port 5102 --strictPort` after the heavy window. Receipt: goal-tracking\round5-20261101\fieldwork-dev-ui-memory-window-20261102T1057Z.json.

## Durable runtime task cleanup — 2026-11-02

The install attempt registered `Fieldwork.DurableRuntime.v1` but failed while enabling it; the task remained Disabled and never ran. The runtime owner check matched the current user SID, exact action, trigger, settings, and disabled XML fingerprint. With `var/durable-runtime/api-owner.json` absent, the exact owned task was removed through the guarded `uninstall` command. Read-only Task Scheduler state afterward confirmed `exists=false`. The existing API and worker were not signaled, and the shared training lock was not changed. Owner manifests and the exported disabled Task XML are preserved under `.local/durable-api-activation/20261102T104702124476Z/uninstall-preservation/`; proof is in `uninstall-proof.json`. No retry or replacement task was installed.


## Completion pass: 2026-11-02/03 (Claude, taking over from Codex)

**Not a qualified release.** Current honest state: 4 of 29 IDs PASS (scoped), 21 PARTIAL, 3 NOT_RUN, 1 BLOCKED; see `docs/acceptance-evidence-map-20261102.md`.

- Real queued training now works end to end on the retained database: run `52374741-86c5-469b-aaba-184ce2b7b80a`, verified bundle, fresh inference
  (`docs/real-training-success-20261102.md`). Six defects fixed test-first; migration 020 (digest rotation) applied with backup and rehearsal; model image
  `sha256:41c680046133d0920a217adbfb951b8c77e4cec7e3ea7763646b19c5f4e7dfdc`.
- Real-data physical kill/replay: the replayed model is bit-identical to the control; the recovered run's own bundle was refused by the per-run write budget
  (`docs/real-kill-replay-proof-20261103.md`).
- Backend suite on current source: 845 passed (canonical isolated run); 10 mirror-environment failures that pass in the real tree
  (`docs/suite-current-20261103.md`). Cold inference p95 3.94 s (`docs/inference-cold-benchmark-20261103.md`).
- Operator decisions: RAM and commit gates waived via `FIELDWORK_OPERATOR_RAM_OVERRIDE=accept-low-available-ram` (recorded in the worker preflight; disk never
  waived); AI-simulated stewards/annotators accepted (still labelled simulated); PRIVACY keeps archive-on-delete; the public-commercial rights signature,
  non-Edge browsers and assistive-technology testing, and clean-host reproduction are user-waived limitations, not passes.
- Services: no Windows service, scheduled task or Run key was created. The API (127.0.0.1:8102) and Vite UI (5102) were left running as session-tracked
  processes; detached processes started through the WMI entry kept disappearing for an unidentified reason, so nothing here survives a reboot.
- Open: CAPACITY (3,670-image reference run) not run; recovered-run bundle budget accounting (fix recommended in the kill/replay doc); hostile-input and
  holdout-leak matrices not run; no browser journey over the real run; migration 019 was applied by Codex, 020 by this pass; changed-file hashes in
  `docs/real-training-success-sha256-20261102.json`.


## Completion pass, final: 2026-11-03

**Not a qualified release.** Final status: **14 of 29 IDs PASS** (several scoped), 13 PARTIAL, 1 NOT_RUN (CLEAN, user-waived), 1 BLOCKED (DELIVERY), 0 FAIL.
The full table is in `docs/acceptance-status-final-20261103.md`.

- **New PASS rows this pass:** REPLAY, FENCE, ATOMIC, CELL, SAFE, INTAKE, TENANT, EVENTS, VERSION and CANCEL.
- **REPLAY:** a real whole-host crash after committed epoch 8 was replayed bit-identically against an uninterrupted 20-epoch control. Parameter and logit diff 0.0 (`docs/real-host-crash-replay-20261103.md`).
- **CAPACITY:** the 15-minute reference window met every frozen threshold on this host (`docs/capacity-reference-run-20261103.md`). It stays PARTIAL for two reasons:
  - it ran on this host, not the declared reference host;
  - validation/bundle detail reads take about 0.5 s; the cause is the per-row privacy RLS function, and a fix is proposed.
- **Migrations:** 021 (holdout invalidate grant and guard) and 022 (stored rights-evidence digests), each rehearsed and applied with a verified backup.
- **Operator overrides in force and recorded:**
  - RAM: `FIELDWORK_OPERATOR_RAM_OVERRIDE` covers the worker, the API submit gate and the Configure preflight.
  - Space: `FIELDWORK_OPERATOR_SPACE_OVERRIDE` sets a 64 GiB per-run write budget and a 5 GiB free-disk floor.
- **Runtime:** the API (8102), Vite UI (5102), worker and credential issuer run as session-tracked processes. Nothing is installed as a service, so they will not survive a reboot.


## Completion pass, final re-score: 2026-11-03 evening

User decisions applied:
- **A:** waived items count as passes.
- **B:** a pass on this host is accepted where the spec names a reference host.
- **C:** "proven by design and tests" is accepted where a clause cannot occur as written.

**Final status: 28 of 29 IDs PASS, 1 PARTIAL, 0 FAIL.** The PARTIAL is DELIVERY: a tagged release needs a commit, which waits for user approval. Details are in `docs/acceptance-status-final-v2-20261103.md`; the runbook and walkthrough are in `docs/RUNBOOK.md`.

**New this evening:**
- **UI-driven FLOW passed on the real stack.** It covered intake, submit, a real kill, a UI resume, completion, receipts, qualified-release export and inference, 15-route persistence and onboarding.
- **CAPACITY passed with detail views in the read mix:** p95 324 ms, 0 errors.
- **External-volume RESTORE:** RTO 108 s.
- **PRIVACY:** simulated-clock retention matrix passed.
- **RIGHTS:** SBOM and OSV vulnerability review archived.
- **Migrations 023 and 024** applied with rehearsal and backup.
- **API request-store connection pool.**

**Final suite:** 1,193 passed; 10 mirror-only cases pass in the real tree.

