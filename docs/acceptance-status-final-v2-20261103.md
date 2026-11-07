# Fieldwork acceptance status — final, re-scored (2026-11-03 evening)

Supersedes `acceptance-status-final-20261103.md`. On 2026-11-03 the user set the acceptance bar to three rules:
- **A:** user-waived items count as passes.
- **B:** "PASS on this host" is accepted where the spec names a reference host.
- **C:** "proven by design and tests" is accepted for clauses that cannot occur as written.

Each relaxed pass names its rule and keeps the underlying gap visible. Everything else is real execution on current source. Simulated humans are labelled as simulated.

**Result: 29 of 29 PASS, 0 FAIL (DELIVERY closed by the `fieldwork-v1.0.0` tag on 2026-11-04). The 15-screen matrix passes.**

## By ID

### Passes on real execution

| ID | Evidence |
|---|---|
| OPTIMIZE | r5cfg2 audit, plus real queued 20-epoch runs (`394fadf8`, `3fc4d517`, `16c40f6e`). |
| METRICS | The independent verifier reconciled the real population; metric tests pass. |
| INTAKE | Hostile intake matrix (`acceptance-safe-intake-matrix-20261103.md`) plus a live UI intake through the real worker: counts and per-file reasons in the UI equal the API, 0 new sample ids. Migration 024 fixed the intake worker's row-lock privilege. |
| SPLIT | `tools/verify_split_current.py` on the frozen version: 0 cross-split sample, raw, pixel or group overlap. pHash was recomputed on all 3,655 admitted images: all 21 near-duplicate pairs fall within one group and one split. All 3,677 intake members reconcile, and the freeze check refuses migrating or dropping a protected group. |
| CELL | Every confusion cell plus the missing bucket match across UI, API and disk (Edge and Chrome, 31/31). |
| QUEUE | `acceptance-queue-holdout-final-20261103.md`: idempotency, 409 on body change, real TCP response-loss replays without duplicates, and restart with queued runs. The 20-queue cap is enforced (C: real runs meet the stricter workspace run limit of 2–16 first, by design). |
| FENCE | Diagnosis stage 25 passed (45 s lease; marked expired within 10 s); stale-writer matrix; real-crash fence advances. |
| REPLAY | A real host power loss after committed epoch 8, replayed from epoch 9, is bit-identical to the uninterrupted control (parameters and logits diff 0.0). |
| CANCEL | Barrier orderings and the scoped SQL capability; the slot is held until the OS child exits. |
| SAFE | Hostile pickle, TorchScript, header, bomb, shape/dtype/key and digest cases rejected without executing the payload. The pinned container has no network (independent control proves it), no secrets, a read-only root and limits. |
| TENANT | Every OpenAPI route probed cross-tenant, plus pooled-connection reuse and CSRF checks (re-run with the new connection pool). |
| EVENTS | Ordering, replay and dedup; the stream closes within 1 s on 7 revocation paths. |
| RESTORE | External-volume drill: backup copied to the SSD (`E:`), corrupted copy refused, restore from the SSD into a brand-new empty container. Tables are hash-identical, and 102 checkpoints, 3 bundles and 4,228 images are digest-verified. Tenant controls hold, leases are fenced and the old worker is refused. RTO 108 s, RPO 5 min. |
| FLOW | UI-driven end to end on the real stack (`apps/web/real-flow.spec.ts`, Edge): intake, then submit, then a real worker kill after epoch 2. Recovery resumed from the Recover screen (twice: the second time after an infrastructure failure), the run completed and its artifact was verified. Receipts appear in the UI, the qualified-release download digest matches, fresh inference ran, all 15 routes persist, and help and Getting started are present. Export and inference go through the qualified release, the product's design for both (C). |
| BUNDLE | Bundle verification covers digests, shapes, class map, preprocess and rights. The fresh-process artifact inference is verified. Two independently trained bundles match (logits diff 0.0). A candidate download returns 403 `QUALIFIED_RELEASE_REQUIRED`. The qualified release was downloaded and verified through the UI, and holds no protected content. |
| HOLDOUT | Leak matrices on the API and on a real built bundle, plus worker job inputs, all before and after consumption. Migration 021 fixed steward invalidation. Simulated AI steward. |

### Passes under a named rule

| ID | Rule | Evidence and the gap the rule covers |
|---|---|---|
| USEFUL | A | Holdout n=573: accuracy 0.8098, macro-F1 0.8072. Annotators and steward are simulated AI; the public-commercial signature is waived. |
| VERSION | C | Concurrency matrix on the annotation workflow; `freeze_real` concurrency covered by design. |
| ATOMIC | C | Crash and disk-full matrix, plus a committed checkpoint surviving a real power loss. Windows directory fsync is uncertified. |
| UX | A + C | Automated on Edge and Chrome: keyboard, focus, skip link, 320 px / 200 % / 390 px without overflow, 44 px targets, offline, axe 0 violations. Human assistive-technology testing is waived. Dialog focus-return doesn't apply (no non-destructive dialog). |
| BROWSER | A | Edge 156 and Chrome 156 on Windows 11, real records; mutating tasks run in Edge through FLOW. Firefox, Safari, iOS and Android are waived. |
| CAPACITY | B | 15-minute window during real training, with the validation, slice and bundle views in the mix: read p95 324 ms (each kind ≤ 438 ms), 0 errors in 18,007 reads, command p95 85 ms, interaction p95 32 ms, 0 long tasks. Training RSS 887 MiB on 2 CPUs; the 20-epoch run took 50 min. The host has 16 cores and 31 GiB, not the reference spec. |
| INFERPERF | B | Cold p95 3.94 s on this host. |
| RESOURCE | C | Defaults are enforced and tested. No preflight token exists to go stale: admission is recomputed live by design. The live operator RAM and space overrides are recorded. |
| MIGRATE | C | 020–024 are expand-only. Each was rehearsed on a restored copy, then applied after a verified backup, with no row or event changes. Old column-explicit code paths pass against the new schema. A literal old-binary rollback isn't meaningful: the committed `HEAD` predates the migrations. |
| CLEAN | A | Clean-host reproduction by a different reviewer is waived. The runbook documents the environment. |
| RIGHTS | A | Per-asset signed decisions are enforced. SBOM and licenses are archived (131 packages, 0 unknown licenses). OSV vulnerability review: 3 affected tooling packages triaged, low risk, upgrade at next rebuild (`evidence-rights-sbom-20261103/`). Simulated signer; commercial signature waived. |
| PRIVACY | C | Retention matrix with a simulated clock, 9/9 (`acceptance-privacy-retention-20261103.md`); 3 defects fixed. |

### Closed on 2026-11-04

| ID | Rule | Evidence |
|---|---|---|
| DELIVERY | A for the human approvals | Runbook and walkthrough (`RUNBOOK.md`), backup and restore, immutable evidence, and the waived approvals. The release is committed on branch `release/fieldwork-v1.0.0` and tagged `fieldwork-v1.0.0` with the user's go-ahead. Private operator state (`.local/`, `.cache/`, `var/`) is excluded by `.gitignore`. |

## Defects fixed in this evening pass
1. Live intake failed on every already-imported image: the intake worker lacked the row-lock privilege on `fw_samples`. Fixed by **migration 024** (inert capability column, as in 015).
2. Windows ephemeral-port exhaustion under load killed a training attempt (`OSError`), because the API opened a new PostgreSQL connection per query block. Fixed with a request-store **connection pool** (`fieldwork/store.py`). The pool resets session state, re-checks role and database settings on every checkout, and drops dead connections. Validation reads went from 8.5–11 s this morning to about 150 ms.
3. The privacy-tombstone RLS function ran once per row. **Migration 023** evaluates it once per statement, with identical results.
4. Three privacy defects: the workspace-deletion route returned 500 (missing import), the deletion pass ran on a closed connection, and backup expiry used the wrong digest.
5. UI additions: intake detail (counts and reasons), artifact receipt panel, Getting-started onboarding.
6. A misleading settings label for dataset-media retention now states the actual policy.

## Final test runs
See `suite-final-20261103.md` (written with the last full run's numbers).
