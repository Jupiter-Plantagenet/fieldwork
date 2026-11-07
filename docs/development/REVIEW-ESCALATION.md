# Fieldwork recovery escalation — terminal compute-slot ownership

## Status

User authorized exactly one further bounded correction and independent re-review (2026-10-27 KST). **That scoped correction passed fresh independent review and parent reruns, and the retained API was refreshed to the pinned source.** The prior terminal-commit/finally-release finding is closed only in this reviewed scope, not full ML/release acceptance. Independent review ran39 actual isolated-PG/tiny-process checks; parent safe subset ran78 passed,2 genuine heavy skips,1 live-writing deselection. All51 source pins match, all8 non-session table digests (including accounts, runs, events and evidence anchors) were unchanged across refresh, compute slot remains empty, and all three existing-account/canonical-host checks pass. No schema migration, credential rotation, new ML execution or separate worker start occurred. Current API handle: `proc_755c168f6e1c`; evidence: `evidence/terminal-slot/parent-activation.json`, `parent-safe.log`, and `../independent-review/terminal-slot-final/review.json`. No further automatic correction round is authorized for this finding. Ambiguous launch/manual physical reconciliation and heavy current-source execution remain separate limits; original historical reports are preserved.

## Finding entering the authorized correction (historical reviewed snapshot)

Independent current-source review: `../independent-review/final-fieldwork/review.json`, finding `FW-03-POST-FAILURE-TERMINAL-SLOT` (medium).

`artifact_transition` commits `failed` or `verified` in one transaction; the worker calls `release_slot` later from `finally`, in another transaction. A crash or DB failure in between can leave a global compute slot owned by a dead supervisor even when no child exists and spawning is not ambiguous. Recovery only scans pending/building/inference, so this known-safe-to-reconcile terminal case is missed. Restarted workers cannot release a slot owned by a different PID/create-time identity. New heavy work can remain blocked indefinitely.

This is an availability/recovery failure, not a demonstrated evidence-forgery or unsafe eviction. The independent reviewer used exact-body seam probes with explicit fake SQL/process boundaries; a future correction needs real isolated PostgreSQL + process-death regression evidence.

## Proposed bounded correction for review

- Place eligible terminal publication and slot release within one transaction, only when the current owner/fence is exact and physical child exit is confirmed.
- Reconcile legacy terminal slots after an expired lease and confirmed dead PID/create-time owner, only for the exact slot/run/fence and confirmed dead registered child with no ambiguous launch.
- Preserve verified artifact attestations, evidence bytes and terminal success; do not rebuild a verified result or reset its attempt budget to clean a slot.
- Preserve live-owner/live-child retention, stale-fence rejection and the explicit `ARTIFACT_CHILD_EXIT_UNCONFIRMED` manual-reconciliation boundary.
- Add RED/GREEN regressions at failed/verified commit-before-release barriers, process kill/restart, stale-owner/new-owner races, live-child retention, ambiguous launch and unchanged verified evidence. Then independently re-review the changed transaction/cleanup paths.

The bounded design above passed scoped independent review and parent reruns; see the current Status section for activation evidence. The original failed review and implementer disposition remain unchanged historical snapshots. This does not claim newly executed ML, complete crash containment or full release approval.

## Other scoped review results

The same reviewer closed `FW-02-POST-API` in its snapshot: evaluation/records/slices/artifacts use bounded read-once DB-manifest-anchored evidence, reject payload tampering, and do not reopen paths after verification. This is not full ML release approval or OS same-user isolation certification.

## Separate resource blocker

Heavy current-source ML tests still require the unchanged 6GiB available RAM and 12GiB free-disk admission thresholds. The user was asked to free memory; no answer was received. No unrelated application was closed and no threshold was waived.
