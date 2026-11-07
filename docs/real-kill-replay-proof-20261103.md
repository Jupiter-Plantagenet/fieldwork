# Real-data physical kill / replay proof (2026-11-02 23:49 KST – 2026-11-03 00:47 KST)

Procedure: `real-run-kill-replay-procedure-20261102.md` (checkpoint-synchronised variant: the worker is killed after epoch K is
durable while the next-epoch model container is live; it does **not** claim a specific batch inside epoch K+1).

| | Control (uninterrupted) | Replayed (killed after epoch 1, resumed) |
|---|---|---|
| Run id | `52374741-86c5-469b-aaba-184ce2b7b80a` | `7c40ef06-222c-4ad1-b7f0-0e772279bae7` |
| Config | frozen version `01a0f1aa-…` rev 3, 2 epochs, batch 16, lr 0.001, seed 42, model image `41c68004…` | identical (`config_equal: true`) |
| Checkpoint epoch 1 | `17e9450a…67bc` | `17e9450a…67bc` (the pre-kill checkpoint, reused) |
| Checkpoint epoch 2 | `e51e6817…25d7` | `e51e6817…25d7` |
| Final weight digest | `da00879e479b7608151a73002836687f60a6eae00611387303e01c0619c38d0b` | identical |
| Epoch-2 row (train/val loss, val acc, weight digest) | — | identical to control's epoch 2 |
| Updates | 320 | 320 |

Evidence: `.local/real-data/kill-replay-20261102T135354Z/{kill.json,resume.json,comparison.json}`, worker logs
`var/activation/fieldwork-real-training-worker-foreground-*.out.log`, DB events 398–432 of the replayed run.

## Sequence actually executed

1. Submitted the run through the API; worker claimed it; staged all 3,108 inputs (~55 min).
2. `kill.json`: at epoch 1 / fence 1 the worker (`pid 11520`, creation time pinned) and its two docker CLI children were killed in
   0.03 s; the model container (`objective_euclid`) stayed up; run still `running`.
3. Runner cleanup (`ModelContainerRunner.recover_stale`) removed the exact nonce container and `fw-model-*` volume;
   `product_lock recover` removed the dead owner's lock only after cleanup (`OWNER_PID_ABSENT`, audit file written).
4. Scoped lease machine (`expire_killed_training_run_once.py`, one target run only): `running → interrupted`, fence 1 → 2,
   event `LOGICAL_EXPIRY_IS_NOT_PHYSICAL_EXIT`, slot retained.
5. `Store().reconcile_training_slot()` → `RELEASED` (`OWNER_AND_CHILD_EXIT_CONFIRMED`).
6. API `POST …/resume {"replay_epoch": 2}` → 202, run `queued`.
7. Fresh worker re-staged inputs, resumed from checkpoint 1 (fence 3), committed epoch 2, run `succeeded`.

## Limitation found (not changed)

The recovered run's **artifact stage failed** with `MODEL_RUN_WRITE_BUDGET_EXCEEDED` (artifact status `failed`, no bundle for this run).
The per-run model write ledger (`limit 2 GiB`) holds: killed attempt 1,202.7 MB (its output could not be measured after the kill, so
it was charged at the full output cap, 814.4 MB) + resumed training 390.6 MB = 1,670.7 MB charged; a bundle stage needs ≈ 548 MB more.
The control run, with no kill, fits. This is a disk-write safety budget (not a RAM gate), so it was not relaxed. Consequences:

- The replay equivalence rests on equal checkpoint digests and final weight digest, **not** on a fresh inference receipt from the
  replayed run (procedure steps 7–8 inference comparison not done for the replayed run).
- A run recovered from a physical kill cannot currently produce its own bundle inside its original budget scope. Recommended fix
  (needs a reviewed product change): measure the dead attempt's output in `recover_stale` before removal and charge actual bytes,
  keeping the full-cap charge only as the fail-closed fallback; or budget per attempt.

## Not covered

No batch-level pause hook; Windows directory fsync remains uncertified; one physical kill (single trial).
