# ML-T-REPLAY: real host crash after committed epoch 8, replay from epoch 9 (2026-11-03)

**Result: PASS.** This is the frozen scenario (kill partial epoch 9 after committed epoch 8, restore in a fresh CPU process, compare with an
uninterrupted run). The kill was not staged: the whole PC froze and was hard-reset while run A was in epoch 9.

| | Replayed (run A) | Uninterrupted control (run B) |
|---|---|---|
| Run | `394fadf8-b61e-470a-ab33-699aadae10a2` | `3fc4d517-24c5-4bd7-92f9-95a5efd5249e` |
| Config | 20 epochs, batch 16, lr 0.001, seed 42, version `01a0f1aa` rev 3, image `41c68004...` | identical (`config_equal: True`) |
| Committed epochs | 1-8 by attempt `3d66982b` before the crash; 9-20 by attempt `0f96b40a` | 1-20, one attempt, fence 1 |

## What happened
1. 03:06:33 UTC: epoch 8 committed. The PC froze and was powered off with the button at 03:06:48 (Kernel-Power 41, BugcheckCode 0). It booted at 03:07:33.
2. After the restart, recovery ran in this order:
   - runner `recover_stale` removed the dead model container and volume;
   - `product_lock recover` released the dead owner's lock (`OWNER_PID_ABSENT`);
   - the scoped lease machine marked the run `interrupted` (fence 1 to 2);
   - `reconcile_training_slot` returned `RELEASED`;
   - an API resume with `replay_epoch` 9 returned HTTP 202.
3. The first resumed attempt `a27aaaa3` stalled during staging because the 5-minute worker credential expired. The credential issuer
   process had not been restarted after the reboot, and the attempt committed nothing. The same recovery was repeated (fence 3 to 4) and the issuer was started.
   Attempt `0f96b40a` then replayed epochs 9-20 and built and verified its own bundle (07:33 UTC). The per-run write budget no longer blocks recovered runs (operator space override).

## Comparison (`tools/compare_replay_runs.py`, `.local/real-data/host-crash-replay-20261103/comparison.json`)
- Committed epochs [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]: no duplicates (True). Epochs 1-8 come from before the crash and 9-20 from the replay.
- Every epoch row equals the control's (train loss, validation loss, updates, checkpoint manifest digest): before the kill True, after True.
- Final parameters: max abs difference **0.0** (frozen <= 1e-6) over all tensors; same keys and shapes.
- Pinned CPU predictions on the same 550 validation samples, each from its own verified bundle: top-1 disagreements **0**,
  max abs logit difference **0.0** (frozen <= 1e-6).
- Bundle model digest equal: True. Within the frozen envelope: **True**.

The committed epoch-8 checkpoint survived a real power loss and restored the model, optimizer, RNG and sampler state; otherwise epochs 9-20 could not match bit for bit.
That is also evidence for ML-T-ATOMIC's "committed checkpoint survives a durable storage restart" (one trial).

Evidence: `.local/real-data/host-crash-replay-20261103/` (`cleanup.json`, `comparison.json`), `.local/real-data/kill-replay-20261103T0618Z-hostcrash/resume.json`,
lease-expiry intents and results under `.local/real-data/training-submissions/`, and the DB events of both runs.
