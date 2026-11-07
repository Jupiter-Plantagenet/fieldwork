# Test suites on final source (2026-11-03 evening)

| Suite | Result | Log |
|---|---|---|
| Canonical light, full (isolated mirror + `fieldwork-pg-verify`) | **1,193 passed**, 10 failed, 4 skipped | `parallel-round5-logs/resume-light-20261103T135557Z.log` |
| The 10 mirror-only failures, run in the real tree | **10 passed** | console, 2026-11-03 ~14:10 UTC |
| Startup stage | 28 passed | `resume-startup-20261103T084251Z.log` |
| Diagnosis stage (45 s lease, identity, cancel ack, slot reconcile) | 25 passed | `resume-diagnosis-20261103T094817Z.log` |
| Torch-executing files (replay, optimization, bundle, worker, faults, artifact stages, postfix, checkpoint, atomic crash edges) | 42 passed | `resume-light-20261103T084311Z.log` |
| Browser: real journey + CELL | Edge 84/84 + 31/31, Chrome 84/84 + 31/31 | `evidence-browser-real-20261103/{edge,chrome}-final-*` |
| Browser: UI-driven FLOW (intake, submit, recover, finish) | all phases passed (Edge) | `evidence-browser-real-20261103/edge-flow-{intake-04,submit-01,recover-01,recover-02,finish-03}` |
| Browser: UX (keyboard, zoom, 320/390 px, 44 px, offline, axe) | 6/6 | `evidence-browser-real-20261103/edge-ux-10` |

**The 10 mirror-only failures.** These are environment artifacts that pass in the real tree:
- 5 need `tools/product_lock.py` / `activate_real_worker.py` beside the mirror;
- 2 exceed the Windows 260-character path limit under the mirror path;
- 1 needs the venv interpreter;
- 1 needs the heavy slot;
- 1 is the decoder early-exit case.

The earlier ephemeral-port errors are gone: the API's request store now pools connections.
