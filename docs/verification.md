# Publication-candidate verification

Executed on 7 November 2026 using the local review copy.

- Fresh installation from `requirements-api.lock` and `pip check` passed.
- The separately pinned CPU PyTorch wheel installed successfully.
- Fresh `npm ci` and the TypeScript/Vite build passed.
- `python verify.py` passed 21 checks covering independent metrics, synthetic manifest integrity, and standalone helper resolution, slot-process path normalization, and worker handoff/liveness behavior.
- A fresh one-epoch synthetic training run committed one checkpoint, made four updates, and produced ten validation predictions.
- The current npm advisory query reported zero findings.

## Evidence

[Command receipt](verification/review-checks.json) records each command and its exit status. The command logs are in the same directory. [The npm audit result](verification/npm-audit.json) records the advisory query at verification time.

## Scope

The installs used fresh local environments and dependency directories on the original host. The broader original project results are historical measurements, with their original datasets, private runtime state, platform assumptions, and waivers. The full public deployment and full integration campaigns remain separate from these focused publication checks.

The small commands are documented in [the reproduction guide](reproduction.md). The test-to-claim mapping is in [the reviewer guide](../REVIEWER_GUIDE.md).
