# Fieldwork engineering overview

ML experiments need identifiable input populations, inspectable prediction errors, and enough saved state to recover from an interruption without silently changing the experiment.

Dataset versions bind content digests and splits. Metric calculation preserves missing predictions in the denominator and is compared with a separate verifier. Training attempts use leases and fences. Checkpoints retain model, optimizer, RNG, and sampler state, and verified artifacts bind preprocessing and class metadata.

## Source map

`fieldwork/` contains the Python implementation. `apps/web/` contains the React workbench. `tests/` contains metric, security, worker, and replay checks. `migrations/` contains the database migrations. `ops/` contains decoder and model containers. `tools/` contains repository-local verification and operator helpers.

[The reviewer guide](../REVIEWER_GUIDE.md) maps the claims to concrete tests and expected outputs.

## Repository byte integrity

Git preserves the raw source, vendor, and fixture bytes used by the provenance checks. Shell scripts use LF line endings across platforms. Runtime state and dependency installations are ignored.
