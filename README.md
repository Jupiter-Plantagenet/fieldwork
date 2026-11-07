# Fieldwork

Reproducible visual ML experiments, error analysis, and checkpoint recovery.

ML experiments need identifiable input populations, inspectable prediction errors, and enough saved state to recover from an interruption without silently changing the experiment.

Built from scratch as a local research software engineering project. The implementation includes application code, tests, and documented experiments.

## Engineering scope

ML evaluation, reproducibility, exact population accounting, durable training state, and portable inference artifacts.

Dataset versions bind content digests and splits. Metric calculation preserves missing predictions in the denominator and is compared with a separate verifier. Training attempts use leases and fences. Checkpoints retain model, optimizer, RNG, and sampler state, and verified artifacts bind preprocessing and class metadata.

## Review the work

- [Reproduce the focused checks](docs/reproduction.md)
- [Trace claims to implementation and tests](REVIEWER_GUIDE.md)
- [Inspect current verification and remaining setup work](docs/verification.md)
- [Watch the one-minute application walkthrough](docs/demos/fieldwork-walkthrough.mp4)
- [Read the recorded project results](docs/acceptance-status-final-v2-20261103.md)

## Repository layout

`fieldwork/` contains the Python implementation. `apps/web/` contains the React workbench. `tests/` contains metric, security, worker, and replay checks. `migrations/` contains the database migrations. `ops/` contains decoder and model containers. `tools/` contains repository-local verification and operator helpers.

## Recorded result

The historical flower holdout contains 573 images and reports accuracy 0.8098 and macro-F1 0.8072. A recorded host-crash recovery comparison reports zero difference in parameters and validation logits against its uninterrupted control. The rights steward and annotators were simulated, and several acceptance items used explicitly recorded waivers.

The recorded experiment reports describe the original development runs. The publication candidate has its own verification record, linked above, with the commands executed against this copy.

## Start here

Follow [the reproduction guide](docs/reproduction.md) to install the pinned dependencies, run the focused tests, and build the web application. The guide identifies the extra infrastructure and private inputs needed for larger experiments.

Third-party source retains its original copyright and license notices. A repository-wide distribution license is pending the author's publication review.
