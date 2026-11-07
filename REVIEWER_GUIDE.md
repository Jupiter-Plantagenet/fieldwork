# Fieldwork reviewer guide

Use the following checks to inspect the engineering claims. Commands run from the repository root with the documented dependencies installed.

| Claim | Implementation | Test | Command | Expected observation |
|---|---|---|---|---|
| Missing predictions remain in the metric denominator | [fieldwork/metrics.py](fieldwork/metrics.py) | [tests/test_metrics.py](tests/test_metrics.py) | `python verify.py` | Accuracy and coverage are 0.5 in the two-member fixture |
| The independent verifier agrees on metrics and unsupported classes | [tools/verify_metrics.py](tools/verify_metrics.py) | [tests/test_full_metrics.py](tests/test_full_metrics.py) | `python verify.py` | Metric values, null reasons, and intervals agree |
| A restarted attempt replays from a committed checkpoint | [fieldwork/ml.py](fieldwork/ml.py) | [tests/test_replay.py](tests/test_replay.py) | `python -m pytest tests/test_replay.py -v` | Final model and logits stay within the declared 1e-6 tolerance |

## Evidence boundaries

The historical flower holdout contains 573 images and reports accuracy 0.8098 and macro-F1 0.8072. A recorded host-crash recovery comparison reports zero difference in parameters and validation logits against its uninterrupted control. The rights steward and annotators were simulated, and several acceptance items used explicitly recorded waivers.

[Current publication verification](docs/verification.md) records the checks executed for this copy. [Reproduction instructions](docs/reproduction.md) distinguish the small review path from the full application and research runs.
