"""Explicit, recorded operator decisions that relax host space gates.

Nothing here is on by default. A launcher must set the environment variable, and every
consumer records that it did (worker preflight detail, write-budget receipts).
"""
import os

SPACE_ENV = 'FIELDWORK_OPERATOR_SPACE_OVERRIDE'
SPACE_VALUE = 'accept-large-run-writes'
# The per-run model write budget is 2 GiB by default; the override lifts it to this.
OVERRIDE_RUN_WRITE_BUDGET_BYTES = 64 * 1024 ** 3
# Free-disk requirements are lowered to this floor (never to zero) so C: cannot be filled outright.
SPACE_FLOOR_BYTES = 5 * 1024 ** 3


def space_override() -> bool:
    return os.environ.get(SPACE_ENV) == SPACE_VALUE


def required_free_bytes(default: int) -> int:
    return min(default, SPACE_FLOOR_BYTES) if space_override() else default
