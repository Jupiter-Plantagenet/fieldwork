"""Shared helpers for the 2026-11-03 concurrency/operations acceptance matrix tests.

Everything here drives the REAL isolated PostgreSQL (the `isolated_store` fixture); nothing is
mocked. Lock orderings are scheduled by PostgreSQL lock barriers (a blocker transaction holds the
lock, each actor is proven to be waiting on it through pg_stat_activity before the next actor is
started, then the blocker commits and the actors are granted the lock in queue order), never by
sleep-based timing.
"""
import concurrent.futures
import time
import uuid

from psycopg.conninfo import make_conninfo

from fieldwork.store import Store


def labelled_store(s, label):
    return Store(dsn=make_conninfo(s.dsn, application_name=label))


def wait_for_database_lock(admin, label, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with admin.connect() as c:
            row = c.execute("SELECT 1 FROM pg_stat_activity WHERE application_name=%s AND wait_event_type='Lock'", (label,)).fetchone()
        if row:
            return
        time.sleep(.005)
    raise AssertionError('actor never reached the PostgreSQL lock barrier: ' + label)


def capture(fn, store):
    """Run fn(store); return ('ok', value) or ('err', exception) so a refusal is data, not a crash."""
    try:
        return ('ok', fn(store))
    except BaseException as exc:  # noqa: BLE001 - refusals are the observation
        return ('err', exc)


def code_of(outcome):
    """Normalise an outcome to 'ok', (status, code) for annotations.Rejection, or the exception's text/code."""
    kind, value = outcome
    if kind == 'ok':
        return 'ok'
    status = getattr(value, 'status', None)
    if status is not None:
        return (status, str(value))
    return getattr(value, 'code', None) or str(value)


def run_ordered(s, blocker_sql, blocker_params, first, second, timeout=20):
    """Run first(store) then second(store) in two threads, both queued behind `blocker_sql`'s lock.

    Returns (outcome_first, outcome_second). The lock is held by a third connection until BOTH actors are
    observed waiting on a PostgreSQL lock, so the order in which they acquire it is the order given.
    """
    l1, l2 = 'fw-matrix-' + uuid.uuid4().hex, 'fw-matrix-' + uuid.uuid4().hex
    a1, a2 = labelled_store(s, l1), labelled_store(s, l2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        with s.connect() as blocker:
            blocker.execute(blocker_sql, blocker_params)
            f1 = pool.submit(capture, first, a1)
            wait_for_database_lock(s, l1)
            f2 = pool.submit(capture, second, a2)
            wait_for_database_lock(s, l2)
            blocker.commit()
        return f1.result(timeout=timeout), f2.result(timeout=timeout)
