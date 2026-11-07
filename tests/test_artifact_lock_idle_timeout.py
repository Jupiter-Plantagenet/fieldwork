"""D1 regression: the artifact-retention lock holder must survive a slow bundle verification on other connections."""
import time

import psycopg


def test_lock_lifts_idle_timeout_for_its_own_transaction_only(isolated_store):
    from fieldwork.real_workspace_api import _lock_artifact
    with isolated_store.connect() as c:
        c.execute("SET idle_in_transaction_session_timeout = '1s'")  # stand-in for the API role's 10 s default
        c.commit()
        _lock_artifact(c, 'ws-d1', 'run-d1')
        assert c.execute('SHOW idle_in_transaction_session_timeout').fetchone()['idle_in_transaction_session_timeout'] == '3min'
        time.sleep(2.5)  # idle while "verification" runs elsewhere: would be terminated at 1 s without the fix
        assert c.execute('SELECT 1 AS ok').fetchone()['ok'] == 1
        c.commit()
        assert c.execute('SHOW idle_in_transaction_session_timeout').fetchone()['idle_in_transaction_session_timeout'] == '1s'


def test_without_the_local_raise_the_idle_holder_is_terminated(isolated_store):
    with isolated_store.connect() as c:
        c.execute("SET idle_in_transaction_session_timeout = '1s'")
        c.commit()
        c.execute("SELECT pg_advisory_xact_lock(hashtextextended('control',0))")
        time.sleep(2.5)
        try:
            c.execute('SELECT 1')
            terminated = False
        except psycopg.Error:
            terminated = True
    assert terminated


def test_readers_share_the_artifact_lock_but_still_exclude_the_archiver(isolated_store):
    from fieldwork.real_workspace_api import _lock_artifact
    key = 'fieldwork-artifact-retention:ws-d1:run-d2'
    with isolated_store.connect() as a, isolated_store.connect() as b, isolated_store.connect() as archiver:
        _lock_artifact(a, 'ws-d1', 'run-d2')
        _lock_artifact(b, 'ws-d1', 'run-d2')  # a second reader is not blocked
        got = archiver.execute('SELECT pg_try_advisory_xact_lock(hashtextextended(%s,0)) AS ok', (key,)).fetchone()['ok']
        assert got is False  # the archiver's exclusive lock waits for every reader
        a.commit(); b.commit()
        assert archiver.execute('SELECT pg_try_advisory_xact_lock(hashtextextended(%s,0)) AS ok', (key,)).fetchone()['ok'] is True
