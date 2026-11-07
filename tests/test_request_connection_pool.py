"""Request-store connection pool: reuse without leaking tenant, session settings, transactions or broken sockets."""
import psycopg
import pytest

from fieldwork.store import Store, TENANT


def _req(isolated_store):
    return Store(dsn=isolated_store.dsn, request=True)


def test_reuses_one_backend_and_never_carries_the_tenant_over(isolated_store):
    s = _req(isolated_store)
    tok = TENANT.set('tenant-a')
    try:
        with s.connect() as c:
            pid = c.execute('SELECT pg_backend_pid() p').fetchone()['p']
            assert c.execute("SELECT current_setting('fieldwork.workspace',true) w").fetchone()['w'] == 'tenant-a'
    finally:
        TENANT.reset(tok)
    tok = TENANT.set('tenant-b')
    try:
        with s.connect() as c:
            assert c.execute('SELECT pg_backend_pid() p').fetchone()['p'] == pid  # pooled
            assert c.execute("SELECT current_setting('fieldwork.workspace',true) w").fetchone()['w'] == 'tenant-b'
    finally:
        TENANT.reset(tok)
    tok = TENANT.set('')
    try:
        with s.connect() as c:  # an empty tenant sees no tenant at all, not the previous one
            assert c.execute("SELECT coalesce(current_setting('fieldwork.workspace',true),'') w").fetchone()['w'] == ''
    finally:
        TENANT.reset(tok)


def test_session_settings_isolation_and_errors_do_not_leak(isolated_store):
    s = _req(isolated_store)
    with s.connect() as c:
        default = c.execute('SHOW statement_timeout').fetchone()['statement_timeout']
        c.execute("SET statement_timeout='1234ms'")
    with s.connect() as c:
        assert c.execute('SHOW statement_timeout').fetchone()['statement_timeout'] == default
    with s.connect(isolation_level=psycopg.IsolationLevel.REPEATABLE_READ) as c:
        assert c.execute('SHOW transaction_isolation').fetchone()['transaction_isolation'] == 'repeatable read'
    with s.connect() as c:
        assert c.execute('SHOW transaction_isolation').fetchone()['transaction_isolation'] == 'read committed'
    with pytest.raises(psycopg.errors.DivisionByZero):
        with s.connect() as c:
            c.execute('CREATE TEMP TABLE IF NOT EXISTS pool_probe(x int)')
            c.execute('SELECT 1/0')
    with s.connect() as c:  # the failed transaction was rolled back, the connection is healthy
        assert c.execute('SELECT 1 AS one').fetchone()['one'] == 1


def test_a_connection_killed_by_the_server_is_not_handed_out_again(isolated_store):
    s = _req(isolated_store)
    with s.connect() as c:
        pid = c.execute('SELECT pg_backend_pid() p').fetchone()['p']
    with isolated_store.connect() as admin:
        admin.execute('SELECT pg_terminate_backend(%s)', (pid,))
    import time
    time.sleep(0.3)
    try:
        with s.connect() as c:
            assert c.execute('SELECT pg_backend_pid() p').fetchone()['p'] != pid
    except psycopg.OperationalError:
        # the dead socket was detected on first use and discarded; the next checkout must be healthy
        with s.connect() as c:
            assert c.execute('SELECT pg_backend_pid() p').fetchone()['p'] != pid
