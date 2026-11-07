"""Migration 023: the privacy tombstone fence is evaluated once per statement but hides and blocks exactly as 017 did.

Runs on the retained migration chain (003..023) as the real nonowner request principal `fieldwork_api` under forced RLS.
"""
import uuid

import psycopg
import pytest

from tests.chain_support import chain  # noqa: F401


def _as_api(chain, workspace):
    from fieldwork.store import TENANT
    token = TENANT.set(workspace)
    try:
        return chain.request.connect()
    finally:
        TENANT.reset(token)


def _settings_rows(chain, workspace):
    with _as_api(chain, workspace) as c:
        return [r['workspace'] for r in c.execute('SELECT workspace FROM fw_workspace_settings').fetchall()]


def test_tombstone_policy_hides_and_blocks_exactly_like_017_and_reads_the_fence_once(chain):
    tag = uuid.uuid4().hex[:8]
    live, tomb = 'p023-live-' + tag, 'p023-tomb-' + tag
    with chain.dba.connect() as db:
        for w in (live, tomb):
            db.execute('INSERT INTO fw_workspace_settings(workspace,revision,retention_days,max_concurrent_runs,max_epochs) '
                       'VALUES(%s,1,180,2,100)', (w,))
        quals = db.execute("""SELECT qual, with_check FROM pg_policies WHERE schemaname='public'
            AND policyname LIKE 'fw_privacy_tombstone_fw_%'""").fetchall()
    assert len(quals) >= 14 and all('CASE' in q['qual'] and 'CASE' in q['with_check'] for q in quals)
    assert _settings_rows(chain, live) == [live]
    assert _settings_rows(chain, tomb) == [tomb]
    assert tomb not in _settings_rows(chain, live)  # tenant policy unchanged

    with chain.dba.connect() as db:
        db.execute('''INSERT INTO fw_privacy_workspace_tombstones(workspace,request_id,requested_by,expected_settings_revision,
            deleted_utc,archive_due_utc) VALUES(%s,%s,'p023-test',1,now(),now()+interval '7 days')''', (tomb, str(uuid.uuid4())))

    assert _settings_rows(chain, tomb) == []  # tombstoned workspace: nothing visible
    assert _settings_rows(chain, live) == [live]  # other workspaces unaffected
    with pytest.raises(psycopg.Error):  # writes into the tombstoned workspace are refused by WITH CHECK
        with _as_api(chain, tomb) as c:
            c.execute('INSERT INTO fw_workspace_settings_events(workspace,actor,event_type,detail) '
                      "VALUES(%s,'p023','settings.updated','{}'::jsonb)", (tomb,))
    with _as_api(chain, tomb) as c:  # updates match no row
        assert c.execute('UPDATE fw_workspace_settings SET max_epochs=99 WHERE workspace=%s', (tomb,)).rowcount == 0


def test_plan_reads_the_fence_as_an_init_plan_not_per_row(chain):
    """The tombstone function appears once as an InitPlan for in-tenant scans, not as a per-row filter call."""
    tag = uuid.uuid4().hex[:8]
    w = 'p023-plan-' + tag
    with chain.dba.connect() as db:
        db.execute('INSERT INTO fw_workspace_settings(workspace,revision,retention_days,max_concurrent_runs,max_epochs) '
                   'VALUES(%s,1,180,2,100)', (w,))
    with _as_api(chain, w) as c:
        plan = '\n'.join(r['QUERY PLAN'] for r in c.execute('EXPLAIN SELECT * FROM fw_workspace_settings').fetchall())
    assert 'InitPlan' in plan, plan
