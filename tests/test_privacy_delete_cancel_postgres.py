"""PostgreSQL-only deletion cancellation probe for a disposable migrated test DB.

Set FIELDWORK_PRIVACY_ADMIN_DSN and FIELDWORK_PRIVACY_API_DSN only in the test
runner. The test refuses any DB whose name does not begin with fieldwork_test_.
"""
import os
import uuid

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


def test_api_role_can_cancel_only_after_tombstone_under_restrictive_rls():
    admin_dsn=os.environ.get('FIELDWORK_PRIVACY_ADMIN_DSN')
    api_dsn=os.environ.get('FIELDWORK_PRIVACY_API_DSN')
    if not admin_dsn or not api_dsn:
        pytest.skip('Dedicated privacy PostgreSQL role DSNs are not configured')
    admin_params=conninfo_to_dict(admin_dsn);api_params=conninfo_to_dict(api_dsn)
    if admin_params.get('dbname')!=api_params.get('dbname') or not admin_params.get('dbname','').startswith('fieldwork_test_'):
        pytest.fail('Privacy cancellation RLS test requires the same fieldwork_test_ database')
    workspace='privacy-cancel-'+uuid.uuid4().hex
    tag=uuid.uuid4().hex
    other_workspace='privacy-other-'+tag
    scope_principal='privacy-cancel-'+tag
    run_ids={name:'privacy-cancel-'+tag+'-'+name for name in ('queued','leased','running','cancel_requested','terminal')}
    request_id=uuid.uuid4()
    with psycopg.connect(admin_dsn,row_factory=dict_row) as admin:
        applied=admin.execute("SELECT to_regprocedure('public.fw_privacy_cancel_deleted_run_v1(text,text)') IS NOT NULL AS ready").fetchone()['ready']
        if not applied:pytest.skip('Forward migration 017 is not applied to the dedicated test database')
        admin.execute('''INSERT INTO public.fw_workspace_settings(workspace,max_concurrent_runs,max_epochs)
            VALUES(%s,16,100)''',(workspace,))
        admin.execute('''INSERT INTO fw_worker_cap_v1.scope(principal,workspaces,version,definer)
            VALUES(%s,%s,1,%s)''',(scope_principal,[workspace,other_workspace],scope_principal+'_definer'))
        for name,run_id in run_ids.items():
            state={'queued':'queued','leased':'leased','running':'running',
                   'cancel_requested':'cancel_requested','terminal':'succeeded'}[name]
            fence=0 if state=='queued' else 2
            revision=1 if state=='queued' else 3
            cancel_generation=0 if state=='queued' else 1
            admin.execute('''INSERT INTO public.fw_runs(id,workspace,actor,idem,digest,config,state,
                fence,revision,cancel_generation,lease)
                VALUES(%s,%s,'synthetic-owner',%s,%s,%s,%s,%s,%s,%s,
                    CASE WHEN %s IN ('leased','running','cancel_requested') THEN clock_timestamp()+interval '1 hour' END)''',
                (run_id,workspace,name,'0'*64,
                 Jsonb({'scope':'real-training/v1','epochs':1}),state,fence,revision,cancel_generation,state))
        now=admin.execute('SELECT clock_timestamp() AS at').fetchone()['at']
        admin.execute('''INSERT INTO public.fw_privacy_workspace_tombstones(workspace,request_id,requested_by,
            expected_settings_revision,deleted_utc,archive_due_utc) VALUES(%s,%s,'synthetic-owner',1,%s,%s+interval '7 days')''',
            (workspace,request_id,now,now))
    try:
        with psycopg.connect(api_dsn,row_factory=dict_row) as api:
            flags=api.execute('''SELECT r.rolsuper,r.rolbypassrls FROM pg_roles r
                WHERE r.rolname=session_user''').fetchone()
            assert flags and not flags['rolsuper'] and not flags['rolbypassrls']
            api.execute("SELECT set_config('fieldwork.workspace',%s,true)",(workspace,))
            assert api.execute('SELECT count(*) AS n FROM public.fw_runs WHERE workspace=%s',(workspace,)).fetchone()['n']==0
            assert api.execute('SELECT count(*) AS n FROM public.fw_events WHERE workspace=%s',(workspace,)).fetchone()['n']==0
            for name,expected in [('queued','cancelled'),('leased','cancel_requested'),('running','cancel_requested')]:
                result=api.execute('SELECT public.fw_privacy_cancel_deleted_run_v1(%s,%s) AS state',
                    (workspace,run_ids[name])).fetchone()['state']
                assert result==expected
            assert api.execute('SELECT public.fw_privacy_cancel_deleted_run_v1(%s,%s) AS state',
                (workspace,run_ids['cancel_requested'])).fetchone()['state']=='cancel_requested'
            assert api.execute('SELECT public.fw_privacy_cancel_deleted_run_v1(%s,%s) AS state',
                (workspace,run_ids['terminal'])).fetchone()['state']=='succeeded'
            # RLS exposes no row for a generic API UPDATE after deletion.
            changed=api.execute("UPDATE public.fw_runs SET state='cancelled' WHERE workspace=%s AND id=%s",
                (workspace,run_ids['queued']))
            assert changed.rowcount==0
        with psycopg.connect(admin_dsn,row_factory=dict_row) as admin:
            rows=admin.execute('''SELECT id,state,fence,revision,cancel_generation FROM public.fw_runs
                WHERE workspace=%s''',(workspace,)).fetchall()
            by_id={row['id']:row for row in rows}
            assert (by_id[run_ids['queued']]['state'],by_id[run_ids['queued']]['fence'],
                    by_id[run_ids['queued']]['revision'],by_id[run_ids['queued']]['cancel_generation'])==('cancelled',1,2,1)
            assert by_id[run_ids['leased']]['state']=='cancel_requested'
            assert by_id[run_ids['running']]['state']=='cancel_requested'
            assert by_id[run_ids['terminal']]['state']=='succeeded'
            assert admin.execute("SELECT count(*) AS n FROM public.fw_events WHERE workspace=%s AND payload->>'reason'='workspace_tombstoned'",
                (workspace,)).fetchone()['n']==3
            scope=admin.execute('''SELECT workspaces,version FROM fw_worker_cap_v1.scope
                WHERE principal=%s''',(scope_principal,)).fetchone()
            assert scope and scope['workspaces']==[other_workspace] and scope['version']==2
    finally:
        with psycopg.connect(admin_dsn) as admin:
            admin.execute('DELETE FROM public.fw_events WHERE workspace=%s',(workspace,))
            admin.execute('DELETE FROM public.fw_runs WHERE workspace=%s',(workspace,))
            admin.execute('DELETE FROM public.fw_privacy_workspace_tombstones WHERE workspace=%s',(workspace,))
            admin.execute('DELETE FROM public.fw_workspace_settings_events WHERE workspace=%s',(workspace,))
            admin.execute('DELETE FROM public.fw_workspace_settings WHERE workspace=%s',(workspace,))
            admin.execute('DELETE FROM fw_worker_cap_v1.scope WHERE principal=%s',(scope_principal,))
