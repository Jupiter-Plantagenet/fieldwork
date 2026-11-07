"""Real socket/nonowner regression; historical accepted bytes are fixture-only.

Run ONLY through evidence/checkpoint-read-20261029-c8e40f12/run_packet.py.
It provides a disposable DB, private approved-scratch mirror and API socket.
"""
import json,os,shutil,uuid
from pathlib import Path
import httpx,pytest,psycopg
from psycopg.types.json import Jsonb
from fieldwork.store import ROOT,Store,TENANT
from fieldwork.api import create_account

@pytest.fixture
def accepted():
    assert os.environ.get('FW_CHECKPOINT_PACKET')=='c8e40f12'
    s=Store();metadata=json.loads((ROOT/'fixture-metadata.json').read_text())
    old=metadata['run'];workspace='cp-read-'+uuid.uuid4().hex
    name=workspace;password=uuid.uuid4().hex
    create_account(name,password,workspace,'viewer')
    r=s.submit(workspace,name,'accepted-fixture',old['config']);a=s.claim(r['id'])
    folder=ROOT/'var/runs'/r['id'];shutil.copytree(ROOT/'fixture',folder)
    with s.connect() as c:
        for cp in metadata['checkpoints']:
            c.execute('INSERT INTO fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES(%s,%s,%s,%s,%s,%s)',(r['id'],cp['epoch'],a['attempt'],cp['digest'],'historical-byte-fixture-only',Jsonb(cp['metrics'])))
        c.execute("UPDATE fw_runs SET state='succeeded',epoch=%s,result=%s,artifact_status='verified',artifact_result=%s WHERE id=%s",(old['epoch'],Jsonb(old['result']),Jsonb(old['artifact_result']),r['id']))
    s.release_slot(r['id'])
    with httpx.Client(base_url=os.environ['FW_CHECKPOINT_URL'],timeout=20) as client:
        reply=client.post('/auth/session',json={'name':name,'password':password});assert reply.status_code==200
        yield s,r,workspace,client,folder


def test_hardened_nonowner_http_evaluation(accepted):
    s,r,w,client,folder=accepted
    with Store(request=True).connect() as c:
        flags=c.execute('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
        assert not flags['rolsuper'] and not flags['rolbypassrls']
        assert c.execute("SELECT has_table_privilege(current_user,'fw_checkpoints','UPDATE') allowed").fetchone()['allowed'] is False
    base='/api/v1/workspaces/'+w+'/runs/'+r['id']
    response=client.get(base+'/evaluation')
    assert response.status_code==200,response.text
    assert response.json()['metrics']['n']==10
    for route in ['records','slices','artifacts']:
        response=client.get(base+'/'+route);assert response.status_code==200,(route,response.text)
    assert response.json()['download_allowed'] is False
    assert client.get('/api/v1/workspaces/'+w+'/bundles/fixture/download').status_code==403
    assert client.get('/api/v1/workspaces/other/runs/'+r['id']+'/evaluation').status_code==404
    with s.connect() as c:c.execute('DELETE FROM fw_sessions WHERE name=%s',(w,))
    assert client.get(base+'/evaluation').status_code==401


def api_connection(workspace):
    token=TENANT.set(workspace)
    try:return Store(request=True).connect()
    finally:TENANT.reset(token)


def test_capability_role_tenant_search_path_and_write_denials(accepted):
    from fieldwork.checkpoint_read import SIGNATURE,verify,install
    from psycopg import sql
    s,r,w,client,folder=accepted;best=json.loads((ROOT/'fixture-metadata.json').read_text())['run']['result']['best']['epoch']
    with api_connection(w) as c:
        role=c.execute('SELECT current_user AS role').fetchone()['role'];owner=role+'_cp_lock'
        expected=c.execute('SELECT digest FROM public.fw_checkpoints WHERE run=%s AND epoch=%s',(r['id'],best)).fetchone()['digest']
        c.execute('CREATE TEMP TABLE fw_runs(id text,workspace text)')
        c.execute('CREATE TEMP TABLE fw_checkpoints(run text,epoch integer,digest text)')
        c.execute("SET LOCAL search_path=pg_temp,public")
        got=c.execute('SELECT * FROM fw_checkpoint_read_v1.locked_digest(%s,%s,%s)',(r['id'],best,w)).fetchone()
        assert got=={'digest':expected}
        assert c.execute('SELECT * FROM fw_checkpoint_read_v1.locked_digest(%s,%s,%s)',(r['id'],99,w)).fetchone() is None
        assert c.execute('SELECT * FROM fw_checkpoint_read_v1.locked_digest(%s,%s,%s)',(r['id'],1 if best==2 else 2,w)).fetchone() is None
        negatives=[
            ('checkpoint-insert',"INSERT INTO public.fw_checkpoints(run,epoch,digest,path,metrics) VALUES(%s,99,'x','x','{}')",(r['id'],)),
            ('checkpoint-update',"UPDATE public.fw_checkpoints SET digest='forged' WHERE run=%s",(r['id'],)),
            ('checkpoint-delete','DELETE FROM public.fw_checkpoints WHERE run=%s',(r['id'],)),
            ('attempt-insert',"INSERT INTO public.fw_attempts(id,run,fence) VALUES('forged',%s,99)",(r['id'],)),
            ('attempt-update','UPDATE public.fw_attempts SET fence=99 WHERE run=%s',(r['id'],)),
            ('attempt-delete','DELETE FROM public.fw_attempts WHERE run=%s',(r['id'],)),
            ('auth-update',"UPDATE public.fw_accounts SET role='owner' WHERE name=%s",(w,)),
            ('owner-assume',sql.SQL('SET ROLE {}').format(sql.Identifier(owner)),()),
            ('capability-create',sql.SQL('CREATE TABLE fw_checkpoint_read_v1.forged(x integer)'),()),
        ]
        for label,statement,params in negatives:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():c.execute(statement,params)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with c.transaction():c.execute('SELECT * FROM fw_checkpoint_read_v1.locked_digest(%s,%s,%s)',(r['id'],best,'other'))
    with api_connection('other') as c:
        assert c.execute('SELECT * FROM public.fw_checkpoints WHERE run=%s',(r['id'],)).fetchone() is None
        assert c.execute('SELECT * FROM fw_checkpoint_read_v1.locked_digest(%s,%s,%s)',(r['id'],best,'other')).fetchone() is None
    with pytest.raises(psycopg.errors.InsufficientPrivilege):Store(Store(request=True).dsn).claim(r['id'])
    with s.connect() as c:
        verify(c,role);install(c,role)
        strangers='cp_stranger_'+uuid.uuid4().hex[:12]
        c.execute(sql.SQL('CREATE ROLE {} NOLOGIN').format(sql.Identifier(strangers)))
        try:
            assert c.execute("SELECT has_function_privilege(%s,%s,'EXECUTE') allowed",(strangers,SIGNATURE)).fetchone()['allowed'] is False
            c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(strangers)))
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():c.execute('SELECT * FROM fw_checkpoint_read_v1.locked_digest(%s,%s,%s)',(r['id'],best,w))
            c.execute('RESET ROLE')
        finally:c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(strangers)))
        for statement in [
            sql.SQL('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO PUBLIC'),
            sql.SQL('ALTER FUNCTION '+SIGNATURE+' SET search_path=public'),
            sql.SQL('ALTER ROLE {} LOGIN').format(sql.Identifier(owner)),
            sql.SQL('GRANT UPDATE(digest) ON public.fw_checkpoints TO {}').format(sql.Identifier(role)),
        ]:
            with pytest.raises(ValueError):
                with c.transaction():
                    c.execute(statement);verify(c,role)
        verify(c,role)


def observed_wait(s,pid,blocker):
    import time
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        with s.connect() as c:
            row=c.execute('SELECT pid,wait_event_type,wait_event,pg_blocking_pids(pid) blockers,query FROM pg_stat_activity WHERE pid=%s',(pid,)).fetchone()
        if row and blocker in row['blockers'] and row['wait_event_type']=='Lock':return row
        time.sleep(.02)
    raise AssertionError(('physical lock edge not observed',pid,blocker,row))


def test_physical_child_and_parent_locks_and_rollback(accepted):
    from concurrent.futures import ThreadPoolExecutor
    import time
    s,r,w,client,folder=accepted;meta=json.loads((ROOT/'fixture-metadata.json').read_text());best=meta['run']['result']['best']['epoch']
    graphs=[];base='/api/v1/workspaces/'+w+'/runs/'+r['id']
    writer=s.connect();contender=s.connect()
    try:
        # Restore's actual first write: child path, before any parent update.
        wp=writer.execute('SELECT pg_backend_pid() p').fetchone()['p']
        writer.execute("UPDATE fw_checkpoints SET path='pending-restore-path' WHERE run=%s AND epoch=%s",(r['id'],best))
        pp=contender.execute('SELECT pg_backend_pid() p').fetchone()['p']
        with ThreadPoolExecutor(2) as pool:
            request=pool.submit(client.get,base+'/evaluation')
            deadline=time.monotonic()+3;reader=None
            while time.monotonic()<deadline:
                with s.connect() as c:
                    rows=c.execute("SELECT pid,pg_blocking_pids(pid) blockers FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'SELECT digest FROM fw_checkpoint_read_v1.locked_digest%%'").fetchall()
                reader=next((x['pid'] for x in rows if wp in x['blockers']),None)
                if reader:break
                time.sleep(.02)
            assert reader,'HTTP checkpoint lock not observed'
            graphs.append(observed_wait(s,reader,wp))
            update=pool.submit(contender.execute,'UPDATE fw_runs SET revision=revision+1 WHERE id=%s',(r['id'],))
            graphs.append(observed_wait(s,pp,reader))
            writer.rollback()
            assert request.result(5).status_code==200
            update.result(5);contender.rollback()
        # A real nonowner reader holds child SHARE until rollback; digest and
        # deletion writers cannot pass it, even without taking the parent lock.
        for mutation in ["UPDATE fw_checkpoints SET digest='forged' WHERE run=%s AND epoch=%s",'DELETE FROM fw_checkpoints WHERE run=%s AND epoch=%s']:
            with api_connection(w) as reader_c:
                rp=reader_c.execute('SELECT pg_backend_pid() p').fetchone()['p']
                assert reader_c.execute('SELECT * FROM fw_checkpoint_read_v1.locked_digest(%s,%s,%s)',(r['id'],best,w)).fetchone()
                with ThreadPoolExecutor(1) as pool:
                    pending=pool.submit(writer.execute,mutation,(r['id'],best))
                    graphs.append(observed_wait(s,wp,rp));reader_c.rollback();pending.result(5);writer.rollback()
        assert client.get(base+'/evaluation').status_code==200
        with s.connect() as c:
            cp=c.execute('SELECT digest,path FROM fw_checkpoints WHERE run=%s AND epoch=%s',(r['id'],best)).fetchone()
            assert cp['digest']==next(x['digest'] for x in meta['checkpoints'] if x['epoch']==best)
            assert cp['path']=='historical-byte-fixture-only'
        __import__('fieldwork.evidence_out',fromlist=['x']).write_evidence(ROOT,'checkpoint-lock-graphs.json',graphs)
    finally:writer.rollback();writer.close();contender.rollback();contender.close()


def test_read_once_and_digest_anchor_remain_fail_closed(accepted):
    from fieldwork.evidence_snapshot import accepted_evidence
    s,r,w,client,folder=accepted
    token=TENANT.set(w)
    try:
        _,_,files,_=accepted_evidence(Store(request=True),ROOT/'var/runs',r['id'],w)
    finally:TENANT.reset(token)
    target=folder/'artifact-attempt-1/bundle/evaluation/predictions.jsonl'
    original=target.read_bytes()
    assert files['evaluation/predictions.jsonl']==original
    # Only this owned test copy is corrupted, never the historical fixture.
    target.chmod(0o600);target.write_bytes(b'{"tampered":true}\n')
    assert files['evaluation/predictions.jsonl']==original
    base='/api/v1/workspaces/'+w+'/runs/'+r['id']
    for route in ['evaluation','records','slices','artifacts']:
        assert client.get(base+'/'+route).status_code==409
    target.write_bytes(original)
    assert client.get(base+'/evaluation').status_code==200
    with s.connect() as c:c.execute("UPDATE fw_checkpoints SET digest=%s WHERE run=%s",('0'*64,r['id']))
    assert client.get(base+'/evaluation').status_code==409


@pytest.mark.parametrize('revocation',['role','membership','expiry'])
def test_current_authorization_is_not_bypassed_by_capability(accepted,revocation):
    s,r,w,client,folder=accepted
    with s.connect() as c:
        if revocation=='role':c.execute("UPDATE fw_accounts SET role='researcher' WHERE name=%s",(w,))
        elif revocation=='membership':c.execute("UPDATE fw_accounts SET workspace='other' WHERE name=%s",(w,))
        else:c.execute("UPDATE fw_sessions SET expires=clock_timestamp()-interval '1 second' WHERE name=%s",(w,))
    assert client.get('/api/v1/workspaces/'+w+'/runs/'+r['id']+'/evaluation').status_code==401
