"""DB lock barriers, not timing sleeps, schedule each cancellation ordering."""
import concurrent.futures,json,time,uuid
import pytest
from psycopg.conninfo import make_conninfo
from fieldwork.store import Store,ROOT,Conflict

SOURCE=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'


def wait_for_database_lock(admin,label):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        with admin.connect() as c:
            row=c.execute("SELECT 1 FROM pg_stat_activity WHERE application_name=%s AND wait_event_type='Lock'",(label,)).fetchone()
        if row:return
        time.sleep(.005)
    raise AssertionError('Actor never reached PostgreSQL lock barrier: '+label)


@pytest.mark.parametrize('operation,first',[('complete','cancel'),('complete','operation'),('checkpoint','cancel'),('checkpoint','operation')])
def test_cancel_publication_linearization_at_real_database_barrier(isolated_store,operation,first):
    s=isolated_store;meta=json.loads((SOURCE/'state.json').read_text());metrics={k:meta[k] for k in ['epoch','train_loss','validation_loss','updates']}
    r=s.submit('barrier','author',str(uuid.uuid4()),{'epochs':1,'dataset_digest':meta['dataset_digest']});a=s.claim(r['id'])
    if operation=='complete':s.publish(r['id'],a['fence'],a['cancel_generation'],SOURCE,metrics,attempt=a['attempt'])
    label1='fieldwork-barrier-'+uuid.uuid4().hex;label2='fieldwork-barrier-'+uuid.uuid4().hex
    actors={key:Store(dsn=make_conninfo(s.dsn,application_name=label)) for key,label in [('cancel',label1 if first=='cancel' else label2),('operation',label1 if first=='operation' else label2)]}
    def perform(key):
        try:
            if key=='cancel':return actors[key].cancel('barrier',r['id'])
            if operation=='checkpoint':actors[key].publish(r['id'],a['fence'],a['cancel_generation'],SOURCE,metrics,attempt=a['attempt'])
            else:actors[key].complete(r['id'],a['fence'],a['cancel_generation'],json.loads((SOURCE.parent/'result.json').read_text()),attempt=a['attempt'])
            return 'committed'
        except Conflict:return 'fenced'
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            with s.connect() as blocker:
                blocker.execute('SELECT id FROM fw_runs WHERE id=%s FOR UPDATE',(r['id'],))
                first_future=pool.submit(perform,first);wait_for_database_lock(s,label1)
                second='operation' if first=='cancel' else 'cancel'
                second_future=pool.submit(perform,second);wait_for_database_lock(s,label2)
                blocker.commit()
            results={first:first_future.result(timeout=10),second:second_future.result(timeout=10)}
        if first=='cancel':
            assert results=={'cancel':'cancel_requested','operation':'fenced'}
        elif operation=='complete':
            assert results=={'operation':'committed','cancel':'succeeded'}
        else:
            assert results=={'operation':'committed','cancel':'cancel_requested'}
            assert s.get(r['id'])['epoch']==1
        # Cancel increments the generation exactly once unless completion won first.
        assert s.get(r['id'])['cancel_generation']==(0 if first=='operation' and operation=='complete' else a['cancel_generation']+1)
        with s.connect() as c:assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run']==r['id']
    finally:s.release_slot(r['id'])
