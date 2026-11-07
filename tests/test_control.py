import uuid
import pytest


def test_postgres_idempotency_live_fence_cancel_and_expiry(isolated_store,tmp_path):
    from fieldwork.store import Store, Conflict
    s=isolated_store;s.migrate()  # throwaway DB: the live DB has migration-011+ guards and a live slot owner
    workspace=str(uuid.uuid4()); cfg={'epochs':10,'dataset':'synthetic'}
    r=s.submit(workspace,'actor','key',cfg)
    assert r['id']==s.submit(workspace,'actor','key',cfg)['id']
    with pytest.raises(Conflict): s.submit(workspace,'actor','key',{'epochs':2})
    assert r['state']=='queued' and r['epoch']==0
    a=s.claim(r['id']); assert a['fence']>r['fence']
    s.heartbeat(r['id'],a['fence'],a['cancel_generation'],attempt=a['attempt'])
    s.expire_for_test(r['id'])
    with pytest.raises(Conflict): s.heartbeat(r['id'],a['fence'],a['cancel_generation'],attempt=a['attempt'])
    assert s.get(r['id'])['state']=='interrupted'
    s.release_slot(r['id'])
    s.cancel(workspace,r['id'])
    with pytest.raises(Conflict): s.claim(r['id'])
    with pytest.raises(Conflict): s.complete(r['id'],a['fence'],a['cancel_generation'],{},attempt=a['attempt'])
    assert s.get(r['id'])['state']=='cancelled'
    assert s.get(r['id'],'wrong') is None
