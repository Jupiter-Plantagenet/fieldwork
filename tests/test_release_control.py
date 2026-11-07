"""Lightweight real PostgreSQL regression boundaries; no optimizer bypass."""
import uuid
import pytest
from fieldwork.store import Store, Conflict


def fresh_run(s):
    s.migrate()  # s is the throwaway isolated_store, never the live DB/process slot
    workspace='control-release-'+str(uuid.uuid4())
    r=s.submit(workspace,'author',str(uuid.uuid4()),{'epochs':1})
    return s,workspace,r


def test_repeated_cancel_cannot_certify_unknown_physical_exit(isolated_store):
    s,w,r=fresh_run(isolated_store);a=s.claim(r['id'])
    try:
        assert s.cancel(w,r['id'])=='cancel_requested'
        assert s.cancel(w,r['id'])=='cancel_requested'
        with s.connect() as c:
            assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run']==r['id']
        with pytest.raises(Conflict):s.complete(r['id'],a['fence'],a['cancel_generation'],{},attempt=a['attempt'])
    # Round 3: the exit acknowledgement names the cancel generation (issued+1).
    finally:s.release_slot(r['id'],cancel_generation=a['cancel_generation']+1)
    assert s.get(r['id'])['state']=='cancelled'
