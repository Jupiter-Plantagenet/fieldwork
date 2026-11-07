from tests.isolated_api import use_isolated_api
import pytest
from fastapi.testclient import TestClient
import fieldwork.api as api
from fieldwork.store import Conflict
from fieldwork.data import generate
from tests.test_annotations import account


def test_accepted_idempotency_replay_precedes_new_admission_failure(isolated_store,monkeypatch):
    use_isolated_api(isolated_store,monkeypatch);api.create_account('queue-author','fixture-password','queue-replay','researcher')
    cfg=api.Config(epochs=1).model_dump(mode='json');cfg.update(dataset_digest=generate(api.DATA)['digest'],recipe='compact-cnn/v1',scope='synthetic-execution-only')
    r=isolated_store.submit('queue-replay','queue-author','accepted-key',cfg)
    monkeypatch.setattr(api.psutil,'virtual_memory',lambda:type('Memory',(),{'available':0})())
    with TestClient(api.app) as c:
        headers={**account(c,'queue-author','fixture-password'),'Idempotency-Key':'accepted-key'};base='/api/v1/workspaces/queue-replay/runs'
        response=c.post(base,json={'epochs':1},headers=headers)
        assert response.status_code==202 and response.json()['id']==r['id']
        assert c.post(base,json={'epochs':2},headers=headers).status_code==409
        assert c.post(base,json={'epochs':1},headers={**headers,'Idempotency-Key':'new-key'}).status_code==423


def test_workspace_queue_cap_is_atomic_and_replay_does_not_consume_another_slot(isolated_store):
    s=isolated_store
    for i in range(20):s.submit('queue-cap','author',str(i),{'epochs':1})
    first=s.submit('queue-cap','author','0',{'epochs':1})
    assert first['state']=='queued' and len(s.list('queue-cap'))==20
    with pytest.raises(Conflict,match='QUEUE_FULL'):s.submit('queue-cap','author','overflow',{'epochs':1})
    assert len(s.list('queue-cap'))==20
