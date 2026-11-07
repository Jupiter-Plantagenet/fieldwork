import json,uuid,shutil
import pytest


# These tests use the throwaway isolated_store DB (not the live .local.json DB): the
# live DB now carries migration 011+ guards and a live worker owns its process slot.
def test_atomic_publication_rejects_partial_lineage_and_replays_lost_ack(isolated_store,tmp_path):
    from fieldwork.store import Store,ROOT,Conflict
    source=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'
    meta=json.loads((source/'state.json').read_text())
    s=isolated_store;s.blob_root=tmp_path/'blobs';s.migrate();r=s.submit('atomic-'+str(uuid.uuid4()),'a',str(uuid.uuid4()),{'epochs':1,'dataset_digest':meta['dataset_digest']})
    a=s.claim(r['id'])
    try:
        stage=tmp_path/'partial';stage.mkdir();shutil.copy(source/'state.safetensors',stage/'state.safetensors')
        with pytest.raises((ValueError,FileNotFoundError)):s.publish(r['id'],a['fence'],a['cancel_generation'],stage,{'epoch':1},attempt=a['attempt'])
        assert s.get(r['id'])['epoch']==0
        with pytest.raises((ValueError,Conflict)):s.publish(r['id'],a['fence'],a['cancel_generation'],source,{'epoch':2},attempt=a['attempt'])
        metrics={k:meta[k] for k in ['epoch','train_loss','validation_loss','updates']}
        s.publish(r['id'],a['fence'],a['cancel_generation'],source,metrics,attempt=a['attempt'])
        before=len(s.events(r['workspace']))
        s.publish(r['id'],a['fence'],a['cancel_generation'],source,metrics,attempt=a['attempt']) # committed DB, acknowledgement lost
        assert len(s.events(r['workspace']))==before
        assert len(s.checkpoints(r['id']))==1
        s.complete(r['id'],a['fence'],a['cancel_generation'],{'proof':'actual checkpoint'},attempt=a['attempt'])
        assert s.cancel(r['workspace'],r['id'])=='succeeded'
    finally:s.release_slot(r['id'])


def test_cancel_first_revokes_publication_before_process_slot_release(isolated_store,tmp_path):
    from fieldwork.store import Store,ROOT,Conflict
    source=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1';meta=json.loads((source/'state.json').read_text())
    s=isolated_store;s.blob_root=tmp_path/'blobs';r=s.submit('cancel-'+str(uuid.uuid4()),'a',str(uuid.uuid4()),{'epochs':1,'dataset_digest':meta['dataset_digest']});a=s.claim(r['id'])
    try:
        assert s.cancel(r['workspace'],r['id'])=='cancel_requested'
        with pytest.raises(Conflict):s.publish(r['id'],a['fence'],a['cancel_generation'],source,{'epoch':1},attempt=a['attempt'])
        with pytest.raises(Conflict):s.complete(r['id'],a['fence'],a['cancel_generation'],{},attempt=a['attempt'])
        with s.connect() as c:assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run']==r['id']
    # Round 3: the exit acknowledgement names the cancel generation (issued+1).
    finally:s.release_slot(r['id'],cancel_generation=a['cancel_generation']+1)
    assert s.get(r['id'])['state']=='cancelled'


def test_checkpoint_wrong_dataset_cannot_be_published(isolated_store,tmp_path):
    from fieldwork.store import Store,ROOT,Conflict
    source=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'
    s=isolated_store;s.blob_root=tmp_path/'blobs';r=s.submit('lineage-'+str(uuid.uuid4()),'a',str(uuid.uuid4()),{'epochs':1,'dataset_digest':'wrong-dataset'});a=s.claim(r['id'])
    try:
        with pytest.raises((ValueError,Conflict),match='LINEAGE'):s.publish(r['id'],a['fence'],a['cancel_generation'],source,{'epoch':1},attempt=a['attempt'])
        assert s.get(r['id'])['epoch']==0
    finally:s.cancel(r['workspace'],r['id']);s.release_slot(r['id'])
