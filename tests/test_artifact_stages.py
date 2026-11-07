"""FW-03: isolated real DB stage faults, not model usefulness fixtures."""
import json
import pytest
from fieldwork.store import ROOT


def test_fw03_artifact_failure_is_durable_after_training_success(isolated_store,tmp_path,monkeypatch):
    import fieldwork.worker as worker
    import fieldwork.bundle as bundle
    s=isolated_store;source=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1';meta=json.loads((source/'state.json').read_text())
    r=s.submit('fw03','author','one',{'epochs':1,'dataset_digest':meta['dataset_digest']});a=s.claim(r['id'])
    try:
        s.publish(r['id'],a['fence'],a['cancel_generation'],source,{k:meta[k] for k in ['epoch','train_loss','validation_loss','updates']},attempt=a['attempt'])
        s.complete(r['id'],a['fence'],a['cancel_generation'],{'best':{'epoch':1}},attempt=a['attempt'])
        def broken(*args,**kwargs):raise OSError('injected disk-full at artifact boundary')
        monkeypatch.setattr(bundle,'build',broken)
        with pytest.raises(OSError):worker.finalize_artifacts(s,a,tmp_path,ROOT/'var/images',{})
        current=s.get(r['id']);assert current['state']=='succeeded'
        assert current['artifact_status']=='failed'
        assert current['artifact_result']['code']=='ARTIFACT_PIPELINE_FAILED'
        assert s.events('fw03')[-1]['kind']=='artifact_failed'
        # Confirmed no-child failure now releases in the terminal transaction,
        # rather than relying on worker finally to perform a second commit.
        with s.connect() as c:assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run'] is None
    finally:s.release_slot(r['id'])


def test_fw03_selfhashed_wrong_logits_receipt_rejected():
    from fieldwork.worker import verify_inference_receipt
    from fieldwork.data import canonical,digest
    bundle=ROOT/'evidence/internal-candidate';image=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/images/SYN-0-6.png'
    receipt=json.loads((ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/fresh-process.json').read_text())
    receipt['logits'][0]+=.1;receipt.pop('output_digest',None);receipt['output_digest']=digest(canonical(receipt))
    with pytest.raises(ValueError,match='logits'):verify_inference_receipt(bundle,image,receipt,expected_bundle_digest=receipt['bundle_digest'])
