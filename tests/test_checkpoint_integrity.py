"""Independent review FW-01 regressions, real isolated PostgreSQL, copied bytes."""
import json,shutil,struct
from pathlib import Path
import pytest
from fieldwork.data import canonical,digest
from fieldwork.store import ROOT,Conflict

SOURCE=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'


def rehash(path):
    manifest=json.loads((path/'manifest.json').read_text())
    for name in manifest['files']:
        data=(path/name).read_bytes();manifest['files'][name]={'bytes':len(data),'sha256':digest(data)}
    (path/'manifest.json').write_bytes(canonical(manifest))


def test_fw01_rejects_selfhashed_invalid_checkpoint_before_durable_epoch(isolated_store,tmp_path):
    from fieldwork.ml import validate_checkpoint
    p=tmp_path/'invalid';p.mkdir();(p/'state.safetensors').write_bytes(b'not a tensor file')
    meta={'dataset_digest':'dataset-fixture','epoch':1,'next_epoch':2}
    (p/'state.json').write_bytes(canonical(meta));(p/'manifest.json').write_bytes(canonical({'schema':999,'files':{n:{'bytes':(p/n).stat().st_size,'sha256':digest((p/n).read_bytes())} for n in ['state.json','state.safetensors']}}))
    s=isolated_store;r=s.submit('fw01','author','one',{'epochs':1,'dataset_digest':'dataset-fixture'});a=s.claim(r['id'])
    try:
        with pytest.raises(ValueError):s.publish(r['id'],a['fence'],a['cancel_generation'],p,{'epoch':1},attempt=a['attempt'])
        assert s.get(r['id'])['epoch']==0 and s.checkpoints(r['id'])==[]
    finally:s.cancel('fw01',r['id']);s.release_slot(r['id'])


@pytest.mark.parametrize('change',['schema','optimizer','rng','header','torch_rng'])
def test_fw01_rejects_rehashed_invalid_state_and_tensor_header(tmp_path,change):
    from fieldwork.ml import validate_checkpoint
    p=tmp_path/'checkpoint';shutil.copytree(SOURCE,p)
    state=json.loads((p/'state.json').read_text())
    if change=='schema':state['schema']=999
    elif change=='optimizer':state['slots']['0.weight'].pop('exp_avg_sq')
    elif change=='rng':state['python_rng']=[3,[1],None]
    elif change=='torch_rng':
        from safetensors.torch import load_file,save_file
        tensors=load_file(str(p/'state.safetensors'));tensors['rng.sampler'].zero_();save_file(tensors,str(p/'state.safetensors'))
    else:(p/'state.safetensors').write_bytes(struct.pack('<Q',1024*1024*1024)+b'{}')
    (p/'state.json').write_bytes(canonical(state));rehash(p)
    with pytest.raises(ValueError):validate_checkpoint(p)


def test_fw01_controller_copies_staging_and_resume_anchors_committed_digest(isolated_store,tmp_path):
    from fieldwork.ml import validate_checkpoint
    stage=tmp_path/'staging';shutil.copytree(SOURCE,stage)
    meta=json.loads((stage/'state.json').read_text());s=isolated_store;s.blob_root=tmp_path/'controller-checkpoints'
    r=s.submit('fw01-cas','author','one',{'epochs':2,'dataset_digest':meta['dataset_digest']});a=s.claim(r['id'])
    metrics={k:meta[k] for k in ['epoch','train_loss','validation_loss','updates']}
    try:
        s.publish(r['id'],a['fence'],a['cancel_generation'],stage,metrics,attempt=a['attempt'])
        saved=s.get(r['id']);committed=Path(saved['checkpoint'])
        assert committed.resolve()!=stage.resolve()
        assert committed.name==s.checkpoints(r['id'])[0]['digest']
        (stage/'state.safetensors').write_bytes(b'destroyed untrusted staging')
        validate_checkpoint(committed)
        s.expire_for_test(r['id']);s.release_slot(r['id'])
        # Same-user corruption is still possible until OS identity isolation is approved.
        # Rehashing it must never replace the digest anchored in PostgreSQL.
        path=committed/'state.json';path.chmod(0o600)
        state=json.loads(path.read_text());state['initial_digest']='f'*64;path.write_bytes(canonical(state))
        (committed/'manifest.json').chmod(0o600);rehash(committed)
        with pytest.raises(ValueError,match='committed checkpoint digest'):s.resume('fw01-cas',r['id'],2)
        assert s.get(r['id'])['state']=='interrupted'
    finally:s.release_slot(r['id'])


def test_fw01_restore_requires_expected_digest_before_tensor_load(tmp_path):
    import torch
    from fieldwork.ml import model,restore
    p=tmp_path/'changed';shutil.copytree(SOURCE,p)
    expected=digest((p/'manifest.json').read_bytes());state=json.loads((p/'state.json').read_text());state['initial_digest']='a'*64
    (p/'state.json').write_bytes(canonical(state));rehash(p)
    net=model();opt=torch.optim.AdamW(net.parameters())
    with pytest.raises(ValueError,match='committed checkpoint digest'):restore(p,net,opt,expected_digest=expected)


def test_fw01_restore_without_controller_digest_is_not_self_authorizing():
    import torch
    from fieldwork.ml import model,restore
    net=model();optimizer=torch.optim.AdamW(net.parameters())
    with pytest.raises(ValueError,match='trusted expected checkpoint digest required'):restore(SOURCE,net,optimizer)


def test_fw01_training_child_refuses_wrong_controller_digest_before_updates(tmp_path):
    import subprocess,sys
    command=[sys.executable,'-m','fieldwork.ml','--data',str(SOURCE.parents[1]/'images'),'--out',str(tmp_path/'child'),'--epochs','2','--resume',str(SOURCE),'--expected-checkpoint-digest','f'*64]
    p=subprocess.run(command,capture_output=True,text=True,timeout=30)
    assert p.returncode!=0 and 'committed checkpoint digest' in p.stderr
    assert not (tmp_path/'child/steps.jsonl').exists()


@pytest.mark.parametrize('mismatch',['seed','learning_rate','metrics'])
def test_fw01_publication_rejects_wrong_resolved_configuration_or_metrics(isolated_store,mismatch):
    meta=json.loads((SOURCE/'state.json').read_text());cfg={'epochs':1,'dataset_digest':meta['dataset_digest'],'seed':42,'learning_rate':'0.001'}
    metrics={k:meta[k] for k in ['epoch','train_loss','validation_loss','updates']}
    if mismatch=='seed':cfg['seed']=43
    elif mismatch=='learning_rate':cfg['learning_rate']='0.1'
    else:metrics['train_loss']+=1
    s=isolated_store;r=s.submit('fw01-lineage','author','one',cfg);a=s.claim(r['id'])
    try:
        with pytest.raises(Conflict,match='CHECKPOINT_LINEAGE_OR_METRICS'):s.publish(r['id'],a['fence'],a['cancel_generation'],SOURCE,metrics,attempt=a['attempt'])
        assert s.get(r['id'])['epoch']==0
    finally:s.release_slot(r['id'])
