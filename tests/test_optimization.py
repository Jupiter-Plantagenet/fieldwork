import json
import torch
from pathlib import Path


def test_actual_optimizer_checkpoint_restores_exact_epoch(tmp_path):
    from fieldwork.data import generate
    from fieldwork.ml import train, restore, model
    data=tmp_path/'data'; generate(data)
    out=tmp_path/'run'
    result=train(data,out,epochs=2,seed=42)
    assert result['initial_digest'] != result['final_digest']
    assert result['updates'] == 8
    assert all(x['grad_norm']>0 for x in result['steps'])
    assert all(x['split']=='train' for x in result['steps'])
    net=model(); optimizer=torch.optim.AdamW(net.parameters())
    from fieldwork.data import digest
    expected=digest((out/'epoch-2/manifest.json').read_bytes())
    meta=restore(out/'epoch-2',net,optimizer,expected_digest=expected)
    assert meta['next_epoch']==3
    assert len(optimizer.state)==len(list(net.parameters()))
    a=train(data,tmp_path/'continued',epochs=3,seed=42,resume=out/'epoch-2',expected_checkpoint_digest=expected)
    b=train(data,tmp_path/'control',epochs=3,seed=42)
    assert a['final_digest']==b['final_digest']
