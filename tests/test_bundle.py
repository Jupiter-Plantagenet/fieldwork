import json, subprocess, sys
import pytest


def test_candidate_safe_inventory_and_actual_fresh_process(tmp_path):
    from fieldwork.data import generate
    from fieldwork.ml import train
    from fieldwork.bundle import build, verify_bundle
    data=tmp_path/'images';generate(data);run=tmp_path/'run';result=train(data,run,epochs=1)
    b=tmp_path/'bundle';manifest=build(run/'epoch-1',data,b,expected_checkpoint_digest=__import__('hashlib').sha256((run/'epoch-1/manifest.json').read_bytes()).hexdigest())
    assert manifest['purpose']=='internal_candidate'
    expected=__import__('hashlib').sha256((b/'manifest.json').read_bytes()).hexdigest()
    assert verify_bundle(b,expected_digest=expected)['purpose']=='internal_candidate'
    process=subprocess.run([sys.executable,'-m','fieldwork.infer','--bundle',str(b),'--image',str(data/'SYN-0-6.png'),'--expected-bundle-digest',expected],capture_output=True,text=True,check=True,timeout=60)
    receipt=json.loads(process.stdout)
    assert receipt['pid']!=__import__('os').getpid()
    assert len(receipt['logits'])==5 and abs(sum(receipt['probabilities'])-1)<1e-6
    assert max(abs(a-b) for a,b in zip(receipt['logits'],result['logits'][0]))<=1e-6
    assert receipt['bundle_digest']==__import__('hashlib').sha256((b/'manifest.json').read_bytes()).hexdigest()
    (tmp_path/'fresh-process.json').write_text(json.dumps(receipt,indent=2))
    import shutil
    tampered=tmp_path/'tampered-bundle';shutil.copytree(b,tampered)
    (tampered/'evil.py').write_text('raise RuntimeError("must not execute")')
    with pytest.raises(ValueError):verify_bundle(tampered,expected_digest=expected)
    (tampered/'evil.py').unlink();(tampered/'classes.json').write_text('[]')
    with pytest.raises(ValueError):verify_bundle(tampered,expected_digest=expected)
