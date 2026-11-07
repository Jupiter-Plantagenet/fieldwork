import json, subprocess,sys,uuid
import pytest,psutil


def test_proof_pause_hook_is_explicit_once_run_only_and_default_is_unchanged():
    from fieldwork.worker import parse_args
    default=parse_args(['--once','--run-id','run-fixture'])
    assert default.proof_pause_epoch is None
    assert default.once and default.run_id=='run-fixture'
    assert parse_args(['--once','--run-id','run-fixture','--proof-pause-epoch','9']).proof_pause_epoch==9
    with pytest.raises(SystemExit):parse_args(['--proof-pause-epoch','9'])
    with pytest.raises(SystemExit):parse_args(['--once','--proof-pause-epoch','9'])
    with pytest.raises(SystemExit):parse_args(['--run-id','run-fixture','--proof-pause-epoch','9'])


def test_separate_worker_executes_queued_run_and_persists_bundle():
    from fieldwork.store import Store,ROOT
    from fieldwork.data import generate
    s=Store();s.migrate();m=generate(ROOT/'var/images')
    r=s.submit('worker-proof-'+str(uuid.uuid4()),'worker-proof',str(uuid.uuid4()),{'epochs':2,'seed':42,'batch_size':8,'learning_rate':'0.001','dataset_digest':m['digest'],'recipe':'compact-cnn/v1','scope':'synthetic-execution-only'})
    command=[sys.executable,'-m','fieldwork.worker','--once','--run-id',r['id']]
    p=subprocess.run(command,capture_output=True,text=True,timeout=180)
    if p.returncode==23:
        assert 'RESOURCE_PREFLIGHT' in p.stdout
        pytest.skip('Measured resource admission blocked actual worker execution')
    assert p.returncode==0,p.stdout+p.stderr
    row=s.get(r['id']);assert row['state']=='succeeded' and row['epoch']==2
    assert row['artifact_status']=='verified'
    folder=ROOT/'var/runs'/r['id']/row['artifact_result']['artifact_directory']
    receipt=json.loads((folder/'fresh-process.json').read_text())
    assert len(receipt['logits'])==5
    assert (folder/'bundle/model.safetensors').exists()
    assert json.loads((folder/'bundle/evaluation/metrics.json').read_text())['n']==10
    print(json.dumps({'run':r['id'],'worker_receipt':str(folder/'fresh-process.json'),'pid':receipt['pid']}))
