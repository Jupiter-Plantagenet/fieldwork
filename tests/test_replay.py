"""Real OS process fault schedule: commit8, kill epoch9/batch2, fence, replay9..10."""
import json, os, subprocess, sys, time, uuid
from pathlib import Path
import pytest


def test_kill_restart_epoch9_replay_and_stale_publication(isolated_store,tmp_path):
    from fieldwork.data import generate
    from fieldwork.store import Store, Conflict
    from fieldwork.supervisor import watch
    from safetensors.torch import load_file
    import torch
    s=isolated_store;s.blob_root=tmp_path/'blobs';s.migrate()  # throwaway DB/blob dir, not the live worker's slot
    data=tmp_path/'images';m=generate(data)
    r=s.submit(str(uuid.uuid4()),'proof',str(uuid.uuid4()),{'epochs':10,'seed':42,'dataset_digest':m['digest']})
    a=s.claim(r['id']);first=tmp_path/'attempt-a'
    p=subprocess.Popen([sys.executable,'-m','fieldwork.ml','--data',str(data),'--out',str(first),'--epochs','10','--pause-epoch','9'],env={k:v for k,v in os.environ.items() if k in ['SYSTEMROOT','PATH','TEMP','TMP','USERPROFILE']})
    watch(s,a,p,first,stop_at_pause=True)
    assert s.get(r['id'])['epoch']==8
    assert json.loads((first/'paused.json').read_text())['batch']==2
    p.kill();p.wait(timeout=10)
    s.expire_for_test(r['id']);s.release_slot(r['id'])
    with pytest.raises(Conflict):s.heartbeat(r['id'],a['fence'],a['cancel_generation'],attempt=a['attempt'])
    with pytest.raises(Conflict):s.publish(r['id'],a['fence'],a['cancel_generation'],first/'epoch-8',{'epoch':9},attempt=a['attempt'])
    with pytest.raises(Conflict):s.complete(r['id'],a['fence'],a['cancel_generation'],{},attempt=a['attempt'])
    s.resume(r['workspace'],r['id'],9);b=s.claim(r['id']);assert b['fence']>a['fence'] and b['attempt']!=a['attempt']
    second=tmp_path/'attempt-b'
    expected=next(x['digest'] for x in s.checkpoints(r['id']) if x['epoch']==8)
    p2=subprocess.Popen([sys.executable,'-m','fieldwork.ml','--data',str(data),'--out',str(second),'--epochs','10','--resume',b['checkpoint'],'--expected-checkpoint-digest',expected])
    watch(s,b,p2,second);s.release_slot(r['id'])
    assert s.get(r['id'])['state']=='succeeded'
    assert [x['epoch'] for x in s.checkpoints(r['id'])]==list(range(1,11))
    control=tmp_path/'control'
    subprocess.run([sys.executable,'-m','fieldwork.ml','--data',str(data),'--out',str(control),'--epochs','10'],check=True,timeout=180)
    restored=load_file(str(second/'epoch-10/state.safetensors'));baseline=load_file(str(control/'epoch-10/state.safetensors'))
    diff=max(float((restored[k]-baseline[k]).abs().max()) for k in restored if k.startswith('model.'))
    ra=json.loads((second/'result.json').read_text());rb=json.loads((control/'result.json').read_text())
    logits=float((torch.tensor(ra['logits'])-torch.tensor(rb['logits'])).abs().max())
    assert diff<=1e-6 and logits<=1e-6
    assert {x['epoch'] for x in ra['steps']}=={9,10}
    report={'scope':'synthetic-execution-only','run':r['id'],'killed_pid':p.pid,'restored_pid':p2.pid,'committed_epochs':[x['epoch'] for x in s.checkpoints(r['id'])],'parameter_max_abs':diff,'logits_max_abs':logits,'updates':ra['updates'],'new_attempt':b['attempt'],'old_attempt':a['attempt'],'replay_epoch':9,'stale_messages_rejected':3,'holdout_opened':False}
    (tmp_path/'replay-diff.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))
