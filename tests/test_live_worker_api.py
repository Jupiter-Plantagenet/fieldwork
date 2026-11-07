"""Actual loopback HTTP -> durable PostgreSQL -> separate worker -> CPU path.
Generated identities are private memory only; geometric data proves mechanics only.
"""
import json,os,subprocess,sys,uuid
import httpx,pytest,psutil,shutil
from fieldwork.store import ROOT,Store
from fieldwork.api import create_account
BASE=os.environ.get('FIELDWORK_LIVE_BASE','http://127.0.0.1:8102')


def test_live_http_queue_worker_checkpoint_evaluation_fresh_inference():
    available=psutil.virtual_memory().available;free=shutil.disk_usage(ROOT).free
    if available<6*1024**3 or free<12*1024**3:pytest.skip(f'BLOCKED real queue lane: RAM={available},disk={free}; admission unchanged')
    name='api-worker-'+uuid.uuid4().hex;password=uuid.uuid4().hex;workspace=name
    create_account(name,password,workspace,'researcher')
    with httpx.Client(base_url=BASE,timeout=30) as c:
        login=c.post('/auth/session',json={'name':name,'password':password});assert login.status_code==200
        headers={'Origin':'http://127.0.0.1:8102','X-CSRF-Token':login.json()['csrf'],'Idempotency-Key':str(uuid.uuid4())}
        base='/api/v1/workspaces/'+workspace
        reply=c.post(base+'/runs',headers=headers,json={'epochs':2,'batch_size':8,'seed':42,'learning_rate':'0.001'})
        if reply.status_code==423:pytest.skip('BLOCKED admission changed between host sample and API submission')
        assert reply.status_code==202,reply.text
        r=reply.json();rid=r['id'];queued=c.get(base+'/runs/'+rid).json()
        assert queued['run']['state']=='queued' and not queued['checkpoints'] and queued['run']['result'] is None
        assert c.post(base+'/runs',headers=headers,json={'epochs':2,'batch_size':8,'seed':42,'learning_rate':'0.001'}).json()['id']==rid
        worker=subprocess.run([sys.executable,'-m','fieldwork.worker','--once','--run-id',rid],capture_output=True,text=True,timeout=240)
        if worker.returncode==23:pytest.skip('BLOCKED resource gate at worker claim: '+worker.stdout)
        assert worker.returncode==0,worker.stdout+worker.stderr
        completed=c.get(base+'/runs/'+rid).json();assert completed['run']['state']=='succeeded'
        assert [x['epoch'] for x in completed['checkpoints']]==[1,2]
        ev=c.get(base+'/runs/'+rid+'/evaluation');assert ev.status_code==200,ev.text
        artifacts=c.get(base+'/runs/'+rid+'/artifacts');assert artifacts.status_code==200,artifacts.text
        payload=artifacts.json();receipt=payload['receipt'];assert receipt['pid']!=__import__('os').getpid()
        assert len(receipt['logits'])==5 and ev.json()['metrics']['n']==10
        # Canonical ml-contracts identities: stable UUIDs bound to the immutable evaluation digest.
        ident=ev.json();assert str(uuid.UUID(ident['evaluation_id']))==ident['evaluation_id']
        assert c.get(base+'/runs/'+rid+'/evaluation').json()['evaluation_id']==ident['evaluation_id']
        sl=c.get(base+'/runs/'+rid+'/slices?actual=0&predicted=0').json()
        assert sl['evaluation_id']==ident['evaluation_id'] and sl['evaluation_digest']==ident['evaluation_digest'] and str(uuid.UUID(sl['slice_id']))==sl['slice_id']
        envelopes=[e for e in c.get(base+'/events').json()['items'] if e['run']==rid]
        assert {e['type'] for e in envelopes}>={'ML-RunChanged','ML-CheckpointCommitted','ML-EvaluationChanged'}
        assert all(e['schema_version']=='1.0' and e['sequence']==str(e['seq']) and e['revision']==e['object_revision'] for e in envelopes)
        assert all(e['manifest_digest'] for e in envelopes if e['type']=='ML-CheckpointCommitted')
        assert payload['download_allowed'] is False
        report={'run':rid,'workspace':workspace,'actual_http':True,'queue_state_before_worker':queued['run']['state'],'checkpoint_epochs':[1,2],'worker_exit':worker.returncode,'evaluation_count':ev.json()['metrics']['n'],'fresh_process':receipt,'scope':'synthetic-mechanics-only','worker_stdout':worker.stdout}
        written=__import__('fieldwork.evidence_out',fromlist=['x']).write_evidence(ROOT,'live-api-worker.json',report)
        print(json.dumps({'run':rid,'evidence':str(written.relative_to(ROOT)),'state':'succeeded','scope':'synthetic-mechanics-only'}))
