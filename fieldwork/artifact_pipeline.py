"""Durable internal candidate stages, with selected-checkpoint numerical comparison."""
import json,math,subprocess,sys,uuid
from pathlib import Path
from .store import ROOT
from .data import canonical,digest


def verify_inference_receipt(bundle,image,receipt,expected_bundle_digest=None):
    bundle=Path(bundle);image=Path(image)
    from .bundle import verify_bundle
    verify_bundle(bundle,expected_digest=expected_bundle_digest)
    lineage=json.loads((bundle/'lineage.json').read_text());classes=json.loads((bundle/'classes.json').read_text())
    expected={'bundle_digest':digest((bundle/'manifest.json').read_bytes()),'model_digest':lineage['model_digest'],'preprocess_digest':digest((bundle/'preprocess.json').read_bytes()),'input_digest':digest(image.read_bytes()),'classes':classes,'scope':'synthetic-execution-only'}
    if any(receipt.get(k)!=v for k,v in expected.items()):raise ValueError('inference receipt identity')
    if type(receipt.get('pid')) is not int or receipt['pid']<=0:raise ValueError('inference process identity')
    uuid.UUID(receipt['process_identity'])
    body={k:v for k,v in receipt.items() if k!='output_digest'}
    if digest(canonical(body))!=receipt.get('output_digest'):raise ValueError('inference receipt digest')
    records=[json.loads(line) for line in (bundle/'evaluation/predictions.jsonl').read_text().splitlines()]
    reference=next((r for r in records if r['sha256']==expected['input_digest'] and r['status']=='ok'),None)
    if reference is None:raise ValueError('inference reference population')
    logits=receipt.get('logits')
    if not isinstance(logits,list) or len(logits)!=5 or any(type(x) not in (int,float) or not math.isfinite(x) for x in logits) or max(abs(a-b) for a,b in zip(logits,reference['logits']))>1e-6:raise ValueError('fresh inference logits mismatch')
    top1=max(range(5),key=lambda i:reference['logits'][i])
    probabilities=receipt.get('probabilities');mx=max(logits);den=sum(math.exp(x-mx) for x in logits)
    if receipt.get('top1')!=top1 or not isinstance(probabilities,list) or len(probabilities)!=5 or any(type(p) not in (int,float) or not math.isfinite(p) or abs(p-math.exp(x-mx)/den)>1e-6 for p,x in zip(probabilities,logits)):raise ValueError('fresh inference probabilities or top1 mismatch')
    return receipt


def evaluation_identity(workspace,rid,bundle):
    """The ML-EvaluationChanged identity, computed at commit time from the exact bytes GET
    .../evaluation later serves (api.evaluation_core): evaluation_id = uuid5(workspace, run,
    split, digest(canonical({metrics, population, independent})))."""
    from .evidence_snapshot import parse
    from .identities import evaluation_id
    core={k:parse((Path(bundle)/'evaluation'/(f+'.json')).read_text()) for k,f in [('metrics','metrics'),('population','population'),('independent','independent-report')]}
    evaluation_digest=digest(canonical(core))
    return {'evaluation_id':evaluation_id(workspace,rid,evaluation_digest),'evaluation_digest':evaluation_digest,
            'records_digest':digest((Path(bundle)/'evaluation/predictions.jsonl').read_bytes())}


def finalize_artifacts(store,attempt,folder,data,env):
    import threading,time
    from .store import Conflict
    rid=attempt['id'];fence=attempt['fence'];folder=Path(folder)
    expected=None;child=None;stop=threading.Event();heartbeat=None
    def renew():
        while not stop.wait(5):
            try:store.artifact_heartbeat(rid,fence)
            except BaseException:return # Every publication independently checks lease/fence.
    try:
        store.artifact_transition(rid,fence,'building',{'code':'BUILDING_INTERNAL_CANDIDATE'})
        # Each fence writes only its own directory, never a later retry's files.
        folder=folder/('artifact-attempt-'+str(fence));folder.mkdir(parents=True,exist_ok=False);bundle=folder/'bundle'
        heartbeat=threading.Thread(target=renew,daemon=True);heartbeat.start()
        from .bundle import build,verify_bundle
        state=store.get(rid);best=state['result']['best']['epoch']
        selected=store.resume_checkpoint(rid,best)  # scoped worker identity: no raw SQL
        if not selected:raise ValueError('missing selected committed checkpoint')
        from .rights import RightsService
        from .rights_registry import load_trusted_registry
        build(selected['path'],data,bundle,expected_checkpoint_digest=selected['digest'],
              rights_service=RightsService(store,load_trusted_registry),
              workspace_id=state['workspace'],dataset_id=state['config'].get('dataset_id'),actor=state['actor'])
        expected=digest((bundle/'manifest.json').read_bytes())
        verify_bundle(bundle,expected_digest=expected,expected_lineage={'dataset_digest':state['config']['dataset_digest'],'checkpoint_digest':selected['digest'],'epoch':best})
        store.artifact_transition(rid,fence,'inference',{'bundle_digest':expected,'checkpoint_digest':selected['digest']})
        image=Path(data)/'SYN-0-6.png'
        store.begin_child(rid,fence,artifact=True)
        try:child=subprocess.Popen([sys.executable,'-m','fieldwork.infer','--bundle',str(bundle),'--image',str(image),'--expected-bundle-digest',expected],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=ROOT)
        except BaseException:
            store.child_spawn_failed(rid,fence);raise
        store.register_child(rid,fence,child)
        stdout,stderr=child.communicate(timeout=60)
        if child.returncode!=0:raise RuntimeError('fresh inference process failed')
        if len(stdout)>64*1024:raise ValueError('inference receipt size')
        receipt=verify_inference_receipt(bundle,image,json.loads(stdout),expected)
        from .ml import write_bytes
        write_bytes(folder/'fresh-process.json',canonical(receipt))
        store.artifact_transition(rid,fence,'verified',{'bundle_digest':expected,'receipt_digest':receipt['output_digest'],'model_digest':receipt['model_digest'],'process_identity':receipt['process_identity'],'artifact_directory':folder.name,**evaluation_identity(state['workspace'],rid,bundle)})
        return receipt
    except BaseException:
        if child is not None and child.poll() is None:child.kill();child.wait(timeout=10)
        try:store.artifact_transition(rid,fence,'failed',{'code':'ARTIFACT_PIPELINE_FAILED','bundle_digest':expected})
        except Conflict:pass # Never overwrite another owner/fence's outcome.
        raise
    finally:
        stop.set()
        if heartbeat is not None:heartbeat.join(timeout=10)
        if child is not None and child.poll() is None:child.kill();child.wait(timeout=10)
