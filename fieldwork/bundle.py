"""Service-produced internal candidates only. Qualified release deliberately blocked."""
import json, math, platform
from pathlib import Path
import torch
from safetensors.torch import save_file,load_file
from .ml import model,pixels,validate_checkpoint,write_bytes
from .data import canonical,digest,verify
from .metrics import evaluate

from .evidence_snapshot import REQUIRED,PREPROCESS


def build(checkpoint,data,out,*,expected_checkpoint_digest,rights_service=None,
          workspace_id=None,dataset_id=None,actor=None):
    if expected_checkpoint_digest is None:raise ValueError("trusted expected checkpoint digest required")
    checkpoint=Path(checkpoint);data=Path(data);out=Path(out)
    m=json.loads((data/'manifest.json').read_text())
    from .rights import require_bundle_rights
    require_bundle_rights(m,service=rights_service,workspace=workspace_id,dataset=dataset_id,actor=actor)
    validate_checkpoint(checkpoint,expected_digest=expected_checkpoint_digest)
    verify(data,m)
    meta=json.loads((checkpoint/'state.json').read_text())
    if meta['dataset_digest']!=m['digest']:raise ValueError('lineage')
    out.mkdir(parents=True,exist_ok=False);(out/'evaluation').mkdir();(out/'rights').mkdir()
    net=model();tensors=load_file(str(checkpoint/'state.safetensors'))
    net.load_state_dict({k:tensors['model.'+k] for k in net.state_dict()},strict=True);net.eval()
    save_file(net.state_dict(),str(out/'model.safetensors'));model_digest=digest((out/'model.safetensors').read_bytes())
    population=[{k:s[k] for k in ['id','label','sha256']} for s in m['samples'] if s['split']=='validation'];rows=[]
    torch.set_num_threads(2)
    with torch.inference_mode():
        for s in m['samples']:
            if s['split']=='validation':rows.append(dict(id=s['id'],label=s['label'],sha256=s['sha256'],model=model_digest,status='ok',logits=net(pixels(data/s['file']).unsqueeze(0))[0].tolist()))
    metrics=evaluate(population,rows,5,model_digest)
    # Oracle is a separately implemented stdlib verifier, not production metrics.
    from tools.verify_metrics import verify as independent
    report=independent(population,rows,5,model_digest)
    for k in metrics:
        if k=='cross_entropy':
            if abs(metrics[k]-report[k])>1e-12:raise ValueError('independent metrics')
        elif metrics[k]!=report[k]:raise ValueError('independent metrics')
    payloads={'architecture.json':{'schema':1,'id':'compact-cnn/v1'},'preprocess.json':PREPROCESS,'classes.json':m['classes'],'lineage.json':{'dataset_digest':m['digest'],'checkpoint_digest':digest((checkpoint/'manifest.json').read_bytes()),'epoch':meta['epoch'],'model_digest':model_digest},'environment-lock.json':{'python':platform.python_version(),'torch':torch.__version__,'platform':platform.platform()},'evaluation/population.json':population,'evaluation/metrics.json':metrics,'evaluation/independent-report.json':report,'rights/review.json':{'scope':'synthetic-execution-only','source':'author-generated','flower_rights':'not cleared','export_qualified':False}}
    for name,value in payloads.items():write_bytes(out/name,canonical(value))
    write_bytes(out/'evaluation/predictions.jsonl',b''.join(canonical(r)+b'\n' for r in rows))
    write_bytes(out/'rights/notices.txt',m['rights'].encode());write_bytes(out/'README.md',b'Internal synthetic execution candidate. Not a qualified release; not flower usefulness evidence. No arbitrary model loading. No holdout exposure.')
    files={f:{'sha256':digest((out/f).read_bytes()),'bytes':(out/f).stat().st_size} for f in sorted(REQUIRED)}
    manifest={'schema':1,'purpose':'internal_candidate','scope':'synthetic-execution-only','evidence_scope':'validation_only','files':files}
    write_bytes(out/'manifest.json',canonical(manifest));verify_bundle(out,expected_digest=digest(canonical(manifest)),expected_lineage=payloads['lineage.json']);return manifest


def verify_bundle(path,expected_digest=None,expected_lineage=None):
    import re
    from .safe_codec import read_json,tensor_header,MODEL_SHAPES
    path=Path(path)
    if expected_digest is None:raise ValueError('trusted expected bundle digest required')
    if path.is_symlink():raise ValueError('bundle symlink')
    m=read_json(path/'manifest.json')
    if expected_digest is not None and digest((path/'manifest.json').read_bytes())!=expected_digest:raise ValueError('trusted bundle digest')
    if set(m)!= {'schema','purpose','scope','evidence_scope','files'} or m['schema']!=1 or m['purpose']!='internal_candidate' or m['scope']!='synthetic-execution-only' or m['evidence_scope']!='validation_only' or set(m['files'])!=REQUIRED:raise ValueError('schema inventory scope')
    actual={p.relative_to(path).as_posix() for p in path.rglob('*') if p.is_file()}
    if actual!=REQUIRED|{'manifest.json'} or any(p.is_symlink() for p in path.rglob('*')):raise ValueError('unexpected files or symlink')
    total=0
    for name,entry in m['files'].items():
        f=path/name;size=f.stat().st_size;total+=size
        if set(entry)!={'bytes','sha256'} or size!=entry['bytes'] or size>32*1024*1024 or digest(f.read_bytes())!=entry['sha256']:raise ValueError('file digest or size')
    if total>64*1024*1024:raise ValueError('bundle size')
    if read_json(path/'architecture.json')!={'schema':1,'id':'compact-cnn/v1'} or read_json(path/'preprocess.json')!=PREPROCESS:raise ValueError('recipe preprocess')
    classes=read_json(path/'classes.json')
    if len(classes)!=5 or len(set(classes))!=5 or any(not isinstance(c,str) or len(c)>100 for c in classes):raise ValueError('class map')
    lineage=read_json(path/'lineage.json')
    if set(lineage)!={'dataset_digest','checkpoint_digest','epoch','model_digest'} or type(lineage['epoch']) is not int or not 1<=lineage['epoch']<=100 or any(not isinstance(lineage[k],str) or re.fullmatch('[a-f0-9]{64}',lineage[k]) is None for k in ['dataset_digest','checkpoint_digest','model_digest']):raise ValueError('lineage schema')
    if expected_lineage is not None and any(lineage.get(k)!=v for k,v in expected_lineage.items()):raise ValueError('trusted lineage')
    if lineage['model_digest']!=digest((path/'model.safetensors').read_bytes()):raise ValueError('model lineage')
    rights=read_json(path/'rights/review.json')
    if rights!={'scope':'synthetic-execution-only','source':'author-generated','flower_rights':'not cleared','export_qualified':False}:raise ValueError('rights scope')
    population=read_json(path/'evaluation/population.json')
    if not isinstance(population,list) or not 1<=len(population)<=10000:raise ValueError('population size')
    if any(set(p)-{'id','label','sha256','group'} or not {'id','label','sha256'}<=set(p) or not isinstance(p['id'],str) or len(p['id'])>100 or type(p['label']) is not int or not 0<=p['label']<5 or not isinstance(p['sha256'],str) or re.fullmatch('[a-f0-9]{64}',p['sha256']) is None for p in population):raise ValueError('population schema')
    records_file=path/'evaluation/predictions.jsonl'
    if records_file.stat().st_size>8*1024*1024:raise ValueError('predictions size')
    from .safe_codec import unique_object
    try:rows=[json.loads(line,object_pairs_hook=unique_object) for line in records_file.read_text().splitlines() if line]
    except (UnicodeError,RecursionError) as exc:raise ValueError('predictions encoding') from exc
    if len(rows)>10000 or any(set(r)-{'id','label','sha256','model','status','logits'} for r in rows):raise ValueError('predictions schema')
    measured=evaluate(population,rows,5,lineage['model_digest'])
    from tools.verify_metrics import verify as independent
    oracle=independent(population,rows,5,lineage['model_digest'])
    legacy={'n','ok','accuracy','coverage','matrix','cells','missing','support','recall','f1','macro_f1','cross_entropy','status'}
    def same(value,wanted):
        if isinstance(wanted,float):return type(value) in (int,float) and math.isfinite(value) and abs(value-wanted)<=1e-12
        if isinstance(wanted,dict):return isinstance(value,dict) and value.keys()==wanted.keys() and all(same(value[k],v) for k,v in wanted.items())
        if isinstance(wanted,list):return isinstance(value,list) and len(value)==len(wanted) and all(same(a,b) for a,b in zip(value,wanted))
        return type(value) is type(wanted) and value==wanted
    for name,wanted in [('metrics',measured),('independent-report',oracle)]:
        saved=read_json(path/'evaluation'/(name+'.json'))
        if set(saved) not in (legacy,set(wanted)) or not same(saved,{k:wanted[k] for k in saved}):raise ValueError('evaluation evidence mismatch')
    if not same(measured,oracle):raise ValueError('independent recomputation mismatch')
    tensor_header(path/'model.safetensors',{k:('F32',v) for k,v in MODEL_SHAPES.items()})
    net=model();tensors=load_file(str(path/'model.safetensors'),device='cpu')
    for k,t in tensors.items():
        ref=net.state_dict()[k]
        if t.shape!=ref.shape or t.dtype!=ref.dtype or not torch.isfinite(t).all():raise ValueError('shape dtype finite')
    return m
