"""Lightweight, bounded, read-once evidence snapshots. No model allocation.

All returned data is derived from the SAME bytes that were hashed against the
controller's accepted DB identity. Paths are never returned for later streaming.
The trusted controller already performed semantic/model validation at acceptance.
"""
import json,math,re,uuid
from pathlib import Path
from types import MappingProxyType
from .data import canonical,digest
from .safe_codec import unique_object

REQUIRED=frozenset({'model.safetensors','architecture.json','preprocess.json','classes.json','lineage.json','environment-lock.json','evaluation/population.json','evaluation/predictions.jsonl','evaluation/metrics.json','evaluation/independent-report.json','rights/review.json','rights/notices.txt','README.md'})
PREPROCESS={'schema':1,'resize':[144,144],'crop':[8,8,136,136],'channels':'RGB','scale':'1/255','orientation':'exif-transpose','training_augmentation':'none; synthetic execution profile deviation'}


def read_once(path,limit):
    path=Path(path)
    # Check each ancestor too: rejecting only the leaf permits symlink directories.
    if any(p.is_symlink() for p in [path,*path.parents]):raise ValueError('evidence symlink')
    with path.open('rb') as f:value=f.read(limit+1)
    if len(value)>limit:raise ValueError('evidence size')
    return value


def parse(value):
    try:return json.loads(value,object_pairs_hook=unique_object,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (UnicodeError,RecursionError,OverflowError) as exc:raise ValueError('evidence JSON') from exc


def snapshot(path,expected_digest):
    if not isinstance(expected_digest,str) or re.fullmatch('[a-f0-9]{64}',expected_digest) is None:raise ValueError('trusted bundle identity required')
    path=Path(path);raw=read_once(path/'manifest.json',1024*1024)
    if digest(raw)!=expected_digest:raise ValueError('trusted bundle digest')
    manifest=parse(raw)
    if not isinstance(manifest,dict) or set(manifest)!={'schema','purpose','scope','evidence_scope','files'} or manifest['schema']!=1 or manifest['purpose']!='internal_candidate' or manifest['scope']!='synthetic-execution-only' or manifest['evidence_scope']!='validation_only' or not isinstance(manifest['files'],dict) or set(manifest['files'])!=REQUIRED:raise ValueError('manifest inventory scope')
    entries=[]
    for entry in path.rglob('*'):
        if len(entries)>=64:raise ValueError('bundle inventory entry budget')
        if entry.is_symlink():raise ValueError('bundle inventory symlink')
        entries.append(entry)
    if {p.relative_to(path).as_posix() for p in entries if p.is_file()}!=REQUIRED|{'manifest.json'}:raise ValueError('bundle inventory')
    files={};total=0
    for name,entry in manifest['files'].items():
        limit=32*1024*1024 if name=='model.safetensors' else (8*1024*1024 if name.endswith('.jsonl') else 1024*1024)
        if not isinstance(entry,dict) or set(entry)!={'bytes','sha256'} or type(entry['bytes']) is not int or not 0<=entry['bytes']<=limit:raise ValueError('inventory size')
        total+=entry['bytes']
        if total>64*1024*1024:raise ValueError('bundle size')
        value=read_once(path/name,entry['bytes'])
        if len(value)!=entry['bytes'] or digest(value)!=entry['sha256']:raise ValueError('payload digest or size')
        files[name]=value
    return manifest,MappingProxyType(files)


def receipt_identity(files,receipt,attestation):
    lineage=parse(files['lineage.json']);classes=parse(files['classes.json'])
    expected={'bundle_digest':attestation['bundle_digest'],'model_digest':lineage['model_digest'],'preprocess_digest':digest(files['preprocess.json']),'classes':classes,'scope':'synthetic-execution-only','process_identity':attestation['process_identity'],'output_digest':attestation['receipt_digest']}
    if not isinstance(receipt,dict) or any(receipt.get(k)!=v for k,v in expected.items()) or lineage['model_digest']!=attestation['model_digest']:raise ValueError('receipt identity')
    if type(receipt.get('pid')) is not int or receipt['pid']<=0:raise ValueError('receipt process')
    uuid.UUID(receipt['process_identity'])
    if digest(canonical({k:v for k,v in receipt.items() if k!='output_digest'}))!=receipt['output_digest']:raise ValueError('receipt digest')
    if parse(files['preprocess.json'])!=PREPROCESS or digest(files['model.safetensors'])!=lineage['model_digest']:raise ValueError('recipe model identity')
    rows=[parse(line) for line in files['evaluation/predictions.jsonl'].splitlines() if line]
    if len(rows)>10000:raise ValueError('prediction count')
    reference=next((r for r in rows if r.get('sha256')==receipt.get('input_digest') and r.get('status')=='ok'),None)
    population=parse(files['evaluation/population.json'])
    if reference is None or not any(all(p.get(k)==reference.get(k) for k in ('id','label','sha256')) for p in population) or reference.get('model')!=lineage['model_digest']:raise ValueError('receipt input provenance')
    logits=receipt.get('logits');probs=receipt.get('probabilities')
    if not isinstance(logits,list) or len(logits)!=5 or not isinstance(probs,list) or len(probs)!=5 or any(type(v) not in (int,float) or not math.isfinite(v) for v in logits+probs):raise ValueError('receipt numbers')
    if len(reference['logits'])!=5 or max(abs(a-b) for a,b in zip(logits,reference['logits']))>1e-6:raise ValueError('receipt logits')
    mx=max(logits);den=sum(math.exp(x-mx) for x in logits)
    if receipt.get('top1')!=max(range(5),key=lambda i:logits[i]) or any(abs(p-math.exp(x-mx)/den)>1e-6 for p,x in zip(probs,logits)):raise ValueError('receipt probabilities')


def accepted_evidence(store,runs,rid,workspace):
    # One transaction's locked canonical run + selected checkpoint, never caller hashes.
    with store.connect() as c:
        r=c.execute('SELECT * FROM fw_runs WHERE id=%s AND workspace=%s FOR SHARE',(rid,workspace)).fetchone()
        if not r:raise LookupError('OBJECT')
        if r['state']!='succeeded' or r['artifact_status']!='verified':raise ValueError('artifact not verified')
        attestation=r['artifact_result']
        best=r['result']['best']['epoch']
        # Preserve the child SHARE lock without granting the API checkpoint writes.
        # Parent locking alone does not cover restore's child-first path rewrite.
        cp=c.execute('SELECT digest FROM fw_checkpoint_read_v1.locked_digest(%s::text,%s::integer,%s::text)',(rid,best,workspace)).fetchone()
        if not cp:raise ValueError('selected checkpoint provenance')
        folder=Path(runs)/rid
        directory=attestation.get('artifact_directory')
        if directory is not None:
            if not isinstance(directory,str) or re.fullmatch(r'artifact-attempt-[0-9]+',directory) is None:raise ValueError('artifact directory identity')
            folder=folder/directory
        manifest,files=snapshot(folder/'bundle',attestation['bundle_digest'])
        lineage=parse(files['lineage.json'])
        if any(lineage.get(k)!=v for k,v in {'dataset_digest':r['config']['dataset_digest'],'checkpoint_digest':cp['digest'],'epoch':best}.items()):raise ValueError('checkpoint provenance')
        receipt=parse(read_once(folder/'fresh-process.json',64*1024));receipt_identity(files,receipt,attestation)
        return r,manifest,files,receipt
