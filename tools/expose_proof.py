"""Expose an ALREADY EXECUTED proof without running or inventing training."""
import json,secrets
from pathlib import Path
from fieldwork.store import Store,ROOT
from fieldwork.api import create_account,DATA
from fieldwork.data import generate,canonical,digest
from fieldwork.metrics import evaluate
from tools.verify_metrics import verify
p=ROOT/'evidence/critical-proof/test_kill_restart_epoch9_repla0'
report=json.loads((p/'replay-diff.json').read_text());result=json.loads((p/'attempt-b/result.json').read_text())
s=Store();r=s.get(report['run']);assert r['state']=='succeeded' and r['epoch']==10
m=generate(DATA);assert m['digest']==r['config']['dataset_digest']
assert result['best']['epoch']==10, 'Diagnostic last-state != selected checkpoint; cannot misrepresent selection'
rows=[];pop=[]
for sid,logits in zip(result['validation_ids'],result['logits'],strict=True):
    sample=next(x for x in m['samples'] if x['id']==sid);assert sample['split']=='validation'
    item={k:sample[k] for k in ['id','label','sha256']};pop.append(item)
    rows.append(dict(item,logits=logits,status='ok',model=result['final_digest']))
a=evaluate(pop,rows,5,result['final_digest']);b=verify(pop,rows,5,result['final_digest'])
assert all(a[k]==b[k] for k in a if k!='cross_entropy');assert abs(a['cross_entropy']-b['cross_entropy'])<=1e-12
out=ROOT/'var/runs'/r['id']/'evaluation';out.mkdir(parents=True,exist_ok=True)
for name,value in [('population',pop),('metrics',a),('independent-report',b)]: (out/(name+'.json')).write_bytes(canonical(value))
(out/'predictions.jsonl').write_bytes(b''.join(canonical(x)+b'\n' for x in rows))
(out/'provenance.json').write_bytes(canonical({'source':'retained process-fault proof','result_digest':digest((p/'attempt-b/result.json').read_bytes()),'report_digest':digest((p/'replay-diff.json').read_bytes()),'run':r['id'],'scope':'synthetic-execution-only','selected_epoch':10}))
local=ROOT/'.browser-test.json'
if not local.exists():
    credentials={'name':'local-proof-reviewer','password':secrets.token_urlsafe(32),'workspace':r['workspace']}
    create_account(credentials['name'],credentials['password'],r['workspace'],'researcher');local.write_text(json.dumps(credentials))
print(json.dumps({'run':r['id'],'evaluation':str(out),'scope':'synthetic-execution-only','source':'actual retained proof; no new training performed'}))
