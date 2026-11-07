from tests.isolated_api import use_isolated_api
import json
from pathlib import Path
from fastapi.testclient import TestClient
import fieldwork.api as api
from fieldwork.metrics import evaluate
from fieldwork.data import canonical,digest
from tests.test_annotations import account


def test_missing_bucket_exact_pages_and_cursor_binds_predicate(isolated_store,monkeypatch,tmp_path):
    use_isolated_api(isolated_store,monkeypatch);monkeypatch.setattr(api,'RUNS',tmp_path)
    api.create_account('reader','test-password-fixture','missing-cells','researcher')
    from tests.test_postfix_evidence import accepted_fixture
    from psycopg.types.json import Jsonb
    r,root=accepted_fixture(isolated_store,tmp_path,'missing-cells');folder=root/'bundle/evaluation'
    reference=json.loads((folder/'predictions.jsonl').read_text().splitlines()[0])
    population=[{'id':str(i),'label':0,'sha256':digest(str(i).encode())} for i in range(3)]+[{k:reference[k] for k in ('id','label','sha256')}]
    rows=[dict(p,model=reference['model'],status='missing') for p in population[:3]]+[reference]
    metrics=evaluate(population,rows,5,reference['model'])
    for name,value in [('metrics',metrics),('population',population),('independent-report',metrics)]:
        (folder/(name+'.json')).write_bytes(canonical(value))
    (folder/'predictions.jsonl').write_bytes(b''.join(canonical(row)+b'\n' for row in rows))
    # Explicit controller identity for a pagination fixture, not a new trained model.
    manifest_path=root/'bundle/manifest.json';manifest=json.loads(manifest_path.read_bytes())
    for name in manifest['files']:
        raw=(root/'bundle'/name).read_bytes();manifest['files'][name]={'bytes':len(raw),'sha256':digest(raw)}
    manifest_path.write_bytes(canonical(manifest));receipt=json.loads((root/'fresh-process.json').read_bytes())
    receipt['bundle_digest']=digest(canonical(manifest));receipt['output_digest']=digest(canonical({k:v for k,v in receipt.items() if k!='output_digest'}));(root/'fresh-process.json').write_bytes(canonical(receipt))
    with isolated_store.connect() as db:db.execute('UPDATE fw_runs SET artifact_result=%s WHERE id=%s',(Jsonb({k:receipt[k] for k in ('bundle_digest','model_digest','process_identity')}|{'receipt_digest':receipt['output_digest']}),r['id']))
    base='/api/v1/workspaces/missing-cells/runs/'+r['id']
    with TestClient(api.app) as c:
        account(c,'reader','test-password-fixture')
        page=c.get(base+'/slices?bucket=missing&actual=0&limit=1').json()
        assert page['total']==3
        assert page['sample_ids']==['0'];assert page['next_cursor']
        cursor=page['next_cursor']
        assert c.get(base+'/slices',params={'bucket':'missing','actual':1,'limit':1,'cursor':cursor}).status_code==409
        assert c.get(base+'/slices',params={'bucket':'missing','actual':0,'limit':1,'cursor':cursor+'bad'}).status_code==409
        ids=page['sample_ids']
        while page['next_cursor']:
            page=c.get(base+'/slices',params={'bucket':'missing','actual':0,'limit':1,'cursor':page['next_cursor']}).json()
            ids+=page['sample_ids']
        assert ids==['0','1','2'] and page['membership_digest']==digest(canonical(ids))
