"""FW-02 residual: HTTP reads of copied historical evidence, real isolated PG."""
from tests.isolated_api import use_isolated_api
import json,shutil
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb
import fieldwork.api as api
from fieldwork.store import ROOT
from fieldwork.data import canonical,digest
from tests.test_annotations import account


def accepted_fixture(s,tmp_path,workspace='post-api'):
    folder=tmp_path/'fixture-placeholder'
    lineage=json.loads((ROOT/'evidence/internal-candidate/lineage.json').read_bytes())
    r=s.submit(workspace,'fixture','one',{'epochs':1,'dataset_digest':lineage['dataset_digest'],'scope':'synthetic-execution-only'})
    a=s.claim(r['id']);folder=tmp_path/r['id'];shutil.copytree(ROOT/'evidence/internal-candidate',folder/'bundle')
    receipt=json.loads((ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/fresh-process.json').read_bytes())
    (folder/'fresh-process.json').write_bytes(canonical(receipt))
    with s.connect() as c:
        c.execute('INSERT INTO fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES(%s,1,%s,%s,%s,%s)',(r['id'],a['attempt'],lineage['checkpoint_digest'],'retained-test-fixture',Jsonb({})))
        c.execute("UPDATE fw_runs SET state='succeeded',epoch=1,result=%s,artifact_status='verified',artifact_result=%s WHERE id=%s",(Jsonb({'best':{'epoch':1}}),Jsonb({'bundle_digest':digest((folder/'bundle/manifest.json').read_bytes()),'receipt_digest':receipt['output_digest'],'model_digest':receipt['model_digest'],'process_identity':receipt['process_identity']}),r['id']))
    s.release_slot(r['id'])
    return r,folder


@pytest.mark.parametrize('payload',['metrics','predictions','receipt','lineage','unverified'])
def test_all_http_evidence_reads_fail_closed_on_payload_only_tamper(isolated_store,monkeypatch,tmp_path,payload):
    s=isolated_store;use_isolated_api(s,monkeypatch);monkeypatch.setattr(api,'RUNS',tmp_path)
    r,folder=accepted_fixture(s,tmp_path)
    api.create_account('post-reader','fixture-password','post-api','viewer')
    base='/api/v1/workspaces/post-api/runs/'+r['id']
    with TestClient(api.app) as c:
        account(c,'post-reader','fixture-password')
        for route in ['evaluation','records','slices','artifacts']:assert c.get(base+'/'+route).status_code==200
        if payload=='metrics':(folder/'bundle/evaluation/metrics.json').write_bytes(canonical({'accuracy':.999999,'cells':{'0:0':['FORGED']}}))
        elif payload=='predictions':(folder/'bundle/evaluation/predictions.jsonl').write_bytes(b'{"FORGED":true}\n')
        elif payload=='lineage':
            with s.connect() as db:db.execute("UPDATE fw_checkpoints SET digest=%s WHERE run=%s",('0'*64,r['id']))
        elif payload=='unverified':
            with s.connect() as db:db.execute("UPDATE fw_runs SET artifact_status='failed' WHERE id=%s",(r['id'],))
        else:
            receipt=json.loads((folder/'fresh-process.json').read_bytes());receipt['process_identity']='00000000-0000-0000-0000-000000000000';receipt['output_digest']=digest(canonical({k:v for k,v in receipt.items() if k!='output_digest'}));(folder/'fresh-process.json').write_bytes(canonical(receipt))
        for route in ['evaluation','records','slices','artifacts']:
            response=c.get(base+'/'+route);assert response.status_code==409,(payload,route,response.text)


def test_records_response_uses_verified_read_once_bytes(isolated_store,monkeypatch,tmp_path):
    s=isolated_store;use_isolated_api(s,monkeypatch);monkeypatch.setattr(api,'RUNS',tmp_path)
    r,folder=accepted_fixture(s,tmp_path);path=folder/'bundle/evaluation/predictions.jsonl';expected=path.read_bytes()
    from fieldwork.store import TENANT
    token=TENANT.set('post-api')  # direct call bypasses the HTTP tenant middleware; RLS needs it
    try:response=api.records('post-api',r['id'],{})
    finally:TENANT.reset(token)
    path.write_bytes(b'FORGED AFTER VERIFICATION')
    assert response.body==expected


def test_standalone_build_requires_explicit_checkpoint_anchor(tmp_path):
    from fieldwork.bundle import build
    with pytest.raises((TypeError,ValueError),match='(expected_checkpoint_digest|trusted.*checkpoint)'):
        build(ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1',ROOT/'var/images',tmp_path/'candidate')


def test_inventory_walk_stops_at_bounded_entry_budget(monkeypatch):
    from fieldwork.evidence_snapshot import snapshot
    from pathlib import Path
    manifest=ROOT/'evidence/internal-candidate/manifest.json';expected=digest(manifest.read_bytes())
    def hostile_walk(self,*args,**kwargs):
        for i in range(65):yield self/('unexpected-'+str(i))
        raise AssertionError('unbounded directory traversal')
    monkeypatch.setattr(Path,'rglob',hostile_walk)
    with pytest.raises(ValueError,match='inventory'):snapshot(manifest.parent,expected)
