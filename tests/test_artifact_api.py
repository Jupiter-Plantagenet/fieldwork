from tests.isolated_api import use_isolated_api
import json
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb
import fieldwork.api as api
from fieldwork.data import canonical,digest
from tests.test_annotations import account
from tests.test_postfix_evidence import accepted_fixture


def test_verified_artifact_read_rejects_manifest_changed_since_controller_attestation(isolated_store,monkeypatch,tmp_path):
    use_isolated_api(isolated_store,monkeypatch);monkeypatch.setattr(api,'RUNS',tmp_path)
    api.create_account('artifact-reader','fixture-password','artifact-test','viewer')
    r,root=accepted_fixture(isolated_store,tmp_path,'artifact-test');folder=root/'bundle'
    original=(folder/'manifest.json').read_bytes()
    with TestClient(api.app) as c:
        account(c,'artifact-reader','fixture-password');base='/api/v1/workspaces/artifact-test/runs/'+r['id']+'/artifacts'
        good=c.get(base);assert good.status_code==200 and good.json()['artifact_status']=='verified'
        (folder/'manifest.json').write_bytes(canonical({'schema':1,'test_only':'replaced after controller attestation'}))
        assert c.get(base).status_code==409
        (folder/'manifest.json').write_bytes(original)
        forged={'test_only':'replaced receipt'};forged['output_digest']=digest(canonical(forged));(folder.parent/'fresh-process.json').write_bytes(canonical(forged))
        assert c.get(base).status_code==409
