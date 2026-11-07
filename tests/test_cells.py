from tests.isolated_api import use_isolated_api
import json
from fastapi.testclient import TestClient


def test_accepted_fixture_export_and_all_paginated_cells_match_oracle(isolated_store,monkeypatch,tmp_path):
    from fieldwork.api import app
    from fieldwork.store import ROOT
    from fieldwork.data import canonical,digest
    from tools.verify_metrics import verify
    import fieldwork.api as api
    from tests.test_annotations import account
    from tests.test_postfix_evidence import accepted_fixture
    use_isolated_api(isolated_store,monkeypatch);monkeypatch.setattr(api,'RUNS',tmp_path)
    r,_=accepted_fixture(isolated_store,tmp_path,'cell-fixture')
    api.create_account('cell-reader','fixture-password','cell-fixture','viewer')
    with TestClient(app) as c:
        account(c,'cell-reader','fixture-password')
        base='/api/v1/workspaces/cell-fixture/runs/'+r['id']
        response=c.get(base+'/records');assert response.status_code==200
        rows=[json.loads(line) for line in response.text.splitlines()];ev=c.get(base+'/evaluation').json()
        oracle=verify(ev['population'],rows,5,rows[0]['model'])
        for actual in range(5):
            for predicted in range(5):
                ids=[];offset=0
                while True:
                    page=c.get(base+f'/slices?actual={actual}&predicted={predicted}&offset={offset}&limit=1').json()
                    ids.extend(page['sample_ids'])
                    if page['next_offset'] is None:break
                    offset=page['next_offset']
                assert ids==oracle['cells'][f'{actual}:{predicted}']
                assert len(ids)==page['total'] and len(ids)==len(set(ids))
                assert page['membership_digest']==digest(canonical(ids))
        assert c.get(base+'/slices?actual=5').status_code==422
        assert c.get(base.replace('cell-fixture','other')+'/records').status_code==404
