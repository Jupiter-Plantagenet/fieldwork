import uuid
from fastapi.testclient import TestClient


def test_auth_csrf_role_tenant_and_candidate_release_denials():
    from fieldwork.api import app, create_account
    name='test-'+str(uuid.uuid4());password=str(uuid.uuid4())
    create_account(name,password,'test-workspace','researcher')
    viewer=name+'v';create_account(viewer,password,'other-workspace','viewer')
    with TestClient(app) as c:
        base='/api/v1/workspaces/test-workspace'
        assert c.get(base+'/snapshot').status_code==401
        assert c.post('/auth/session',json={'name':name,'password':'wrong'}).status_code==401
        login=c.post('/auth/session',json={'name':name,'password':password});assert login.status_code==200
        token=login.json()['csrf'];headers={'X-CSRF-Token':token,'Origin':'http://127.0.0.1:5102','Idempotency-Key':str(uuid.uuid4())}
        assert c.get('/api/v1/workspaces/other-workspace/snapshot').status_code==404
        assert c.post(base+'/runs',json={'epochs':1}).status_code==403
        assert c.post(base+'/runs',json={'epochs':1},headers={**headers,'Origin':'https://evil.invalid'}).status_code==403
        a=c.post(base+'/runs',json={'epochs':1},headers=headers)
        assert a.status_code in (202,423)
        if a.status_code==202:
            b=c.post(base+'/runs',json={'epochs':1},headers=headers);assert a.json()['id']==b.json()['id']
            assert c.post(base+'/runs',json={'epochs':2},headers=headers).status_code==409
        else:
            assert a.json()['detail']=='RESOURCE_PREFLIGHT'
            print('Actual API submission blocked by measured resource gate; queue idempotency exercised independently in PostgreSQL store test.')
        assert c.post(base+'/inferences',json={'bundle_id':'candidate'},headers=headers).status_code==403
        assert c.get(base+'/bundles/candidate/download').status_code==403
        assert c.get(base+'/samples/SYN-0-8/media').status_code==403
        assert c.post(base+'/runs',json={'epochs':1,'role':'owner'},headers=headers).status_code==422
        c.post('/auth/session',json={'name':viewer,'password':password})
        assert c.post('/api/v1/workspaces/other-workspace/runs',json={'epochs':1},headers={**headers,'X-CSRF-Token':c.get('/auth/session').json()['csrf']}).status_code==403
