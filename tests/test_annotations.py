from tests.isolated_api import use_isolated_api
import uuid
from fastapi.testclient import TestClient
import fieldwork.api as api


def account(client,name,password):
    r=client.post('/auth/session',json={'name':name,'password':password});assert r.status_code==200
    return {'Origin':'http://127.0.0.1:5102','X-CSRF-Token':r.json()['csrf']}


def test_freeze_requires_independent_digest_review_and_keeps_parent_immutable(isolated_store,monkeypatch):
    use_isolated_api(isolated_store,monkeypatch)
    pw=uuid.uuid4().hex
    api.create_account('author',pw,'annotations','owner');api.create_account('reviewer',pw,'annotations','reviewer')
    base='/api/v1/workspaces/annotations'
    with TestClient(api.app) as c:
        author=account(c,'author',pw)
        r=c.post(base+'/versions',json={},headers=author);assert r.status_code==201,r.text
        draft=r.json();vid=draft['id'];parent=draft['parent_digest']
        proposal=c.post(base+f'/versions/{vid}/proposals',json={'sample_id':'SYN-0-0','label':1,'reason':'Verified correction for workflow regression.'},headers={**author,'If-Match':str(draft['revision'])})
        assert proposal.status_code==201,proposal.text
        p=proposal.json()
        assert c.post(base+f'/versions/{vid}/freeze',json={},headers={**author,'If-Match':str(p['revision'])}).status_code==422
        assert c.post(base+f'/versions/{vid}/proposals',json={'sample_id':'SYN-0-1','label':1,'reason':'Stale revision must preserve local work.'},headers={**author,'If-Match':'1'}).status_code==412
        assert c.post(base+f'/proposals/{p["id"]}/review',json={'digest':p['digest'],'approve':True,'reason':'Self review is not independent.'},headers=author).status_code==403
        reviewer=account(c,'reviewer',pw)
        result=c.post(base+f'/proposals/{p["id"]}/review',json={'digest':p['digest'],'approve':True,'reason':'Independently checked regression fixture.'},headers=reviewer)
        assert result.status_code==200,result.text
        current=c.get(base+f'/versions/{vid}').json()
        reviewed=c.post(base+f'/versions/{vid}/review',json={'digest':current['digest'],'reason':'Reviewed complete exact child version.'},headers={**reviewer,'If-Match':str(current['revision'])})
        assert reviewed.status_code==200,reviewed.text
        author=account(c,'author',pw)
        result=c.post(base+f'/versions/{vid}/freeze',json={},headers={**author,'If-Match':str(reviewed.json()['revision'])})
        assert result.status_code==200,result.text
        frozen=result.json();assert frozen['state']=='frozen' and frozen['parent_digest']==parent
        assert frozen['manifest']['samples'][0]['label']==1
        assert frozen['manifest']['digest']!=parent
        assert c.post(base+f'/versions/{vid}/proposals',json={'sample_id':'SYN-0-0','label':2,'reason':'Cannot edit an immutable child snapshot.'},headers={**author,'If-Match':str(frozen['revision'])}).status_code==409
        assert c.get(base+f'/versions/{vid}').json()['digest']==frozen['digest']
        from fieldwork.data import generate
        assert generate(api.DATA)['digest']==parent
        other=c.get('/api/v1/workspaces/not-annotations'+f'/versions/{vid}')
        assert other.status_code==404
