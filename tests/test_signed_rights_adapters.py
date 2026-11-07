"""New application adapter tests. No database, startup, image decode or model run."""
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]


@pytest.fixture
def api_client(monkeypatch):
    from fieldwork.store import Store
    # Never read retained connection settings, connect, run lifespan or migrate.
    monkeypatch.setattr(Store,'__init__',lambda self,*a,**k:None)
    from fieldwork import api
    from fastapi.testclient import TestClient
    from test_signed_rights import fixture_context,WORKSPACE
    repo,registry,facts,sign=fixture_context('model_bundle')
    monkeypatch.setattr(api,'store',repo)
    if hasattr(api,'load_trusted_registry'):monkeypatch.setattr(api,'load_trusted_registry',lambda:registry)
    api.app.dependency_overrides[api.session]=lambda:dict(name='test-author',workspace=WORKSPACE,role='researcher',csrf='test-csrf')
    client=TestClient(api.app)
    yield api,client,repo,registry,facts,sign
    api.app.dependency_overrides.clear()
    client.close()


def test_actual_intake_and_preflight_routes(api_client):
    from test_signed_rights import WORKSPACE,DATASET,MEMBER
    api,client,repo,registry,facts,sign=api_client
    base=f'/api/v1/workspaces/{WORKSPACE}/datasets/{DATASET}'
    response=client.post(base+'/rights/model_bundle',params={'member_id':MEMBER},content=sign(),headers={'origin':'http://127.0.0.1:5102','x-csrf-token':'test-csrf'})
    assert response.status_code==200,response.text
    assert response.json()=={'status':'verified','code':'VERIFIED','use_permitted':False}
    assert client.get(base+'/rights/preflight',params={'purpose':'model_bundle'}).json()['rights_status']=='verified'
    registry.clear()
    result=client.get(base+'/rights/preflight',params={'purpose':'model_bundle'})
    assert result.status_code==403 and result.json()['code']=='UNTRUSTED_REVIEWER'


def test_existing_download_checks_current_model_export_rights(api_client,monkeypatch):
    from test_signed_rights import WORKSPACE,DATASET,MEMBER
    api,client,repo,registry,facts,sign=api_client
    monkeypatch.setattr(repo,'get',lambda bundle,workspace:dict(config={'dataset_id':DATASET,'scope':'real-data'}),raising=False)
    base=f'/api/v1/workspaces/{WORKSPACE}'
    denied=client.get(base+'/bundles/real-run/download')
    assert denied.status_code==403 and denied.json().get('code')=='MISSING_DECISION'
    api.rights_service().intake(WORKSPACE,DATASET,MEMBER,'test-author','model_bundle',sign())
    # Rights alone must not open the independent release gate.
    result=client.get(base+'/bundles/real-run/download')
    assert result.status_code==403 and result.json()['detail']=='QUALIFIED_RELEASE_REQUIRED'
    registry.clear()
    denied=client.get(base+'/bundles/real-run/download')
    assert denied.json()['code']=='UNTRUSTED_REVIEWER'


def test_request_cannot_bypass_csrf_or_workspace(api_client):
    from test_signed_rights import WORKSPACE,DATASET,MEMBER
    api,client,repo,registry,facts,sign=api_client
    url=f'/api/v1/workspaces/{WORKSPACE}/datasets/{DATASET}/rights/model_bundle'
    assert client.post(url,params={'member_id':MEMBER},content=sign()).status_code==403
    assert not repo.decisions
    assert client.get(url.replace(WORKSPACE,DATASET).replace('/model_bundle','/preflight'),params={'purpose':'model_bundle'}).status_code==404


def test_oversized_intake_quarantines_previous_decision(api_client):
    from test_signed_rights import WORKSPACE,DATASET,MEMBER
    api,client,repo,registry,facts,sign=api_client
    api.rights_service().intake(WORKSPACE,DATASET,MEMBER,'test-author','model_bundle',sign())
    url=f'/api/v1/workspaces/{WORKSPACE}/datasets/{DATASET}/rights/model_bundle'
    response=client.post(url,params={'member_id':MEMBER},content=b'x'*16385,headers={'origin':'http://127.0.0.1:5102','x-csrf-token':'test-csrf'})
    assert response.json()['status']=='quarantined'
    assert repo.decisions[MEMBER,'model_bundle']==b''
    assert client.get(url.replace('/model_bundle','/preflight'),params={'purpose':'model_bundle'}).status_code==403


def test_registry_reload_observes_operator_removal(tmp_path,monkeypatch):
    import json
    from fieldwork.rights_registry import load_trusted_registry
    from test_signed_rights import fixture_context,REVIEWER,KEY
    repo,registry,facts,sign=fixture_context();reviewer=registry[REVIEWER,KEY]
    row=dict(reviewer_id=REVIEWER,key_id=KEY,public_key_hex=reviewer.public_key_hex,workspace_ids=list(reviewer.workspace_ids),purposes=list(reviewer.purposes))
    path=tmp_path/'public-reviewers.json';path.write_text(json.dumps(dict(schema=1,reviewers=[row])))
    monkeypatch.setenv('FIELDWORK_RIGHTS_REVIEWERS_FILE',str(path))
    assert load_trusted_registry()==registry
    path.write_text(json.dumps(dict(schema=1,reviewers=[])))
    assert load_trusted_registry()=={}


def test_missing_database_dependency_is_redacted(monkeypatch):
    from contextlib import contextmanager
    from fieldwork.store import Store
    from fieldwork.rights_decision import DecisionRejected
    import psycopg
    store=Store(dsn='unit-test-never-connect')
    @contextmanager
    def unavailable(**kwargs):
        raise psycopg.OperationalError('private connection details must not escape')
        yield
    monkeypatch.setattr(store,'connect',unavailable)
    with pytest.raises(DecisionRejected,match='^RIGHTS_DATABASE_DEPENDENCY$'):
        with store.rights_repository():pass


def test_real_repository_uses_independent_persisted_rows():
    from fieldwork.rights_store import RightsRepository
    class Query:
        def __init__(self):self.calls=[]
        def execute(self,sql,params):self.calls.append((sql,params));return self
        def fetchone(self):
            sql=self.calls[-1][0]
            if 'COUNT(a.member_id)' in sql:return {'member_count':1,'state':'authenticated','actual_count':1}
            if 'fw_accounts' in sql:return {'role':'researcher'}
            if 'fw_rights_datasets' in sql:return {'member_count':1,'state':'authenticated'}
            if 'fw_rights_decisions' in sql:return {'envelope':memoryview(b'persisted-envelope')}
            return {'member_id':'independent-row'}
        def fetchall(self):return [{'member_id':'independent-row'}]
    query=Query();repo=RightsRepository(query)
    assert repo.authorize('workspace','actor','model_bundle')
    assert repo.asset('workspace','dataset','member')=={'member_id':'independent-row'}
    assert repo.members('workspace','dataset')==['independent-row']
    assert repo.authenticated_inventory('workspace','dataset')==1
    count_sql, count_params=query.calls[-1]
    assert 'COUNT(a.member_id)' in count_sql and 'SELECT member_id' not in count_sql
    assert count_params==('workspace','dataset')
    assert repo.decision('workspace','dataset','member','model_bundle')==b'persisted-envelope'
    repo.save('workspace','dataset','member','model_bundle',b'new-envelope','FORMAT')
    assert query.calls[-1][1]==('workspace','dataset','member','model_bundle',b'new-envelope','FORMAT')
    assert 'canonical_license,license_text,source_evidence,attribution,rights_state' in query.calls[1][0]
    assert all('FOR SHARE' not in sql for sql,params in query.calls)


@pytest.mark.parametrize('inventory,code',[
    ({'member_count':1,'state':'pending','actual_count':1},'RIGHTS_QUARANTINED'),
    ({'member_count':2,'state':'authenticated','actual_count':1},'INCOMPLETE_INVENTORY'),
    ({'member_count':0,'state':'authenticated','actual_count':0},'RIGHTS_QUARANTINED'),
])
def test_authenticated_inventory_count_only_fails_closed(inventory,code):
    from fieldwork.rights_store import RightsRepository
    from fieldwork.rights_decision import DecisionRejected
    class Query:
        def execute(self,sql,params):
            assert 'COUNT(a.member_id)' in sql
            assert 'SELECT member_id' not in sql
            return self
        def fetchone(self):return inventory
    with pytest.raises(DecisionRejected,match=code):
        RightsRepository(Query()).authenticated_inventory('workspace','dataset')


def test_rights_snapshot_configured_before_first_tenant_query(monkeypatch):
    import psycopg
    from fieldwork.store import Store,TENANT
    from contextlib import contextmanager
    calls=[]
    class Connection:
        isolation_level=None
        def execute(self,sql,params):
            assert self.isolation_level==psycopg.IsolationLevel.REPEATABLE_READ
            calls.append((sql,params))
    connection=Connection()
    monkeypatch.setattr(psycopg,'connect',lambda *a,**k:connection)
    store=Store(dsn='unit-test-never-connect',request=True)
    token=TENANT.set('literal-workspace')
    try:assert store.connect(isolation_level=psycopg.IsolationLevel.REPEATABLE_READ) is connection
    finally:TENANT.reset(token)
    assert calls==[("SELECT set_config('fieldwork.workspace',%s,true)",('literal-workspace',))]


def test_actual_bundle_build_denies_before_checkpoint_or_output(tmp_path,monkeypatch):
    import json
    from fieldwork import bundle
    from fieldwork.rights_decision import DecisionRejected
    data=tmp_path/'nonphoto-metadata';data.mkdir()
    (data/'manifest.json').write_text(json.dumps({'scope':'real-data'}))
    out=tmp_path/'must-not-create'
    def forbidden(*args,**kwargs):pytest.fail('checkpoint/model work reached before rights admission')
    monkeypatch.setattr(bundle,'validate_checkpoint',forbidden)
    with pytest.raises(DecisionRejected,match='MISSING_TRUST_CONTEXT'):
        bundle.build(tmp_path/'no-checkpoint',data,out,expected_checkpoint_digest='a'*64)
    assert not out.exists()


def test_non_synthetic_data_fails_before_any_file_access():
    from fieldwork.data import verify
    with pytest.raises(ValueError,match='REAL_DATA_RIGHTS_REQUIRED'):
        verify('must-not-read',{'scope':'natural-images'})


def test_unapplied_schema_separates_operator_facts_from_submitted_decisions():
    path=ROOT/'migrations/003_signed_rights.sql'
    assert path.is_file(), 'additive operator-applied rights schema missing'
    sql=path.read_text()
    for table in ('fw_rights_datasets','fw_rights_assets','fw_rights_decisions'):
        assert f'CREATE TABLE {table}' in sql
        assert f'ALTER TABLE {table} FORCE ROW LEVEL SECURITY' in sql
    assert 'GRANT ' not in '\n'.join(line for line in sql.splitlines() if not line.startswith('--'))
    assert 'CREATE ROLE' not in sql


def test_operator_registry_is_not_request_data(tmp_path,monkeypatch):
    import importlib.util
    assert importlib.util.find_spec('fieldwork.rights_registry') is not None
    from fieldwork.rights_registry import load_trusted_registry
    from fieldwork.rights_decision import DecisionRejected
    monkeypatch.delenv('FIELDWORK_RIGHTS_REVIEWERS_FILE',raising=False)
    assert load_trusted_registry()=={}
    path=tmp_path/'public-reviewers.json';path.write_text('{"payload":{"public_key_hex":"injected"}}')
    monkeypatch.setenv('FIELDWORK_RIGHTS_REVIEWERS_FILE',str(path))
    with pytest.raises(DecisionRejected,match='TRUST_REGISTRY'):load_trusted_registry()
