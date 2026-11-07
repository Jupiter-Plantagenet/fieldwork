from tests.isolated_api import use_isolated_api
import uuid
from fastapi.testclient import TestClient
import fieldwork.api as api


def login(client, name, password):
    r = client.post('/auth/session', json={'name': name, 'password': password})
    assert r.status_code == 200
    return {'Origin': 'http://127.0.0.1:5102', 'X-CSRF-Token': r.json()['csrf']}


def test_versions_list_cache_is_never_stale_and_stays_no_store(isolated_store, monkeypatch):
    use_isolated_api(isolated_store, monkeypatch)
    pw = uuid.uuid4().hex
    api.create_account('author', pw, 'vcache', 'owner')
    api.create_account('reviewer', pw, 'vcache', 'reviewer')
    base = '/api/v1/workspaces/vcache'
    api._VERSIONS_CACHE.clear()
    with TestClient(api.app) as c:
        author = login(c, 'author', pw)
        first = c.get(base + '/versions')
        assert first.status_code == 200 and first.json() == {'items': []}
        assert first.headers['cache-control'] == 'no-store' and 'etag' not in first.headers

        draft = c.post(base + '/versions', json={}, headers=author).json()
        listed = c.get(base + '/versions')
        assert [v['id'] for v in listed.json()['items']] == [draft['id']]
        # the cached body is byte-identical to a fresh uncached serialization and to the second hit
        assert c.get(base + '/versions').content == listed.content
        api._VERSIONS_CACHE.clear()
        assert c.get(base + '/versions').content == listed.content

        proposal = c.post(base + f'/versions/{draft["id"]}/proposals', headers={**author, 'If-Match': str(draft['revision'])},
                          json={'sample_id': 'SYN-0-0', 'label': 1, 'reason': 'Verified correction for cache regression.'}).json()
        after = c.get(base + '/versions')
        assert len(after.json()['items'][0]['proposals']) == 1
        reviewer = login(c, 'reviewer', pw)
        assert c.post(base + f'/proposals/{proposal["id"]}/review', headers=reviewer,
                      json={'digest': proposal['digest'], 'approve': True, 'reason': 'Independently checked fixture.'}).status_code == 200
        reviewed = c.get(base + '/versions')
        assert reviewed.json()['items'][0]['proposals'][0]['decision'] is not None
        assert reviewed.json()['items'][0]['revision'] > after.json()['items'][0]['revision']


def test_versions_cache_is_not_served_across_workspaces(isolated_store, monkeypatch):
    use_isolated_api(isolated_store, monkeypatch)
    pw = uuid.uuid4().hex
    api.create_account('a-owner', pw, 'vcache-a', 'owner')
    api.create_account('b-owner', pw, 'vcache-b', 'owner')
    api._VERSIONS_CACHE.clear()
    with TestClient(api.app) as c:
        a = login(c, 'a-owner', pw)
        draft = c.post('/api/v1/workspaces/vcache-a/versions', json={}, headers=a).json()
        assert [v['id'] for v in c.get('/api/v1/workspaces/vcache-a/versions').json()['items']] == [draft['id']]
        login(c, 'b-owner', pw)
        assert c.get('/api/v1/workspaces/vcache-a/versions').status_code == 404
        assert c.get('/api/v1/workspaces/vcache-b/versions').json() == {'items': []}
