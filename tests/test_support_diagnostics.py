import json
from contextlib import contextmanager

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fieldwork import qualified_release
from fieldwork.real_workspace_api import create_router


class DiagnosticStore:
    def __init__(self):
        self.statements = []

    @contextmanager
    def connect(self):
        yield self

    def execute(self, sql, params=()):
        self.statements.append((sql, params))
        if 'FROM fw_workspace_settings' in sql:
            return _Rows([{'retention_days': 45, 'max_concurrent_runs': 3, 'max_epochs': 80}])
        if 'FROM fw_runs' in sql:
            return _Rows([{'state': 'succeeded', 'n': 100_001}, {'state': 'private-state', 'n': 2}])
        if 'FROM fw_versions' in sql:
            return _Rows([{'state': 'frozen', 'n': 4}])
        raise AssertionError(f'unexpected query: {sql}')


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


def _client(monkeypatch, role='viewer', workspace='alpha'):
    monkeypatch.setattr(qualified_release, 'initialize_registry', lambda: None)
    store = DiagnosticStore()
    app = FastAPI()
    app.include_router(create_router(store=store,
        session_dependency=lambda: {'workspace': workspace, 'name': 'private@example.test', 'role': role},
        rights_service=None))
    return TestClient(app), store


def test_redacted_support_export_is_available_to_workspace_read_roles(monkeypatch):
    for role in ('owner', 'researcher', 'reviewer', 'viewer', 'holdout_steward'):
        client, store = _client(monkeypatch, role=role)
        response = client.get('/api/v1/workspaces/alpha/real/support-diagnostics')
        assert response.status_code == 200
        assert response.headers['cache-control'] == 'no-store'
        assert 'attachment; filename="fieldwork-support-diagnostics.json"' in response.headers['content-disposition']
        body = response.json()
        assert body['resource_limits'] == {
            'retention_days': 45, 'max_concurrent_runs': 3, 'max_epochs': 80,
            'aggregate_count_cap': 100_000,
        }
        assert body['workspace_summary']['runs_by_state']['succeeded'] == 100_000
        assert body['workspace_summary']['runs_by_state']['other'] == 2
        assert body['workspace_summary']['counts_capped'] is True
        serialized = json.dumps(body)
        for forbidden in ('private@example.test', 'alpha', 'private-state', 'run-id', 'digest', 'path'):
            assert forbidden not in serialized
        assert all(params == ('alpha',) and 'WHERE workspace=%s' in sql for sql, params in store.statements)


def test_support_export_rejects_a_workspace_outside_the_session_scope(monkeypatch):
    client, store = _client(monkeypatch, role='viewer', workspace='alpha')
    response = client.get('/api/v1/workspaces/beta/real/support-diagnostics')
    assert response.status_code == 404
    assert store.statements == []
