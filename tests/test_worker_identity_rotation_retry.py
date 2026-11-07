from __future__ import annotations

import copy

import psycopg
import pytest

from fieldwork import worker_identity as identity


class PasswordAuthFailure(psycopg.OperationalError):
    @property
    def sqlstate(self):
        return '28P01'


def _authority(password, previous=None):
    value = {
        'authority_mode': identity.MODE,
        'workspaces': ['workspace-a'],
        'connection': {
            'host': '127.0.0.1', 'port': 5542, 'dbname': 'fieldwork',
            'user': 'fw_worker_test', 'password': password, 'sslmode': 'disable',
        },
    }
    if previous is not None:
        value['previous_password'] = previous
    return value


def _store(path, authority):
    path.write_text('authored-private-authority-fixture')
    store = identity.WorkerStore.__new__(identity.WorkerStore)
    store.authority_path = path
    store._authority = copy.deepcopy(authority)
    store._authority_mtime = path.stat().st_mtime_ns
    return store


def test_connect_forces_one_validated_reload_after_stale_rotation_snapshot(monkeypatch, tmp_path, capsys):
    store = _store(tmp_path / 'worker-authority.json', _authority('A', 'Z'))
    refreshed = _authority('B', 'A')
    reloads = []
    monkeypatch.setattr(identity, 'read_authority', lambda path: reloads.append(str(path)) or copy.deepcopy(refreshed))
    attempts = []

    def connect(**kwargs):
        attempts.append(kwargs['password'])
        if kwargs['password'] in {'A', 'Z'}:
            raise psycopg.OperationalError('FATAL: password authentication failed')
        if kwargs['password'] == 'B':
            return object()
        raise AssertionError('unexpected password candidate')

    monkeypatch.setattr(identity.psycopg, 'connect', connect)
    result = store.connect()
    assert result is not None
    assert attempts == ['A', 'Z', 'B']
    assert len(reloads) == 1
    assert store._authority['connection']['password'] == 'B'
    assert capsys.readouterr().out == ''


def test_unchanged_invalid_password_is_bounded_to_two_snapshots(monkeypatch, tmp_path, capsys):
    original = _authority('bad-current', 'bad-previous')
    store = _store(tmp_path / 'worker-authority.json', original)
    reloads = []
    monkeypatch.setattr(identity, 'read_authority', lambda path: reloads.append(str(path)) or copy.deepcopy(original))
    attempts = []

    def connect(**kwargs):
        attempts.append(kwargs['password'])
        raise PasswordAuthFailure('password authentication failed')

    monkeypatch.setattr(identity.psycopg, 'connect', connect)
    with pytest.raises(PasswordAuthFailure):
        store.connect()
    assert attempts == ['bad-current', 'bad-previous', 'bad-current', 'bad-previous']
    assert len(attempts) <= 4 and len(reloads) == 1
    assert capsys.readouterr().out == ''


@pytest.mark.parametrize('message,sqlstate', [
    ('connection timed out', None),
    ('role is not permitted to log in', '28000'),
])
def test_non_password_operational_failure_is_not_retried(monkeypatch, tmp_path, message, sqlstate):
    store = _store(tmp_path / 'worker-authority.json', _authority('A', 'Z'))
    reloads = []
    monkeypatch.setattr(identity, 'read_authority', lambda path: reloads.append(str(path)) or _authority('B', 'A'))
    attempts = []

    class OtherFailure(psycopg.OperationalError):
        def __init__(self, message, state):
            self._state = state
            super().__init__(message)

        @property
        def sqlstate(self):
            return self._state

    def connect(**kwargs):
        attempts.append(kwargs['password'])
        raise OtherFailure(message, sqlstate)

    monkeypatch.setattr(identity.psycopg, 'connect', connect)
    with pytest.raises(OtherFailure):
        store.connect()
    assert attempts == ['A']
    assert reloads == []


def test_auth_failure_refuses_reloaded_scope_or_endpoint_change(monkeypatch, tmp_path):
    store = _store(tmp_path / 'worker-authority.json', _authority('A', 'Z'))
    changed = _authority('B', 'A')
    changed['workspaces'] = ['workspace-a', 'workspace-b']
    monkeypatch.setattr(identity, 'read_authority', lambda path: copy.deepcopy(changed))
    attempts = []

    def connect(**kwargs):
        attempts.append(kwargs['password'])
        raise PasswordAuthFailure('password authentication failed')

    monkeypatch.setattr(identity.psycopg, 'connect', connect)
    with pytest.raises(ValueError, match='WORKER_AUTHORITY_RELOAD_REFUSED'):
        store.connect()
    assert attempts == ['A', 'Z']
