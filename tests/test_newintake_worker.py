"""Focused queue-consumer protocol tests; no database or media corpus is read."""
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from fieldwork.newintake_worker import (
    IntakeWorker,
    LeaseLost,
    TenantIntakeStore,
    _spool_archive,
)
from fieldwork.container_decoder import DecoderUnavailable


def _row():
    return {
        'workspace': str(uuid.uuid4()), 'intake_id': uuid.uuid4(), 'actor': 'researcher',
        'rights_dataset_id': str(uuid.uuid4()), 'archive_path': 'unused until replay',
        'archive_sha256': 'a' * 64, 'archive_bytes': 1, 'lease_owner': 'worker-1', 'lease_fence': 3,
        'attempts': 1,
    }


class _Conn:
    def __init__(self, *, lease=True):
        self.lease = lease
        self.queries = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def execute(self, query, params=None):
        self.queries.append(query)
        if 'SELECT lease_until' in query or 'RETURNING lease_until' in query:
            row = {'lease_until': 'db-clock'} if self.lease else None
            return SimpleNamespace(fetchone=lambda: row)
        return SimpleNamespace(fetchone=lambda: None)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.commit()
        self.close()
        return False


def test_import_transaction_final_fence_runs_before_commit():
    row = _row()
    conn = _Conn()
    callbacks = []
    store = TenantIntakeStore({'connection': {}}, row,
        before_commit=lambda c, r: callbacks.append(r['lease_fence']))
    # Patch the module connection factory without needing an actual PostgreSQL server.
    import fieldwork.newintake_worker as module
    original = module._connect
    module._connect = lambda _authority: conn
    try:
        with store.connect():
            pass
    finally:
        module._connect = original
    assert callbacks == [3]
    assert conn.commits == 1 and conn.rollbacks == 0 and conn.closed
    assert any('pg_advisory_xact_lock' in q for q in conn.queries)
    assert any('UPDATE public.fw_real_intake_queue' in q and 'lease_until>clock_timestamp()' in q for q in conn.queries)


def test_import_transaction_rolls_back_when_final_fence_is_lost():
    row = _row()
    conn = _Conn(lease=False)
    store = TenantIntakeStore({'connection': {}}, row, before_commit=lambda *_: None)
    import fieldwork.newintake_worker as module
    original = module._connect
    module._connect = lambda _authority: conn
    try:
        with pytest.raises(LeaseLost):
            with store.connect():
                pass
    finally:
        module._connect = original
    assert conn.commits == 0 and conn.rollbacks == 1 and conn.closed


def test_heartbeat_never_revives_an_expired_lease():
    row = _row()
    worker = IntakeWorker({'connection': {}, 'rights_registry_path': 'test-registry'},
                          worker_id='worker-1', connect_factory=lambda: _Conn())
    connection = worker.connect_factory()
    worker.connect_factory = lambda: connection
    assert not worker.heartbeat_once(row)
    update = next(query for query in connection.queries if 'SET lease_until=' in query)
    assert 'lease_until>clock_timestamp()' in update
    assert connection.commits == 1


def test_retry_recovers_terminal_source_link_without_reimport(tmp_path):
    row = _row()
    called = []
    worker = IntakeWorker({'upload_root': str(tmp_path), 'spool_root': str(tmp_path),
                            'quarantine_root': str(tmp_path), 'media_root': str(tmp_path),
                            'rights_registry_path': str(tmp_path / 'unused')},
                          worker_id='worker-1', run_import=lambda *_a, **_kw: called.append('import'))
    batch = {'batch_id': uuid.uuid4(), 'state': 'complete', 'report_sha256': 'b' * 64}
    worker._completed_batch = lambda current: batch if current['intake_id'] == row['intake_id'] else None
    published = []
    worker._publish = lambda current, result, **kwargs: published.append((current['intake_id'], result['batch_id'])) or True
    assert worker.process(row) == 'published'
    assert called == []
    assert published == [(row['intake_id'], batch['batch_id'])]


def test_worker_fails_before_import_when_pinned_decoder_is_unavailable(tmp_path, monkeypatch):
    row = _row()
    authority = {'upload_root': str(tmp_path), 'spool_root': str(tmp_path),
                 'quarantine_root': str(tmp_path), 'media_root': str(tmp_path),
                 'rights_registry_path': str(tmp_path / 'unused'),
                 'decoder_image_id': 'sha256:' + 'a' * 64}
    imported = []
    retried = []
    worker = IntakeWorker(authority, worker_id='worker-1',
                          run_import=lambda *_a, **_kw: imported.append(True))
    worker._completed_batch = lambda _row: None
    worker._mark_staging_interrupted = lambda _row: None
    monkeypatch.setattr('fieldwork.newintake_worker._spool_archive', lambda *_a, **_kw: tmp_path / 'archive')

    def unavailable(*_args, **_kwargs):
        raise DecoderUnavailable('DECODER_IMAGE_MISSING')

    monkeypatch.setattr('fieldwork.newintake_worker.ContainerDecoder', unavailable)
    worker._requeue = lambda _row, code: retried.append(code)
    assert worker.process(row) == 'retry'
    assert imported == []
    assert retried == ['DECODER_IMAGE_MISSING']


def test_archive_spool_rechecks_digest_and_path(tmp_path):
    upload = tmp_path / 'upload'
    spool = tmp_path / 'spool'
    upload.mkdir()
    spool.mkdir()
    archive = upload / 'server-name.archive'
    content = b'PK\x05\x06archive bytes'
    archive.write_bytes(content)
    row = _row()
    row.update(archive_path=str(archive), archive_sha256=sha256(content).hexdigest(), archive_bytes=len(content))
    result = _spool_archive(row, upload_root=upload, spool_root=spool)
    assert result.read_bytes() == content
    assert result.name == row['archive_sha256'] + '.archive'

    bad = dict(row, archive_sha256='0' * 64)
    from fieldwork.newintake_worker import IntakeRefused
    with pytest.raises(IntakeRefused, match='ARCHIVE_DIGEST_MISMATCH'):
        _spool_archive(bad, upload_root=upload, spool_root=spool)


def test_migration_has_worker_only_rls_fence_and_source_batch_recovery():
    migration = Path(__file__).parents[1] / 'migrations' / '006_real_data_api.sql'
    sql = migration.read_text(encoding='utf-8')
    assert 'fieldwork_intake_worker' in sql
    assert 'AS RESTRICTIVE FOR ALL TO fieldwork_intake_worker' in sql
    assert 'source_intake_id' in sql
    assert 'fw_intake_one_terminal_batch' in sql
    assert 'FOR SHARE' in sql  # rights and actor authority stay locked through commit
    assert "NEW.lease_fence<>OLD.lease_fence+1" in sql
