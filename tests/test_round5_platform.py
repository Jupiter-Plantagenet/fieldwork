"""Round-5 platform fixes: restore generation (F1), GC vs publish (F2), operator slot
recovery (F6), shared host lock (F6), durable rename (F8), ML-Start / ML-Fail, receipts."""
import errno, json, os, subprocess, sys, uuid
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'


def metrics(meta):
    return {k: meta[k] for k in ['epoch', 'train_loss', 'validation_loss', 'updates']}


def submitted(s, ws='p5-' + uuid.uuid4().hex[:6]):
    meta = json.loads((SOURCE / 'state.json').read_text())
    return s.submit(ws, 'alice', str(uuid.uuid4()), {'epochs': 1, 'dataset_digest': meta['dataset_digest']}), meta


def test_restore_fence_refuses_a_worker_from_the_lost_lineage(isolated_store, tmp_path):
    """Probe P1 scenario as a product test: backup while queued, old worker claims after the
    backup, restore + Store.restore_fence, new worker claims. Old worker is refused."""
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from fieldwork.store import Store, Conflict
    A = isolated_store; A.blob_root = tmp_path / 'a'
    r, meta = submitted(A)
    params = conninfo_to_dict(A.dsn); b_name = params['dbname'] + '_b'
    with psycopg.connect(make_conninfo(**dict(params, dbname='postgres')), autocommit=True) as c:
        c.execute(sql.SQL('CREATE DATABASE {} TEMPLATE {}').format(sql.Identifier(b_name), sql.Identifier(params['dbname'])))
    try:
        old = A.claim(r['id'])
        B = Store(dsn=make_conninfo(**dict(params, dbname=b_name))); B.blob_root = tmp_path / 'b'
        receipt = B.restore_fence(source='p5-test-template-copy')
        assert receipt['fence_floor'] >= 1_000_000 and receipt['previous_restore_generation'] != receipt['restore_generation']
        new = B.claim(r['id'])
        assert new['fence'] > receipt['fence_floor'] > old['fence'] and new['restore_generation'] != old['restore_generation']
        for call in [lambda: B.heartbeat(r['id'], old['fence'], 0, attempt=old['attempt'], restore_generation=old['restore_generation']),
                     lambda: B.heartbeat(r['id'], old['fence'], 0, attempt=old['attempt']),
                     lambda: B.heartbeat(r['id'], new['fence'], 0, attempt=old['attempt']),
                     lambda: B.publish(r['id'], old['fence'], 0, SOURCE, metrics(meta), attempt=old['attempt']),
                     lambda: B.complete(r['id'], old['fence'], 0, {}, attempt=old['attempt'])]:
            with pytest.raises(Conflict):
                call()
        with B.connect() as c:
            assert c.execute('SELECT count(*) n FROM fw_checkpoints WHERE run=%s', (r['id'],)).fetchone()['n'] == 0
        B.heartbeat(r['id'], new['fence'], 0, attempt=new['attempt'], restore_generation=new['restore_generation'])
    finally:
        with psycopg.connect(make_conninfo(**dict(params, dbname='postgres')), autocommit=True) as c:
            c.execute(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(sql.Identifier(b_name)))


def test_restore_fence_interrupts_live_runs_and_clears_slot(isolated_store):
    s = isolated_store
    r, _ = submitted(s); a = s.claim(r['id'])
    out = s.restore_fence()
    run = s.get(r['id'])
    assert run['state'] == 'interrupted' and run['fence'] == out['fence_floor'] and out['slot_cleared_run'] == r['id']
    with s.connect() as c:
        assert c.execute('SELECT run FROM fw_slot WHERE id=1').fetchone()['run'] is None
        assert c.execute("SELECT kind FROM fw_events WHERE run=%s ORDER BY seq DESC LIMIT 1", (r['id'],)).fetchone()['kind'] == 'restore_fenced'


def test_ml_start_is_separate_and_ml_fail_is_fenced(isolated_store):
    from fieldwork.store import Conflict
    s = isolated_store
    r, _ = submitted(s)
    a = s.claim(r['id'], start=False)
    assert s.get(r['id'])['state'] == 'leased'
    with pytest.raises(Conflict, match='FENCED'):
        s.start(r['id'], str(uuid.uuid4()), a['fence'], 0, a['digest'])
    with pytest.raises(Conflict, match='FENCED'):
        s.start(r['id'], a['attempt'], a['fence'], 0, 'f' * 64)
    with pytest.raises(Conflict, match='FENCED_OR_EXPIRED'):  # no heartbeat before ML-Start
        s.heartbeat(r['id'], a['fence'], 0, attempt=a['attempt'])
    key = str(uuid.uuid4())
    assert s.start(r['id'], a['attempt'], a['fence'], 0, a['digest'], key=key)['state'] == 'running'
    assert s.start(r['id'], a['attempt'], a['fence'], 0, a['digest'], key=key)['state'] == 'running'  # replay
    with pytest.raises(Conflict, match='IDEMPOTENCY_CONFLICT'):
        s.start(r['id'], a['attempt'], a['fence'], 0, 'e' * 64, key=key)
    with pytest.raises(Conflict, match='FENCED'):
        s.fail(r['id'], a['attempt'], a['fence'] + 7, 'WORKER_FAILED', False, '0' * 64)
    assert s.fail(r['id'], a['attempt'], a['fence'], 'WORKER_FAILED', True, '0' * 64)['state'] == 'interrupted'
    assert s.get(r['id'])['state'] == 'interrupted'


def test_leased_run_cancel_requested_and_expiry(isolated_store):
    s = isolated_store
    r, _ = submitted(s); a = s.claim(r['id'], start=False)
    assert s.cancel(s.get(r['id'])['workspace'], r['id']) == 'cancel_requested'
    r2, _ = submitted(s)
    s.release_slot(r['id'], fence=a['fence'])
    b = s.claim(r2['id'], start=False)
    with s.connect() as c:
        c.execute("UPDATE fw_runs SET lease=now()-interval '1 second' WHERE id=%s", (r2['id'],))
    s.expire(r2['id'])
    assert s.get(r2['id'])['state'] == 'interrupted'


def test_cancel_ack_records_exit_receipt_digest(isolated_store):
    s = isolated_store
    r, _ = submitted(s); a = s.claim(r['id'])
    s.cancel(s.get(r['id'])['workspace'], r['id'])
    receipt = {'attempt': a['attempt'], 'fence': a['fence'], 'child_pid': None, 'child_returncode': -9}
    assert s.acknowledge_cancel(r['id'], a['fence'], 1, exit_receipt=receipt, key=str(uuid.uuid4())) == 'cancelled'
    with s.connect() as c:
        stored = c.execute('SELECT exit_receipt_digest FROM fw_attempts WHERE id=%s', (a['attempt'],)).fetchone()['exit_receipt_digest']
        ev = c.execute("SELECT payload FROM fw_events WHERE run=%s AND kind='cancelled'", (r['id'],)).fetchone()['payload']
    assert stored == s.exit_receipt_digest(receipt) == ev['exit_receipt_digest'] and len(stored) == 64


def test_cancel_of_requested_cancel_is_idempotent_with_stale_revision(isolated_store):
    s = isolated_store
    r, _ = submitted(s); s.claim(r['id']); ws = s.get(r['id'])['workspace']
    rev = s.get(r['id'])['revision']
    assert s.cancel_command(ws, 'alice', str(uuid.uuid4()), r['id'], rev, 'stop')[0] == 200
    status, body = s.cancel_command(ws, 'alice', str(uuid.uuid4()), r['id'], rev, 'stop again')  # stale revision
    assert status == 200 and json.loads(body)['state'] == 'cancel_requested' and s.get(r['id'])['cancel_generation'] == 1


def test_gc_after_read_before_insert_rolls_back_the_pointer(isolated_store, tmp_path, monkeypatch):
    """Probe P2 interleaving B: GC removes the reused blob after publish read state.json but
    before its INSERT; the in-transaction re-validation refuses and nothing is committed."""
    import shutil
    from fieldwork import store as store_module
    s = isolated_store; s.blob_root = tmp_path / 'blobs'
    r, meta = submitted(s); a = s.claim(r['id'])
    from fieldwork.checkpoint_store import promote
    target, md = promote(SOURCE, s.blob_root)
    real_live = s.live
    def live_then_gc(*args, **kw):
        row = real_live(*args, **kw)  # publish's locked fence check passed; GC now removes the blob
        if target.exists():
            for p in target.rglob('*'): p.chmod(0o666)
            shutil.rmtree(target)
        return row
    monkeypatch.setattr(s, 'live', live_then_gc)
    with pytest.raises((FileNotFoundError, ValueError, OSError)):
        s.publish(r['id'], a['fence'], 0, SOURCE, metrics(meta), attempt=a['attempt'])
    with s.connect() as c:
        assert c.execute('SELECT count(*) n FROM fw_checkpoints WHERE run=%s', (r['id'],)).fetchone()['n'] == 0


def test_promote_reuse_refreshes_mtime(tmp_path):
    from fieldwork.checkpoint_store import promote
    target, _ = promote(SOURCE, tmp_path)
    os.utime(target, (1, 1))
    promote(SOURCE, tmp_path)
    assert target.stat().st_mtime > 1_000_000


def test_operator_slot_release_requires_proof(isolated_store):
    s = isolated_store
    r, _ = submitted(s); a = s.claim(r['id'])
    dead = subprocess.Popen([sys.executable, '-c', 'pass']); dead.wait()
    import psutil
    with s.connect() as c:
        c.execute('UPDATE fw_slot SET launching=true,owner_pid=%s,owner_created=%s WHERE id=1', (os.getpid(), psutil.Process().create_time()))
    assert s.operator_release_slot('p5', lambda run: [])['reason'] == 'OWNER_ALIVE'
    with s.connect() as c:
        c.execute('UPDATE fw_slot SET owner_pid=%s,owner_created=%s WHERE id=1', (dead.pid, 12345.0))
    assert s.operator_release_slot('p5')['reason'] == 'CHILD_EXIT_UNPROVEN'
    assert s.operator_release_slot('p5', lambda run: [{'pid': 1}])['reason'] == 'CANDIDATE_CHILD_ALIVE'
    out = s.operator_release_slot('p5', lambda run: [])
    assert out['released'] and out['proof']['child'] == 'NO_PROCESS_NAMES_RUN_DIRECTORY'
    with s.connect() as c:
        c.execute('UPDATE fw_slot SET run=%s,fence=1,owner_pid=NULL,owner_created=NULL WHERE id=1', (r['id'],))
    assert s.operator_release_slot('p5', lambda run: [])['reason'] == 'OWNER_IDENTITY_UNKNOWN'


def _product_lock():
    import importlib.util
    spec = importlib.util.spec_from_file_location('pl', next(p / 'tools/product_lock.py' for p in ROOT.parents if (p / 'tools/product_lock.py').exists())); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def test_shared_host_lock_recovers_only_proven_dead_owner(tmp_path):
    pl = _product_lock(); lock = tmp_path / 'host.lock'
    assert pl.acquire('fieldwork', 'p5 test', lock) and not pl.acquire('fieldwork', 'second', lock)
    rec = pl.read_owner(lock)
    assert rec['pid'] == os.getpid() and rec['create_time'] and rec['product'] == 'fieldwork'
    assert pl.recover(lock)['reason'] == 'OWNER_ALIVE' and lock.exists()
    assert pl.release(lock) and not lock.exists()
    # crashed owner: record names a process that is gone
    child = subprocess.Popen([sys.executable, '-c', 'import time'], stdout=subprocess.PIPE); child.wait()
    lock.mkdir(); (lock / 'owner.json').write_text(json.dumps({'pid': child.pid, 'create_time': 1.0, 'product': 'x', 'purpose': 'y'}))
    out = pl.recover(lock)
    assert out['recovered'] and not lock.exists() and Path(out['audit']).exists()
    # legacy/partial record without creation time: refused, never removed
    lock.mkdir(); (lock / 'owner.json').write_text(json.dumps({'pid': child.pid}))
    assert pl.recover(lock)['reason'] == 'OWNER_IDENTITY_INCOMPLETE' and lock.exists()
    (lock / 'owner.json').unlink(); lock.rmdir()
    lock.mkdir()  # crash between mkdir and owner record
    assert pl.recover(lock)['reason'] == 'OWNER_RECORD_MISSING_OR_UNREADABLE' and lock.exists()


def test_durable_rename_retries_windows_sharing_violation(tmp_path):
    from fieldwork.fsops import durable_rename
    src = tmp_path / 'stage'; src.mkdir(); dst = tmp_path / 'final'; calls = []
    def flaky(a, b):
        calls.append(1)
        if len(calls) < 3: raise PermissionError(13, 'in use')
        os.rename(a, b)
    durable_rename(src, dst, rename=flaky, sleep=lambda _: None)
    assert dst.exists() and len(calls) == 3
    other = tmp_path / 'other'; other.mkdir()
    with pytest.raises(FileExistsError):
        durable_rename(other, dst, rename=lambda a, b: (_ for _ in ()).throw(OSError(errno.ENOTEMPTY, 'not empty')))
    with pytest.raises(PermissionError):
        durable_rename(other, tmp_path / 'never', attempts=2, rename=lambda a, b: (_ for _ in ()).throw(PermissionError(13, 'x')), sleep=lambda _: None)


def test_child_checkpoint_publishes_by_rename_never_partial(tmp_path, monkeypatch):
    """ml.checkpoint stages in a sibling and publishes with durable_rename; the final
    directory only ever appears complete (torch-free: the tensor writer is stubbed)."""
    import psutil
    if psutil.virtual_memory().available < 1024**3:
        pytest.skip('importing torch needs >=1 GiB available RAM on this host')
    torch = pytest.importorskip('torch')
    from fieldwork import ml
    seen = []
    def fake_write(path, *args):
        (path / 'manifest.json').write_text('{}'); seen.append((tmp_path / 'epoch-1').exists()); return 'ok'
    monkeypatch.setattr(ml, '_write_checkpoint', fake_write)
    assert ml.checkpoint(tmp_path / 'epoch-1', None, None, None, {}) == 'ok'
    assert seen == [False] and (tmp_path / 'epoch-1/manifest.json').exists()
    assert not list(tmp_path.glob('.staging-*'))
    with pytest.raises(FileExistsError):
        ml.checkpoint(tmp_path / 'epoch-1', None, None, None, {})
