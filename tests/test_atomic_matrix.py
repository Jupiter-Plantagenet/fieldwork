"""ML-T-ATOMIC matrix on current source (complements tests/test_atomic_crash_edges.py, which it does not replace).

Frozen pass condition: no incomplete checkpoint visible as committed; the pointer only references
digest-validated required files; a committed checkpoint survives a restart; orphan GC is safe after 24 h
and checks live references; disk full is injected.

* Process death: a real child process runs the real `Store.publish` against the isolated PostgreSQL and is
  killed with `os._exit` (no cleanup) at one exact edge.
* Disk full: an OSError(ENOSPC) is injected at the OS write/fsync/rename call of the real write path,
  with a byte quota that is exhausted part-way through a file (a tmpfs-like size limit), and PostgreSQL's
  own DiskFull at the INSERT.
* Torn / corrupted committed blobs and tampered sources are refused everywhere a pointer or resume could trust them.
* GC runs in the exact windows before and after the pointer INSERT, with PostgreSQL lock barriers.
"""
import errno
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import psycopg
import pytest

from fieldwork.ml import validate_checkpoint
from fieldwork.store import ROOT, Conflict, Store
from tests.matrix_support import capture, labelled_store, wait_for_database_lock

SOURCE = ROOT / 'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'
META = json.loads((SOURCE / 'state.json').read_text())
METRICS = {k: META[k] for k in ['epoch', 'train_loss', 'validation_loss', 'updates']}
FILES = ['state.safetensors', 'state.json', 'manifest.json']  # promote() write order
W = 'amatrix'


def new_run(s, tmp_path, epochs=1):
    blob = tmp_path / 'blobs'
    s.blob_root = blob
    r = s.submit(W + uuid.uuid4().hex[:6], 'a', str(uuid.uuid4()), {'epochs': epochs, 'dataset_digest': META['dataset_digest']})
    a = s.claim(r['id'])
    return r, a, blob


def publish(s, r, a, source=SOURCE, **kw):
    return s.publish(r['id'], a['fence'], a['cancel_generation'], source, METRICS, attempt=a['attempt'], **kw)


def assert_nothing_committed(s, r, blob, *, state='running'):
    run = s.get(r['id'])
    assert s.checkpoints(r['id']) == [] and run['epoch'] == 0 and run['checkpoint'] is None and run['state'] == state
    assert [e for e in s.events(r['workspace']) if e['kind'] == 'epoch_committed'] == []


def assert_blob_root_clean_or_valid(blob):
    """Every non-staging entry is a complete digest-valid checkpoint; nothing half-written under a final name."""
    for entry in (blob.iterdir() if blob.exists() else []):
        if entry.name.startswith('.staging-'):
            continue
        validate_checkpoint(entry, entry.name)


def assert_pointer_is_validated(s, r, blob):
    run = s.get(r['id'])
    rows = s.checkpoints(r['id'])
    assert [x['epoch'] for x in rows] == [1] and run['epoch'] == 1
    path = Path(run['checkpoint'])
    assert path.parent == blob and path.name == rows[0]['digest']
    validate_checkpoint(path, rows[0]['digest'])
    assert {p.name for p in path.iterdir()} == set(FILES)
    assert len([e for e in s.events(r['workspace']) if e['kind'] == 'epoch_committed']) == 1


# ----------------------------------------------------------- process death edges
HARNESS = r'''
import json, os, sys
from pathlib import Path
args = json.loads(sys.argv[1])
from fieldwork.store import Store
import fieldwork.checkpoint_store as cs
s = Store(dsn=args['dsn']); s.blob_root = Path(args['blob'])
edge = args['edge']
die = lambda: os._exit(77)
if edge in ('second_file_fsync', 'third_file_fsync'):
    real = cs.os.fsync; count = {'n': 0}; target = 2 if edge == 'second_file_fsync' else 3
    def fsync(fd):
        real(fd); count['n'] += 1
        if count['n'] == target: die()
    cs.os.fsync = fsync
elif edge == 'torn_write_first_file':
    Base = type(Path())
    class Torn:
        def __init__(self, f): self.f = f
        def __enter__(self): return self
        def __exit__(self, *a): self.f.close()
        def fileno(self): return self.f.fileno()
        def flush(self): self.f.flush()
        def write(self, data):
            self.f.write(data[:len(data)//2]); self.f.flush(); die()
    class TornPath(Base):
        def open(self, mode='r', *a, **k):
            f = super().open(mode, *a, **k)
            return Torn(f) if mode == 'xb' and self.name == 'state.safetensors' else f
    cs.Path = TornPath
elif edge == 'after_stage_validate_before_rename':
    import fieldwork.ml as ml
    real = ml.validate_checkpoint; count = {'n': 0}
    def validate(*a, **k):
        out = real(*a, **k); count['n'] += 1
        if count['n'] == 2: die()   # 1 = source, 2 = staged copy
        return out
    ml.validate_checkpoint = validate
elif edge == 'after_rename_before_target_validate':
    import fieldwork.fsops as fo
    real = fo.durable_rename
    def durable_rename(source, target, *a, **k):
        out = real(source, target, *a, **k)
        die()
    fo.durable_rename = durable_rename
elif edge == 'after_insert_before_pointer_update':
    import fieldwork.ml as ml
    real = ml.validate_checkpoint; count = {'n': 0}
    def validate(*a, **k):
        count['n'] += 1
        if count['n'] == 4: die()   # 1-3 inside promote; 4 = publish's post-INSERT re-validation, before UPDATE fw_runs
        return real(*a, **k)
    ml.validate_checkpoint = validate
elif edge == 'after_receipt_before_commit':
    real = Store._store_receipt
    def store_receipt(self, c, workspace, actor, command, key, request, body, run=None, status=200):
        real(self, c, workspace, actor, command, key, request, body, run, status)
        if command == 'ML-CheckpointCommit': die()
    Store._store_receipt = store_receipt
s.publish(args['run'], args['fence'], args['generation'], Path(args['source']), args['metrics'],
          attempt=args['attempt'], key=args['key'])
os._exit(0)
'''

NEW_EDGES = ['second_file_fsync', 'third_file_fsync', 'torn_write_first_file', 'after_stage_validate_before_rename',
             'after_rename_before_target_validate', 'after_insert_before_pointer_update', 'after_receipt_before_commit']


@pytest.mark.parametrize('edge', NEW_EDGES)
def test_process_death_at_additional_checkpoint_edges_never_exposes_a_partial_commit(isolated_store, tmp_path, edge):
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    key = str(uuid.uuid4())
    args = {'dsn': s.dsn, 'blob': str(blob), 'edge': edge, 'run': r['id'], 'fence': a['fence'], 'generation': a['cancel_generation'],
            'attempt': a['attempt'], 'source': str(SOURCE), 'metrics': METRICS, 'key': key}
    try:
        child = subprocess.run([sys.executable, '-B', '-c', HARNESS, json.dumps(args)], cwd=ROOT, capture_output=True, text=True, timeout=180)
        assert child.returncode == 77, child.stderr[-2000:]
        assert_nothing_committed(s, r, blob)
        assert_blob_root_clean_or_valid(blob)
        with s.connect() as c:  # the dead connection's receipt, if it was written, rolled back with the transaction
            assert c.execute("SELECT count(*) n FROM fw_command_receipts WHERE run=%s AND command='ML-CheckpointCommit'", (r['id'],)).fetchone()['n'] == 0
        if edge == 'torn_write_first_file':
            staging = [p for p in blob.iterdir() if p.name.startswith('.staging-')]
            assert staging and (staging[0] / 'state.safetensors').stat().st_size < (SOURCE / 'state.safetensors').stat().st_size
            assert [p.name for p in blob.iterdir() if not p.name.startswith('.staging-')] == []  # never under a digest name
        # retry with the SAME idempotency key by the same live attempt commits exactly once, replays are idempotent
        publish(s, r, a, key=key)
        publish(s, r, a, key=key)
        assert_pointer_is_validated(s, r, blob)
    finally:
        s.release_slot(r['id'])


def test_committed_checkpoint_is_readable_by_a_fresh_process_after_the_writer_is_gone(isolated_store, tmp_path):
    """Process-restart survival only. Surviving an OS/volume/power restart is NOT exercised here."""
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    try:
        publish(s, r, a)
        reader = (
            "import json,sys\nfrom pathlib import Path\nfrom fieldwork.store import Store\nfrom fieldwork.ml import validate_checkpoint\n"
            "s=Store(dsn=sys.argv[1]);row=s.get(sys.argv[2]);cp=s.checkpoints(sys.argv[2])\n"
            "validate_checkpoint(row['checkpoint'],cp[0]['digest'])\n"
            "print(json.dumps({'epoch':row['epoch'],'name':Path(row['checkpoint']).name,'digest':cp[0]['digest']}))\n")
        out = subprocess.run([sys.executable, '-B', '-c', reader, s.dsn, r['id']], cwd=ROOT, capture_output=True, text=True, timeout=180)
        assert out.returncode == 0, out.stderr[-1500:]
        got = json.loads(out.stdout.strip().splitlines()[-1])
        assert got['epoch'] == 1 and got['name'] == got['digest']
    finally:
        s.release_slot(r['id'])


# ------------------------------------------------------------------- disk full
class QuotaFile:
    """A file on a volume with a hard byte quota: writes up to the limit, then ENOSPC (like a full tmpfs)."""
    def __init__(self, f, state):
        self.f, self.state = f, state

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.f.close()

    def fileno(self):
        return self.f.fileno()

    def flush(self):
        self.f.flush()

    def write(self, data):
        left = self.state['left']
        if len(data) > left:
            if left:
                self.f.write(data[:left])
            self.f.flush()
            self.state['left'] = 0
            raise OSError(errno.ENOSPC, 'No space left on device (quota injected at the OS write call)')
        self.state['left'] = left - len(data)
        return self.f.write(data)


def quota_path(state):
    import fieldwork.checkpoint_store as cs
    base = type(Path())

    class QuotaPath(base):
        def open(self, mode='r', *a, **k):
            f = super().open(mode, *a, **k)
            return QuotaFile(f, state) if mode == 'xb' else f

    return cs, QuotaPath


SIZES = [(SOURCE / n).stat().st_size for n in FILES]
QUOTAS = {
    'file1_first_byte': 1,
    'file1_half': SIZES[0] // 2,
    'file2_partial': SIZES[0] + SIZES[1] // 2,
    'file3_partial': SIZES[0] + SIZES[1] + SIZES[2] // 2,
    'all_but_one_byte': sum(SIZES) - 1,
}


@pytest.mark.parametrize('where', sorted(QUOTAS))
def test_disk_full_quota_at_os_write_leaves_no_committed_or_visible_checkpoint(isolated_store, tmp_path, monkeypatch, where):
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    try:
        state = {'left': QUOTAS[where]}
        cs, QuotaPath = quota_path(state)
        monkeypatch.setattr(cs, 'Path', QuotaPath)
        with pytest.raises(OSError) as e:
            publish(s, r, a)
        assert e.value.errno == errno.ENOSPC and state['left'] == 0
        assert_nothing_committed(s, r, blob)  # run is still running: the worker can retry; nothing silently spilled
        assert not [p for p in blob.iterdir() if p.name.startswith('.staging-')], 'partial stage must be cleaned up'
        assert [p for p in blob.iterdir()] == [], 'nothing may appear under a final digest name'
        monkeypatch.undo()
        publish(s, r, a)
        assert_pointer_is_validated(s, r, blob)
    finally:
        s.release_slot(r['id'])


@pytest.mark.parametrize('call', [1, 2, 3])
def test_disk_full_at_fsync_of_each_required_file(isolated_store, tmp_path, monkeypatch, call):
    import fieldwork.checkpoint_store as cs
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    try:
        real, count = cs.os.fsync, {'n': 0}

        def fsync(fd):
            count['n'] += 1
            if count['n'] == call:
                raise OSError(errno.ENOSPC, 'No space left on device (injected at fsync)')
            return real(fd)

        monkeypatch.setattr(cs.os, 'fsync', fsync)
        with pytest.raises(OSError) as e:
            publish(s, r, a)
        assert e.value.errno == errno.ENOSPC
        assert_nothing_committed(s, r, blob)
        assert [p for p in blob.iterdir()] == []
        monkeypatch.setattr(cs.os, 'fsync', real)
        publish(s, r, a)
        assert_pointer_is_validated(s, r, blob)
    finally:
        s.release_slot(r['id'])


def test_disk_full_at_the_publishing_rename(isolated_store, tmp_path, monkeypatch):
    import fieldwork.fsops as fo
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    try:
        real = fo.durable_rename

        def full(*args, **kw):
            raise OSError(errno.ENOSPC, 'No space left on device (injected at rename)')

        monkeypatch.setattr(fo, 'durable_rename', full)
        with pytest.raises(OSError):
            publish(s, r, a)
        assert_nothing_committed(s, r, blob)
        assert [p for p in blob.iterdir()] == []
        monkeypatch.setattr(fo, 'durable_rename', real)
        publish(s, r, a)
        assert_pointer_is_validated(s, r, blob)
    finally:
        s.release_slot(r['id'])


def test_database_disk_full_at_the_pointer_transaction_rolls_back_and_orphan_blob_is_inert(isolated_store, tmp_path, monkeypatch):
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    try:
        real = Store.event

        def event(self, c, run, kind, payload):
            if kind == 'epoch_committed':
                raise psycopg.errors.DiskFull('could not extend file: No space left on device (injected)')
            return real(self, c, run, kind, payload)

        monkeypatch.setattr(Store, 'event', event)
        with pytest.raises(psycopg.errors.DiskFull):
            publish(s, r, a)
        assert_nothing_committed(s, r, blob)
        orphans = [p for p in blob.iterdir()]
        assert len(orphans) == 1 and not orphans[0].name.startswith('.staging-')
        validate_checkpoint(orphans[0], orphans[0].name)  # complete and digest-valid, but referenced by nothing
        monkeypatch.setattr(Store, 'event', real)
        publish(s, r, a)
        assert_pointer_is_validated(s, r, blob)
        assert Path(s.get(r['id'])['checkpoint']) == orphans[0]  # the retry reused the validated orphan
    finally:
        s.release_slot(r['id'])


# ------------------------------------------- torn/corrupted blobs and tampered sources
def corrupt_truncate(path):
    p = path / 'state.safetensors'
    p.write_bytes(p.read_bytes()[:-1])


def corrupt_flip(path):
    p = path / 'state.json'
    b = bytearray(p.read_bytes())
    b[len(b) // 2] ^= 1
    p.write_bytes(bytes(b))


def corrupt_delete_manifest(path):
    (path / 'manifest.json').unlink()


def corrupt_extra_file(path):
    (path / 'extra.bin').write_bytes(b'x')


CORRUPTIONS = {'truncated_tensors': corrupt_truncate, 'flipped_state_json_byte': corrupt_flip,
               'deleted_manifest': corrupt_delete_manifest, 'unlisted_extra_file': corrupt_extra_file}


@pytest.mark.parametrize('kind', sorted(CORRUPTIONS))
def test_corrupted_committed_blob_is_never_trusted_for_resume_or_republish(isolated_store, tmp_path, kind):
    s = isolated_store
    r, a, blob = new_run(s, tmp_path, epochs=2)
    try:
        publish(s, r, a)
        run = s.get(r['id'])
        digest_ = s.checkpoints(r['id'])[0]['digest']
        path = Path(run['checkpoint'])
        s.expire_for_test(r['id'])  # lease lapses: interrupted at epoch 1
        assert s.get(r['id'])['state'] == 'interrupted'
        for f in path.iterdir():
            f.chmod(0o666)
        CORRUPTIONS[kind](path)
        with pytest.raises((ValueError, OSError)):
            validate_checkpoint(path, digest_)
        before = s.get(r['id'])
        with pytest.raises((ValueError, OSError)):
            s.resume(run['workspace'], r['id'], 2)  # resume re-validates the pointer's blob: refuses
        after = s.get(r['id'])
        assert after['state'] == 'interrupted' and after['revision'] == before['revision'] and after['checkpoint'] == before['checkpoint']
        from fieldwork.checkpoint_store import promote
        with pytest.raises((ValueError, OSError)):
            promote(SOURCE, blob)  # the same digest name now holds a bad blob: never reused as if valid
    finally:
        s.release_slot(r['id'])


def test_control_healthy_checkpoint_resumes(isolated_store, tmp_path):
    s = isolated_store
    r, a, blob = new_run(s, tmp_path, epochs=2)
    try:
        publish(s, r, a)
        s.expire_for_test(r['id'])
        s.resume(s.get(r['id'])['workspace'], r['id'], 2)
        assert s.get(r['id'])['state'] == 'queued'
    finally:
        s.release_slot(r['id'])


@pytest.mark.parametrize('kind', ['flipped_tensor_byte', 'missing_state_json', 'extra_file', 'tampered_manifest'])
def test_tampered_source_is_refused_before_anything_is_staged_or_pointed_at(isolated_store, tmp_path, kind):
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    bad = tmp_path / 'bad-source'
    shutil.copytree(SOURCE, bad)
    if kind == 'flipped_tensor_byte':
        b = bytearray((bad / 'state.safetensors').read_bytes())
        b[-1] ^= 1
        (bad / 'state.safetensors').write_bytes(bytes(b))
    elif kind == 'missing_state_json':
        (bad / 'state.json').unlink()
    elif kind == 'extra_file':
        (bad / 'note.txt').write_text('x')
    else:
        m = json.loads((bad / 'manifest.json').read_text())
        m['files']['state.json']['sha256'] = '0' * 64
        (bad / 'manifest.json').write_text(json.dumps(m))
    try:
        with pytest.raises((ValueError, OSError)):
            publish(s, r, a, source=bad)
        assert_nothing_committed(s, r, blob)
        assert not blob.exists() or [p for p in blob.iterdir() if not p.name.startswith('.staging-')] == []
    finally:
        s.release_slot(r['id'])


# ----------------------------------------------------------------- orphan GC
def make_orphan(blob, name, age_seconds=0):
    target = blob / name
    shutil.copytree(SOURCE, target)
    t = time.time() - age_seconds
    for f in [target, *target.rglob('*')]:
        os.utime(f, (t, t))
    return target


def test_gc_24h_boundary_live_reference_and_dry_run_default(isolated_store, tmp_path):
    from fieldwork.checkpoint_gc import collect
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    try:
        publish(s, r, a)
    finally:
        s.release_slot(r['id'])
    live = Path(s.get(r['id'])['checkpoint'])
    young = make_orphan(blob, 'a' * 64, 23 * 3600 + 55 * 60)
    old = make_orphan(blob, 'b' * 64, 24 * 3600 + 5 * 60)
    fresh_stage = blob / '.staging-fresh'
    fresh_stage.mkdir()
    (fresh_stage / 'state.json').write_text('{}')
    stray = blob / 'README.txt'
    stray.write_text('not a checkpoint directory')
    dry = collect(s, blob)  # default is a dry run
    assert dry['candidates'] == ['b' * 64] and dry['removed'] == [] and old.exists()
    assert dry['kept_young'] == 2 and dry['kept_referenced'] == 1 and dry['kept_unknown'] == 1
    done = collect(s, blob, apply=True)
    assert done['removed'] == ['b' * 64] and not old.exists()
    assert young.exists() and fresh_stage.exists() and stray.exists() and live.exists()
    # a referenced checkpoint is never removed however old it becomes
    far_future = time.time() + 400 * 24 * 3600
    again = collect(s, blob, apply=True, now=far_future)
    assert sorted(again['removed']) == sorted(['a' * 64, '.staging-fresh']) and live.exists()
    assert again['kept_referenced'] == 1
    validate_checkpoint(live, s.checkpoints(r['id'])[0]['digest'])
    # a digest referenced by ANOTHER run's pointer is also live
    r2, a2, _ = new_run(s, tmp_path)
    s.blob_root = blob
    try:
        publish(s, r2, a2)
    finally:
        s.release_slot(r2['id'])
    assert Path(s.get(r2['id'])['checkpoint']) == live  # same digest reused
    assert collect(s, blob, apply=True, now=far_future)['removed'] == []


def test_gc_cli_refuses_a_grace_below_24h():
    out = subprocess.run([sys.executable, '-B', '-m', 'fieldwork.checkpoint_gc', '--grace-hours', '23', '--blob-root', str(ROOT / 'var/none-gc-test')],
                         cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert out.returncode != 0 and 'GRACE_BELOW_24H_REFUSED' in out.stderr


def test_gc_between_promote_and_insert_cannot_leave_a_pointer_to_a_missing_blob(isolated_store, tmp_path, monkeypatch):
    """GC deletes the digest directory after promote() validated it and before the pointer INSERT: the
    post-INSERT re-validation must raise and the transaction must roll back (no dangling pointer)."""
    import fieldwork.checkpoint_store as cs
    from fieldwork.checkpoint_gc import collect
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    try:
        real = cs.promote
        far = time.time() + 400 * 24 * 3600

        def promote_then_gc(*args, **kw):
            out = real(*args, **kw)
            report = collect(s, blob, apply=True, now=far)  # the unreferenced fresh blob looks ancient to this pass
            assert out[0].name in report['removed']
            return out

        monkeypatch.setattr(cs, 'promote', promote_then_gc)
        with pytest.raises((ValueError, OSError)):
            publish(s, r, a)
        assert_nothing_committed(s, r, blob)
        monkeypatch.setattr(cs, 'promote', real)
        publish(s, r, a)
        assert_pointer_is_validated(s, r, blob)
    finally:
        s.release_slot(r['id'])


def test_gc_blocks_on_an_uncommitted_pointer_insert_then_sees_the_reference(isolated_store, tmp_path, monkeypatch):
    """GC must not run between the pointer INSERT and its COMMIT: its SHARE lock waits for the publisher's
    ROW EXCLUSIVE lock, and after the commit the digest is referenced and kept even though it looks ancient."""
    from fieldwork.checkpoint_gc import collect
    s = isolated_store
    r, a, blob = new_run(s, tmp_path)
    inserted, release = threading.Event(), threading.Event()
    publisher = labelled_store(s, 'fw-matrix-pub-' + uuid.uuid4().hex)
    publisher.blob_root = blob
    real = Store.event
    pub_thread = {}

    def event(self, c, run, kind, payload):
        if kind == 'epoch_committed' and threading.current_thread() is pub_thread.get('t'):
            inserted.set()
            assert release.wait(timeout=30)
        return real(self, c, run, kind, payload)

    monkeypatch.setattr(Store, 'event', event)
    gc_label = 'fw-matrix-gc-' + uuid.uuid4().hex
    gc_store = labelled_store(s, gc_label)
    out = {}
    try:
        t = threading.Thread(target=lambda: out.update(pub=capture(lambda st: publish(st, r, a), publisher)))
        pub_thread['t'] = t
        t.start()
        assert inserted.wait(timeout=60)
        far = time.time() + 400 * 24 * 3600
        g = threading.Thread(target=lambda: out.update(gc=capture(lambda st: collect(st, blob, apply=True, now=far), gc_store)))
        g.start()
        wait_for_database_lock(s, gc_label)  # GC is parked on the lock held by the uncommitted INSERT
        assert 'gc' not in out
        release.set()
        t.join(timeout=60)
        g.join(timeout=60)
        assert out['pub'][0] == 'ok', out['pub']
        report = out['gc'][1]
        assert out['gc'][0] == 'ok' and report['removed'] == [] and report['kept_referenced'] == 1
        assert_pointer_is_validated(s, r, blob)
    finally:
        release.set()
        monkeypatch.setattr(Store, 'event', real)
        s.release_slot(r['id'])
