"""Cross-process ownership and atomic publication for the local worker heartbeat."""
from __future__ import annotations

import json
import os
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .artifact_state import alive, identity
from .store import ROOT


def effective_worker_id(pid: int | None = None) -> str:
    """Match the supervisor's stable-ID fallback for both marker writers."""
    value = os.environ.get('FIELDWORK_WORKER_ID')
    return value if value is not None else 'fieldwork-worker-' + str(os.getpid() if pid is None else pid)


@contextmanager
def _marker_lock(path: Path):
    """Serialize every worker marker writer across processes on the same host."""
    lock_path = path.with_name(path.name + '.lock')
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a+b') as stream:
        if os.name == 'nt':
            import msvcrt
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b'0')
                stream.flush()
            stream.seek(0)
            deadline = time.monotonic() + 5
            while True:
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise OSError('WORKER_HEARTBEAT_LOCK_TIMEOUT') from None
                    time.sleep(.01)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _read_marker(path: Path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError):
        raise OSError('WORKER_HEARTBEAT_MARKER_INVALID') from None
    if type(value) is not dict:
        raise OSError('WORKER_HEARTBEAT_MARKER_INVALID')
    return value


def _write_marker(path: Path, value: dict):
    payload = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    fd, temporary = tempfile.mkstemp(prefix='.worker-heartbeat-', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def publish_worker_heartbeat(value: dict, path: Path | None = None):
    """Publish the loop heartbeat, refusing to overwrite another live worker."""
    target = Path(path) if path is not None else ROOT / 'var/worker.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    if type(value) is not dict or type(value.get('pid')) is not int or type(value.get('create_time')) not in (int, float):
        raise OSError('WORKER_HEARTBEAT_IDENTITY_INVALID')
    with _marker_lock(target):
        prior = _read_marker(target)
        if prior is not None:
            same_owner = (prior.get('pid'), prior.get('create_time')) == (value['pid'], value['create_time'])
            if not same_owner and alive(prior.get('pid'), prior.get('create_time')):
                raise OSError('WORKER_HEARTBEAT_OWNER_ACTIVE')
        _write_marker(target, value)


def refresh_worker_heartbeat_after_progress(path: Path | None = None):
    """Refresh only this scoped real worker after its DB progress callback succeeds."""
    target = Path(path) if path is not None else ROOT / 'var/worker.json'
    pid, created = identity()
    worker_id = effective_worker_id(pid)
    with _marker_lock(target):
        beat = _read_marker(target)
        if (beat is None or beat.get('pid') != pid or beat.get('create_time') != created
                or beat.get('identity') != 'scoped-worker-v1'
                or beat.get('profile') != 'scoped-real-training-and-inference'
                or beat.get('worker_id') != worker_id):
            raise OSError('WORKER_HEARTBEAT_OWNERSHIP_CHANGED')
        beat['as_of'] = datetime.now(timezone.utc).isoformat()
        _write_marker(target, beat)
