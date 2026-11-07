"""Shared host heavy-work lock for every portfolio product (review F6).

Lock = a directory created atomically with mkdir. The owner record is written to a
temporary file INSIDE the new directory and renamed to `owner.json`, so a reader sees
either no owner record yet or a complete one. The record holds pid, process creation
time, product, purpose and acquisition time.

Rules:
* acquire  - atomic mkdir; never waits, never steals. Returns False when held.
* release  - removes the lock only when the owner record names this exact process
             (pid AND creation time).
* recover  - removes a lock ONLY when its recorded owner process is proven gone: the pid
             does not exist, or it exists with a different creation time (pid reuse).
             A missing/partial owner record, a missing creation time, or an owner that
             cannot be inspected (access denied) is NOT proof: recover refuses.

CLI (from any product):
  python C:/Users/user/portfolio-build/tools/product_lock.py status
  python C:/Users/user/portfolio-build/tools/product_lock.py recover
Default path: C:/Users/user/portfolio-build/.cache/product-build.lock
(override with --path or PORTFOLIO_PRODUCT_LOCK).
"""
import argparse, json, os, sys, time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT = Path(os.environ.get('PORTFOLIO_PRODUCT_LOCK') or Path(__file__).resolve().parents[1] / '.cache' / 'product-build.lock')
OWNER = 'owner.json'


def _process_created(pid):
    import psutil
    return psutil.Process(pid).create_time()


def this_process():
    return {'pid': os.getpid(), 'create_time': _process_created(os.getpid())}


def read_owner(path=DEFAULT):
    path = Path(path)
    try:
        return json.loads((path / OWNER).read_text())
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (ValueError, OSError):
        return {'unreadable': True}


def acquire(product, purpose, path=DEFAULT, *, check_fieldwork_cleanup=True):
    path = Path(path)
    # A daemon container can outlive its Docker CLI and crashed lock owner.
    # Its real runner must positively clean it before any new heavy admission.
    if check_fieldwork_cleanup and fieldwork_model_cleanup_pending():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.mkdir()
    except FileExistsError:
        return False
    record = {**this_process(), 'product': product, 'purpose': purpose,
              'acquired_utc': datetime.now(timezone.utc).isoformat(), 'host_lock_version': 2}
    tmp = path / ('.owner-' + str(os.getpid()) + '.tmp')
    tmp.write_text(json.dumps(record))
    os.replace(tmp, path / OWNER)
    return True


def is_mine(record):
    me = this_process()
    return bool(record) and record.get('pid') == me['pid'] and record.get('create_time') == me['create_time']


def release(path=DEFAULT):
    path = Path(path)
    record = read_owner(path)
    if not is_mine(record):
        return False
    (path / OWNER).unlink()
    for leftover in path.glob('.owner-*.tmp'):
        leftover.unlink()
    path.rmdir()
    return True


def owner_gone(record):
    """True only with positive proof that the recorded owner process no longer exists."""
    import psutil
    if not record or record.get('unreadable'):
        return False, 'OWNER_RECORD_MISSING_OR_UNREADABLE'
    pid, created = record.get('pid'), record.get('create_time')
    if type(pid) is not int or not isinstance(created, (int, float)):
        return False, 'OWNER_IDENTITY_INCOMPLETE'
    try:
        actual = _process_created(pid)
    except psutil.NoSuchProcess:
        return True, 'OWNER_PID_ABSENT'
    except psutil.Error:
        return False, 'OWNER_UNINSPECTABLE'
    if actual != created:
        return True, 'OWNER_PID_REUSED'
    return False, 'OWNER_ALIVE'


def fieldwork_model_cleanup_pending():
    registry=Path(__file__).resolve().parents[1]/'.local/real-data/model-private/.model-container-receipts'
    try:
        registry.stat()
        if registry.is_symlink() or not registry.is_dir():return True
        return any(registry.glob('.model-*.cleanup.json'))
    except FileNotFoundError:return False
    except OSError:return True


def recover(path=DEFAULT):
    path = Path(path)
    if not path.exists():
        return {'recovered': False, 'reason': 'NOT_HELD'}
    record = read_owner(path)
    # Pre-v2 locks had no creation time. Recover only an absent PID: an alive
    # PID (including reuse) cannot safely be attributed to the legacy owner.
    legacy = path / 'owner.txt'
    if record is None and legacy.is_file():
        import psutil
        raw = legacy.read_text(encoding='utf-8-sig')
        fields = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        try:
            pid = int(fields['pid'])
            if pid <= 0:
                raise ValueError('invalid pid')
        except (KeyError, ValueError):
            return {'recovered': False, 'reason': 'LEGACY_OWNER_IDENTITY_INCOMPLETE'}
        try:
            psutil.Process(pid).create_time()
        except psutil.NoSuchProcess:
            pass
        except psutil.Error:
            return {'recovered': False, 'reason': 'LEGACY_OWNER_UNINSPECTABLE'}
        else:
            return {'recovered': False, 'reason': 'LEGACY_OWNER_PID_PRESENT'}
        # Never erase unknown files alongside the legacy record.
        if {p.name for p in path.iterdir()} != {'owner.txt'}:
            return {'recovered': False, 'reason': 'LEGACY_LOCK_UNEXPECTED_CONTENTS'}
        if fieldwork_model_cleanup_pending():
            return {'recovered': False, 'reason': 'FIELDWORK_MODEL_CLEANUP_REQUIRED'}
        archive = path.parent / (path.name + '.recovered-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '.json')
        result = {'recovered': True, 'reason': 'LEGACY_OWNER_PID_ABSENT',
                  'owner': fields, 'legacy_record': raw,
                  'recovered_utc': datetime.now(timezone.utc).isoformat(),
                  'recovered_by': this_process()}
        with archive.open('x') as f:
            json.dump(result, f)
        legacy.unlink()
        path.rmdir()
        return {**result, 'audit': str(archive)}
    gone, reason = owner_gone(record)
    if not gone:
        return {'recovered': False, 'reason': reason, 'owner': record}
    if fieldwork_model_cleanup_pending():
        return {'recovered': False, 'reason': 'FIELDWORK_MODEL_CLEANUP_REQUIRED', 'owner': record}
    archive = path.parent / (path.name + '.recovered-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '.json')
    with archive.open('x') as f:
        json.dump({'owner': record, 'reason': reason, 'recovered_utc': datetime.now(timezone.utc).isoformat(),
                   'recovered_by': this_process()}, f)
    (path / OWNER).unlink()
    for leftover in path.glob('.owner-*.tmp'):
        leftover.unlink()
    path.rmdir()
    return {'recovered': True, 'reason': reason, 'owner': record, 'audit': str(archive)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('action', choices=['status', 'recover'])
    ap.add_argument('--path', default=str(DEFAULT))
    a = ap.parse_args(argv)
    if a.action == 'status':
        record = read_owner(a.path)
        print(json.dumps({'held': Path(a.path).exists(), 'owner': record,
                          'owner_gone': owner_gone(record) if Path(a.path).exists() else None}))
        return 0
    result = recover(a.path)
    print(json.dumps(result))
    return 0 if result['recovered'] or result['reason'] == 'NOT_HELD' else 3


if __name__ == '__main__':
    sys.exit(main())
