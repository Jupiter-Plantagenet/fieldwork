"""Torch-free filesystem publication helpers (review F8).

`durable_rename` publishes a fully written staging directory under its final name:

* Windows: a freshly written directory is often briefly held open by Defender or the
  indexer, so `os.rename` fails with PermissionError. It is retried with bounded backoff
  (default about 3 s in total); the last error is re-raised, never swallowed.
* An existing destination is never replaced. Both FileExistsError and the POSIX
  ENOTEMPTY/EEXIST OSError are reported as FileExistsError.
* Afterwards the parent directory is fsynced where the OS supports opening directories
  (POSIX). On Windows a directory handle cannot be fsynced through the Python API, so
  directory-entry durability there is NOT certified (power loss stays explicitly
  uncertified, as round 4 stated).
"""
import errno, os, time
from pathlib import Path


def fsync_directory(path):
    """Return True when the directory entry was flushed, False when unsupported."""
    if os.name == 'nt':
        return False
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
        return True
    finally:
        os.close(fd)


def durable_rename(source, target, attempts=12, first_delay=0.025, sleep=time.sleep, rename=os.rename):
    source = Path(source); target = Path(target); delay = first_delay
    for attempt in range(attempts):
        try:
            rename(source, target)
            break
        except FileExistsError:
            raise
        except PermissionError:
            if target.exists():
                raise FileExistsError(str(target)) from None
            if attempt == attempts - 1:
                raise
            sleep(delay); delay = min(delay * 2, 0.5)
        except OSError as exc:
            if exc.errno in (errno.ENOTEMPTY, errno.EEXIST):
                raise FileExistsError(str(target)) from exc
            raise
    fsync_directory(target.parent)
    return target
