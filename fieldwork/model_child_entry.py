"""Tiny fixed dispatcher for the sealed real-model image."""
from __future__ import annotations

import io
import os
import runpy
import sys
import time
from pathlib import Path

APP = Path('/app')
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

MODULES = {
    'training': 'fieldwork.real_train_child',
    'inference': 'fieldwork.real_infer_child',
    'qualified-inference': 'fieldwork.qualified_infer_child',
    'bundle': 'fieldwork.real_bundle_child',
}
MAX_STDOUT = 64 * 1024
MAX_STDERR = 64 * 1024


class _BoundedText(io.TextIOBase):
    def __init__(self, limit: int):
        self.limit = limit
        self.data = []
        self.size = 0

    def writable(self):
        return True

    def write(self, value):
        if not isinstance(value, str):
            raise TypeError('text required')
        raw = value.encode('utf-8', errors='replace')
        if self.size + len(raw) > self.limit:
            raise ValueError('MODEL_CHILD_OUTPUT_LIMIT')
        self.size += len(raw)
        self.data.append(value)
        return len(value)

    def flush(self):
        return None

    def bytes(self):
        return ''.join(self.data).encode('utf-8')


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2 or argv[0] not in MODULES or argv[1] != MODULES[argv[0]]:
        return 2
    operation, module, *args = argv
    output = Path(os.environ.get('FW_CHILD_RECEIPT', '/tmp/child-stdout.txt'))
    if output not in {Path('/tmp/child-stdout.txt'), Path('/workspace/output/child-stdout.txt')}:
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_root = os.environ.get('TMPDIR')
    if temp_root:
        if temp_root != '/workspace/output/tmp':
            return 2
        Path(temp_root).mkdir(parents=True, exist_ok=True)
    out, err = _BoundedText(MAX_STDOUT), _BoundedText(MAX_STDERR)
    failure = None
    try:
        sys.argv = [module, *args]
        with _redirect(out, err):
            runpy.run_module(module, run_name='__main__', alter_sys=True)
    except BaseException as exc:
        # Store a short type-only receipt. Native/library stderr is discarded by
        # the Docker log driver; no private paths or source content are emitted.
        failure = type(exc).__name__[:80]
    payload = out.bytes() if failure is None else ('{"error":"' + failure + '"}\n').encode('ascii')
    if len(payload) > MAX_STDOUT:
        return 3
    with output.open('xb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    # Docker unmounts tmpfs when PID 1 exits. Keep the credential-free container
    # alive until the supervisor exports the bounded files and removes it.
    # The actual model task is finished; this sentinel is its exit receipt.
    status = output.parent / '.child-exit.json'
    staged = status.with_suffix('.writing')
    with staged.open('xb') as stream:
        stream.write(b'{"exit_code":1}' if failure is not None else b'{"exit_code":0}')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(staged, status)
    while True:
        time.sleep(1)


class _redirect:
    def __init__(self, stdout, stderr):
        self.stdout, self.stderr = stdout, stderr

    def __enter__(self):
        self.oldout, self.olderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = self.stdout, self.stderr

    def __exit__(self, *exc):
        sys.stdout, sys.stderr = self.oldout, self.olderr


if __name__ == '__main__':
    raise SystemExit(main())
