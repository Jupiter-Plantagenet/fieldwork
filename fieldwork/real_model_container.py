"""Pinned Docker lifecycle for credential-free real model children.

Inputs are copied through a bounded, hash-verified stdin tar into a per-run
Docker named volume and mounted read-only. Training and bundle work use a
write-budgeted tmpfs plus bounded /tmp and /dev/shm; only validated checkpoint
and bundle outputs are exported to the host. A durable nonce/CID/volume receipt
remains until Docker proves the owned resources are absent.
"""
from __future__ import annotations

import io
import hashlib
import json
import os
import re
import subprocess
import tarfile
import threading
import time
import uuid
from pathlib import Path, PurePosixPath

try:
    import psutil
except ImportError:
    psutil = None

from .container_decoder import CONTAINER_ID_RE
from .model_volume_staging import (collect_stage_inputs, write_stage_tar, STAGER_CODE,
    MAX_STAGE_PROTOCOL_OVERHEAD_BYTES, MODEL_RUN_WRITE_BUDGET_BYTES, DEFAULT_RUN_WRITE_BUDGET_BYTES,
    MODEL_FIXED_TMP_WRITE_BYTES, STAGE_ROOT_ENV, StageProgressCounter)

# Records written under the default 2 GiB budget stay readable when the operator space override
# raises it; they are rewritten with the larger limit. Without the override only the exact limit passes.
_ACCEPTED_BUDGET_LIMITS = frozenset({MODEL_RUN_WRITE_BUDGET_BYTES, DEFAULT_RUN_WRITE_BUDGET_BYTES})

IMAGE_ID_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
MODEL_LABEL = 'fieldwork.real-model.child'
STAGE_LABEL = 'fieldwork.real-model.stage'
RECEIPT_SCHEMA = 'fieldwork.real-model.cleanup/v1'
MAX_WALL_SECONDS = 4 * 60 * 60
MAX_STDOUT = 64 * 1024
MAX_CID_OUTPUT = 4096
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_CHECKPOINT_BYTES = 34 * 1024 * 1024
MODEL_TMPFS_BYTES = 1920 * 1024 * 1024
OUTPUT_CONTAINER = '/workspace/output'
TRAINING_CONTAINER = OUTPUT_CONTAINER + '/training'
INFERENCE_RECEIPT = '/tmp/child-stdout.txt'


def _call_progress(callback, *, force=False):
    if callback is not None:
        if force:
            callback(force=True)
        else:
            callback()


def _wait_for_stage_helper(proc, *, progress_callback=None, timeout=30,
                          poll_interval=5, monotonic=None):
    """Poll helper completion under one deadline that includes heartbeat time."""
    now = monotonic or time.monotonic
    started = now()
    deadline = started + timeout

    def renew_within_budget():
        _call_progress(progress_callback, force=True)
        if now() >= deadline:
            raise subprocess.TimeoutExpired('model stage helper', timeout)

    renew_within_budget()
    while True:
        remaining = deadline - now()
        if remaining <= 0:
            raise subprocess.TimeoutExpired('model stage helper', timeout)
        try:
            code = proc.wait(timeout=min(poll_interval, remaining))
        except subprocess.TimeoutExpired:
            if now() >= deadline:
                raise subprocess.TimeoutExpired('model stage helper', timeout) from None
            renew_within_budget()
            continue
        # Completion and the renewal needed before the next cleanup phase share
        # the same finite budget; callback latency is deliberately included.
        renew_within_budget()
        return code


def _wait_for_stage_writer(writer, progress, *, progress_callback=None,
                           timeout=300, no_progress_timeout=30, poll_interval=1,
                           monotonic=None):
    """Poll a live tar transfer; renew only after verified source bytes advance."""
    now = monotonic or time.monotonic
    started = last_progress = now()
    observed = progress.snapshot()
    while writer.is_alive():
        current_time = now()
        if current_time - started >= timeout:
            raise TimeoutError('MODEL_STAGE_TIMEOUT')
        if current_time - last_progress >= no_progress_timeout:
            raise TimeoutError('MODEL_STAGE_NO_PROGRESS')
        writer.join(timeout=min(poll_interval, timeout - (current_time - started),
                                no_progress_timeout - (current_time - last_progress)))
        current_time = now()
        total = progress.snapshot()
        if total > observed:
            observed = total
            last_progress = current_time
            _call_progress(progress_callback)
    if now() - started >= timeout:
        raise TimeoutError('MODEL_STAGE_TIMEOUT')
OUTPUT_RECEIPT = OUTPUT_CONTAINER + '/child-stdout.txt'

# The container remains alive after its task exits so the supervisor can export
# bounded files. Docker Desktop's `docker cp` does not reliably see writable
# tmpfs mounts in that state, so stream only these fixed paths through exec.
_OUTPUT_STREAM_PROGRAM = r'''import os, re, stat, sys, tarfile
path, cap = sys.argv[1], int(sys.argv[2])
fixed = {'/tmp/child-stdout.txt', '/workspace/output/child-stdout.txt',
         '/workspace/output/training/result.json', '/workspace/output/bundle'}
if path not in fixed and not re.fullmatch(r'/workspace/output/training/epoch-(?:[1-9][0-9]{0,2})', path):
    raise SystemExit(4)
try:
    root_st = os.lstat(path)
except FileNotFoundError:
    raise SystemExit(3)
if stat.S_ISLNK(root_st.st_mode) or not (stat.S_ISREG(root_st.st_mode) or stat.S_ISDIR(root_st.st_mode)):
    raise SystemExit(4)
root = os.path.abspath(path)
root_base = os.path.basename(root)
files = []
if stat.S_ISREG(root_st.st_mode):
    files = [(root, root_base)]
else:
    for base, dirs, names in os.walk(root, topdown=True, followlinks=False):
        dirs.sort(); names.sort()
        for name in list(dirs):
            st = os.lstat(os.path.join(base, name))
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode): raise SystemExit(4)
        for name in names:
            p = os.path.join(base, name); st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode): raise SystemExit(4)
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            if rel.startswith('../') or rel == '..': raise SystemExit(4)
            files.append((p, root_base + '/' + rel))
            if len(files) > 4096: raise SystemExit(5)
if not files: raise SystemExit(3)
total = 0
with tarfile.open(fileobj=sys.stdout.buffer, mode='w|', format=tarfile.PAX_FORMAT) as archive:
    for filename, arcname in files:
        st = os.lstat(filename)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size > cap-total:
            raise SystemExit(5)
        fd = os.open(filename, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != st.st_dev or opened.st_ino != st.st_ino
                    or opened.st_size != st.st_size): raise SystemExit(4)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                info = tarfile.TarInfo(arcname); info.size = opened.st_size; info.mode = 0o600
                archive.addfile(info, stream)
        finally:
            os.close(fd)
        total += st.st_size
'''


def _output_tmpfs_capacity(staged_bytes, already_charged=0):
    if (type(staged_bytes) is not int or staged_bytes < 0
            or type(already_charged) is not int or already_charged < 0):
        raise ModelContainerUnavailable('MODEL_RUN_WRITE_BUDGET_INVALID')
    remaining = (MODEL_RUN_WRITE_BUDGET_BYTES - already_charged - staged_bytes
                 - MAX_STAGE_PROTOCOL_OVERHEAD_BYTES - MODEL_FIXED_TMP_WRITE_BYTES)
    capacity = min(MODEL_TMPFS_BYTES, remaining // 2)
    if capacity < 64 * 1024 * 1024:
        raise ModelContainerUnavailable('MODEL_RUN_WRITE_BUDGET_EXCEEDED')
    return capacity


class ModelContainerUnavailable(RuntimeError):
    def __init__(self, code):
        self.code = str(code)
        super().__init__(self.code)


def _docker_env():
    if any(os.environ.get(k) for k in ('DOCKER_HOST', 'DOCKER_CONTEXT',
                                        'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY')):
        raise ModelContainerUnavailable('MODEL_REMOTE_DOCKER_FORBIDDEN')
    return {k: v for k, v in os.environ.items()
            if k in {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE'}}


def _docker(*args):
    return ['docker', '--context', 'default', *args]


def _no_reparse(path: Path):
    path = Path(path)
    parts = [path, *path.parents]
    for entry in parts:
        info = entry.lstat()
        if (entry.is_symlink() or getattr(info, 'st_file_attributes', 0)
                & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
            raise ModelContainerUnavailable('MODEL_PATH_REPARSE_POINT')


def _mount_dir(path, *, create=False, require_empty=False):
    path = Path(path).absolute()
    if create:
        path.mkdir(parents=True, exist_ok=False)
    try:
        _no_reparse(path)
        if not path.is_dir():
            raise ValueError()
        resolved = path.resolve(strict=True)
        if ',' in str(resolved):
            raise ValueError()
        if require_empty and any(resolved.iterdir()):
            raise ValueError()
        return resolved
    except (OSError, ValueError):
        raise ModelContainerUnavailable('MODEL_MOUNT_SOURCE_INVALID') from None


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('MODEL_CONTAINER_DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _safe_relative(name):
    path = PurePosixPath(name)
    return (not path.is_absolute() and bool(path.parts)
            and all(part not in ('', '.', '..') for part in path.parts))


def _write_receipt(path: Path, value: dict, *, exclusive=False):
    mode = 'x' if exclusive else 'w'
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.writing')
    try:
        with temp.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, separators=(',', ':'), sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.replace(temp, path)
        else:
            os.replace(temp, path)
    except OSError:
        temp.unlink(missing_ok=True)
        raise ModelContainerUnavailable('MODEL_RECEIPT_WRITE_FAILED') from None


class ModelContainerRunner:
    """One local, pinned-image supervisor. It refuses unknown cleanup state."""

    def __init__(self, image_id: str, *, private_dir: str | Path):
        if type(image_id) is not str or not IMAGE_ID_RE.fullmatch(image_id):
            raise ModelContainerUnavailable('MODEL_IMAGE_PIN_REQUIRED')
        if psutil is None:
            raise ModelContainerUnavailable('MODEL_PROCESS_INSPECTION_UNAVAILABLE')
        self.image_id = image_id
        self.env = _docker_env()
        try:
            base = Path(private_dir).absolute()
            base.mkdir(parents=True, exist_ok=True)
            self.private_dir = _mount_dir(base)
            registry = self.private_dir / '.model-container-receipts'
            registry.mkdir(exist_ok=True)
            self.registry_dir = _mount_dir(registry)
        except OSError:
            raise ModelContainerUnavailable('MODEL_PRIVATE_STATE_UNAVAILABLE') from None
        self._active: set[Path] = set()
        self._write_budget_scope = None
        self._verify_local_daemon_and_image()
        self.recover_stale()

    def set_write_budget_scope(self, run_id):
        if type(run_id) is not str or not re.fullmatch(
                r'[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', run_id):
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_SCOPE_INVALID')
        self._write_budget_scope = run_id

    def clear_write_budget_scope(self):
        self._write_budget_scope = None

    def _budget_path(self, scope_digest):
        if type(scope_digest) is not str or not re.fullmatch(r'[0-9a-f]{64}', scope_digest):
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_LEDGER_INVALID')
        return self.registry_dir / ('.model-write-budget-' + scope_digest + '.json')

    def _load_budget_ledger(self, scope_digest):
        path = self._budget_path(scope_digest)
        if not path.exists():
            return {'schema': 'fieldwork.model-run-write-budget/v2', 'scope_sha256': scope_digest,
                    'limit_bytes': MODEL_RUN_WRITE_BUDGET_BYTES, 'charged_bytes': 0,
                    'reservations': [], 'completed': []}
        try:
            _no_reparse(path)
            if path.stat().st_size > 256 * 1024:
                raise ValueError()
            ledger = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique_pairs)
        except (OSError, ValueError, TypeError, UnicodeError):
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_LEDGER_INVALID') from None
        legacy = type(ledger) is dict and ledger.get('schema') == 'fieldwork.model-run-write-budget/v1'
        if (type(ledger) is not dict or set(ledger) != {'schema','scope_sha256','limit_bytes',
                'charged_bytes','reservations','completed'}
                or ledger['schema'] not in {'fieldwork.model-run-write-budget/v1',
                                            'fieldwork.model-run-write-budget/v2'}
                or ledger['scope_sha256'] != scope_digest
                or ledger['limit_bytes'] not in _ACCEPTED_BUDGET_LIMITS
                or type(ledger['charged_bytes']) is not int or not 0 <= ledger['charged_bytes'] <= ledger['limit_bytes']
                or type(ledger['reservations']) is not list or len(ledger['reservations']) > 1
                or type(ledger['completed']) is not list or len(ledger['completed']) > 256):
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_LEDGER_INVALID')
        for reservation in ledger['reservations']:
            if (type(reservation) is not dict or set(reservation) != {'nonce','staged_bytes',
                    'reserved_bytes','exported_bytes','child_output_bytes'}
                    or type(reservation['nonce']) is not str or not re.fullmatch(r'[0-9a-f]{32}', reservation['nonce'])
                    or any(type(reservation[k]) is not int or reservation[k] < 0
                           for k in ('staged_bytes','reserved_bytes','exported_bytes','child_output_bytes'))):
                raise ModelContainerUnavailable('MODEL_RUN_WRITE_LEDGER_INVALID')
        for item in ledger['completed']:
            expected_completed = ({'nonce','charged_bytes','staged_bytes','exported_bytes','child_output_bytes'}
                                  if legacy else {'nonce','charged_bytes','staged_bytes','exported_bytes',
                                                  'child_output_bytes','fixed_tmp_bytes'})
            if (type(item) is not dict or set(item) != expected_completed
                    or type(item['nonce']) is not str or not re.fullmatch(r'[0-9a-f]{32}', item['nonce'])
                    or any(type(item[k]) is not int or item[k] < 0 for k in
                           ('charged_bytes','staged_bytes','exported_bytes','child_output_bytes')
                           + (() if legacy else ('fixed_tmp_bytes',)))
                    or item['charged_bytes'] != (item['staged_bytes'] + item['exported_bytes']
                        + item['child_output_bytes'] + (0 if legacy else item['fixed_tmp_bytes']))):
                raise ModelContainerUnavailable('MODEL_RUN_WRITE_LEDGER_INVALID')
            if legacy:
                item['fixed_tmp_bytes'] = MODEL_FIXED_TMP_WRITE_BYTES
                item['charged_bytes'] += MODEL_FIXED_TMP_WRITE_BYTES
                ledger['charged_bytes'] += MODEL_FIXED_TMP_WRITE_BYTES
        ledger['schema'] = 'fieldwork.model-run-write-budget/v2'
        ledger['limit_bytes'] = MODEL_RUN_WRITE_BUDGET_BYTES
        completed_nonces =[item['nonce'] for item in ledger['completed']]
        reservation_nonces = [item['nonce'] for item in ledger['reservations']]
        if (len(set(completed_nonces)) != len(completed_nonces)
                or len(set(reservation_nonces)) != len(reservation_nonces)
                or set(completed_nonces) & set(reservation_nonces)
                or ledger['charged_bytes'] != sum(item['charged_bytes'] for item in ledger['completed'])):
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_LEDGER_INVALID')
        if ledger['charged_bytes'] + sum(r['reserved_bytes'] for r in ledger['reservations']) > MODEL_RUN_WRITE_BUDGET_BYTES:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_LEDGER_OVER_BUDGET')
        return ledger

    def _save_budget_ledger(self, scope_digest, ledger):
        ledger['schema'] = 'fieldwork.model-run-write-budget/v2'
        path = self._budget_path(scope_digest)
        temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.writing')
        try:
            with temp.open('x', encoding='utf-8') as stream:
                json.dump(ledger, stream, separators=(',', ':'), sort_keys=True)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, path)
        except OSError:
            temp.unlink(missing_ok=True)
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_LEDGER_WRITE_FAILED') from None

    def _reserve_run_budget(self, receipt, staged_bytes, *, output_tmpfs):
        scope = self._write_budget_scope or ('ephemeral:' + receipt['nonce'])
        scope_digest = hashlib.sha256(scope.encode('utf-8')).hexdigest()
        ledger = self._load_budget_ledger(scope_digest)
        if ledger['reservations']:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_RESERVATION_ACTIVE')
        charged = ledger['charged_bytes']
        if output_tmpfs:
            output_bytes = _output_tmpfs_capacity(staged_bytes, charged)
        else:
            output_bytes = 0
        reserved = (staged_bytes + MAX_STAGE_PROTOCOL_OVERHEAD_BYTES
                    + MODEL_FIXED_TMP_WRITE_BYTES + 2 * output_bytes)
        if charged + sum(r['reserved_bytes'] for r in ledger['reservations']) + reserved > MODEL_RUN_WRITE_BUDGET_BYTES:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_BUDGET_EXCEEDED')
        reservation = {'nonce': receipt['nonce'], 'staged_bytes': staged_bytes,
                       'reserved_bytes': reserved, 'exported_bytes': 0, 'child_output_bytes': 0}
        ledger['reservations'].append(reservation)
        receipt['budget_scope_sha256'] = scope_digest
        receipt['budget_file'] = self._budget_path(scope_digest).name
        receipt['staged_bytes'] = staged_bytes
        receipt['write_budget'] = {'limit_bytes': MODEL_RUN_WRITE_BUDGET_BYTES,
            'charged_before_bytes': charged, 'staged_bytes': staged_bytes,
            'protocol_overhead_reserved_bytes': MAX_STAGE_PROTOCOL_OVERHEAD_BYTES,
            'fixed_tmp_reserved_bytes': MODEL_FIXED_TMP_WRITE_BYTES,
            'output_tmpfs_cap_bytes': output_bytes, 'export_copy_cap_bytes': output_bytes,
            'reserved_bytes': reserved, 'exported_bytes': 0, 'child_output_bytes': 0,
            'stage_start_pending': False, 'stage_started': False, 'stage_complete': False,
            'child_start_pending': False, 'child_started': False, 'child_output_measured': False}
        receipt_path = self.registry_dir / ('.model-' + receipt['nonce'] + '.cleanup.json')
        _write_receipt(receipt_path, receipt)
        self._save_budget_ledger(scope_digest, ledger)
        return output_bytes

    def _charge_budget_export(self, receipt_path, receipt, amount):
        if type(amount) is not int or amount < 0 or not receipt.get('budget_scope_sha256'):
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_BUDGET_INVALID')
        scope_digest = receipt['budget_scope_sha256']
        ledger = self._load_budget_ledger(scope_digest)
        reservation = next((x for x in ledger['reservations'] if x['nonce'] == receipt['nonce']), None)
        if reservation is None:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_RESERVATION_MISSING')
        budget = receipt['write_budget']
        exported = budget['exported_bytes'] + amount
        if exported > budget['export_copy_cap_bytes']:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_EXPORT_BOUNDS')
        budget['exported_bytes'] = exported
        reservation['exported_bytes'] = exported
        _write_receipt(receipt_path, receipt)
        self._save_budget_ledger(scope_digest, ledger)

    def _record_child_output(self, receipt_path, receipt, amount):
        if type(amount) is not int or amount < 0 or not receipt.get('budget_scope_sha256'):
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_BUDGET_INVALID')
        budget = receipt['write_budget']
        if amount > budget['output_tmpfs_cap_bytes']:
            amount = budget['output_tmpfs_cap_bytes']
        scope_digest = receipt['budget_scope_sha256']
        ledger = self._load_budget_ledger(scope_digest)
        reservation = next((x for x in ledger['reservations'] if x['nonce'] == receipt['nonce']), None)
        if reservation is None:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_RESERVATION_MISSING')
        budget['child_output_bytes'] = amount
        budget['child_output_measured'] = True
        reservation['child_output_bytes'] = amount
        _write_receipt(receipt_path, receipt)
        self._save_budget_ledger(scope_digest, ledger)

    def _finish_run_budget(self, receipt):
        scope_digest = receipt.get('budget_scope_sha256')
        if scope_digest is None:
            return
        ledger = self._load_budget_ledger(scope_digest)
        nonce = receipt['nonce']
        if any(item['nonce'] == nonce for item in ledger['completed']):
            return
        reservation = next((item for item in ledger['reservations'] if item['nonce'] == nonce), None)
        if reservation is None and ledger['reservations']:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_RESERVATION_MISSING')
        budget = receipt.get('write_budget')
        if type(budget) is not dict:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_RECEIPT_MISSING')
        staged = (budget['staged_bytes'] if (budget['stage_complete'] or budget['stage_started']
                   or budget['stage_start_pending']) else 0)
        exported = budget['exported_bytes']
        # /tmp and /dev/shm are private bounded mounts. Charge their full cap for
        # any spawned/ambiguous child instead of claiming file usage is physical I/O.
        child_output = (budget['child_output_bytes'] if budget['child_output_measured']
                        else budget['output_tmpfs_cap_bytes']
                        if (budget['child_started'] or budget['child_start_pending']) else 0)
        fixed_tmp = (budget['fixed_tmp_reserved_bytes']
                     if (budget['child_started'] or budget['child_start_pending']) else 0)
        actual = staged + exported + child_output + fixed_tmp
        if actual > MODEL_RUN_WRITE_BUDGET_BYTES:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_BUDGET_EXCEEDED')
        if reservation is not None and (reservation['staged_bytes'] != budget['staged_bytes']
                or reservation['reserved_bytes'] != budget['reserved_bytes']
                or actual > reservation['reserved_bytes']):
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_RESERVATION_MISMATCH')
        ledger['reservations'] = [x for x in ledger['reservations'] if x['nonce'] != nonce]
        ledger['charged_bytes'] += actual
        if ledger['charged_bytes'] > MODEL_RUN_WRITE_BUDGET_BYTES:
            raise ModelContainerUnavailable('MODEL_RUN_WRITE_BUDGET_EXCEEDED')
        ledger['completed'].append({'nonce': nonce, 'charged_bytes': actual,
            'staged_bytes': staged, 'exported_bytes': exported,
            'child_output_bytes': child_output, 'fixed_tmp_bytes': fixed_tmp})
        self._save_budget_ledger(scope_digest, ledger)

    def _run(self, args, *, timeout=5, capture=False, input_bytes=None, limit=MAX_CID_OUTPUT):
        try:
            result = subprocess.run(_docker(*args), env=self.env, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                input=input_bytes, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ModelContainerUnavailable('MODEL_DOCKER_STATE_UNAVAILABLE') from None
        if capture and len(result.stdout) > limit:
            raise ModelContainerUnavailable('MODEL_DOCKER_OUTPUT_LIMIT')
        return result

    def _verify_local_daemon_and_image(self):
        try:
            context = self._run(('context', 'inspect', 'default', '--format={{json .Endpoints.docker}}'), capture=True)
            endpoint = json.loads(context.stdout.decode('utf-8')) if context.returncode == 0 else {}
            host = endpoint.get('Host') if type(endpoint) is dict else None
            if not (host == 'npipe:////./pipe/docker_engine'
                    or type(host) is str and host.startswith('unix:///')):
                raise ModelContainerUnavailable('MODEL_LOCAL_DOCKER_ENDPOINT_REQUIRED')
            info = self._run(('info', '--format={{.OSType}}'), capture=True)
            if info.returncode != 0 or info.stdout.decode('ascii', 'ignore').strip() != 'linux':
                raise ModelContainerUnavailable('MODEL_LINUX_DOCKER_REQUIRED')
            inspected = self._run(('image', 'inspect', '--format={{.Id}}', self.image_id), capture=True)
        except (ValueError, TypeError, UnicodeError):
            raise ModelContainerUnavailable('MODEL_DOCKER_UNAVAILABLE') from None
        if inspected.returncode != 0 or inspected.stdout.decode('ascii', 'ignore').strip() != self.image_id:
            raise ModelContainerUnavailable('MODEL_IMAGE_NOT_PINNED_LOCALLY')

    def _owner_alive(self, receipt):
        try:
            proc = psutil.Process(receipt['owner_pid'])
            return abs(proc.create_time() - receipt['owner_created']) < 0.02
        except psutil.NoSuchProcess:
            return False
        except (psutil.AccessDenied, OSError, TypeError, ValueError):
            raise ModelContainerUnavailable('MODEL_OWNER_STATUS_UNKNOWN') from None

    def _read_receipt(self, path):
        try:
            _no_reparse(path)
            if path.stat().st_size > 4096:
                raise ValueError()
            receipt = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique_pairs)
        except (OSError, ValueError, TypeError, UnicodeError):
            raise ModelContainerUnavailable('MODEL_CLEANUP_RECEIPT_INVALID') from None
        expected = {'schema', 'state', 'nonce', 'cid_file', 'owner_pid', 'owner_created', 'image_id'}
        optional = {'cleanup_error', 'updated_utc', 'volumes', 'write_budget', 'staged_bytes',
                    'budget_scope_sha256', 'budget_file'}
        if (type(receipt) is not dict or not expected <= receipt.keys()
                or receipt.keys() - expected - optional or receipt['schema'] != RECEIPT_SCHEMA
                or receipt['state'] not in {'active', 'cleanup_required', 'resolved'}
                or type(receipt['nonce']) is not str or not re.fullmatch(r'[0-9a-f]{32}', receipt['nonce'])
                or receipt['cid_file'] != '.model-' + receipt['nonce'] + '.cid'
                or type(receipt['image_id']) is not str or not IMAGE_ID_RE.fullmatch(receipt['image_id'])
                or type(receipt['owner_pid']) is not int or receipt['owner_pid'] <= 0
                or type(receipt['owner_created']) not in (int, float)):
            raise ModelContainerUnavailable('MODEL_CLEANUP_RECEIPT_INVALID')
        volumes = receipt.get('volumes', [])
        if (type(volumes) is not list or len(volumes) > 1
                or any(type(n) is not str or n != 'fw-model-' + receipt['nonce'] for n in volumes)):
            raise ModelContainerUnavailable('MODEL_CLEANUP_RECEIPT_INVALID')
        if ('staged_bytes' in receipt and (type(receipt['staged_bytes']) is not int
                or not 0 <= receipt['staged_bytes'] <= MODEL_RUN_WRITE_BUDGET_BYTES)):
            raise ModelContainerUnavailable('MODEL_CLEANUP_RECEIPT_INVALID')
        budget = receipt.get('write_budget')
        if (('budget_scope_sha256' in receipt) != ('budget_file' in receipt)
                or ('budget_scope_sha256' in receipt and
                    (type(receipt['budget_scope_sha256']) is not str
                     or not re.fullmatch(r'[0-9a-f]{64}', receipt['budget_scope_sha256'])
                     or receipt['budget_file'] != '.model-write-budget-' + receipt['budget_scope_sha256'] + '.json'))):
            raise ModelContainerUnavailable('MODEL_CLEANUP_RECEIPT_INVALID')
        if budget is not None:
            keys = {'limit_bytes', 'charged_before_bytes', 'staged_bytes', 'protocol_overhead_reserved_bytes',
                    'fixed_tmp_reserved_bytes', 'output_tmpfs_cap_bytes', 'export_copy_cap_bytes',
                    'reserved_bytes', 'exported_bytes', 'child_output_bytes',
                    'stage_start_pending', 'stage_started', 'stage_complete',
                    'child_start_pending', 'child_started', 'child_output_measured'}
            boolean_keys = {'stage_start_pending', 'stage_started', 'stage_complete',
                            'child_start_pending', 'child_started', 'child_output_measured'}
            numeric_keys = keys - boolean_keys
            if (type(budget) is not dict or set(budget) != keys
                    or any(type(budget[k]) is not int or budget[k] < 0 for k in numeric_keys)
                    or budget['limit_bytes'] not in _ACCEPTED_BUDGET_LIMITS
                    or budget['staged_bytes'] != receipt.get('staged_bytes', 0)
                    or budget['protocol_overhead_reserved_bytes'] != MAX_STAGE_PROTOCOL_OVERHEAD_BYTES
                    or budget['fixed_tmp_reserved_bytes'] != MODEL_FIXED_TMP_WRITE_BYTES
                    or budget['output_tmpfs_cap_bytes'] != budget['export_copy_cap_bytes']
                    or budget['exported_bytes'] > budget['export_copy_cap_bytes']
                    or budget['child_output_bytes'] > budget['output_tmpfs_cap_bytes']
                    or any(type(budget[k]) is not bool for k in boolean_keys)
                    or (budget['stage_start_pending'] and budget['stage_started'])
                    or (budget['stage_complete'] and not budget['stage_started'])
                    or (budget['child_start_pending'] and budget['child_started'])
                    or budget['reserved_bytes'] != (budget['staged_bytes']
                        + budget['protocol_overhead_reserved_bytes']
                        + budget['fixed_tmp_reserved_bytes'] + 2 * budget['output_tmpfs_cap_bytes'])
                    or (budget['charged_before_bytes'] + budget['reserved_bytes'] > budget['limit_bytes'])
                    or (budget['charged_before_bytes'] + budget['staged_bytes']
                        + budget['protocol_overhead_reserved_bytes']
                        + budget['fixed_tmp_reserved_bytes']
                        + 2 * budget['output_tmpfs_cap_bytes'] > budget['limit_bytes'])):
                raise ModelContainerUnavailable('MODEL_CLEANUP_RECEIPT_INVALID')
        return receipt

    def _list_by_nonce(self, nonce):
        result = self._run(('ps', '--all', '--quiet', '--no-trunc', '--filter',
            f'label={MODEL_LABEL}.nonce={nonce}'), capture=True)
        if result.returncode != 0:
            raise ModelContainerUnavailable('MODEL_CONTAINER_QUERY_FAILED')
        values = [x.strip() for x in result.stdout.decode('ascii', 'strict').splitlines() if x.strip()]
        if len(values) > 1 or any(not CONTAINER_ID_RE.fullmatch(x) for x in values):
            raise ModelContainerUnavailable('MODEL_CONTAINER_IDENTITY_AMBIGUOUS')
        return values

    def _list_by_id(self, cid):
        result = self._run(('ps', '--all', '--quiet', '--no-trunc', '--filter', f'id={cid}'), capture=True)
        if result.returncode != 0:
            raise ModelContainerUnavailable('MODEL_CONTAINER_QUERY_FAILED')
        values = [x.strip() for x in result.stdout.decode('ascii', 'strict').splitlines() if x.strip()]
        if len(values) > 1 or any(not CONTAINER_ID_RE.fullmatch(x) for x in values):
            raise ModelContainerUnavailable('MODEL_CONTAINER_IDENTITY_AMBIGUOUS')
        return values

    def _list_stage_by_nonce(self, nonce):
        result = self._run(('ps', '--all', '--quiet', '--no-trunc', '--filter',
            f'label={STAGE_LABEL}.nonce={nonce}'), capture=True)
        if result.returncode != 0:
            raise ModelContainerUnavailable('MODEL_STAGE_CONTAINER_QUERY_FAILED')
        values = [x.strip() for x in result.stdout.decode('ascii', 'strict').splitlines() if x.strip()]
        if len(values) > 1 or any(not CONTAINER_ID_RE.fullmatch(x) for x in values):
            raise ModelContainerUnavailable('MODEL_STAGE_CONTAINER_AMBIGUOUS')
        return values

    def _inspect_volume(self, name, receipt):
        result = self._run(('volume', 'inspect', '--format={{json .}}', name), capture=True)
        if result.returncode != 0:
            if self._volume_name_present(name):
                raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_INSPECT_FAILED')
            return None
        try:
            row = json.loads(result.stdout.decode('utf-8'), object_pairs_hook=_unique_pairs)
            labels = row.get('Labels') or {}
        except (ValueError, TypeError, UnicodeError):
            raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_INSPECT_INVALID') from None
        if (type(row) is not dict or row.get('Name') != name or type(labels) is not dict
                or labels.get(STAGE_LABEL) != '1'
                or labels.get(STAGE_LABEL + '.nonce') != receipt['nonce']
                or labels.get(STAGE_LABEL + '.image') != receipt['image_id']
                or labels.get(STAGE_LABEL + '.owner') != self._owner_label(receipt)):
            raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_OWNERSHIP_MISMATCH')
        return row

    @staticmethod
    def _owner_label(receipt):
        return f"{receipt['owner_pid']}-{int(float(receipt['owner_created']) * 1000)}"

    def _list_volumes_by_nonce(self, nonce):
        result = self._run(('volume', 'ls', '--quiet', '--filter', f'label={STAGE_LABEL}.nonce={nonce}'),
                           capture=True)
        if result.returncode != 0:
            raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_QUERY_FAILED')
        values = [x.strip() for x in result.stdout.decode('ascii', 'strict').splitlines() if x.strip()]
        if len(values) > 1 or any(not re.fullmatch(r'fw-model-[0-9a-f]{32}', x) for x in values):
            raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_AMBIGUOUS')
        return values

    def _volume_name_present(self, name):
        result = self._run(('volume', 'ls', '--quiet', '--filter', f'name=^{name}$'), capture=True)
        if result.returncode != 0:
            raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_QUERY_FAILED')
        values = [x.strip() for x in result.stdout.decode('ascii', 'strict').splitlines() if x.strip()]
        if any(value != name for value in values) or len(values) > 1:
            raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_AMBIGUOUS')
        return bool(values)

    def _cleanup_volumes(self, receipt):
        names = receipt.get('volumes', [])
        if type(names) is not list or len(names) > 1 or any(
                type(n) is not str or n != 'fw-model-' + receipt['nonce'] for n in names):
            raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_RECEIPT_INVALID')
        try:
            if self._list_stage_by_nonce(receipt['nonce']):
                raise ModelContainerUnavailable('MODEL_STAGE_CONTAINER_REMAINS')
            for name in names:
                row = self._inspect_volume(name, receipt)
                if row is not None:
                    self._run(('volume', 'rm', name), timeout=20)
                if self._inspect_volume(name, receipt) is not None:
                    raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_CLEANUP_UNCONFIRMED')
        except ModelContainerUnavailable:
            raise

    def _cleanup_stage_container(self, receipt, *, progress_callback=None):
        progress_error = []
        def progress_tick():
            if not progress_error:
                try:
                    _call_progress(progress_callback, force=True)
                except BaseException as exc:
                    progress_error.append(exc)
        progress_tick()
        for cid in self._list_stage_by_nonce(receipt['nonce']):
            progress_tick()
            result = self._run(('container', 'inspect', '--format={{json .}}', cid), capture=True)
            if result.returncode != 0:
                if self._list_stage_by_nonce(receipt['nonce']):
                    raise ModelContainerUnavailable('MODEL_STAGE_CONTAINER_INSPECT_FAILED')
                continue
            try:
                row = json.loads(result.stdout.decode('utf-8'), object_pairs_hook=_unique_pairs)
                labels = row['Config']['Labels'] or {}
                image = row['Image']
            except (ValueError, TypeError, KeyError, UnicodeError):
                raise ModelContainerUnavailable('MODEL_STAGE_CONTAINER_INSPECT_INVALID') from None
            if (row.get('Id') != cid or type(labels) is not dict
                    or labels.get(STAGE_LABEL) != '1'
                    or labels.get(STAGE_LABEL + '.nonce') != receipt['nonce']
                    or labels.get(STAGE_LABEL + '.image') != receipt['image_id']
                    or labels.get(STAGE_LABEL + '.owner') != self._owner_label(receipt)
                    or image != receipt['image_id']):
                raise ModelContainerUnavailable('MODEL_STAGE_CONTAINER_OWNERSHIP_MISMATCH')
            progress_tick()
            self._run(('kill', '--signal=KILL', cid), timeout=10)
            progress_tick()
            self._run(('rm', '--force', cid), timeout=20)
            progress_tick()
        if self._list_stage_by_nonce(receipt['nonce']):
            raise ModelContainerUnavailable('MODEL_STAGE_CONTAINER_REMAINS')
        if progress_error:
            raise progress_error[0]

    def _stage_volume(self, manifest, records, receipt, *, progress_callback=None):
        name = 'fw-model-' + receipt['nonce']
        receipt['volumes'] = [name]
        _write_receipt(self.registry_dir / ('.model-' + receipt['nonce'] + '.cleanup.json'), receipt)
        labels = [f'--label={STAGE_LABEL}=1', f'--label={STAGE_LABEL}.nonce={receipt["nonce"]}',
                  f'--label={STAGE_LABEL}.image={receipt["image_id"]}',
                  f'--label={STAGE_LABEL}.owner={self._owner_label(receipt)}']
        _call_progress(progress_callback, force=True)
        created = self._run(('volume', 'create', *labels, name), timeout=30, capture=True)
        if created.returncode != 0 or created.stdout.decode('ascii', 'ignore').strip() != name:
            raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_CREATE_FAILED')
        _call_progress(progress_callback, force=True)
        self._inspect_volume(name, receipt)
        argv = _docker('run', '--pull=never', '--rm', '--interactive', '--platform=linux/amd64',
            '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges=true',
            '--user=0:0', '--memory=512m', '--memory-swap=512m', '--cpus=2', '--pids-limit=32',
            '--ulimit=core=0', '--ulimit=nofile=64:64', '--log-driver=none',
            *labels, '--env=' + STAGE_ROOT_ENV, '--mount',
            f'type=volume,source={name},target=/stage,volume-nocopy',
            '--entrypoint=/usr/local/bin/python', self.image_id, '-I', '-B', '-c', STAGER_CODE)
        budget = receipt['write_budget']
        budget['stage_start_pending'] = True
        _write_receipt(self.registry_dir / ('.model-' + receipt['nonce'] + '.cleanup.json'), receipt)
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=self.env, bufsize=0)
        except OSError:
            budget['stage_start_pending'] = False
            _write_receipt(self.registry_dir / ('.model-' + receipt['nonce'] + '.cleanup.json'), receipt)
            raise ModelContainerUnavailable('MODEL_STAGE_START_FAILED') from None
        budget['stage_start_pending'] = False
        budget['stage_started'] = True
        try:
            _call_progress(progress_callback, force=True)
            _write_receipt(self.registry_dir / ('.model-' + receipt['nonce'] + '.cleanup.json'), receipt)
        except BaseException:
            proc.kill()
            proc.wait(timeout=10)
            self._cleanup_stage_container(receipt)
            raise
        failure = []
        progress = StageProgressCounter()
        def stream():
            try:
                write_stage_tar(proc.stdin, manifest, records, progress=progress)
                proc.stdin.close()
            except BaseException as exc:
                failure.append(exc)
                try: proc.stdin.close()
                except OSError: pass
        writer = threading.Thread(target=stream, daemon=True)
        writer.start()
        try:
            _wait_for_stage_writer(writer, progress, progress_callback=progress_callback)
        except BaseException:
            proc.kill()
            proc.wait(timeout=10)
            writer.join(timeout=5)
            self._cleanup_stage_container(receipt)
            if writer.is_alive():
                raise ModelContainerUnavailable('MODEL_STAGE_WRITER_UNCONFIRMED')
            raise
        _call_progress(progress_callback, force=True)
        try:
            code = _wait_for_stage_helper(proc, progress_callback=progress_callback, timeout=30)
        except subprocess.TimeoutExpired:
            # The helper wait consumes up to 30s of the 45s lease. Renew before
            # the bounded reap, and between reap and Docker cleanup. If renewal
            # is denied, still finish exact-resource cleanup before propagating.
            renewal_error = None
            try:
                _call_progress(progress_callback, force=True)
            except BaseException as exc:
                renewal_error = exc
            proc.kill(); proc.wait(timeout=10)
            self._cleanup_stage_container(receipt, progress_callback=progress_callback)
            if renewal_error is not None:
                raise renewal_error
            raise ModelContainerUnavailable('MODEL_STAGE_EXIT_UNCONFIRMED') from None
        self._cleanup_stage_container(receipt, progress_callback=progress_callback)
        if failure or code != 0:
            raise ModelContainerUnavailable('MODEL_STAGE_VERIFY_FAILED')
        _call_progress(progress_callback, force=True)
        if self._inspect_volume(name, receipt) is None:
            raise ModelContainerUnavailable('MODEL_STAGE_VOLUME_MISSING')
        budget['stage_complete'] = True
        _write_receipt(self.registry_dir / ('.model-' + receipt['nonce'] + '.cleanup.json'), receipt)
        return name

    def _read_cid(self, path):
        try:
            _no_reparse(path)
            text = path.read_text(encoding='ascii').strip()
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError):
            raise ModelContainerUnavailable('MODEL_CID_UNREADABLE') from None
        if not text:
            return None
        if not CONTAINER_ID_RE.fullmatch(text):
            raise ModelContainerUnavailable('MODEL_CID_INVALID')
        return text

    def _inspect_owned(self, cid, nonce, image_id=None):
        # Full Docker container JSON includes mounts, environment and host config
        # and can exceed the strict 4 KiB CLI output bound. Cleanup and liveness
        # need only these pinned identity fields and the two state scalars.
        projection = ('{{.Id}} {{.Image}} {{json .Config.Labels}} '
                      '{{.State.Running}} {{.State.ExitCode}}')
        result = self._run(('container', 'inspect', '--format=' + projection, cid), capture=True)
        if result.returncode != 0:
            if self._list_by_id(cid):
                raise ModelContainerUnavailable('MODEL_CONTAINER_INSPECT_FAILED')
            return None
        try:
            raw = result.stdout.decode('utf-8').strip()
            cid_value, image, encoded_labels = raw.split(' ', 2)
            labels, end = json.JSONDecoder(object_pairs_hook=_unique_pairs).raw_decode(encoded_labels)
            running, exit_code = encoded_labels[end:].strip().split(' ')
            if running not in {'true', 'false'} or not exit_code.isdecimal():
                raise ValueError()
            state = {'Running':running == 'true', 'ExitCode':int(exit_code)}
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise ModelContainerUnavailable('MODEL_CONTAINER_INSPECT_INVALID') from None
        if (cid_value != cid or image != (image_id or self.image_id) or type(labels) is not dict
                or labels.get(MODEL_LABEL) != '1'
                or labels.get(MODEL_LABEL + '.nonce') != nonce
                or type(state.get('Running')) is not bool or not 0 <= state['ExitCode'] <= 255):
            raise ModelContainerUnavailable('MODEL_CONTAINER_OWNERSHIP_MISMATCH')
        return state

    def _cleanup(self, receipt_path, receipt, cid_path, *, retain_receipt=False):
        nonce, cid = receipt['nonce'], None
        try:
            by_nonce = self._list_by_nonce(nonce)
            cid = self._read_cid(cid_path)
            if cid and by_nonce and by_nonce[0] != cid:
                raise ModelContainerUnavailable('MODEL_CID_LABEL_MISMATCH')
            owned = by_nonce[0] if by_nonce else cid
            if owned:
                present = self._list_by_id(owned)
                if present:
                    state = self._inspect_owned(owned, nonce, receipt['image_id'])
                    if state is None:
                        # Container disappearance between inspect queries is fine
                        # only after fresh positive absence checks below.
                        pass
                    else:
                        self._run(('kill', '--signal=KILL', owned), timeout=10)
                    # Remove only the container tied to this durable nonce and CID.
                    self._run(('rm', '--force', owned), timeout=20)
            if self._list_by_nonce(nonce):
                raise ModelContainerUnavailable('MODEL_CLEANUP_UNCONFIRMED')
            if cid and self._list_by_id(cid):
                raise ModelContainerUnavailable('MODEL_CLEANUP_UNCONFIRMED')
            self._cleanup_stage_container(receipt)
            self._cleanup_volumes(receipt)
            self._finish_run_budget(receipt)
        except ModelContainerUnavailable as exc:
            receipt['state'] = 'cleanup_required'
            receipt['cleanup_error'] = exc.code[:80]
            receipt['updated_utc'] = time.time()
            _write_receipt(receipt_path, receipt)
            raise ModelContainerUnavailable('MODEL_CLEANUP_REQUIRED') from None
        except BaseException:
            receipt['state'] = 'cleanup_required'
            receipt['cleanup_error'] = 'MODEL_CLEANUP_UNCONFIRMED'
            receipt['updated_utc'] = time.time()
            _write_receipt(receipt_path, receipt)
            raise ModelContainerUnavailable('MODEL_CLEANUP_REQUIRED') from None
        if not retain_receipt:
            cid_path.unlink(missing_ok=True)
            receipt_path.unlink(missing_ok=True)

    def recover_stale(self):
        try:
            paths = list(self.registry_dir.glob('.model-*.cleanup.json'))
        except OSError:
            raise ModelContainerUnavailable('MODEL_CLEANUP_REGISTRY_UNAVAILABLE') from None
        for path in paths:
            receipt = self._read_receipt(path)
            if receipt['state'] == 'resolved':
                path.unlink(missing_ok=True)
                continue
            if path in self._active:
                raise ModelContainerUnavailable('MODEL_CONTAINER_ALREADY_ACTIVE')
            if self._owner_alive(receipt):
                raise ModelContainerUnavailable('MODEL_CONTAINER_OWNER_STILL_ALIVE')
            self._cleanup(path, receipt, path.parent / receipt['cid_file'])

    def _new_receipt(self):
        nonce = uuid.uuid4().hex
        cid_path = self.registry_dir / ('.model-' + nonce + '.cid')
        receipt_path = self.registry_dir / ('.model-' + nonce + '.cleanup.json')
        receipt = {'schema': RECEIPT_SCHEMA, 'state': 'active', 'nonce': nonce,
                   'cid_file': cid_path.name, 'owner_pid': os.getpid(),
                   'owner_created': psutil.Process().create_time(), 'image_id': self.image_id}
        _write_receipt(receipt_path, receipt, exclusive=True)
        self._active.add(receipt_path)
        return receipt_path, receipt, cid_path

    def _cleanup_failed_start(self, receipt_path, receipt, cid_path):
        try:
            self._cleanup(receipt_path, receipt, cid_path)
        except ModelContainerUnavailable:
            self._active.add(receipt_path)
            raise
        self._active.discard(receipt_path)

    @property
    def has_unresolved_container(self):
        return bool(self._active)

    def _start(self, operation, module, args, *, mounts=(), stage_sources=(), input_bytes=None,
               output_tmpfs=False, timeout=MAX_WALL_SECONDS, progress_callback=None):
        if mounts:
            raise ModelContainerUnavailable('MODEL_HOST_BIND_MOUNTS_DISABLED')
        if timeout <= 0 or timeout > MAX_WALL_SECONDS:
            raise ModelContainerUnavailable('MODEL_WALL_LIMIT_INVALID')
        if input_bytes is not None and (type(input_bytes) is not bytes or len(input_bytes) > 1_000_000):
            raise ModelContainerUnavailable('MODEL_STDIN_BOUNDS')
        self.recover_stale()
        receipt_path, receipt, cid_path = self._new_receipt()
        nonce = receipt['nonce']
        staged_bytes = 0
        try:
            if progress_callback is not None:
                progress_callback()
            stage_manifest, stage_records = (collect_stage_inputs(stage_sources,
                progress_callback=progress_callback) if stage_sources
                                              else (None, []))
            if stage_manifest is not None:
                staged_bytes = int(json.loads(stage_manifest.decode('ascii'))['total_bytes'])
            output_bytes = self._reserve_run_budget(receipt, staged_bytes, output_tmpfs=output_tmpfs)
            if stage_sources:
                self._stage_volume(stage_manifest, stage_records, receipt,
                                   progress_callback=progress_callback)
        except BaseException:
            self._cleanup_failed_start(receipt_path, receipt, cid_path)
            raise
        argv = _docker('run', '--pull=never', '--platform=linux/amd64',
            '--cidfile', str(cid_path), '--network=none', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges=true', '--user=65532:65532',
            '--memory=2g', '--memory-swap=2g', '--cpus=2', '--pids-limit=64',
            '--ulimit=core=0', '--ulimit=nofile=128:128', '--ulimit=fsize=2147483648:2147483648',
            '--shm-size=64m', '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m',
            '--workdir=/app', '--log-driver=none',
            f'--label={MODEL_LABEL}=1', f'--label={MODEL_LABEL}.nonce={nonce}',
            f'--env=OMP_NUM_THREADS=2', f'--env=MKL_NUM_THREADS=2', f'--env=PYTHONDONTWRITEBYTECODE=1',
            f'--env=FW_CHILD_RECEIPT={OUTPUT_RECEIPT if output_tmpfs else INFERENCE_RECEIPT}')
        if output_tmpfs:
            # The staged volume pre-creates output/ as root 0755; current runc makes a tmpfs
            # inherit that mountpoint's owner/mode, so the 65532 child needs an explicit mode.
            argv += [f'--tmpfs={OUTPUT_CONTAINER}:rw,noexec,nosuid,nodev,size={output_bytes},mode=1777']
            argv += ['--env=TMPDIR=' + OUTPUT_CONTAINER + '/tmp']
        if stage_sources:
            argv += ['--mount', f'type=volume,source=fw-model-{nonce},target=/workspace,readonly,volume-nocopy']
        if input_bytes is not None:
            argv.append('--interactive')
        argv += [self.image_id, operation, module, *args]
        budget = receipt['write_budget']
        budget['child_start_pending'] = True
        try:
            _write_receipt(receipt_path, receipt)
            _call_progress(progress_callback, force=True)
        except BaseException:
            self._cleanup_failed_start(receipt_path, receipt, cid_path)
            raise
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=self.env, bufsize=0)
        except OSError:
            budget['child_start_pending'] = False
            try: _write_receipt(receipt_path, receipt)
            except ModelContainerUnavailable: pass
            self._cleanup_failed_start(receipt_path, receipt, cid_path)
            raise ModelContainerUnavailable('MODEL_DOCKER_START_FAILED') from None
        budget['child_start_pending'] = False
        budget['child_started'] = True
        try:
            _call_progress(progress_callback, force=True)
            _write_receipt(receipt_path, receipt)
        except BaseException:
            proc.kill()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: pass
            self._cleanup_failed_start(receipt_path, receipt, cid_path)
            raise
        process = ModelContainerProcess(self, proc, receipt_path, receipt, cid_path,
                                        timeout=timeout, output_tmpfs=output_tmpfs)
        try:
            _call_progress(progress_callback, force=True)
        except BaseException:
            try:
                process.cleanup()
            except ModelContainerUnavailable:
                self._active.add(receipt_path)
            raise
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            cid = self._read_cid(cid_path)
            if cid:
                process.cid = cid
                break
            if proc.poll() is not None:
                break
            time.sleep(.025)
        if not process.cid:
            renewal_error = None
            try:
                _call_progress(progress_callback, force=True)
            except BaseException as exc:
                renewal_error = exc
            try:
                process.cleanup()
            except ModelContainerUnavailable:
                self._active.add(receipt_path)
                raise
            if renewal_error is not None:
                raise renewal_error
            exit_code = process.proc.returncode
            if type(exit_code) is int and exit_code != 0:
                suffix = f'NEG{abs(exit_code)}' if exit_code < 0 else str(exit_code)
                raise ModelContainerUnavailable('MODEL_CONTAINER_START_EXIT_' + suffix)
            raise ModelContainerUnavailable('MODEL_CONTAINER_START_FAILED')
        try:
            _call_progress(progress_callback, force=True)
            process.verify_identity()
        except BaseException:
            try: process.cleanup()
            except ModelContainerUnavailable: pass
            raise
        if input_bytes is not None:
            input_error = []
            written_done = threading.Event()
            def write_input():
                try:
                    view, offset = memoryview(input_bytes), 0
                    while offset < len(view):
                        written = process.proc.stdin.write(view[offset:])
                        if type(written) is not int or written <= 0:
                            raise BrokenPipeError()
                        offset += written
                    process.proc.stdin.flush()
                except (BrokenPipeError, OSError) as exc:
                    input_error.append(exc)
                finally:
                    try: process.proc.stdin.close()
                    except OSError: pass
                    written_done.set()
            writer = threading.Thread(target=write_input, daemon=True)
            try:
                _call_progress(progress_callback, force=True)
            except BaseException:
                try:
                    process.cleanup()
                except ModelContainerUnavailable:
                    self._active.add(receipt_path)
                raise
            writer.start()
            writer.join(timeout=20)
            if writer.is_alive():
                process.cleanup()
                raise ModelContainerUnavailable('MODEL_STDIN_WRITE_TIMEOUT')
            if input_error:
                process.cleanup()
                raise ModelContainerUnavailable('MODEL_STDIN_WRITE_FAILED') from None
            try:
                _call_progress(progress_callback, force=True)
            except BaseException:
                try:
                    process.cleanup()
                except ModelContainerUnavailable:
                    self._active.add(receipt_path)
                raise
        return process

    def start_training(self, input_dir, export_dir, config, *, resume_dir=None,
                       resume_digest=None, timeout=MAX_WALL_SECONDS, progress_callback=None):
        inputs = _mount_dir(input_dir)
        exported = _mount_dir(export_dir, require_empty=True)
        args = ['--inputs', '/workspace/input', '--out', TRAINING_CONTAINER,
                '--dataset-digest', config['version_digest'], '--recipe-digest', config['recipe_digest'],
                '--preprocess-digest', config['preprocess_digest'],
                '--decoder-image-id', config['decoder_image_id'], '--epochs', str(config['epochs']),
                '--seed', str(config['seed']), '--batch-size', str(config['batch_size']),
                '--learning-rate', config['learning_rate']]
        sources = [('input', inputs)]
        if resume_dir is not None:
            if not isinstance(resume_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', resume_digest):
                raise ModelContainerUnavailable('MODEL_RESUME_DIGEST_REQUIRED')
            resume = _mount_dir(resume_dir)
            sources.append(('resume', resume))
            args += ['--resume', '/workspace/resume', '--expected-checkpoint-digest', resume_digest]
        process = self._start('training', 'fieldwork.real_train_child', args, stage_sources=sources,
                              output_tmpfs=True, timeout=min(timeout, MAX_WALL_SECONDS),
                              progress_callback=progress_callback)
        process.operation = 'training'
        process.export_dir = exported
        return process

    def start_inference(self, bundle_dir, pixel_dir, sample_entry, bundle_digest, *, model_image_id,
                        scope='real-inference/v1',
                        timeout=90, progress_callback=None):
        bundle = _mount_dir(bundle_dir)
        pixels = _mount_dir(pixel_dir)
        if model_image_id != self.image_id:
            raise ModelContainerUnavailable('MODEL_IMAGE_CONFIG_MISMATCH')
        if (type(sample_entry) is not dict or set(sample_entry) !=
                {'id', 'split', 'pixel_file', 'width', 'height', 'decoded_pixel_sha256'}
                or scope not in {'real-inference/v1', 'real-image-inference/v1'}
                or sample_entry.get('split') not in ({'train', 'validation'} if scope == 'real-inference/v1' else {'upload'})):
            raise ModelContainerUnavailable('MODEL_INFERENCE_INPUT_SCHEMA')
        entry = json.dumps(sample_entry, separators=(',', ':'), ensure_ascii=True)
        if len(entry) > 4096:
            raise ModelContainerUnavailable('MODEL_INFERENCE_INPUT_BOUNDS')
        process = self._start('inference', 'fieldwork.real_infer_child',
            ['--bundle', '/workspace/bundle', '--pixel-root', '/workspace/pixels',
             '--sample-entry', entry, '--expected-bundle-digest', bundle_digest,
             '--expected-model-image-id', model_image_id, '--scope', scope],
            stage_sources=[('bundle', bundle), ('pixels', pixels)],
            timeout=min(timeout, MAX_WALL_SECONDS), progress_callback=progress_callback)
        process.operation = 'inference'
        return process

    def start_qualified_inference(self, bundle_dir, pixel_dir, sample_entry, *,
            bundle_digest, model_digest, plan_id, plan_result_sha256,
            model_image_id, timeout=90, progress_callback=None):
        """Run only the one pinned R5 release through the same offline bounded child."""
        from .qualified_release import (RELEASE_ID, PLAN_ID, PLAN_RESULT_SHA256,
            MODEL_SHA256, MANIFEST_SHA256)
        bundle = _mount_dir(bundle_dir)
        pixels = _mount_dir(pixel_dir)
        if (model_image_id != self.image_id or bundle_digest != MANIFEST_SHA256
                or model_digest != MODEL_SHA256 or plan_id != PLAN_ID
                or plan_result_sha256 != PLAN_RESULT_SHA256):
            raise ModelContainerUnavailable('QUALIFIED_RELEASE_PIN_MISMATCH')
        if (type(sample_entry) is not dict or set(sample_entry) !=
                {'id', 'split', 'pixel_file', 'width', 'height', 'decoded_pixel_sha256'}
                or sample_entry.get('split') != 'upload'):
            raise ModelContainerUnavailable('QUALIFIED_INFERENCE_INPUT_SCHEMA')
        entry = json.dumps(sample_entry, separators=(',', ':'), ensure_ascii=True)
        if len(entry) > 4096:
            raise ModelContainerUnavailable('MODEL_INFERENCE_INPUT_BOUNDS')
        args = ['--bundle', '/workspace/bundle', '--pixel-root', '/workspace/pixels',
            '--sample-entry', entry, '--expected-bundle', bundle_digest,
            '--expected-model', model_digest, '--expected-plan', plan_id,
            '--expected-result', plan_result_sha256, '--expected-model-image', model_image_id]
        process = self._start('qualified-inference', 'fieldwork.qualified_infer_child', args,
            stage_sources=[('bundle', bundle), ('pixels', pixels)],
            timeout=min(timeout, MAX_WALL_SECONDS), progress_callback=progress_callback)
        process.operation = 'qualified-inference:' + RELEASE_ID
        return process

    def start_bundle(self, input_dir, checkpoint_dir, artifact_export_dir, *, expected_checkpoint_digest,
                     version_id, version_digest, classes, rights_decision_digests, model_image_id,
                     timeout=MAX_WALL_SECONDS):
        inputs, checkpoint = _mount_dir(input_dir), _mount_dir(checkpoint_dir)
        export_root = _mount_dir(artifact_export_dir)
        if model_image_id != self.image_id:
            raise ModelContainerUnavailable('MODEL_IMAGE_CONFIG_MISMATCH')
        rights = json.dumps(rights_decision_digests, separators=(',', ':')).encode('ascii')
        if len(rights) > 1_000_000:
            raise ModelContainerUnavailable('MODEL_BUNDLE_RIGHTS_INPUT_BOUNDS')
        args = ['--checkpoint', '/workspace/checkpoint', '--inputs', '/workspace/input',
                '--out', OUTPUT_CONTAINER + '/bundle', '--expected-checkpoint-digest', expected_checkpoint_digest,
                '--version-id', version_id, '--version-digest', version_digest,
                '--classes-json', json.dumps(classes, separators=(',', ':')),
                '--model-image-id', model_image_id]
        process = self._start('bundle', 'fieldwork.real_bundle_child', args,
            stage_sources=[('input', inputs), ('checkpoint', checkpoint)],
            input_bytes=rights, output_tmpfs=True, timeout=min(timeout, MAX_WALL_SECONDS))
        process.operation = 'bundle'
        process.export_dir = export_root
        return process


class ModelContainerProcess:
    """Popen-compatible child handle whose poll/kill are container-state based."""

    def __init__(self, runner, proc, receipt_path, receipt, cid_path, *, timeout, output_tmpfs):
        self.runner, self.proc = runner, proc
        self.receipt_path, self.receipt, self.cid_path = receipt_path, receipt, cid_path
        self.cid = None
        self._identity_verified = False
        self.pid = proc.pid
        self.timeout = timeout
        self.output_tmpfs = output_tmpfs
        self.operation = None
        self.export_dir = None
        self._started = time.monotonic()
        self._closed = False
        self._probe_at = {}
        self._last_inspect = 0.0
        self._last_state = None
        self._returncode = None
        self._task_finished = False
        self._last_task_probe = 0.0

    def verify_identity(self):
        if not self.cid or self.runner._list_by_nonce(self.receipt['nonce']) != [self.cid]:
            raise ModelContainerUnavailable('MODEL_CONTAINER_NONCE_BINDING')
        if self.runner._inspect_owned(self.cid, self.receipt['nonce'], self.runner.image_id) is None:
            raise ModelContainerUnavailable('MODEL_CONTAINER_INSPECT_MISSING')
        self._identity_verified = True

    def poll(self):
        if self._returncode is not None:
            return self._returncode
        if time.monotonic() - self._started > self.timeout:
            # wait() polls: without this guard the wall-time branch re-entered itself through
            # wait() -> poll() and surfaced as RecursionError instead of the typed timeout.
            if not getattr(self, '_wall_timed_out', False):
                self._wall_timed_out = True
                self.kill()
                self.wait(timeout=30)
            raise ModelContainerUnavailable('MODEL_CONTAINER_WALL_TIMEOUT')
        if time.monotonic() - self._last_inspect >= .2:
            try:
                self._last_state = self.runner._inspect_owned(
                    self.cid, self.receipt['nonce'], self.runner.image_id)
                self._last_inspect = time.monotonic()
            except ModelContainerUnavailable:
                raise
        state = self._last_state
        if state is None:
            # A query that found the container missing is not enough unless the
            # nonce query also confirms it is absent and the CLI has exited.
            if self.runner._list_by_nonce(self.receipt['nonce']):
                raise ModelContainerUnavailable('MODEL_CONTAINER_IDENTITY_AMBIGUOUS')
            if self.proc.poll() is None:
                return None
            self._returncode = self.proc.returncode
            return self._returncode
        if state['Running']:
            if time.monotonic() - self._last_task_probe >= 1:
                self._last_task_probe = time.monotonic()
                status_path = (OUTPUT_CONTAINER if self.output_tmpfs else '/tmp') + '/.child-exit.json'
                probe = self.runner._run(('exec', self.cid, '/usr/local/bin/python', '-I', '-B', '-c',
                    "import os; p=" + repr(status_path)
                    + "; print(open(p,encoding='ascii').read(128) if os.path.isfile(p) else 'pending')"),
                    timeout=5, capture=True, limit=128)
                if probe.returncode == 0 and probe.stdout.strip() != b'pending':
                    try:
                        status = json.loads(probe.stdout.decode('ascii'), object_pairs_hook=_unique_pairs)
                        if (type(status) is not dict or set(status) != {'exit_code'}
                                or type(status['exit_code']) is not int or status['exit_code'] not in (0, 1)):
                            raise ValueError()
                    except (ValueError, TypeError, UnicodeError):
                        raise ModelContainerUnavailable('MODEL_TASK_EXIT_RECEIPT_INVALID') from None
                    self._task_finished = True
                    self._returncode = status['exit_code']
                    return self._returncode
            return None
        code = state.get('ExitCode')
        if type(code) is not int or code < 0 or code > 255:
            raise ModelContainerUnavailable('MODEL_CONTAINER_EXIT_STATE_INVALID')
        self._returncode = code
        return code

    @property
    def returncode(self):
        return self.poll()

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired('owned model container', timeout)
            time.sleep(.05)
        if not self._task_finished and self.proc.poll() is None:
            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            self.proc.wait(timeout=remaining)
        return self._returncode

    def kill(self):
        if not self.cid:
            raise ModelContainerUnavailable('MODEL_CONTAINER_CID_REQUIRED')
        state = self.runner._inspect_owned(self.cid, self.receipt['nonce'], self.runner.image_id)
        if state is not None and state['Running']:
            self.runner._run(('kill', '--signal=KILL', self.cid), timeout=10)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            state = self.runner._inspect_owned(self.cid, self.receipt['nonce'], self.runner.image_id)
            if state is None or not state['Running']:
                return
            time.sleep(.05)
        raise ModelContainerUnavailable('MODEL_CONTAINER_KILL_UNCONFIRMED')

    def _tar_from_container(self, path, *, max_bytes):
        if (path not in {INFERENCE_RECEIPT, OUTPUT_RECEIPT,
                TRAINING_CONTAINER + '/result.json', OUTPUT_CONTAINER + '/bundle'}
                and not re.fullmatch(re.escape(TRAINING_CONTAINER) + r'/epoch-(?:[1-9][0-9]{0,2})', path)):
            raise ModelContainerUnavailable('MODEL_OUTPUT_PATH_INVALID')
        if not self.cid or self.runner._list_by_nonce(self.receipt['nonce']) != [self.cid]:
            raise ModelContainerUnavailable('MODEL_CONTAINER_NONCE_BINDING')
        state = self.runner._inspect_owned(self.cid, self.receipt['nonce'], self.runner.image_id)
        if state is None or not state['Running']:
            raise ModelContainerUnavailable('MODEL_CONTAINER_NONCE_BINDING')
        try:
            proc = subprocess.Popen(_docker('exec', self.cid, '/usr/local/bin/python', '-I', '-B',
                    '-c', _OUTPUT_STREAM_PROGRAM, path, str(max_bytes)), env=self.runner.env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        except OSError:
            raise ModelContainerUnavailable('MODEL_OUTPUT_EXPORT_FAILED') from None
        output = bytearray()
        finished, overflow = threading.Event(), threading.Event()
        deadline = time.monotonic() + 30
        def drain():
            try:
                while True:
                    block = proc.stdout.read(64 * 1024)
                    if not block:
                        break
                    if len(output) + len(block) > max_bytes:
                        overflow.set()
                        break
                    output.extend(block)
            finally:
                finished.set()
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            while not finished.wait(.05):
                if overflow.is_set():
                    proc.kill()
                    proc.wait(timeout=5)
                    raise ModelContainerUnavailable('MODEL_OUTPUT_EXPORT_BOUNDS')
                if time.monotonic() > deadline:
                    proc.kill()
                    proc.wait(timeout=5)
                    raise ModelContainerUnavailable('MODEL_OUTPUT_EXPORT_TIMEOUT')
            code = proc.wait(timeout=5)
        except BaseException:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            raise
        finally:
            reader.join(timeout=2)
            if reader.is_alive():
                raise ModelContainerUnavailable('MODEL_OUTPUT_EXPORT_READER_STUCK')
        if overflow.is_set():
            raise ModelContainerUnavailable('MODEL_OUTPUT_EXPORT_BOUNDS')
        if code == 3 and not output:
            return None
        if code != 0:
            raise ModelContainerUnavailable('MODEL_OUTPUT_EXPORT_FAILED')
        return bytes(output)

    def _exists_in_container(self, path):
        safe = path
        if not safe.startswith(OUTPUT_CONTAINER + '/') or any(c in safe for c in ('\n', '\r', "'", '"')):
            raise ModelContainerUnavailable('MODEL_OUTPUT_PATH_INVALID')
        result = self.runner._run(('exec', self.cid, '/usr/local/bin/python', '-I', '-B', '-c',
            f"import os; print('yes' if os.path.isfile('{safe}') else 'no')"),
            timeout=5, capture=True, limit=128)
        if result.returncode != 0:
            raise ModelContainerUnavailable('MODEL_OUTPUT_PROBE_FAILED')
        text = result.stdout.decode('ascii', 'strict').strip()
        if text not in {'yes', 'no'}:
            raise ModelContainerUnavailable('MODEL_OUTPUT_PROBE_INVALID')
        return text == 'yes'

    @staticmethod
    def _extract_tar(raw, destination, *, expected_prefix, limits):
        if raw is None:
            return False
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
                members = archive.getmembers()
                if not members or len(members) > len(limits) + 1:
                    raise ValueError()
                expected = set(limits)
                seen = set()
                payloads = {}
                for member in members:
                    name = member.name.removeprefix('./')
                    path = PurePosixPath(name)
                    if member.isdir() and name.rstrip('/') == expected_prefix and not path.is_absolute():
                        continue
                    if expected_prefix.endswith('.json'):
                        relative = path.as_posix() if len(path.parts) == 1 else None
                    else:
                        relative = path.parts[1] if len(path.parts) == 2 and path.parts[0] == expected_prefix else None
                    if (not _safe_relative(name) or member.issym() or member.islnk()
                            or not member.isfile() or relative not in expected
                            or relative in seen or member.size > limits[relative]):
                        raise ValueError()
                    seen.add(relative)
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError()
                    body = stream.read(limits[relative] + 1)
                    if len(body) != member.size or len(body) > limits[relative]:
                        raise ValueError()
                    payloads[relative] = body
                if seen != expected:
                    raise ValueError()
            destination = Path(destination)
            destination.mkdir(parents=True, exist_ok=False)
            for name, body in payloads.items():
                with (destination / name).open('xb') as stream:
                    stream.write(body); stream.flush(); os.fsync(stream.fileno())
            return True
        except (OSError, tarfile.TarError, ValueError, KeyError):
            raise ModelContainerUnavailable('MODEL_OUTPUT_ARCHIVE_INVALID') from None

    def export_checkpoint(self, host_training_dir: Path, epoch: int, *, stopped=False):
        if type(epoch) is not int or not 1 <= epoch <= 100:
            raise ModelContainerUnavailable('MODEL_EPOCH_INVALID')
        host_training_dir = Path(host_training_dir)
        target = host_training_dir / f'epoch-{epoch}'
        if target.exists():
            return True
        internal = f'{TRAINING_CONTAINER}/epoch-{epoch}'
        due = self._probe_at.get(internal, 0.0)
        if not stopped and time.monotonic() < due:
            return False
        self._probe_at[internal] = time.monotonic() + .5
        if not stopped and not self._exists_in_container(internal + '/manifest.json'):
            return False
        raw = self._tar_from_container(internal, max_bytes=MAX_CHECKPOINT_BYTES)
        if raw is None:
            if stopped:
                raise ModelContainerUnavailable('MODEL_CHECKPOINT_EXPORT_MISSING')
            return False
        extracted = self._extract_tar(raw, target, expected_prefix=f'epoch-{epoch}', limits={
            'manifest.json': 1024 * 1024, 'state.json': 1024 * 1024,
            'state.safetensors': 32 * 1024 * 1024})
        if extracted and self.receipt.get('budget_scope_sha256'):
            self.runner._charge_budget_export(self.receipt_path, self.receipt,
                sum(p.stat().st_size for p in target.rglob('*') if p.is_file()))
        return extracted

    def export_training_result(self, host_training_dir: Path):
        raw = self._tar_from_container(TRAINING_CONTAINER + '/result.json', max_bytes=128 * 1024)
        if raw is None:
            raise ModelContainerUnavailable('MODEL_RESULT_EXPORT_MISSING')
        temp = Path(host_training_dir) / 'result.export'
        self._extract_tar(raw, temp, expected_prefix='result.json', limits={'result.json': 64 * 1024})
        target = Path(host_training_dir) / 'result.json'
        (temp / 'result.json').replace(target)
        temp.rmdir()
        if self.receipt.get('budget_scope_sha256'):
            self.runner._charge_budget_export(self.receipt_path, self.receipt, target.stat().st_size)
        return target

    def read_receipt(self):
        path = OUTPUT_RECEIPT if self.output_tmpfs else INFERENCE_RECEIPT
        raw = self._tar_from_container(path, max_bytes=MAX_STDOUT + 16 * 1024)
        if raw is None:
            raise ModelContainerUnavailable('MODEL_CHILD_RECEIPT_MISSING')
        return self._single_file_tar(raw, 'child-stdout.txt', MAX_STDOUT)

    @staticmethod
    def _single_file_tar(raw, name, limit):
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
                members = archive.getmembers()
                if len(members) != 1:
                    raise ValueError()
                member = members[0]
                actual = member.name.removeprefix('./')
                if (actual != name or not member.isfile() or member.issym() or member.islnk()
                        or member.size > limit):
                    raise ValueError()
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError()
                value = stream.read(limit + 1)
                if len(value) != member.size or len(value) > limit:
                    raise ValueError()
                return value
        except (OSError, ValueError, tarfile.TarError):
            raise ModelContainerUnavailable('MODEL_RECEIPT_ARCHIVE_INVALID') from None

    def export_bundle(self, host_bundle_dir):
        raw = self._tar_from_container(OUTPUT_CONTAINER + '/bundle', max_bytes=MAX_BUNDLE_BYTES + 2 * 1024 * 1024)
        if raw is None:
            raise ModelContainerUnavailable('MODEL_BUNDLE_EXPORT_MISSING')
        expected = {'manifest.json': 1024 * 1024, 'architecture.json': 1024 * 1024,
            'preprocess.json': 1024 * 1024, 'classes.json': 1024 * 1024,
            'lineage.json': 1024 * 1024, 'model.safetensors': 32 * 1024 * 1024,
            'rights/review.json': 1024 * 1024, 'evaluation/population.json': 8 * 1024 * 1024,
            'evaluation/metrics.json': 2 * 1024 * 1024,
            'evaluation/independent-report.json': 2 * 1024 * 1024,
            'evaluation/predictions.jsonl': 32 * 1024 * 1024}
        result = self._extract_bundle_tar(raw, host_bundle_dir, expected)
        if self.receipt.get('budget_scope_sha256'):
            self.runner._charge_budget_export(self.receipt_path, self.receipt,
                sum(p.stat().st_size for p in result.rglob('*') if p.is_file()))
        return result

    @staticmethod
    def _extract_bundle_tar(raw, destination, limits):
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
                members = archive.getmembers()
                if len(members) > len(limits) + 3:
                    raise ValueError()
                seen, payloads = set(), {}
                for member in members:
                    name = member.name.removeprefix('./')
                    path = PurePosixPath(name)
                    if member.isdir() and name.rstrip('/') in {'bundle', 'bundle/evaluation', 'bundle/rights'}:
                        continue
                    relative = path.relative_to('bundle').as_posix() if path.parts and path.parts[0] == 'bundle' else None
                    if (not _safe_relative(name) or member.issym() or member.islnk()
                            or not member.isfile() or relative not in limits or relative in seen
                            or member.size > limits[relative]):
                        raise ValueError()
                    seen.add(relative)
                    stream = archive.extractfile(member)
                    if stream is None: raise ValueError()
                    data = stream.read(limits[relative] + 1)
                    if len(data) != member.size or len(data) > limits[relative]: raise ValueError()
                    payloads[relative] = data
            if seen != set(limits) or sum(map(len, payloads.values())) > MAX_BUNDLE_BYTES:
                raise ValueError()
            destination = Path(destination)
            destination.mkdir(parents=True, exist_ok=False)
            for name, data in payloads.items():
                target = destination.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
            return destination
        except (OSError, tarfile.TarError, ValueError, KeyError):
            raise ModelContainerUnavailable('MODEL_BUNDLE_ARCHIVE_INVALID') from None

    def cleanup(self):
        if self._closed:
            return
        if self.output_tmpfs and self.receipt.get('budget_scope_sha256'):
            try:
                child_output = self._measure_output_bytes()
            except ModelContainerUnavailable:
                child_output = self.receipt['write_budget']['output_tmpfs_cap_bytes']
            self.runner._record_child_output(self.receipt_path, self.receipt, child_output)
        # Keep the durable nonce receipt until both the Docker container and its
        # local CLI are proven gone. If Docker failed before writing a CID file,
        # first reap the exact Popen handle, then reconcile by the unguessable
        # receipt nonce and the fixed image/ownership labels.
        if self.cid is not None:
            self.runner._cleanup(self.receipt_path, self.receipt, self.cid_path,
                                 retain_receipt=True)
        if self.proc.poll() is None:
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                try:
                    self.proc.kill()
                    self.proc.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    raise ModelContainerUnavailable('MODEL_DOCKER_CLI_EXIT_UNCONFIRMED') from None
        if self.proc.poll() is None:
            raise ModelContainerUnavailable('MODEL_DOCKER_CLI_EXIT_UNCONFIRMED')
        self.runner._cleanup(self.receipt_path, self.receipt, self.cid_path)
        self.runner._active.discard(self.receipt_path)
        self._closed = True

    def _measure_output_bytes(self):
        cap = self.receipt['write_budget']['output_tmpfs_cap_bytes']
        if not self.cid or not self._identity_verified:
            raise ModelContainerUnavailable('MODEL_RUN_OUTPUT_MEASURE_UNAVAILABLE')
        program = ("import os,stat; root='/workspace/output'; total=0; "
            "\nfor base,dirs,files in os.walk(root,topdown=True,followlinks=False):\n"
            " for name in dirs+files:\n"
            "  p=os.path.join(base,name); s=os.lstat(p)\n"
            "  if stat.S_ISLNK(s.st_mode) or not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)): raise SystemExit(2)\n"
            "  if stat.S_ISREG(s.st_mode): total+=s.st_size\n"
            f"  if total>{cap}: raise SystemExit(3)\n"
            "print(total)")
        result = self.runner._run(('exec', self.cid, '/usr/local/bin/python', '-I', '-B', '-c', program),
                                  timeout=10, capture=True, limit=128)
        if result.returncode != 0:
            raise ModelContainerUnavailable('MODEL_RUN_OUTPUT_MEASURE_FAILED')
        raw = result.stdout.decode('ascii', 'strict').strip()
        if not re.fullmatch(r'0|[1-9][0-9]{0,12}', raw):
            raise ModelContainerUnavailable('MODEL_RUN_OUTPUT_MEASURE_INVALID')
        value = int(raw)
        if value > cap:
            raise ModelContainerUnavailable('MODEL_RUN_OUTPUT_BOUNDS')
        return value

    def communicate(self, timeout=None):
        self.wait(timeout)
        payload = self.read_receipt()
        return payload, b''
