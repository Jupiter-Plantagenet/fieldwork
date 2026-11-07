"""Round-5 recipe exploration on VALIDATION ONLY (small-residual/v1), one complete config per call.

Usage: python -B tools/r5_train.py --tag r5cfg2 --config '{"epochs":40,...}' --why "..."

- Loads ONLY train+validation rows of the frozen child version (JSONB path filter in SQL,
  so no protected row is ever loaded by the researcher process) and re-verifies signed
  local_private_training rights for every one of them.
- Exploration cap: exact immutable round-4 cfg1 baseline plus at most 5 round-5
  configurations and <=24 CPU-hours charged in total. Every attempt is hash-chained;
  a missing ledger/history fails closed and is never recreated from defaults.
- Each attempt reserves <=4 CPU-hours (or the exact remaining global budget less a
  guard). A Windows Job Object limits the training child tree and a conservative
  wall deadline terminates stalled work before the reservation can be exceeded.
- The internal child path requires a distinct live parent, exact active reservation,
  nonce-bound start gate, actual parent lock ownership, and a current bounded Job Object.
- A durable spawn-intent separates verifiably never-spawned reservations from the
  ambiguous Popen-to-PID-record interval; the latter is never auto-recovered.
- One valid unanchored history event can be reconciled explicitly under the metadata
  product lock, after archiving the inconsistent byte snapshot. Other divergence fails closed.
- Local Windows operator/admin and all source/state files remain a trusted boundary.
- Host protocol (tools/r5_host.py) around training AND validation inference.
- After training (still holding the slot): validation predictions of the selected
  checkpoint, production metric-spec/v1 and the independent stdlib verifier.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psutil
import torch
from round5_common import C5, EVIDENCE, ROOT, admin_dsn, context, request_store, resolve_media, set_registry_env, write_json
from r5_host import (CPU_TIME_TICKS_PER_SECOND, JOB_OBJECT_LIMIT_JOB_TIME,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, heavy_slot, lock_identity, metadata_lock,
    recover_stale_pause, run_bounded_child, folio_health, verify_current_job_budget)
from safetensors.torch import save_file
from fieldwork import residual_recipe as rr
from fieldwork.data import canonical
from fieldwork.metrics import evaluate
from fieldwork.real_training import center, load_resized, to_tensor
from fieldwork.rights import RightsService
from fieldwork.rights_registry import load_trusted_registry
from fieldwork.store import Store

LEDGER = EVIDENCE / 'optimize/config-ledger.json'
HISTORY = EVIDENCE / 'optimize/config-history.jsonl'
ANCHOR = ROOT / '.local/round5-resume/r5-training-budget-anchor.json'
BOOTSTRAP_RECEIPT = ROOT / '.local/round5-resume/r5-training-budget-bootstrap.json'
CAP_CONFIGS_TOTAL = 6
CAP_CPU_SECONDS = 24 * 60 * 60
MAX_RUN_CPU_SECONDS = 4 * 60 * 60
CPU_GUARD_SECONDS = 30
CPU_PARALLELISM_BOUND = 3  # two configured Torch threads plus wrapper/verifier overhead
ROUND4_CONFIG1 = {'tag': 'cfg1', 'recipe': 'compact-cnn/v1', 'validation_accuracy': 0.70182, 'elapsed_s': 635.8, 'round': 4}
ROUND4_CONFIGS = (ROUND4_CONFIG1,)
CAP_HOURS = 24.0
VERIFIER = ROOT / 'tools/verify_population_metrics.py'


def version_ref():
    seal = json.loads((EVIDENCE / 'holdout/r5-seal.json').read_text())
    return seal['version_id'], seal['version_digest']


def training_view(op, ws, vid):
    with op.connect() as c:
        r = c.execute('''SELECT manifest->>'digest' AS digest, manifest->>'version_id' AS version_id, manifest->>'rights_dataset_id' AS rds,
            jsonb_path_query_array(manifest, '$.samples[*] ? (@.split == "train" || @.split == "validation")') AS samples
            FROM fw_versions WHERE workspace=%s AND id=%s AND state='frozen' ''', (ws, vid)).fetchone()
    samples=[dict(s,file=resolve_media(s['file'])) for s in r['samples']]
    return {'digest': r['digest'], 'version_id': r['version_id'], 'rights_dataset_id': r['rds'], 'samples': samples}


def verify_trainval_rights(service, workspace, rights_dataset_id, actor, samples):
    """Recheck signed rights for only the explicit members in a train/validation view."""
    if not isinstance(samples, list) or not samples:
        raise SystemExit('TRAINING_VIEW_EMPTY')
    if type(rights_dataset_id) is not str or not rights_dataset_id:
        raise SystemExit('TRAINING_RIGHTS_DATASET_INVALID')
    members = set()
    for sample in samples:
        if sample.get('split') not in ('train', 'validation'):
            raise SystemExit('TRAINING_VIEW_SPLIT_BOUNDARY')
        member = sample.get('source_member')
        if type(member) is not str or not member:
            raise SystemExit('TRAINING_RIGHTS_MEMBER_INVALID')
        members.add(member)
    decisions = service.require_members(workspace, rights_dataset_id, actor,
                                        'local_private_training', sorted(members))
    verified = {decision.member_id: decision.asset_sha256 for decision in decisions}
    if len(verified) != len(members) or any(verified.get(sample['source_member']) != sample.get('sha256')
                                            for sample in samples):
        raise SystemExit('RIGHTS_NOT_VERIFIED_FOR_TRAINING_INPUT')
    return len(verified)


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _event_digest(record):
    return hashlib.sha256(_json_bytes(record)).hexdigest()


def _genesis_event():
    payload = {'cap_configs_total': CAP_CONFIGS_TOTAL, 'cap_cpu_seconds_total': CAP_CPU_SECONDS,
               'round4_baseline': ROUND4_CONFIG1}
    event = {'seq': 0, 'kind': 'genesis', 'previous_digest': '0' * 64, 'payload': payload}
    return {**event, 'digest': _event_digest(event)}


def _genesis_ledger(event=None):
    event = event or _genesis_event()
    return {'schema_version': 2, 'cap_configs_total': CAP_CONFIGS_TOTAL,
            'cap_cpu_seconds_total': CAP_CPU_SECONDS, 'configs': [dict(ROUND4_CONFIG1)],
            'history_seq': 0, 'history_digest': event['digest']}


def _anchor_paths(path, anchor_path=None, receipt_path=None):
    path = Path(path)
    if anchor_path is None:
        anchor_path = ANCHOR if path.resolve() == LEDGER.resolve() else path.with_name('config-budget-anchor.json')
    if receipt_path is None:
        receipt_path = BOOTSTRAP_RECEIPT if path.resolve() == LEDGER.resolve() else path.with_name('config-budget-bootstrap.json')
    return Path(anchor_path), Path(receipt_path)


def _read_anchor_record(anchor_path, receipt_path):
    anchor_path, receipt_path = Path(anchor_path), Path(receipt_path)
    for path, error in ((anchor_path, 'LEDGER_ANCHOR_MISSING_OR_UNSAFE'),
                        (receipt_path, 'LEDGER_BOOTSTRAP_RECEIPT_MISSING_OR_UNSAFE')):
        if path.is_symlink() or not path.is_file():
            raise SystemExit(error)
    try:
        anchor = json.loads(anchor_path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
        receipt = json.loads(receipt_path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit('LEDGER_ANCHOR_MALFORMED') from exc
    if not isinstance(receipt, dict) or set(receipt) != {'schema_version', 'bootstrap_id', 'initialized_utc',
            'source_sha256', 'baseline_sha256', 'genesis_digest'} or receipt.get('schema_version') != 1:
        raise SystemExit('LEDGER_BOOTSTRAP_RECEIPT_INVALID')
    if (not isinstance(receipt['bootstrap_id'], str) or not re.fullmatch('[a-f0-9]{32}', receipt['bootstrap_id'])
            or not re.fullmatch('[a-f0-9]{64}', str(receipt['source_sha256']))
            or receipt['baseline_sha256'] != _event_digest(ROUND4_CONFIG1)
            or receipt['genesis_digest'] != _genesis_event()['digest']):
        raise SystemExit('LEDGER_BOOTSTRAP_RECEIPT_INVALID')
    try:
        initialized = datetime.fromisoformat(receipt['initialized_utc'].replace('Z', '+00:00'))
    except (TypeError, ValueError, AttributeError) as exc:
        raise SystemExit('LEDGER_BOOTSTRAP_RECEIPT_INVALID') from exc
    if initialized.tzinfo is None or initialized.utcoffset() is None:
        raise SystemExit('LEDGER_BOOTSTRAP_RECEIPT_INVALID')
    expected_keys = {'schema_version', 'bootstrap_id', 'history_seq', 'history_digest',
                     'ledger_sha256', 'history_sha256'}
    if not isinstance(anchor, dict) or set(anchor) != expected_keys or anchor.get('schema_version') != 1:
        raise SystemExit('LEDGER_ANCHOR_INVALID')
    if (anchor['bootstrap_id'] != receipt['bootstrap_id'] or type(anchor['history_seq']) is not int
            or anchor['history_seq'] < 0 or not re.fullmatch('[a-f0-9]{64}', str(anchor['history_digest']))
            or not re.fullmatch('[a-f0-9]{64}', str(anchor['ledger_sha256']))
            or not re.fullmatch('[a-f0-9]{64}', str(anchor['history_sha256']))):
        raise SystemExit('LEDGER_ANCHOR_INVALID')
    return anchor, receipt


def _read_anchor(anchor_path, receipt_path, ledger_path, history_path, value):
    anchor, receipt = _read_anchor_record(anchor_path, receipt_path)
    if anchor['history_seq'] != value['history_seq'] or anchor['history_digest'] != value['history_digest']:
        raise SystemExit('LEDGER_ANCHOR_DIVERGED')
    ledger_digest = hashlib.sha256(Path(ledger_path).read_bytes()).hexdigest()
    history_digest = hashlib.sha256(Path(history_path).read_bytes()).hexdigest()
    if anchor['ledger_sha256'] != ledger_digest or anchor['history_sha256'] != history_digest:
        raise SystemExit('LEDGER_ANCHOR_DIVERGED')
    return receipt


def _write_anchor(anchor_path, receipt_path, ledger_path, history_path, value):
    anchor_path, receipt_path = _anchor_paths(ledger_path, anchor_path, receipt_path)
    receipt = json.loads(Path(receipt_path).read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
    anchor = {'schema_version': 1, 'bootstrap_id': receipt['bootstrap_id'],
              'history_seq': value['history_seq'], 'history_digest': value['history_digest'],
              'ledger_sha256': hashlib.sha256(Path(ledger_path).read_bytes()).hexdigest(),
              'history_sha256': hashlib.sha256(Path(history_path).read_bytes()).hexdigest()}
    _write_ledger_atomic(anchor_path, anchor)


def initialize_budget_ledger(path=LEDGER, history_path=HISTORY, *, lock_record,
                             anchor_path=None, receipt_path=None):
    """One-time, explicit cfg1 genesis under the exact product lock; never reset existing state."""
    path, history_path = Path(path), Path(history_path)
    anchor_path, receipt_path = _anchor_paths(path, anchor_path, receipt_path)
    purpose = 'round5-config-ledger-bootstrap'
    if (not isinstance(lock_record, dict) or lock_record.get('pid') != os.getpid()
            or lock_record.get('create_time') != psutil.Process().create_time()
            or lock_record.get('product') != 'fieldwork' or lock_record.get('purpose') != purpose
            or lock_record.get('owner') != f'fieldwork-dataset-round5-{purpose}-{os.getpid()}'):
        raise SystemExit('LEDGER_BOOTSTRAP_REQUIRES_CURRENT_LOCK')
    paths = (path, history_path, anchor_path, receipt_path)
    if any(p.exists() or p.is_symlink() for p in paths):
        raise SystemExit('LEDGER_BOOTSTRAP_STATE_ALREADY_EXISTS')
    for p in paths:
        p.parent.mkdir(parents=True, exist_ok=True)
    event = _genesis_event()
    history_bytes = _json_bytes(event) + b'\n'
    ledger_value = _genesis_ledger(event)
    ledger_bytes = _json_bytes(ledger_value) + b'\n'
    source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    receipt = {'schema_version': 1, 'bootstrap_id': uuid.uuid4().hex,
               'initialized_utc': datetime.now(timezone.utc).isoformat(),
               'source_sha256': source_digest, 'baseline_sha256': _event_digest(ROUND4_CONFIG1),
               'genesis_digest': event['digest']}
    anchor = {'schema_version': 1, 'bootstrap_id': receipt['bootstrap_id'], 'history_seq': 0,
              'history_digest': event['digest'], 'ledger_sha256': hashlib.sha256(ledger_bytes).hexdigest(),
              'history_sha256': hashlib.sha256(history_bytes).hexdigest()}
    # Receipt is exclusive and written first. A partial bootstrap therefore blocks
    # automatic retry and requires an audited operator disposition.
    with receipt_path.open('x', encoding='utf-8') as f:
        f.write(_json_bytes(receipt).decode('utf-8') + '\n')
        f.flush(); os.fsync(f.fileno())
    with history_path.open('xb') as f:
        f.write(history_bytes); f.flush(); os.fsync(f.fileno())
    with path.open('xb') as f:
        f.write(ledger_bytes); f.flush(); os.fsync(f.fileno())
    with anchor_path.open('xb') as f:
        f.write(_json_bytes(anchor) + b'\n'); f.flush(); os.fsync(f.fileno())
    _load_current_ledger(path, history_path, anchor_path=anchor_path, receipt_path=receipt_path)
    return {'bootstrap_id': receipt['bootstrap_id'], 'history_digest': event['digest'],
            'source_sha256': source_digest}


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate ledger key')
        out[key] = value
    return out


def _valid_tag(tag):
    return isinstance(tag, str) and tag not in ('.', '..') and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', tag) is not None


def _validate_ledger(value):
    if not isinstance(value, dict) or set(value) != {'schema_version', 'cap_configs_total', 'cap_cpu_seconds_total', 'configs', 'history_seq', 'history_digest'}:
        raise SystemExit('LEDGER_SCHEMA_INVALID')
    if value['schema_version'] != 2 or value['cap_configs_total'] != CAP_CONFIGS_TOTAL or value['cap_cpu_seconds_total'] != CAP_CPU_SECONDS or not isinstance(value['configs'], list):
        raise SystemExit('LEDGER_CAP_INVALID')
    if type(value['history_seq']) is not int or value['history_seq'] < 0 or not re.fullmatch('[a-f0-9]{64}', str(value['history_digest'])):
        raise SystemExit('LEDGER_HISTORY_HEAD_INVALID')
    if not value['configs'] or value['configs'][0] != ROUND4_CONFIG1:
        raise SystemExit('LEDGER_BASELINE_INVALID')
    if len(value['configs']) > CAP_CONFIGS_TOTAL:
        raise SystemExit('EXPLORATION_CAP_EXHAUSTED')
    tags = set()
    legacy_keys = {'tag', 'recipe', 'elapsed_s', 'round', 'validation_accuracy'}
    attempt_keys = {'tag', 'recipe', 'config', 'why', 'round', 'complete', 'status', 'elapsed_s', 'started_utc',
                    'error_type', 'peak_rss_bytes', 'selected_epoch', 'validation_cross_entropy',
                    'validation_accuracy', 'validation_macro_f1', 'model_digest', 'checkpoint_digest', 'train_elapsed_s',
                    'cpu_seconds_reserved', 'cpu_seconds_charged', 'wall_deadline_utc', 'reservation_pid',
                    'reservation_create_time', 'lock_owner', 'execution_mode', 'child_pid', 'child_create_time',
                    'launcher_pid', 'launcher_create_time', 'job_object_name', 'job_scope_sha256', 'wall_elapsed_s',
                    'observed_cpu_seconds', 'recovery', 'launch_nonce', 'spawn_state'}
    running = 0
    cpu_total = math.ceil(ROUND4_CONFIG1['elapsed_s'] * 2)
    for index, row in enumerate(value['configs']):
        if not isinstance(row, dict) or not _valid_tag(row.get('tag')) or row['tag'] in tags:
            raise SystemExit('LEDGER_CONFIG_INVALID')
        if type(row.get('round')) is not int:
            raise SystemExit('LEDGER_CONFIG_ROUND_INVALID')
        if index == 0:
            if set(row) != legacy_keys or row.get('recipe') != 'compact-cnn/v1':
                raise SystemExit('LEDGER_LEGACY_CONFIG_INVALID')
            acc = row.get('validation_accuracy')
            if isinstance(acc, bool) or not isinstance(acc, (int, float)) or not math.isfinite(acc) or not 0 <= acc <= 1:
                raise SystemExit('LEDGER_LEGACY_METRIC_INVALID')
            if row != ROUND4_CONFIG1:
                raise SystemExit('LEDGER_BASELINE_INVALID')
        elif row['round'] == 5:
            base_required = {'tag', 'recipe', 'config', 'why', 'round', 'complete', 'status', 'elapsed_s', 'started_utc',
                             'cpu_seconds_reserved', 'reservation_pid', 'reservation_create_time', 'lock_owner',
                             'launch_nonce', 'spawn_state'}
            if not base_required <= set(row) or not set(row) <= attempt_keys:
                raise SystemExit('LEDGER_CONFIG_SCHEMA_INVALID')
            if row.get('recipe') != rr.RECIPE or not isinstance(row.get('config'), dict) or not isinstance(row.get('why'), str) or not row['why'].strip():
                raise SystemExit('LEDGER_CONFIG_SCHEMA_INVALID')
            if row.get('execution_mode') != 'windows-job-object-kill-on-close-v1':
                raise SystemExit('LEDGER_EXECUTION_MODE_INVALID')
            try:
                if rr.default_config(**row['config']) != row['config']:
                    raise ValueError('noncanonical config')
                started = datetime.fromisoformat(row['started_utc'].replace('Z', '+00:00'))
            except (TypeError, ValueError, AttributeError) as exc:
                raise SystemExit('LEDGER_CONFIG_SCHEMA_INVALID') from exc
            if started.tzinfo is None or started.utcoffset() is None:
                raise SystemExit('LEDGER_CONFIG_SCHEMA_INVALID')
            if type(row.get('complete')) is not bool or (row['status'] == 'complete') != row['complete']:
                raise SystemExit('LEDGER_STATUS_INVALID')
            if type(row['cpu_seconds_reserved']) is not int or not 1 <= row['cpu_seconds_reserved'] <= MAX_RUN_CPU_SECONDS:
                raise SystemExit('LEDGER_CPU_RESERVATION_INVALID')
            if type(row['reservation_pid']) is not int or row['reservation_pid'] <= 0 or isinstance(row['reservation_create_time'], bool) or not isinstance(row['reservation_create_time'], (int, float)) or not math.isfinite(row['reservation_create_time']) or not isinstance(row['lock_owner'], str) or not row['lock_owner']:
                raise SystemExit('LEDGER_OWNER_IDENTITY_INVALID')
            if not isinstance(row.get('launch_nonce'), str) or not re.fullmatch('[a-f0-9]{64}', row['launch_nonce']) or row.get('spawn_state') not in ('not_started', 'spawn_intent', 'spawned'):
                raise SystemExit('LEDGER_SPAWN_STATE_INVALID')
            if row.get('child_pid') is not None and (type(row['child_pid']) is not int or row['child_pid'] <= 0 or isinstance(row.get('child_create_time'), bool) or not isinstance(row.get('child_create_time'), (int, float)) or not math.isfinite(row['child_create_time']) or row['child_create_time'] <= 0):
                raise SystemExit('LEDGER_CHILD_IDENTITY_INVALID')
            if row.get('child_pid') is None and row.get('child_create_time') is not None:
                raise SystemExit('LEDGER_CHILD_IDENTITY_INVALID')
            launcher_pid, launcher_created = row.get('launcher_pid'), row.get('launcher_create_time')
            if launcher_pid is not None and (type(launcher_pid) is not int or launcher_pid <= 0 or isinstance(launcher_created, bool)
                    or not isinstance(launcher_created, (int, float)) or not math.isfinite(launcher_created) or launcher_created <= 0):
                raise SystemExit('LEDGER_LAUNCHER_IDENTITY_INVALID')
            if launcher_pid is None and launcher_created is not None:
                raise SystemExit('LEDGER_LAUNCHER_IDENTITY_INVALID')
            if (row.get('child_pid') is None) != (launcher_pid is None):
                raise SystemExit('LEDGER_LAUNCHER_IDENTITY_INVALID')
            if launcher_pid == row.get('child_pid') and launcher_created != row.get('child_create_time'):
                raise SystemExit('LEDGER_LAUNCHER_IDENTITY_INVALID')
            scope_digest = row.get('job_scope_sha256')
            if scope_digest is not None and (not isinstance(scope_digest, str) or not re.fullmatch('[a-f0-9]{64}', scope_digest)):
                raise SystemExit('LEDGER_JOB_SCOPE_DIGEST_INVALID')
            if (row.get('child_pid') is None) != (scope_digest is None):
                raise SystemExit('LEDGER_JOB_SCOPE_DIGEST_INVALID')
            job_object_name = row.get('job_object_name')
            if job_object_name is not None and (not isinstance(job_object_name, str)
                    or not re.fullmatch(r'Local\\FieldworkTraining-[a-f0-9]{64}', job_object_name)):
                raise SystemExit('LEDGER_JOB_OBJECT_NAME_INVALID')
            if (row.get('child_pid') is None) != (job_object_name is None):
                raise SystemExit('LEDGER_JOB_OBJECT_NAME_INVALID')
            if ((row['spawn_state'] in ('not_started', 'spawn_intent')) != (row.get('child_pid') is None)
                    or (row['spawn_state'] == 'spawned' and (row.get('child_pid') is None or launcher_pid is None))):
                raise SystemExit('LEDGER_SPAWN_STATE_INVALID')
            if row['status'] != 'running' and (type(row.get('cpu_seconds_charged')) is not int or not 0 <= row['cpu_seconds_charged'] <= row['cpu_seconds_reserved']):
                raise SystemExit('LEDGER_CPU_CHARGE_INVALID')
            if row['status'] == 'running':
                running += 1
                cpu_total += row['cpu_seconds_reserved']
            else:
                cpu_total += row['cpu_seconds_charged']
            if row['status'] == 'failed' and (not isinstance(row.get('error_type'), str) or not row['error_type']):
                raise SystemExit('LEDGER_FAILED_RECORD_INVALID')
            if row['status'] == 'complete':
                for metric in ('selected_epoch', 'validation_cross_entropy', 'validation_accuracy', 'validation_macro_f1', 'peak_rss_bytes', 'train_elapsed_s'):
                    if metric not in row:
                        raise SystemExit('LEDGER_COMPLETE_RECORD_INVALID')
                for metric in ('validation_cross_entropy', 'validation_accuracy', 'validation_macro_f1', 'train_elapsed_s'):
                    val = row[metric]
                    if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val) or val < 0:
                        raise SystemExit('LEDGER_COMPLETE_RECORD_INVALID')
                if row['validation_accuracy'] > 1 or row['validation_macro_f1'] > 1 or type(row['selected_epoch']) is not int or not 1 <= row['selected_epoch'] <= row['config']['epochs'] or type(row['peak_rss_bytes']) is not int or row['peak_rss_bytes'] < 0 or not re.fullmatch('[a-f0-9]{64}', str(row.get('model_digest', ''))) or not re.fullmatch('[a-f0-9]{64}', str(row.get('checkpoint_digest', ''))):
                    raise SystemExit('LEDGER_COMPLETE_RECORD_INVALID')
        else:
            raise SystemExit('LEDGER_CONFIG_ROUND_INVALID')
        tags.add(row['tag'])
        elapsed = row.get('elapsed_s')
        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0:
            raise SystemExit('LEDGER_ELAPSED_INVALID')
        status = row.get('status')
        if status not in (None, 'running', 'failed', 'complete'):
            raise SystemExit('LEDGER_STATUS_INVALID')
        # One running row is a valid durable reservation and is required for
        # crash recovery. New reservations are rejected separately by
        # reserve_configuration; replay must still validate the existing row.
        if status is None and row.get('complete') is False:
            raise SystemExit('LEDGER_ATTEMPT_IN_PROGRESS')
        if status == 'complete' and row.get('complete') is False:
            raise SystemExit('LEDGER_STATUS_INVALID')
    if running > 1:
        raise SystemExit('LEDGER_MULTIPLE_RUNNING_ATTEMPTS')
    if cpu_total > CAP_CPU_SECONDS:
        raise SystemExit('EXPLORATION_CPU_CAP_EXHAUSTED')
    return value


def _write_ledger_atomic(path, value):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SystemExit('LEDGER_PATH_UNSAFE')
    payload = _json_bytes(value) + b'\n'
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', prefix='.config-ledger-', suffix='.tmp', dir=path.parent,
                                         delete=False) as f:
            tmp = Path(f.name)
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _publish_json_exclusive(path, value):
    """Publish a complete JSON receipt atomically without replacing an existing path."""
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise SystemExit('RECOVERY_COMPLETION_ALREADY_EXISTS')
    payload = _json_bytes(value) + b'\n'
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', prefix='.recovery-complete-', suffix='.tmp',
                                         dir=path.parent, delete=False) as f:
            tmp = Path(f.name)
            if f.write(payload) != len(payload):
                raise OSError('short receipt write')
            f.flush()
            os.fsync(f.fileno())
    except OSError as exc:
        raise SystemExit(f'RECOVERY_COMPLETION_TEMP_WRITE_FAILED temp={tmp}') from exc
    try:
        os.link(tmp, path)
    except FileExistsError as exc:
        raise SystemExit('RECOVERY_COMPLETION_ALREADY_EXISTS') from exc
    except OSError as exc:
        # Keep the fully-written temporary file as a diagnostic; never expose a partial target.
        raise SystemExit(f'RECOVERY_COMPLETION_PUBLISH_FAILED temp={tmp}') from exc
    try:
        tmp.unlink()
    except OSError as exc:
        raise SystemExit(f'RECOVERY_COMPLETION_TEMP_CLEANUP_FAILED temp={tmp}') from exc


def _make_recovery_completion(intent, verified_state, *, ledger_path, history_path, anchor_path, receipt_path):
    names = {'config-ledger.json': ledger_path, 'config-history.jsonl': history_path,
             'config-budget-anchor.json': anchor_path, 'config-budget-bootstrap.json': receipt_path}
    return {**intent, 'state': 'recovery-complete',
            'completed_utc': datetime.now(timezone.utc).isoformat(),
            'recovered_history_seq': verified_state['history_seq'],
            'recovered_history_digest': verified_state['history_digest'],
            'verified_current_sha256': {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                        for name, path in names.items()}}


def _replay_history_bytes(raw):
    try:
        if not raw.endswith(b'\n'):
            raise ValueError('truncated history')
        rows = [json.loads(line, object_pairs_hook=_unique_object) for line in raw.splitlines()]
    except (SystemExit, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit('LEDGER_HISTORY_MALFORMED') from exc
    if not rows or rows[0] != _genesis_event():
        raise SystemExit('LEDGER_HISTORY_GENESIS_INVALID')
    configs = [dict(ROUND4_CONFIG1)]
    previous = rows[0]['digest']
    for seq, row in enumerate(rows[1:], 1):
        if not isinstance(row, dict) or set(row) != {'seq', 'kind', 'previous_digest', 'payload', 'digest'} or type(row['seq']) is not int or row['seq'] != seq or row['previous_digest'] != previous:
            raise SystemExit('LEDGER_HISTORY_CHAIN_INVALID')
        body = {k: row[k] for k in ('seq', 'kind', 'previous_digest', 'payload')}
        if not re.fullmatch('[a-f0-9]{64}', str(row['digest'])) or _event_digest(body) != row['digest']:
            raise SystemExit('LEDGER_HISTORY_CHAIN_INVALID')
        payload = row['payload']
        if row['kind'] == 'reserve':
            if not isinstance(payload, dict) or set(payload) != {'row'} or not isinstance(payload['row'], dict) or payload['row'].get('status') != 'running':
                raise SystemExit('LEDGER_HISTORY_EVENT_INVALID')
            if (payload['row'].get('spawn_state') != 'not_started' or payload['row'].get('child_pid') is not None
                    or payload['row'].get('launcher_pid') is not None or payload['row'].get('job_scope_sha256') is not None
                    or payload['row'].get('job_object_name') is not None):
                raise SystemExit('LEDGER_HISTORY_EVENT_INVALID')
            _validate_ledger({'schema_version': 2, 'cap_configs_total': CAP_CONFIGS_TOTAL, 'cap_cpu_seconds_total': CAP_CPU_SECONDS,
                              'configs': [*configs, payload['row']], 'history_seq': seq, 'history_digest': row['digest']})
            configs.append(payload['row'])
        elif row['kind'] in ('finish', 'recover', 'recovered-completion', 'spawn-intent', 'child-started'):
            if not isinstance(payload, dict) or set(payload) != {'row'} or not isinstance(payload['row'], dict):
                raise SystemExit('LEDGER_HISTORY_EVENT_INVALID')
            new = payload['row']
            matches = [i for i, old in enumerate(configs) if old.get('tag') == new.get('tag')]
            if len(matches) != 1 or configs[matches[0]].get('status') != 'running':
                raise SystemExit('LEDGER_HISTORY_EVENT_INVALID')
            old = configs[matches[0]]
            immutable = ('tag', 'recipe', 'config', 'why', 'round', 'started_utc', 'cpu_seconds_reserved',
                         'reservation_pid', 'reservation_create_time', 'lock_owner', 'execution_mode', 'launch_nonce')
            if any(old.get(k) != new.get(k) for k in immutable):
                raise SystemExit('LEDGER_HISTORY_EVENT_INVALID')
            if row['kind'] == 'spawn-intent':
                if (old.get('spawn_state') != 'not_started' or new.get('spawn_state') != 'spawn_intent'
                        or new.get('status') != 'running' or new.get('child_pid') is not None
                        or new.get('launcher_pid') is not None or new.get('job_scope_sha256') is not None
                        or new.get('job_object_name') is not None):
                    raise SystemExit('LEDGER_HISTORY_EVENT_INVALID')
            elif row['kind'] == 'child-started':
                if (old.get('spawn_state') != 'spawn_intent' or new.get('spawn_state') != 'spawned'
                        or new.get('status') != 'running' or type(new.get('child_pid')) is not int
                        or isinstance(new.get('child_create_time'), bool)
                        or not isinstance(new.get('child_create_time'), (int, float))
                        or not math.isfinite(new['child_create_time']) or new['child_create_time'] <= 0
                        or type(new.get('launcher_pid')) is not int or new['launcher_pid'] <= 0
                        or isinstance(new.get('launcher_create_time'), bool)
                        or not isinstance(new.get('launcher_create_time'), (int, float))
                        or not math.isfinite(new['launcher_create_time']) or new['launcher_create_time'] <= 0
                        or not isinstance(new.get('job_scope_sha256'), str)
                        or not re.fullmatch('[a-f0-9]{64}', new['job_scope_sha256'])
                        or not isinstance(new.get('job_object_name'), str)
                        or not re.fullmatch(r'Local\\FieldworkTraining-[a-f0-9]{64}', new['job_object_name'])):
                    raise SystemExit('LEDGER_HISTORY_EVENT_INVALID')
            elif (old.get('spawn_state') != new.get('spawn_state') or old.get('child_pid') != new.get('child_pid')
                    or old.get('child_create_time') != new.get('child_create_time')
                    or old.get('launcher_pid') != new.get('launcher_pid')
                    or old.get('launcher_create_time') != new.get('launcher_create_time')
                    or old.get('job_scope_sha256') != new.get('job_scope_sha256')
                    or old.get('job_object_name') != new.get('job_object_name')):
                raise SystemExit('LEDGER_HISTORY_EVENT_INVALID')
            if row['kind'] == 'recovered-completion':
                recovery = new.get('recovery')
                required_recovery = {'method', 'recovered_utc', 'source_manifest_sha256', 'child_result_sha256',
                                     'process_receipt_sha256', 'failed_cli_log_sha256', 'pid_birth_death_receipts',
                                     'process_exit_receipts', 'child_returncode', 'timed_out', 'cpu_limit_reached',
                                     'job_kill_on_close', 'observed_cpu_seconds'}
                if (new.get('status') != 'complete' or new.get('complete') is not True
                        or not isinstance(recovery, dict) or set(recovery) != required_recovery
                        or recovery.get('method') != 'recovered-completion-from-verified-child-result'
                        or recovery.get('child_returncode') != 0 or recovery.get('timed_out') is not False
                        or recovery.get('cpu_limit_reached') is not False or recovery.get('job_kill_on_close') is not True
                        or isinstance(recovery.get('observed_cpu_seconds'), bool)
                        or not isinstance(recovery.get('observed_cpu_seconds'), (int, float))
                        or not math.isfinite(recovery['observed_cpu_seconds']) or recovery['observed_cpu_seconds'] <= 0):
                    raise SystemExit('LEDGER_RECOVERED_COMPLETION_INVALID')
                for key in ('source_manifest_sha256', 'child_result_sha256', 'process_receipt_sha256', 'failed_cli_log_sha256'):
                    if not isinstance(recovery.get(key), str) or not re.fullmatch('[a-f0-9]{64}', recovery[key]):
                        raise SystemExit('LEDGER_RECOVERED_COMPLETION_INVALID')
                proofs = recovery.get('pid_birth_death_receipts')
                expected_proofs = {
                    'reservation_parent': (old.get('reservation_pid'), old.get('reservation_create_time')),
                    'actual_training_child': (old.get('child_pid'), old.get('child_create_time')),
                    'child_launcher': (old.get('launcher_pid'), old.get('launcher_create_time')),
                }
                if not isinstance(proofs, list) or len(proofs) != len(expected_proofs):
                    raise SystemExit('LEDGER_RECOVERED_COMPLETION_INVALID')
                observed_proofs = {}
                for proof in proofs:
                    if (not isinstance(proof, dict) or set(proof) != {'role', 'pid', 'create_time', 'proof'}
                            or proof.get('proof') not in ('pid-absent', 'pid-reused')
                            or type(proof.get('pid')) is not int or proof['pid'] <= 0
                            or isinstance(proof.get('create_time'), bool)
                            or not isinstance(proof.get('create_time'), (int, float))
                            or not math.isfinite(proof['create_time']) or proof['create_time'] <= 0
                            or proof.get('role') in observed_proofs):
                        raise SystemExit('LEDGER_RECOVERED_COMPLETION_INVALID')
                    observed_proofs[proof['role']] = (proof['pid'], proof['create_time'])
                if observed_proofs != expected_proofs:
                    raise SystemExit('LEDGER_RECOVERED_COMPLETION_INVALID')
                exits = recovery.get('process_exit_receipts')
                if (not isinstance(exits, list) or not exits
                        or any(not isinstance(x, dict) or set(x) not in (
                                   {'pid', 'create_time', 'exit_proven'},
                                   {'pid', 'create_time', 'exit_proven', 'death_proof'})
                               or ('death_proof' in x and x['death_proof'] not in ('pid-absent', 'pid-reused'))
                               or type(x.get('pid')) is not int or x['pid'] <= 0
                               or isinstance(x.get('create_time'), bool)
                               or not isinstance(x.get('create_time'), (int, float))
                               or not math.isfinite(x['create_time']) or x['create_time'] <= 0
                               or x.get('exit_proven') is not True for x in exits)):
                    raise SystemExit('LEDGER_RECOVERED_COMPLETION_INVALID')
                exit_ids = {(x['pid'], x['create_time']) for x in exits}
                if any(expected_proofs[role] not in exit_ids for role in ('actual_training_child', 'child_launcher')):
                    raise SystemExit('LEDGER_RECOVERED_COMPLETION_INVALID')
            configs[matches[0]] = new
            _validate_ledger({'schema_version': 2, 'cap_configs_total': CAP_CONFIGS_TOTAL, 'cap_cpu_seconds_total': CAP_CPU_SECONDS,
                              'configs': configs, 'history_seq': seq, 'history_digest': row['digest']})
        else:
            raise SystemExit('LEDGER_HISTORY_EVENT_INVALID')
        previous = row['digest']
    return configs, len(rows) - 1, previous, rows


def _read_history(path):
    if path.is_symlink() or not path.is_file():
        raise SystemExit('LEDGER_HISTORY_MISSING_OR_UNSAFE')
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SystemExit('LEDGER_HISTORY_MALFORMED') from exc
    configs, seq, digest, _ = _replay_history_bytes(raw)
    return configs, seq, digest


def _load_current_ledger(path=LEDGER, history_path=HISTORY, *, anchor_path=None, receipt_path=None):
    path, history_path = Path(path), Path(history_path)
    anchor_path, receipt_path = _anchor_paths(path, anchor_path, receipt_path)
    if not path.exists():
        raise SystemExit('LEDGER_MISSING_AFTER_INITIALIZATION')
    if path.is_symlink() or not path.is_file():
        raise SystemExit('LEDGER_PATH_UNSAFE')
    try:
        value = _validate_ledger(json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit('LEDGER_MALFORMED') from exc
    configs, seq, digest = _read_history(history_path)
    if value['configs'] != configs or value['history_seq'] != seq or value['history_digest'] != digest:
        raise SystemExit('LEDGER_HISTORY_DIVERGED')
    _read_anchor(anchor_path, receipt_path, path, history_path, value)
    return value


def reconcile_budget_state(path=LEDGER, history_path=HISTORY, *, current_lock,
                           anchor_path=None, receipt_path=None, archive_root=None):
    """Recover only one hash-valid history commit beyond its prior anchored head."""
    purpose = 'round5-config-ledger-reconcile'
    expected_owner = f'fieldwork-dataset-round5-{purpose}-{os.getpid()}'
    if (not isinstance(current_lock, dict) or current_lock.get('pid') != os.getpid()
            or current_lock.get('create_time') != psutil.Process().create_time()
            or current_lock.get('product') != 'fieldwork' or current_lock.get('purpose') != purpose
            or current_lock.get('owner') != expected_owner):
        raise SystemExit('LEDGER_RECONCILE_REQUIRES_CURRENT_LOCK')
    path, history_path = Path(path), Path(history_path)
    anchor_path, receipt_path = _anchor_paths(path, anchor_path, receipt_path)
    if archive_root is None:
        archive_root = ROOT / '.local/round5-resume/budget-commit-recovery'
    archive_root = Path(archive_root)
    for candidate in (path, history_path, anchor_path, receipt_path):
        if candidate.is_symlink() or not candidate.is_file():
            raise SystemExit('LEDGER_RECONCILE_INPUT_MISSING_OR_UNSAFE')
    try:
        ledger_bytes = path.read_bytes()
        history_bytes = history_path.read_bytes()
        anchor_bytes = anchor_path.read_bytes()
        receipt_bytes = receipt_path.read_bytes()
    except OSError as exc:
        raise SystemExit('LEDGER_RECONCILE_INPUT_MISSING') from exc
    def preserve_refusal(reason):
        archive_root.mkdir(parents=True, exist_ok=True)
        archive_dir = archive_root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ-refused-') + uuid.uuid4().hex)
        archive_dir.mkdir()
        contents = {'config-ledger.json': ledger_bytes, 'config-history.jsonl': history_bytes,
                    'config-budget-anchor.json': anchor_bytes, 'config-budget-bootstrap.json': receipt_bytes}
        hashes = {}
        for name, raw in contents.items():
            with (archive_dir / name).open('xb') as f:
                f.write(raw); f.flush(); os.fsync(f.fileno())
            hashes[name] = hashlib.sha256(raw).hexdigest()
        record = {'schema_version': 1, 'state': 'recovery-refused', 'reason': reason,
                  'created_utc': datetime.now(timezone.utc).isoformat(), 'prior_bytes_sha256': hashes}
        with (archive_dir / 'recovery-refused.json').open('x', encoding='utf-8') as f:
            f.write(_json_bytes(record).decode('utf-8') + '\n'); f.flush(); os.fsync(f.fileno())
        return archive_dir
    def finalize_verified_pending_intent(verified_state):
        if archive_root.is_symlink():
            raise SystemExit('LEDGER_RECONCILE_ARCHIVE_ROOT_UNSAFE')
        if not archive_root.exists():
            return None
        if not archive_root.is_dir():
            archived = preserve_refusal('LEDGER_RECONCILE_ARCHIVE_ROOT_UNSAFE')
            raise SystemExit(f'LEDGER_RECONCILE_ARCHIVE_ROOT_UNSAFE archived={archived}')
        pending = []
        archived_files = {'config-ledger.json': 'ledger', 'config-history.jsonl': 'history',
                          'config-budget-anchor.json': 'anchor', 'config-budget-bootstrap.json': 'receipt'}
        for archive_dir in sorted(archive_root.iterdir()):
            if archive_dir.is_symlink():
                archived = preserve_refusal('LEDGER_RECONCILE_ARCHIVE_ENTRY_UNSAFE')
                raise SystemExit(f'LEDGER_RECONCILE_ARCHIVE_ENTRY_UNSAFE archived={archived}')
            if not archive_dir.is_dir():
                continue
            intent_path = archive_dir / 'recovery-intent.json'
            complete_path = archive_dir / 'recovery-complete.json'
            if intent_path.is_symlink() or complete_path.is_symlink():
                archived = preserve_refusal('LEDGER_RECONCILE_ARCHIVE_RECEIPT_UNSAFE')
                raise SystemExit(f'LEDGER_RECONCILE_ARCHIVE_RECEIPT_UNSAFE archived={archived}')
            if complete_path.exists() and not intent_path.exists():
                archived = preserve_refusal('LEDGER_RECONCILE_ORPHAN_COMPLETION_RECEIPT')
                raise SystemExit(f'LEDGER_RECONCILE_ORPHAN_COMPLETION_RECEIPT archived={archived}')
            if not intent_path.exists():
                continue
            try:
                intent = json.loads(intent_path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                archived = preserve_refusal('LEDGER_RECONCILE_PENDING_INTENT_MALFORMED')
                raise SystemExit(f'LEDGER_RECONCILE_PENDING_INTENT_MALFORMED archived={archived}') from exc
            expected_intent_keys = {'schema_version', 'state', 'created_utc', 'from_seq', 'to_seq',
                                    'from_digest', 'to_digest', 'unanchored_events', 'prior_bytes_sha256',
                                    'ledger_projection'}
            prior_hashes = intent.get('prior_bytes_sha256') if isinstance(intent, dict) else None
            valid = (isinstance(intent, dict) and set(intent) == expected_intent_keys
                     and intent.get('schema_version') == 1 and intent.get('state') == 'recovery-intent'
                     and type(intent.get('from_seq')) is int and type(intent.get('to_seq')) is int
                     and type(intent.get('unanchored_events')) is int
                     and intent['from_seq'] >= 0 and intent['to_seq'] > intent['from_seq']
                     and intent['unanchored_events'] == intent['to_seq'] - intent['from_seq']
                     and re.fullmatch('[a-f0-9]{64}', str(intent.get('from_digest', ''))) is not None
                     and re.fullmatch('[a-f0-9]{64}', str(intent.get('to_digest', ''))) is not None
                     and intent.get('ledger_projection') in ('anchored-prefix', 'full-history')
                     and isinstance(prior_hashes, dict) and set(prior_hashes) == set(archived_files)
                     and all(re.fullmatch('[a-f0-9]{64}', str(prior_hashes.get(name, ''))) is not None
                             for name in archived_files))
            if valid:
                try:
                    created_dt = datetime.fromisoformat(intent['created_utc'].replace('Z', '+00:00'))
                    valid = created_dt.tzinfo is not None and created_dt.utcoffset() is not None
                except (TypeError, ValueError, AttributeError):
                    valid = False
            if valid:
                prior_bytes = {}
                for name in archived_files:
                    snapshot = archive_dir / name
                    if snapshot.is_symlink() or not snapshot.is_file():
                        valid = False
                        break
                    try:
                        prior_bytes[name] = snapshot.read_bytes()
                        if hashlib.sha256(prior_bytes[name]).hexdigest() != prior_hashes[name]:
                            valid = False
                            break
                    except OSError:
                        valid = False
                        break
            if valid:
                try:
                    prior_anchor, prior_receipt = _read_anchor_record(
                        archive_dir / 'config-budget-anchor.json',
                        archive_dir / 'config-budget-bootstrap.json')
                    prior_configs, prior_seq, prior_digest, _ = _replay_history_bytes(
                        prior_bytes['config-history.jsonl'])
                    prior_lines = prior_bytes['config-history.jsonl'].splitlines(keepends=True)
                    prior_prefix = b''.join(prior_lines[:prior_anchor['history_seq'] + 1])
                    prefix_configs, prefix_seq, prefix_digest, _ = _replay_history_bytes(prior_prefix)
                    prior_ledger = _validate_ledger(json.loads(
                        prior_bytes['config-ledger.json'].decode('utf-8'), object_pairs_hook=_unique_object))
                    prior_prefix_state = {'schema_version': 2, 'cap_configs_total': CAP_CONFIGS_TOTAL,
                                          'cap_cpu_seconds_total': CAP_CPU_SECONDS, 'configs': prefix_configs,
                                          'history_seq': prefix_seq, 'history_digest': prefix_digest}
                    prior_full_state = {'schema_version': 2, 'cap_configs_total': CAP_CONFIGS_TOTAL,
                                        'cap_cpu_seconds_total': CAP_CPU_SECONDS, 'configs': prior_configs,
                                        'history_seq': prior_seq, 'history_digest': prior_digest}
                    valid = (prior_anchor['history_seq'] == intent['from_seq']
                             and prior_anchor['history_digest'] == intent['from_digest']
                             and prefix_seq == intent['from_seq'] and prefix_digest == intent['from_digest']
                             and hashlib.sha256(prior_prefix).hexdigest() == prior_anchor['history_sha256']
                             and prior_seq == intent['to_seq'] and prior_digest == intent['to_digest']
                             and prior_receipt['bootstrap_id'] == receipt['bootstrap_id'])
                    if intent['ledger_projection'] == 'anchored-prefix':
                        valid = (valid and prior_ledger == prior_prefix_state
                                 and prior_hashes['config-ledger.json'] == prior_anchor['ledger_sha256'])
                    else:
                        valid = valid and prior_ledger == prior_full_state
                except (SystemExit, OSError, UnicodeError, json.JSONDecodeError, ValueError):
                    valid = False
            if not valid:
                archived = preserve_refusal('LEDGER_RECONCILE_PENDING_INTENT_INVALID')
                raise SystemExit(f'LEDGER_RECONCILE_PENDING_INTENT_INVALID archived={archived}')
            if complete_path.exists():
                try:
                    completed = json.loads(complete_path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
                except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                    archived = preserve_refusal('LEDGER_RECONCILE_COMPLETION_INVALID')
                    raise SystemExit(f'LEDGER_RECONCILE_COMPLETION_INVALID archived={archived}') from exc
                common_keys = expected_intent_keys | {'completed_utc', 'recovered_history_seq',
                                                     'recovered_history_digest'}
                legacy_keys = common_keys
                current_keys = common_keys | {'verified_current_sha256'}
                completed_valid = isinstance(completed, dict) and set(completed) in (legacy_keys, current_keys)
                if completed_valid:
                    completed_at = completed.get('completed_utc')
                    try:
                        created_dt = datetime.fromisoformat(intent['created_utc'].replace('Z', '+00:00'))
                        completed_dt = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
                        timestamps_valid = (created_dt.tzinfo is not None and created_dt.utcoffset() is not None
                                            and completed_dt.tzinfo is not None and completed_dt.utcoffset() is not None
                                            and completed_dt >= created_dt)
                    except (TypeError, ValueError, AttributeError):
                        timestamps_valid = False
                    completed_valid = (timestamps_valid
                                       and all(completed.get(key) == ('recovery-complete' if key == 'state' else value)
                                               for key, value in intent.items())
                                       and completed.get('recovered_history_seq') == intent['to_seq']
                                       and completed.get('recovered_history_digest') == intent['to_digest'])
                    if completed_valid and 'verified_current_sha256' in completed:
                        current_hashes = completed['verified_current_sha256']
                        completed_valid = (isinstance(current_hashes, dict)
                                           and set(current_hashes) == set(archived_files)
                                           and all(re.fullmatch('[a-f0-9]{64}', str(current_hashes.get(name, ''))) is not None
                                                   for name in archived_files))
                if not completed_valid:
                    archived = preserve_refusal('LEDGER_RECONCILE_COMPLETION_INVALID')
                    raise SystemExit(f'LEDGER_RECONCILE_COMPLETION_INVALID archived={archived}')
                continue
            if (prior_bytes['config-history.jsonl'] != history_bytes
                    or prior_bytes['config-budget-bootstrap.json'] != receipt_bytes
                    or intent['to_seq'] != verified_state['history_seq']
                    or intent['to_digest'] != verified_state['history_digest']):
                archived = preserve_refusal('LEDGER_RECONCILE_PENDING_INTENT_DIVERGED')
                raise SystemExit(f'LEDGER_RECONCILE_PENDING_INTENT_DIVERGED archived={archived}')
            pending.append((archive_dir, intent))
        if not pending:
            return None
        matches = [(archive_dir, intent) for archive_dir, intent in pending
                   if intent['to_seq'] == verified_state['history_seq']
                   and intent['to_digest'] == verified_state['history_digest']]
        if len(matches) != 1 or len(pending) != 1:
            archived = preserve_refusal('LEDGER_RECONCILE_PENDING_INTENT_AMBIGUOUS_OR_DIVERGED')
            raise SystemExit(f'LEDGER_RECONCILE_PENDING_INTENT_AMBIGUOUS_OR_DIVERGED archived={archived}')
        archive_dir, intent = matches[0]
        complete = _make_recovery_completion(intent, verified_state,
                ledger_path=path, history_path=history_path, anchor_path=anchor_path, receipt_path=receipt_path)
        completion_path = archive_dir / 'recovery-complete.json'
        _publish_json_exclusive(completion_path, complete)
        return archive_dir
    try:
        anchor, receipt = _read_anchor_record(anchor_path, receipt_path)
    except SystemExit as exc:
        archived = preserve_refusal(str(exc))
        raise SystemExit(f'LEDGER_RECONCILE_ANCHOR_INVALID archived={archived}') from exc
    if receipt['genesis_digest'] != _genesis_event()['digest'] or receipt['baseline_sha256'] != _event_digest(ROUND4_CONFIG1):
        archived = preserve_refusal('LEDGER_BOOTSTRAP_RECEIPT_INVALID')
        raise SystemExit(f'LEDGER_BOOTSTRAP_RECEIPT_INVALID archived={archived}')
    try:
        full_configs, full_seq, full_digest, history_rows = _replay_history_bytes(history_bytes)
    except SystemExit as exc:
        archived = preserve_refusal(str(exc))
        raise SystemExit(f'LEDGER_RECONCILE_HISTORY_INVALID archived={archived}') from exc
    lines = history_bytes.splitlines(keepends=True)
    anchored_count = anchor['history_seq'] + 1
    if anchored_count > len(lines):
        archived = preserve_refusal('LEDGER_RECONCILE_HISTORY_ROLLBACK')
        raise SystemExit(f'LEDGER_RECONCILE_HISTORY_ROLLBACK archived={archived}')
    prefix_bytes = b''.join(lines[:anchored_count])
    prefix_configs, prefix_seq, prefix_digest, _ = _replay_history_bytes(prefix_bytes)
    if (prefix_seq != anchor['history_seq'] or prefix_digest != anchor['history_digest']
            or hashlib.sha256(prefix_bytes).hexdigest() != anchor['history_sha256']):
        archived = preserve_refusal('LEDGER_RECONCILE_ANCHOR_PREFIX_INVALID')
        raise SystemExit(f'LEDGER_RECONCILE_ANCHOR_PREFIX_INVALID archived={archived}')
    extra_events = full_seq - anchor['history_seq']
    if extra_events not in (0, 1):
        archived = preserve_refusal('LEDGER_RECONCILE_TOO_MANY_UNANCHORED_EVENTS')
        raise SystemExit(f'LEDGER_RECONCILE_TOO_MANY_UNANCHORED_EVENTS archived={archived}')
    try:
        ledger_value = _validate_ledger(json.loads(ledger_bytes.decode('utf-8'), object_pairs_hook=_unique_object))
    except (SystemExit, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        archived = preserve_refusal('LEDGER_RECONCILE_LEDGER_MALFORMED')
        raise SystemExit(f'LEDGER_RECONCILE_LEDGER_MALFORMED archived={archived}') from exc
    prefix_state = {'schema_version': 2, 'cap_configs_total': CAP_CONFIGS_TOTAL,
                    'cap_cpu_seconds_total': CAP_CPU_SECONDS, 'configs': prefix_configs,
                    'history_seq': prefix_seq, 'history_digest': prefix_digest}
    full_state = {'schema_version': 2, 'cap_configs_total': CAP_CONFIGS_TOTAL,
                  'cap_cpu_seconds_total': CAP_CPU_SECONDS, 'configs': full_configs,
                  'history_seq': full_seq, 'history_digest': full_digest}
    ledger_is_anchored_prefix = (hashlib.sha256(ledger_bytes).hexdigest() == anchor['ledger_sha256']
                                 and ledger_value == prefix_state)
    ledger_is_full_projection = ledger_value == full_state
    if extra_events == 0:
        if (hashlib.sha256(history_bytes).hexdigest() == anchor['history_sha256']
                and hashlib.sha256(ledger_bytes).hexdigest() == anchor['ledger_sha256']
                and ledger_value == full_state):
            finalized = finalize_verified_pending_intent(ledger_value)
            result = {'reconciled': False, 'history_seq': full_seq, 'history_digest': full_digest}
            if finalized is not None:
                result.update({'intent_finalized': True, 'audit_dir': str(finalized)})
            return result
        archived = preserve_refusal('LEDGER_RECONCILE_UNANCHORED_BYTES')
        raise SystemExit(f'LEDGER_RECONCILE_UNANCHORED_BYTES archived={archived}')
    if not ledger_is_anchored_prefix and not ledger_is_full_projection:
        archived = preserve_refusal('LEDGER_RECONCILE_LEDGER_NOT_VALID_PROJECTION')
        raise SystemExit(f'LEDGER_RECONCILE_LEDGER_NOT_VALID_PROJECTION archived={archived}')
    if not isinstance(history_rows[-1].get('kind'), str) or history_rows[-1]['kind'] not in ('reserve', 'spawn-intent', 'child-started', 'finish', 'recover'):
        archived = preserve_refusal('LEDGER_RECONCILE_EVENT_INVALID')
        raise SystemExit(f'LEDGER_RECONCILE_EVENT_INVALID archived={archived}')
    archive_root.mkdir(parents=True, exist_ok=True)
    archive_dir = archive_root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ-') + uuid.uuid4().hex)
    archive_dir.mkdir()
    old_bytes = {'config-ledger.json': ledger_bytes, 'config-history.jsonl': history_bytes,
                 'config-budget-anchor.json': anchor_bytes, 'config-budget-bootstrap.json': receipt_bytes}
    hashes = {}
    for name, raw in old_bytes.items():
        with (archive_dir / name).open('xb') as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        hashes[name] = hashlib.sha256(raw).hexdigest()
    intent = {'schema_version': 1, 'state': 'recovery-intent', 'created_utc': datetime.now(timezone.utc).isoformat(),
              'from_seq': anchor['history_seq'], 'to_seq': full_seq, 'from_digest': anchor['history_digest'],
              'to_digest': full_digest, 'unanchored_events': extra_events,
              'prior_bytes_sha256': hashes, 'ledger_projection': 'anchored-prefix' if ledger_is_anchored_prefix else 'full-history'}
    with (archive_dir / 'recovery-intent.json').open('x', encoding='utf-8') as f:
        f.write(_json_bytes(intent).decode('utf-8') + '\n'); f.flush(); os.fsync(f.fileno())
    if ledger_is_anchored_prefix:
        _write_ledger_atomic(path, full_state)
    _write_anchor(anchor_path, receipt_path, path, history_path, full_state)
    verified = _load_current_ledger(path, history_path, anchor_path=anchor_path, receipt_path=receipt_path)
    complete = _make_recovery_completion(intent, verified,
            ledger_path=path, history_path=history_path, anchor_path=anchor_path, receipt_path=receipt_path)
    _publish_json_exclusive(archive_dir / 'recovery-complete.json', complete)
    return {'reconciled': True, 'history_seq': full_seq, 'history_digest': full_digest,
            'unanchored_event_kind': history_rows[-1]['kind'], 'audit_dir': str(archive_dir)}


def ledger():
    return _load_current_ledger()


def _append_event(history_path, state, kind, row):
    seq = state['history_seq'] + 1
    body = {'seq': seq, 'kind': kind, 'previous_digest': state['history_digest'], 'payload': {'row': row}}
    event = {**body, 'digest': _event_digest(body)}
    try:
        with Path(history_path).open('ab') as f:
            f.write(_json_bytes(event) + b'\n')
            f.flush()
            os.fsync(f.fileno())
    except OSError as exc:
        raise SystemExit('LEDGER_HISTORY_APPEND_FAILED') from exc
    return seq, event['digest']


def _cpu_spent(state):
    spent = math.ceil(ROUND4_CONFIG1['elapsed_s'] * 2)
    for row in state['configs'][1:]:
        spent += row.get('cpu_seconds_reserved', 0) if row.get('status') == 'running' else row.get('cpu_seconds_charged', 0)
    return spent


def plan_run_budget(cpu_remaining_seconds, config_threads):
    if type(cpu_remaining_seconds) is not int or type(config_threads) is not int or config_threads not in (1, 2):
        raise SystemExit('CPU_BUDGET_INPUT_INVALID')
    if cpu_remaining_seconds <= CPU_GUARD_SECONDS:
        raise SystemExit('EXPLORATION_CPU_CAP_EXHAUSTED')
    reserved = min(MAX_RUN_CPU_SECONDS, cpu_remaining_seconds - CPU_GUARD_SECONDS)
    return {'cpu_seconds_reserved': reserved,
            'wall_deadline_seconds': max(0, reserved - CPU_GUARD_SECONDS) / CPU_PARALLELISM_BOUND,
            'parallelism_bound': CPU_PARALLELISM_BOUND}


def record_spawn_intent(path, tag, *, history_path=HISTORY, anchor_path=None, receipt_path=None):
    current = _load_current_ledger(path, history_path, anchor_path=anchor_path, receipt_path=receipt_path)
    matches = [row for row in current['configs'] if row.get('tag') == tag and row.get('status') == 'running']
    if len(matches) != 1 or matches[0].get('spawn_state') != 'not_started':
        raise SystemExit('LEDGER_SPAWN_INTENT_INVALID')
    old = matches[0]
    new = dict(old, spawn_state='spawn_intent')
    prospective = {**current, 'configs': [new if row['tag'] == tag else row for row in current['configs']]}
    _validate_ledger(prospective)
    seq, digest = _append_event(history_path, current, 'spawn-intent', new)
    updated = {**prospective, 'history_seq': seq, 'history_digest': digest}
    _write_ledger_atomic(path, updated)
    _write_anchor(anchor_path, receipt_path, path, history_path, updated)
    return updated, new


def record_child_started(path, tag, pid, create_time, nonce, *, launcher_pid, launcher_create_time, job_scope,
                         history_path=HISTORY, anchor_path=None, receipt_path=None):
    current = _load_current_ledger(path, history_path, anchor_path=anchor_path, receipt_path=receipt_path)
    matches = [row for row in current['configs'] if row.get('tag') == tag and row.get('status') == 'running']
    if (len(matches) != 1 or type(pid) is not int or pid <= 0 or isinstance(create_time, bool)
            or not isinstance(create_time, (int, float)) or not math.isfinite(create_time) or create_time <= 0
            or type(launcher_pid) is not int or launcher_pid <= 0 or isinstance(launcher_create_time, bool)
            or not isinstance(launcher_create_time, (int, float)) or not math.isfinite(launcher_create_time)
            or launcher_create_time <= 0 or not isinstance(job_scope, dict)):
        raise SystemExit('LEDGER_CHILD_IDENTITY_INVALID')
    old = matches[0]
    if old.get('spawn_state') != 'spawn_intent' or old.get('child_pid') is not None or nonce != old.get('launch_nonce'):
        raise SystemExit('LEDGER_CHILD_ALREADY_RECORDED')
    if (job_scope.get('schema_version') != 1 or job_scope.get('launch_nonce') != nonce
            or not isinstance(job_scope.get('job_object_name'), str)
            or not re.fullmatch(r'Local\\FieldworkTraining-[a-f0-9]{64}', job_scope['job_object_name'])
            or job_scope.get('child_pid') != pid or job_scope.get('child_create_time') != create_time
            or job_scope.get('launcher_pid') != launcher_pid
            or job_scope.get('launcher_create_time') != launcher_create_time
            or job_scope.get('reserved_cpu_seconds') != old.get('cpu_seconds_reserved')
            or job_scope.get('in_exact_job') is not True or job_scope.get('kill_on_close') is not True
            or type(job_scope.get('limit_flags')) is not int
            or job_scope['limit_flags'] & (JOB_OBJECT_LIMIT_JOB_TIME | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
                != (JOB_OBJECT_LIMIT_JOB_TIME | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
            or type(job_scope.get('cpu_limit_ticks')) is not int or job_scope['cpu_limit_ticks'] <= 0
            or job_scope['cpu_limit_ticks'] > old.get('cpu_seconds_reserved') * CPU_TIME_TICKS_PER_SECOND
            or not isinstance(job_scope.get('job_scope_nonce'), str)
            or not re.fullmatch('[a-f0-9]{64}', job_scope['job_scope_nonce'])):
        raise SystemExit('LEDGER_JOB_SCOPE_RECEIPT_INVALID')
    scope_digest = hashlib.sha256(_json_bytes(job_scope)).hexdigest()
    new = dict(old, spawn_state='spawned', child_pid=pid, child_create_time=create_time,
               launcher_pid=launcher_pid, launcher_create_time=launcher_create_time,
               job_object_name=job_scope['job_object_name'], job_scope_sha256=scope_digest)
    prospective = {**current, 'configs': [new if row['tag'] == tag else row for row in current['configs']]}
    _validate_ledger(prospective)
    seq, digest = _append_event(history_path, current, 'child-started', new)
    updated = {**prospective,
               'history_seq': seq, 'history_digest': digest}
    _write_ledger_atomic(path, updated)
    _write_anchor(anchor_path, receipt_path, path, history_path, updated)
    return updated, new


def _positive_dead_identity(pid, create_time):
    if type(pid) is not int or pid <= 0 or not isinstance(create_time, (int, float)):
        return None
    try:
        actual = psutil.Process(pid).create_time()
    except psutil.NoSuchProcess:
        return 'pid-absent'
    except psutil.Error:
        return None
    return 'pid-reused' if actual != create_time else None


def recover_orphan_attempt(path, tag, *, current_lock, history_path=HISTORY, anchor_path=None, receipt_path=None, now=None):
    """Settle a lost attempt only from owner/tree death proof or durable never-spawn state."""
    if not isinstance(current_lock, dict) or current_lock.get('pid') != os.getpid() or current_lock.get('create_time') != psutil.Process().create_time() or current_lock.get('product') != 'fieldwork' or current_lock.get('purpose') != 'round5-config-orphan-recovery' or current_lock.get('owner') != f"fieldwork-dataset-round5-round5-config-orphan-recovery-{os.getpid()}":
        raise SystemExit('ORPHAN_RECOVERY_REQUIRES_CURRENT_LOCK')
    current = _load_current_ledger(path, history_path, anchor_path=anchor_path, receipt_path=receipt_path)
    matches = [row for row in current['configs'] if row.get('tag') == tag and row.get('status') == 'running']
    if len(matches) != 1:
        raise SystemExit('ORPHAN_RESERVATION_NOT_FOUND')
    row = matches[0]
    owner_proof = _positive_dead_identity(row.get('reservation_pid'), row.get('reservation_create_time'))
    if owner_proof is None:
        raise SystemExit('ORPHAN_OWNER_NOT_PROVEN_DEAD')
    if row.get('child_pid') is None:
        if row.get('spawn_state') != 'not_started':
            raise SystemExit('ORPHAN_CHILD_IDENTITY_UNCERTAIN')
        child_proof = 'verified-never-spawn-intent-recorded'
    else:
        child_proof = _positive_dead_identity(row.get('child_pid'), row.get('child_create_time'))
        if child_proof is None:
            raise SystemExit('ORPHAN_PROCESS_TREE_NOT_PROVEN_DEAD')
        launcher_proof = _positive_dead_identity(row.get('launcher_pid'), row.get('launcher_create_time'))
        if launcher_proof is None:
            raise SystemExit('ORPHAN_LAUNCHER_NOT_PROVEN_DEAD')
        if row.get('launcher_pid') == row.get('child_pid'):
            launcher_proof = child_proof
    now = now or datetime.now(timezone.utc)
    try:
        started = datetime.fromisoformat(row['started_utc'].replace('Z', '+00:00'))
        wall = max(0.0, (now - started).total_seconds())
    except (TypeError, ValueError) as exc:
        raise SystemExit('ORPHAN_START_TIME_INVALID') from exc
    audit = {'method': 'exact owner/module-child/launcher PID-birth death proof or durable never-spawn state',
             'owner_proof': owner_proof, 'child_proof': child_proof,
             'recovered_utc': now.isoformat(), 'recovered_by_pid': os.getpid(),
             'recovered_by_create_time': psutil.Process().create_time(),
             'conservative_cpu_charge_seconds': row['cpu_seconds_reserved'],
             'charged_full_reserved_budget': True}
    if row.get('child_pid') is not None:
        audit['launcher_proof'] = launcher_proof
    terminal = dict(row)
    finish_attempt(path, current, terminal, status='failed', elapsed_s=wall,
                   cpu_seconds_charged=row['cpu_seconds_reserved'],
                   fields={'error_type': 'ProcessLost', 'recovery': audit}, history_path=history_path, kind='recover',
                   anchor_path=anchor_path, receipt_path=receipt_path)
    return audit


def reserve_configuration(path, tag, config, why, *, lock_record, history_path=HISTORY, anchor_path=None, receipt_path=None):
    """Reload and persist a unique budget reservation; caller MUST hold product_lock."""
    if not _valid_tag(tag):
        raise SystemExit('TAG_INVALID')
    if not isinstance(why, str) or not why.strip():
        raise SystemExit('WHY_REQUIRED')
    if not isinstance(config, dict):
        raise SystemExit('CONFIG_INVALID')
    try:
        if rr.default_config(**config) != config:
            raise ValueError('noncanonical config')
    except (TypeError, ValueError) as exc:
        raise SystemExit('CONFIG_INVALID') from exc
    current = _load_current_ledger(path, history_path, anchor_path=anchor_path, receipt_path=receipt_path)
    before_count = len(current['configs'])
    cpu_spent = _cpu_spent(current)
    remaining = CAP_CPU_SECONDS - cpu_spent
    before_hours = cpu_spent / 3600
    if any(row.get('status') == 'running' for row in current['configs']):
        raise SystemExit('LEDGER_ATTEMPT_IN_PROGRESS')
    if any(row['tag'] == tag for row in current['configs']):
        raise SystemExit('TAG_ALREADY_USED')
    if before_count >= CAP_CONFIGS_TOTAL:
        raise SystemExit(f'EXPLORATION_CONFIG_CAP_EXHAUSTED configs={before_count}')
    try:
        budget = plan_run_budget(remaining, config['threads'])
    except SystemExit as exc:
        raise SystemExit(f'EXPLORATION_CPU_CAP_EXHAUSTED spent={cpu_spent} remaining={remaining}') from exc
    run_budget = budget['cpu_seconds_reserved']
    if type(lock_record.get('pid')) is not int or lock_record['pid'] != os.getpid() or not isinstance(lock_record.get('create_time'), (int, float)) or lock_record['create_time'] != psutil.Process().create_time() or not isinstance(lock_record.get('owner'), str) or not lock_record['owner'] or lock_record.get('product') != 'fieldwork' or lock_record.get('purpose') != f'train-{tag}':
        raise SystemExit('LOCK_OWNER_IDENTITY_INVALID')
    attempt = {'tag': tag, 'recipe': rr.RECIPE, 'config': config, 'why': why,
               'round': 5, 'complete': False, 'status': 'running', 'elapsed_s': 0,
               'started_utc': datetime.now(timezone.utc).isoformat(), 'cpu_seconds_reserved': run_budget,
               'reservation_pid': lock_record['pid'], 'reservation_create_time': lock_record['create_time'],
               'lock_owner': lock_record['owner'], 'execution_mode': 'windows-job-object-kill-on-close-v1',
               'launch_nonce': secrets.token_hex(32), 'spawn_state': 'not_started',
               'child_pid': None, 'child_create_time': None,
               'launcher_pid': None, 'launcher_create_time': None,
               'job_object_name': None, 'job_scope_sha256': None}
    _validate_ledger({**current, 'configs': [*current['configs'], attempt]})
    seq, digest = _append_event(history_path, current, 'reserve', attempt)
    updated = {**current, 'configs': [*current['configs'], attempt], 'history_seq': seq, 'history_digest': digest}
    _write_ledger_atomic(path, updated)
    _write_anchor(anchor_path, receipt_path, path, history_path, updated)
    return updated, attempt, {'configs_before': before_count, 'hours_before': before_hours,
                              'cpu_spent_before': cpu_spent, 'cpu_remaining_before': remaining,
                              'run_cpu_budget_seconds': run_budget,
                              'run_wall_deadline_seconds': budget['wall_deadline_seconds'],
                              'parallelism_bound': budget['parallelism_bound']}


def finish_attempt(path, ledger_value, attempt, *, status, elapsed_s, cpu_seconds_charged, fields=None, history_path=HISTORY, kind='finish', anchor_path=None, receipt_path=None):
    if status not in ('failed', 'complete') or isinstance(elapsed_s, bool) or not isinstance(elapsed_s, (int, float)) or not math.isfinite(elapsed_s) or elapsed_s < 0:
        raise SystemExit('LEDGER_RESULT_INVALID')
    if type(cpu_seconds_charged) is not int or not 0 <= cpu_seconds_charged <= attempt['cpu_seconds_reserved']:
        raise SystemExit('LEDGER_CPU_CHARGE_INVALID')
    attempt.update(fields or {})
    attempt.update({'complete': status == 'complete', 'status': status, 'elapsed_s': round(elapsed_s, 3),
                    'cpu_seconds_charged': cpu_seconds_charged})
    current = _load_current_ledger(path, history_path, anchor_path=anchor_path, receipt_path=receipt_path)
    prospective = {**current, 'configs': [attempt if row['tag'] == attempt['tag'] else row for row in current['configs']]}
    _validate_ledger(prospective)
    seq, digest = _append_event(history_path, current, kind, attempt)
    updated = {**prospective,
               'history_seq': seq, 'history_digest': digest}
    _write_ledger_atomic(path, updated)
    _write_anchor(anchor_path, receipt_path, path, history_path, updated)


def population(rows):
    members = [{'id': s['id'], 'label': s['label'], 'sha256': s['sha256'], 'group': s['group']} for s in sorted(rows, key=lambda s: s['id'])]
    return members, hashlib.sha256(canonical(members)).hexdigest()


def predict(net, rows, model_digest):
    out = []
    files = {s['id']: resolve_media(s['file']) for s in rows}
    members, _ = population(rows)
    with torch.inference_mode():
        for m in members:
            try:
                raw = Path(files[m['id']]).read_bytes()
                if hashlib.sha256(raw).hexdigest() != m['sha256']:
                    out.append({**{k: m[k] for k in ('id', 'label', 'sha256')}, 'model': model_digest, 'status': 'missing', 'logits': []}); continue
                arr = center(load_resized(files[m['id']]))
            except Exception:
                out.append({**{k: m[k] for k in ('id', 'label', 'sha256')}, 'model': model_digest, 'status': 'decode_failed', 'logits': []}); continue
            try:
                lg = net(to_tensor([arr]))[0].tolist()
                out.append({**{k: m[k] for k in ('id', 'label', 'sha256')}, 'model': model_digest, 'status': 'ok', 'logits': lg})
            except Exception:
                out.append({**{k: m[k] for k in ('id', 'label', 'sha256')}, 'model': model_digest, 'status': 'inference_failed', 'logits': []})
    return members, out


def run_verifier(directory, members, pd, rows, model_digest, service):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'population.json').write_bytes(canonical({'classes': 5, 'population_digest': pd, 'members': members}))
    (directory / 'predictions.jsonl').write_bytes(b''.join(canonical(r) + b'\n' for r in rows))
    (directory / 'service-metrics.json').write_bytes(canonical(service))
    p = subprocess.run([sys.executable, '-I', '-B', str(VERIFIER), str(directory / 'population.json'), str(directory / 'predictions.jsonl'),
                        model_digest, str(directory / 'service-metrics.json')], capture_output=True, text=True, timeout=900)
    (directory / 'independent-report.json').write_text(p.stdout)
    return p.returncode, json.loads(p.stdout)


def aggregate(m):
    return {k: m.get(k) for k in ('n', 'ok', 'accuracy', 'coverage', 'macro_f1', 'recall', 'precision', 'f1', 'support', 'matrix', 'wilson_accuracy',
                                  'group_support', 'group_accuracy_interval', 'cross_entropy', 'disposition_counts', 'status')}


def validation_eval(tag, result, view, log):
    sel = result['selected']
    net = rr.load_model(sel['path'], sel['checkpoint_digest'])
    cand = C5 / 'candidates' / tag
    cand.mkdir(parents=True, exist_ok=True)
    save_file(net.state_dict(), str(cand / 'model.safetensors'))
    model_digest = hashlib.sha256((cand / 'model.safetensors').read_bytes()).hexdigest()
    rows = [s for s in view['samples'] if s['split'] == 'validation']
    torch.set_num_threads(2)
    members, pd = population(rows)
    _, recs = predict(net, rows, model_digest)
    service = evaluate(members, [dict(r) for r in recs], 5, model_digest)
    code, rep = run_verifier(EVIDENCE / 'metrics' / tag / 'validation', members, pd, recs, model_digest, service)
    val = {'tag': tag, 'recipe': rr.RECIPE, 'model_digest': model_digest, 'checkpoint_digest': sel['checkpoint_digest'], 'selected_epoch': sel['epoch'],
           'dataset_digest': view['digest'], 'population_digest': pd, 'service': aggregate(service), 'verifier_exit': code,
           'verifier_population_digest_matches': rep['population_digest_matches'], 'verifier_service_differences': rep.get('service_differences'),
           'verifier_group_bootstrap': rep.get('group_bootstrap'),
           'verifier_sha256': hashlib.sha256(VERIFIER.read_bytes()).hexdigest()}
    write_json(EVIDENCE / 'metrics' / tag / 'validation-summary.json', val)
    log(json.dumps({'event': 'validation', 'accuracy': service['accuracy'], 'macro_f1': service['macro_f1'], 'cross_entropy': service['cross_entropy'],
                    'verifier_exit': code, 'differences': rep.get('service_differences')}))
    return val


def _product_lock_module():
    helper = ROOT.parent / 'tools/product_lock.py'
    spec = importlib.util.spec_from_file_location('portfolio_product_lock', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_child_scope(tag, config, why, nonce, parent_pid, parent_create_time, lock_owner, gate_path, *,
                        lock_path=None, ledger_path=LEDGER, history_path=HISTORY,
                        anchor_path=None, receipt_path=None):
    me = psutil.Process()
    if parent_pid == me.pid:
        raise SystemExit('CHILD_PARENT_SELF_FORBIDDEN')
    if type(parent_pid) is not int or parent_pid <= 0 or not isinstance(parent_create_time, (int, float)):
        raise SystemExit('CHILD_PARENT_IDENTITY_INVALID')
    try:
        parent = psutil.Process(parent_pid)
        actual = parent.create_time()
        ancestors = me.parents()
    except psutil.Error as exc:
        raise SystemExit('CHILD_PARENT_NOT_LIVE') from exc
    if actual != parent_create_time:
        raise SystemExit('CHILD_PARENT_IDENTITY_MISMATCH')
    ancestor_matches = False
    for ancestor in ancestors:
        try:
            if ancestor.pid == parent_pid and ancestor.create_time() == parent_create_time:
                ancestor_matches = True
                break
        except psutil.Error:
            continue
    if not ancestor_matches:
        raise SystemExit('CHILD_PARENT_NOT_LAUNCH_ANCESTOR')
    lock_path = lock_path or (ROOT.parent / '.cache/product-build.lock')
    lock = _product_lock_module().read_owner(lock_path)
    purpose = f'train-{tag}'
    if not lock or lock.get('pid') != parent_pid or lock.get('create_time') != parent_create_time or lock.get('product') != 'fieldwork' or lock.get('purpose') != purpose:
        raise SystemExit('CHILD_LOCK_SCOPE_MISMATCH')
    expected_owner = f'fieldwork-dataset-round5-{purpose}-{parent_pid}'
    if not isinstance(lock_owner, str) or lock_owner != expected_owner:
        raise SystemExit('CHILD_LOCK_OWNER_MISMATCH')
    if not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{64}', nonce):
        raise SystemExit('CHILD_LAUNCH_NONCE_INVALID')
    current = _load_current_ledger(ledger_path, history_path, anchor_path=anchor_path, receipt_path=receipt_path)
    attempts = [row for row in current['configs'] if row.get('tag') == tag and row.get('status') == 'running']
    if len(attempts) != 1:
        raise SystemExit('CHILD_ACTIVE_RESERVATION_MISSING')
    attempt = attempts[0]
    me_time = me.create_time()
    if (attempt.get('config') != config or attempt.get('why') != why or attempt.get('launch_nonce') != nonce
            or attempt.get('spawn_state') != 'spawned' or attempt.get('reservation_pid') != parent_pid
            or attempt.get('reservation_create_time') != parent_create_time or attempt.get('lock_owner') != lock_owner
            or attempt.get('child_pid') != me.pid or attempt.get('child_create_time') != me_time
            or type(attempt.get('launcher_pid')) is not int or attempt.get('launcher_pid') <= 0
            or not isinstance(attempt.get('launcher_create_time'), (int, float))):
        raise SystemExit('CHILD_ACTIVE_RESERVATION_MISMATCH')
    gate = Path(gate_path)
    if gate.is_symlink() or not gate.is_file():
        raise SystemExit('CHILD_START_GATE_MISSING')
    try:
        value = json.loads(gate.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit('CHILD_START_GATE_INVALID') from exc
    expected = {'schema_version': 4, 'tag': tag, 'config_sha256': hashlib.sha256(_json_bytes(config)).hexdigest(),
                'why_sha256': hashlib.sha256(why.encode('utf-8')).hexdigest(), 'launch_nonce': nonce,
                'parent_pid': parent_pid,
                'parent_create_time': parent_create_time, 'lock_owner': lock_owner,
                'child_pid': me.pid, 'child_create_time': me_time,
                'launcher_pid': attempt['launcher_pid'], 'launcher_create_time': attempt['launcher_create_time']}
    if (not isinstance(value, dict) or set(value) != set(expected) | {'job_scope'}
            or any(value.get(key) != expected_value for key, expected_value in expected.items())
            or not isinstance(value.get('job_scope'), dict)
            or value['job_scope'].get('job_object_name') != attempt.get('job_object_name')
            or hashlib.sha256(_json_bytes(value['job_scope'])).hexdigest() != attempt.get('job_scope_sha256')):
        raise SystemExit('CHILD_START_GATE_SCOPE_MISMATCH')
    verify_current_job_budget(attempt['cpu_seconds_reserved'], job_name=value['job_scope'].get('job_object_name'),
            launch_nonce=nonce, launcher_pid=attempt['launcher_pid'],
            launcher_create_time=attempt['launcher_create_time'])


def _wait_for_child_gate(tag, config, why, nonce, parent_pid, parent_create_time, lock_owner, gate_path, **scope_paths):
    deadline = time.monotonic() + 30
    gate = Path(gate_path)
    if parent_pid == os.getpid():
        raise SystemExit('CHILD_PARENT_SELF_FORBIDDEN')
    while not gate.exists():
        try:
            if psutil.Process(parent_pid).create_time() != parent_create_time:
                raise SystemExit('CHILD_PARENT_IDENTITY_MISMATCH')
        except psutil.Error as exc:
            raise SystemExit('CHILD_PARENT_NOT_LIVE') from exc
        lock_path = scope_paths.get('lock_path') or (ROOT.parent / '.cache/product-build.lock')
        lock = _product_lock_module().read_owner(lock_path)
        if not lock or lock.get('pid') != parent_pid or lock.get('create_time') != parent_create_time or lock.get('purpose') != f'train-{tag}':
            raise SystemExit('CHILD_LOCK_SCOPE_MISMATCH')
        if time.monotonic() >= deadline:
            raise SystemExit('CHILD_START_GATE_TIMEOUT')
        time.sleep(0.025)
    _verify_child_scope(tag, config, why, nonce, parent_pid, parent_create_time, lock_owner, gate_path, **scope_paths)


def _execute_reserved(tag, cfg, why, child_result_path, *, parent_pid, parent_create_time, lock_owner, gate_path, nonce):
    _wait_for_child_gate(tag, cfg, why, nonce, parent_pid, parent_create_time, lock_owner, gate_path)
    ev = EVIDENCE / 'optimize' / tag
    def log(line):
        print(line, flush=True)

    scope_stop = threading.Event()
    def scope_watchdog():
        while not scope_stop.wait(0.25):
            try:
                _verify_child_scope(tag, cfg, why, nonce, parent_pid, parent_create_time, lock_owner, gate_path)
            except BaseException:
                # The parent owns the Windows Job Object and will record the
                # process exit. Never keep training after its lock lease is gone.
                os._exit(91)
    watchdog = threading.Thread(target=scope_watchdog, daemon=True)
    watchdog.start()
    peak = {'rss': 0, 'min_available': 1 << 62}
    sample_stop = threading.Event()
    def sample():
        me = psutil.Process()
        while not sample_stop.is_set():
            try:
                peak['rss'] = max(peak['rss'], me.memory_info().rss)
                peak['min_available'] = min(peak['min_available'], psutil.virtual_memory().available)
            except psutil.Error:
                return
            sample_stop.wait(0.5)
    sampler = threading.Thread(target=sample, daemon=True)
    t0 = time.monotonic()
    sampler.start()
    try:
        ctx = context()
        ws = ctx['workspace_id']
        set_registry_env()
        op = Store(dsn=admin_dsn())
        vid, vdig = version_ref()
        view = training_view(op, ws, vid)
        if view['digest'] != vdig or any(s['split'] not in ('train', 'validation') for s in view['samples']):
            raise SystemExit('TRAINING_VIEW_LINEAGE')
        service = RightsService(request_store(ws), load_trusted_registry)
        rights_verified = verify_trainval_rights(service, ws, view['rights_dataset_id'],
                                                  ctx['actors']['steward'], view['samples'])
        log(json.dumps({'event': 'training_child_admitted', 'dataset_digest': vdig,
                        'train': sum(s['split'] == 'train' for s in view['samples']),
                        'validation': sum(s['split'] == 'validation' for s in view['samples']),
                        'rights_verified': rights_verified, 'config': cfg, 'why': why,
                        'protected_rows_loaded': 0}))
        result = rr.train(view, C5 / 'runs' / tag, cfg, log=log)
        val = validation_eval(tag, result, view, log)
        elapsed = time.monotonic() - t0
        train_ids = {s['id'] for s in view['samples'] if s['split'] == 'train'}
        steps = [json.loads(line) for line in (C5 / 'runs' / tag / 'steps.jsonl').open()]
        audit = {'recipe': rr.RECIPE, 'parameters': result['parameters'], 'steps': len(steps), 'updates': result['updates'],
                 'all_batch_ids_in_train_split': all(set(s['ids']) <= train_ids for s in steps),
                 'examples_processed': sum(s['n'] for s in steps), 'expected_examples': len(train_ids) * cfg['epochs'],
                 'grad_norm_min': min(s['grad_norm'] for s in steps), 'grad_norm_max': max(s['grad_norm'] for s in steps),
                 'update_norm_min': min(s['update_norm'] for s in steps), 'update_norm_max': max(s['update_norm'] for s in steps),
                 'all_losses_finite': all(s['loss'] == s['loss'] and abs(s['loss']) != float('inf') for s in steps),
                 'initial_digest': result['initial_digest'], 'final_digest': result['final_digest'],
                 'weight_digests_differ': result['initial_digest'] != result['final_digest'], 'selected': result['selected'],
                 'selection_uses': 'validation split cross-entropy only', 'protected_rows_loaded_by_training_process': 0,
                 'peak_rss_bytes': peak['rss'], 'rss_within_2GiB': peak['rss'] <= 2 * 1024 ** 3,
                 'min_available_ram_bytes': peak['min_available'], 'fresh_run_no_stored_result_reuse': True,
                 'train_elapsed_s': result['elapsed_s'], 'child_elapsed_s': round(elapsed, 2)}
        write_json(ev / 'optimize-audit.json', audit)
        write_json(ev / 'train-result.json', result)
        summary = {'tag': tag, 'recipe': rr.RECIPE, 'selected_epoch': result['selected']['epoch'],
                   'validation_cross_entropy': result['selected']['validation_loss'],
                   'validation_accuracy': val['service']['accuracy'], 'validation_macro_f1': val['service']['macro_f1'],
                   'model_digest': val['model_digest'], 'checkpoint_digest': result['selected']['checkpoint_digest'],
                   'peak_rss_bytes': peak['rss'], 'train_elapsed_s': result['elapsed_s'],
                   'child_elapsed_s': round(elapsed, 2), 'protected_rows_loaded': 0}
        write_json(child_result_path, summary)
        return 0
    finally:
        sample_stop.set()
        sampler.join(timeout=2)
        scope_stop.set()
        watchdog.join(timeout=1)


def _child_cli(args):
    cfg = rr.default_config(**json.loads(args.config_json))
    if not _valid_tag(args.tag):
        raise SystemExit('TAG_INVALID')
    if not isinstance(args.why, str) or not args.why.strip():
        raise SystemExit('WHY_REQUIRED')
    if args.parent_pid == os.getpid():
        raise SystemExit('CHILD_PARENT_SELF_FORBIDDEN')
    if not args.child_ready:
        raise SystemExit('CHILD_READY_PATH_REQUIRED')
    expected_ready = (EVIDENCE / 'optimize' / args.tag / 'child-ready.json').resolve()
    if Path(args.child_ready).resolve() != expected_ready:
        raise SystemExit('CHILD_READY_PATH_INVALID')
    _write_child_ready(args.child_ready, args.child_nonce)
    return _execute_reserved(args.tag, cfg, args.why, args.child_result,
                             parent_pid=args.parent_pid, parent_create_time=args.parent_create_time,
                             lock_owner=args.lock_owner, gate_path=args.start_gate, nonce=args.child_nonce)


def _gate_writer(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as f:
        json.dump(data, f, sort_keys=True, separators=(',', ':'), allow_nan=False)
        f.flush(); os.fsync(f.fileno())


def _write_child_ready(path, nonce):
    if not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{64}', nonce):
        raise SystemExit('CHILD_LAUNCH_NONCE_INVALID')
    process = psutil.Process()
    target = Path(path)
    if target.parent.is_symlink() or not target.parent.is_dir():
        raise SystemExit('CHILD_READY_DIRECTORY_UNSAFE')
    _gate_writer(target, {'schema_version': 1, 'pid': process.pid,
                        'create_time': process.create_time(), 'launch_nonce': nonce})


def _parent_cli(tag, cfg, why):
    if not _valid_tag(tag):
        raise SystemExit('TAG_INVALID')
    if not isinstance(why, str) or not why.strip():
        raise SystemExit('WHY_REQUIRED')
    ev = EVIDENCE / 'optimize' / tag
    ev.mkdir(parents=True, exist_ok=True)
    logf = (ev / 'train.log').open('a', encoding='utf-8')
    def log(line):
        logf.write(line + '\n'); logf.flush(); print(line, flush=True)
    purpose = f'train-{tag}'
    owner = f'fieldwork-dataset-round5-{purpose}-{os.getpid()}'
    child_result_path = ev / 'child-result.json'
    child_ready_path = ev / 'child-ready.json'
    gate_path = ev / 'execution-gate.json'
    process_receipt_path = ev / 'child-process.json'
    attempt = None
    led = None
    receipt = None
    started = time.monotonic()
    with heavy_slot(purpose, log, data_path=C5):
        identity = lock_identity(owner=owner, purpose=purpose)
        led, attempt, prior = reserve_configuration(LEDGER, tag, cfg, why, lock_record=identity)
        started = time.monotonic()
        log(json.dumps({'event': 'admission', 'config': cfg, 'why': why,
                        'configs_used_before': prior['configs_before'],
                        'cpu_seconds_spent_before': prior['cpu_spent_before'],
                        'cpu_seconds_remaining_before': prior['cpu_remaining_before'],
                        'run_cpu_budget_seconds': prior['run_cpu_budget_seconds'],
                        'run_wall_deadline_seconds': prior['run_wall_deadline_seconds']}))
        try:
            if gate_path.exists() or child_result_path.exists() or child_ready_path.exists():
                raise RuntimeError('TRAINING_EVIDENCE_PATH_ALREADY_EXISTS')
            led, attempt = record_spawn_intent(LEDGER, tag)
            nonce = attempt['launch_nonce']
            child_args = [sys.executable, '-B', str(Path(__file__).resolve()), '--_execute-reserved',
                          '--tag', tag, '--config-json', json.dumps(cfg, sort_keys=True), '--why', why,
                          '--parent-pid', str(identity['pid']), '--parent-create-time', str(identity['create_time']),
                          '--lock-owner', owner, '--child-nonce', nonce,
                          '--start-gate', str(gate_path), '--child-ready', str(child_ready_path),
                          '--child-result', str(child_result_path)]
            env = dict(os.environ, PYTHONPATH=str(ROOT))
            for key in ('OMP_NUM_THREADS', 'MKL_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'NUMEXPR_NUM_THREADS', 'VECLIB_MAXIMUM_THREADS'):
                env[key] = str(cfg['threads'])
            def on_spawn(pid, create_time, launcher_pid, launcher_create_time, job_scope):
                nonlocal led, attempt
                led, attempt = record_child_started(LEDGER, tag, pid, create_time, nonce,
                        launcher_pid=launcher_pid, launcher_create_time=launcher_create_time,
                        job_scope=job_scope)
                write_json(process_receipt_path, {'schema_version': 1, 'parent_pid': identity['pid'],
                             'parent_create_time': identity['create_time'], 'lock_owner': owner,
                             'child_pid': pid, 'child_create_time': create_time,
                             'launcher_pid': launcher_pid, 'launcher_create_time': launcher_create_time,
                             'job_scope_sha256': hashlib.sha256(_json_bytes(job_scope)).hexdigest(),
                              'launch_nonce_sha256': hashlib.sha256(nonce.encode('ascii')).hexdigest(),
                             'launched_utc': datetime.now(timezone.utc).isoformat(),
                             'job_mode': 'windows-job-object-kill-on-close-v1'})
            def start_gate(job_scope):
                gate = {'schema_version': 4, 'tag': tag,
                        'config_sha256': hashlib.sha256(_json_bytes(cfg)).hexdigest(),
                        'why_sha256': hashlib.sha256(why.encode('utf-8')).hexdigest(), 'launch_nonce': nonce,
                        'parent_pid': identity['pid'],
                        'parent_create_time': identity['create_time'], 'lock_owner': owner,
                        'child_pid': attempt['child_pid'], 'child_create_time': attempt['child_create_time'],
                        'launcher_pid': attempt['launcher_pid'], 'launcher_create_time': attempt['launcher_create_time'],
                        'job_scope': job_scope}
                _gate_writer(gate_path, gate)
            receipt = run_bounded_child(child_args, env=env, stdout=logf,
                    cpu_budget_seconds=attempt['cpu_seconds_reserved'],
                    parallelism_bound=CPU_PARALLELISM_BOUND, on_spawn=on_spawn, start_gate=start_gate,
                    ready_path=child_ready_path,
                    expected_markers=[str(Path(__file__).resolve()), '--_execute-reserved', '--tag', tag,
                                      '--child-nonce', nonce, '--child-ready', str(child_ready_path)],
                    expected_cwd=ROOT, expected_nonce=nonce)
            write_json(process_receipt_path, {'schema_version': 1, 'parent_pid': identity['pid'],
                         'parent_create_time': identity['create_time'], 'lock_owner': owner,
                         'child_pid': receipt['child_pid'], 'child_create_time': receipt['child_create_time'],
                         'launcher_pid': receipt['launcher_pid'], 'launcher_create_time': receipt['launcher_create_time'],
                         'job_scope_sha256': hashlib.sha256(_json_bytes(receipt['job_scope'])).hexdigest(),
                         'returncode': receipt['returncode'], 'timed_out': receipt['timed_out'],
                         'cpu_limit_reached': receipt['cpu_limit_reached'], 'cpu_accounting': receipt['cpu_accounting'],
                         'wall_elapsed_seconds': receipt['wall_elapsed_seconds'],
                         'process_exit_receipts': receipt['process_exit_receipts'],
                         'job_kill_on_close': receipt['job_kill_on_close']})
            if receipt['timed_out'] or receipt['returncode'] != 0:
                raise RuntimeError('TRAINING_CHILD_CPU_DEADLINE' if receipt['timed_out'] else f"TRAINING_CHILD_EXIT_{receipt['returncode']}")
            if not child_result_path.is_file() or child_result_path.is_symlink():
                raise RuntimeError('TRAINING_CHILD_RESULT_MISSING')
            result = json.loads(child_result_path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
            required = {'tag', 'recipe', 'selected_epoch', 'validation_cross_entropy', 'validation_accuracy',
                        'validation_macro_f1', 'model_digest', 'checkpoint_digest', 'peak_rss_bytes',
                        'train_elapsed_s', 'child_elapsed_s', 'protected_rows_loaded'}
            if not isinstance(result, dict) or set(result) != required or result['tag'] != tag or result['recipe'] != rr.RECIPE or result['protected_rows_loaded'] != 0:
                raise RuntimeError('TRAINING_CHILD_RESULT_INVALID')
            observed_cpu = int(math.ceil(receipt['cpu_accounting']['total_seconds']))
            charged_cpu = min(attempt['cpu_seconds_reserved'], max(1, observed_cpu + CPU_GUARD_SECONDS))
            elapsed = receipt['wall_elapsed_seconds']
            finish_attempt(LEDGER, led, attempt, status='complete', elapsed_s=elapsed,
                    cpu_seconds_charged=charged_cpu,
                    fields={'selected_epoch': result['selected_epoch'],
                            'validation_cross_entropy': result['validation_cross_entropy'],
                            'validation_accuracy': result['validation_accuracy'], 'validation_macro_f1': result['validation_macro_f1'],
                            'model_digest': result['model_digest'], 'checkpoint_digest': result['checkpoint_digest'],
                            'peak_rss_bytes': result['peak_rss_bytes'], 'train_elapsed_s': result['train_elapsed_s'],
                            'observed_cpu_seconds': observed_cpu, 'wall_elapsed_s': round(elapsed, 3)})
            log(json.dumps({'event': 'validation_complete', 'cpu_seconds_observed': observed_cpu,
                            'cpu_seconds_charged': charged_cpu, 'wall_elapsed_seconds': round(elapsed, 2)}))
        except BaseException as exc:
            if attempt is not None and attempt.get('status') == 'running':
                if receipt is None:
                    elapsed = time.monotonic() - started
                    charged = attempt['cpu_seconds_reserved'] if (attempt.get('child_pid') is not None
                            or attempt.get('spawn_state') != 'not_started') else min(
                                attempt['cpu_seconds_reserved'], max(CPU_GUARD_SECONDS,
                                    math.ceil(elapsed * CPU_PARALLELISM_BOUND)))
                elif receipt.get('timed_out') or receipt.get('cpu_limit_reached'):
                    charged = attempt['cpu_seconds_reserved']
                    elapsed = receipt['wall_elapsed_seconds']
                else:
                    observed = int(math.ceil(receipt.get('cpu_accounting', {}).get('total_seconds', 0)))
                    charged = min(attempt['cpu_seconds_reserved'], max(1, observed + CPU_GUARD_SECONDS))
                    elapsed = receipt.get('wall_elapsed_seconds', time.monotonic() - started)
                finish_attempt(LEDGER, led, attempt, status='failed', elapsed_s=elapsed,
                        cpu_seconds_charged=charged,
                        fields={'error_type': type(exc).__name__, 'observed_cpu_seconds': receipt.get('cpu_accounting', {}).get('total_seconds') if receipt else None,
                                'wall_elapsed_s': round(elapsed, 3)})
            raise


def _recover_cli(tag):
    if not _valid_tag(tag):
        raise SystemExit('TAG_INVALID')
    purpose = 'round5-config-orphan-recovery'
    owner = f'fieldwork-dataset-round5-{purpose}-{os.getpid()}'
    def log(line):
        print(line, flush=True)
    with metadata_lock(purpose, log) as identity:
        recover_stale_pause(current_lock=identity,
                            supervisor=lambda action: subprocess.run(
                                [str(ROOT.parent / 'folio/.venv/Scripts/python.exe'), 'scripts/live_supervisor.py',
                                 action, '--lock-owner', owner], cwd=str(ROOT.parent / 'folio'),
                                env=dict(os.environ, PYTHONPATH='.'), capture_output=True, text=True,
                                timeout=900).returncode,
                            health=__import__('r5_host').folio_health, log=log)
        record = recover_orphan_attempt(LEDGER, tag, current_lock=identity)
        log(json.dumps({'event': 'orphan_attempt_recovered', 'tag': tag,
                        'cpu_seconds_charged': record['conservative_cpu_charge_seconds'],
                        'owner_proof': record['owner_proof'], 'child_proof': record['child_proof']}))


def _reconcile_cli():
    purpose = 'round5-config-ledger-reconcile'
    def log(line):
        print(line, flush=True)
    with metadata_lock(purpose, log) as identity:
        result = reconcile_budget_state(current_lock=identity)
        log(json.dumps({'event': 'training_budget_reconciled', 'reconciled': result['reconciled'],
                        'history_seq': result['history_seq'], 'history_digest': result['history_digest'],
                        'unanchored_event_kind': result.get('unanchored_event_kind'),
                        'audit_dir': result.get('audit_dir')}))


def _bootstrap_cli():
    purpose = 'round5-config-ledger-bootstrap'
    owner = f'fieldwork-dataset-round5-{purpose}-{os.getpid()}'
    def log(line):
        print(line, flush=True)
    with metadata_lock(purpose, log) as identity:
        receipt = initialize_budget_ledger(lock_record=identity)
        log(json.dumps({'event': 'training_budget_genesis_initialized',
                        'bootstrap_id': receipt['bootstrap_id'],
                        'genesis_digest': receipt['history_digest'],
                        'source_sha256': receipt['source_sha256'],
                        'round5_configs_used': 0}))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--tag')
    ap.add_argument('--config')
    ap.add_argument('--why')
    ap.add_argument('--_execute-reserved', action='store_true', dest='execute_reserved')
    ap.add_argument('--config-json')
    ap.add_argument('--parent-pid', type=int)
    ap.add_argument('--parent-create-time', type=float)
    ap.add_argument('--lock-owner')
    ap.add_argument('--child-nonce')
    ap.add_argument('--start-gate')
    ap.add_argument('--child-ready')
    ap.add_argument('--child-result')
    ap.add_argument('--recover-orphan')
    ap.add_argument('--initialize-ledger', action='store_true')
    ap.add_argument('--reconcile-budget', action='store_true')
    a = ap.parse_args(argv)
    if a.execute_reserved and (a.recover_orphan or a.initialize_ledger or a.reconcile_budget):
        raise SystemExit('CHILD_MODE_ARGUMENT_CONFLICT')
    if sum((bool(a.recover_orphan), a.initialize_ledger, a.reconcile_budget)) > 1:
        raise SystemExit('LEDGER_MODE_ARGUMENT_CONFLICT')
    if a.execute_reserved:
        if any(x is None for x in (a.tag, a.config_json, a.why, a.parent_pid, a.parent_create_time, a.lock_owner, a.child_nonce, a.start_gate, a.child_result)):
            raise SystemExit('CHILD_ARGUMENTS_INCOMPLETE')
        return _child_cli(a)
    if a.recover_orphan:
        if any(x is not None for x in (a.tag, a.config, a.why, a.config_json, a.parent_pid, a.parent_create_time, a.lock_owner, a.child_nonce, a.start_gate, a.child_result)):
            raise SystemExit('RECOVERY_ARGUMENTS_CONFLICT')
        return _recover_cli(a.recover_orphan)
    if a.reconcile_budget:
        if any(x is not None for x in (a.tag, a.config, a.why, a.config_json, a.parent_pid, a.parent_create_time, a.lock_owner, a.child_nonce, a.start_gate, a.child_result)):
            raise SystemExit('RECONCILE_ARGUMENTS_CONFLICT')
        return _reconcile_cli()
    if a.initialize_ledger:
        if any(x is not None for x in (a.tag, a.config, a.why, a.config_json, a.parent_pid, a.parent_create_time, a.lock_owner, a.child_nonce, a.start_gate, a.child_result)):
            raise SystemExit('BOOTSTRAP_ARGUMENTS_CONFLICT')
        return _bootstrap_cli()
    if a.tag is None or a.config is None or a.why is None or any(x is not None for x in (a.config_json, a.parent_pid, a.parent_create_time, a.lock_owner, a.child_nonce, a.start_gate, a.child_result)):
        raise SystemExit('TRAIN_ARGUMENTS_INCOMPLETE')
    return _parent_cli(a.tag, rr.default_config(**json.loads(a.config)), a.why)


if __name__ == '__main__':
    main()
