"""Run the existing scoped real worker in the tracked caller session.

This operator entrypoint holds no product lock. The worker acquires the shared
heavy-job lock itself only when a real run is admitted. It requires the existing
pause marker so startup cannot claim queued work.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
WORKSPACE = '814830e3-55a0-4925-ad37-5d3dac7d4df8'
DOCKER = Path(r'C:\Program Files\Docker\Docker\resources\bin\docker.exe')
DOCKER_ENDPOINT = r'npipe:////./pipe/dockerDesktopLinuxEngine'


def _image_ok(image_id: str) -> None:
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise RuntimeError('IMAGE_ID_INVALID')
    docker_env = dict(os.environ)
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY'):
        docker_env.pop(key, None)
    result = subprocess.run([str(DOCKER), '--host', DOCKER_ENDPOINT, 'image', 'inspect',
        '--format', '{{.Id}}', image_id], env=docker_env, capture_output=True, text=True,
        check=False, timeout=15)
    if result.returncode != 0 or result.stdout.strip() != image_id:
        raise RuntimeError('PINNED_IMAGE_NOT_PRESENT')


def _local_endpoint_ok() -> str:
    if not DOCKER.is_file():
        raise RuntimeError('LOCAL_DOCKER_CLI_MISSING')
    docker_env = dict(os.environ)
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY'):
        docker_env.pop(key, None)
    context = subprocess.run([str(DOCKER), 'context', 'show'], env=docker_env,
        capture_output=True, text=True, check=False, timeout=10)
    endpoint = subprocess.run([str(DOCKER), 'context', 'inspect', 'desktop-linux',
        '--format', '{{(index .Endpoints "docker").Host}}'], env=docker_env, capture_output=True,
        text=True, check=False, timeout=10)
    if (context.returncode != 0 or context.stdout.strip() != 'desktop-linux'
            or endpoint.returncode != 0
            or endpoint.stdout.strip().lower() != DOCKER_ENDPOINT.lower()):
        raise RuntimeError('LOCAL_DOCKER_ENDPOINT_REFUSED')
    default_daemon = subprocess.run([str(DOCKER), 'info', '--format', '{{.ID}}'],
        env=docker_env, capture_output=True, text=True, check=False, timeout=15)
    pinned_daemon = subprocess.run([str(DOCKER), '--host', DOCKER_ENDPOINT,
        'info', '--format', '{{.ID}}'], env=docker_env, capture_output=True,
        text=True, check=False, timeout=15)
    left, right = default_daemon.stdout.strip(), pinned_daemon.stdout.strip()
    if (default_daemon.returncode != 0 or pinned_daemon.returncode != 0
            or not re.fullmatch(r'[A-Fa-f0-9-]{16,80}', left)
            or left != right):
        raise RuntimeError('LOCAL_DOCKER_DAEMON_IDENTITY_MISMATCH')
    return left


def _owned_worker_heartbeat(beat, *, expected_worker_id: str,
                            launcher_pid: int, launcher_create_time: float,
                            started_epoch: float, pause_nonce_sha256: str):
    """Bind the heartbeat to this launch, its pause nonce, and process ancestry."""
    import psutil
    if (not isinstance(beat, dict) or beat.get('worker_id') != expected_worker_id
            or beat.get('identity') != 'scoped-worker-v1'
            or beat.get('profile') != 'scoped-real-training-and-inference'
            or beat.get('operator_paused') is not True
            or beat.get('pause_nonce_sha256') != pause_nonce_sha256
            or type(beat.get('pid')) is not int
            or type(beat.get('create_time')) not in (int, float)
            or float(beat['create_time']) < started_epoch - 1):
        return None
    try:
        process = psutil.Process(beat['pid'])
        parent = process.parent()
        parent_ok = False
        if process.pid == launcher_pid:
            parent_ok = abs(process.create_time() - launcher_create_time) < .01
        elif parent is not None and parent.pid == launcher_pid:
            parent_ok = abs(parent.create_time() - launcher_create_time) < .01
        elif parent is not None and 'python' in parent.name().casefold():
            grandparent = parent.parent()
            parent_command = parent.cmdline()
            parent_ok = (grandparent is not None
                and grandparent.pid == launcher_pid
                and abs(grandparent.create_time() - launcher_create_time) < .01
                and str(parent.cwd()).lower() == str(ROOT).lower()
                and 'fieldwork.worker' in parent_command
                and '--real-runs' in parent_command)
        command_line = process.cmdline()
        if (abs(process.create_time() - float(beat['create_time'])) >= .01
                or process.create_time() < started_epoch - 1
                or str(process.cwd()).lower() != str(ROOT).lower()
                or 'fieldwork.worker' not in command_line
                or '--real-runs' not in command_line
                or not parent_ok):
            return None
        return {'pid': process.pid, 'create_time': process.create_time(),
            'as_of': beat.get('as_of'), 'operator_paused': True,
            'pause_nonce_sha256': pause_nonce_sha256}
    except psutil.Error:
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--pixel-image-id', required=True)
    parser.add_argument('--model-image-id', required=True)
    args = parser.parse_args()

    sys.path.insert(0, str(REPO / 'tools'))
    import product_lock
    import activate_real_worker
    from fieldwork.scoped_authority import check_private

    owner = product_lock.read_owner(REPO / '.cache/product-build.lock')
    if owner is not None:
        raise RuntimeError('SHARED_PRODUCT_LOCK_HELD')
    activate_real_worker._refuse_live_scoped_worker()
    authority, auth = activate_real_worker._training_authority()
    if WORKSPACE not in auth.get('workspaces', []):
        raise RuntimeError('TRAINING_WORKER_SCOPE_NOT_EXTENDED')

    pause = ROOT / '.local/worker-training.pause'
    if not pause.is_file():
        raise RuntimeError('TRAINING_PAUSE_MARKER_REQUIRED')
    check_private(pause.parent)
    check_private(pause)

    daemon_id = _local_endpoint_ok()
    _image_ok(args.pixel_image_id)
    _image_ok(args.model_image_id)
    with urllib.request.urlopen('http://127.0.0.1:8102/health/ready', timeout=5) as response:
        if response.status != 200:
            raise RuntimeError('FIELDWORK_API_NOT_READY')

    env = dict(os.environ)
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY'):
        env.pop(key, None)
    env.update({
        'FIELDWORK_WORKER_AUTHORITY': str(authority),
        'FIELDWORK_HOST_HEAVY_LOCK': str(REPO / '.cache/product-build.lock'),
        'FIELDWORK_WORKER_ID': 'fieldwork-real-completion-worker',
        'FIELDWORK_REAL_PIXEL_IMAGE_ID': args.pixel_image_id,
        'FIELDWORK_REAL_MODEL_IMAGE_ID': args.model_image_id,
        'FIELDWORK_RIGHTS_REVIEWERS_FILE': str(ROOT / 'var/commons_r5/rights/reviewers.json'),
        'FIELDWORK_TRAINING_PAUSE_FILE': str(pause),
        'FIELDWORK_TRAINING_PAUSE_NONCE': secrets.token_urlsafe(24),
    })
    pause_nonce_sha256 = hashlib.sha256(
        env['FIELDWORK_TRAINING_PAUSE_NONCE'].encode('utf-8')).hexdigest()
    observed = datetime.now(timezone.utc).isoformat()
    import psutil
    receipts = ROOT / '.local/real-data/activation-observations'
    receipts.mkdir(parents=True, exist_ok=True)
    check_private(receipts)
    launch_id = uuid.uuid4().hex
    intent = receipts / ('foreground-worker-intent-' + launch_id + '.json')
    log_dir = ROOT / 'var/activation'
    log_dir.mkdir(parents=True, exist_ok=True)
    check_private(log_dir)
    log_path = log_dir / ('fieldwork-real-training-worker-foreground-' + launch_id + '.out.log')
    created_before = time.time()
    command = [sys.executable, '-B', '-m', 'fieldwork.worker', '--real-runs']
    with log_path.open('xb') as output:
        child = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, close_fds=True)
    launch = {
        'schema': 'fieldwork.foreground-real-worker-intent/v1',
        'status': 'foreground-starting-paused', 'at_utc': observed,
        'launcher_pid': child.pid, 'launcher_create_time': psutil.Process(child.pid).create_time(),
        'worker_id': env['FIELDWORK_WORKER_ID'],
        'workspace_scope_verified': True, 'operator_pause_marker_present': True,
        'pixel_image_id': args.pixel_image_id, 'model_image_id': args.model_image_id,
        'docker_daemon_id': daemon_id, 'log': str(log_path.relative_to(ROOT)),
    }
    with intent.open('x', encoding='utf-8') as stream:
        json.dump(launch, stream, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    check_private(intent)
    deadline = time.monotonic() + 60
    worker_identity = None
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError('FOREGROUND_WORKER_EXITED_BEFORE_HEARTBEAT')
        try:
            beat = json.loads((ROOT / 'var/worker.json').read_text(encoding='utf-8'))
        except (OSError, ValueError, TypeError):
            beat = None
        worker_identity = _owned_worker_heartbeat(beat,
            expected_worker_id=env['FIELDWORK_WORKER_ID'], launcher_pid=child.pid,
            launcher_create_time=launch['launcher_create_time'],
            started_epoch=created_before, pause_nonce_sha256=pause_nonce_sha256)
        if worker_identity is not None:
            break
        time.sleep(.25)
    if worker_identity is None:
        # Do not detach or kill an unconfirmed child. Keep this foreground
        # supervisor attached until the exact launcher exits for diagnosis.
        print(json.dumps({'status': 'heartbeat_not_confirmed',
            'launcher_pid': child.pid, 'intent_receipt': str(intent.relative_to(ROOT)),
            'log': str(log_path.relative_to(ROOT))}), flush=True)
        exit_code = child.wait()
        print(json.dumps({'status': 'launcher_exited_without_scoped_heartbeat',
            'launcher_pid': child.pid, 'exit_code': exit_code}), flush=True)
        return int(exit_code or 2)

    started = {**launch, 'status': 'foreground-worker-heartbeat-confirmed',
        'worker': worker_identity, 'heartbeat_receipt': str(intent.relative_to(ROOT))}
    started_path = receipts / ('foreground-worker-started-' + launch_id + '.json')
    with started_path.open('x', encoding='utf-8') as stream:
        json.dump(started, stream, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    check_private(started_path)
    print(json.dumps({'status': started['status'], 'worker': worker_identity,
        'worker_id': env['FIELDWORK_WORKER_ID'], 'operator_paused': True,
        'intent_receipt': str(intent.relative_to(ROOT)),
        'started_receipt': str(started_path.relative_to(ROOT)),
        'log': str(log_path.relative_to(ROOT))}), flush=True)

    # Keep the tracked caller session alive for the exact confirmed worker.
    # This is deliberately not a Task, service, WMI process, or second worker.
    while True:
        try:
            process = psutil.Process(worker_identity['pid'])
            if abs(process.create_time() - worker_identity['create_time']) >= .01:
                break
        except psutil.NoSuchProcess:
            break
        time.sleep(5)
    worker_exit_code = None
    try:
        worker_exit_code = process.wait(timeout=1)
    except psutil.Error:
        pass
    ended = {**started, 'status': 'foreground-worker-exit-observed',
        'ended_utc': datetime.now(timezone.utc).isoformat()}
    launcher_exit = child.wait()
    ended['launcher_exit_code'] = launcher_exit
    ended_path = receipts / ('foreground-worker-ended-' + launch_id + '.json')
    with ended_path.open('x', encoding='utf-8') as stream:
        json.dump(ended, stream, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    check_private(ended_path)
    print(json.dumps({'status': ended['status'], 'worker': worker_identity,
        'ended_receipt': str(ended_path.relative_to(ROOT)),
        'log': str(log_path.relative_to(ROOT))}), flush=True)
    if isinstance(worker_exit_code, int):
        return worker_exit_code
    return launcher_exit if launcher_exit != 0 else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        code = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch(r'[A-Z0-9_]{4,100}', str(exc)) else type(exc).__name__
        print(json.dumps({'status': 'refused', 'code': code, 'secret_printed': False}), flush=True)
        raise SystemExit(2)
