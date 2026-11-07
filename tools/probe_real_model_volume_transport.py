"""Bounded no-network smoke for the approved model-image named-volume transport.

Stages one authored byte string, verifies it inside the pinned image with a
fixed read-only Python snippet, then reconciles the nonce-owned container and
volume. No host path is mounted into Docker and no model or dataset is read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fieldwork.real_model_container import (
    MODEL_LABEL, ModelContainerRunner, ModelContainerUnavailable, _docker,
)
from fieldwork.model_volume_staging import collect_stage_inputs

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b'fieldwork named-volume transport smoke v1\n'
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
PROBE_CODE = (
    "from pathlib import Path; import hashlib; "
    "p=Path('/workspace/input/probe.bin'); b=p.read_bytes(); "
    f"assert hashlib.sha256(b).hexdigest()=='{PAYLOAD_SHA256}'; "
    "assert Path('/workspace/output').is_dir(); "
    "print('named-volume-read-ok')"
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model-image-id', required=True)
    args = parser.parse_args()
    evidence_root = ROOT / '.local/real-data/workflow-20261102'
    evidence_root.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    run_root = evidence_root / ('named-volume-smoke-' + token)
    source = run_root / 'source'
    source.mkdir(parents=True, exist_ok=False)
    with (source / 'probe.bin').open('xb') as stream:
        stream.write(PAYLOAD); stream.flush()
    runner = ModelContainerRunner(args.model_image_id,
        private_dir=ROOT / '.local/real-data/model-private')
    runner.set_write_budget_scope(str(uuid.uuid4()))
    receipt_path = receipt = cid_path = None
    status = 'failed'
    error_code = None
    try:
        receipt_path, receipt, cid_path = runner._new_receipt()
        manifest, records = collect_stage_inputs([('input', source)])
        staged_bytes = int(json.loads(manifest.decode('ascii'))['total_bytes'])
        runner._reserve_run_budget(receipt, staged_bytes, output_tmpfs=False)
        volume = runner._stage_volume(manifest, records, receipt)
        argv = _docker('run', '--pull=never', '--rm', '--platform=linux/amd64',
            '--cidfile', str(cid_path), '--network=none', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges=true', '--user=65532:65532',
            '--memory=512m', '--memory-swap=512m', '--cpus=1', '--pids-limit=32',
            '--ulimit=core=0', '--ulimit=nofile=64:64', '--shm-size=32m',
            '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m', '--workdir=/app', '--log-driver=none',
            '--tmpfs=/workspace/output:rw,noexec,nosuid,nodev,size=16m',
            f'--label={MODEL_LABEL}=1', f'--label={MODEL_LABEL}.nonce={receipt["nonce"]}',
            '--mount', f'type=volume,source={volume},target=/workspace,readonly,volume-nocopy',
            '--entrypoint=/usr/local/bin/python', runner.image_id,
            '-I', '-B', '-c', PROBE_CODE)
        result = runner._run(tuple(argv[3:]), timeout=90, capture=True, limit=256)
        if result.returncode != 0 or result.stdout.strip() != b'named-volume-read-ok':
            raise ModelContainerUnavailable('MODEL_VOLUME_READ_SMOKE_FAILED')
        status = 'passed'
    except ModelContainerUnavailable as exc:
        error_code = exc.code
    except (OSError, ValueError, TypeError, UnicodeError):
        error_code = 'MODEL_VOLUME_SMOKE_SOURCE_OR_PROTOCOL_FAILED'
    finally:
        if receipt_path is not None:
            try:
                runner._cleanup(receipt_path, receipt, cid_path)
                runner._active.discard(receipt_path)
            except ModelContainerUnavailable as exc:
                error_code = exc.code
                status = 'cleanup-pending'
            else:
                try:
                    runner._finish_run_budget(receipt)
                except ModelContainerUnavailable as exc:
                    error_code = exc.code
                    status = 'failed'
    report = {'schema':'fieldwork.named-volume-smoke/v1','status':status,
        'error_code':error_code,'staged_file_count':1,'staged_bytes':len(PAYLOAD),
        'payload_sha256':PAYLOAD_SHA256,'model_image_id':args.model_image_id,
        'host_bind_mounts':0,'network':'none','cleanup_confirmed':not runner.has_unresolved_container,
        'as_of_utc':datetime.now(timezone.utc).isoformat()}
    report_path = evidence_root / ('named-volume-smoke-' + token + '.json')
    report_path.write_text(json.dumps(report, sort_keys=True, separators=(',',':')) + '\n', encoding='utf-8')
    print(json.dumps({'status':status,'error_code':error_code,'report':str(report_path),
        'payload_sha256':PAYLOAD_SHA256,'cleanup_confirmed':report['cleanup_confirmed']}, sort_keys=True))
    return 0 if status == 'passed' and report['cleanup_confirmed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
