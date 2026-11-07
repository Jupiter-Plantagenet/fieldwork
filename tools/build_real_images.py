"""Prepare and build the pinned Fieldwork real-data container images.

The Docker build receives only deterministic, explicit tar contexts. Run `prepare`
as a light source check; run `build` only inside the coordinator-admitted wrapper.
Build and smoke logs are append-preserving and scoped to one unique run ID.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCAL_ROOT = ROOT / '.local' / 'real-image-build'
BUILDLOG_ROOT = ROOT / 'buildlogs' / 'real-images'
MODEL_BUILDER = ROOT / 'tools' / 'build_real_model_context.py'

PIXEL_FILES = (
    'ops/Dockerfile.real-pixels',
    'ops/decoder-pillow-requirements.lock',
    'fieldwork/container_real_pixels.py',
)
PIXEL_DOCKERFILE = 'ops/Dockerfile.real-pixels'
MODEL_DOCKERFILE = 'ops/Dockerfile.real-model'
PIXEL_LOCK = 'ops/decoder-pillow-requirements.lock'
MODEL_LOCK = 'ops/requirements-real-model.lock'
SCHEMA = 'fieldwork.real-image-build-provenance/v1'
BASE_RE = re.compile(r'^FROM\s+\S+@(?P<digest>sha256:[0-9a-f]{64})\s*$', re.MULTILINE)
RUN_ID_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def source_map(files: tuple[str, ...]) -> dict[str, str]:
    out = {}
    for name in files:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise SystemExit('REAL_IMAGE_SOURCE_MISSING:' + name)
        out[name] = sha256(path)
    return out


def base_digest(name: str) -> str:
    text = (ROOT / name).read_text(encoding='utf-8')
    match = BASE_RE.search(text)
    if not match:
        raise SystemExit('REAL_IMAGE_BASE_DIGEST_REQUIRED:' + name)
    return match.group('digest')


def run_dir(run_id: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id):
        raise SystemExit('REAL_IMAGE_RUN_ID_INVALID')
    return LOCAL_ROOT / run_id


def write_json(path: Path, value: dict, *, replace: bool = False) -> None:
    if path.is_symlink():
        raise SystemExit('REAL_IMAGE_OUTPUT_REPARSE')
    temp = path.with_name(path.name + '.writing')
    if temp.exists() or temp.is_symlink() or (path.exists() and not replace):
        raise SystemExit('REAL_IMAGE_OUTPUT_EXISTS')
    payload = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')
    try:
        with temp.open('xb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    except OSError:
        temp.unlink(missing_ok=True)
        raise SystemExit('REAL_IMAGE_PROVENANCE_WRITE_FAILED') from None


def make_pixel_context(output: Path) -> dict:
    files = source_map(PIXEL_FILES)
    if output.is_symlink() or output.exists():
        raise SystemExit('REAL_IMAGE_CONTEXT_OUTPUT_EXISTS')
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(output.name + '.writing')
    try:
        with temp.open('xb') as stream:
            with tarfile.open(fileobj=stream, mode='w') as archive:
                for name in PIXEL_FILES:
                    blob = (ROOT / name).read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size = len(blob)
                    info.mode = 0o644
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mtime = 0
                    archive.addfile(info, BytesIO(blob))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, output)
    except OSError:
        temp.unlink(missing_ok=True)
        raise SystemExit('REAL_IMAGE_CONTEXT_WRITE_FAILED') from None
    return {'schema': 'fieldwork.real-pixel-context/v1', 'context_sha256': sha256(output),
            'context_bytes': output.stat().st_size, 'entry_count': len(PIXEL_FILES),
            'source_lock_sha256': hashlib.sha256(json.dumps(files, sort_keys=True,
                separators=(',', ':')).encode('ascii')).hexdigest(), 'files': files}


def prepare(run_id: str) -> dict:
    directory = run_dir(run_id)
    if directory.exists() or directory.is_symlink():
        raise SystemExit('REAL_IMAGE_RUN_DIRECTORY_EXISTS')
    directory.mkdir(parents=True)
    pixel_context = make_pixel_context(directory / 'real-pixels-context.tar')
    try:
        context_module = runpy.run_path(str(MODEL_BUILDER))
        model_context = context_module['create_context'](directory / 'real-model-context.tar')
    except SystemExit:
        raise
    except Exception:
        raise SystemExit('REAL_MODEL_CONTEXT_PREPARATION_FAILED') from None

    model_source_lock = json.loads((ROOT / 'ops/real-model-source-lock.json').read_text(encoding='utf-8'))
    model_files = dict(model_source_lock['files'])
    pixel_sources = source_map(PIXEL_FILES)
    prepared = {
        'schema': 'fieldwork.real-image-preparation/v1',
        'run_id': run_id,
        'platform': 'linux/amd64',
        'pixel': {'dockerfile': PIXEL_DOCKERFILE, 'base_repo_digest': base_digest(PIXEL_DOCKERFILE),
                  'dependency_lock': PIXEL_LOCK, 'dependency_lock_sha256': sha256(ROOT / PIXEL_LOCK),
                  **pixel_context},
        'model': {'dockerfile': MODEL_DOCKERFILE, 'base_repo_digest': base_digest(MODEL_DOCKERFILE),
                  'dependency_lock': MODEL_LOCK, 'dependency_lock_sha256': sha256(ROOT / MODEL_LOCK),
                  'source_manifest': 'ops/real-model-source-lock.json',
                  'source_manifest_sha256': sha256(ROOT / 'ops/real-model-source-lock.json'),
                  **model_context},
        'contexts': {'pixel': str(directory / 'real-pixels-context.tar'),
                     'model': str(directory / 'real-model-context.tar')},
        'source_files': {'pixel': pixel_sources, 'model': model_files},
    }
    write_json(directory / 'prepared.json', prepared)
    return prepared


def validate_prepared(prepared: dict, run_id: str, directory: Path) -> None:
    if directory != run_dir(run_id):
        raise SystemExit('REAL_IMAGE_RUN_DIRECTORY_MISMATCH')
    expected_contexts = {'pixel': str(directory / 'real-pixels-context.tar'),
                         'model': str(directory / 'real-model-context.tar')}
    if prepared.get('contexts') != expected_contexts:
        raise SystemExit('REAL_IMAGE_CONTEXT_PATH_MISMATCH')
    if prepared.get('source_files', {}).get('pixel') != source_map(PIXEL_FILES):
        raise SystemExit('REAL_PIXEL_SOURCE_CHANGED_AFTER_PREPARE')
    try:
        model_validator = runpy.run_path(str(MODEL_BUILDER))['_validate_manifest']
        model_source_lock = model_validator()
    except SystemExit:
        raise
    except Exception:
        raise SystemExit('REAL_MODEL_SOURCE_LOCK_INVALID') from None
    if prepared.get('source_files', {}).get('model') != model_source_lock.get('files'):
        raise SystemExit('REAL_MODEL_SOURCE_CHANGED_AFTER_PREPARE')
    checks = (
        ('pixel', PIXEL_DOCKERFILE, PIXEL_LOCK),
        ('model', MODEL_DOCKERFILE, MODEL_LOCK),
    )
    for key, dockerfile, lockfile in checks:
        entry = prepared.get(key, {})
        if (entry.get('dockerfile') != dockerfile or entry.get('base_repo_digest') != base_digest(dockerfile)
                or entry.get('dependency_lock') != lockfile
                or entry.get('dependency_lock_sha256') != sha256(ROOT / lockfile)):
            raise SystemExit('REAL_IMAGE_PIN_CHANGED_AFTER_PREPARE:' + key)
    model = prepared.get('model', {})
    if (model.get('source_manifest') != 'ops/real-model-source-lock.json'
            or model.get('source_manifest_sha256') != sha256(ROOT / 'ops/real-model-source-lock.json')):
        raise SystemExit('REAL_MODEL_SOURCE_MANIFEST_CHANGED_AFTER_PREPARE')
    for key in ('pixel', 'model'):
        entry = prepared[key]
        path = Path(expected_contexts[key])
        if path.is_symlink() or not path.is_file() or sha256(path) != entry.get('context_sha256'):
            raise SystemExit('REAL_IMAGE_CONTEXT_CHANGED:' + key)


def _record_log(command: list[str], log_path: Path, *, stdin_path: Path | None = None,
                capture_output: bool = False) -> str:
    if log_path.exists() or log_path.is_symlink():
        raise SystemExit('REAL_IMAGE_LOG_EXISTS')
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open('xb') as out:
        out.write((json.dumps({'argv': command, 'started_utc': datetime.now(timezone.utc).isoformat()},
                              separators=(',', ':')) + '\n').encode('utf-8'))
        out.flush()
        input_stream = stdin_path.open('rb') if stdin_path is not None else None
        try:
            if capture_output:
                proc = subprocess.run(command, cwd=ROOT, stdin=input_stream,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
                out.write(proc.stdout)
            else:
                proc = subprocess.run(command, cwd=ROOT, stdin=input_stream,
                                      stdout=out, stderr=subprocess.STDOUT, check=False)
        finally:
            if input_stream is not None:
                input_stream.close()
        out.write((json.dumps({'exit_code': proc.returncode,
                               'finished_utc': datetime.now(timezone.utc).isoformat()},
                              separators=(',', ':')) + '\n').encode('utf-8'))
    if proc.returncode:
        raise SystemExit('REAL_IMAGE_COMMAND_FAILED:' + Path(command[1]).name)
    return proc.stdout.decode('utf-8', errors='replace') if capture_output else ''


def build(run_id: str, only: str | None = None) -> dict:
    directory = run_dir(run_id)
    prepared_path = directory / 'prepared.json'
    if prepared_path.is_symlink() or not prepared_path.is_file():
        raise SystemExit('REAL_IMAGE_PREPARED_CONTEXT_REQUIRED')
    prepared = json.loads(prepared_path.read_text(encoding='utf-8'))
    if prepared.get('run_id') != run_id or prepared.get('schema') != 'fieldwork.real-image-preparation/v1':
        raise SystemExit('REAL_IMAGE_PREPARATION_INVALID')
    validate_prepared(prepared, run_id, directory)
    docker = shutil.which('docker')
    if not docker:
        raise SystemExit('DOCKER_CLI_UNAVAILABLE')
    logs_dir = BUILDLOG_ROOT / run_id
    logs_dir.mkdir(parents=True, exist_ok=False)
    ids_dir = directory / 'ids'
    ids_dir.mkdir()
    record = {'schema': SCHEMA, 'run_id': run_id, 'platform': 'linux/amd64',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'preparation_sha256': sha256(prepared_path), 'state': 'building', 'images': {}}
    provenance_path = logs_dir / 'provenance.json'
    write_json(provenance_path, record)
    image_definitions = (
        ('pixel', 'fieldwork-real-pixels', PIXEL_DOCKERFILE, prepared['contexts']['pixel'],
         prepared['pixel'], 'real-pixels-context.tar'),
        ('model', 'fieldwork-real-model', MODEL_DOCKERFILE, prepared['contexts']['model'],
         prepared['model'], 'real-model-context.tar'),
    )
    if only is not None:
        # Rebuild one image without changing the other's pinned image ID.
        image_definitions = tuple(d for d in image_definitions if d[0] == only)
    try:
        for key, image_name, dockerfile, context, pin, context_basename in image_definitions:
            context_path = Path(context)
            image_tag = f'{image_name}:{run_id}'
            iid_path = ids_dir / f'{key}.iid'
            build_log = logs_dir / f'{key}-build.raw.log'
            command = [docker, 'build', '--platform', 'linux/amd64', '--iidfile', str(iid_path),
                       '--tag', image_tag, '--file', dockerfile, '-']
            _record_log(command, build_log, stdin_path=context_path)
            image_id = iid_path.read_text(encoding='ascii').strip()
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
                raise SystemExit('REAL_IMAGE_ID_INVALID:' + key)
            inspect_format = '{{.Id}}|{{.Os}}|{{.Architecture}}|{{json .Config.Entrypoint}}|{{.Config.User}}'
            inspect_text = _record_log([docker, 'image', 'inspect', '--format', inspect_format, image_tag],
                                       logs_dir / f'{key}-inspect.raw.log', capture_output=True).strip()
            fields = inspect_text.split('|', 4)
            if len(fields) != 5 or fields[0] != image_id or fields[1:3] != ['linux', 'amd64']:
                raise SystemExit('REAL_IMAGE_CONFIG_MISMATCH:' + key)
            record['images'][key] = {'tag': image_tag, 'image_id': image_id,
                                     'base_repo_digest': pin['base_repo_digest'],
                                     'dockerfile': pin['dockerfile'],
                                     'dependency_lock': pin['dependency_lock'],
                                     'dependency_lock_sha256': pin['dependency_lock_sha256'],
                                     'source_manifest_sha256': pin.get('source_manifest_sha256', pin['source_lock_sha256']),
                                     'context_sha256': pin['context_sha256'],
                                     'config': {'os': fields[1], 'architecture': fields[2],
                                                'entrypoint': json.loads(fields[3]), 'user': fields[4]},
                                     'build_log': f'{key}-build.raw.log',
                                     'inspect_log': f'{key}-inspect.raw.log'}
            write_json(provenance_path, record, replace=True)

        smoke_code = {
            'pixel': "import sys; sys.path.insert(0, '/app'); import PIL; assert PIL.__version__ == '13.0.0'; import container_real_pixels; print('PIXEL_IMPORT_SMOKE_OK')",
            'model': "import sys; sys.path.insert(0, '/app'); import numpy, PIL, safetensors, torch; assert numpy.__version__ == '2.5.4'; assert PIL.__version__ == '13.0.0'; assert safetensors.__version__ == '0.8.0'; assert torch.__version__ == '2.14.1+cpu'; import fieldwork.model_child_entry, fieldwork.real_train_child, fieldwork.real_infer_child, fieldwork.qualified_infer_child, fieldwork.residual_recipe, fieldwork.real_bundle_child, fieldwork.real_bundle, fieldwork.real_run_profile, fieldwork.ml, fieldwork.data, fieldwork.safe_codec, fieldwork.fsops, fieldwork.metrics, fieldwork.real_pixels, fieldwork.container_real_pixels; import tools.verify_metrics, tools.verify_release_bundle, tools.verify_population_metrics; print('MODEL_IMPORT_SMOKE_OK')",
        }
        for key, *_ in image_definitions:
            image = record['images'][key]['image_id']
            smoke_log = logs_dir / f'{key}-import-smoke.raw.log'
            command = [docker, 'run', '--rm', '--network=none', '--read-only',
                       '--tmpfs', '/tmp:rw,noexec,nosuid,size=2m', '--entrypoint', '/usr/local/bin/python',
                       image, '-I', '-B', '-c', smoke_code[key]]
            output = _record_log(command, smoke_log, capture_output=True)
            marker = 'PIXEL_IMPORT_SMOKE_OK' if key == 'pixel' else 'MODEL_IMPORT_SMOKE_OK'
            if marker not in output:
                raise SystemExit('REAL_IMAGE_IMPORT_SMOKE_MISSING:' + key)
            record['images'][key]['import_smoke'] = 'executed-pass'
            record['images'][key]['import_smoke_log'] = f'{key}-import-smoke.raw.log'
            write_json(provenance_path, record, replace=True)
        record['state'] = 'built-and-import-smoked'
        record['finished_utc'] = datetime.now(timezone.utc).isoformat()
        write_json(provenance_path, record, replace=True)
        return record
    except BaseException as exc:
        record['state'] = 'failed'
        record['failure_code'] = str(exc)[:160] if isinstance(exc, SystemExit) else type(exc).__name__
        record['finished_utc'] = datetime.now(timezone.utc).isoformat()
        write_json(provenance_path, record, replace=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare', help='validate source pins and create deterministic contexts; no Docker calls')
    prep.add_argument('--run-id', required=True)
    build_parser = sub.add_parser('build', help='build images and run import-only smoke containers')
    build_parser.add_argument('--run-id', required=True)
    build_parser.add_argument('--only', choices=('pixel', 'model'), default=None)
    args = parser.parse_args(argv)
    if args.action == 'prepare':
        result = prepare(args.run_id)
    else:
        result = build(args.run_id, args.only)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
