"""Create the exact, deterministic allowlisted tar context for Dockerfile.real-model."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'ops/real-model-source-lock.json'
CONTEXT_FILES = (
    'ops/Dockerfile.real-model',
    'ops/requirements-real-model.lock',
    'fieldwork/model_child_entry.py',
    'fieldwork/real_train_child.py',
    'fieldwork/real_infer_child.py',
    'fieldwork/qualified_infer_child.py',
    'fieldwork/residual_recipe.py',
    'fieldwork/real_training.py',
    'fieldwork/real_bundle_child.py',
    'fieldwork/real_bundle.py',
    'fieldwork/real_run_profile.py',
    'fieldwork/ml.py',
    'fieldwork/data.py',
    'fieldwork/safe_codec.py',
    'fieldwork/fsops.py',
    'fieldwork/metrics.py',
    'fieldwork/real_pixels.py',
    'fieldwork/container_real_pixels.py',
    'fieldwork/real_pixel_decoder.py',
    'tools/verify_metrics.py',
    'tools/verify_release_bundle.py',
    'tools/verify_population_metrics.py',
    'ops/real-model-source-lock.json',
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_manifest() -> dict:
    try:
        if MANIFEST.is_symlink():
            raise ValueError()
        doc = json.loads(MANIFEST.read_text(encoding='utf-8'))
    except (OSError, ValueError, UnicodeError):
        raise SystemExit('REAL_MODEL_SOURCE_MANIFEST_INVALID') from None
    if (type(doc) is not dict or doc.get('schema') != 'fieldwork.real-model-source-lock/v1'
            or doc.get('platform') != 'linux/amd64'
            or set(doc.get('files', {})) != set(CONTEXT_FILES) - {'ops/real-model-source-lock.json'}):
        raise SystemExit('REAL_MODEL_SOURCE_MANIFEST_SCHEMA')
    builder_hash = doc.get('context_builder_sha256')
    if builder_hash != _sha(Path(__file__)):
        raise SystemExit('REAL_MODEL_CONTEXT_BUILDER_PIN_MISMATCH')
    for name, expected in doc['files'].items():
        path = ROOT / name
        try:
            if path.is_symlink() or not path.is_file() or _sha(path) != expected:
                raise ValueError()
        except (OSError, ValueError):
            raise SystemExit('REAL_MODEL_SOURCE_PIN_MISMATCH:' + name) from None
    return doc


def create_context(output: Path) -> dict:
    doc = _validate_manifest()
    output = Path(output)
    if output.is_symlink():
        raise SystemExit('REAL_MODEL_CONTEXT_OUTPUT_REPARSE')
    temp = output.with_name(output.name + '.writing')
    try:
        with temp.open('xb') as stream:
            with tarfile.open(fileobj=stream, mode='w') as archive:
                for name in CONTEXT_FILES:
                    path = ROOT / name
                    data = path.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o644
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mtime = 0
                    archive.addfile(info, __import__('io').BytesIO(data))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, output)
    except OSError:
        temp.unlink(missing_ok=True)
        raise SystemExit('REAL_MODEL_CONTEXT_WRITE_FAILED') from None
    return {'schema': 'fieldwork.real-model-context/v1',
            'context_sha256': _sha(output), 'context_bytes': output.stat().st_size,
            'entry_count': len(CONTEXT_FILES), 'source_lock_sha256': _sha(MANIFEST),
            'files': dict(doc['files'])}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    result = create_context(Path(args.output))
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
