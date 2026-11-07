"""Fixed local registry for the single steward-qualified R5 model release.

The registry is deliberately data-only and does not allow request-selected paths,
model identifiers, code, or arbitrary release manifests. Every use rechecks the
consumed plan row and the exact closed bundle inventory before bytes are served or
the model is selected by a worker.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import uuid
from pathlib import Path

from .store import ROOT

REGISTRY_PATH = ROOT / '.local' / 'qualified-release-registry.json'
RELEASE_ID = 'flowers-r5-small-residual-v1'
WORKSPACE = '814830e3-55a0-4925-ad37-5d3dac7d4df8'
PLAN_ID = '9252ee17-1e80-4159-8dbf-b3f77d2bb674'
PLAN_RESULT_SHA256 = '6686d29ef0d2b6aa792bdc06508a84d3fdf9e4caa3a7b16165aae1b10cb4256c'
RESULT_RECORD_SHA256 = '55d321a06bde245735126ecde5ff1047f779d8d8429591d84b9015a77cbaac6d'
MODEL_SHA256 = 'c5b41d6a12cd2473abac7628ca23aa3abe6afad8304e21164fece14d58c16bde'
PREPROCESS_SHA256 = '865d7ea9790301672bbbbe61f73fa4653878f17c8eec4814ae75a80c51c59d76'
MANIFEST_SHA256 = 'cf5c88be9addebcf1ade349710494464611e14e1627d44351116ce7a55b6742d'
VERSION_ID = '553eec3b-7173-442a-b99d-995ca63c18a5'
VERSION_DIGEST = 'a298b6e702310a224370b21213edfb0925e005dd176ed98f177f31ad844c58f8'
DATASET_ID = '0ad2719a-2319-418b-b072-ba8ce310a997'
RELEASE_DIR = ROOT / 'var' / 'commons_r5' / 'release' / 'r5cfg2-qualified'
RESULT_RECORD = ROOT / 'evidence' / 'ml' / 'round5' / 'tests' / 'useful' / 'r5-holdout-result.json'
QUALIFIED_UPLOAD_ROOT = ROOT / '.local' / 'real-inference-uploads'
QUALIFIED_UPLOAD_ARCHIVE = ROOT / 'var' / 'qualified-inference-archive'


def _entry():
    """Return the one code-pinned registry value; paths are never read from input."""
    return {
        'release_id': RELEASE_ID, 'workspace_id': WORKSPACE,
        'plan_id': PLAN_ID, 'plan_result_sha256': PLAN_RESULT_SHA256,
        'result_record_sha256': RESULT_RECORD_SHA256,
        'model_sha256': MODEL_SHA256, 'manifest_sha256': MANIFEST_SHA256,
        'version_id': VERSION_ID, 'version_digest': VERSION_DIGEST,
        'dataset_id': DATASET_ID,
        'bundle_relpath': 'var/commons_r5/release/r5cfg2-qualified',
    }


def _reparse_in_root(path: Path) -> bool:
    try:
        relative = Path(path).absolute().relative_to(ROOT.absolute())
        current = ROOT.absolute()
        for part in relative.parts:
            current = current / part
            info = current.lstat()
            if (current.is_symlink() or getattr(info, 'st_file_attributes', 0)
                    & getattr(__import__('os'), 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
                return True
        return False
    except (OSError, ValueError):
        return True


def initialize_registry():
    """Install the expected local operator registry only when it is absent."""
    if REGISTRY_PATH.parent.exists() and _reparse_in_root(REGISTRY_PATH.parent):
        raise OSError('QUALIFIED_REGISTRY_PATH_INVALID')
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _reparse_in_root(REGISTRY_PATH.parent):
        raise OSError('QUALIFIED_REGISTRY_PATH_INVALID')
    expected = {'schema': 'fieldwork.qualified-release-registry/v1',
                'releases': [_entry()]}
    encoded = json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()
    try:
        with REGISTRY_PATH.open('xb') as stream:
            stream.write(encoded)
            stream.flush()
    except FileExistsError:
        pass
    return expected


def registered_release(release_id: str, workspace_id: str):
    """Resolve the fixed release, checking local registry and source evidence."""
    if release_id != RELEASE_ID or workspace_id != WORKSPACE:
        return None
    try:
        if _reparse_in_root(REGISTRY_PATH):
            return None
        registry = json.loads(REGISTRY_PATH.read_text(encoding='utf-8'))
        if registry != {'schema': 'fieldwork.qualified-release-registry/v1',
                        'releases': [_entry()]}:
            return None
        if _reparse_in_root(RELEASE_DIR) or _reparse_in_root(RESULT_RECORD):
            return None
        root = ROOT.resolve(strict=True)
        bundle = RELEASE_DIR.resolve(strict=True)
        bundle.relative_to(root)
        result = RESULT_RECORD.read_bytes()
        if hashlib.sha256(result).hexdigest() != RESULT_RECORD_SHA256:
            return None
        # Full, independent bundle verification uses only the bounded fixed bundle;
        # its evaluation population is validation-only and the final file aggregate-only.
        verifier_path = ROOT / 'tools' / 'verify_release_bundle.py'
        spec = importlib.util.spec_from_file_location('_fieldwork_qualified_bundle_verifier', verifier_path)
        if spec is None or spec.loader is None:
            return None
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        verifier.check(bundle, MANIFEST_SHA256)
        manifest = json.loads((bundle / 'manifest.json').read_text(encoding='utf-8'))
        lineage = json.loads((bundle / 'lineage.json').read_text(encoding='utf-8'))
        attestation = json.loads((bundle / 'evaluation' / 'final-acceptance-attestation.json').read_text(encoding='utf-8'))
        if (manifest.get('purpose') != 'qualified_release'
                or manifest.get('recipe') != 'small-residual/v1'
                or lineage.get('version_id') != VERSION_ID
                or lineage.get('dataset_digest') != VERSION_DIGEST
                or lineage.get('model_digest') != MODEL_SHA256
                or attestation.get('plan_id') != PLAN_ID
                or attestation.get('plan_result_sha256') != PLAN_RESULT_SHA256
                or attestation.get('candidate_model_digest') != MODEL_SHA256
                or attestation.get('passed') is not True):
            return None
        return {'release_id': RELEASE_ID, 'workspace_id': WORKSPACE,
                'plan_id': PLAN_ID, 'plan_result_sha256': PLAN_RESULT_SHA256,
                'result_record_sha256': RESULT_RECORD_SHA256,
                'manifest_sha256': MANIFEST_SHA256, 'model_digest': MODEL_SHA256,
                'version_id': VERSION_ID, 'version_digest': VERSION_DIGEST,
                'dataset_id': DATASET_ID,
                'bundle': bundle, 'manifest': manifest, 'lineage': lineage,
                'attestation': attestation}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def require_consumed_plan(store, release: dict):
    """Bind the trusted local entry to the live DB's exact consumed result."""
    try:
        with store.connect() as c:
            row = c.execute('''SELECT state,exposures,consumed_utc,result_sha256,
                    candidate_model_digest,version_id,version_digest
                FROM fw_holdout_plans WHERE workspace=%s AND plan_id=%s''',
                (release['workspace_id'], release['plan_id'])).fetchone()
    except Exception:
        return False
    return bool(row and row['state'] == 'consumed' and row['consumed_utc'] is not None
        and row['exposures'] >= 1
        and row['result_sha256'] == release['plan_result_sha256']
        and row['candidate_model_digest'] == release['model_digest']
        and row['version_id'] == release['version_id']
        and row['version_digest'] == release['version_digest'])


def sha256(path: Path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def verify_inference_receipt(receipt: dict, *, pixel_digest: str, image_id: str, input_id: str):
    """Validate the bounded child receipt against the one source-pinned release."""
    from .data import canonical, digest
    fields = {'schema','scope','pid','process_identity','release_id','plan_id',
        'plan_result_sha256','result_record_sha256','bundle_digest','model_digest',
        'version_id','version_digest','model_image_id','sample_id','sample_split',
        'pixel_digest','logits','probabilities','top1','classes','public_export_authorized',
        'receipt_digest'}
    if type(receipt) is not dict or set(receipt) != fields:
        raise ValueError('QUALIFIED_RECEIPT_FIELDS')
    body = {k:v for k,v in receipt.items() if k != 'receipt_digest'}
    if (receipt['schema'] != 'fieldwork.qualified-inference-receipt/v1'
            or receipt['scope'] != 'qualified-release-image-inference/v1'
            or type(receipt['pid']) is not int or receipt['pid'] <= 0
            or receipt['release_id'] != RELEASE_ID or receipt['plan_id'] != PLAN_ID
            or receipt['plan_result_sha256'] != PLAN_RESULT_SHA256
            or receipt['result_record_sha256'] != RESULT_RECORD_SHA256
            or receipt['bundle_digest'] != MANIFEST_SHA256
            or receipt['model_digest'] != MODEL_SHA256
            or receipt['version_id'] != VERSION_ID or receipt['version_digest'] != VERSION_DIGEST
            or receipt['model_image_id'] != image_id or receipt['sample_split'] != 'upload'
            or receipt['sample_id'] != input_id
            or receipt['classes'] != ['Daisy','Dandelion','Rose','Sunflower','Tulip']
            or receipt['pixel_digest'] != pixel_digest or receipt['public_export_authorized'] is not False
            or receipt['receipt_digest'] != digest(canonical(body))):
        raise ValueError('QUALIFIED_RECEIPT_BINDING')
    try:
        import uuid
        uuid.UUID(receipt['process_identity'])
    except (ValueError, TypeError, AttributeError):
        raise ValueError('QUALIFIED_RECEIPT_PROCESS') from None
    logits, probabilities = receipt['logits'], receipt['probabilities']
    if (type(logits) is not list or len(logits) != 5 or type(probabilities) is not list
            or len(probabilities) != 5 or any(type(x) not in (int, float) or not __import__('math').isfinite(x)
                for x in logits + probabilities)
            or type(receipt['top1']) is not int
            or receipt['top1'] != max(range(5), key=lambda i: logits[i])):
        raise ValueError('QUALIFIED_RECEIPT_NUMERICS')
    peak = max(logits)
    denom = sum(__import__('math').exp(x - peak) for x in logits)
    expected = [__import__('math').exp(x - peak) / denom for x in logits]
    if any(abs(a-b) > 1e-6 for a,b in zip(probabilities, expected, strict=True)):
        raise ValueError('QUALIFIED_RECEIPT_SOFTMAX')
    return receipt


def safe_release_id(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value) is not None


def archive_qualified_upload(input_id: str, expected_sha256: str) -> Path | None:
    """Move a terminal accepted upload into its private retained archive.

    Accepted image bytes are evidence needed for provenance and are retained;
    only the transient staging copy is removed after an exact digest check.
    """
    import os
    import stat
    try:
        name = str(uuid.UUID(input_id))
        if (name != input_id or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256)
                or _reparse_in_root(QUALIFIED_UPLOAD_ROOT) or _reparse_in_root(ROOT / 'var')):
            return None
        source = QUALIFIED_UPLOAD_ROOT / (name + '.img')
        destination_root = QUALIFIED_UPLOAD_ARCHIVE
        destination_root.mkdir(parents=True, exist_ok=True)
        if _reparse_in_root(destination_root):
            return None
        destination = destination_root / (name + '.img')
        if source.exists():
            info = source.lstat()
            if (_reparse_in_root(source) or not stat.S_ISREG(info.st_mode)
                    or source.is_symlink() or sha256(source) != expected_sha256):
                return None
            if destination.exists():
                target_info = destination.lstat()
                if (_reparse_in_root(destination) or not stat.S_ISREG(target_info.st_mode)
                        or destination.is_symlink()
                        or sha256(destination) != expected_sha256):
                    return None
                source.unlink()
            else:
                os.replace(source, destination)
        if (destination.is_file() and not _reparse_in_root(destination)
                and not destination.is_symlink() and sha256(destination) == expected_sha256):
            return destination
    except (OSError, ValueError, TypeError):
        return None
    return None
