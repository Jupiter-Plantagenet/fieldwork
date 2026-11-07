"""ML-T-SAFE hostile-artifact acceptance matrix, executed on current source.

Every hostile case is a REAL artifact fed to the REAL code path. Rejections are
asserted by exact error text, the marker file a payload would create must be
absent, and native/unsafe loaders are wrapped in tripwires that fail the test if
reached. Where the artifact code runs inside the pinned Docker images (the shipped
model/decoder/pixel images) the real container runners are used.

Host vs container:
  * HOST: safe_codec / ml.validate_checkpoint / real_bundle.verify_real_bundle /
    real_training.load_selected / real_infer_child.infer / real_bundle.build, plus
    the tar export extractors of real_model_container.
  * CONTAINER (pinned images, real runner, real docker run arguments): hostile
    bundle through start_inference, inspect/exec isolation probes, OOM/pids/tmpfs,
    wall-time kill, decoder and pixel-decoder timeout kill + positive absence proof.
"""
import ast
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import uuid
import zipfile
import zlib
from pathlib import Path

import pytest

from tests.hostile_fixtures import (
    DECODER_IMAGE_ID, MODEL_IMAGE_ID, PIXEL_IMAGE_ID, make_bundle, make_checkpoint,
    pickle_payload, reseal_bundle, reseal_checkpoint, run_unsafely_in_throwaway_interpreter,
    safetensors_bytes, tar_bytes, torch_pt_payload, torchscript_payload, valid_model_tensors,
    zip_bomb_bytes)

ROOT = Path(__file__).resolve().parents[1]


class NativeReached(BaseException):
    """Raised by a tripwire when an unsafe/native loader is reached."""


def _tripwire(*_a, **_k):
    raise NativeReached('native or unsafe loader reached before validation finished')


@pytest.fixture
def tripwires(monkeypatch):
    """Native tensor loaders and every general-purpose deserializer raise if reached."""
    import pickle
    import safetensors.torch as st
    import torch
    import fieldwork.ml as ml
    import fieldwork.real_infer_child as infer_child     # import BEFORE patching so patches are undone
    import fieldwork.residual_recipe as residual
    monkeypatch.setattr(torch, 'load', _tripwire)
    monkeypatch.setattr(torch.jit, 'load', _tripwire)
    monkeypatch.setattr(pickle, 'loads', _tripwire)
    monkeypatch.setattr(pickle, 'load', _tripwire)
    monkeypatch.setattr(st, 'load_file', _tripwire)
    for module in (ml, infer_child, residual):
        monkeypatch.setattr(module, 'load_file', _tripwire)
    return True


@pytest.fixture(scope='module')
def template_bundle(tmp_path_factory):
    root = tmp_path_factory.mktemp('tpl-bundle') / 'bundle'
    path, digest = make_bundle(root)
    return path, digest


@pytest.fixture(scope='module')
def template_checkpoint(tmp_path_factory):
    root = tmp_path_factory.mktemp('tpl-ckpt')
    return make_checkpoint(root)


def _expected():
    from fieldwork.safe_codec import MODEL_SHAPES
    return {k: ('F32', shape) for k, shape in MODEL_SHAPES.items()}


def _bundle_with_model(template, tmp_path, model_bytes):
    src, _ = template
    dst = tmp_path / 'bundle'
    shutil.copytree(src, dst)
    return dst, reseal_bundle(dst, model_bytes=model_bytes)


def _checkpoint_with_state(template, tmp_path, state_bytes):
    src, _ = template
    dst = tmp_path / 'epoch-1'
    shutil.copytree(src, dst)
    (dst / 'state.safetensors').write_bytes(state_bytes)
    return dst, reseal_checkpoint(dst)


# =========================================================================== A. payload liveness
def test_payloads_are_live_when_loaded_unsafely(tmp_path):
    """Positive control: the pickle and torch.save payloads really run code if naively loaded."""
    marker = tmp_path / 'naive-pickle.marker'
    run_unsafely_in_throwaway_interpreter(pickle_payload(marker), tmp_path)
    assert marker.exists(), 'pickle payload is not live, hostile tests would prove nothing'
    marker_pt = tmp_path / 'naive-torch.marker'
    pt = tmp_path / 'evil.pt'
    torch_pt_payload(marker_pt, pt)
    subprocess.run([sys.executable, '-I', '-B', '-c',
                    'import torch,sys;torch.load(sys.argv[1],weights_only=False)', str(pt)],
                   check=False, timeout=120, capture_output=True)
    assert marker_pt.exists(), 'torch.save payload is not live'


# =========================================================================== B. parser matrix (host)
def _hostile_blobs(tmp_path):
    marker = tmp_path / 'MARKER-must-not-exist'
    pt = tmp_path / 'evil.pt'
    ts = tmp_path / 'script.pt'
    return marker, {
        'malicious_pickle': pickle_payload(marker),
        'malicious_torch_save_pickle_zip': torch_pt_payload(marker, pt),
        'torchscript_archive': torchscript_payload(ts),
        'zip_bomb_declared_1GiB': zip_bomb_bytes(members=40, member_bytes=25 * 1024 * 1024),
    }


@pytest.mark.parametrize('kind', ['malicious_pickle', 'malicious_torch_save_pickle_zip',
                                  'torchscript_archive', 'zip_bomb_declared_1GiB'])
def test_non_safetensors_payload_rejected_at_header_without_execution(tmp_path, kind, tripwires):
    from fieldwork.safe_codec import tensor_header
    marker, blobs = _hostile_blobs(tmp_path)
    blob = blobs[kind]
    target = tmp_path / 'model.safetensors'
    target.write_bytes(blob)
    with pytest.raises(ValueError) as caught:
        tensor_header(target, _expected())
    assert str(caught.value) == 'tensor header size'
    assert not marker.exists()


@pytest.mark.parametrize('case,expected', [
    ('header_length_2_63', 'tensor header size'),
    ('header_length_just_over_64KiB', 'tensor header size'),
    ('file_smaller_than_prefix', 'tensor size'),
    ('file_over_32MiB', 'tensor size'),
    ('nested_json_30000_deep', 'tensor header JSON'),
    ('invalid_utf8_header', 'tensor header JSON'),
    ('truncated_json_header', 'tensor header JSON'),
    ('duplicate_json_key', 'duplicate JSON key'),
    ('header_is_a_list', 'tensor header keys'),
    ('metadata_key_smuggled', 'tensor header keys'),
    ('declared_oversized_dimension', 'tensor header shape or dtype'),
    ('declared_oversized_offsets', 'tensor offsets'),
    ('negative_offset', 'tensor offsets'),
    ('offsets_not_ints', 'tensor offsets'),
    ('gapped_storage', 'tensor overlapping or gapped storage'),
    ('payload_truncated', 'tensor payload size'),
    ('trailing_garbage_after_payload', 'tensor payload size'),
])
def test_oversized_and_malformed_tensor_headers_rejected(tmp_path, case, expected, tripwires):
    from safetensors.torch import save_file
    from fieldwork.safe_codec import tensor_header
    good = tmp_path / 'good.safetensors'
    save_file(valid_model_tensors(), str(good))
    raw = good.read_bytes()
    import struct
    n = struct.unpack('<Q', raw[:8])[0]
    header = json.loads(raw[8:8 + n])
    payload = raw[8 + n:]
    if case == 'header_length_2_63':
        blob = struct.pack('<Q', 2 ** 63) + b'{}' + b'\0' * 64
    elif case == 'header_length_just_over_64KiB':
        blob = struct.pack('<Q', 65537) + b' ' * 65537 + b'\0' * 64
    elif case == 'file_smaller_than_prefix':
        blob = b'12345'
    elif case == 'file_over_32MiB':
        blob = raw + b'\0' * (32 * 1024 * 1024)
    elif case == 'nested_json_30000_deep':
        body = b'[' * 30000 + b']' * 30000
        blob = struct.pack('<Q', len(body)) + body
    elif case == 'invalid_utf8_header':
        body = b'\xff\xfe\xfd{'
        blob = struct.pack('<Q', len(body)) + body + b'\0' * 16
    elif case == 'truncated_json_header':
        body = b'{"0.weight":{"dtype":"F32"'
        blob = struct.pack('<Q', len(body)) + body + b'\0' * 16
    elif case == 'duplicate_json_key':
        body = b'{"0.weight":{},"0.weight":{}}'
        blob = struct.pack('<Q', len(body)) + body + b'\0' * 16
    elif case == 'header_is_a_list':
        body = b'[]'
        blob = struct.pack('<Q', len(body)) + body + b'\0' * 16
    elif case == 'metadata_key_smuggled':
        h = dict(header); h['__metadata__'] = {'format': 'pt'}
        blob = safetensors_bytes(h, payload)
    elif case == 'declared_oversized_dimension':
        h = json.loads(json.dumps(header)); h['0.weight']['shape'] = [4_000_000, 3, 3, 3]
        blob = safetensors_bytes(h, payload)
    elif case == 'declared_oversized_offsets':
        h = json.loads(json.dumps(header)); h['0.weight']['data_offsets'] = [0, 2 ** 62]
        blob = safetensors_bytes(h, payload)
    elif case == 'negative_offset':
        h = json.loads(json.dumps(header)); a, b = h['0.weight']['data_offsets']
        h['0.weight']['data_offsets'] = [-8, b - a - 8]
        blob = safetensors_bytes(h, payload)
    elif case == 'offsets_not_ints':
        h = json.loads(json.dumps(header)); h['0.weight']['data_offsets'] = ['0', '3456']
        blob = safetensors_bytes(h, payload)
    elif case == 'gapped_storage':
        h = json.loads(json.dumps(header)); a, b = h['11.bias']['data_offsets']
        h['11.bias']['data_offsets'] = [a + 4, b + 4]
        blob = safetensors_bytes(h, payload + b'\0' * 4)
    elif case == 'payload_truncated':
        blob = safetensors_bytes(header, payload[:-4])
    elif case == 'trailing_garbage_after_payload':
        blob = safetensors_bytes(header, payload + b'GARBAGE!')
    target = tmp_path / 'case.safetensors'
    target.write_bytes(blob)
    with pytest.raises(ValueError) as caught:
        tensor_header(target, _expected())
    assert str(caught.value) == expected
    # control: the unmodified file is accepted by the very same parser
    assert tensor_header(good, _expected())


def _save(path, tensors):
    from safetensors.torch import save_file
    save_file(tensors, str(path))


@pytest.mark.parametrize('case,expected', [
    ('wrong_shape_first_conv', 'tensor header shape or dtype'),
    ('wrong_shape_classifier', 'tensor header shape or dtype'),
    ('wrong_dtype_float16', 'tensor header shape or dtype'),
    ('wrong_dtype_float64', 'tensor header shape or dtype'),
    ('wrong_dtype_int64', 'tensor header shape or dtype'),
    ('wrong_dtype_uint8', 'tensor header shape or dtype'),
    ('missing_key', 'tensor header keys'),
    ('extra_key', 'tensor header keys'),
    ('renamed_key', 'tensor header keys'),
    ('key_with_optimizer_prefix', 'tensor header keys'),
])
def test_wrong_shape_dtype_or_key_rejected_by_parser_and_bundle_verifier(
        tmp_path, template_bundle, case, expected, tripwires):
    import torch
    from fieldwork.safe_codec import tensor_header
    from fieldwork.real_bundle import verify_real_bundle
    t = valid_model_tensors()
    if case == 'wrong_shape_first_conv':
        t['0.weight'] = torch.zeros(32, 3, 5, 5)
    elif case == 'wrong_shape_classifier':
        t['11.weight'] = torch.zeros(10, 128)
    elif case == 'wrong_dtype_float16':
        t['0.bias'] = t['0.bias'].half()
    elif case == 'wrong_dtype_float64':
        t['0.bias'] = t['0.bias'].double()
    elif case == 'wrong_dtype_int64':
        t['0.bias'] = torch.zeros(32, dtype=torch.int64)
    elif case == 'wrong_dtype_uint8':
        t['0.bias'] = torch.zeros(32, dtype=torch.uint8)
    elif case == 'missing_key':
        del t['11.bias']
    elif case == 'extra_key':
        t['evil.extra'] = torch.zeros(1)
    elif case == 'renamed_key':
        t['0.weights'] = t.pop('0.weight')
    elif case == 'key_with_optimizer_prefix':
        t['optimizer.0.weight.exp_avg'] = t['0.weight'].clone()
    path = tmp_path / 'wrong.safetensors'
    _save(path, t)
    with pytest.raises(ValueError) as caught:
        tensor_header(path, _expected())
    assert str(caught.value) == expected
    bundle, digest = _bundle_with_model(template_bundle, tmp_path, path.read_bytes())
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(bundle, expected_digest=digest)
    assert str(caught.value) == expected


def test_nonfinite_tensor_rejected_at_bundle_verification(tmp_path, template_bundle, tripwires):
    import torch
    from fieldwork.real_bundle import verify_real_bundle
    t = valid_model_tensors()
    t['0.bias'][0] = float('nan')
    path = tmp_path / 'nan.safetensors'
    _save(path, t)
    # fully consistent bundle (predictions bound to the NaN model's digest) so only the finiteness gate can fire
    bundle, digest = make_bundle(tmp_path / 'nan-bundle', model_bytes=path.read_bytes())
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(bundle, expected_digest=digest)
    assert str(caught.value) == 'REAL_BUNDLE_TENSOR'


def test_valid_bundle_and_checkpoint_pass_the_same_validators(template_bundle, template_checkpoint):
    """Positive controls: the validators accept good artifacts, so rejections above are specific."""
    from fieldwork.real_bundle import verify_real_bundle
    from fieldwork.ml import validate_checkpoint
    bundle, digest = template_bundle
    assert verify_real_bundle(bundle, expected_digest=digest)['purpose'] == 'private_real_candidate'
    ckpt, cdigest = template_checkpoint
    assert validate_checkpoint(ckpt, expected_digest=cdigest)['schema'] == 1


# =========================================================================== C. hostile model through every real entry point
@pytest.mark.parametrize('kind', ['malicious_pickle', 'malicious_torch_save_pickle_zip',
                                  'torchscript_archive', 'zip_bomb_declared_1GiB'])
def test_hostile_model_refused_by_bundle_verifier_and_inference_child(tmp_path, template_bundle, kind, tripwires):
    from fieldwork.real_bundle import verify_real_bundle
    from fieldwork.real_infer_child import infer
    marker, blobs = _hostile_blobs(tmp_path)
    bundle, digest = _bundle_with_model(template_bundle, tmp_path, blobs[kind])
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(bundle, expected_digest=digest)
    assert str(caught.value) == 'tensor header size'
    entry = {'id': 's0', 'split': 'validation', 'pixel_file': 'p.rgb', 'width': 144, 'height': 144,
             'decoded_pixel_sha256': '0' * 64}
    from tests.hostile_fixtures import MODEL_IMAGE_ID as image
    with pytest.raises(ValueError) as caught:
        infer(bundle, tmp_path / 'pixels', entry, digest, image)
    assert str(caught.value) == 'tensor header size'
    assert not marker.exists()


@pytest.mark.parametrize('kind', ['malicious_pickle', 'malicious_torch_save_pickle_zip',
                                  'torchscript_archive', 'zip_bomb_declared_1GiB'])
def test_hostile_checkpoint_refused_by_every_checkpoint_consumer(tmp_path, template_checkpoint, kind, tripwires):
    import torch
    from fieldwork.ml import validate_checkpoint, restore, model
    from fieldwork.real_training import load_selected
    from fieldwork.real_bundle import build
    marker, blobs = _hostile_blobs(tmp_path)
    ckpt, digest = _checkpoint_with_state(template_checkpoint, tmp_path, blobs[kind])
    with pytest.raises(ValueError) as caught:
        validate_checkpoint(ckpt, expected_digest=digest)
    assert str(caught.value) == 'tensor header size'
    with pytest.raises(ValueError) as caught:
        load_selected(ckpt, digest)
    assert str(caught.value) == 'tensor header size'
    net = model(); opt = torch.optim.AdamW(net.parameters())
    with pytest.raises(ValueError) as caught:
        restore(ckpt, net, opt, expected_digest=digest)
    assert str(caught.value) == 'tensor header size'
    with pytest.raises(ValueError) as caught:
        build(ckpt, tmp_path / 'no-inputs', tmp_path / 'out', expected_checkpoint_digest=digest,
              version_id='v', version_digest='a' * 64, classes=list('abcde'),
              rights_decision_digests=['e' * 64], model_image_id=MODEL_IMAGE_ID)
    assert str(caught.value) == 'tensor header size'
    assert not marker.exists()


def test_checkpoint_wrong_dtype_and_extra_tensor_rejected_after_reseal(tmp_path, template_checkpoint, tripwires):
    import torch
    from safetensors import safe_open
    from safetensors.torch import save as save_bytes
    from fieldwork.ml import validate_checkpoint
    src, _ = template_checkpoint
    tensors = {}
    with safe_open(str(src / 'state.safetensors'), framework='pt') as f:
        for key in f.keys():
            tensors[key] = f.get_tensor(key)
    half = dict(tensors); half['model.0.bias'] = half['model.0.bias'].half()
    ckpt, _ = _checkpoint_with_state(template_checkpoint, tmp_path / 'a', save_bytes(half))
    with pytest.raises(ValueError) as caught:
        validate_checkpoint(ckpt, expected_digest=reseal_checkpoint(ckpt))
    assert str(caught.value) == 'tensor header shape or dtype'
    extra = dict(tensors); extra['evil.extra'] = torch.zeros(1)
    ckpt2, _ = _checkpoint_with_state(template_checkpoint, tmp_path / 'b', save_bytes(extra))
    with pytest.raises(ValueError) as caught:
        validate_checkpoint(ckpt2, expected_digest=reseal_checkpoint(ckpt2))
    assert str(caught.value) == 'tensor header keys'


# =========================================================================== D. python recipe / import code
RECIPE_SOURCE = "open({marker!r}, 'w').write('recipe-imported')\nclass Model: pass\n"


@pytest.mark.parametrize('name', ['recipe.py', 'model.py', 'sitecustomize.py', 'usercustomize.py',
                                  '__init__.py', 'architecture.py', 'evil.pyc', 'setup.cfg', 'recipe.pth'])
def test_bundle_with_python_recipe_file_rejected_and_never_imported(tmp_path, template_bundle, name, monkeypatch, tripwires):
    from fieldwork.real_bundle import verify_real_bundle
    marker = tmp_path / 'RECIPE-MARKER'
    src, digest = template_bundle
    unlisted = tmp_path / 'unlisted'
    shutil.copytree(src, unlisted)
    (unlisted / name).write_text(RECIPE_SOURCE.format(marker=str(marker)))
    monkeypatch.syspath_prepend(str(unlisted))
    monkeypatch.chdir(unlisted)
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(unlisted, expected_digest=digest)
    assert str(caught.value) == 'REAL_BUNDLE_INVENTORY'
    listed = tmp_path / 'listed'
    shutil.copytree(src, listed)
    (listed / name).write_text(RECIPE_SOURCE.format(marker=str(marker)))
    listed_digest = reseal_bundle(listed, extra_manifest_files=[name])
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(listed, expected_digest=listed_digest)
    assert str(caught.value) == 'REAL_BUNDLE_MANIFEST'
    assert not marker.exists()


def test_architecture_json_is_inert_data_and_never_resolves_to_code(tmp_path, template_bundle, monkeypatch, tripwires):
    """architecture.json naming an importable module must not import it."""
    from fieldwork.real_bundle import verify_real_bundle
    marker = tmp_path / 'ARCH-MARKER'
    evil_dir = tmp_path / 'evilmods'
    evil_dir.mkdir()
    (evil_dir / 'evil_recipe_module.py').write_text(RECIPE_SOURCE.format(marker=str(marker)))
    monkeypatch.syspath_prepend(str(evil_dir))
    src, _ = template_bundle
    dst = tmp_path / 'b'
    shutil.copytree(src, dst)
    (dst / 'architecture.json').write_text(json.dumps(
        {'schema': 1, 'id': 'evil_recipe_module', '__import__': 'evil_recipe_module', 'module': 'evil_recipe_module:Model'}))
    digest = reseal_bundle(dst)
    try:
        verify_real_bundle(dst, expected_digest=digest)
    except ValueError:
        pass
    assert not marker.exists()
    assert 'evil_recipe_module' not in sys.modules


@pytest.mark.parametrize('recipe', ["__import__('os').system('echo pwn')", 'os.system', 'evil:Model',
                                    'compact-cnn/v1; import os'])
def test_checkpoint_recipe_string_is_not_executable_and_is_rejected(tmp_path, template_checkpoint, recipe, tripwires):
    from fieldwork.ml import validate_checkpoint
    from fieldwork.data import canonical
    src, _ = template_checkpoint
    dst = tmp_path / 'epoch-1'
    shutil.copytree(src, dst)
    meta = json.loads((dst / 'state.json').read_bytes())
    meta['recipe'] = recipe
    (dst / 'state.json').write_bytes(canonical(meta))
    digest = reseal_checkpoint(dst)
    with pytest.raises(ValueError) as caught:
        validate_checkpoint(dst, expected_digest=digest)
    assert str(caught.value) == 'checkpoint state schema'


def test_checkpoint_with_python_file_rejected(tmp_path, template_checkpoint, tripwires):
    from fieldwork.ml import validate_checkpoint
    src, digest = template_checkpoint
    dst = tmp_path / 'epoch-1'
    shutil.copytree(src, dst)
    marker = tmp_path / 'CK-MARKER'
    (dst / 'recipe.py').write_text(RECIPE_SOURCE.format(marker=str(marker)))
    with pytest.raises(ValueError) as caught:
        validate_checkpoint(dst, expected_digest=digest)
    assert str(caught.value) == 'checkpoint unexpected files'
    assert not marker.exists()


def test_child_dispatch_is_a_closed_set_and_refuses_arbitrary_modules(tmp_path, monkeypatch):
    """No user allowlist: the sealed image dispatcher accepts exactly four fixed (op, module) pairs."""
    from fieldwork import model_child_entry as entry
    marker = tmp_path / 'DISPATCH-MARKER'
    (tmp_path / 'evil_child.py').write_text(RECIPE_SOURCE.format(marker=str(marker)))
    monkeypatch.syspath_prepend(str(tmp_path))
    assert entry.MODULES == {'training': 'fieldwork.real_train_child',
                             'inference': 'fieldwork.real_infer_child',
                             'qualified-inference': 'fieldwork.qualified_infer_child',
                             'bundle': 'fieldwork.real_bundle_child'}
    monkeypatch.setenv('FW_CHILD_RECEIPT', '/tmp/child-stdout.txt')
    for argv in (['training', 'evil_child'], ['evil', 'evil_child'], ['inference', 'os'],
                 ['training', 'fieldwork.real_infer_child'], ['bundle'], [], ['inference', 'evil_child', '--x'],
                 ['training', 'fieldwork.real_train_child\x00evil_child']):
        assert entry.main(list(argv)) == 2, argv
    assert not marker.exists() and 'evil_child' not in sys.modules
    # nothing in the environment can extend the set
    monkeypatch.setenv('FW_CHILD_MODULES', 'evil_child')
    monkeypatch.setenv('FW_ALLOWLIST', 'evil_child')
    assert entry.main(['inference', 'evil_child']) == 2


# =========================================================================== E. no unsafe loader / fallback in source
FORBIDDEN_CALLS = {
    'torch.load', 'torch.jit.load', 'jit.load', 'pickle.load', 'pickle.loads', 'pickle.Unpickler',
    'cPickle.load', 'cPickle.loads', 'marshal.load', 'marshal.loads', 'dill.load', 'dill.loads',
    'cloudpickle.load', 'cloudpickle.loads', 'joblib.load', 'shelve.open', 'yaml.load', 'yaml.unsafe_load',
    'importlib.import_module', 'importlib.__import__', 'torch.hub.load', 'torch.package.PackageImporter',
    'eval', 'exec', 'compile',
}
# Reviewed, non-model-artifact uses. Each must stay literal and unrelated to model artifacts.
REVIEWED_EXCEPTIONS = {
    # no entries expected in product source; any new hit fails the test until reviewed.
}


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr); node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return '.'.join(reversed(parts))
    return None


def _scan_source(files):
    hits = []
    for path in files:
        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            if name in FORBIDDEN_CALLS:
                hits.append((path.name, node.lineno, name))
            if name == '__import__' and not (node.args and isinstance(node.args[0], ast.Constant)):
                hits.append((path.name, node.lineno, '__import__(non-literal)'))
            if name in ('np.load', 'numpy.load'):
                for kw in node.keywords:
                    if kw.arg == 'allow_pickle' and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                        hits.append((path.name, node.lineno, 'numpy.load(allow_pickle!=False)'))
            for kw in node.keywords:
                if kw.arg == 'weights_only' and not (isinstance(kw.value, ast.Constant) and kw.value.value is True):
                    hits.append((path.name, node.lineno, 'weights_only!=True'))
    return hits


def test_no_unsafe_deserializer_or_dynamic_import_in_product_source():
    files = sorted((ROOT / 'fieldwork').glob('*.py'))
    assert len(files) > 40
    hits = [h for h in _scan_source(files) if h not in REVIEWED_EXCEPTIONS]
    assert hits == [], hits
    # Control: the scanner flags these when they are present.
    sample = ast.parse("import torch,pickle\ntorch.load('x')\npickle.loads(b'')\nexec('1')\n"
                       "torch.load('x', weights_only=False)\n__import__(name)\n")
    flagged = []
    for node in ast.walk(sample):
        if isinstance(node, ast.Call) and _dotted(node.func) in FORBIDDEN_CALLS | {'__import__'}:
            flagged.append(_dotted(node.func))
    assert flagged == ['torch.load', 'pickle.loads', 'exec', 'torch.load', '__import__']


def test_no_torch_load_fallback_after_safetensors_failure_in_model_paths(tmp_path, template_checkpoint, tripwires):
    """A failing safetensors parse must end in an error, never in a legacy loader retry."""
    from fieldwork.ml import validate_checkpoint
    ckpt, digest = _checkpoint_with_state(template_checkpoint, tmp_path, b'\x80\x02not safetensors at all')
    with pytest.raises(ValueError):
        validate_checkpoint(ckpt, expected_digest=digest)   # a fallback would hit NativeReached (BaseException)
    # Control: tripwires do fire on the legitimate native path.
    src, good = template_checkpoint
    with pytest.raises(NativeReached):
        validate_checkpoint(src, expected_digest=good)


# =========================================================================== F. archive exports (artifact transport)
def _runner_cls():
    from fieldwork.real_model_container import ModelContainerProcess as P
    return P


def _bundle_members(extra=None):
    names = ['manifest.json', 'architecture.json', 'preprocess.json', 'classes.json', 'lineage.json',
             'model.safetensors', 'rights/review.json', 'evaluation/population.json', 'evaluation/metrics.json',
             'evaluation/independent-report.json', 'evaluation/predictions.jsonl']
    members = [('bundle', None, 'dir'), ('bundle/evaluation', None, 'dir'), ('bundle/rights', None, 'dir')]
    members += [('bundle/' + n, b'{}', 'file') for n in names]
    return members + list(extra or [])


EXPORT_LIMITS = {'manifest.json': 1 << 20, 'architecture.json': 1 << 20, 'preprocess.json': 1 << 20,
                 'classes.json': 1 << 20, 'lineage.json': 1 << 20, 'model.safetensors': 32 << 20,
                 'rights/review.json': 1 << 20, 'evaluation/population.json': 8 << 20,
                 'evaluation/metrics.json': 2 << 20, 'evaluation/independent-report.json': 2 << 20,
                 'evaluation/predictions.jsonl': 32 << 20}


def test_bundle_export_extractor_accepts_exact_tree_control(tmp_path):
    P = _runner_cls()
    out = P._extract_bundle_tar(tar_bytes(_bundle_members()), tmp_path / 'ok', EXPORT_LIMITS)
    assert (out / 'model.safetensors').exists()


@pytest.mark.parametrize('case', ['symlink', 'hardlink', 'traversal', 'absolute', 'duplicate', 'extra_member',
                                  'fifo', 'oversize_member', 'gzip_bomb', 'zip_instead_of_tar', 'missing_member'])
def test_bundle_export_extractor_rejects_hostile_archives(tmp_path, case):
    P = _runner_cls()
    members = _bundle_members()
    if case == 'symlink':
        members.append(('bundle/model.safetensors', '/etc/passwd', 'sym'))
    elif case == 'hardlink':
        members.append(('bundle/evil', 'bundle/model.safetensors', 'hard'))
    elif case == 'traversal':
        members.append(('bundle/../../escape.txt', b'x', 'file'))
    elif case == 'absolute':
        members.append(('/abs/escape.txt', b'x', 'file'))
    elif case == 'duplicate':
        members.append(('bundle/classes.json', b'{}', 'file'))
    elif case == 'extra_member':
        members.append(('bundle/recipe.py', b'import os', 'file'))
    elif case == 'fifo':
        members.append(('bundle/pipe', None, 'fifo'))
    elif case == 'oversize_member':
        members = [(n, (b'x' * (EXPORT_LIMITS['model.safetensors'] + 1) if n.endswith('model.safetensors') else d), k)
                   for n, d, k in members]
    elif case == 'missing_member':
        members = [m for m in members if not m[0].endswith('lineage.json')]
    raw = tar_bytes(members)
    if case == 'gzip_bomb':
        big = tar_bytes([('bundle', None, 'dir'), ('bundle/model.safetensors', b'\0' * (200 << 20), 'file')])
        comp = zlib.compressobj(9, zlib.DEFLATED, 31)
        raw = comp.compress(big) + comp.flush()
        assert len(raw) < 1 << 20 and len(big) > 190 << 20
        del big
    elif case == 'zip_instead_of_tar':
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('bundle/model.safetensors', b'\0' * (5 << 20))
        raw = buf.getvalue()
    from fieldwork.real_model_container import ModelContainerUnavailable
    with pytest.raises(ModelContainerUnavailable) as caught:
        P._extract_bundle_tar(raw, tmp_path / 'out', EXPORT_LIMITS)
    assert caught.value.code == 'MODEL_BUNDLE_ARCHIVE_INVALID'
    assert not (tmp_path / 'out').exists()
    assert not (tmp_path / 'escape.txt').exists()


@pytest.mark.parametrize('case', ['symlink', 'traversal', 'oversize', 'extra', 'gzip_bomb'])
def test_checkpoint_export_extractor_rejects_hostile_archives(tmp_path, case):
    P = _runner_cls()
    limits = {'manifest.json': 1 << 20, 'state.json': 1 << 20, 'state.safetensors': 32 << 20}
    good = [('epoch-1', None, 'dir'), ('epoch-1/manifest.json', b'{}', 'file'),
            ('epoch-1/state.json', b'{}', 'file'), ('epoch-1/state.safetensors', b'x', 'file')]
    if case == 'symlink':
        good[3] = ('epoch-1/state.safetensors', '/etc/shadow', 'sym')
    elif case == 'traversal':
        good.append(('epoch-1/../x', b'x', 'file'))
    elif case == 'oversize':
        good[3] = ('epoch-1/state.safetensors', b'x' * ((32 << 20) + 1), 'file')
    elif case == 'extra':
        good.append(('epoch-1/evil.py', b'x', 'file'))
    raw = tar_bytes(good)
    if case == 'gzip_bomb':
        big = tar_bytes([('epoch-1', None, 'dir'), ('epoch-1/state.safetensors', b'\0' * (100 << 20), 'file')])
        comp = zlib.compressobj(9, zlib.DEFLATED, 31)
        raw = comp.compress(big) + comp.flush()
        del big
    from fieldwork.real_model_container import ModelContainerUnavailable
    with pytest.raises(ModelContainerUnavailable) as caught:
        P._extract_tar(raw, tmp_path / 'out', expected_prefix='epoch-1', limits=limits)
    assert caught.value.code == 'MODEL_OUTPUT_ARCHIVE_INVALID'
    assert not (tmp_path / 'out').exists()


# =========================================================================== G. corrupted digests
def test_corrupted_digest_matrix_for_bundle(tmp_path, template_bundle, tripwires):
    from fieldwork.real_bundle import verify_real_bundle
    from fieldwork.data import canonical
    src, digest = template_bundle
    def fresh(name):
        dst = tmp_path / name
        shutil.copytree(src, dst)
        return dst
    # 1. single flipped byte in model.safetensors, manifest untouched
    b = fresh('flip')
    raw = bytearray((b / 'model.safetensors').read_bytes()); raw[-5] ^= 1
    (b / 'model.safetensors').write_bytes(bytes(raw))
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(b, expected_digest=digest)
    assert str(caught.value) == 'REAL_BUNDLE_FILE_DIGEST'
    # 2. flipped byte in a metric file
    b = fresh('metric')
    raw = bytearray((b / 'evaluation/metrics.json').read_bytes()); raw[10] ^= 1
    (b / 'evaluation/metrics.json').write_bytes(bytes(raw))
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(b, expected_digest=digest)
    assert str(caught.value) == 'REAL_BUNDLE_FILE_DIGEST'
    # 3. manifest rewritten (attacker re-seals files) but trusted digest unchanged
    b = fresh('manifest')
    m = json.loads((b / 'manifest.json').read_bytes())
    m['files']['classes.json']['sha256'] = '0' * 64
    (b / 'manifest.json').write_bytes(canonical(m))
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(b, expected_digest=digest)
    assert str(caught.value) == 'REAL_BUNDLE_MANIFEST'
    # 4. wrong / empty trusted digest
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(src, expected_digest='f' * 64)
    assert str(caught.value) == 'REAL_BUNDLE_MANIFEST'
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(src, expected_digest='')
    assert str(caught.value) == 'REAL_BUNDLE_TRUSTED_DIGEST_REQUIRED'
    # 5. wrong lineage binding
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(src, expected_digest=digest, expected_lineage={'checkpoint_digest': '9' * 64})
    assert str(caught.value) == 'REAL_BUNDLE_LINEAGE'
    # 6. model digest in lineage disagrees with the model file (manifest honestly re-sealed)
    from fieldwork.data import digest as sha
    b = fresh('lineage')
    lin = json.loads((b / 'lineage.json').read_bytes()); lin['model_digest'] = '1' * 64
    (b / 'lineage.json').write_bytes(canonical(lin))
    m = json.loads((b / 'manifest.json').read_bytes())
    m['files']['lineage.json'] = {'sha256': sha((b / 'lineage.json').read_bytes()),
                                  'bytes': (b / 'lineage.json').stat().st_size}
    (b / 'manifest.json').write_bytes(canonical(m))
    with pytest.raises(ValueError) as caught:
        verify_real_bundle(b, expected_digest=sha(canonical(m)))
    assert str(caught.value) == 'REAL_BUNDLE_LINEAGE_SCHEMA'


def test_corrupted_digest_matrix_for_checkpoint(tmp_path, template_checkpoint, tripwires):
    import torch
    from fieldwork.ml import validate_checkpoint, restore, model
    src, digest = template_checkpoint
    dst = tmp_path / 'epoch-1'
    shutil.copytree(src, dst)
    raw = bytearray((dst / 'state.safetensors').read_bytes()); raw[-3] ^= 0xFF
    (dst / 'state.safetensors').write_bytes(bytes(raw))
    with pytest.raises(ValueError) as caught:
        validate_checkpoint(dst, expected_digest=digest)
    assert str(caught.value) == 'checkpoint digest or size'
    with pytest.raises(ValueError) as caught:
        validate_checkpoint(src, expected_digest='0' * 64)
    assert str(caught.value) == 'committed checkpoint digest'
    net = model(); opt = torch.optim.AdamW(net.parameters())
    with pytest.raises(ValueError) as caught:
        restore(src, net, opt)
    assert 'trusted expected checkpoint digest required' in str(caught.value)
    with pytest.raises(ValueError) as caught:
        restore(src, net, opt, expected_digest='0' * 64)
    assert str(caught.value) == 'committed checkpoint digest'


# =========================================================================== H. never served inline
def test_no_route_serves_model_or_artifact_bytes_inline_and_media_is_image_only():
    from fieldwork import real_api
    allowed_image = {'image/jpeg', 'image/png', 'image/webp'}
    assert set(real_api.MEDIA_TYPES.values()) <= allowed_image
    served = []
    for path in sorted((ROOT / 'fieldwork').glob('*.py')):
        text = path.read_text(encoding='utf-8')
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _dotted(node.func) in {'Response', 'FileResponse', 'StreamingResponse'}:
                kw = {k.arg: k.value for k in node.keywords}
                mt = kw.get('media_type')
                served.append((path.name, ast.unparse(mt) if mt is not None else 'default',
                               'Content-Disposition' in ast.unparse(kw['headers']) if 'headers' in kw else False,
                               'nosniff' in ast.unparse(kw['headers']) if 'headers' in kw else False))
    for name, media, attachment, nosniff in served:
        assert media not in {"'text/html'", "'application/xhtml+xml'", "'image/svg+xml'", "'application/javascript'",
                             "'text/javascript'", "'application/octet-stream'", 'default'} or name in {'api.py'}, (name, media)
        if media in {"'application/zip'", "'application/x-ndjson'"}:
            assert attachment, (name, media)   # archives/ndjson only ever as attachments
    # the gated real media route: content type from decoded image format, nosniff, verified digest
    source = (ROOT / 'fieldwork/real_api.py').read_text(encoding='utf-8')
    assert "'X-Content-Type-Options': 'nosniff'" in source and 'media_type=content_type' in source
    assert 'inline' not in ' '.join(t for t in re.findall(r'Content-Disposition[^\n]*', source))
    # served bytes must equal the digest-pinned catalogue bytes, never different or oversized bytes
    import tempfile
    from hashlib import sha256
    from fastapi import HTTPException
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'x.png'
        p.write_bytes(b'<html><script>alert(1)</script>')
        with pytest.raises(HTTPException):
            real_api._read_verified_media(p, sha256(b'real image bytes').hexdigest(), len(b'<html><script>alert(1)</script>'))


# =========================================================================== I. containers (pinned images, real runners)
def _docker(*args, timeout=60, input=None):
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE')}
    return subprocess.run(['docker', '--context', 'default', *args], capture_output=True, text=True,
                          timeout=timeout, env=env, input=input)


def _docker_available():
    try:
        return _docker('info', '--format', '{{.OSType}}', timeout=15).stdout.strip() == 'linux'
    except Exception:
        return False


PROBE = r'''
import json, os, resource, socket, sys, time
r = {}
r['env'] = dict(os.environ)
host = sys.argv[1] if len(sys.argv) > 1 else ''
port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
if host:
    try:
        socket.create_connection((host, port), timeout=3).close(); r['connect'] = 'CONNECTED'
    except OSError as e:
        r['connect'] = 'FAILED:%s:%s' % (type(e).__name__, e.errno)
for name in ('example.com', 'localhost.localdomain.invalid'):
    try:
        socket.getaddrinfo(name, 80); r['dns_' + name] = 'RESOLVED'
    except OSError as e:
        r['dns_' + name] = 'FAILED:' + type(e).__name__
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.connect(('1.1.1.1', 53)); s.send(b'x')
    r['udp'] = 'SENT'
except OSError as e:
    r['udp'] = 'FAILED:%s' % e.errno
r['ifaces'] = [l.split(':')[0].strip() for l in open('/proc/net/dev').read().splitlines()[2:]]
r['routes'] = open('/proc/net/route').read().splitlines()[1:]
st = dict(l.split(':', 1) for l in open('/proc/self/status').read().splitlines() if ':' in l)
r['CapEff'] = st['CapEff'].strip(); r['CapBnd'] = st['CapBnd'].strip(); r['NoNewPrivs'] = st['NoNewPrivs'].strip()
r['uid'] = os.getuid(); r['gid'] = os.getgid()
mi = [l.split() for l in open('/proc/self/mountinfo').read().splitlines()]
r['mounts'] = [(m[4], m[m.index('-') + 1]) for m in mi]
r['mount_sources'] = [m[m.index('-') + 2] for m in mi]
for path in ('/app/_w', '/etc/_w', '/usr/_w', '/workspace/_w', '/_w'):
    try:
        open(path, 'w').write('x'); r['write:' + path] = 'WRITTEN'
    except OSError as e:
        r['write:' + path] = 'FAILED:%s' % e.errno
r['host_visible'] = [p for p in ('/mnt/c', '/host_mnt', '/run/desktop/mnt/host', '/c', '/Users') if os.path.exists(p)]
for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max'):
    try:
        r['cg:' + name] = open('/sys/fs/cgroup/' + name).read().strip()
    except OSError:
        r['cg:' + name] = None
r['nofile'] = list(resource.getrlimit(resource.RLIMIT_NOFILE))
r['fsize'] = list(resource.getrlimit(resource.RLIMIT_FSIZE))
r['core'] = list(resource.getrlimit(resource.RLIMIT_CORE))
mode = os.environ.get('FW_PROBE_MODE', '') or (sys.argv[3] if len(sys.argv) > 3 else '')
try:
    with open('/tmp/_fill', 'wb') as f:
        for _ in range(120):
            f.write(b'\0' * (1 << 20)); f.flush()
    r['tmp_fill'] = 'NO_LIMIT'
except OSError as e:
    r['tmp_fill'] = 'FAILED:%s' % e.errno
finally:
    try: os.unlink('/tmp/_fill')
    except OSError: pass
kids = []
for _ in range(150):
    try:
        pid = os.fork()
    except OSError as e:
        r['fork_error'] = e.errno; break
    if pid == 0:
        time.sleep(3); os._exit(0)
    kids.append(pid)
r['forked'] = len(kids)
for pid in kids:
    try: os.kill(pid, 9); os.waitpid(pid, 0)
    except OSError: pass
print(json.dumps(r, default=str))
'''.strip()


def _wait_cid(runner, process, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.cid:
            return process.cid
        time.sleep(.1)
    raise AssertionError('no container id')


def _inspect(cid):
    out = _docker('inspect', cid)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)[0]


def _exec_probe(cid, *argv):
    out = _docker('exec', cid, '/usr/local/bin/python', '-I', '-B', '-c', PROBE, *argv, timeout=60)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout)


def _absent_by_nonce(label, nonce):
    out = _docker('ps', '--all', '--quiet', '--no-trunc', '--filter', f'label={label}.nonce={nonce}')
    assert out.returncode == 0
    return out.stdout.strip() == ''


@pytest.fixture(scope='module')
def docker_ready():
    if not _docker_available():
        pytest.fail('Docker Linux engine unavailable: container rows cannot be proven')
    for image in (MODEL_IMAGE_ID, DECODER_IMAGE_ID, PIXEL_IMAGE_ID):
        out = _docker('image', 'inspect', '--format', '{{.Id}}', image)
        assert out.stdout.strip() == image, f'pinned image missing: {image}'
    return True


def _valid_pixel_entry(tmp_path):
    from hashlib import sha256
    root = tmp_path / 'pixels'
    root.mkdir()
    payload = bytes((i * 7 + 3) % 256 for i in range(144 * 144 * 3))
    (root / 'p.rgb').write_bytes(payload)
    return root, {'id': 's0', 'split': 'validation', 'pixel_file': 'p.rgb', 'width': 144, 'height': 144,
                  'decoded_pixel_sha256': sha256(b'RGB8|144|144|' + payload).hexdigest()}


@pytest.fixture(scope='module')
def model_scenario(tmp_path_factory, docker_ready, template_bundle):
    """Drive the REAL ModelContainerRunner on the pinned model image with hostile + valid bundles."""
    from fieldwork.real_model_container import ModelContainerRunner, ModelContainerUnavailable
    import tempfile
    # Short path on purpose: the runner's ledger temp names are ~140 chars and Windows MAX_PATH is 260.
    base = Path(tempfile.mkdtemp(prefix='fwm'))
    os.environ['FW_CANARY_SECRET'] = 'canary-secret-value-123'
    os.environ['FIELDWORK_DSN'] = 'postgresql://canary:canary@127.0.0.1/canary'
    os.environ['PGPASSWORD'] = 'canary-pg-password'
    runner = ModelContainerRunner(MODEL_IMAGE_ID, private_dir=base / 'private')
    pixels, entry = _valid_pixel_entry(base)
    evidence = {'errors': {}}
    marker_in_container = '/tmp/fw-hostile-marker'
    # --- hostile pickle model.safetensors, correctly sealed so only the parser can stop it
    hostile_dir = base / 'hostile'
    from tests.hostile_fixtures import pickle_payload as pp
    payload = pp(marker_in_container)
    shutil_bundle, digest = _bundle_with_model(template_bundle, base, payload)
    process = runner.start_inference(shutil_bundle, pixels, entry, digest, model_image_id=MODEL_IMAGE_ID, timeout=240)
    evidence['hostile_process'] = process
    try:
        _wait_cid(runner, process)
        evidence['cid'] = process.cid
        evidence['nonce'] = process.receipt['nonce']
        deadline = time.monotonic() + 150
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(.5)
        evidence['returncode'] = process.poll()
        evidence['receipt'] = process.read_receipt()
        evidence['inspect'] = _inspect(process.cid)
        marker_probe = _docker('exec', process.cid, '/usr/local/bin/python', '-I', '-B', '-c',
                               f'import os;print(os.path.exists({marker_in_container!r}))')
        evidence['marker_exists_in_container'] = marker_probe.stdout.strip()
        # --- network target and probes inside this hardened container
        listener = socket.socket(); listener.bind(('0.0.0.0', 0)); listener.listen(5)
        port = listener.getsockname()[1]
        evidence['probe'] = _exec_probe(process.cid, 'host.docker.internal', str(port))
        evidence['listener_accepts'] = []
        listener.settimeout(0.2)
        try:
            while True:
                evidence['listener_accepts'].append(listener.accept()[1])
        except OSError:
            pass
        evidence['host_listener'] = (listener, port)
        # --- independent OS network-denial control: container-to-container on the default bridge
        server = _docker('run', '-d', '--rm', '--pull=never', '--entrypoint', '/usr/local/bin/python', MODEL_IMAGE_ID,
                         '-I', '-B', '-c',
                         "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
                         "s.bind(('0.0.0.0',9999));s.listen(8);s.settimeout(25)\n"
                         "t=time.time()\n"
                         "while time.time()-t<25:\n"
                         "    try: c,_=s.accept(); c.close()\n"
                         "    except OSError: pass\n")
        assert server.returncode == 0, server.stderr
        server_id = server.stdout.strip()
        try:
            time.sleep(2.5)
            ip = _docker('inspect', '--format', '{{(index .NetworkSettings.Networks "bridge").IPAddress}}', server_id).stdout.strip()
            assert re.fullmatch(r'\d+\.\d+\.\d+\.\d+', ip), ip
            evidence['server_ip'] = ip
            evidence['hardened_to_server'] = _exec_probe(process.cid, ip, '9999')['connect']
            control = _docker('run', '--rm', '--pull=never', '--entrypoint', '/usr/local/bin/python', MODEL_IMAGE_ID,
                              '-I', '-B', '-c', PROBE, ip, '9999', timeout=60)
            evidence['control_returncode'] = control.returncode
            evidence['control_connect'] = json.loads(control.stdout)['connect'] if control.returncode == 0 else control.stderr[-500:]
            control_ifaces = json.loads(control.stdout)['ifaces'] if control.returncode == 0 else None
            evidence['control_ifaces'] = control_ifaces
        finally:
            _docker('kill', server_id)
    finally:
        try:
            process.cleanup()
        except Exception as exc:
            evidence['errors']['cleanup'] = repr(exc)
    evidence['absent_after_cleanup'] = _absent_by_nonce('fieldwork.real-model.child', evidence.get('nonce', 'x'))
    # --- valid bundle through the same real runner: positive control for the container verifier
    good_dir = base / 'valid'
    good, good_digest = _bundle_with_model(template_bundle, good_dir, None)
    valid = runner.start_inference(good, pixels, entry, good_digest, model_image_id=MODEL_IMAGE_ID, timeout=240)
    try:
        deadline = time.monotonic() + 150
        while valid.poll() is None and time.monotonic() < deadline:
            time.sleep(.5)
        evidence['valid_returncode'] = valid.poll()
        evidence['valid_receipt'] = valid.read_receipt()
    finally:
        try:
            valid.cleanup()
        except Exception as exc:
            evidence['errors']['valid_cleanup'] = repr(exc)
    # --- real wall-time kill: fresh container, 2 s budget, poll() must kill it and prove the limit
    wall = runner.start_inference(good, pixels, entry, good_digest, model_image_id=MODEL_IMAGE_ID, timeout=2)
    evidence['wall_nonce'] = wall.receipt['nonce']
    time.sleep(2.6)
    try:
        wall.poll()
        evidence['wall'] = 'NO_EXCEPTION'
    except ModelContainerUnavailable as exc:
        evidence['wall'] = exc.code
    except BaseException as exc:
        evidence['wall'] = 'UNEXPECTED:' + type(exc).__name__
    try:
        wall.cleanup()
    except Exception as exc:
        evidence['errors']['wall_cleanup'] = repr(exc)
    evidence['wall_absent'] = _absent_by_nonce('fieldwork.real-model.child', evidence['wall_nonce'])
    evidence['listener_close'] = evidence['host_listener'][0].close()
    os.environ.pop('FW_CANARY_SECRET', None); os.environ.pop('FIELDWORK_DSN', None); os.environ.pop('PGPASSWORD', None)
    shutil.rmtree(base, ignore_errors=True)
    return evidence


SECRET_KEY = re.compile(r'(PASS|SECRET|TOKEN|CRED|DSN|DATABASE|PGHOST|PGUSER|PGPASSWORD|API_?KEY|AWS|AZURE|FIELDWORK|FW_CANARY)', re.I)


def test_container_real_runner_hostile_bundle_refused_inside_pinned_image(model_scenario):
    ev = model_scenario
    assert ev['errors'] == {}, ev['errors']
    assert ev['returncode'] == 1
    assert json.loads(ev['receipt'].decode('ascii')) == {'error': 'ValueError'}
    assert ev['marker_exists_in_container'] == 'False'


def test_container_valid_bundle_control_is_accepted_by_same_runner(model_scenario):
    ev = model_scenario
    assert ev['valid_returncode'] == 0
    receipt = json.loads(ev['valid_receipt'].decode('ascii'))
    assert receipt['schema'] == 'fieldwork.real-inference-receipt/v1' and len(receipt['logits']) == 5


def test_container_runtime_flags_of_real_model_container(model_scenario):
    host = model_scenario['inspect']['HostConfig']
    cfg = model_scenario['inspect']['Config']
    assert host['NetworkMode'] == 'none'
    assert host['Privileged'] is False and host['ReadonlyRootfs'] is True
    assert host['CapDrop'] == ['ALL'] and not host['CapAdd']
    assert any(o.startswith('no-new-privileges') for o in host['SecurityOpt'])
    assert cfg['User'] == '65532:65532'
    assert host['Memory'] == host['MemorySwap'] == 2 * 1024 ** 3
    assert host['NanoCpus'] == 2_000_000_000
    assert host['PidsLimit'] == 64
    ulimits = {u['Name']: (u['Soft'], u['Hard']) for u in host['Ulimits']}
    assert ulimits == {'core': (0, 0), 'nofile': (128, 128), 'fsize': (2147483648, 2147483648)}
    assert host['ShmSize'] == 64 * 1024 * 1024
    assert host['Tmpfs']['/tmp'].startswith('rw,noexec,nosuid,nodev,size=64m')
    mounts = model_scenario['inspect']['Mounts']
    assert not host['Binds']                                           # no host bind mounts, ever
    assert [(m['Type'], m['Destination'], m['RW']) for m in mounts] == [('volume', '/workspace', False)]
    assert not any(m['Type'] == 'bind' for m in mounts)                # only the read-only staged named volume
    assert not host['PortBindings'] and not host['Devices'] and not host['Links']
    assert host['PidMode'] == '' and host['UsernsMode'] == ''


def test_container_no_secrets_in_environment_or_filesystem(model_scenario):
    probe = model_scenario['probe']
    env = probe['env']
    assert 'canary-secret-value-123' not in json.dumps(env) and 'canary-pg-password' not in json.dumps(env)
    assert [k for k in env if SECRET_KEY.search(k)] == []
    cfg_env = {e.split('=', 1)[0] for e in model_scenario['inspect']['Config']['Env']}
    assert [k for k in cfg_env if SECRET_KEY.search(k)] == []
    assert probe['host_visible'] == []
    bad_sources = [s for s in probe['mount_sources'] if re.search(r'(9p|drvfs|virtiofs|fuse|grpcfuse|/run/desktop|/mnt/)', s)]
    assert bad_sources == []
    for p in ('/app/_w', '/etc/_w', '/usr/_w', '/workspace/_w', '/_w'):
        assert probe['write:' + p].startswith('FAILED:'), p      # read-only rootfs
    assert probe['uid'] == 65532 and probe['gid'] == 65532
    assert int(probe['CapEff'], 16) == 0 and int(probe['CapBnd'], 16) == 0 and probe['NoNewPrivs'] == '1'


def test_container_network_denied_and_independent_control_proves_probe_valid(model_scenario):
    ev = model_scenario
    probe = ev['probe']
    # hardened container: only loopback, no routes, every outbound attempt fails
    assert probe['ifaces'] == ['lo'] and probe['routes'] == []
    assert probe['connect'].startswith('FAILED:') and probe['dns_example.com'].startswith('FAILED:')
    assert probe['udp'].startswith('FAILED:')
    assert ev['listener_accepts'] == []          # the host listener never saw a packet from the container
    assert ev['hardened_to_server'].startswith('FAILED:')
    # INDEPENDENT CONTROL: same image, same probe, default bridge network, same server: connects.
    assert ev['control_returncode'] == 0
    assert ev['control_connect'] == 'CONNECTED'
    assert ev['control_ifaces'] and 'eth0' in ev['control_ifaces']


def test_container_process_tree_tmpfs_and_resource_limits_enforced(model_scenario):
    probe = model_scenario['probe']
    assert probe['cg:pids.max'] == '64'
    assert probe['forked'] <= 63 and probe.get('fork_error') in (11, 35, 12)   # EAGAIN at the pids limit
    assert probe['cg:memory.max'] == str(2 * 1024 ** 3) and probe['cg:memory.swap.max'] == '0'
    assert probe['cg:cpu.max'].split()[0] == '200000'
    assert probe['nofile'] == [128, 128] and probe['fsize'] == [2147483648, 2147483648] and probe['core'] == [0, 0]
    assert probe['tmp_fill'].startswith('FAILED:28')                          # ENOSPC on the 64 MiB tmpfs


def test_container_wall_time_limit_kills_real_model_container_and_proves_absence(model_scenario):
    ev = model_scenario
    assert ev['wall'] == 'MODEL_CONTAINER_WALL_TIMEOUT', ev['wall']
    assert ev['wall_absent'] is True and ev['absent_after_cleanup'] is True
    from fieldwork.real_model_container import MAX_WALL_SECONDS
    assert MAX_WALL_SECONDS == 4 * 60 * 60


# --- decoder / pixel containers --------------------------------------------------------------
def _hang_writer(seconds):
    def fake(stream, data):
        time.sleep(seconds)
        raise BrokenPipeError('test hold: stdin never closed in time')
    return fake


def _find_nonce(private_dir, deadline_s=20):
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        found = list(Path(private_dir).glob('.decoder-sessions/*/.decoder-*.cleanup.json'))
        for p in found:
            try:
                nonce = json.loads(p.read_text())['nonce']
            except (OSError, ValueError):
                continue
            ids = _docker('ps', '--quiet', '--no-trunc', '--filter',
                          f'label=fieldwork.real-intake.decoder.nonce={nonce}').stdout.split()
            if ids:
                return nonce, ids[0]
        time.sleep(.1)
    raise AssertionError('decoder container never appeared')


def test_intake_decoder_container_flags_probe_and_timeout_kill(tmp_path, monkeypatch, docker_ready):
    from fieldwork import container_decoder as cd
    assert cd.DECODE_TIMEOUT == 12 and cd.CONTAINER_START_TIMEOUT == 8      # production limits, not patched
    monkeypatch.setattr(cd, '_write_all', _hang_writer(13.5))
    sample = tmp_path / 'x.png'
    sample.write_bytes(b'irrelevant')
    decoder = cd.ContainerDecoder(DECODER_IMAGE_ID, private_dir=tmp_path)
    outcome = {}
    def run():
        try:
            decoder.decode(sample)
        except cd.DecoderUnavailable as exc:
            outcome['code'] = exc.code
    t = threading.Thread(target=run); t.start()
    nonce, cid = _find_nonce(tmp_path)
    info = _inspect(cid)
    host, cfg = info['HostConfig'], info['Config']
    assert host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and host['CapDrop'] == ['ALL']
    assert host['Memory'] == host['MemorySwap'] == 512 * 1024 ** 2 and host['NanoCpus'] == 1_000_000_000
    assert host['PidsLimit'] == 16 and cfg['User'] == '65532:65532' and not host['Binds'] and info['Mounts'] == []
    assert cfg['Env'] is not None and [e for e in cfg['Env'] if SECRET_KEY.search(e.split('=')[0])] == []
    probe = _exec_probe(cid, 'host.docker.internal', '9')
    assert probe['connect'].startswith('FAILED:') and probe['ifaces'] == ['lo'] and probe['udp'].startswith('FAILED:')
    assert int(probe['CapEff'], 16) == 0 and probe['forked'] <= 15 and probe['cg:memory.max'] == str(512 * 1024 ** 2)
    assert probe['tmp_fill'].startswith('FAILED:28') and probe['write:/app/_w'].startswith('FAILED:')
    t.join(timeout=60)
    assert outcome == {'code': 'DECODER_TIMEOUT'}
    assert _absent_by_nonce(cd.CONTAINER_LABEL, nonce)


def test_intake_decoder_oom_kill_is_enforced_by_cgroup(docker_ready):
    """Memory is a hard kill (exit 137), exercised with the real container_args of the intake decoder."""
    from fieldwork.container_decoder import container_args
    nonce = uuid.uuid4().hex
    args = container_args(DECODER_IMAGE_ID, str(Path(os.environ.get('TEMP', '.')) / ('fw-oom-' + nonce + '.cid')), nonce)
    i = args.index(DECODER_IMAGE_ID)
    args = args[:i] + [DECODER_IMAGE_ID, '-I', '-B', '-c',
        "import sys\nb=[]\nfor _ in range(40):\n b.append(b'x'*(64<<20))\nprint('SURVIVED')"]
    cid = args[args.index('--cidfile') + 1]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                                env={k: v for k, v in os.environ.items() if k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE')})
    finally:
        Path(cid).unlink(missing_ok=True)
    assert result.returncode == 137 and 'SURVIVED' not in result.stdout


def test_pixel_decoder_container_flags_probe_and_timeout_kill(tmp_path, monkeypatch, docker_ready):
    from fieldwork import real_pixel_decoder as rpd
    from fieldwork.container_decoder import DecoderUnavailable, CONTAINER_LABEL
    monkeypatch.setattr(rpd, '_write_all', _hang_writer(16.5))   # production wall limit is the literal 15 s
    decoder = rpd.ContainerRealPixelDecoder(PIXEL_IMAGE_ID, private_dir=tmp_path)
    outcome = {}
    def run():
        try:
            decoder.decode_bytes(b'irrelevant')
        except DecoderUnavailable as exc:
            outcome['code'] = exc.code
    t = threading.Thread(target=run); t.start()
    nonce, cid = _find_nonce(tmp_path)
    info = _inspect(cid)
    host = info['HostConfig']
    assert host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and host['CapDrop'] == ['ALL']
    assert host['Memory'] == host['MemorySwap'] == 512 * 1024 ** 2 and host['PidsLimit'] == 16
    assert info['Config']['User'] == '65532:65532' and not host['Binds'] and info['Mounts'] == []
    probe = _exec_probe(cid, 'host.docker.internal', '9')
    assert probe['connect'].startswith('FAILED:') and probe['ifaces'] == ['lo'] and probe['udp'].startswith('FAILED:')
    assert [k for k in probe['env'] if SECRET_KEY.search(k)] == []
    assert int(probe['CapEff'], 16) == 0 and probe['forked'] <= 15
    t.join(timeout=90)
    assert outcome == {'code': 'REAL_PIXEL_TIMEOUT'}
    assert _absent_by_nonce(CONTAINER_LABEL, nonce)


def test_shipped_model_image_contains_no_unsafe_loader_calls(docker_ready):
    """AST-scan the product code actually shipped inside the pinned model image (hardened flags)."""
    program = r'''
import ast, json, pathlib
bad = []
names = {'torch.load','torch.jit.load','jit.load','pickle.load','pickle.loads','pickle.Unpickler','marshal.load','marshal.loads','dill.load','dill.loads','joblib.load','shelve.open','importlib.import_module','eval','exec','compile'}
def dotted(n):
    p = []
    while isinstance(n, ast.Attribute): p.append(n.attr); n = n.value
    return '.'.join(reversed(p + [n.id])) if isinstance(n, ast.Name) else None
count = 0
for f in sorted(pathlib.Path('/app/fieldwork').glob('*.py')):
    count += 1
    for node in ast.walk(ast.parse(f.read_text())):
        if isinstance(node, ast.Call):
            d = dotted(node.func)
            if d in names: bad.append([f.name, node.lineno, d])
            if d == '__import__' and not (node.args and isinstance(node.args[0], ast.Constant)): bad.append([f.name, node.lineno, '__import__'])
            for kw in node.keywords:
                if kw.arg == 'weights_only' and not (isinstance(kw.value, ast.Constant) and kw.value.value is True): bad.append([f.name, node.lineno, 'weights_only'])
print(json.dumps({'files': count, 'bad': bad}))
'''
    out = _docker('run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL',
                  '--user=65532:65532', '--entrypoint', '/usr/local/bin/python', MODEL_IMAGE_ID, '-I', '-B', '-c', program, timeout=60)
    assert out.returncode == 0, out.stderr[-1000:]
    result = json.loads(out.stdout)
    assert result['files'] >= 10 and result['bad'] == [], result
