"""Shared REAL hostile-artifact builders for the ML-T-SAFE / ML-T-INTAKE matrices.

Nothing here is a mock: every builder writes real bytes that real code parses.
The pickle payloads are genuine (their __reduce__ writes a marker file when
unpickled) and are proven live by a positive control that runs them in a
separate throwaway interpreter.
"""
from __future__ import annotations

import io
import json
import os
import pickle
import random
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import torch

from fieldwork.data import canonical, digest
from fieldwork.ml import checkpoint, model
from fieldwork.metrics import evaluate
from fieldwork.real_bundle import FILES
from fieldwork.real_run_profile import PREPROCESS_DESCRIPTOR, PREPROCESS_DIGEST, RECIPE_DIGEST

MODEL_IMAGE_ID = 'sha256:41c680046133d0920a217adbfb951b8c77e4cec7e3ea7763646b19c5f4e7dfdc'
DECODER_IMAGE_ID = 'sha256:f1c22ce0d7121dbc4f53d072abb1ade888872ad8b669f035c581fd29dfb4d9a9'
PIXEL_IMAGE_ID = 'sha256:b42e39dfea7adbace1be7766fc071e94ff3424ac175485c633986ac8ae883dcd'


# ----------------------------------------------------------------------------- payloads
class _Evil:
    """Unpickling this executes code that creates ``self.marker``."""

    def __init__(self, marker):
        self.marker = str(marker)

    def __reduce__(self):
        return (exec, (f"open({self.marker!r}, 'w').write('payload-executed')",))


def pickle_payload(marker) -> bytes:
    return pickle.dumps(_Evil(marker), protocol=2)


def torch_pt_payload(marker, path):
    """A real torch.save() archive (zip + data.pkl) whose pickle runs code on load."""
    torch.save(_Evil(marker), str(path))
    return Path(path).read_bytes()


def torchscript_payload(path):
    """A real TorchScript archive (code + constants) produced by torch.jit."""
    class Tiny(torch.nn.Module):
        def forward(self, x):
            return x * 2
    torch.jit.script(Tiny()).save(str(path))
    return Path(path).read_bytes()


def run_unsafely_in_throwaway_interpreter(payload: bytes, tmp: Path) -> None:
    """POSITIVE CONTROL: prove the payload really executes code when naively loaded."""
    target = tmp / 'control.pkl'
    target.write_bytes(payload)
    subprocess.run([sys.executable, '-I', '-B', '-c',
                    'import pickle,sys;pickle.loads(open(sys.argv[1],"rb").read())', str(target)],
                   check=False, timeout=30, capture_output=True)


def zip_bomb_bytes(members=40, member_bytes=25 * 1024 * 1024) -> bytes:
    """Hand-built ZIP: `members` entries sharing one deflated stream of zeros.

    Declares members*member_bytes of expansion at ~1000:1 ratio while the archive
    itself stays a couple of MiB. Compressed once, so building is cheap.
    """
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    chunk = b'\0' * (1 << 20)
    stream = bytearray()
    crc = 0
    for _ in range(member_bytes >> 20):
        stream += comp.compress(chunk)
        crc = zlib.crc32(chunk, crc)
    stream += comp.flush()
    return _raw_zip([(f'bomb/{i:03d}.png', bytes(stream), member_bytes, crc) for i in range(members)])


def _raw_zip(entries) -> bytes:
    """entries: (name, deflated_stream, declared_uncompressed_size, crc32)."""
    out = bytearray()
    central = bytearray()
    for name, stream, usize, crc in entries:
        raw_name = name.encode()
        offset = len(out)
        out += struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, 8, 0, 0x21, crc, len(stream), usize,
                           len(raw_name), 0) + raw_name + stream
        central += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, 8, 0, 0x21, crc,
                               len(stream), usize, len(raw_name), 0, 0, 0, 0, 0, offset) + raw_name
    end = struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, len(entries), len(entries), len(central), len(out), 0)
    return bytes(out) + bytes(central) + end


def lying_zip_bytes(real_bytes=25 * 1024 * 1024, declared=64) -> bytes:
    """ZIP whose header declares `declared` bytes but whose stream inflates to `real_bytes`."""
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    chunk = b'\0' * (1 << 20)
    stream = bytearray()
    crc = 0
    for _ in range(real_bytes >> 20):
        stream += comp.compress(chunk)
        crc = zlib.crc32(chunk, crc)
    stream += comp.flush()
    return _raw_zip([('lying/a.png', bytes(stream), declared, crc)])


# ----------------------------------------------------------------------------- safetensors
def safetensors_bytes(header: dict, payload: bytes = b'', *, length_override=None) -> bytes:
    raw = json.dumps(header, separators=(',', ':')).encode()
    return struct.pack('<Q', len(raw) if length_override is None else length_override) + raw + payload


def valid_model_tensors():
    return {k: v.detach().clone().contiguous() for k, v in model().state_dict().items()}


# ----------------------------------------------------------------------------- checkpoint
def make_checkpoint(root: Path):
    """A REAL committed checkpoint: one optimizer step on a tiny batch (milliseconds)."""
    torch.set_num_threads(1)
    net = model()
    opt = torch.optim.AdamW(net.parameters(), lr=0.001, weight_decay=0.0001)
    generator = torch.Generator().manual_seed(1)
    random.seed(1)
    x = torch.rand(2, 3, 16, 16)
    loss = torch.nn.functional.cross_entropy(net(x), torch.tensor([0, 1]))
    opt.zero_grad(); loss.backward(); opt.step()
    meta = dict(epoch=1, train_loss=1.0, validation_loss=1.0, updates=1, next_epoch=2,
                dataset_digest='a' * 64, seed=1, best={'epoch': 1, 'loss': 1.0}, initial_digest='b' * 64)
    path = Path(root) / 'epoch-1'
    manifest_digest = checkpoint(path, net, opt, generator, meta)
    return path, manifest_digest


def reseal_checkpoint(path: Path) -> str:
    """Recompute the inventory so a hostile payload reaches the parser, not the digest gate."""
    path = Path(path)
    files = {f: {'sha256': digest((path / f).read_bytes()), 'bytes': (path / f).stat().st_size}
             for f in ('state.json', 'state.safetensors')}
    (path / 'manifest.json').write_bytes(canonical({'schema': 1, 'files': files}))
    return digest((path / 'manifest.json').read_bytes())


# ----------------------------------------------------------------------------- real bundle
def make_bundle(root: Path, *, model_bytes=None):
    """A structurally valid real-candidate bundle (random weights; no training)."""
    root = Path(root)
    (root / 'evaluation').mkdir(parents=True)
    (root / 'rights').mkdir()
    from safetensors.torch import save_file
    save_file(valid_model_tensors(), str(root / 'model.safetensors'))
    if model_bytes is not None:
        (root / 'model.safetensors').write_bytes(model_bytes)
    rnd = random.Random(7)
    population = [{'id': f's{i}', 'label': i % 5, 'sha256': f'{i:064x}'} for i in range(10)]
    model_digest = digest((root / 'model.safetensors').read_bytes())
    predictions = [dict(id=p['id'], label=p['label'], sha256=p['sha256'], model=model_digest,
                        status='ok', logits=[rnd.uniform(-2, 2) for _ in range(5)]) for p in population]
    metrics = evaluate(population, predictions, 5, model_digest)
    from tools.verify_metrics import verify as independent
    report = independent(population, predictions, 5, model_digest)
    payloads = {
        'architecture.json': {'schema': 1, 'id': 'compact-cnn/real-v1'},
        'preprocess.json': PREPROCESS_DESCRIPTOR,
        'classes.json': ['Daisy', 'Dandelion', 'Rose', 'Sunflower', 'Tulip'],
        'lineage.json': {'scope': 'real-training/v1', 'version_id': 'v-hostile', 'dataset_digest': 'c' * 64,
                         'checkpoint_digest': 'd' * 64, 'epoch': 1, 'model_digest': model_digest,
                         'recipe_digest': RECIPE_DIGEST, 'preprocess_digest': PREPROCESS_DIGEST,
                         'decoder_image_id': DECODER_IMAGE_ID, 'model_image_id': MODEL_IMAGE_ID},
        'rights/review.json': {'scope': 'real-rights-cleared', 'purpose': 'model_bundle',
                               'decision_digests_sha256': digest(canonical(['e' * 64])),
                               'public_export_authorized': False},
        'evaluation/population.json': population,
        'evaluation/metrics.json': metrics,
        'evaluation/independent-report.json': report,
    }
    for name, value in payloads.items():
        (root / name).write_bytes(canonical(value))
    (root / 'evaluation/predictions.jsonl').write_bytes(
        b''.join(canonical(r) + b'\n' for r in predictions))
    return root, reseal_bundle(root)


def reseal_bundle(root: Path, *, model_bytes=None, extra_manifest_files=()) -> str:
    """Recompute inventory + manifest (and lineage model digest) after a deliberate edit."""
    root = Path(root)
    if model_bytes is not None:
        (root / 'model.safetensors').write_bytes(model_bytes)
    lineage = json.loads((root / 'lineage.json').read_bytes())
    lineage['model_digest'] = digest((root / 'model.safetensors').read_bytes())
    (root / 'lineage.json').write_bytes(canonical(lineage))
    names = sorted(FILES | set(extra_manifest_files))
    inventory = {n: {'sha256': digest((root / n).read_bytes()), 'bytes': (root / n).stat().st_size}
                 for n in names}
    manifest = {'schema': 1, 'purpose': 'private_real_candidate', 'scope': 'real-training/v1',
                'evidence_scope': 'validation_only', 'files': inventory}
    (root / 'manifest.json').write_bytes(canonical(manifest))
    return digest(canonical(manifest))


# ----------------------------------------------------------------------------- tar / images
def tar_bytes(members) -> bytes:
    """members: (name, bytes|None, kind) with kind in {'file','sym','hard','dir','fifo'}."""
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:') as tf:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == 'sym':
                info.type = tarfile.SYMTYPE; info.linkname = data; tf.addfile(info)
            elif kind == 'hard':
                info.type = tarfile.LNKTYPE; info.linkname = data; tf.addfile(info)
            elif kind == 'dir':
                info.type = tarfile.DIRTYPE; tf.addfile(info)
            elif kind == 'fifo':
                info.type = tarfile.FIFOTYPE; tf.addfile(info)
            else:
                info.size = len(data); tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def png_bytes(color=(10, 120, 40), size=(24, 20), pattern=False) -> bytes:
    from PIL import Image
    image = Image.new('RGB', size, color)
    if pattern:
        for x in range(size[0]):
            for y in range(size[1]):
                image.putpixel((x, y), ((x * 9) % 256, (y * 13) % 256, (x * y) % 256))
    out = io.BytesIO()
    image.save(out, format='PNG')
    return out.getvalue()


def png_decompression_bomb() -> bytes:
    """Tiny, valid PNG whose IHDR declares 30000x30000 (900 MP); IDAT is a few hundred bytes."""
    def chunk(kind, data):
        body = kind + data
        return struct.pack('>I', len(data)) + body + struct.pack('>I', zlib.crc32(body) & 0xffffffff)
    width = height = 30000
    row = b'\0' + b'\0' * width
    comp = zlib.compressobj(9)
    idat = b''.join(comp.compress(row) for _ in range(64)) + comp.flush()
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 0, 0, 0, 0))
            + chunk(b'IDAT', idat) + chunk(b'IEND', b''))


# ----------------------------------------------------------------------------- intake image fixtures
def _pattern_image(seed=0, size=(40, 32)):
    from PIL import Image
    image = Image.new('RGB', size)
    for x in range(size[0]):
        for y in range(size[1]):
            image.putpixel((x, y), ((x * 7 + seed * 53) % 256, (y * 11 + seed * 29) % 256, (x * y + seed * 17) % 256))
    return image


def pattern_png(seed=0, size=(40, 32), **save):
    out = io.BytesIO()
    _pattern_image(seed, size).save(out, format='PNG', **save)
    return out.getvalue()


def pattern_png_reencoded(seed=0, size=(40, 32)):
    """Pixel-identical to pattern_png(seed) but different bytes (optimised + text chunk)."""
    from PIL.PngImagePlugin import PngInfo
    info = PngInfo(); info.add_text('Comment', 're-encoded copy')
    return pattern_png(seed, size, optimize=True, pnginfo=info)


def pattern_webp_lossless(seed=0, size=(40, 32)):
    out = io.BytesIO()
    _pattern_image(seed, size).save(out, format='WEBP', lossless=True)
    return out.getvalue()


def pattern_png_rgba_opaque(seed=0, size=(40, 32)):
    out = io.BytesIO()
    _pattern_image(seed, size).convert('RGBA').save(out, format='PNG')
    return out.getvalue()


def pattern_jpeg(seed=0, size=(40, 32), quality=95):
    out = io.BytesIO()
    _pattern_image(seed, size).save(out, format='JPEG', quality=quality)
    return out.getvalue()


def smooth_png(size=(64, 48)):
    from PIL import Image
    image = Image.new('RGB', size)
    for x in range(size[0]):
        for y in range(size[1]):
            image.putpixel((x, y), (x * 255 // size[0], y * 255 // size[1], 128))
    out = io.BytesIO(); image.save(out, format='PNG')
    return out.getvalue()


def jpeg_resave_of(png_bytes, quality=90):
    from PIL import Image
    out = io.BytesIO()
    Image.open(io.BytesIO(png_bytes)).convert('RGB').save(out, format='JPEG', quality=quality)
    return out.getvalue()


def gif_bytes():
    from PIL import Image
    out = io.BytesIO()
    Image.new('P', (8, 8), 3).save(out, format='GIF')
    return out.getvalue()


def apng_bytes():
    from PIL import Image
    frames = [Image.new('RGB', (16, 16), c) for c in ((255, 0, 0), (0, 255, 0))]
    out = io.BytesIO()
    frames[0].save(out, format='PNG', save_all=True, append_images=frames[1:], duration=100, loop=0)
    return out.getvalue()


def zip_bytes(members):
    """members: (name, bytes|None, kind) kind in file/dir/sym. Names are stored verbatim."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, data, kind in members:
            if kind == 'sym':
                info = zipfile.ZipInfo(name); info.external_attr = 0o120777 << 16
                zf.writestr(info, data)
            elif kind == 'dir':
                zf.writestr(zipfile.ZipInfo(name if name.endswith('/') else name + '/'), b'')
            else:
                zf.writestr(zipfile.ZipInfo(name), data, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def tar_gz_bomb(path, members=54, member_bytes=19 * 1024 * 1024):
    """Streaming .tar.gz of `members` zero-filled files (declared total > 1 GiB, ~1000:1 ratio)."""
    import tarfile
    comp = zlib.compressobj(1, zlib.DEFLATED, 31)
    chunk = b'\0' * (1 << 20)
    with open(path, 'wb') as out:
        for i in range(members):
            info = tarfile.TarInfo(f'bomb/{i:03d}.png'); info.size = member_bytes
            out.write(comp.compress(info.tobuf(tarfile.GNU_FORMAT)))
            for _ in range(member_bytes >> 20):
                out.write(comp.compress(chunk))
            pad = (-member_bytes) % 512
            if pad:
                out.write(comp.compress(b'\0' * pad))
        out.write(comp.compress(b'\0' * 1024))
        out.write(comp.flush())
