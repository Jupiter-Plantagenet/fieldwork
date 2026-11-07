"""Container entry point: source image bytes in, bounded short-edge RGB8 out."""
from __future__ import annotations

import hashlib
import json
import os
import warnings
from io import BytesIO

MAX_INPUT = 20 * 1024 * 1024
MAX_PIXELS = 20_000_000
MAX_EDGE = 1024
DECODER = 'fieldwork.real-pixels/v2 pillow-13.0.0 canonical-intake-rgb8 short-edge144-bilinear'
FORMATS = {'JPEG', 'PNG', 'WEBP'}


def decode(data: bytes):
    if len(data) > MAX_INPUT:
        return None, {'ok': False, 'reason': 'INPUT_LIMIT', 'decoder': DECODER}
    try:
        from PIL import Image, ImageOps, __version__
        if __version__ != '13.0.0':
            raise ValueError('PILLOW_PIN_MISMATCH')
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        with Image.open(BytesIO(data)) as image:
            if image.format not in FORMATS or image.width * image.height > MAX_PIXELS:
                return None, {'ok': False, 'reason': 'FORMAT_OR_PIXEL_LIMIT', 'decoder': DECODER}
            source_format = image.format
            if getattr(image, 'is_animated', False) or getattr(image, 'n_frames', 1) != 1:
                return None, {'ok': False, 'reason': 'MULTIFRAME', 'decoder': DECODER}
            image.load()
            image = ImageOps.exif_transpose(image)
            if image.mode in ('RGBA', 'LA') or (image.mode == 'P' and 'transparency' in image.info):
                rgba = image.convert('RGBA')
                base = Image.new('RGBA', rgba.size, (255, 255, 255, 255))
                image = Image.alpha_composite(base, rgba)
            canonical = image.convert('RGB')
            canonical_digest = hashlib.sha256(
                b'RGB8|%d|%d|' % canonical.size + canonical.tobytes()).hexdigest()
            width, height = canonical.size
            scale = 144 / min(width, height)
            target = (max(144, round(width * scale)), max(144, round(height * scale)))
            if max(target) > MAX_EDGE:
                return None, {'ok': False, 'reason': 'ASPECT_OUTPUT_LIMIT', 'decoder': DECODER}
            image = canonical.resize(target, Image.Resampling.BILINEAR)
            payload = image.tobytes()
            pixel_digest = hashlib.sha256(b'RGB8|%d|%d|' % target + payload).hexdigest()
            return payload, {'ok': True, 'format': source_format,
                             'width': target[0], 'height': target[1],
                             'pixel_sha256': pixel_digest,
                             'canonical_pixel_sha256': canonical_digest, 'decoder': DECODER}
    except Exception as exc:
        try:
            from PIL import Image
            if isinstance(exc, (Image.DecompressionBombError, Image.DecompressionBombWarning)):
                return None, {'ok': False, 'reason': 'PIXEL_LIMIT', 'decoder': DECODER}
        except Exception:
            pass
        return None, {'ok': False, 'reason': 'DECODE_FAILED', 'decoder': DECODER}


def main():
    data = bytearray()
    while len(data) <= MAX_INPUT:
        block = os.read(0, min(1024 * 1024, MAX_INPUT + 1 - len(data)))
        if not block:
            break
        data.extend(block)
    raw = bytes(data)
    payload, result = decode(raw)
    header = {'schema': 'fieldwork.real-pixels-result/v1',
              'input_sha256': hashlib.sha256(raw).hexdigest(),
              'input_bytes': len(raw), 'result': result,
              'payload_bytes': len(payload) if payload is not None else 0}
    encoded = json.dumps(header, separators=(',', ':')).encode('ascii') + b'\n'
    os.write(1, encoded)
    if payload is not None:
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            offset += os.write(1, view[offset:])


if __name__ == '__main__':
    import sys
    if sys.argv[1:] != ['--container']:
        raise SystemExit(2)
    main()

