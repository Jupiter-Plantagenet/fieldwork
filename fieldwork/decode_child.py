"""Isolated decoder child. Self-contained (no package imports): run as a file with -I -B.

Reads one JSON object per stdin line {"path": ...}; writes one JSON line per item.
Bounds (fieldwork.decode/v1): file <=20MiB, JPEG/PNG/WEBP only, single frame,
<=20 megapixels checked from the header before pixel decode, EXIF orientation
applied, alpha composited on white, RGB8. pixel_sha256 = sha256(b'RGB8|W|H|' + bytes).
"""
import hashlib
import json
import os
import sys
import warnings

os.environ.setdefault('OMP_NUM_THREADS', '1')
from PIL import Image, ImageOps, __version__ as PIL_VERSION  # noqa: E402

MAX_FILE = 20 * 1024 * 1024
MAX_PIXELS = 20_000_000
FORMATS = {'JPEG', 'PNG', 'WEBP'}
DECODER = f'fieldwork.decode/v1 pillow-{PIL_VERSION} exif-transpose rgb8 alpha-on-white'
Image.MAX_IMAGE_PIXELS = MAX_PIXELS
warnings.simplefilter('error', Image.DecompressionBombWarning)


def decode(path):
    size = os.path.getsize(path)
    if size > MAX_FILE:
        return {'ok': False, 'reason': 'FILE_TOO_LARGE', 'bytes': size}
    try:
        with Image.open(path) as im:
            fmt = im.format
            if fmt not in FORMATS:
                return {'ok': False, 'reason': 'UNSUPPORTED_FORMAT:' + str(fmt)}
            if im.width * im.height > MAX_PIXELS:
                return {'ok': False, 'reason': 'PIXEL_LIMIT', 'width': im.width, 'height': im.height}
            if getattr(im, 'is_animated', False) or getattr(im, 'n_frames', 1) != 1:
                return {'ok': False, 'reason': 'MULTIFRAME'}
            im.load()
            im = ImageOps.exif_transpose(im)
            if im.mode in ('RGBA', 'LA') or (im.mode == 'P' and 'transparency' in im.info):
                rgba = im.convert('RGBA')
                base = Image.new('RGBA', rgba.size, (255, 255, 255, 255))
                im = Image.alpha_composite(base, rgba)
            rgb = im.convert('RGB')
            raw = rgb.tobytes()
            h = hashlib.sha256(b'RGB8|%d|%d|' % rgb.size)
            h.update(raw)
            return {'ok': True, 'format': fmt, 'width': rgb.width, 'height': rgb.height, 'pixel_sha256': h.hexdigest()}
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        return {'ok': False, 'reason': 'PIXEL_LIMIT'}
    except Exception as exc:  # any decoder failure is a per-item rejection
        return {'ok': False, 'reason': 'DECODE_FAILED:' + type(exc).__name__}


def main():
    print(json.dumps({'ready': True, 'decoder': DECODER, 'pid': os.getpid()}), flush=True)
    for line in sys.stdin:
        req = json.loads(line)
        out = decode(req['path'])
        out['path'] = req['path']
        print(json.dumps(out), flush=True)


if __name__ == '__main__':
    main()
