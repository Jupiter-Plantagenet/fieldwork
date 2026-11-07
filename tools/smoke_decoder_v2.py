"""Network-off authored-fixture smoke for a locally built decoder v2 image."""
from __future__ import annotations

import hashlib
import io
import json
import re
import uuid
from pathlib import Path

from PIL import Image, ImageDraw

from fieldwork.container_decoder import ContainerDecoder, DECODER_VERSION, PHASH_ALGORITHM
from fieldwork.splits import phash

ROOT = Path(__file__).resolve().parents[1]
IMAGE_ID_PATTERN = re.compile(r'^sha256:[0-9a-f]{64}$')


def smoke(image_id: str) -> dict:
    if not IMAGE_ID_PATTERN.fullmatch(image_id):
        raise ValueError('DECODER_IMAGE_ID_INVALID')
    run_id = uuid.uuid4().hex
    out = ROOT / '.local' / ('decoder-v2-smoke-' + run_id[:12])
    spool = out / 'spool'
    spool.mkdir(parents=True, exist_ok=False)

    image = Image.new('RGB', (97, 83), '#e8ede3')
    draw = ImageDraw.Draw(image)
    draw.ellipse((13, 9, 74, 71), fill='#5a8c63')
    draw.rectangle((36, 22, 83, 61), fill='#c3a643')
    payload = io.BytesIO()
    image.save(payload, format='PNG')
    data = payload.getvalue()
    path = out / 'authored-phash-smoke.png'
    path.write_bytes(data)

    decoder = ContainerDecoder(image_id, private_dir=spool, session_id='smoke-' + run_id[:10])
    try:
        result = decoder.decode(path)
    finally:
        decoder.close()
    expected_hash = f'{phash(path):016x}'
    if (result.get('ok') is not True or result.get('decoder') != DECODER_VERSION
            or result.get('phash_algorithm') != PHASH_ALGORITHM
            or result.get('phash_hex') != expected_hash):
        raise RuntimeError('DECODER_V2_AUTHORED_SMOKE_FAILED')
    report = {
        'schema': 'fieldwork.decoder-v2-smoke/v1', 'status': 'passed',
        'image_id': image_id, 'decoder': result['decoder'],
        'phash_algorithm': result['phash_algorithm'], 'phash_hex': result['phash_hex'],
        'phash_matches_existing_implementation': True, 'container_network': 'none',
        'input_bytes': len(data), 'input_sha256': hashlib.sha256(data).hexdigest(),
        'authored_fixture_only': True,
    }
    (out / 'smoke.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--image-id', required=True)
    args = parser.parse_args()
    report = smoke(args.image_id)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
