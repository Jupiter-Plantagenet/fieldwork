"""Authored-image parity tests for the decoder's frozen DCT64 hash algorithm."""
from io import BytesIO
import hashlib
import zipfile
from contextlib import contextmanager
from uuid import uuid4

from PIL import Image, ImageDraw

from fieldwork.container_decoder import PHASH_ALGORITHM, decode_bytes
from fieldwork.splits import PHASH, phash
from fieldwork.intake import run_intake


def test_bounded_decoder_hash_matches_existing_split_phash(tmp_path):
    image = Image.new('RGB', (97, 83), '#e8ede3')
    draw = ImageDraw.Draw(image)
    draw.ellipse((13, 9, 74, 71), fill='#5a8c63')
    draw.rectangle((36, 22, 83, 61), fill='#c3a643')
    payload = BytesIO()
    image.save(payload, format='PNG')
    raw = payload.getvalue()

    result = decode_bytes(raw)
    image_path = tmp_path / 'authored-fixture.png'
    image_path.write_bytes(raw)

    assert result['ok'] is True
    assert result['phash_algorithm'] == PHASH_ALGORITHM == 'phash-dct64/v1'
    assert result['phash_hex'] == f'{phash(image_path):016x}'
    assert PHASH.startswith('phash-dct64/v1')


def test_same_member_raw_reintake_repairs_only_missing_feature_for_canonical_sample(tmp_path):
    member = 'flowers/daisy/same.png'
    raw = b'authored-nonsensitive-image-fixture'
    raw_sha = hashlib.sha256(raw).hexdigest()
    pixel_sha = 'a' * 64
    sample_id = str(uuid4())
    dataset = 'authored-rights-dataset'
    calls = []

    class Cursor:
        result = None

        def execute(self, sql, params=None):
            if 'FROM fw_samples WHERE workspace=%s AND raw_sha256=%s FOR UPDATE' in sql:
                self.result = {'sample_id': sample_id, 'raw_bytes': len(raw), 'pixel_sha256': pixel_sha,
                               'source_member': member, 'rights_dataset_id': dataset}
            elif 'FROM public.fw_sample_perceptual_features' in sql:
                self.result = None
            elif 'repair_sample_phash' in sql:
                calls.append((sql, params))
                self.result = None
            else:
                self.result = None
            return self

        def fetchone(self):
            return self.result

    class Store:
        @contextmanager
        def connect(self):
            yield Cursor()

    class BoundedDecoder:
        version = 'fieldwork.decode/v2 pillow-13.0.0 numpy-2.5.4 exif-transpose rgb8 alpha-on-white phash-dct64/v1'
        restarts = 0
        peak_rss = 0

        def __init__(self):
            self.paths = []

        def decode(self, path):
            self.paths.append(path)
            return {'ok': True, 'pixel_sha256': pixel_sha, 'phash_algorithm': 'phash-dct64/v1',
                    'phash_hex': '0123456789abcdef', 'width': 10, 'height': 10, 'format': 'PNG'}

        def close(self):
            pass

    decoder = BoundedDecoder()
    archive = tmp_path / 'retry.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr(member, raw)
    rights_calls = []

    report = run_intake(Store(), 'workspace-fixture', 'operator-fixture', archive,
        quarantine_root=tmp_path / 'quarantine', media_root=tmp_path / 'media',
        rights_dataset_id=dataset,
        rights_check=lambda name, sha, size: rights_calls.append((name, sha, size)),
        decoder_factory=lambda: decoder, repair_missing_features=True)

    assert report['noop'] == 1 and report['accepted'] == 0
    assert report['members'][0]['reason'] == 'RAW_DIGEST_FEATURE_BACKFILLED'
    assert report['members'][0]['linked_sample_id'] == sample_id
    assert rights_calls == [(member, raw_sha, len(raw))]
    assert len(decoder.paths) == 1
    assert len(calls) == 1
    assert calls[0][1] == ( 'workspace-fixture', sample_id, raw_sha, len(raw), pixel_sha,
        '0123456789abcdef', decoder.version, member, dataset)
