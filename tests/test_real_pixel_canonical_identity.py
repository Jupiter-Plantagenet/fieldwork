"""Regression coverage for protected identity versus resized model pixels."""
from __future__ import annotations

from io import BytesIO

from PIL import Image

from fieldwork.container_decoder import decode_bytes as intake_decode_bytes
from fieldwork.container_real_pixels import decode as real_pixel_decode


def _encode(image: Image.Image, fmt: str, **kwargs) -> bytes:
    output = BytesIO()
    image.save(output, format=fmt, **kwargs)
    return output.getvalue()


def _assert_canonical_matches_intake(encoded: bytes):
    resized, fresh = real_pixel_decode(encoded)
    intake = intake_decode_bytes(encoded)
    assert fresh['ok'] and intake['ok']
    assert fresh['canonical_pixel_sha256'] == intake['pixel_sha256']
    assert len(resized) == fresh['width'] * fresh['height'] * 3
    assert fresh['pixel_sha256'] != ''  # This remains the separate resized model identity.
    return fresh


def test_reencoded_same_pixels_keep_protected_canonical_identity():
    image = Image.new('RGB', (7, 5))
    image.putdata([(x * 31, y * 43, (x + y) * 19) for y in range(5) for x in range(7)])
    first = _encode(image, 'PNG', compress_level=1)
    second = _encode(image, 'PNG', compress_level=9)
    assert first != second
    one, two = _assert_canonical_matches_intake(first), _assert_canonical_matches_intake(second)
    assert one['canonical_pixel_sha256'] == two['canonical_pixel_sha256']


def test_alpha_is_composited_white_before_protected_identity_hash():
    image = Image.new('RGBA', (4, 3), (221, 12, 51, 0))
    image.putpixel((1, 1), (0, 64, 200, 128))
    fresh = _assert_canonical_matches_intake(_encode(image, 'PNG'))
    assert fresh['canonical_pixel_sha256']


def test_exif_transpose_is_applied_before_protected_identity_hash():
    image = Image.new('RGB', (5, 3))
    image.putdata([(x * 40, y * 70, 15) for y in range(3) for x in range(5)])
    exif = Image.Exif(); exif[274] = 6
    fresh = _assert_canonical_matches_intake(_encode(image, 'JPEG', quality=100, exif=exif))
    assert (fresh['width'], fresh['height']) == (144, 240)
