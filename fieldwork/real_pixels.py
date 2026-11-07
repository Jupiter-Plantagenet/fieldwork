"""Validated numeric RGB8 assets produced by the pinned pixel-decoder container."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

MAX_EDGE = 1024
MAX_BYTES = MAX_EDGE * 144 * 3


def validate_rgb8(width: int, height: int, payload: bytes, claimed_digest: str) -> str:
    if (type(width) is not int or type(height) is not int or min(width, height) != 144
            or max(width, height) > MAX_EDGE or len(payload) != width * height * 3
            or len(payload) > MAX_BYTES):
        raise ValueError('REAL_PIXEL_OUTPUT_BOUNDS')
    actual = hashlib.sha256(b'RGB8|%d|%d|' % (width, height) + payload).hexdigest()
    if actual != claimed_digest:
        raise ValueError('REAL_PIXEL_OUTPUT_DIGEST')
    return actual


def write_rgb8(root: str | Path, relative_name: str, width: int, height: int,
               payload: bytes, claimed_digest: str) -> dict:
    """Create an exclusive, server-named numeric asset; never writes raw source bytes."""
    validate_rgb8(width, height, payload, claimed_digest)
    root = Path(root).resolve(strict=True)
    relative = Path(relative_name)
    if relative.is_absolute() or '..' in relative.parts or len(relative.parts) != 1:
        raise ValueError('REAL_PIXEL_NAME')
    target = root / relative
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return {'pixel_file': relative.name, 'width': width, 'height': height,
            'decoded_pixel_sha256': claimed_digest}

