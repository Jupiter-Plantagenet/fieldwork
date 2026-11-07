"""Bounded host client for the pinned real-pixel decoder container.

The container lifecycle reuses the intake decoder's nonce/CID cleanup journal and
positive daemon-side absence proof. The new image is independent and must be pinned
by its immutable Docker config ID at runtime.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import threading
import time
from pathlib import Path

from .container_decoder import (CONTAINER_LABEL, ContainerDecoder, DecoderUnavailable,
                                _read_container_id, _unique_pairs, _write_all)
from .real_pixels import validate_rgb8

MAX_INPUT = 20 * 1024 * 1024
MAX_EDGE = 1024
MAX_PAYLOAD = MAX_EDGE * 144 * 3
MAX_OUTPUT = MAX_PAYLOAD + 4096
PIXEL_DECODER_VERSION = 'fieldwork.real-pixels/v2 pillow-13.0.0 canonical-intake-rgb8 short-edge144-bilinear'
RESULT_SCHEMA = 'fieldwork.real-pixels-result/v1'


def pixel_container_args(image_id: str, cid_file: str, nonce: str):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('REAL_PIXEL_IMAGE_ID')
    if not re.fullmatch(r'[0-9a-f]{32}', nonce):
        raise ValueError('REAL_PIXEL_NONCE')
    from .container_decoder import _docker_command
    return _docker_command(
        'run', '--pull=never', '--platform=linux/amd64', '--rm', '--interactive',
        '--cidfile', cid_file, '--network=none', '--read-only', '--cap-drop=ALL',
        f'--label={CONTAINER_LABEL}=1', f'--label={CONTAINER_LABEL}.nonce={nonce}',
        '--security-opt=no-new-privileges=true', '--user=65532:65532',
        '--memory=512m', '--memory-swap=512m', '--cpus=1', '--pids-limit=16',
        '--ulimit=core=0', '--ulimit=nofile=64:64',
        '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m', '--workdir=/tmp',
        '--entrypoint=/usr/local/bin/python', image_id, '-I', '-B',
        '/app/container_real_pixels.py', '--container')


class ContainerRealPixelDecoder(ContainerDecoder):
    """Decode bytes in the new pinned image and return only bounded numeric RGB8."""
    version = PIXEL_DECODER_VERSION

    def decode_bytes(self, data: bytes) -> tuple[dict, bytes]:
        if type(data) is not bytes or len(data) > MAX_INPUT:
            raise DecoderUnavailable('REAL_PIXEL_INPUT_BOUNDS')
        self._recover_receipts()
        receipt_path, receipt, cid_path = self._new_receipt()
        proc = None
        output = bytearray()
        overflow = threading.Event()
        reader_done, writer_done = threading.Event(), threading.Event()
        threads = []
        failure = None
        decoded = None
        try:
            proc = subprocess.Popen(pixel_container_args(self.image_id, str(cid_path), receipt['nonce']),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=self.env, bufsize=0)
            deadline = time.monotonic() + 8
            cid = None
            while proc.poll() is None and time.monotonic() < deadline:
                cid = _read_container_id(cid_path)
                if cid:
                    break
                time.sleep(.01)
            if not cid:
                raise DecoderUnavailable('REAL_PIXEL_CONTAINER_START_FAILED')

            def write_input():
                try:
                    _write_all(proc.stdin, data)
                    proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try: proc.stdin.close()
                    except OSError: pass
                    writer_done.set()

            def read_output():
                try:
                    while True:
                        block = proc.stdout.read(8192)
                        if not block:
                            break
                        if len(output) + len(block) > MAX_OUTPUT:
                            overflow.set()
                        else:
                            output.extend(block)
                finally:
                    reader_done.set()

            threads = [threading.Thread(target=write_input, daemon=True),
                       threading.Thread(target=read_output, daemon=True)]
            for thread in threads: thread.start()
            deadline = time.monotonic() + 15
            while proc.poll() is None and not overflow.is_set() and time.monotonic() < deadline:
                time.sleep(.02)
            if overflow.is_set():
                failure = 'REAL_PIXEL_OUTPUT_LIMIT'
            elif proc.poll() is None:
                failure = 'REAL_PIXEL_TIMEOUT'
            else:
                for thread in threads: thread.join(timeout=2)
                if (proc.returncode != 0 or not reader_done.is_set() or not writer_done.is_set()
                        or overflow.is_set()):
                    failure = 'REAL_PIXEL_CONTAINER_FAILED'
                else:
                    decoded = self._decode_result(bytes(output), data)
        except DecoderUnavailable:
            raise
        except OSError:
            failure = 'REAL_PIXEL_DOCKER_UNAVAILABLE'
        finally:
            self._stop_cli(proc)
            for thread in threads: thread.join(timeout=2)
            stuck = any(thread.is_alive() for thread in threads)
            try:
                self._cleanup_receipt(receipt_path, receipt, cid_path)
            except DecoderUnavailable:
                raise
            if stuck:
                self._record_cleanup_failure(receipt_path, receipt, 'REAL_PIXEL_PIPE_THREAD_STUCK')
                raise DecoderUnavailable('REAL_PIXEL_CLEANUP_REQUIRED')
        if failure:
            raise DecoderUnavailable(failure)
        if decoded is None:
            raise DecoderUnavailable('REAL_PIXEL_PROTOCOL_INVALID')
        return decoded

    @staticmethod
    def _decode_result(output: bytes, input_data: bytes):
        header_bytes, sep, payload = output.partition(b'\n')
        if not sep or len(header_bytes) > 4096:
            raise DecoderUnavailable('REAL_PIXEL_PROTOCOL_HEADER')
        try:
            envelope = json.loads(header_bytes.decode('ascii'), object_pairs_hook=_unique_pairs)
        except (UnicodeError, ValueError, TypeError):
            raise DecoderUnavailable('REAL_PIXEL_PROTOCOL_JSON') from None
        required = {'schema', 'input_sha256', 'input_bytes', 'result', 'payload_bytes'}
        if (type(envelope) is not dict or set(envelope) != required
                or envelope['schema'] != RESULT_SCHEMA
                or envelope['input_sha256'] != hashlib.sha256(input_data).hexdigest()
                or envelope['input_bytes'] != len(input_data)):
            raise DecoderUnavailable('REAL_PIXEL_INPUT_BINDING')
        result = envelope['result']
        if type(result) is not dict or result.get('decoder') != PIXEL_DECODER_VERSION:
            raise DecoderUnavailable('REAL_PIXEL_DECODER_IDENTITY')
        if result.get('ok') is not True:
            if payload or envelope['payload_bytes'] != 0:
                raise DecoderUnavailable('REAL_PIXEL_REJECT_PROTOCOL')
            raise DecoderUnavailable(str(result.get('reason', 'REAL_PIXEL_REJECTED'))[:64])
        if (set(result) != {'ok', 'format', 'width', 'height', 'pixel_sha256',
                            'canonical_pixel_sha256', 'decoder'}
                or result['format'] not in {'JPEG', 'PNG', 'WEBP', 'RGB'}
                or type(result['canonical_pixel_sha256']) is not str
                or not re.fullmatch(r'[0-9a-f]{64}', result['canonical_pixel_sha256'])
                or type(envelope['payload_bytes']) is not int or envelope['payload_bytes'] != len(payload)):
            raise DecoderUnavailable('REAL_PIXEL_RESULT_SCHEMA')
        validate_rgb8(result['width'], result['height'], payload, result['pixel_sha256'])
        return result, payload

