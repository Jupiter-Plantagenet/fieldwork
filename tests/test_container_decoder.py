"""Authored-fixture tests for decoder protocol and container isolation flags.

These tests do not start Docker or inspect any real/heldout media.
"""
import struct
import io
import json
import os
import psutil
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from fieldwork.container_decoder import (
    DECODER_VERSION,
    DecoderProtocolError,
    DecoderUnavailable,
    ContainerDecoder,
    _validate_result,
    _validate_envelope,
    _write_all,
    _read_container_id,
    container_args,
    decode_bytes,
)
from fieldwork.decode_child import decode as legacy_decode


def _png_rgb_2x1():
    def chunk(kind, data):
        body = kind + data
        return struct.pack('!I', len(data)) + body + struct.pack('!I', zlib.crc32(body) & 0xffffffff)
    scanline = b'\x00\xff\x00\x00\x00\xff\x00'
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('!IIBBBBB', 2, 1, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(scanline)) + chunk(b'IEND', b''))


def test_authored_png_matches_legacy_decoder_semantics(tmp_path):
    raw = _png_rgb_2x1()
    path = tmp_path / 'authored.png'
    path.write_bytes(raw)
    modern = decode_bytes(raw)
    legacy = legacy_decode(str(path))
    assert modern['ok'] and legacy['ok']
    assert {key: modern[key] for key in ('format', 'width', 'height', 'pixel_sha256')} == {
        key: legacy[key] for key in ('format', 'width', 'height', 'pixel_sha256')}
    assert modern['decoder'] == DECODER_VERSION


def test_container_invocation_is_pinned_and_has_no_host_mounts():
    args = container_args('sha256:' + 'a' * 64, r'C:\private\decoder.cid', 'c' * 32)
    for required in ('--context', 'default', '--pull=never', '--platform=linux/amd64',
                     '--network=none', '--read-only', '--cap-drop=ALL',
                     '--security-opt=no-new-privileges=true', '--user=65532:65532',
                     '--memory=512m', '--memory-swap=512m', '--cpus=1', '--pids-limit=16',
                     '--ulimit=core=0', '--ulimit=nofile=64:64',
                     '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m'):
        assert required in args
    assert '--cidfile' in args
    assert f'--label=fieldwork.real-intake.decoder.nonce={"c" * 32}' in args
    assert not any(arg in ('--mount', '-v', '--volume') for arg in args)


def test_container_result_schema_is_bounded_and_digest_validated():
    accepted = {'ok': True, 'format': 'PNG', 'width': 2, 'height': 1,
                'pixel_sha256': 'b' * 64, 'phash_algorithm': 'phash-dct64/v1',
                'phash_hex': 'c' * 16, 'decoder': DECODER_VERSION}
    assert _validate_result(accepted) == accepted
    for bad in (dict(accepted, pixel_sha256='not-a-digest'),
                dict(accepted, phash_hex='not-a-phash'),
                dict(accepted, phash_algorithm='phash-unknown/v0'),
                {k: v for k, v in accepted.items() if k != 'phash_hex'}):
        with pytest.raises(DecoderProtocolError, match='DECODER_PROTOCOL_INVALID'):
            _validate_result(bad)


def test_decoder_envelope_binds_exact_input_digest_and_size():
    raw = _png_rgb_2x1()
    result = decode_bytes(raw)
    envelope = {'schema': 'fieldwork.decoder-result/v2',
                'input_sha256': __import__('hashlib').sha256(raw).hexdigest(),
                'input_bytes': len(raw), 'result': result}
    assert _validate_envelope(envelope, raw) == result
    for changed in (dict(envelope, input_bytes=len(raw) + 1),
                    dict(envelope, input_sha256='0' * 64),
                    dict(envelope, schema='fieldwork.decoder-result/v1'),
                    dict(envelope, schema='fieldwork.decoder-result/v0')):
        with pytest.raises(DecoderProtocolError, match='DECODER_INPUT_BINDING_MISMATCH'):
            _validate_envelope(changed, raw)


def test_unbuffered_decoder_pipe_retries_partial_writes():
    class PartialWriter:
        def __init__(self):
            self.data = bytearray()

        def write(self, view):
            amount = min(3, len(view))
            self.data.extend(view[:amount])
            return amount

    writer = PartialWriter()
    raw = b'authored input larger than a pipe write'
    _write_all(writer, raw)
    assert bytes(writer.data) == raw


def test_unbuffered_decoder_pipe_rejects_no_progress():
    class StalledWriter:
        def write(self, _view):
            return 0

    with pytest.raises(BrokenPipeError, match='DECODER_INPUT_WRITE_INCOMPLETE'):
        _write_all(StalledWriter(), b'payload')


def test_empty_docker_cidfile_is_pending_not_corrupt(tmp_path):
    cid = tmp_path / 'decoder.cid'
    cid.write_bytes(b'')
    assert _read_container_id(cid) is None
    cid.write_text('d' * 64, encoding='ascii')
    assert _read_container_id(cid) == 'd' * 64


def test_missing_local_docker_fails_closed(tmp_path):
    with patch('fieldwork.container_decoder.subprocess.run', side_effect=FileNotFoundError):
        with pytest.raises(DecoderUnavailable, match='DOCKER_STATE_UNAVAILABLE'):
            ContainerDecoder('sha256:' + 'a' * 64, private_dir=tmp_path, docker_env={})


def test_early_cli_exit_cannot_hide_container_and_retry_cleanup_resolves_receipt(tmp_path, monkeypatch):
    container_id = 'd' * 64

    class DockerState:
        active = True
        fail_remove = True
        nonce = None

        def run(self, args, **_kwargs):
            if args[:3] == ('context', 'inspect', 'default'):
                return SimpleNamespace(returncode=0, stdout='{"Host":"unix:///var/run/docker.sock"}')
            if args[:2] == ('info', '--format={{.OSType}}'):
                return SimpleNamespace(returncode=0, stdout='linux')
            if args[:2] == ('image', 'inspect'):
                return SimpleNamespace(returncode=0, stdout='sha256:' + 'a' * 64)
            if args[0:1] == ('ps',):
                if args[-1].startswith('label='):
                    assert self.nonce in args[-1]
                ids = [container_id] if self.active else []
                return SimpleNamespace(returncode=0, stdout='\n'.join(ids))
            if args[:2] == ('container', 'inspect'):
                return SimpleNamespace(returncode=0, stdout=json.dumps({
                    'fieldwork.real-intake.decoder': '1',
                    'fieldwork.real-intake.decoder.nonce': self.nonce}))
            if args[0] == 'kill':
                return SimpleNamespace(returncode=0, stdout='')
            if args[0] == 'rm':
                if self.fail_remove:
                    return SimpleNamespace(returncode=1, stdout='')
                self.active = False
                return SimpleNamespace(returncode=0, stdout='')
            raise AssertionError(args)

    state = DockerState()
    monkeypatch.setattr(ContainerDecoder, '_run', state.run)

    class ExitedDockerCli:
        def __init__(self, args, **_kwargs):
            Path(args[args.index('--cidfile') + 1]).write_text(container_id, encoding='ascii')
            state.nonce = next(arg.rsplit('=', 1)[1] for arg in args
                               if arg.startswith('--label=fieldwork.real-intake.decoder.nonce='))
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(b'')
            self.returncode = 1

        def poll(self):
            return self.returncode

        def terminate(self):
            pass

        def kill(self):
            pass

        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr('fieldwork.container_decoder.subprocess.Popen', ExitedDockerCli)
    session = 'e' * 32
    image = 'sha256:' + 'a' * 64
    decoder = ContainerDecoder(image, private_dir=tmp_path, session_id=session, docker_env={})
    image_file = tmp_path / 'authored.png'
    image_file.write_bytes(_png_rgb_2x1())
    with pytest.raises(DecoderUnavailable, match='DECODER_CLEANUP_REQUIRED'):
        decoder.decode(image_file)
    receipt = next((tmp_path / '.decoder-sessions' / session).glob('*.cleanup.json'))
    cid = next((tmp_path / '.decoder-sessions' / session).glob('*.cid'))
    assert state.active and receipt.exists() and cid.exists()

    state.fail_remove = False
    recovered = ContainerDecoder(image, private_dir=tmp_path, session_id=session, docker_env={})
    assert not state.active
    assert receipt.exists()  # resolved cleanup-failure audit is retained
    assert not cid.exists()


def test_docker_query_failure_is_not_treated_as_container_absence(tmp_path):
    from types import MethodType

    session_dir = tmp_path / '.decoder-sessions' / 'session'
    session_dir.mkdir(parents=True)
    nonce = 'f' * 32
    cid_path = session_dir / ('.decoder-' + nonce + '.cid')
    cid_path.write_text('e' * 64, encoding='ascii')
    receipt_path = session_dir / ('.decoder-' + nonce + '.cleanup.json')
    receipt = {'schema': 'fieldwork.decoder-cleanup/v1', 'state': 'active', 'nonce': nonce,
               'cid_file': cid_path.name, 'owner_pid': os.getpid(),
               'owner_created': psutil.Process().create_time()}
    receipt_path.write_text(json.dumps(receipt), encoding='utf-8')
    decoder = object.__new__(ContainerDecoder)
    decoder.env = {}
    unavailable = {'first': True}

    def docker_state(_self, args, **_kwargs):
        if args[0] == 'ps' and unavailable['first']:
            unavailable['first'] = False
            raise DecoderUnavailable('DOCKER_STATE_UNAVAILABLE')
        return SimpleNamespace(returncode=0, stdout='')

    decoder._run = MethodType(docker_state, decoder)
    with pytest.raises(DecoderUnavailable, match='DECODER_CLEANUP_REQUIRED'):
        decoder._cleanup_receipt(receipt_path, receipt, cid_path)
    assert cid_path.exists()
    assert json.loads(receipt_path.read_text(encoding='utf-8'))['state'] == 'cleanup_required'

    decoder._cleanup_receipt(receipt_path, json.loads(receipt_path.read_text(encoding='utf-8')), cid_path)
    assert not cid_path.exists()
    assert json.loads(receipt_path.read_text(encoding='utf-8'))['state'] == 'resolved'


def test_decoder_factory_seam_keeps_worker_contract_explicit():
    source = (Path(__file__).parents[1] / 'fieldwork' / 'intake.py').read_text(encoding='utf-8')
    worker = (Path(__file__).parents[1] / 'fieldwork' / 'newintake_worker.py').read_text(encoding='utf-8')
    assert 'decoder_factory=None' in source
    assert 'decoder_factory() if decoder_factory is not None else Decoder()' in source
    assert "decoder_factory=lambda: decoder" in worker
