import pytest

from fieldwork import real_job
from fieldwork.container_decoder import DecoderUnavailable


class _Decoder:
    def __init__(self, failures):
        self.failures, self.calls = list(failures), 0

    def decode_bytes(self, raw):
        self.calls += 1
        if self.failures:
            raise DecoderUnavailable(self.failures.pop(0))
        return {'ok': True}, b'px'


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(real_job.time, 'sleep', lambda _s: None)


def test_transient_decoder_failures_are_retried_then_succeed():
    d = _Decoder(['REAL_PIXEL_CONTAINER_START_FAILED', 'REAL_PIXEL_TIMEOUT'])
    assert real_job._decode_with_retry(d, b'x') == ({'ok': True}, b'px')
    assert d.calls == 3


def test_transient_failure_is_bounded():
    d = _Decoder(['REAL_PIXEL_TIMEOUT'] * 10)
    with pytest.raises(DecoderUnavailable) as caught:
        real_job._decode_with_retry(d, b'x')
    assert caught.value.code == 'REAL_PIXEL_TIMEOUT' and d.calls == 4


@pytest.mark.parametrize('code', ['REAL_PIXEL_CLEANUP_REQUIRED', 'REAL_PIXEL_INPUT_BOUNDS',
                                  'REAL_PIXEL_DECODER_IDENTITY', 'REAL_PIXEL_OUTPUT_LIMIT'])
def test_non_transient_failures_are_not_retried(code):
    d = _Decoder([code])
    with pytest.raises(DecoderUnavailable):
        real_job._decode_with_retry(d, b'x')
    assert d.calls == 1


def test_failure_code_uses_typed_code_or_class_name_only():
    assert real_job._failure_code(DecoderUnavailable('REAL_PIXEL_TIMEOUT')) == 'REAL_WORKER_FAILED_REAL_PIXEL_TIMEOUT'
    assert real_job._failure_code(KeyError('secret-path C:/x')) == 'REAL_WORKER_FAILED_KEYERROR'
    assert real_job._failure_code(real_job.RealModelChildFailure('ValueError')) == 'REAL_MODEL_CHILD_FAILED_VALUEERROR'
    odd = RuntimeError('boom'); odd.code = 'lower case with spaces and /path'
    assert real_job._failure_code(odd) == 'REAL_WORKER_FAILED_RUNTIMEERROR'
    assert len(real_job._failure_code(type('X' * 200, (Exception,), {})())) <= 120


def test_every_decode_site_passes_the_lease_renewer():
    import re
    from pathlib import Path
    src = Path(real_job.__file__).read_text(encoding='utf-8')
    calls = re.findall(r'(?<!def )_decode_with_retry\(decoder, raw[^)]*\)', src)
    assert len(calls) == 4 and all(c.endswith('renew)') or c.endswith('renew_lease)') for c in calls), calls
