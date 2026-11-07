import json

from fieldwork.real_job import _real_model_child_failure
from fieldwork.worker import _real_job_failure_summary


class _Process:
    def __init__(self, raw):
        self.raw = raw

    def read_receipt(self):
        return self.raw


class _Runner:
    def __init__(self, unresolved=False):
        self.has_unresolved_container = unresolved


def test_real_child_failure_uses_only_typed_allowlisted_receipt():
    exc = _real_model_child_failure(_Process(b'{"error":"ValueError"}\n'))

    assert str(exc) == 'real training child failed'
    assert exc.safe_failure_code == 'REAL_MODEL_CHILD_FAILED_VALUEERROR'
    code, event = _real_job_failure_summary(exc, 'run-id', _Runner())
    assert code == 26
    assert event == {'code': 'RUN_REAL_JOB_FAILED', 'run': 'run-id',
                     'reason': 'REAL_MODEL_CHILD_FAILED_VALUEERROR',
                     'cleanup_pending': False}


def test_malformed_or_unreadable_child_receipt_is_unclassified_and_fail_closed():
    exc = _real_model_child_failure(_Process(b'{"error":"bad\nsecret"}'))
    assert exc.safe_failure_code == 'REAL_MODEL_CHILD_FAILED_UNCLASSIFIED'
    assert 'secret' not in str(exc)

    class _Unreadable:
        def read_receipt(self):
            raise OSError('private detail')

    unreadable = _real_model_child_failure(_Unreadable())
    assert unreadable.safe_failure_code == 'REAL_MODEL_CHILD_FAILED_UNCLASSIFIED'
    assert 'private detail' not in str(unreadable)


def test_real_job_loop_summary_never_emits_exception_text():
    exc = RuntimeError('private path and secret-like detail')
    code, event = _real_job_failure_summary(exc, 'run-id', _Runner(unresolved=True))

    assert code == 26
    assert event == {'code': 'RUN_REAL_JOB_FAILED', 'run': 'run-id',
                     'reason': 'REAL_JOB_EXECUTION_FAILED',
                     'cleanup_pending': True}
    assert 'private' not in json.dumps(event)


def test_repeated_real_job_failures_for_one_revision_are_blocked_after_a_bound():
    from fieldwork.worker import _note_real_job_failure
    counts = {}
    key = ('run-id', 4)
    assert [_note_real_job_failure(counts, key) for _ in range(3)] == [False, False, True]
    assert _note_real_job_failure(counts, ('run-id', 5)) is False  # a new revision is eligible again
