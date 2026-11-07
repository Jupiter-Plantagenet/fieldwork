"""Pure authored TAR/config checks for the fixed model-child container boundary."""
import io
import json
import subprocess
import tarfile
from types import SimpleNamespace

import pytest

from fieldwork.real_model_container import ModelContainerProcess, ModelContainerUnavailable


def test_stage_helper_wait_forces_renewal_across_30_second_bound():
    from fieldwork.real_model_container import _wait_for_stage_helper

    now = [0.0]
    renewals = []

    class Helper:
        remaining = 11.0
        def wait(self, timeout):
            assert 0 < timeout <= 5
            now[0] += min(timeout, self.remaining)
            self.remaining -= min(timeout, self.remaining)
            if self.remaining:
                raise subprocess.TimeoutExpired('helper', timeout)
            return 0

    def renew(*, force=False):
        assert force is True
        renewals.append(now[0])

    assert _wait_for_stage_helper(Helper(), progress_callback=renew, timeout=30,
                                  monotonic=lambda: now[0]) == 0
    assert renewals == [0.0, 5.0, 10.0, 11.0]


def test_stage_helper_heartbeat_latency_counts_toward_same_30_second_deadline():
    from fieldwork.real_model_container import _wait_for_stage_helper

    now = [0.0]

    class Helper:
        def wait(self, timeout):
            now[0] += timeout
            raise subprocess.TimeoutExpired('helper', timeout)

    def renew(*, force=False):
        assert force is True
        now[0] += 1.0

    with pytest.raises(subprocess.TimeoutExpired):
        _wait_for_stage_helper(Helper(), progress_callback=renew, timeout=30,
                               monotonic=lambda: now[0])
    assert now[0] == 30.0


def test_stage_cleanup_renews_between_bounded_docker_steps():
    from fieldwork.real_model_container import ModelContainerRunner, STAGE_LABEL

    runner = ModelContainerRunner.__new__(ModelContainerRunner)
    now = [0.0]
    renewals = []
    cid = 'a' * 64
    nonce = 'b' * 32
    image = 'sha256:' + 'c' * 64
    receipt = {'nonce': nonce, 'image_id': image, 'owner_pid': 12,
               'owner_created': 1.0}
    listed = [False]

    def list_stage(_nonce):
        assert _nonce == nonce
        if not listed[0]:
            listed[0] = True
            return [cid]
        return []

    runner._list_stage_by_nonce = list_stage
    runner._owner_label = lambda _receipt: '12-1000'

    def run(args, *, capture=False, timeout=5):
        if args[0] == 'container' and args[1] == 'inspect':
            now[0] += 12
            labels = {STAGE_LABEL: '1', STAGE_LABEL + '.nonce': nonce,
                      STAGE_LABEL + '.image': image, STAGE_LABEL + '.owner': '12-1000'}
            row = {'Id': cid, 'Image': image, 'Config': {'Labels': labels}}
            return SimpleNamespace(returncode=0, stdout=json.dumps(row).encode())
        if args[0] == 'kill':
            assert timeout == 10
            now[0] += timeout
        elif args[0:2] == ('rm', '--force'):
            assert timeout == 20
            now[0] += timeout
        return SimpleNamespace(returncode=0, stdout=b'')

    runner._run = run

    def renew(*, force=False):
        assert force is True
        renewals.append(now[0])

    runner._cleanup_stage_container(receipt, progress_callback=renew)
    assert renewals == sorted(renewals)
    assert len(renewals) >= 5
    assert max(b - a for a, b in zip(renewals, renewals[1:])) <= 20


def test_owned_inspection_uses_bounded_identity_projection():
    from fieldwork.real_model_container import ModelContainerRunner, MODEL_LABEL
    runner = ModelContainerRunner.__new__(ModelContainerRunner)
    runner.image_id = 'sha256:' + 'a' * 64
    cid = 'b' * 64
    nonce = 'c' * 32
    labels = {MODEL_LABEL:'1', MODEL_LABEL + '.nonce':nonce}
    output = f'{cid} {runner.image_id} {json.dumps(labels,separators=(",",":"))} true 0'.encode()
    calls = []
    def run(args, *, capture=False):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=output)
    runner._run = run

    state = runner._inspect_owned(cid, nonce, runner.image_id)
    assert state == {'Running':True,'ExitCode':0}
    assert len(output) < 4096
    assert calls[0][0:2] == ('container','inspect')
    assert calls[0][2].startswith('--format={{.Id}} {{.Image}} {{json .Config.Labels}}')


def _tar(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, body, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == 'dir':
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == 'symlink':
                info.type = tarfile.SYMTYPE
                info.linkname = body
                archive.addfile(info)
            else:
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
    return stream.getvalue()


def test_checkpoint_export_accepts_only_small_regular_files(tmp_path):
    raw = _tar([
        ('epoch-2/', b'', 'dir'),
        ('epoch-2/manifest.json', b'{}', 'file'),
        ('epoch-2/state.json', b'{}', 'file'),
        ('epoch-2/state.safetensors', b'1234', 'file'),
    ])
    out = tmp_path / 'epoch-2'
    assert ModelContainerProcess._extract_tar(raw, out, expected_prefix='epoch-2', limits={
        'manifest.json': 32, 'state.json': 32, 'state.safetensors': 64})
    assert {p.name for p in out.iterdir()} == {'manifest.json', 'state.json', 'state.safetensors'}


def test_bundle_export_accepts_exact_allowlisted_tree(tmp_path):
    names = ('manifest.json', 'architecture.json', 'preprocess.json', 'classes.json',
             'lineage.json', 'model.safetensors', 'rights/review.json',
             'evaluation/population.json', 'evaluation/metrics.json',
             'evaluation/independent-report.json', 'evaluation/predictions.jsonl')
    entries = [('bundle/', b'', 'dir'), ('bundle/rights/', b'', 'dir'),
               ('bundle/evaluation/', b'', 'dir')]
    entries.extend(('bundle/' + name, b'{}', 'file') for name in names)
    limits = {name: 32 for name in names}
    out = tmp_path / 'bundle'
    assert ModelContainerProcess._extract_bundle_tar(_tar(entries), out, limits) == out
    assert {p.relative_to(out).as_posix() for p in out.rglob('*') if p.is_file()} == set(names)


def test_bundle_export_rejects_symlinks_and_extra_paths(tmp_path):
    names = {'manifest.json': 32}
    with pytest.raises(ModelContainerUnavailable):
        ModelContainerProcess._extract_bundle_tar(
            _tar([('bundle/manifest.json', '../outside', 'symlink')]), tmp_path / 'link', names)
    with pytest.raises(ModelContainerUnavailable):
        ModelContainerProcess._extract_bundle_tar(
            _tar([('bundle/../outside', b'x', 'file')]), tmp_path / 'traversal', names)


def test_cleanup_reconciles_owned_container_when_docker_never_wrote_cid(tmp_path):
    events = []

    class Proc:
        returncode = 125

        def poll(self):
            events.append('cli-reaped')
            return self.returncode

        def wait(self, timeout=None):
            events.append('cli-reaped')
            return self.returncode

    class Runner:
        def __init__(self):
            self._active = {tmp_path / 'receipt'}

        def _cleanup(self, receipt_path, receipt, cid_path, *, retain_receipt=False):
            events.append(('nonce-cleanup', retain_receipt))

    process = ModelContainerProcess.__new__(ModelContainerProcess)
    process._closed = False
    process.cid = None
    process.output_tmpfs = False
    process.proc = Proc()
    process.runner = Runner()
    process.receipt_path = tmp_path / 'receipt'
    process.receipt = {'nonce': 'a' * 32}
    process.cid_path = tmp_path / 'cid'

    process.cleanup()

    assert events == ['cli-reaped', 'cli-reaped', ('nonce-cleanup', False)]
    assert process.receipt_path not in process.runner._active
    assert process._closed is True


def test_failed_start_cleanup_error_keeps_runner_unresolved_for_slot_fence(tmp_path):
    from fieldwork.real_model_container import ModelContainerRunner

    runner = ModelContainerRunner.__new__(ModelContainerRunner)
    receipt_path = tmp_path / 'active-receipt'
    runner._active = {receipt_path}

    def volume_removal_unconfirmed(*args, **kwargs):
        raise ModelContainerUnavailable('MODEL_CLEANUP_REQUIRED')

    runner._cleanup = volume_removal_unconfirmed
    with pytest.raises(ModelContainerUnavailable, match='MODEL_CLEANUP_REQUIRED'):
        runner._cleanup_failed_start(receipt_path, {}, tmp_path / 'cid')
    assert runner.has_unresolved_container
