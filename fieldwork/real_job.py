"""Scoped supervisor for rights-checked real training over container-decoded pixels."""
from __future__ import annotations
import base64, hashlib, json, os, re, subprocess, time
from pathlib import Path
from . import real_api
from .data import canonical, digest
from .real_pixels import write_rgb8
from .real_run_profile import (REAL_INFER_SCOPE, REAL_TRAIN_SCOPE,
                              MAX_REAL_SAMPLES, validate_inference_config,
                              validate_training_config)
from .store import Conflict, ROOT
from .supervisor import command_key
from .worker import exit_receipt

MAX_ROWS = MAX_REAL_SAMPLES


class RealModelChildFailure(RuntimeError):
    """A bounded, type-only failure from the sealed real-model child."""
    def __init__(self, error_type=None):
        if (not isinstance(error_type, str)
                or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', error_type)):
            error_type = None
        self.safe_failure_code = ('REAL_MODEL_CHILD_FAILED_' + error_type.upper()
                                  if error_type else 'REAL_MODEL_CHILD_FAILED_UNCLASSIFIED')
        super().__init__('real training child failed')


def _real_model_child_failure(process):
    """Read only the image's bounded type-only error receipt; never expose stderr."""
    error_type = None
    try:
        raw = process.read_receipt()
        if type(raw) is bytes and len(raw) <= 64 * 1024:
            payload = json.loads(raw.decode('utf-8'))
            if (type(payload) is dict and set(payload) == {'error'}
                    and isinstance(payload.get('error'), str)):
                error_type = payload['error']
    except Exception:
        # The normal cleanup path still verifies container/volume absence.
        # Failure to read a diagnostic never masks the original nonzero exit.
        pass
    return RealModelChildFailure(error_type)


_TRANSIENT_DECODER_CODES = frozenset({
    'REAL_PIXEL_CONTAINER_START_FAILED', 'REAL_PIXEL_TIMEOUT',
    'REAL_PIXEL_CONTAINER_FAILED', 'REAL_PIXEL_DOCKER_UNAVAILABLE'})


def _decode_with_retry(decoder, raw, renew=None, attempts=4):
    """Decode one image, retrying only transient container start/timeout failures.

    A single Docker stall must not permanently fail a ~1 h staging pass. Cleanup,
    identity, bounds and output-limit failures are never retried.
    """
    from .container_decoder import DecoderUnavailable
    for n in range(attempts):
        try:
            return decoder.decode_bytes(raw)
        except DecoderUnavailable as exc:
            if exc.code not in _TRANSIENT_DECODER_CODES or n == attempts - 1:
                raise
            time.sleep(2 * (n + 1))
            if renew is not None:
                renew()


def _failure_code(exc):
    """Stored failure code: typed code, else a fixed-token code or the exception class name."""
    code = getattr(exc, 'safe_failure_code', None)
    if isinstance(code, str) and re.fullmatch(r'[A-Z0-9_]{1,120}', code):
        return code
    detail = getattr(exc, 'code', None)
    if not (isinstance(detail, str) and re.fullmatch(r'[A-Z0-9_]{1,80}', detail)):
        detail = re.sub(r'[^A-Z0-9]+', '_', type(exc).__name__.upper()).strip('_')[:80]
    code = 'REAL_WORKER_FAILED' + ('_' + detail if detail else '')
    return code if re.fullmatch(r'[A-Z0-9_]{1,120}', code) else 'REAL_WORKER_FAILED'


def _attempt_paths(run_id, attempt):
    root = ROOT / 'var/runs' / run_id / attempt['attempt']
    return root, root / 'real-inputs', root / 'training'


def verify_member(sample, *, workspace, purpose, dataset_id=None):
    from .rights_decision import ExpectedFacts, verify_decision, DecisionRejected
    from .rights_registry import load_trusted_registry
    try:
        facts = sample['rights_facts']
        expected = ExpectedFacts(**facts)
        if (expected.workspace_id != workspace or expected.purpose != purpose
                or expected.member_id != sample['source_member']
                or expected.asset_sha256 != sample['sha256']
                or expected.asset_bytes != sample['raw_bytes']
                or dataset_id is not None and expected.dataset_id != dataset_id):
            raise DecisionRejected('CONTEXT_MISMATCH')
        raw = base64.b64decode(sample['rights_envelope_b64'], validate=True)
        verify_decision(raw, registry=load_trusted_registry(), expected=expected)
    except (DecisionRejected, KeyError, TypeError, ValueError):
        raise Conflict('REAL_RIGHTS_REVOKED_OR_INVALID') from None


def _check_rights(samples, actor, workspace, dataset_id, purpose='local_private_training'):
    if type(samples) is not list or not samples or len(samples) > MAX_ROWS:
        raise Conflict('REAL_POPULATION_BOUNDS')
    for sample in samples:
        verify_member(sample, workspace=workspace, purpose=purpose, dataset_id=dataset_id)


def _validate_inputs(run, inputs):
    config = validate_training_config(run['config'], workspace=run['workspace'])
    if (inputs.get('version_id') != config['version_id']
            or inputs.get('version_revision') != config['version_revision']
            or inputs.get('version_digest') != config['version_digest']
            or inputs.get('dataset_id') != config['dataset_id']):
        raise Conflict('REAL_FROZEN_VERSION_CHANGED')
    if inputs.get('actor_authorized') is not True:
        raise Conflict('REAL_ACTOR_AUTHORIZATION_REVOKED')
    samples = inputs.get('samples')
    if type(samples) is not list or not samples or len(samples) > MAX_ROWS:
        raise Conflict('REAL_POPULATION_BOUNDS')
    if any(type(s) is not dict or s.get('split') not in {'train', 'validation'} for s in samples):
        raise Conflict('REAL_SPLIT_BOUNDARY')
    if {s['split'] for s in samples} != {'train', 'validation'}:
        raise Conflict('REAL_TRAIN_VALIDATION_REQUIRED')
    return config, samples


def _stage_pixels(run_id, attempt, config, samples, decoder, inputs, verify_current_member,
                  renew_lease=lambda: None):
    media_root = (ROOT / '.local/real-data/media').resolve(strict=True)
    _, stage, _ = _attempt_paths(run_id, attempt)
    stage.mkdir(parents=True, exist_ok=False)
    groups = {'train': [], 'validation': []}
    for index, sample in enumerate(samples):
        renew_lease()
        verify_current_member(sample)
        path = real_api._inside_root(sample['media_path'], media_root)
        raw = real_api._read_verified_media(path, sample['sha256'], sample['raw_bytes'])
        decoded, pixels = _decode_with_retry(decoder, raw, renew_lease)
        renew_lease()
        if not decoded.get('ok'):
            raise Conflict('REAL_MEDIA_DECODE_REJECTED')
        pixel = write_rgb8(stage, 'pixel-%06d.rgb' % index, decoded['width'], decoded['height'],
                           pixels, decoded['pixel_sha256'])
        row = {k: sample[k] for k in ('id', 'label', 'split', 'source_member')}
        row['source_sha256'] = sample['sha256']
        groups[sample['split']].append({**row, **pixel})
    manifest = {'schema': 'fieldwork.real-pixel-input/v1', 'version_id': config['version_id'],
                'version_digest': config['version_digest'], 'recipe': config['recipe'],
                'recipe_digest': config['recipe_digest'], 'preprocess': config['preprocess'],
                'preprocess_digest': config['preprocess_digest'],
                'decoder_image_id': config['decoder_image_id'],
                'classes': inputs.get('classes'), 'train': groups['train'],
                'validation': groups['validation']}
    with (stage / 'inputs.json').open('xb') as stream:
        stream.write(canonical(manifest)); stream.flush(); os.fsync(stream.fileno())
    return stage


def _lease_renewer(store, attempt, phase):
    """Renew the fenced lease during preprocessing and inference, not just training."""
    last, sequence = 0.0, 0

    def renew(force=False):
        nonlocal last, sequence
        if force or time.monotonic() - last >= 10:
            sequence += 1
            store.heartbeat(attempt['id'], attempt['fence'], attempt['cancel_generation'],
                attempt=attempt['attempt'], restore_generation=attempt['restore_generation'],
                key=command_key(attempt['attempt'], phase, sequence))
            last = time.monotonic()
    return renew


def _watch(store, attempt, process, output, recheck, timeout):
    rid, fence, generation = attempt['id'], attempt['fence'], attempt['cancel_generation']
    scope = {'attempt': attempt['attempt'], 'restore_generation': attempt['restore_generation']}
    deadline, last_beat, beats = time.monotonic() + timeout, 0.0, 0
    try:
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('real training timeout')
            if time.monotonic() - last_beat > 10:
                beats += 1
                store.heartbeat(rid, fence, generation,
                    key=command_key(attempt['attempt'], 'ML-Heartbeat', beats), **scope)
                last_beat = time.monotonic()
            run = store.get(rid)
            if run['state'] == 'cancel_requested':
                attempt['observed_cancel_generation'] = run.get('cancel_generation')
                process.kill(); process.wait(timeout=10); return
            status = process.poll()
            if status is not None:
                if status != 0: raise _real_model_child_failure(process)
                process.export_training_result(output)
                result = json.loads((output / 'result.json').read_text(encoding='utf-8'))
                history = result.get('history')
                if type(history) is not list:
                    raise Conflict('REAL_TRAINING_HISTORY_INVALID')
                for row in history:
                    if type(row) is not dict or type(row.get('epoch')) is not int:
                        raise Conflict('REAL_TRAINING_HISTORY_INVALID')
                    current = store.get(rid)
                    if row['epoch'] <= current['epoch']:
                        continue
                    process.export_checkpoint(output, row['epoch'], stopped=True)
                    recheck()
                    meta = json.loads((output / ('epoch-%d' % row['epoch']) / 'state.json').read_text())
                    metrics = {k: meta[k] for k in ('epoch', 'train_loss', 'validation_loss', 'updates')}
                    store.publish(rid, fence, generation, output / ('epoch-%d' % row['epoch']), metrics,
                        key=command_key(attempt['attempt'], 'ML-CheckpointCommit', row['epoch']), **scope)
                recheck()
                # The model task has exited, but its container remains alive to
                # retain tmpfs outputs. Confirm container/CLI exit before the DB
                # completion capability checks the registered child identity.
                process.cleanup()
                store.complete(rid, fence, generation, result,
                    key=command_key(attempt['attempt'], 'ML-Complete'), **scope)
                return
            epoch = run['epoch'] + 1
            if process.export_checkpoint(output, epoch, stopped=False):
                recheck()
                meta = json.loads((output / ('epoch-%d' % epoch) / 'state.json').read_text())
                metrics = {k: meta[k] for k in ('epoch', 'train_loss', 'validation_loss', 'updates')}
                store.publish(rid, fence, generation, output / ('epoch-%d' % epoch), metrics,
                    key=command_key(attempt['attempt'], 'ML-CheckpointCommit', epoch), **scope)
                continue
            time.sleep(.05)
    except BaseException as exc:
        if getattr(exc, 'code', None) == 'CANCEL_GENERATION_FENCED' and getattr(exc, 'state', None) == 'cancel_requested':
            attempt['observed_cancel_generation'] = exc.current_generation
        if process.poll() is None: process.kill(); process.wait(timeout=10)
        raise


def execute_real(run_id, store, *, decoder, model_runner, artifact_pipeline=None, timeout=3600):
    """Run only the exact real-training profile through scoped worker capabilities."""
    if decoder is None:
        raise Conflict('REAL_DECODER_REQUIRED')
    current = store.get(run_id)
    if not current or current['state'] != 'queued' or current['config'].get('scope') != REAL_TRAIN_SCOPE:
        raise Conflict('REAL_RUN_NOT_QUEUED')
    config = validate_training_config(current['config'], workspace=current['workspace'])
    if getattr(decoder, 'image_id', None) != config['decoder_image_id']:
        raise Conflict('REAL_PIXEL_IMAGE_BINDING_MISMATCH')
    if model_runner is None or model_runner.image_id != config['model_image_id']:
        raise Conflict('REAL_MODEL_IMAGE_BINDING_MISMATCH')
    attempt = store.claim_real(run_id, worker_id=os.environ.get('FIELDWORK_WORKER_ID', 'real-worker'),
        key=command_key('real-worker', 'ML-Claim', run_id, current['revision']))
    child = None
    observed_exit = None
    _, _, out = _attempt_paths(run_id, attempt)
    try:
        renew = _lease_renewer(store, attempt, 'ML-PreprocessHeartbeat')
        renew()
        inputs = store.real_inputs(run_id, attempt['attempt'], attempt['fence'],
                                   attempt['cancel_generation'], attempt['restore_generation'])
        _, samples = _validate_inputs(attempt, inputs)
        def recheck(purpose='local_private_training'):
            fresh = store.real_inputs(run_id, attempt['attempt'], attempt['fence'],
                attempt['cancel_generation'], attempt['restore_generation'])
            _, current_samples = _validate_inputs(attempt, fresh)
            identity_before = {(s['id'], s['split'], s['source_member'], s['sha256'], s['raw_bytes'])
                               for s in samples}
            identity_now = {(s['id'], s['split'], s['source_member'], s['sha256'], s['raw_bytes'])
                            for s in current_samples}
            if identity_now != identity_before:
                raise Conflict('REAL_FROZEN_VERSION_CHANGED')
            _check_rights(current_samples, config['actor'], config['workspace'], config['dataset_id'], purpose)
        def verify_current_member(sample):
            fresh = store.real_member_rights(run_id, attempt['attempt'], attempt['fence'],
                attempt['cancel_generation'], attempt['restore_generation'], sample['id'])
            if (fresh.get('sample_id') != sample['id'] or fresh.get('source_member') != sample['source_member']
                    or fresh.get('sha256') != sample['sha256'] or fresh.get('asset_bytes') != sample['raw_bytes']
                    or fresh.get('rights_facts', {}).get('dataset_id') != config['dataset_id']):
                raise Conflict('REAL_RIGHTS_ASSET_CHANGED')
            verify_member({**sample, 'rights_facts': fresh.get('rights_facts'),
                           'rights_envelope_b64': fresh.get('rights_envelope_b64')},
                          workspace=config['workspace'], dataset_id=config['dataset_id'],
                          purpose='local_private_training')
        recheck()
        stage = _stage_pixels(run_id, attempt, config, samples, decoder, inputs,
                              verify_current_member, renew)
        renew()
        out.mkdir(parents=True, exist_ok=False)
        resume_dir = None
        resume_digest = None
        if attempt.get('checkpoint'):
            cp = store.resume_checkpoint(run_id, attempt['epoch'], attempt=attempt['attempt'])
            if not cp or cp['path'] != attempt['checkpoint']:
                raise Conflict('CHECKPOINT_POINTER_MISMATCH')
            resume_dir, resume_digest = cp['path'], cp['digest']
        store.begin_child(run_id, attempt['fence'])
        try:
            child = model_runner.start_training(stage, out, config, resume_dir=resume_dir,
                resume_digest=resume_digest, timeout=min(timeout, 4 * 60 * 60),
                progress_callback=renew)
        except BaseException:
            store.child_spawn_failed(run_id, attempt['fence']); raise
        store.register_child(run_id, attempt['fence'], child)
        _watch(store, attempt, child, out, recheck, timeout)
        child.cleanup()
        observed_exit = exit_receipt(attempt, child)
        child = None
        if store.get(run_id)['state'] != 'succeeded': return 0
        if artifact_pipeline is None: raise Conflict('REAL_ARTIFACT_PIPELINE_REQUIRED')
        artifact_pipeline.finalize_real_artifacts(store, attempt, out, stage, inputs,
                                                  decoder=decoder, model_runner=model_runner)
        return 0
    except BaseException as exc:
        if (getattr(exc, 'code', None) == 'CANCEL_GENERATION_FENCED'
                and getattr(exc, 'state', None) == 'cancel_requested'):
            attempt['observed_cancel_generation'] = exc.current_generation
        if child is not None:
            if child.poll() is None:
                child.kill(); child.wait(timeout=30)
            child.cleanup()
        try:
            retryable = isinstance(exc, (OSError, TimeoutError, subprocess.TimeoutExpired))
            failure_code = _failure_code(exc)
            store.fail(run_id, attempt['attempt'], attempt['fence'], failure_code, retryable,
                digest(canonical({'type': type(exc).__name__, 'code': failure_code})),
                restore_generation=attempt.get('restore_generation'),
                key=command_key(attempt['attempt'], 'ML-Fail'))
        except Conflict:
            pass
        raise
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired: pass
        if model_runner.has_unresolved_container:
            raise Conflict('MODEL_CONTAINER_CLEANUP_REQUIRED')
        observed = attempt.get('observed_cancel_generation')
        if observed is not None:
            store.acknowledge_cancel(run_id, attempt['fence'], observed,
                exit_receipt=observed_exit or exit_receipt(attempt, child),
                key=command_key(attempt['attempt'], 'ML-AcknowledgeCancel'))
        else:
            store.release_slot(run_id, fence=attempt['fence'])


def _check_inference_rights(source, workspace, dataset_id):
    sample = source.get('sample')
    if (type(sample) is not dict or sample.get('split') not in {'train', 'validation'}
            or type(sample.get('id')) is not str):
        raise Conflict('REAL_INFERENCE_SAMPLE_SCOPE')
    for purpose, prefix in (('local_private_training', 'training'), ('model_bundle', 'bundle')):
        adapted = {**sample, 'rights_facts': sample.get(prefix + '_rights_facts'),
                   'rights_envelope_b64': sample.get(prefix + '_rights_envelope_b64')}
        verify_member(adapted, workspace=workspace, dataset_id=dataset_id, purpose=purpose)
    return sample


def _ensure_inference_bundle_available(store, workspace, source_run_id):
    """Fence worker execution against retention transitions on the bundle row."""
    try:
        from .real_retention import bundle_inference_blocked
        blocked = bundle_inference_blocked(store, workspace, source_run_id)
    except Exception:
        raise Conflict('REAL_BUNDLE_RETENTION_UNAVAILABLE') from None
    if blocked:
        raise Conflict('REAL_BUNDLE_RETENTION_LOCKED')


def _trusted_bundle_path(run_id, leaf):
    base = ROOT / 'var/runs' / run_id
    try:
        current = base
        base_info = current.lstat()
        if current.is_symlink() or getattr(base_info, 'st_file_attributes', 0) & 0x400:
            raise ValueError()
        for part in (leaf, 'bundle'):
            current = current / part
            info = current.lstat()
            if current.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError()
        resolved = current.resolve(strict=True)
        resolved.relative_to(base.resolve(strict=True))
        if not resolved.is_dir(): raise ValueError()
        return resolved
    except (OSError, ValueError):
        raise Conflict('REAL_BUNDLE_PATH_BINDING') from None


def execute_real_inference(run_id, store, *, decoder, model_runner, timeout=90):
    """Run a fresh inference job against a verified private real bundle."""
    from .real_run_profile import validate_inference_config
    from .real_bundle import verify_real_bundle
    from .real_pixels import write_rgb8
    import re

    if decoder is None: raise Conflict('REAL_DECODER_REQUIRED')
    current = store.get(run_id)
    if not current or current['state'] != 'queued' or current['config'].get('scope') != REAL_INFER_SCOPE:
        raise Conflict('REAL_INFERENCE_NOT_QUEUED')
    config = validate_inference_config(current['config'], workspace=current['workspace'])
    _ensure_inference_bundle_available(store, current['workspace'], config['run_id'])
    if getattr(decoder, 'image_id', None) != config['decoder_image_id']:
        raise Conflict('REAL_PIXEL_IMAGE_BINDING_MISMATCH')
    if model_runner is None or model_runner.image_id != config['model_image_id']:
        raise Conflict('REAL_MODEL_IMAGE_BINDING_MISMATCH')
    attempt = store.claim_real(run_id, worker_id=os.environ.get('FIELDWORK_WORKER_ID', 'real-worker'),
        key=command_key('real-worker', 'ML-Claim', run_id, current['revision']))
    child = None
    input_root = ROOT / 'var/runs' / run_id / attempt['attempt'] / 'real-inference-input'
    observed_exit = None
    try:
        renew = _lease_renewer(store, attempt, 'ML-InferenceHeartbeat')
        renew()
        source = store.real_inference_input(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'])
        if (source.get('version_id') != config['version_id']
                or source.get('version_digest') != config['version_digest']
                or source.get('bundle_digest') != config['bundle_digest']
                or source.get('sample', {}).get('id') != config['sample_id']):
            raise Conflict('REAL_INFERENCE_BINDING')
        sample = _check_inference_rights(source, config['workspace'], source.get('dataset_id'))
        if sample.get('split') != config['sample_split']:
            raise Conflict('REAL_INFERENCE_SPLIT_BINDING')
        leaf = source.get('artifact_directory')
        if type(leaf) is not str or not re.fullmatch(r'real-artifact-attempt-[0-9]+', leaf):
            raise Conflict('REAL_BUNDLE_PATH_BINDING')
        bundle = _trusted_bundle_path(config['run_id'], leaf)
        verify_real_bundle(bundle, expected_digest=config['bundle_digest'],
            expected_lineage={'version_id': config['version_id'], 'dataset_digest': config['version_digest'],
                              'preprocess_digest': config['preprocess_digest'],
                              'model_image_id': config['model_image_id']})
        media_root = (ROOT / '.local/real-data/media').resolve(strict=True)
        path = real_api._inside_root(sample['media_path'], media_root)
        raw = real_api._read_verified_media(path, sample['sha256'], sample['raw_bytes'])
        decoded, pixels = _decode_with_retry(decoder, raw, renew)
        renew()
        if not decoded.get('ok'): raise Conflict('REAL_MEDIA_DECODE_REJECTED')
        if decoded.get('format') not in {'JPEG', 'PNG', 'WEBP'}:
            raise Conflict('REAL_MEDIA_FORMAT_REJECTED')
        input_root.mkdir(parents=True, exist_ok=False)
        pixel = write_rgb8(input_root, 'inference.rgb', decoded['width'], decoded['height'],
                           pixels, decoded['pixel_sha256'])
        entry = {'id': sample['id'], 'split': sample['split'], **pixel}
        store.begin_child(run_id, attempt['fence'])
        try:
            child = model_runner.start_inference(bundle, input_root, entry, config['bundle_digest'],
                model_image_id=config['model_image_id'], timeout=min(timeout, 4 * 60 * 60),
                progress_callback=renew)
        except BaseException:
            store.child_spawn_failed(run_id, attempt['fence']); raise
        store.register_child(run_id, attempt['fence'], child)
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            renew()
            if time.monotonic() > deadline:
                raise TimeoutError('real inference timeout')
            time.sleep(.05)
        status = child.poll()
        if status != 0:
            raise Conflict('REAL_INFERENCE_CHILD_FAILED')
        stdout = child.read_receipt()
        receipt = json.loads(stdout.decode('utf-8'))
        try:
            from .real_bundle import verify_real_inference_receipt
            verify_real_inference_receipt(receipt, bundle=bundle,
                expected_bundle_digest=config['bundle_digest'], sample_id=sample['id'],
                sample_split=sample['split'], pixel_digest=pixel['decoded_pixel_sha256'])
            if (receipt.get('version_id') != config['version_id']
                    or receipt.get('version_digest') != config['version_digest']):
                raise ValueError('REAL_INFERENCE_VERSION_BINDING')
        except (ValueError, TypeError, KeyError):
            raise Conflict('REAL_INFERENCE_RECEIPT_INVALID') from None
        # Repeat DB object/rights checks after the child exits and before commit.
        final_source = store.real_inference_input(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'])
        _check_inference_rights(final_source, config['workspace'], final_source.get('dataset_id'))
        child.cleanup()
        observed_exit = exit_receipt(attempt, child)
        child = None
        store.complete_real_inference(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'],
            {'receipt_digest': receipt['receipt_digest'], 'bundle_digest': config['bundle_digest'],
             'version_digest': config['version_digest'], 'sample_split': sample['split'],
             'prediction': {k: receipt[k] for k in ('classes', 'probabilities', 'top1')}})
        return 0
    except BaseException as exc:
        if (getattr(exc, 'code', None) == 'CANCEL_GENERATION_FENCED'
                and getattr(exc, 'state', None) == 'cancel_requested'):
            attempt['observed_cancel_generation'] = exc.current_generation
        if child is not None:
            if child.poll() is None:
                child.kill(); child.wait(timeout=30)
            child.cleanup()
        try:
            retryable = isinstance(exc, (OSError, TimeoutError, subprocess.TimeoutExpired))
            store.fail(run_id, attempt['attempt'], attempt['fence'], 'REAL_INFERENCE_FAILED', retryable,
                digest(canonical({'type': type(exc).__name__})),
                restore_generation=attempt.get('restore_generation'),
                key=command_key(attempt['attempt'], 'ML-Fail'))
        except Conflict:
            pass
        raise
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill(); child.wait(timeout=30)
            child.cleanup()
        if model_runner.has_unresolved_container:
            raise Conflict('MODEL_CONTAINER_CLEANUP_REQUIRED')
        observed = attempt.get('observed_cancel_generation')
        if observed is not None:
            store.acknowledge_cancel(run_id, attempt['fence'], observed,
                exit_receipt=observed_exit or exit_receipt(attempt, child),
                key=command_key(attempt['attempt'], 'ML-AcknowledgeCancel'))
        else:
            store.release_slot(run_id, fence=attempt['fence'])


def _check_image_inference_rights(source, config):
    sample = source.get('sample')
    if (type(sample) is not dict or sample.get('split') != 'upload'
            or sample.get('id') != config['input_id']
            or sample.get('source_member') != config['member_id']
            or sample.get('sha256') != config['asset_sha256']
            or sample.get('raw_bytes') != config['asset_bytes']):
        raise Conflict('REAL_IMAGE_INPUT_BINDING')
    for purpose, prefix in (('local_private_training', 'training'), ('model_bundle', 'bundle')):
        adapted = {**sample, 'rights_facts': sample.get(prefix + '_rights_facts'),
                   'rights_envelope_b64': sample.get(prefix + '_rights_envelope_b64')}
        verify_member(adapted, workspace=config['workspace'], dataset_id=config['dataset_id'],
                      purpose=purpose)
    if source.get('protected_match') is True:
        raise Conflict('REAL_IMAGE_PROTECTED_INPUT')
    return sample


def execute_real_image_inference(run_id, store, *, decoder, model_runner, timeout=90):
    """Infer on a new upload matched to current signed rights and a verified bundle."""
    import re
    from .real_run_profile import REAL_IMAGE_INFER_SCOPE, validate_image_inference_config
    from .real_bundle import verify_real_bundle, verify_real_inference_receipt

    if decoder is None: raise Conflict('REAL_DECODER_REQUIRED')
    current = store.get(run_id)
    if (not current or current['state'] != 'queued'
            or current['config'].get('scope') != REAL_IMAGE_INFER_SCOPE):
        raise Conflict('REAL_IMAGE_INFERENCE_NOT_QUEUED')
    config = validate_image_inference_config(current['config'], workspace=current['workspace'])
    _ensure_inference_bundle_available(store, current['workspace'], config['run_id'])
    if getattr(decoder, 'image_id', None) != config['decoder_image_id']:
        raise Conflict('REAL_PIXEL_IMAGE_BINDING_MISMATCH')
    if model_runner is None or model_runner.image_id != config['model_image_id']:
        raise Conflict('REAL_MODEL_IMAGE_BINDING_MISMATCH')
    attempt = store.claim_real(run_id, worker_id=os.environ.get('FIELDWORK_WORKER_ID', 'real-worker'),
        key=command_key('real-worker', 'ML-Claim', run_id, current['revision']))
    child = None; observed_exit = None
    input_root = ROOT / 'var/runs' / run_id / attempt['attempt'] / 'real-image-input'
    upload_root = ROOT / '.local/real-inference-uploads'
    upload_path = upload_root / (config['input_id'] + '.img')
    try:
        renew = _lease_renewer(store, attempt, 'ML-ImageInferenceHeartbeat'); renew()
        source = store.real_image_inference_input(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'])
        if (source.get('version_id') != config['version_id']
                or source.get('version_digest') != config['version_digest']
                or source.get('bundle_digest') != config['bundle_digest']
                or source.get('dataset_id') != config['dataset_id']
                or source.get('upload_key') != config['input_id']):
            raise Conflict('REAL_IMAGE_INFERENCE_BINDING')
        sample = _check_image_inference_rights(source, config)
        from .real_api import _inside_root, _read_verified_media
        path = _inside_root(str(upload_path), upload_root.resolve(strict=True))
        raw = _read_verified_media(path, config['asset_sha256'], config['asset_bytes'])
        decoded, pixels = _decode_with_retry(decoder, raw, renew)
        renew()
        if not decoded.get('ok'): raise Conflict('REAL_MEDIA_DECODE_REJECTED')
        # The DB capability checks raw digest, decoded pixel digest and registered
        # source member against every frozen protected split before model launch.
        source = store.real_image_inference_input(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'], decoded['canonical_pixel_sha256'])
        sample = _check_image_inference_rights(source, config)
        leaf = source.get('artifact_directory')
        if type(leaf) is not str or not re.fullmatch(r'real-artifact-attempt-[0-9]+', leaf):
            raise Conflict('REAL_BUNDLE_PATH_BINDING')
        bundle = _trusted_bundle_path(config['run_id'], leaf)
        verify_real_bundle(bundle, expected_digest=config['bundle_digest'], expected_lineage={
            'version_id': config['version_id'], 'dataset_digest': config['version_digest'],
            'preprocess_digest': config['preprocess_digest'], 'model_image_id': config['model_image_id']})
        input_root.mkdir(parents=True, exist_ok=False)
        pixel = write_rgb8(input_root, 'upload.rgb', decoded['width'], decoded['height'],
                           pixels, decoded['pixel_sha256'])
        entry = {'id': config['input_id'], 'split': 'upload', **pixel}
        store.begin_child(run_id, attempt['fence'])
        try:
            child = model_runner.start_inference(bundle, input_root, entry, config['bundle_digest'],
                model_image_id=config['model_image_id'], scope=REAL_IMAGE_INFER_SCOPE,
                timeout=min(timeout, 90), progress_callback=renew)
        except BaseException:
            store.child_spawn_failed(run_id, attempt['fence']); raise
        store.register_child(run_id, attempt['fence'], child)
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            renew()
            if time.monotonic() > deadline: raise TimeoutError('real image inference timeout')
            time.sleep(.05)
        if child.poll() != 0: raise Conflict('REAL_IMAGE_INFERENCE_CHILD_FAILED')
        receipt = json.loads(child.read_receipt().decode('utf-8'))
        try:
            verify_real_inference_receipt(receipt, bundle=bundle,
                expected_bundle_digest=config['bundle_digest'], sample_id=config['input_id'],
                sample_split='upload', pixel_digest=pixel['decoded_pixel_sha256'],
                expected_scope=REAL_IMAGE_INFER_SCOPE)
            if receipt.get('version_id') != config['version_id'] or receipt.get('version_digest') != config['version_digest']:
                raise ValueError('REAL_IMAGE_INFERENCE_VERSION_BINDING')
        except (ValueError, TypeError, KeyError):
            raise Conflict('REAL_INFERENCE_RECEIPT_INVALID') from None
        # Repeat signed rights, protected-set and DB binding checks after child exit.
        final_source = store.real_image_inference_input(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'], decoded['canonical_pixel_sha256'])
        _check_image_inference_rights(final_source, config)
        child.cleanup(); observed_exit = exit_receipt(attempt, child); child = None
        rights_digests = {
            'training': hashlib.sha256(base64.b64decode(final_source['sample']['training_rights_envelope_b64'], validate=True)).hexdigest(),
            'bundle': hashlib.sha256(base64.b64decode(final_source['sample']['bundle_rights_envelope_b64'], validate=True)).hexdigest(),
        }
        store.complete_real_image_inference(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'], {
                'receipt_digest': receipt['receipt_digest'], 'bundle_digest': config['bundle_digest'],
                'version_digest': config['version_digest'], 'sample_split': 'upload',
                'prediction': {k: receipt[k] for k in ('classes', 'probabilities', 'top1')}},
            decoded['canonical_pixel_sha256'], rights_digests)
        return 0
    except BaseException as exc:
        if (getattr(exc, 'code', None) == 'CANCEL_GENERATION_FENCED'
                and getattr(exc, 'state', None) == 'cancel_requested'):
            attempt['observed_cancel_generation'] = exc.current_generation
        if child is not None:
            if child.poll() is None: child.kill(); child.wait(timeout=30)
            child.cleanup()
        try:
            retryable = isinstance(exc, (OSError, TimeoutError, subprocess.TimeoutExpired))
            store.fail(run_id, attempt['attempt'], attempt['fence'], 'REAL_IMAGE_INFERENCE_FAILED', retryable,
                digest(canonical({'type': type(exc).__name__})),
                restore_generation=attempt.get('restore_generation'), key=command_key(attempt['attempt'], 'ML-Fail'))
        except Conflict: pass
        raise
    finally:
        if child is not None:
            if child.poll() is None: child.kill(); child.wait(timeout=30)
            child.cleanup()
        if model_runner.has_unresolved_container: raise Conflict('MODEL_CONTAINER_CLEANUP_REQUIRED')
        observed = attempt.get('observed_cancel_generation')
        if observed is not None:
            store.acknowledge_cancel(run_id, attempt['fence'], observed,
                exit_receipt=observed_exit or exit_receipt(attempt, child),
                key=command_key(attempt['attempt'], 'ML-AcknowledgeCancel'))


def execute_qualified_image_inference(run_id, store, *, decoder, model_runner, timeout=90):
    """Run fresh-image inference only through the exact R5 qualified release."""
    from .real_run_profile import (QUALIFIED_IMAGE_INFER_SCOPE,
                                   validate_qualified_image_inference_config)
    from .qualified_release import (registered_release, verify_inference_receipt, RELEASE_ID,
                                    archive_qualified_upload)
    from .real_pixels import write_rgb8
    if decoder is None:
        raise Conflict('REAL_DECODER_REQUIRED')
    current = store.get(run_id)
    if (not current or current['state'] != 'queued'
            or current['config'].get('scope') != QUALIFIED_IMAGE_INFER_SCOPE):
        raise Conflict('QUALIFIED_IMAGE_INFERENCE_NOT_QUEUED')
    config = validate_qualified_image_inference_config(current['config'], workspace=current['workspace'])
    release = registered_release(config['release_id'], config['workspace'])
    if not release:
        raise Conflict('QUALIFIED_RELEASE_UNAVAILABLE')
    # WorkerStore is a constrained capability; DB consumed-plan binding is rechecked
    # by qualified_image_inference_input after the fenced claim and before commit.
    if getattr(decoder, 'image_id', None) != config['decoder_image_id']:
        raise Conflict('REAL_PIXEL_IMAGE_BINDING_MISMATCH')
    if model_runner is None or model_runner.image_id != config['model_image_id']:
        raise Conflict('REAL_MODEL_IMAGE_BINDING_MISMATCH')
    attempt = store.claim_real(run_id, worker_id=os.environ.get('FIELDWORK_WORKER_ID', 'real-worker'),
        key=command_key('real-worker', 'ML-Claim', run_id, current['revision']))
    child = None
    observed_exit = None
    input_root = ROOT / 'var/runs' / run_id / attempt['attempt'] / 'qualified-image-input'
    upload_root = ROOT / '.local/real-inference-uploads'
    upload_path = upload_root / (config['input_id'] + '.img')
    try:
        renew = _lease_renewer(store, attempt, 'ML-QualifiedImageInferenceHeartbeat')
        renew()
        source = store.qualified_image_inference_input(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'])
        if (source.get('release_id') != RELEASE_ID
                or source.get('plan_id') != config['plan_id']
                or source.get('plan_result_sha256') != config['plan_result_sha256']
                or source.get('result_record_sha256') != config['result_record_sha256']
                or source.get('model_digest') != config['model_digest']
                or source.get('bundle_digest') != config['bundle_digest']
                or source.get('version_id') != config['version_id']
                or source.get('version_digest') != config['version_digest']
                or source.get('dataset_id') != config['dataset_id']
                or source.get('upload_key') != config['input_id']):
            raise Conflict('QUALIFIED_IMAGE_INFERENCE_BINDING')
        sample = _check_image_inference_rights(source, config)
        from .real_api import _inside_root, _read_verified_media
        path = _inside_root(str(upload_path), upload_root.resolve(strict=True))
        raw = _read_verified_media(path, config['asset_sha256'], config['asset_bytes'])
        decoded, pixels = _decode_with_retry(decoder, raw, renew)
        renew()
        if not decoded.get('ok') or decoded.get('format') not in {'JPEG', 'PNG', 'WEBP'}:
            raise Conflict('REAL_MEDIA_DECODE_REJECTED')
        source = store.qualified_image_inference_input(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'], decoded['canonical_pixel_sha256'])
        sample = _check_image_inference_rights(source, config)
        # Read the fixed release a second time immediately before the model child.
        release = registered_release(config['release_id'], config['workspace'])
        if not release:
            raise Conflict('QUALIFIED_RELEASE_INTEGRITY')
        input_root.mkdir(parents=True, exist_ok=False)
        pixel = write_rgb8(input_root, 'upload.rgb', decoded['width'], decoded['height'],
                           pixels, decoded['pixel_sha256'])
        entry = {'id': config['input_id'], 'split': 'upload', **pixel}
        store.begin_child(run_id, attempt['fence'])
        try:
            child = model_runner.start_qualified_inference(release['bundle'], input_root, entry,
                bundle_digest=config['bundle_digest'], model_digest=config['model_digest'],
                plan_id=config['plan_id'], plan_result_sha256=config['plan_result_sha256'],
                model_image_id=config['model_image_id'], timeout=min(timeout, 90),
                progress_callback=renew)
        except BaseException:
            store.child_spawn_failed(run_id, attempt['fence'])
            raise
        store.register_child(run_id, attempt['fence'], child)
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            renew()
            if time.monotonic() > deadline:
                raise TimeoutError('qualified image inference timeout')
            time.sleep(.05)
        if child.poll() != 0:
            raise Conflict('QUALIFIED_IMAGE_INFERENCE_CHILD_FAILED')
        receipt = json.loads(child.read_receipt().decode('utf-8'))
        try:
            verify_inference_receipt(receipt, pixel_digest=pixel['decoded_pixel_sha256'],
                image_id=config['model_image_id'], input_id=config['input_id'])
        except (ValueError, TypeError, KeyError):
            raise Conflict('QUALIFIED_INFERENCE_RECEIPT_INVALID') from None
        final_source = store.qualified_image_inference_input(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'], decoded['canonical_pixel_sha256'])
        _check_image_inference_rights(final_source, config)
        child.cleanup()
        observed_exit = exit_receipt(attempt, child)
        child = None
        rights_digests = {
            'training': hashlib.sha256(base64.b64decode(final_source['sample']['training_rights_envelope_b64'], validate=True)).hexdigest(),
            'bundle': hashlib.sha256(base64.b64decode(final_source['sample']['bundle_rights_envelope_b64'], validate=True)).hexdigest(),
        }
        store.complete_qualified_image_inference(run_id, attempt['attempt'], attempt['fence'],
            attempt['cancel_generation'], attempt['restore_generation'], {
                'receipt_digest': receipt['receipt_digest'], 'release_id': RELEASE_ID,
                'plan_id': config['plan_id'], 'bundle_digest': config['bundle_digest'],
                'model_digest': config['model_digest'], 'sample_split': 'upload',
                'prediction': {k: receipt[k] for k in ('classes','probabilities','top1')},
                'public_export_authorized': False},
            decoded['canonical_pixel_sha256'], rights_digests)
        archive_qualified_upload(config['input_id'], config['asset_sha256'])
        return 0
    except BaseException as exc:
        if (getattr(exc, 'code', None) == 'CANCEL_GENERATION_FENCED'
                and getattr(exc, 'state', None) == 'cancel_requested'):
            attempt['observed_cancel_generation'] = exc.current_generation
        if child is not None:
            if child.poll() is None:
                child.kill(); child.wait(timeout=30)
            child.cleanup()
        try:
            retryable = isinstance(exc, (OSError, TimeoutError, subprocess.TimeoutExpired))
            store.fail(run_id, attempt['attempt'], attempt['fence'], 'QUALIFIED_INFERENCE_FAILED', retryable,
                digest(canonical({'type': type(exc).__name__})),
                restore_generation=attempt.get('restore_generation'),
                key=command_key(attempt['attempt'], 'ML-Fail'))
        except Conflict:
            pass
        terminal = store.get(run_id)
        if terminal and terminal['state'] in {'failed', 'cancelled'}:
            archive_qualified_upload(config['input_id'], config['asset_sha256'])
        raise
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill(); child.wait(timeout=30)
            child.cleanup()
        if model_runner.has_unresolved_container:
            raise Conflict('MODEL_CONTAINER_CLEANUP_REQUIRED')
        observed = attempt.get('observed_cancel_generation')
        if observed is not None:
            store.acknowledge_cancel(run_id, attempt['fence'], observed,
                exit_receipt=observed_exit or exit_receipt(attempt, child),
                key=command_key(attempt['attempt'], 'ML-AcknowledgeCancel'))
            terminal = store.get(run_id)
            if (terminal and terminal['state'] == 'cancelled'
                    and terminal['config'].get('scope') == QUALIFIED_IMAGE_INFER_SCOPE):
                archive_qualified_upload(terminal['config']['input_id'],
                                         terminal['config']['asset_sha256'])
        else: store.release_slot(run_id, fence=attempt['fence'])

