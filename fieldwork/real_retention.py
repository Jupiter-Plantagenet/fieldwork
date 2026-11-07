"""Bounded retention scanner for verified private Fieldwork model bundles.

Retention archives verified bundle bytes; it never deletes run rows, events,
checkpoints, source data, or the archive copy. A separate ledger preserves the
original bundle and tree digests so an operator can inspect/recover it without
making the old run eligible for model inference again.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import time
from pathlib import Path

from .store import ROOT
from .operator_overrides import required_free_bytes
from .data import canonical, digest

ARCHIVE_ROOT = ROOT / '.local' / 'real-artifact-archive'
RECOVERY_ROOT = ROOT / '.local' / 'real-artifact-recovery'
RUN_ID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
LEAF = re.compile(r'real-artifact-attempt-[0-9]{1,12}')
ARCHIVE_STATES = {'prepared', 'archived', 'recovery_required', 'recovered'}
ACTIVE_STATES = ('queued', 'leased', 'running', 'cancel_requested')
MIN_FREE = required_free_bytes(50 * 1024**3)  # lowered only by the recorded operator space override
MIN_AVAILABLE_RAM = 6 * 1024**3


class RetentionSchemaRequired(RuntimeError):
    """The retained 011 migration has not been applied; scanner fails closed."""


def _advisory_key(workspace: str, run_id: str) -> str:
    return 'fieldwork-artifact-retention:' + workspace + ':' + run_id


def bundle_inference_blocked(store, workspace_id: str, source_run_id: str) -> bool:
    """Fail-closed check used by inference admission and worker start.

    Recovery copies remain operator-only. Any journal row means model reuse is
    blocked, including a recovered bundle.
    """
    capability = getattr(store, 'bundle_inference_blocked', None)
    if callable(capability):
        try:
            return bool(capability(workspace_id, source_run_id))
        except Exception as exc:
            raise RetentionSchemaRequired('REAL_RETENTION_SCHEMA_REQUIRED') from exc
    try:
        with store.connect() as c:
            return bool(c.execute('''SELECT 1 FROM fw_real_artifact_retention
                WHERE workspace=%s AND run=%s''', (workspace_id, source_run_id)).fetchone())
    except Exception as exc:
        raise RetentionSchemaRequired('REAL_RETENTION_SCHEMA_REQUIRED') from exc


def _global_lock_module():
    tools_root = Path(__file__).resolve().parents[1] / 'tools'
    if os.environ.get('PORTFOLIO_TOOLS'):
        tools_root = Path(os.environ['PORTFOLIO_TOOLS'])
    path = tools_root / 'product_lock.py'
    spec = importlib.util.spec_from_file_location('portfolio_product_lock_retention', path)
    if not spec or not spec.loader:
        raise RuntimeError('PRODUCT_LOCK_UNAVAILABLE')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _host_admission() -> dict:
    """Measure host conditions and skip the pass unless the completion gate holds."""
    import psutil
    usage = shutil.disk_usage(ROOT.drive + '\\')
    free = usage.free
    available = psutil.virtual_memory().available
    committed, limit = _commit_bytes()
    ratio = committed / limit if limit else 1.0
    okay = free >= MIN_FREE and available > MIN_AVAILABLE_RAM and ratio < .85
    return {'admitted': okay, 'free_bytes': free, 'available_ram_bytes': available,
            'committed_bytes': committed, 'commit_limit_bytes': limit,
            'commit_ratio': ratio}


def _commit_bytes() -> tuple[int, int]:
    if os.name == 'nt':
        import ctypes
        class PERFORMANCE_INFORMATION(ctypes.Structure):
            _fields_ = [('cb', ctypes.c_size_t), ('CommitTotal', ctypes.c_size_t),
                        ('CommitLimit', ctypes.c_size_t), ('CommitPeak', ctypes.c_size_t),
                        ('PhysicalTotal', ctypes.c_size_t), ('PhysicalAvailable', ctypes.c_size_t),
                        ('SystemCache', ctypes.c_size_t), ('KernelTotal', ctypes.c_size_t),
                        ('KernelPaged', ctypes.c_size_t), ('KernelNonpaged', ctypes.c_size_t),
                        ('PageSize', ctypes.c_size_t), ('HandleCount', ctypes.c_uint),
                        ('ProcessCount', ctypes.c_uint), ('ThreadCount', ctypes.c_uint)]
        info = PERFORMANCE_INFORMATION(); info.cb = ctypes.sizeof(info)
        if not ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(info), info.cb):
            return 0, 0
        return info.CommitTotal * info.PageSize, info.CommitLimit * info.PageSize
    try:
        values = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, raw = line.split(':', 1)
            if key in ('Committed_AS', 'CommitLimit'):
                values[key] = int(raw.strip().split()[0]) * 1024
        return values.get('Committed_AS', 0), values.get('CommitLimit', 0)
    except (OSError, ValueError, IndexError):
        return 0, 0


def _ensure_local_tree(path: Path) -> None:
    root = ROOT.resolve(strict=True)
    absolute = path.absolute()
    absolute.relative_to(root)
    current = root
    for part in absolute.relative_to(root).parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if current.is_symlink() or getattr(info, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
            raise ValueError('RETENTION_REPARSE_POINT')


def _validate_bundle(bundle: Path, expected_digest: str, run: dict,
                     *, allowed_root: Path | None = None) -> tuple[dict, dict, str]:
    from .real_bundle import verify_real_bundle
    run_id = run['id']
    if not RUN_ID.fullmatch(run_id):
        raise ValueError('RETENTION_RUN_ID')
    run_root = allowed_root or (ROOT / 'var' / 'runs' / run_id)
    _ensure_local_tree(run_root)
    _ensure_local_tree(bundle)
    resolved = bundle.resolve(strict=True)
    resolved.relative_to(run_root.resolve(strict=True))
    manifest = verify_real_bundle(bundle, expected_digest=expected_digest,
        expected_lineage={'version_id': run['config']['version_id'],
                          'dataset_digest': run['config']['version_digest'],
                          'model_image_id': run['config']['model_image_id']})
    lineage = json.loads((bundle / 'lineage.json').read_text(encoding='utf-8'))
    entries = []
    total = 0
    for path in sorted(bundle.rglob('*')):
        _ensure_local_tree(path)
        if path.is_dir():
            continue
        relative = path.relative_to(bundle).as_posix()
        stat = path.stat()
        if stat.st_size > 32 * 1024 * 1024:
            raise ValueError('RETENTION_FILE_LIMIT')
        total += stat.st_size
        if total > 64 * 1024 * 1024:
            raise ValueError('RETENTION_BUNDLE_LIMIT')
        entries.append({'name': relative, 'bytes': stat.st_size,
                        'sha256': _hash_file(path)})
    if {entry['name'] for entry in entries} != set(manifest['files']) | {'manifest.json'}:
        raise ValueError('RETENTION_INVENTORY')
    tree_digest = digest(canonical(entries))
    return manifest, {key: lineage[key] for key in (
        'scope', 'version_id', 'dataset_digest', 'checkpoint_digest', 'epoch',
        'model_digest', 'recipe_digest', 'preprocess_digest', 'model_image_id')}, tree_digest


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    before = path.lstat()
    if not path.is_file() or path.is_symlink() or before.st_size > 32 * 1024 * 1024:
        raise ValueError('RETENTION_FILE_TYPE_OR_SIZE')
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError('RETENTION_FILE_CHANGED')
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            h.update(block)
    finally:
        os.close(fd)
    after = path.stat()
    if (after.st_dev, after.st_ino, after.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
        raise ValueError('RETENTION_FILE_CHANGED')
    return h.hexdigest()


def _archive_path(workspace: str, run_id: str, leaf: str) -> Path:
    if not RUN_ID.fullmatch(run_id) or not LEAF.fullmatch(leaf):
        raise ValueError('RETENTION_ARCHIVE_ID')
    workspace_key = hashlib.sha256(workspace.encode('utf-8')).hexdigest()
    run_key = hashlib.sha256(run_id.encode('ascii')).hexdigest()
    return ARCHIVE_ROOT / workspace_key / run_key / leaf / 'bundle'


def _active_inferences(c, workspace: str, run_id: str) -> bool:
    return bool(c.execute('''SELECT 1 FROM fw_runs WHERE workspace=%s
        AND config->>'run_id'=%s
        AND config->>'scope' IN ('real-inference/v1','real-image-inference/v1')
        AND state=ANY(%s) LIMIT 1''', (workspace, run_id, list(ACTIVE_STATES))).fetchone())


def _privacy_hold_active(c, workspace: str, run_id: str) -> bool:
    return bool(c.execute('''SELECT 1 FROM public.fw_privacy_objects
        WHERE object_kind='run_artifact' AND workspace=%s AND object_key=%s
          AND (legal_hold OR pinned) LIMIT 1''',(workspace,run_id)).fetchone())


def _prepare_archive(store, workspace: str, run_id: str, candidate: dict,
                     manifest: dict, lineage: dict, tree_digest: str) -> dict:
    leaf = candidate['artifact_result']['artifact_directory']
    source = ROOT / 'var' / 'runs' / run_id / leaf / 'bundle'
    target = _archive_path(workspace, run_id, leaf)
    if not LEAF.fullmatch(leaf):
        raise ValueError('RETENTION_ARTIFACT_LEAF')
    with store.connect() as c:
        c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))', (_advisory_key(workspace, run_id),))
        current = c.execute('''SELECT r.*,s.retention_days,
                e.created AS verified_at,
                e.created + make_interval(days=>coalesce(s.retention_days,180)) AS expires_at
            FROM fw_runs r LEFT JOIN fw_workspace_settings s ON s.workspace=r.workspace
            JOIN LATERAL (SELECT created,payload FROM fw_events WHERE run=r.id
                AND kind='artifact_verified'
                AND payload->>'bundle_digest'=r.artifact_result->>'bundle_digest'
                ORDER BY seq DESC LIMIT 1) e ON true
            WHERE r.workspace=%s AND r.id=%s FOR UPDATE OF r''', (workspace, run_id)).fetchone()
        current_result = (current.get('artifact_result') or {}) if current else {}
        if (not current or current['state'] != 'succeeded' or current['artifact_status'] != 'verified'
                or current['config'].get('scope') != 'real-training/v1'
                or current_result.get('bundle_digest') != (candidate.get('artifact_result') or {}).get('bundle_digest')
                or current_result.get('artifact_directory') != leaf):
            return {'status': 'skipped', 'reason': 'RUN_CHANGED'}
        if current['expires_at'] > c.execute('SELECT clock_timestamp() AS now').fetchone()['now']:
            return {'status': 'skipped', 'reason': 'RETENTION_NOT_EXPIRED'}
        if _active_inferences(c, workspace, run_id):
            return {'status': 'skipped', 'reason': 'ACTIVE_INFERENCE_REFERENCE'}
        prior = c.execute('SELECT state FROM fw_real_artifact_retention WHERE workspace=%s AND run=%s FOR UPDATE',
                          (workspace, run_id)).fetchone()
        if prior:
            if prior['state'] == 'prepared':
                saved = c.execute('''SELECT archive_tree_sha256 FROM fw_real_artifact_retention
                    WHERE workspace=%s AND run=%s''', (workspace, run_id)).fetchone()
                return {'status': 'resume', 'state': prior['state'], 'source': source,
                        'target': target, 'tree_digest': saved['archive_tree_sha256']}
            return {'status': 'skipped', 'reason': 'RETENTION_JOURNAL_ALREADY_EXISTS',
                    'state': prior['state']}
        c.execute('''INSERT INTO fw_real_artifact_retention(workspace,run,source_leaf,
            bundle_digest,verified_at,retention_days,expires_at,state,source_relpath,
            archive_relpath,archive_tree_sha256,manifest_snapshot,lineage_snapshot)
            VALUES(%s,%s,%s,%s,%s,%s,%s,'prepared',%s,%s,%s,%s,%s)''',
            (workspace, run_id, leaf, current_result['bundle_digest'],
             current['verified_at'], current['retention_days'] or 180, current['expires_at'],
             f'var/runs/{run_id}/{leaf}/bundle',
             target.relative_to(ROOT).as_posix(), tree_digest,
             json.dumps(manifest), json.dumps(lineage)))
    return {'status': 'prepared', 'source': source, 'target': target, 'tree_digest': tree_digest}


def _set_state(store, workspace: str, run_id: str, state: str, reason: str | None = None) -> None:
    with store.connect() as c:
        c.execute('''UPDATE fw_real_artifact_retention SET state=%s,
            archived_at=CASE WHEN %s='archived' THEN clock_timestamp() ELSE archived_at END,
            last_error=%s,updated_at=clock_timestamp()
            WHERE workspace=%s AND run=%s''', (state, state, reason, workspace, run_id))


def _record_recovery_required(store, candidate: dict, reason: str) -> None:
    """Persist an integrity counterexample without pretending bytes were archived."""
    run_id = candidate.get('id')
    workspace = candidate.get('workspace')
    result = candidate.get('artifact_result') or {}
    leaf = result.get('artifact_directory')
    bundle_digest = result.get('bundle_digest')
    if (not workspace or not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id)
            or not isinstance(leaf, str) or not LEAF.fullmatch(leaf)
            or not isinstance(bundle_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', bundle_digest)):
        return
    target = _archive_path(workspace, run_id, leaf)
    with store.connect() as c:
        anchor = c.execute('''SELECT coalesce(s.retention_days,180) AS days,e.created AS verified_at,
                e.created+make_interval(days=>coalesce(s.retention_days,180)) AS expires_at
            FROM fw_runs r LEFT JOIN fw_workspace_settings s ON s.workspace=r.workspace
            JOIN LATERAL (SELECT created,payload FROM fw_events WHERE run=r.id
                AND kind='artifact_verified' AND payload->>'bundle_digest'=r.artifact_result->>'bundle_digest'
                ORDER BY seq DESC LIMIT 1) e ON true
            WHERE r.workspace=%s AND r.id=%s AND r.artifact_status='verified' ''',
            (workspace, run_id)).fetchone()
        if not anchor:
            return
        c.execute('''INSERT INTO fw_real_artifact_retention(workspace,run,source_leaf,
            bundle_digest,verified_at,retention_days,expires_at,state,source_relpath,
            archive_relpath,archive_tree_sha256,manifest_snapshot,lineage_snapshot,last_error)
            VALUES(%s,%s,%s,%s,%s,%s,%s,'recovery_required',%s,%s,NULL,'{}'::jsonb,'{}'::jsonb,%s)
            ON CONFLICT(workspace,run) DO NOTHING''',
            (workspace, run_id, leaf, bundle_digest, anchor['verified_at'], anchor['days'],
             anchor['expires_at'], f'var/runs/{run_id}/{leaf}/bundle',
             target.relative_to(ROOT).as_posix(), reason[:240]))


def _archive_prepared(store, workspace: str, run_id: str, record: dict) -> dict:
    source, target = record['source'], record['target']
    target_root = ARCHIVE_ROOT
    _ensure_local_tree(ROOT / 'var' / 'runs' / run_id)
    _ensure_local_tree(target_root)
    source_exists, target_exists = source.exists(), target.exists()
    if source_exists == target_exists:
        reason = 'SOURCE_AND_ARCHIVE_BOTH_PRESENT' if source_exists else 'SOURCE_AND_ARCHIVE_BOTH_MISSING'
        _set_state(store, workspace, run_id, 'recovery_required', reason)
        return {'status': 'recovery_required', 'reason': reason}
    present = source if source_exists else target
    try:
        run = store.get(run_id, workspace)
        manifest, lineage, actual_tree = _validate_bundle(
            present, run['artifact_result']['bundle_digest'], run,
            allowed_root=ARCHIVE_ROOT if target_exists else None)
        if actual_tree != record['tree_digest']:
            raise ValueError('RETENTION_TREE_DIGEST_CHANGED')
        if source_exists:
            target.parent.mkdir(parents=True, exist_ok=True)
            _ensure_local_tree(target.parent)
            if source.stat().st_dev != target.parent.stat().st_dev:
                raise ValueError('RETENTION_CROSS_VOLUME')
            os.replace(source, target)
        # Read back the moved bundle and verify the closed manifest and tree.
        moved_manifest, _, moved_tree = _validate_bundle(target, run['artifact_result']['bundle_digest'], run,
                                                           allowed_root=ARCHIVE_ROOT)
        if moved_tree != record['tree_digest'] or moved_manifest != manifest:
            raise ValueError('RETENTION_ARCHIVE_READBACK')
        _set_state(store, workspace, run_id, 'archived')
        return {'status': 'archived', 'bundle_digest': run['artifact_result']['bundle_digest'],
                'tree_sha256': actual_tree}
    except Exception as exc:
        _set_state(store, workspace, run_id, 'recovery_required', type(exc).__name__ + ':' + str(exc)[:100])
        return {'status': 'recovery_required', 'reason': type(exc).__name__}


def _existing_prepared(store, max_items: int) -> list[dict]:
    with store.connect() as c:
        return c.execute('''SELECT workspace,run,state,source_relpath,archive_relpath,
            archive_tree_sha256 FROM fw_real_artifact_retention
            WHERE state='prepared' ORDER BY expires_at,run LIMIT %s''', (max_items,)).fetchall()


def _eligible(store, max_items: int) -> list[dict]:
    with store.connect() as c:
        return c.execute('''SELECT r.id,r.workspace,r.config,r.artifact_result,
                coalesce(s.retention_days,180) AS retention_days,
                e.created AS verified_at,
                e.created+make_interval(days=>coalesce(s.retention_days,180)) AS expires_at
            FROM fw_runs r LEFT JOIN fw_workspace_settings s ON s.workspace=r.workspace
            JOIN LATERAL (SELECT created,payload FROM fw_events WHERE run=r.id
                AND kind='artifact_verified'
                AND payload->>'bundle_digest'=r.artifact_result->>'bundle_digest'
                ORDER BY seq DESC LIMIT 1) e ON true
            LEFT JOIN fw_real_artifact_retention a ON a.workspace=r.workspace AND a.run=r.id
            WHERE r.config->>'scope'='real-training/v1' AND r.state='succeeded'
              AND r.artifact_status='verified' AND a.run IS NULL
              AND NOT EXISTS (SELECT 1 FROM public.fw_privacy_objects p
                WHERE p.object_kind='run_artifact' AND p.workspace=r.workspace AND p.object_key=r.id
                  AND (p.legal_hold OR p.pinned))
              AND e.created+make_interval(days=>coalesce(s.retention_days,180))<=clock_timestamp()
            ORDER BY e.created,r.id LIMIT %s''', (max_items,)).fetchall()


def run_retention_pass(store, *, max_items: int = 1, lock_path: Path | None = None) -> dict:
    """Archive at most ``max_items`` verified bundles; busy/low-resource host skips."""
    if type(max_items) is not int or not 1 <= max_items <= 20:
        raise ValueError('RETENTION_BATCH_BOUND')
    host = _host_admission()
    if not host['admitted']:
        return {'status': 'skipped', 'reason': 'HOST_ADMISSION', 'host': host, 'items': []}
    lock = _global_lock_module()
    candidates = list(_existing_prepared(store, max_items))
    if len(candidates) < max_items:
        candidates += list(_eligible(store, max_items - len(candidates)))
    outcomes = []
    for candidate in candidates:
        if not _host_admission()['admitted']:
            outcomes.append({'status': 'skipped', 'reason': 'HOST_ADMISSION_CHANGED'})
            break
        if not lock.acquire('Fieldwork', 'verified-artifact-retention-archive', path=lock_path or lock.DEFAULT):
            outcomes.append({'status': 'skipped', 'reason': 'GLOBAL_PRODUCT_LOCK_BUSY'})
            break
        try:
            workspace = candidate['workspace']; run_id = candidate.get('id', candidate.get('run'))
            with store.connect() as c:
                if _privacy_hold_active(c,workspace,run_id):
                    outcomes.append({'run_id':run_id,'status':'skipped','reason':'PRIVACY_HOLD_OR_PIN'})
                    continue
            if candidate.get('state') == 'prepared':
                record = {'source': ROOT / Path(candidate['source_relpath']),
                          'target': ROOT / Path(candidate['archive_relpath']),
                          'tree_digest': candidate['archive_tree_sha256']}
                outcomes.append({'run_id': run_id, **_archive_prepared(store, workspace, run_id, record)})
                continue
            run_id = candidate['id']
            result = candidate['artifact_result'] or {}
            leaf = result.get('artifact_directory')
            if not isinstance(leaf, str) or not LEAF.fullmatch(leaf):
                outcomes.append({'run_id': run_id, 'status': 'skipped', 'reason': 'ARTIFACT_LEAF_INVALID'})
                continue
            bundle = ROOT / 'var' / 'runs' / run_id / leaf / 'bundle'
            try:
                manifest, lineage, tree_digest = _validate_bundle(bundle, result.get('bundle_digest'), candidate)
                prepared = _prepare_archive(store, workspace, run_id, candidate, manifest, lineage, tree_digest)
                if prepared['status'] == 'prepared':
                    outcomes.append({'run_id': run_id, **_archive_prepared(store, workspace, run_id, prepared)})
                elif prepared['status'] == 'resume':
                    outcomes.append({'run_id': run_id, **_archive_prepared(store, workspace, run_id, prepared)})
                else:
                    outcomes.append({'run_id': run_id, **prepared})
            except Exception as exc:
                try:
                    _record_recovery_required(store, candidate,
                                              'BUNDLE_VERIFICATION:' + type(exc).__name__)
                except Exception:
                    pass
                outcomes.append({'run_id': run_id, 'status': 'recovery_required', 'reason': type(exc).__name__})
        finally:
            lock.release(path=lock_path or lock.DEFAULT)
    return {'status': 'complete', 'host': host, 'items': outcomes}


def recover_archive_for_operator(store, workspace: str, run_id: str) -> dict:
    """Copy an archived bundle to a fixed operator-only recovery area.

    This does not restore its serving path or clear the ledger, so it cannot be
    reused by inference. Original archive bytes are never removed.
    """
    if not RUN_ID.fullmatch(run_id):
        raise ValueError('RETENTION_RUN_ID')
    host = _host_admission()
    if not host['admitted']:
        return {'status': 'skipped', 'reason': 'HOST_ADMISSION', 'host': host}
    lock = _global_lock_module()
    if not lock.acquire('Fieldwork', 'verified-artifact-retention-recovery'):
        return {'status': 'skipped', 'reason': 'GLOBAL_PRODUCT_LOCK_BUSY', 'host': host}
    try:
        with store.connect() as c:
            row = c.execute('''SELECT * FROM fw_real_artifact_retention
                WHERE workspace=%s AND run=%s''', (workspace, run_id)).fetchone()
        if not row or row['state'] not in ('archived', 'recovery_required', 'recovered'):
            raise ValueError('RETENTION_NOT_ARCHIVED')
        source = ROOT / Path(row['archive_relpath'])
        target = RECOVERY_ROOT / hashlib.sha256(workspace.encode()).hexdigest() / hashlib.sha256(run_id.encode()).hexdigest()
        _ensure_local_tree(ARCHIVE_ROOT)
        _ensure_local_tree(source)
        if target.exists():
            raise FileExistsError('RETENTION_RECOVERY_TARGET_EXISTS')
        run = store.get(run_id, workspace)
        manifest, _, actual_tree = _validate_bundle(source, row['bundle_digest'], run,
                                                     allowed_root=ARCHIVE_ROOT)
        if actual_tree != row['archive_tree_sha256']:
            raise ValueError('RETENTION_ARCHIVE_DIGEST_MISMATCH')
        target.parent.mkdir(parents=True, exist_ok=True)
        _ensure_local_tree(target.parent)
        shutil.copytree(source, target, symlinks=False)
        copied_manifest, _, copied_tree = _validate_bundle(target, row['bundle_digest'], run,
                                                              allowed_root=RECOVERY_ROOT)
        if copied_tree != actual_tree or copied_manifest != manifest:
            raise ValueError('RETENTION_RECOVERY_COPY_MISMATCH')
        with store.connect() as c:
            c.execute('''UPDATE fw_real_artifact_retention SET state='recovered',
                recovered_at=clock_timestamp(),updated_at=clock_timestamp()
                WHERE workspace=%s AND run=%s AND state IN ('archived','recovery_required','recovered')''',
                (workspace, run_id))
        return {'status': 'recovered_copy', 'run_id': run_id,
                'archive_sha256': actual_tree, 'manifest_digest': row['bundle_digest'],
                'copy_location': target.relative_to(ROOT).as_posix(), 'model_reuse_allowed': False}
    finally:
        lock.release()


def retention_loop(store, *, stop_event=None, interval_seconds: int = 900) -> None:
    """Bounded recurring lifecycle worker; it starts only when operator launched."""
    if not 60 <= interval_seconds <= 86400:
        raise ValueError('RETENTION_INTERVAL_BOUND')
    from .privacy_lifecycle import privacy_loop
    privacy_loop(store,stop_event=stop_event,interval_seconds=min(interval_seconds,3600))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Fieldwork real artifact retention operator')
    parser.add_argument('--once', action='store_true', help='scan and archive at most one expired bundle')
    parser.add_argument('--loop', action='store_true', help='run opt-in 15 minute scanner loop')
    parser.add_argument('--recover-run', help='copy an archived bundle to operator-only recovery storage')
    parser.add_argument('--workspace', help='workspace identity required with --recover-run')
    args = parser.parse_args(argv)
    if sum((args.once, args.loop, bool(args.recover_run))) != 1:
        parser.error('choose exactly one of --once, --loop, or --recover-run')
    if args.recover_run and not args.workspace:
        parser.error('--workspace is required with --recover-run')
    from .store import Store
    store = Store()
    if args.once:
        print(json.dumps(run_retention_pass(store), sort_keys=True, default=str))
    elif args.loop:
        retention_loop(store)
    else:
        print(json.dumps(recover_archive_for_operator(store, args.workspace, args.recover_run),
                         sort_keys=True, default=str))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
