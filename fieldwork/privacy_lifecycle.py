"""Bounded privacy retention worker.

The worker preserves all source bytes. Expired live inputs are copied into a
private archive, verified, then fenced from the real worker by migration 017.
It never purges catalog, run, event, or evidence rows.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .data import canonical, digest
from .store import ROOT

POLICY = {
    'fresh_inference_input_hours': 24,
    'abandoned_staging_hours': 24,
    'application_log_days': 30,
    'event_replay_days': 7,
    'audit_days': 90,
    'unpinned_artifact_days': 180,
    'workspace_live_access_days_after_delete': 7,
    'backup_expiry_days': 30,
}
MAX_ITEMS = 20
MAX_INPUT_BYTES = 20 * 1024 * 1024
MAX_STAGE_BYTES = 512 * 1024 * 1024
MAX_WORKSPACE_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_PASS_BYTES = 2 * 1024 * 1024 * 1024
ARCHIVE_ROOT = ROOT / '.local' / 'privacy-archive'
DELETION_LEDGER_ROOT = ROOT / '.local' / 'privacy-deletions'


def dataset_retention_eligible(*, protected: bool, legal_hold: bool, pinned: bool) -> bool:
    return not protected and not legal_hold and not pinned


class PrivacySchemaRequired(RuntimeError):
    """Forward migration 017 is not applied; no processing is safe yet."""


class PrivacyDeletionLedgerError(RuntimeError):
    """The external deletion tombstone is unavailable or does not verify."""


def _check_private_path(path: Path) -> None:
    from .scoped_authority import check_private
    try:
        check_private(path)
    except Exception:
        raise ValueError('PRIVACY_PRIVATE_ACL_REQUIRED') from None


def _exclusive_private_file(path: Path):
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0)
    return os.fdopen(os.open(path,flags,0o600),'wb')


def _ensure_private_directory(path: Path) -> None:
    _check_c_ancestry(path,allow_missing_leaf=True,allow_missing_parents=True)
    if path!=ROOT and not path.parent.exists():
        _ensure_private_directory(path.parent)
    path.mkdir(mode=0o700,exist_ok=True)
    _check_c_ancestry(path)
    _check_private_path(path)


def _check_c_ancestry(path: Path, *, allow_missing_leaf: bool = False,
                      allow_missing_parents: bool = False) -> Path:
    """Require a local C: path and check each ancestor before file metadata."""
    absolute = Path(os.path.abspath(str(path)))
    if os.name == 'nt' and (absolute.drive.upper() != 'C:' or str(absolute).startswith('\\\\')):
        raise ValueError('PRIVACY_PATH_OUTSIDE_C')
    root = Path(os.path.abspath(str(ROOT)))
    if os.name == 'nt':
        if root.drive.upper() != 'C:' or str(root).startswith('\\\\'):
            raise ValueError('PRIVACY_PRODUCT_ROOT_OUTSIDE_C')
        current = Path(root.anchor)
        for part in root.parts[1:]:
            current = current / part
            try:
                root_info = current.lstat()
            except OSError:
                raise ValueError('PRIVACY_PRODUCT_ROOT_UNAVAILABLE') from None
            root_attrs = getattr(root_info, 'st_file_attributes', 0)
            if current.is_symlink() or root_attrs & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
                raise ValueError('PRIVACY_PRODUCT_ROOT_REPARSE')
    try:
        relative = absolute.relative_to(root)
    except ValueError:
        raise ValueError('PRIVACY_PATH_OUTSIDE_PRODUCT_ROOT') from None
    current = root
    # Root ancestry is checked before stat/lstat of the target itself.
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if allow_missing_parents:
                break
            if allow_missing_leaf and index == len(relative.parts) - 1:
                break
            raise ValueError('PRIVACY_PATH_UNAVAILABLE') from None
        attrs = getattr(info, 'st_file_attributes', 0)
        if current.is_symlink() or attrs & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
            raise ValueError('PRIVACY_REPARSE_REFUSED')
    return absolute


def _hash_regular(path: Path, *, limit: int = MAX_INPUT_BYTES) -> tuple[str, int]:
    safe = _check_c_ancestry(path)
    before = safe.lstat()
    if not safe.is_file() or before.st_size > limit:
        raise ValueError('PRIVACY_FILE_TYPE_OR_SIZE')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(safe, flags)
    hasher = hashlib.sha256(); total = 0
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError('PRIVACY_FILE_CHANGED')
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise ValueError('PRIVACY_FILE_SIZE_LIMIT')
            hasher.update(block)
    finally:
        os.close(fd)
    after = safe.stat()
    if (after.st_dev, after.st_ino, after.st_size) != (opened.st_dev, opened.st_ino, total):
        raise ValueError('PRIVACY_FILE_CHANGED')
    return hasher.hexdigest(), total


def _deletion_ledger_path(workspace: str) -> Path:
    key=hashlib.sha256(workspace.encode('utf-8')).hexdigest()
    return DELETION_LEDGER_ROOT/(key+'.json')


def _write_deletion_ledger(target: Path, workspace: str, intents: list[dict]) -> None:
    body={'schema':'fieldwork.privacy-deletion/v2','workspace':workspace,'intents':intents}
    payload={**body,'sha256':hashlib.sha256(canonical(body)).hexdigest()}
    encoded=canonical(payload)+b'\n'
    stage=target.with_name('.'+uuid.uuid4().hex+'.writing')
    try:
        with _exclusive_private_file(stage) as stream:
            stream.write(encoded);stream.flush();os.fsync(stream.fileno())
        _check_c_ancestry(stage,allow_missing_leaf=True)
        _check_private_path(stage)
        os.replace(stage,target)
        _check_c_ancestry(target);_check_private_path(target)
    finally:
        stage.unlink(missing_ok=True)


def append_deletion_tombstone(workspace: str, request_id: str, deleted_utc: datetime,
                              *, requested_by: str = 'owner', expected_revision: int = 1,
                              restore_generation: str | None = None) -> None:
    """Durably prepare a revoke intent before its matching DB transaction commits."""
    _ensure_private_directory(ROOT/'.local')
    _ensure_private_directory(DELETION_LEDGER_ROOT)
    _check_c_ancestry(DELETION_LEDGER_ROOT)
    _check_private_path(DELETION_LEDGER_ROOT)
    target=_deletion_ledger_path(workspace)
    _check_c_ancestry(target,allow_missing_leaf=True)
    target.parent.mkdir(parents=True,exist_ok=True)
    _check_c_ancestry(target.parent)
    if target.exists():
        prior=_read_deletion_tombstone(target,workspace)
        for intent in prior['intents']:
            if intent['request_id']==request_id:
                if intent['deleted_utc']==deleted_utc.isoformat() and intent['state'] in ('prepared','committed'):
                    return
                raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_CONFLICT')
        if any(intent['state'] in ('prepared','committed') for intent in prior['intents']):
            raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_CONFLICT')
        intents=list(prior['intents'])
    else:intents=[]
    if len(intents)>=8:raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_LIMIT')
    intents.append({'request_id':request_id,'deleted_utc':deleted_utc.isoformat(),
        'state':'prepared','requested_by':requested_by,'expected_revision':expected_revision,
        'restore_generation':restore_generation,
        'updated_utc':datetime.now(timezone.utc).isoformat()})
    _write_deletion_ledger(target,workspace,intents)


def set_deletion_intent_state(workspace: str, request_id: str, state: str) -> None:
    """Record an append-only intent transition while preserving prior intent evidence."""
    if state!='committed':
        raise ValueError('PRIVACY_DELETE_INTENT_STATE')
    _transition_deletion_intent(workspace,request_id,state)


def _transition_deletion_intent(workspace: str, request_id: str, state: str) -> None:
    path=_deletion_ledger_path(workspace)
    prior=_read_deletion_tombstone(path,workspace)
    intents=list(prior['intents']);found=False
    for index,intent in enumerate(intents):
        if intent['request_id']!=request_id:continue
        found=True
        if intent['state']==state:return
        if intent['state']!='prepared':
            raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_CONFLICT')
        intents[index]={**intent,'state':state,'updated_utc':datetime.now(timezone.utc).isoformat()}
        break
    if not found:raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_MISSING_INTENT')
    _write_deletion_ledger(path,workspace,intents)


def _read_deletion_tombstone(path: Path, workspace: str) -> dict:
    safe=_check_c_ancestry(path)
    try:_check_private_path(safe)
    except ValueError:raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_UNAVAILABLE') from None
    before=safe.lstat()
    if before.st_size>4096 or not safe.is_file():
        raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_INVALID')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
    try:
        fd=os.open(safe,flags)
        try:
            opened=os.fstat(fd)
            data=os.read(fd,4097)
        finally:os.close(fd)
    except OSError:
        raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_UNAVAILABLE') from None
    if len(data)>4096 or (opened.st_dev,opened.st_ino,opened.st_size)!=(before.st_dev,before.st_ino,before.st_size):
        raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_INVALID')
    try:
        payload=json.loads(data)
        if payload.get('schema')=='fieldwork.privacy-deletion/v1':
            body={k:payload[k] for k in ('schema','workspace','request_id','deleted_utc')}
            if payload.get('sha256')!=hashlib.sha256(canonical(body)).hexdigest() or body['workspace']!=workspace:
                raise ValueError()
            intents=[{'request_id':body['request_id'],'deleted_utc':body['deleted_utc'],
                'state':'committed','requested_by':'legacy-tombstone','expected_revision':1,
                'updated_utc':body['deleted_utc']}]
        else:
            body={k:payload[k] for k in ('schema','workspace','intents')}
            if (body['schema']!='fieldwork.privacy-deletion/v2' or body['workspace']!=workspace
                    or payload.get('sha256')!=hashlib.sha256(canonical(body)).hexdigest()
                    or not isinstance(body['intents'],list) or not body['intents'] or len(body['intents'])>8):
                raise ValueError()
            intents=body['intents']
        seen=set()
        for intent in intents:
            request_id=intent['request_id'];deleted_utc=intent['deleted_utc']
            if (str(uuid.UUID(request_id))!=request_id or request_id in seen
                    or intent['state'] not in ('prepared','committed','aborted')
                    or not isinstance(intent['requested_by'],str) or not 1<=len(intent['requested_by'])<=100
                    or type(intent['expected_revision']) is not int or intent['expected_revision']<1):
                raise ValueError()
            generation=intent.get('restore_generation')
            if generation is not None and str(uuid.UUID(generation))!=generation:raise ValueError()
            seen.add(request_id)
            deleted=datetime.fromisoformat(deleted_utc)
            if deleted.tzinfo is None or deleted.utcoffset() is None:raise ValueError()
            updated=datetime.fromisoformat(intent['updated_utc'])
            if updated.tzinfo is None or updated.utcoffset() is None:raise ValueError()
    except (ValueError,TypeError,KeyError,json.JSONDecodeError,UnicodeDecodeError):
        raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_INVALID') from None
    active=[intent for intent in intents if intent['state'] in ('prepared','committed')]
    latest=active[-1] if active else intents[-1]
    return {**payload,'intents':intents,'request_id':latest['request_id'],
        'deleted_utc':latest['deleted_utc'],'state':latest['state']}


def workspace_deleted_locally(workspace: str) -> bool:
    _check_c_ancestry(DELETION_LEDGER_ROOT,allow_missing_leaf=True,allow_missing_parents=True)
    if not DELETION_LEDGER_ROOT.exists():
        return False
    try:_check_private_path(DELETION_LEDGER_ROOT)
    except ValueError:raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_UNAVAILABLE') from None
    path=_deletion_ledger_path(workspace)
    try:
        _check_c_ancestry(path,allow_missing_leaf=True)
    except ValueError:
        raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_UNAVAILABLE') from None
    if not path.exists():
        return False
    try:payload=_read_deletion_tombstone(path,workspace)
    except PrivacyDeletionLedgerError:raise
    except Exception:raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_UNAVAILABLE') from None
    return any(intent['state'] in ('prepared','committed') for intent in payload['intents'])


def cancel_deleted_run(store, workspace: str, run_id: str) -> str:
    """Use the deletion-only SQL capability; ordinary cancel remains RLS fenced."""
    with store.connect() as c:
        ready=c.execute("SELECT to_regprocedure('public.fw_privacy_cancel_deleted_run_v1(text,text)') IS NOT NULL AS ready").fetchone()['ready']
        if not ready:raise PrivacySchemaRequired('PRIVACY_DELETE_CANCEL_SCHEMA_REQUIRED')
        return c.execute('SELECT public.fw_privacy_cancel_deleted_run_v1(%s,%s) AS state',
            (workspace,run_id)).fetchone()['state']


def abort_deletion_intent(store, workspace: str, request_id: str) -> None:
    """Abort only with a verified same-generation DB absence; restores cannot clear it."""
    path=_deletion_ledger_path(workspace)
    payload=_read_deletion_tombstone(path,workspace)
    intent=next((row for row in payload['intents'] if row['request_id']==request_id),None)
    if not intent or intent['state']!='prepared' or not intent.get('restore_generation'):
        raise PrivacyDeletionLedgerError('PRIVACY_DELETE_ABORT_UNVERIFIED')
    with store.connect() as c:
        c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                  ('fieldwork-workspace-delete:' + workspace,))
        ready=c.execute("""SELECT to_regclass('public.fw_privacy_workspace_tombstones') IS NOT NULL AS tombstones,
            to_regclass('public.fw_control') IS NOT NULL AS control""").fetchone()
        if not ready['tombstones'] or not ready['control']:
            raise PrivacyDeletionLedgerError('PRIVACY_DELETE_ABORT_UNVERIFIED')
        deleted=c.execute('''SELECT 1 FROM public.fw_privacy_workspace_tombstones
            WHERE workspace=%s OR request_id=%s''',(workspace,request_id)).fetchone()
        generation=c.execute('SELECT restore_generation::text FROM public.fw_control WHERE id=1 FOR UPDATE').fetchone()
        if deleted or not generation or generation['restore_generation']!=intent['restore_generation']:
            raise PrivacyDeletionLedgerError('PRIVACY_DELETE_ABORT_UNVERIFIED')
        # Keep the deletion lock and restore-generation row lock until the
        # append-only abort marker is durable, preventing a stale reconciler from
        # completing the same prepared request concurrently.
        _transition_deletion_intent(workspace,request_id,'aborted')


def reconcile_deletion_intents(store, *, max_items: int = MAX_ITEMS, workspace: str | None = None) -> dict:
    """Resolve prepared external intents against DB tombstones, fail-closed on uncertainty.

    A missing DB row is completed from the previously owner-authorized durable
    intent. This covers transaction rollback and response loss without clearing
    the external marker or reopening access.
    """
    if type(max_items) is not int or not 1<=max_items<=MAX_ITEMS:
        raise ValueError('PRIVACY_BATCH_BOUND')
    _check_c_ancestry(DELETION_LEDGER_ROOT,allow_missing_leaf=True,allow_missing_parents=True)
    if not DELETION_LEDGER_ROOT.exists():return {'status':'complete','prepared_seen':0,'committed':0}
    committed=0;prepared_seen=0;processed=0;errors=[]
    paths=([_deletion_ledger_path(workspace)] if workspace else sorted(DELETION_LEDGER_ROOT.glob('*.json')))
    for path in paths:
        if processed>=max_items:break
        _check_c_ancestry(path)
        if not path.exists():continue
        _check_private_path(path)
        if path.lstat().st_size>4096:raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_INVALID')
        payload_raw=json.loads(path.read_bytes())
        payload=_read_deletion_tombstone(path,payload_raw['workspace'])
        for intent in payload['intents']:
            if intent['state']!='prepared':continue
            if processed>=max_items:break
            prepared_seen+=1;processed+=1
            try:
                deleted=datetime.fromisoformat(intent['deleted_utc'])
                with store.connect() as c:
                    # Serialize recovery with owner-authorized deletion requests and
                    # other reconcilers for this workspace. The API uses the same key.
                    c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                              ('fieldwork-workspace-delete:' + payload['workspace'],))
                    current=_read_deletion_tombstone(path,payload['workspace'])
                    current_intent=next((row for row in current['intents']
                        if row['request_id']==intent['request_id']),None)
                    if not current_intent or current_intent['state']!='prepared':
                        continue
                    if (current_intent['deleted_utc']!=intent['deleted_utc']
                            or current_intent['expected_revision']!=intent['expected_revision']):
                        raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_CONFLICT')
                    ready=c.execute("SELECT to_regclass('public.fw_privacy_workspace_tombstones') IS NOT NULL AS ready").fetchone()['ready']
                    if not ready:raise PrivacySchemaRequired('PRIVACY_LIFECYCLE_SCHEMA_REQUIRED')
                    prior=c.execute('''SELECT request_id,deleted_utc FROM public.fw_privacy_workspace_tombstones
                        WHERE workspace=%s FOR UPDATE''',(payload['workspace'],)).fetchone()
                    if prior:
                        if str(prior['request_id'])!=intent['request_id'] or prior['deleted_utc']!=deleted:
                            raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_CONFLICT')
                    else:
                        c.execute('''INSERT INTO public.fw_privacy_workspace_tombstones(workspace,request_id,
                            requested_by,expected_settings_revision,deleted_utc,archive_due_utc)
                            VALUES(%s,%s,%s,%s,%s,%s+interval '7 days')''',
                            (payload['workspace'],intent['request_id'],intent['requested_by'],
                             intent['expected_revision'],deleted,deleted))
                        c.execute('''DELETE FROM public.fw_sessions WHERE name IN
                            (SELECT name FROM public.fw_accounts WHERE workspace=%s)''',(payload['workspace'],))
                set_deletion_intent_state(payload['workspace'],intent['request_id'],'committed')
                committed+=1
                with store.connect() as c:
                    active=c.execute('''SELECT id FROM public.fw_runs WHERE workspace=%s
                        AND state IN ('queued','interrupted','leased','running') ORDER BY id LIMIT %s''',
                        (payload['workspace'],MAX_ITEMS)).fetchall()
                for run in active:
                    try:cancel_deleted_run(store,payload['workspace'],run['id'])
                    except Exception:errors.append('PRIVACY_DELETE_CANCEL_PENDING')
            except PrivacySchemaRequired:
                raise
            except Exception:
                # Unknown DB commit/connectivity state keeps the local marker prepared.
                errors.append('PRIVACY_DELETE_RECONCILE_PENDING')
    return {'status':'recovery_required' if errors else 'complete','prepared_seen':prepared_seen,
            'committed':committed,'pending_or_failed':len(errors),'error_codes':sorted(set(errors))}


def export_deletion_ledger(destination: Path) -> dict:
    """Copy the minimal revoke ledger into a backup and seal its inventory."""
    destination=Path(destination)
    _check_c_ancestry(destination,allow_missing_leaf=True)
    destination.mkdir(parents=True,exist_ok=True,mode=0o700)
    _check_c_ancestry(destination)
    _check_private_path(destination)
    files=[]
    _check_c_ancestry(DELETION_LEDGER_ROOT,allow_missing_leaf=True,allow_missing_parents=True)
    if DELETION_LEDGER_ROOT.exists():
        _check_c_ancestry(DELETION_LEDGER_ROOT)
        for index,path in enumerate(sorted(DELETION_LEDGER_ROOT.glob('*.json'))):
            if index>=100_000:raise ValueError('PRIVACY_DELETE_LEDGER_LIMIT')
            _check_c_ancestry(path)
            info=path.lstat()
            if path.is_symlink() or getattr(info,'st_file_attributes',0)&0x400 or not path.is_file() or info.st_size>4096:
                raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_INVALID')
            data=path.read_bytes()
            try:
                payload=json.loads(data)
                workspace=payload['workspace']
                _read_deletion_tombstone(path,workspace)
            except (ValueError,KeyError,TypeError,json.JSONDecodeError):
                raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_INVALID') from None
            if path.name!=_deletion_ledger_path(workspace).name:
                raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_INVALID')
            target=destination/path.name
            with _exclusive_private_file(target) as stream:
                stream.write(data);stream.flush();os.fsync(stream.fileno())
            _check_private_path(target)
            files.append({'name':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    body={'schema':'fieldwork.privacy-deletion-backup/v1','files':files}
    manifest={**body,'sha256':hashlib.sha256(canonical(body)).hexdigest()}
    manifest_path=destination/'manifest.json'
    with _exclusive_private_file(manifest_path) as stream:
        stream.write(canonical(manifest)+b'\n');stream.flush();os.fsync(stream.fileno())
    return {'path':str(destination.relative_to(ROOT).as_posix()),'file_count':len(files),
            'manifest_sha256':hashlib.sha256(canonical(manifest)).hexdigest()}


def verify_apply_deletion_ledger(store, source: Path) -> dict:
    """Validate a backup package, then apply missing revoke markers before restore access."""
    source=Path(source)
    _check_c_ancestry(source)
    _check_private_path(source)
    manifest_path=_check_c_ancestry(source/'manifest.json')
    _check_private_path(manifest_path)
    raw=manifest_path.read_bytes()
    try:
        manifest=json.loads(raw)
        body={key:manifest[key] for key in ('schema','files')}
        if body['schema']!='fieldwork.privacy-deletion-backup/v1' or manifest.get('sha256')!=hashlib.sha256(canonical(body)).hexdigest():
            raise ValueError()
        entries=body['files']
        if not isinstance(entries,list) or len(entries)>100_000:raise ValueError()
        imported={}
        for item in entries:
            name=item['name']
            if not re.fullmatch(r'[0-9a-f]{64}\.json',name):raise ValueError()
            path=_check_c_ancestry(source/name)
            _check_private_path(path)
            info=path.lstat()
            if path.is_symlink() or getattr(info,'st_file_attributes',0)&0x400 or not path.is_file() or info.st_size>4096:raise ValueError()
            data=path.read_bytes()
            if len(data)!=item['bytes'] or hashlib.sha256(data).hexdigest()!=item['sha256']:raise ValueError()
            payload=json.loads(data)
            workspace=payload['workspace']
            verified=_read_deletion_tombstone(path,workspace)
            if _deletion_ledger_path(workspace).name!=name:raise ValueError()
            if workspace in imported:raise ValueError()
            active=[intent for intent in verified['intents'] if intent['state'] in ('prepared','committed')]
            if active:imported[workspace]=active[-1]
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError,UnicodeDecodeError):
        raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_INVALID') from None
    for workspace,item in imported.items():
        append_deletion_tombstone(workspace,item['request_id'],datetime.fromisoformat(item['deleted_utc']),
            requested_by=item['requested_by'],expected_revision=item['expected_revision'])
    with store.connect() as c:
        ready=c.execute("SELECT to_regclass('public.fw_privacy_workspace_tombstones') IS NOT NULL AS ready").fetchone()['ready']
        if not ready:raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_SCHEMA_REQUIRED')
        existing=c.execute('''SELECT workspace,request_id,deleted_utc FROM public.fw_privacy_workspace_tombstones''').fetchall()
        existing_by_workspace={row['workspace']:row for row in existing}
        # A database tombstone missing from the separately protected package means
        # backup/restore did not preserve the external revocation authority.
        if any(row['workspace'] not in imported for row in existing):
            raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_INCOMPLETE')
        for workspace,item in imported.items():
            prior=existing_by_workspace.get(workspace)
            request_id=item['request_id']
            deleted=datetime.fromisoformat(item['deleted_utc'])
            if prior:
                if str(prior['request_id'])!=request_id or prior['deleted_utc']!=deleted:
                    raise PrivacyDeletionLedgerError('PRIVACY_DELETE_LEDGER_CONFLICT')
                continue
            c.execute('''INSERT INTO public.fw_privacy_workspace_tombstones(workspace,request_id,
                requested_by,expected_settings_revision,deleted_utc,archive_due_utc)
                VALUES(%s,%s,%s,%s,%s,%s+interval '7 days')''',
                (workspace,request_id,item['requested_by'],item['expected_revision'],deleted,deleted))
            c.execute('''DELETE FROM public.fw_sessions WHERE name IN
                (SELECT name FROM public.fw_accounts WHERE workspace=%s)''',(workspace,))
    for workspace,item in imported.items():
        set_deletion_intent_state(workspace,item['request_id'],'committed')
    return {'status':'verified_and_applied','ledger_entries':len(imported),
            'restored_tombstones':sum(workspace not in existing_by_workspace for workspace in imported)}


def _archive_object(row: dict, *, object_kind: str, object_key: str,
                    expected_hash: str | None, expected_bytes: int | None,
                    max_bytes: int) -> dict:
    if not row.get('workspace') or not object_key or object_kind not in (
            'fresh_inference_input','abandoned_staging','workspace_deleted_blob','application_log',
            'dataset_artifact','run_artifact','filesystem_staging','backup_artifact'):
        raise ValueError('PRIVACY_OBJECT_IDENTITY')
    source = _check_c_ancestry(Path(row['source_path']))
    archive_key = hashlib.sha256((row['workspace'] + ':' + object_key).encode()).hexdigest()
    suffix = {'fresh_inference_input':'.img','abandoned_staging':'.archive',
              'workspace_deleted_blob':'.blob','application_log':'.log','dataset_artifact':'.blob',
              'run_artifact':'.checkpoint','filesystem_staging':'.stage','backup_artifact':'.backup'}[object_kind]
    # Keep new archive files in a flat class directory. The prior two-level key
    # path could exceed Win32 MAX_PATH once a staging name and product root were
    # included. Shorter existing v1 archive paths are still reused in place.
    target = ARCHIVE_ROOT / object_kind / (archive_key + suffix)
    source_hash, source_bytes = _hash_regular(source, limit=max_bytes)
    if expected_hash and source_hash != expected_hash:
        raise ValueError('PRIVACY_SOURCE_DIGEST_MISMATCH')
    if expected_bytes is not None and source_bytes != expected_bytes:
        raise ValueError('PRIVACY_SOURCE_SIZE_MISMATCH')
    legacy_target = ARCHIVE_ROOT / object_kind / archive_key[:2] / archive_key / (archive_key + suffix)
    if len(str(legacy_target)) < 260:
        _check_c_ancestry(legacy_target,allow_missing_leaf=True,allow_missing_parents=True)
        if legacy_target.exists():
            _check_private_path(legacy_target)
            if _hash_regular(legacy_target,limit=max_bytes)!=(source_hash,source_bytes):
                raise ValueError('PRIVACY_ARCHIVE_CONFLICT')
            return {'archive_path':str(legacy_target.relative_to(ROOT).as_posix()),
                    'content_sha256':source_hash,'content_bytes':source_bytes}
    for directory in (ARCHIVE_ROOT,ARCHIVE_ROOT/object_kind):
        _ensure_private_directory(directory)
    _check_c_ancestry(target.parent)
    _check_private_path(target.parent)
    _check_c_ancestry(target,allow_missing_leaf=True)
    stage = target.with_name('.' + uuid.uuid4().hex + '.writing')
    try:
        with source.open('rb') as inp, _exclusive_private_file(stage) as out:
            shutil.copyfileobj(inp, out, 1024 * 1024)
            out.flush(); os.fsync(out.fileno())
        _check_c_ancestry(stage)
        _check_private_path(stage)
        archived_hash, archived_bytes = _hash_regular(stage, limit=max_bytes)
        if (archived_hash, archived_bytes) != (source_hash, source_bytes):
            raise ValueError('PRIVACY_ARCHIVE_READBACK_MISMATCH')
        if target.exists():
            prior = _hash_regular(target, limit=max_bytes)
            if prior != (source_hash, source_bytes):
                raise ValueError('PRIVACY_ARCHIVE_CONFLICT')
            stage.unlink()
        else:
            os.replace(stage, target)
        _check_c_ancestry(target)
        _check_private_path(target)
        return {'archive_path': str(target.relative_to(ROOT).as_posix()),
                'content_sha256': source_hash, 'content_bytes': source_bytes}
    finally:
        stage.unlink(missing_ok=True)


def _archive_fresh_input(row: dict) -> dict:
    input_id = str(row.get('input_id') or '')
    return _archive_object(row, object_kind='fresh_inference_input', object_key=input_id,
                           expected_hash=row.get('asset_sha256'), expected_bytes=row.get('asset_bytes'),
                           max_bytes=MAX_INPUT_BYTES)


def _archive_deleted_bundle(row: dict) -> dict:
    """Privately move a previously verified bundle as one opaque directory.

    This deliberately does not enumerate or open bundle members: frozen or
    sealed media/manifests must remain opaque to the privacy lifecycle worker.
    The digest comes from the earlier artifact_verified record.
    """
    source=_check_c_ancestry(Path(row['source_path']))
    info=source.lstat()
    if not source.is_dir() or source.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
        raise ValueError('PRIVACY_BUNDLE_TYPE')
    digest_value=row.get('expected_sha256')
    if not isinstance(digest_value,str) or not re.fullmatch(r'[0-9a-f]{64}',digest_value):
        raise ValueError('PRIVACY_BUNDLE_ANCHOR_REQUIRED')
    archive_key=hashlib.sha256((row['workspace']+':'+row['object_key']).encode()).hexdigest()
    target=ARCHIVE_ROOT/'workspace_deleted_bundle'/archive_key[:2]/archive_key/'bundle'
    for directory in (ARCHIVE_ROOT,ARCHIVE_ROOT/'workspace_deleted_bundle',
                      ARCHIVE_ROOT/'workspace_deleted_bundle'/archive_key[:2],target.parent):
        _ensure_private_directory(directory)
    _check_c_ancestry(target,allow_missing_leaf=True)
    _check_private_path(target.parent)
    if target.exists():
        raise ValueError('PRIVACY_BUNDLE_ARCHIVE_CONFLICT')
    if source.stat().st_dev!=target.parent.stat().st_dev:
        raise ValueError('PRIVACY_BUNDLE_CROSS_VOLUME')
    os.replace(source,target)
    _check_c_ancestry(target)
    archived=target.lstat()
    if not target.is_dir() or target.is_symlink() or getattr(archived,'st_file_attributes',0)&0x400:
        raise ValueError('PRIVACY_BUNDLE_ARCHIVE_READBACK')
    _check_private_path(target)
    if source.exists():
        raise ValueError('PRIVACY_BUNDLE_SOURCE_REMAINS')
    return {'archive_path':str(target.relative_to(ROOT).as_posix()),
            'content_sha256':digest_value,'content_bytes':None,'live_bytes_retired':True}


def _archive_checkpoint_directory(row: dict) -> dict:
    """Move an immutable checkpoint tree opaquely using its stored digest anchor."""
    source=_check_c_ancestry(Path(row['source_path']))
    info=source.lstat()
    if not source.is_dir() or source.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
        raise ValueError('PRIVACY_CHECKPOINT_TYPE')
    digest_value=row.get('expected_sha256')
    if not isinstance(digest_value,str) or not re.fullmatch(r'[0-9a-f]{64}',digest_value):
        raise ValueError('PRIVACY_CHECKPOINT_ANCHOR_REQUIRED')
    archive_key=hashlib.sha256((row['workspace']+':'+row['object_key']).encode()).hexdigest()
    target=ARCHIVE_ROOT/'run_artifact'/archive_key[:2]/archive_key/'checkpoint'
    for directory in (ARCHIVE_ROOT,ARCHIVE_ROOT/'run_artifact',
                      ARCHIVE_ROOT/'run_artifact'/archive_key[:2],target.parent):
        _ensure_private_directory(directory)
    _check_c_ancestry(target,allow_missing_leaf=True)
    _check_private_path(target.parent)
    if target.exists():raise ValueError('PRIVACY_CHECKPOINT_ARCHIVE_CONFLICT')
    if source.stat().st_dev!=target.parent.stat().st_dev:
        raise ValueError('PRIVACY_CHECKPOINT_CROSS_VOLUME')
    os.replace(source,target)
    _check_c_ancestry(target)
    archived=target.lstat()
    if not target.is_dir() or target.is_symlink() or getattr(archived,'st_file_attributes',0)&0x400:
        raise ValueError('PRIVACY_CHECKPOINT_ARCHIVE_READBACK')
    _check_private_path(target)
    if source.exists():raise ValueError('PRIVACY_CHECKPOINT_SOURCE_REMAINS')
    return {'archive_path':str(target.relative_to(ROOT).as_posix()),
            'content_sha256':digest_value,'content_bytes':None,'live_bytes_retired':True}


def _register_expired_app_logs(store, *, max_entries: int = 100) -> int:
    """Archive only the fixed private app and managed intake worker log files."""
    api_log_name=lambda name: name=='api-live.log' or bool(re.fullmatch(r'api-live\.log\.\d{4}-\d{2}-\d{2}(?:\.[0-9a-f]{32})?',name))
    roots=((ROOT/'.local'/'app-logs',None,True),
           (ROOT/'var',api_log_name,False),
           (ROOT/'.local'/'real-data'/'activation',{'worker.stdout.log'},True))
    cutoff=time.time()-POLICY['application_log_days']*86400
    registered=0
    for log_root,allowed_names,recursive in roots:
        _check_c_ancestry(log_root,allow_missing_leaf=True,allow_missing_parents=True)
        if not log_root.exists():continue
        candidates=log_root.rglob('*') if recursive else log_root.iterdir()
        for path in candidates:
            if allowed_names is not None:
                allowed=allowed_names(path.name) if callable(allowed_names) else path.name in allowed_names
                if not allowed:continue
            _check_c_ancestry(path)
            info=path.lstat()
            if path.is_symlink() or getattr(info,'st_file_attributes',0)&0x400 or not path.is_file():continue
            _check_private_path(path)
            if info.st_mtime>cutoff:continue
            relative=path.relative_to(log_root).as_posix()
            object_key=hashlib.sha256((str(log_root.relative_to(ROOT))+':'+relative+':'+str(info.st_mtime_ns)+':'+str(info.st_size)).encode()).hexdigest()
            created=datetime.fromtimestamp(info.st_mtime,timezone.utc)
            with store.connect() as c:
                inserted=c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    created_utc,expires_utc) VALUES('application_log','__system__',%s,%s,%s,%s)
                    ON CONFLICT(object_kind,workspace,object_key) DO NOTHING RETURNING object_key''',
                    (object_key,str(path),created,created+timedelta(days=POLICY['application_log_days']))).fetchone()
            if not inserted:continue
            registered+=1
            if registered>=max_entries:return registered
    return registered


def _register_expired_backups(store, *, max_entries: int = 100) -> int:
    """Register managed snapshot files from their recorded creation timestamp."""
    root=ROOT/'var'/'snapshots'
    _check_c_ancestry(root,allow_missing_leaf=True,allow_missing_parents=True)
    if not root.exists():return 0
    _check_private_path(root)
    registered=0;referenced=set()
    for index,receipt_path in enumerate(sorted(root.glob('*.json'))):
        if index>=max_entries:break
        _check_c_ancestry(receipt_path)
        info=receipt_path.lstat()
        if receipt_path.is_symlink() or getattr(info,'st_file_attributes',0)&0x400 or not receipt_path.is_file() or info.st_size>1024*1024:continue
        try:
            receipt=json.loads(receipt_path.read_bytes())
            created=datetime.strptime(receipt['at'],'%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
            descriptors=[receipt['db'],receipt['globals']]
            paths=[]
            for descriptor in descriptors:
                rel=Path(descriptor['path'])
                candidate=_check_c_ancestry(ROOT/rel)
                candidate.relative_to(root)
                if not rel.name.endswith(('.dump','-globals.sql')):raise ValueError('PRIVACY_BACKUP_INVENTORY')
                if not candidate.is_file() or candidate.stat().st_size!=int(descriptor['bytes']):raise ValueError('PRIVACY_BACKUP_INVENTORY')
                if not re.fullmatch(r'[0-9a-f]{64}',descriptor['sha256']):raise ValueError('PRIVACY_BACKUP_INVENTORY')
                paths.append((candidate,descriptor['sha256'],int(descriptor['bytes'])))
            if len(paths)!=2:raise ValueError('PRIVACY_BACKUP_INVENTORY')
            ledger=receipt.get('privacy_deletion_ledger')
            if isinstance(ledger,dict) and isinstance(ledger.get('path'),str):
                package=_check_c_ancestry(ROOT/ledger['path']);package.relative_to(root)
                manifest_path=_check_c_ancestry(package/'manifest.json')
                manifest_raw=manifest_path.read_bytes()
                manifest=json.loads(manifest_raw)
                manifest_body={'schema':manifest['schema'],'files':manifest['files']}
                if (manifest.get('sha256')!=hashlib.sha256(canonical(manifest_body)).hexdigest()
                        or hashlib.sha256(canonical(manifest)).hexdigest()!=ledger.get('manifest_sha256')
                        or len(manifest['files'])!=ledger.get('file_count')):
                    raise ValueError('PRIVACY_BACKUP_LEDGER_MANIFEST')
                ledger_files={item['name']:item for item in manifest['files']}
                inventory_complete=True
                for child in sorted(package.iterdir()):
                    _check_c_ancestry(child)
                    if child.name=='manifest.json':
                        paths.append((child,hashlib.sha256(manifest_raw).hexdigest(),len(manifest_raw)))
                    elif child.is_file() and child.name in ledger_files:
                        item=ledger_files.pop(child.name)
                        child_key=hashlib.sha256((child.relative_to(root).as_posix()+':'+created.isoformat()).encode()).hexdigest()
                        with store.connect() as c:
                            already_registered=c.execute('''SELECT 1 FROM public.fw_privacy_objects
                                WHERE object_kind='backup_artifact' AND workspace='__system__' AND object_key=%s''',
                                (child_key,)).fetchone()
                        if already_registered:
                            continue
                        if registered+len(paths)>=max_entries:
                            inventory_complete=False
                            ledger_files[item['name']]=item
                            break
                        if child.stat().st_size!=item['bytes'] or _hash_regular(child,limit=4096)[0]!=item['sha256']:
                            raise ValueError('PRIVACY_BACKUP_LEDGER_CONTENT')
                        paths.append((child,item['sha256'],item['bytes']))
                    else:
                        raise ValueError('PRIVACY_BACKUP_LEDGER_INVENTORY')
                if ledger_files and inventory_complete:
                    raise ValueError('PRIVACY_BACKUP_LEDGER_INCOMPLETE')
            # The receipt is part of the inventory and is archived with both blobs.
            paths.append((receipt_path,None,None))
        except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError):
            continue
        for candidate,expected,expected_bytes in paths:
            referenced.add(candidate)
            relative=candidate.relative_to(root).as_posix()
            key=hashlib.sha256((relative+':'+created.isoformat()).encode()).hexdigest()
            with store.connect() as c:
                inserted=c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    created_utc,expires_utc,expected_sha256,expected_bytes)
                    VALUES('backup_artifact','__system__',%s,%s,%s,%s+interval '30 days',%s,%s)
                    ON CONFLICT(object_kind,workspace,object_key) DO NOTHING RETURNING object_key''',
                    (key,str(candidate),created,created,expected,expected_bytes)).fetchone()
            if not inserted:continue
            registered+=1
            if registered>=max_entries:return registered
    cutoff=time.time()-POLICY['backup_expiry_days']*86400
    for pattern in ('*.dump','*-globals.sql','*.json'):
        for candidate in sorted(root.glob(pattern)):
            if candidate in referenced:continue
            _check_c_ancestry(candidate)
            info=candidate.lstat()
            if candidate.is_symlink() or getattr(info,'st_file_attributes',0)&0x400 or not candidate.is_file() or info.st_mtime>cutoff:continue
            created=datetime.fromtimestamp(info.st_mtime,timezone.utc)
            relative=candidate.relative_to(root).as_posix()
            key=hashlib.sha256(('unreceipted:'+relative+':'+str(info.st_mtime_ns)+':'+str(info.st_size)).encode()).hexdigest()
            with store.connect() as c:
                inserted=c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    created_utc,expires_utc,expected_sha256,expected_bytes)
                    VALUES('backup_artifact','__system__',%s,%s,%s,%s+interval '30 days',NULL,%s)
                    ON CONFLICT(object_kind,workspace,object_key) DO NOTHING RETURNING object_key''',
                    (key,str(candidate),created,created,info.st_size)).fetchone()
            if not inserted:continue
            registered+=1
            if registered>=max_entries:return registered
    return registered


def _register_abandoned_upload_stages(store, *, max_entries: int = 100) -> int:
    roots=(ROOT/'.local'/'real-data'/'uploads',ROOT/'.local'/'real-inference-uploads')
    registered=0; cutoff=time.time()-POLICY['abandoned_staging_hours']*3600
    for root in roots:
        _check_c_ancestry(root,allow_missing_leaf=True,allow_missing_parents=True)
        if not root.exists():continue
        for path in root.rglob('*'):
            _check_c_ancestry(path)
            info=path.lstat()
            if path.is_symlink() or getattr(info,'st_file_attributes',0)&0x400 or not path.is_file():continue
            name=path.name
            candidate=(name.endswith('.uploading') or name.startswith('.upload-') and name.endswith('.part')
                       or name.endswith('.archive') or name.endswith('.img'))
            if not candidate or info.st_mtime>cutoff:continue
            path_text=str(path)
            with store.connect() as c:
                if name.endswith('.archive') and c.execute('''SELECT 1 FROM public.fw_real_intake_queue
                    WHERE archive_path=%s''',(path_text,)).fetchone():continue
                if name.endswith('.img'):
                    input_id=path.stem
                    if c.execute('''SELECT 1 FROM public.fw_real_image_inputs
                        WHERE input_id::text=%s''',(input_id,)).fetchone():continue
            relative=path.relative_to(root).as_posix()
            key=hashlib.sha256((str(root.name)+':'+relative+':'+str(info.st_mtime_ns)+':'+str(info.st_size)).encode()).hexdigest()
            created=datetime.fromtimestamp(info.st_mtime,timezone.utc)
            with store.connect() as c:
                inserted=c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    created_utc,expires_utc) VALUES('filesystem_staging','__system__',%s,%s,%s,%s)
                    ON CONFLICT(object_kind,workspace,object_key) DO NOTHING RETURNING object_key''',
                    (key,path_text,created,created+timedelta(hours=POLICY['abandoned_staging_hours']))).fetchone()
            if not inserted:continue
            registered+=1
    return registered


def _retire_live_source(row: dict, receipt: dict) -> bool:
    """Remove only the live directory entry after the verified archive is durable."""
    if row.get('shared_live') or row.get('legal_hold') or row.get('pinned'):
        return False
    source = _check_c_ancestry(Path(row['source_path']), allow_missing_leaf=True)
    if not source.exists():
        return True
    if _hash_regular(source, limit=max(int(row.get('max_bytes') or MAX_STAGE_BYTES), MAX_INPUT_BYTES)) != (
            receipt['content_sha256'], receipt['content_bytes']):
        raise ValueError('PRIVACY_SOURCE_CHANGED_BEFORE_RETIRE')
    source.unlink()
    return True


def _register_already_archived(c, workspace: str, object_key: str, source_path: str, deleted_utc,
                               prior_kind: str, prior_key: str) -> bool:
    """A live blob already moved by its own retention class is recorded as archived, not missing."""
    return c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
        created_utc,expires_utc,state,archive_path,content_sha256,content_bytes,live_bytes_retired,legal_hold,pinned)
        SELECT 'workspace_deleted_blob',%s,%s,%s,%s,%s,'archived',p.archive_path,p.content_sha256,p.content_bytes,
          true,p.legal_hold,p.pinned FROM public.fw_privacy_objects p
        WHERE p.object_kind=%s AND p.workspace=%s AND p.object_key=%s AND p.state='archived' AND p.live_bytes_retired
        ON CONFLICT(object_kind,workspace,object_key) DO NOTHING RETURNING object_key''',
        (workspace,object_key,source_path,deleted_utc,deleted_utc,prior_kind,workspace,prior_key)).fetchone() is not None


def _register_workspace_delete_files(store, tombstone: dict, *, max_entries: int = 100) -> int:
    workspace = tombstone['workspace']
    with store.connect() as c:
        paths = c.execute('''SELECT 'dataset_media' AS kind,s.sample_id::text AS key,s.media_path AS path,
                  s.raw_sha256 AS sha,s.raw_bytes AS bytes,
                  EXISTS(SELECT 1 FROM public.fw_samples other WHERE other.media_path=s.media_path
                    AND other.workspace<>s.workspace) AS shared,
                  coalesce(p.legal_hold,false) AS legal_hold,coalesce(p.pinned,false) AS pinned
            FROM public.fw_samples s LEFT JOIN public.fw_privacy_objects p
              ON p.object_kind='dataset_artifact' AND p.workspace=s.workspace AND p.object_key=s.sample_id::text
            WHERE s.workspace=%s AND NOT EXISTS (SELECT 1 FROM public.fw_privacy_objects done
              WHERE done.object_kind='workspace_deleted_blob' AND done.workspace=s.workspace
                AND done.object_key='dataset_media:'||s.sample_id::text)
            UNION ALL
            SELECT 'checkpoint' AS kind,cp.run||':'||cp.epoch::text AS key,cp.path AS path,
                  cp.digest AS sha,NULL::bigint AS bytes,false AS shared,
                  coalesce(p.legal_hold,false) AS legal_hold,coalesce(p.pinned,false) AS pinned
            FROM public.fw_checkpoints cp JOIN public.fw_runs r ON r.id=cp.run
            LEFT JOIN public.fw_privacy_objects p ON p.object_kind='run_artifact' AND p.workspace=r.workspace
              AND p.object_key=cp.run||':'||cp.epoch::text
            WHERE r.workspace=%s AND NOT EXISTS (SELECT 1 FROM public.fw_privacy_objects done
              WHERE done.object_kind='workspace_deleted_blob' AND done.workspace=r.workspace
                AND done.object_key='checkpoint:'||cp.run||':'||cp.epoch::text)
            LIMIT %s''', (workspace,workspace,max_entries)).fetchall()
        # Fresh inference and intake uploads have fixed app-owned roots. Reuse
        # already-created privacy ledger rows when available.
        for row in paths:
            _check_c_ancestry(Path(row['path']),allow_missing_leaf=True)
            if not Path(row['path']).exists():
                object_key=row['kind']+':'+row['key']
                if _register_already_archived(c,workspace,object_key,row['path'],tombstone['deleted_utc'],
                        'dataset_artifact' if row['kind']=='dataset_media' else 'run_artifact',row['key']):
                    continue
                c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    created_utc,expires_utc,state,last_error_code) VALUES('workspace_deleted_blob',%s,%s,%s,%s,%s,
                    'recovery_required','PRIVACY_SOURCE_NOT_PRESENT')
                    ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                    (workspace,object_key,row['path'],tombstone['deleted_utc'],tombstone['deleted_utc']))
                # Keep the missing marker in the ledger so subsequent passes do
                # not repeatedly select it or claim that its bytes were archived.
                continue
            object_key = row['kind'] + ':' + row['key']
            c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                created_utc,expires_utc,shared_live,legal_hold,pinned) VALUES('workspace_deleted_blob',%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                (workspace,object_key,row['path'],tombstone['deleted_utc'],tombstone['deleted_utc'],
                 row['shared'],row['legal_hold'],row['pinned']))
        registered=len(paths)
        inputs = c.execute('''SELECT i.input_id::text AS id,r.config->>'scope' AS scope
            FROM public.fw_real_image_inputs i JOIN public.fw_runs r ON r.id=i.run AND r.workspace=i.workspace
            WHERE i.workspace=%s AND NOT EXISTS (SELECT 1 FROM public.fw_privacy_objects done
              WHERE done.object_kind='workspace_deleted_blob' AND done.workspace=i.workspace
                AND done.object_key='fresh_input:'||i.input_id::text) LIMIT %s''',
            (workspace,max(0,max_entries-registered))).fetchall()
        for item in inputs:
            upload_root = (ROOT / '.local' / 'real-inference-uploads'
                if item['scope'] == 'qualified-release-image-inference/v1'
                else ROOT / '.local' / 'real-data' / 'uploads')
            source_path = upload_root / (item['id'] + '.img')
            _check_c_ancestry(source_path,allow_missing_leaf=True)
            if not source_path.exists():
                object_key='fresh_input:'+item['id']
                if not _register_already_archived(c,workspace,object_key,str(source_path),tombstone['deleted_utc'],
                                                  'fresh_inference_input',item['id']):
                    c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                        created_utc,expires_utc,state,last_error_code) VALUES('workspace_deleted_blob',%s,%s,%s,%s,%s,
                        'recovery_required','PRIVACY_SOURCE_NOT_PRESENT')
                        ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                        (workspace,object_key,str(source_path),tombstone['deleted_utc'],tombstone['deleted_utc']))
                registered+=1
                continue
            object_key = 'fresh_input:' + item['id']
            c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                created_utc,expires_utc,legal_hold,pinned) VALUES('workspace_deleted_blob',%s,%s,%s,%s,%s,
                coalesce((SELECT legal_hold FROM public.fw_privacy_objects WHERE object_kind='fresh_inference_input'
                  AND workspace=%s AND object_key=%s),false),
                coalesce((SELECT pinned FROM public.fw_privacy_objects WHERE object_kind='fresh_inference_input'
                  AND workspace=%s AND object_key=%s),false))
                ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                (workspace,object_key,str(source_path),tombstone['deleted_utc'],tombstone['deleted_utc'],
                 workspace,item['id'],workspace,item['id']))
            registered+=1
        queues = c.execute('''SELECT intake_id::text AS id,archive_path FROM public.fw_real_intake_queue
            WHERE workspace=%s AND NOT EXISTS (SELECT 1 FROM public.fw_privacy_objects done
              WHERE done.object_kind='workspace_deleted_blob' AND done.workspace=fw_real_intake_queue.workspace
                AND done.object_key='intake:'||fw_real_intake_queue.intake_id::text) LIMIT %s''',
            (workspace,max(0,max_entries-registered))).fetchall()
        for item in queues:
            _check_c_ancestry(Path(item['archive_path']),allow_missing_leaf=True)
            if not Path(item['archive_path']).exists():
                object_key='intake:'+item['id']
                if not _register_already_archived(c,workspace,object_key,item['archive_path'],tombstone['deleted_utc'],
                                                  'abandoned_staging',item['id']):
                    c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                        created_utc,expires_utc,state,last_error_code) VALUES('workspace_deleted_blob',%s,%s,%s,%s,%s,
                        'recovery_required','PRIVACY_SOURCE_NOT_PRESENT')
                        ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                        (workspace,object_key,item['archive_path'],tombstone['deleted_utc'],tombstone['deleted_utc']))
                registered+=1
                continue
            object_key = 'intake:' + item['id']
            c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                created_utc,expires_utc,legal_hold,pinned) VALUES('workspace_deleted_blob',%s,%s,%s,%s,%s,
                coalesce((SELECT legal_hold FROM public.fw_privacy_objects WHERE object_kind='abandoned_staging'
                  AND workspace=%s AND object_key=%s),false),
                coalesce((SELECT pinned FROM public.fw_privacy_objects WHERE object_kind='abandoned_staging'
                  AND workspace=%s AND object_key=%s),false))
                ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                (workspace,object_key,item['archive_path'],tombstone['deleted_utc'],tombstone['deleted_utc'],
                 workspace,item['id'],workspace,item['id']))
            registered+=1
    with store.connect() as c:
        runs = c.execute('''SELECT r.id,r.artifact_result FROM public.fw_runs r
            LEFT JOIN public.fw_privacy_workspace_bundle_scan scan ON scan.workspace=r.workspace AND scan.run=r.id
            WHERE r.workspace=%s AND coalesce(scan.complete,false)=false
              AND r.artifact_status='verified' AND r.config->>'scope'='real-training/v1'
              AND NOT EXISTS (SELECT 1 FROM public.fw_real_artifact_retention a
                WHERE a.workspace=r.workspace AND a.run=r.id AND a.state IN ('archived','recovered'))
            ORDER BY r.id LIMIT %s''',(workspace,max_entries)).fetchall()
    for run in runs:
        if registered>=max_entries:break
        result=run['artifact_result'] or {}; leaf=result.get('artifact_directory')
        if not isinstance(leaf,str) or not re.fullmatch(r'real-artifact-attempt-[0-9]{1,12}',leaf):
            continue
        bundle=ROOT/'var'/'runs'/run['id']/leaf/'bundle'
        try:
            _check_c_ancestry(bundle)
            # Treat the verified bundle as one opaque directory. No member names,
            # manifests or media are enumerated or opened by this scanner.
            with store.connect() as c:
                c.execute('''INSERT INTO public.fw_privacy_workspace_bundle_scan(workspace,run)
                    VALUES(%s,%s) ON CONFLICT(workspace,run) DO NOTHING''',(workspace,run['id']))
                c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    expected_sha256,created_utc,expires_utc) VALUES('workspace_deleted_blob',%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                    (workspace,'bundle:'+run['id'],str(bundle),result.get('bundle_digest'),
                     tombstone['deleted_utc'],tombstone['deleted_utc']))
                c.execute('''UPDATE public.fw_privacy_workspace_bundle_scan SET complete=true,
                    after_relative_path='',last_error_code=NULL,updated_utc=clock_timestamp()
                    WHERE workspace=%s AND run=%s''',(workspace,run['id']))
            registered+=1
        except Exception:
            # Leave workspace archiving visibly incomplete; no tree is declared done
            # when a path cannot be safely inventoried.
            with store.connect() as c:
                c.execute('''UPDATE public.fw_privacy_workspace_tombstones SET state='recovery_required',
                    last_error_code='PRIVACY_WORKSPACE_INVENTORY_FAILED',updated_utc=clock_timestamp()
                    WHERE workspace=%s AND state IN ('revoked','archiving')''',(workspace,))
            raise ValueError('PRIVACY_WORKSPACE_INVENTORY_FAILED') from None
    return registered


def _run_workspace_deletion_pass(store, *, max_items: int, max_bytes: int = MAX_PASS_BYTES) -> dict:
    with store.connect() as c:
        tombstones = c.execute('''SELECT workspace,deleted_utc,archive_due_utc,state FROM
            public.fw_privacy_workspace_tombstones WHERE state IN ('revoked','archiving','recovery_required')
            ORDER BY archive_due_utc,workspace LIMIT %s''',(max_items,)).fetchall()
    out=[];pass_bytes=0
    for tombstone in tombstones:
        with store.connect() as c:
            active=c.execute('''SELECT id FROM public.fw_runs WHERE workspace=%s
                AND state IN ('queued','leased','running','cancel_requested') ORDER BY id LIMIT 20''',
                (tombstone['workspace'],)).fetchall()
        for run in active:
            try:cancel_deleted_run(store,tombstone['workspace'],run['id'])
            except Exception:pass
        if active:
            out.append({'workspace_digest':hashlib.sha256(tombstone['workspace'].encode()).hexdigest(),
                        'state':'cancellation_pending','active_count':len(active)})
            continue
        _register_workspace_delete_files(store,tombstone,max_entries=max_items*10)
        with store.connect() as c:
            c.execute('''UPDATE public.fw_privacy_workspace_tombstones SET state='archiving',
                last_error_code=NULL,updated_utc=clock_timestamp() WHERE workspace=%s AND state IN ('revoked','recovery_required') ''',
                (tombstone['workspace'],))
            objects=c.execute('''SELECT p.object_kind,p.workspace,p.object_key,p.source_path,
                    p.content_sha256 AS expected_sha256,p.content_bytes AS expected_bytes,p.shared_live,
                p.legal_hold,p.pinned,
                    2147483648::bigint AS max_bytes FROM public.fw_privacy_objects p
                WHERE p.workspace=%s AND p.object_kind='workspace_deleted_blob' AND p.state='active'
                  AND p.expires_utc<=clock_timestamp()
                ORDER BY p.object_key LIMIT %s''',(tombstone['workspace'],max_items)).fetchall()
        archived=0; failures=0
        for row in objects:
            remaining=max_bytes-pass_bytes
            if remaining<=0:break
            try:
                source=_check_c_ancestry(Path(row['source_path']))
                opaque_bundle=(row['object_key'].startswith('bundle:') and source.is_dir())
                size=0 if opaque_bundle else source.stat().st_size
                if not opaque_bundle and size>MAX_WORKSPACE_FILE_BYTES:
                    failures+=1
                    with store.connect() as c:
                        c.execute('''UPDATE public.fw_privacy_objects SET state='recovery_required',
                            last_error_code='PRIVACY_FILE_SIZE_LIMIT',updated_utc=clock_timestamp()
                            WHERE object_kind=%s AND workspace=%s AND object_key=%s AND state='active' ''',
                            (row['object_kind'],row['workspace'],row['object_key']))
                    continue
                if size>remaining:break
                from .real_retention import _global_lock_module
                product_lock=_global_lock_module()
                if not product_lock.acquire('Fieldwork','workspace-deletion-archive',path=product_lock.DEFAULT):
                    failures+=1
                    continue
                try:
                    if opaque_bundle:
                        receipt=_archive_deleted_bundle(row)
                    else:
                        receipt=_archive_object(row,object_kind='workspace_deleted_blob',object_key=row['object_key'],
                            expected_hash=row['expected_sha256'],expected_bytes=row['expected_bytes'],
                            max_bytes=min(MAX_WORKSPACE_FILE_BYTES,remaining))
                        pass_bytes+=receipt['content_bytes']
                    with store.connect() as c:
                        c.execute('''UPDATE public.fw_privacy_objects SET state='archived',archive_path=%s,
                            content_sha256=%s,content_bytes=%s,updated_utc=clock_timestamp()
                            WHERE object_kind=%s AND workspace=%s AND object_key=%s AND state='active'
                            RETURNING state''',
                            (receipt['archive_path'],receipt['content_sha256'],receipt['content_bytes'],
                             row['object_kind'],row['workspace'],row['object_key']))
                    retired=bool(receipt.get('live_bytes_retired')) if opaque_bundle else _retire_live_source(row,receipt)
                    if retired:
                        with store.connect() as c:
                            c.execute('''UPDATE public.fw_privacy_objects SET live_bytes_retired=true,
                                updated_utc=clock_timestamp() WHERE object_kind=%s AND workspace=%s
                                AND object_key=%s AND state='archived' ''',
                                (row['object_kind'],row['workspace'],row['object_key']))
                finally:
                    product_lock.release()
                archived+=1
            except Exception:
                failures+=1
                with store.connect() as c:
                    c.execute('''UPDATE public.fw_privacy_objects SET state='recovery_required',
                        last_error_code='PRIVACY_ARCHIVE_FAILED',updated_utc=clock_timestamp()
                        WHERE object_kind=%s AND workspace=%s AND object_key=%s AND state='active' ''',
                        (row['object_kind'],row['workspace'],row['object_key']))
        with store.connect() as c:
            pending=c.execute('''SELECT count(*) AS n FROM public.fw_privacy_objects
                WHERE workspace=%s AND object_kind='workspace_deleted_blob'
                  AND (state<>'archived' OR (NOT live_bytes_retired AND NOT shared_live AND NOT legal_hold AND NOT pinned))''',
                (tombstone['workspace'],)).fetchone()['n']
            recovery_rows=c.execute('''SELECT count(*) AS n FROM public.fw_privacy_objects
                WHERE workspace=%s AND object_kind='workspace_deleted_blob' AND state='recovery_required' ''',
                (tombstone['workspace'],)).fetchone()['n']
            still_active=c.execute('''SELECT count(*) AS n FROM public.fw_runs WHERE workspace=%s
                AND state IN ('queued','leased','running','cancel_requested')''',(tombstone['workspace'],)).fetchone()['n']
            if not pending and not still_active and not failures:
                c.execute('''UPDATE public.fw_privacy_workspace_tombstones SET state='archived',
                    updated_utc=clock_timestamp(),archived_objects=archived_objects+%s
                    WHERE workspace=%s AND state='archiving' ''',(archived,tombstone['workspace']))
            elif failures or recovery_rows:
                c.execute('''UPDATE public.fw_privacy_workspace_tombstones SET state='recovery_required',
                    last_error_code='PRIVACY_RECOVERY_REQUIRED',updated_utc=clock_timestamp()
                    WHERE workspace=%s AND state='archiving' ''',(tombstone['workspace'],))
        out.append({'workspace_digest':hashlib.sha256(tombstone['workspace'].encode()).hexdigest(),
                    'state':'archiving','archived_this_pass':archived,'pending_objects':pending,
                    'recovery_required':failures+recovery_rows})
    return {'processed_workspaces':len(tombstones),'bytes_processed':pass_bytes,'items':out}


def run_privacy_pass(store, *, max_items: int = MAX_ITEMS) -> dict:
    """Archive a bounded batch of expired fresh inputs; never delete source bytes."""
    if type(max_items) is not int or not 1 <= max_items <= MAX_ITEMS:
        raise ValueError('PRIVACY_BATCH_BOUND')
    from .real_retention import _host_admission
    host = _host_admission()
    if not host['admitted']:
        try:
            with store.connect() as c:
                c.execute('''UPDATE public.fw_privacy_scanner_status SET last_started_utc=clock_timestamp(),
                    last_error_code='HOST_ADMISSION',updated_utc=clock_timestamp() WHERE id=true''')
        except Exception:
            pass
        return {'status': 'skipped', 'reason': 'HOST_ADMISSION', 'host': host,
                'processed': 0}
    now = datetime.now(timezone.utc)
    try:
        deletion_reconciliation=reconcile_deletion_intents(store,max_items=max_items)
        registered_logs=_register_expired_app_logs(store,max_entries=max_items)
        registered_stages=_register_abandoned_upload_stages(store,max_entries=max_items)
        registered_backups=_register_expired_backups(store,max_entries=max_items)
        with store.connect() as c:
            c.execute("SELECT 1 FROM public.fw_privacy_scanner_status WHERE id=true")
            fresh = c.execute('''SELECT i.workspace,i.input_id,i.created_utc,r.config->>'scope' AS scope
                FROM public.fw_real_image_inputs i JOIN public.fw_runs r ON r.id=i.run
                  AND r.workspace=i.workspace
                WHERE i.created_utc <= clock_timestamp()-interval '24 hours'
                ORDER BY i.created_utc,i.workspace,i.input_id LIMIT %s''', (max_items,)).fetchall()
            for item in fresh:
                if item['scope'] == 'qualified-release-image-inference/v1':
                    upload_root = ROOT / '.local' / 'real-inference-uploads'
                elif item['scope'] == 'real-image-inference/v1':
                    upload_root = ROOT / '.local' / 'real-data' / 'uploads'
                else:
                    continue
                c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    created_utc,expires_utc,state) VALUES('fresh_inference_input',%s,%s,%s,%s,
                    %s+interval '24 hours','active') ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                    (item['workspace'], str(item['input_id']), str(upload_root / (str(item['input_id']) + '.img')),
                     item['created_utc'], item['created_utc']))
            staging = c.execute('''SELECT workspace,intake_id,archive_path,archive_sha256,archive_bytes,
                    created_utc,state,lease_until FROM public.fw_real_intake_queue
                WHERE created_utc<=clock_timestamp()-interval '24 hours'
                  AND (state<>'running' OR lease_until<=clock_timestamp())
                ORDER BY created_utc,workspace,intake_id LIMIT %s''', (max_items,)).fetchall()
            for item in staging:
                c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    created_utc,expires_utc,state) VALUES('abandoned_staging',%s,%s,%s,%s,
                    %s+interval '24 hours','active') ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                    (item['workspace'], str(item['intake_id']), item['archive_path'],
                     item['created_utc'], item['created_utc']))
            datasets=c.execute('''SELECT s.workspace,s.sample_id::text AS object_key,s.media_path,
                    s.raw_sha256,s.raw_bytes,s.created_utc,s.privacy_protected,
                    coalesce(p.legal_hold,false) AS legal_hold,coalesce(p.pinned,false) AS pinned,
                    EXISTS(SELECT 1 FROM public.fw_samples other WHERE other.media_path=s.media_path
                      AND other.workspace<>s.workspace) AS shared_live
                FROM public.fw_samples s LEFT JOIN public.fw_privacy_objects p
                  ON p.object_kind='dataset_artifact' AND p.workspace=s.workspace AND p.object_key=s.sample_id::text
                WHERE s.created_utc<=clock_timestamp()-interval '180 days'
                  AND NOT s.privacy_protected AND NOT coalesce(p.legal_hold,false)
                  AND NOT coalesce(p.pinned,false)
                ORDER BY s.created_utc,s.workspace,s.sample_id LIMIT %s''',(max_items,)).fetchall()
            for item in datasets:
                if not dataset_retention_eligible(protected=item['privacy_protected'],
                        legal_hold=item['legal_hold'],pinned=item['pinned']):
                    continue
                c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    created_utc,expires_utc,shared_live) VALUES('dataset_artifact',%s,%s,%s,%s,
                    %s+interval '180 days',%s) ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                    (item['workspace'],item['object_key'],item['media_path'],item['created_utc'],
                     item['created_utc'],item['shared_live']))
            checkpoints=c.execute('''SELECT r.workspace,cp.run,cp.epoch,cp.path,cp.digest,e.created AS created_utc
                FROM public.fw_checkpoints cp JOIN public.fw_runs r ON r.id=cp.run
                JOIN LATERAL (SELECT created FROM public.fw_events e WHERE e.run=cp.run
                    AND e.kind='epoch_committed' AND e.payload->>'epoch'=cp.epoch::text
                    ORDER BY seq DESC LIMIT 1) e ON true
                WHERE r.config->>'scope'='real-training/v1'
                  AND r.state IN ('succeeded','failed','cancelled')
                  AND e.created<=clock_timestamp()-interval '180 days'
                ORDER BY e.created,cp.run,cp.epoch LIMIT %s''',(max_items,)).fetchall()
            for item in checkpoints:
                object_key=f"{item['run']}:{item['epoch']}"
                c.execute('''INSERT INTO public.fw_privacy_objects(object_kind,workspace,object_key,source_path,
                    created_utc,expires_utc,legal_hold,pinned)
                    VALUES('run_artifact',%s,%s,%s,%s,%s+interval '180 days',
                      coalesce((SELECT legal_hold FROM public.fw_privacy_objects
                        WHERE object_kind='run_artifact' AND workspace=%s AND object_key=%s),false),
                      coalesce((SELECT pinned FROM public.fw_privacy_objects
                        WHERE object_kind='run_artifact' AND workspace=%s AND object_key=%s),false))
                    ON CONFLICT(object_kind,workspace,object_key) DO NOTHING''',
                    (item['workspace'],object_key,item['path'],item['created_utc'],item['created_utc'],
                     item['workspace'],item['run'],item['workspace'],item['run']))
            fresh_rows = c.execute('''SELECT p.object_kind,p.workspace,p.object_key,
                       i.asset_sha256 AS expected_sha256,i.asset_bytes AS expected_bytes,
                       r.config->>'scope' AS scope,
                       20971520::bigint AS max_bytes
                FROM public.fw_privacy_objects p
                JOIN public.fw_real_image_inputs i ON i.workspace=p.workspace AND i.input_id::text=p.object_key
                JOIN public.fw_runs r ON r.id=i.run AND r.workspace=i.workspace
                WHERE p.object_kind='fresh_inference_input' AND p.state='active'
                  AND p.expires_utc<=clock_timestamp() AND NOT p.legal_hold AND NOT p.pinned
                  AND r.config->>'scope' IN ('real-image-inference/v1','qualified-release-image-inference/v1')
                ORDER BY p.expires_utc,p.workspace,p.object_key LIMIT %s''', (max_items,)).fetchall()
            stage_rows = c.execute('''SELECT p.object_kind,p.workspace,p.object_key,q.archive_path AS source_path,
                       q.archive_sha256 AS expected_sha256,q.archive_bytes AS expected_bytes,
                       536870912::bigint AS max_bytes
                FROM public.fw_privacy_objects p
                JOIN public.fw_real_intake_queue q ON q.workspace=p.workspace AND q.intake_id::text=p.object_key
                WHERE p.object_kind='abandoned_staging' AND p.state='active'
                  AND p.expires_utc<=clock_timestamp() AND NOT p.legal_hold AND NOT p.pinned
                  AND (q.state<>'running' OR q.lease_until<=clock_timestamp())
                ORDER BY p.expires_utc,p.workspace,p.object_key LIMIT %s''', (max_items,)).fetchall()
            dataset_rows = c.execute('''SELECT p.object_kind,p.workspace,p.object_key,s.media_path AS source_path,
                       s.raw_sha256 AS expected_sha256,s.raw_bytes AS expected_bytes,
                       20971520::bigint AS max_bytes,p.shared_live,p.legal_hold,p.pinned
                FROM public.fw_privacy_objects p JOIN public.fw_samples s
                  ON s.workspace=p.workspace AND s.sample_id::text=p.object_key
                WHERE p.object_kind='dataset_artifact' AND p.state='active'
                  AND p.expires_utc<=clock_timestamp() AND NOT p.legal_hold AND NOT p.pinned
                  AND NOT s.privacy_protected
                ORDER BY p.expires_utc,p.workspace,p.object_key LIMIT %s''',(max_items,)).fetchall()
            checkpoint_rows = c.execute('''SELECT p.object_kind,p.workspace,p.object_key,cp.path AS source_path,
                       cp.digest AS expected_sha256,NULL::bigint AS expected_bytes,
                       2147483648::bigint AS max_bytes,false AS shared_live,p.legal_hold,p.pinned
                FROM public.fw_privacy_objects p JOIN public.fw_checkpoints cp
                  ON cp.run||':'||cp.epoch::text=p.object_key
                JOIN public.fw_runs r ON r.id=cp.run AND r.workspace=p.workspace
                WHERE p.object_kind='run_artifact' AND p.state='active'
                  AND p.expires_utc<=clock_timestamp() AND NOT p.legal_hold AND NOT p.pinned
                  AND r.state IN ('succeeded','failed','cancelled')
                ORDER BY p.expires_utc,p.workspace,p.object_key LIMIT %s''',(max_items,)).fetchall()
            fresh_rows=[dict(row,source_path=str((ROOT/'.local'/'real-inference-uploads'
                if row['scope']=='qualified-release-image-inference/v1'
                else ROOT/'.local'/'real-data'/'uploads')/(row['object_key']+'.img'))) for row in fresh_rows]
            rows = sorted([*fresh_rows, *stage_rows,*dataset_rows,*checkpoint_rows], key=lambda row: (row['object_kind'], row['workspace'], row['object_key']))[:max_items]
            log_rows = c.execute('''SELECT object_kind,workspace,object_key,source_path,
                    NULL::text AS expected_sha256,NULL::bigint AS expected_bytes,2147483648::bigint AS max_bytes
                FROM public.fw_privacy_objects WHERE object_kind='application_log' AND state='active'
                  AND expires_utc<=clock_timestamp() AND NOT legal_hold AND NOT pinned
                ORDER BY expires_utc,object_key LIMIT %s''',(max_items,)).fetchall()
            orphan_stage_rows = c.execute('''SELECT object_kind,workspace,object_key,source_path,
                    NULL::text AS expected_sha256,NULL::bigint AS expected_bytes,536870912::bigint AS max_bytes
                FROM public.fw_privacy_objects WHERE object_kind='filesystem_staging' AND state='active'
                  AND expires_utc<=clock_timestamp() AND NOT legal_hold AND NOT pinned
                ORDER BY expires_utc,object_key LIMIT %s''',(max_items,)).fetchall()
            backup_rows = c.execute('''SELECT object_kind,workspace,object_key,source_path,
                    expected_sha256,expected_bytes,2147483648::bigint AS max_bytes
                FROM public.fw_privacy_objects WHERE object_kind='backup_artifact' AND state='active'
                  AND expires_utc<=clock_timestamp() AND NOT legal_hold AND NOT pinned
                ORDER BY expires_utc,object_key LIMIT %s''',(max_items,)).fetchall()
            rows = sorted([*rows,*log_rows,*orphan_stage_rows,*backup_rows], key=lambda row: (row['object_kind'],row['workspace'],row['object_key']))[:max_items]
            cleanup_rows = c.execute('''SELECT object_kind,workspace,object_key,source_path,
                    content_sha256,content_bytes,shared_live,legal_hold,pinned,
                    CASE WHEN object_kind IN ('run_artifact','backup_artifact','application_log') THEN 2147483648::bigint ELSE 536870912::bigint END AS max_bytes
                FROM public.fw_privacy_objects
                WHERE state='archived' AND NOT live_bytes_retired AND NOT shared_live
                ORDER BY updated_utc,workspace,object_key LIMIT %s''', (max_items,)).fetchall()
    except Exception as exc:
        raise PrivacySchemaRequired('PRIVACY_LIFECYCLE_SCHEMA_REQUIRED') from exc
    results = []
    for row in cleanup_rows:
        try:
            receipt = {'content_sha256': row['content_sha256'], 'content_bytes': row['content_bytes']}
            retired = _retire_live_source(row, receipt)
            if retired:
                with store.connect() as c:
                    c.execute('''UPDATE public.fw_privacy_objects SET live_bytes_retired=true,
                        updated_utc=clock_timestamp() WHERE object_kind=%s AND workspace=%s AND object_key=%s
                        AND state='archived' ''', (row['object_kind'],row['workspace'],row['object_key']))
                results.append({'status':'live_source_retired','object_kind':row['object_kind']})
        except Exception:
            results.append({'status':'recovery_required','reason':'PRIVACY_LIVE_SOURCE_RETIRE_FAILED'})
    pass_bytes = 0
    for row in rows:
        try:
            remaining = MAX_PASS_BYTES - pass_bytes
            max_bytes = min(int(row['max_bytes']), remaining)
            if max_bytes <= 0:break
            if row['expected_bytes'] is not None and int(row['expected_bytes'])>int(row['max_bytes']):
                with store.connect() as c:
                    c.execute('''UPDATE public.fw_privacy_objects SET state='recovery_required',
                        last_error_code='PRIVACY_FILE_SIZE_LIMIT',updated_utc=clock_timestamp()
                        WHERE object_kind=%s AND workspace=%s AND object_key=%s AND state='active'
                          AND NOT legal_hold AND NOT pinned''',(row['object_kind'],row['workspace'],row['object_key']))
                results.append({'status':'recovery_required','reason':'PRIVACY_FILE_SIZE_LIMIT',
                                'object_kind':row['object_kind']})
                continue
            if row['expected_bytes'] is not None and int(row['expected_bytes'])>max_bytes:break
            source_checked=_check_c_ancestry(Path(row['source_path']))
            opaque_checkpoint=(row['object_kind']=='run_artifact' and source_checked.is_dir())
            source_bytes=0 if opaque_checkpoint else source_checked.stat().st_size
            if not opaque_checkpoint and source_bytes>int(row['max_bytes']):
                with store.connect() as c:
                    c.execute('''UPDATE public.fw_privacy_objects SET state='recovery_required',
                        last_error_code='PRIVACY_FILE_SIZE_LIMIT',updated_utc=clock_timestamp()
                        WHERE object_kind=%s AND workspace=%s AND object_key=%s AND state='active'
                          AND NOT legal_hold AND NOT pinned''',(row['object_kind'],row['workspace'],row['object_key']))
                results.append({'status':'recovery_required','reason':'PRIVACY_FILE_SIZE_LIMIT',
                                'object_kind':row['object_kind']})
                continue
            if source_bytes>remaining:break
            if opaque_checkpoint:
                receipt=_archive_checkpoint_directory(row)
            else:
                receipt = _archive_object(row, object_kind=row['object_kind'],object_key=row['object_key'],
                    expected_hash=row['expected_sha256'],expected_bytes=row['expected_bytes'],max_bytes=max_bytes)
                pass_bytes += receipt['content_bytes']
            with store.connect() as c:
                updated=c.execute('''UPDATE public.fw_privacy_objects SET state='archived',archive_path=%s,
                    content_sha256=%s,content_bytes=%s,last_error_code=NULL,updated_utc=clock_timestamp()
                    WHERE object_kind=%s AND workspace=%s AND object_key=%s
                      AND state='active' AND NOT legal_hold AND NOT pinned RETURNING state''',
                    (receipt['archive_path'], receipt['content_sha256'], receipt['content_bytes'],
                     row['object_kind'],row['workspace'], row['object_key']))
            if not updated:
                results.append({'status':'held_during_archive','object_kind':row['object_kind']})
                continue
            retired = bool(receipt.get('live_bytes_retired')) if opaque_checkpoint else _retire_live_source(row, receipt)
            if retired:
                with store.connect() as c:
                    c.execute('''UPDATE public.fw_privacy_objects SET live_bytes_retired=true,
                        updated_utc=clock_timestamp() WHERE object_kind=%s AND workspace=%s AND object_key=%s
                        AND state='archived' ''', (row['object_kind'],row['workspace'],row['object_key']))
            results.append({'status': 'archived', 'object_kind': row['object_kind'],
                            'content_sha256': receipt['content_sha256'], 'content_bytes': receipt['content_bytes'],
                            'live_bytes_retired': retired})
        except Exception as exc:
            # Store a fixed error code only. Do not persist paths, exception text, or payload bytes.
            code = str(exc) if str(exc).startswith('PRIVACY_') else 'PRIVACY_PROCESSING_ERROR'
            with store.connect() as c:
                c.execute('''UPDATE public.fw_privacy_objects SET state='recovery_required',
                    last_error_code=%s,updated_utc=clock_timestamp()
                    WHERE object_kind=%s AND workspace=%s AND object_key=%s
                      AND state='active' AND NOT legal_hold AND NOT pinned ''',
                    (code, row['object_kind'],row['workspace'], row['object_key']))
            results.append({'status': 'recovery_required', 'reason': code})
    lag = 0
    with store.connect() as c:
        c.execute('''UPDATE public.fw_privacy_scanner_status SET last_started_utc=%s,
            last_lag_seconds=%s,passes=passes+1,
            archived_objects=archived_objects+%s,updated_utc=clock_timestamp() WHERE id=true''',
            (now, lag, sum(item['status'] == 'archived' for item in results)))
        pending = c.execute('''SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(expires_utc))::int) AS lag
            FROM public.fw_privacy_objects WHERE state='active' AND NOT legal_hold AND NOT pinned
              AND expires_utc<=clock_timestamp()''').fetchone()['lag']
        c.execute('UPDATE public.fw_privacy_scanner_status SET last_lag_seconds=%s WHERE id=true', (pending or 0,))
    bundle_retention = {'status': 'pending_migration'}
    try:
        # Reuse the existing verified-bundle scanner in the same recurring
        # worker; its host gate and immutable bundle verifier remain authoritative.
        from .real_retention import run_retention_pass
        bundle_retention = run_retention_pass(store, max_items=min(max_items, 5))
    except Exception as exc:
        bundle_retention = {'status': 'blocked', 'reason':
                            'REAL_RETENTION_SCHEMA_REQUIRED' if isinstance(exc, PrivacySchemaRequired)
                            else 'BUNDLE_RETENTION_PASS_FAILED'}
    try:
        workspace_deletions = _run_workspace_deletion_pass(store,max_items=min(max_items,2),
            max_bytes=max(0,MAX_PASS_BYTES-pass_bytes))
    except Exception:
        workspace_deletions = {'status':'blocked','reason':'WORKSPACE_ARCHIVE_PASS_FAILED'}
    lifecycle_failed=(any(item['status']=='recovery_required' for item in results)
        or deletion_reconciliation.get('status')!='complete'
        or workspace_deletions.get('status')=='blocked'
        or any(item.get('recovery_required',0)>0 for item in workspace_deletions.get('items',[]))
        or bundle_retention.get('status') in ('blocked','error','recovery_required','skipped'))
    with store.connect() as c:
        c.execute('''UPDATE public.fw_privacy_scanner_status SET
            last_success_utc=CASE WHEN %s THEN last_success_utc ELSE clock_timestamp() END,
            last_error_code=%s,updated_utc=clock_timestamp() WHERE id=true''',
            (lifecycle_failed,'PRIVACY_RECOVERY_REQUIRED' if lifecycle_failed else None))
    return {'status': 'complete', 'policy': POLICY, 'host': host, 'processed': len(rows),
            'expired_logs_registered':registered_logs,
            'abandoned_stages_registered':registered_stages,
            'expired_backups_registered':registered_backups,
            'deletion_intent_reconciliation':deletion_reconciliation,
            'items': results, 'backlog_lag_seconds': pending or 0,
            'verified_bundle_retention': bundle_retention,
            'workspace_deletions':workspace_deletions}


def privacy_loop(store, *, stop_event=None, interval_seconds: int = 900) -> None:
    if type(interval_seconds) is not int or not 60 <= interval_seconds <= 3600:
        raise ValueError('PRIVACY_INTERVAL_BOUND')
    instance=str(uuid.uuid4())
    try:
        while stop_event is None or not stop_event.is_set():
            with store.connect() as c:
                c.execute('''UPDATE public.fw_privacy_scanner_status SET scheduler_instance=%s,
                    scheduler_heartbeat_utc=clock_timestamp(),updated_utc=clock_timestamp() WHERE id=true''',
                    (instance,))
            try:
                print(json.dumps(run_privacy_pass(store), sort_keys=True))
            except PrivacySchemaRequired:
                print(json.dumps({'status': 'blocked', 'reason': 'PRIVACY_LIFECYCLE_SCHEMA_REQUIRED'}))
            with store.connect() as c:
                c.execute('''UPDATE public.fw_privacy_scanner_status SET scheduler_heartbeat_utc=clock_timestamp(),
                    updated_utc=clock_timestamp() WHERE id=true AND scheduler_instance=%s''',(instance,))
            if stop_event is not None:
                if stop_event.wait(interval_seconds):
                    return
            else:
                time.sleep(interval_seconds)
    finally:
        with store.connect() as c:
            c.execute('''UPDATE public.fw_privacy_scanner_status SET scheduler_heartbeat_utc=NULL,
                scheduler_instance=NULL,updated_utc=clock_timestamp() WHERE id=true AND scheduler_instance=%s''',
                (instance,))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Fieldwork privacy lifecycle worker')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--once', action='store_true')
    mode.add_argument('--loop', action='store_true')
    parser.add_argument('--interval-seconds', type=int, default=900)
    args = parser.parse_args(argv)
    from .store import Store
    store = Store()
    if args.once:
        print(json.dumps(run_privacy_pass(store), sort_keys=True))
    else:
        privacy_loop(store, interval_seconds=args.interval_seconds)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
