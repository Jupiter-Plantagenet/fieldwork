"""Synthetic source-boundary checks for the privacy archive helper."""
import ast
from pathlib import Path
from datetime import datetime, timezone

import pytest

from fieldwork import privacy_lifecycle as lifecycle


def test_archive_fresh_input_preserves_source_and_verifies_private_copy(tmp_path, monkeypatch):
    root = tmp_path
    monkeypatch.setattr(lifecycle, 'ROOT', root)
    fixture = root / 'privacy-lifecycle-fixture'
    fixture.mkdir(parents=True, exist_ok=True)
    source = fixture / 'synthetic.img'
    source.write_bytes(b'authored synthetic image fixture')
    archive_root = fixture / 'private-archive'
    monkeypatch.setattr(lifecycle, 'ARCHIVE_ROOT', archive_root)
    import hashlib
    content = source.read_bytes()
    row = {'workspace': 'synthetic-workspace', 'input_id': 'synthetic-input-id',
           'source_path': str(source), 'asset_sha256': hashlib.sha256(content).hexdigest(),
           'asset_bytes': len(content)}
    receipt = lifecycle._archive_fresh_input(row)
    archived = root / receipt['archive_path']
    assert archived.read_bytes() == content
    assert source.read_bytes() == content
    assert receipt['content_sha256'] == hashlib.sha256(content).hexdigest()
    assert receipt['content_bytes'] == len(content)
    assert lifecycle._retire_live_source({'source_path':str(source),'max_bytes':100},receipt) is True
    assert not source.exists()
    assert archived.read_bytes() == content


def test_existing_nested_private_archive_path_remains_usable(tmp_path,monkeypatch):
    # Use the pytest base directory rather than its long per-test child name so
    # the legacy path stays below Windows MAX_PATH for this compatibility probe.
    root=tmp_path.parent
    monkeypatch.setattr(lifecycle,'ROOT',root)
    fixture=root/'a';fixture.mkdir(parents=True,exist_ok=True)
    source=fixture/'synthetic.img';source.write_bytes(b'authored nested-archive fixture')
    archive_root=fixture/'private-archive';monkeypatch.setattr(lifecycle,'ARCHIVE_ROOT',archive_root)
    workspace='synthetic-workspace';input_id='legacy-layout-input'
    key=__import__('hashlib').sha256((workspace+':'+input_id).encode()).hexdigest()
    legacy=archive_root/'fresh_inference_input'/key[:2]/key/(key+'.img')
    assert len(str(legacy))<260
    lifecycle._ensure_private_directory(legacy.parent)
    legacy.write_bytes(source.read_bytes())
    content=source.read_bytes()
    row={'workspace':workspace,'input_id':input_id,'source_path':str(source),
         'asset_sha256':__import__('hashlib').sha256(content).hexdigest(),'asset_bytes':len(content)}
    receipt=lifecycle._archive_fresh_input(row)
    assert receipt['archive_path']==legacy.relative_to(root).as_posix()
    assert legacy.read_bytes()==content and source.read_bytes()==content


def test_retire_keeps_held_or_shared_source(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, 'ROOT', tmp_path)
    source=tmp_path/'synthetic.bin';source.write_bytes(b'authored held fixture')
    receipt={'content_sha256':'0'*64,'content_bytes':source.stat().st_size}
    assert lifecycle._retire_live_source({'source_path':str(source),'shared_live':True},receipt) is False
    assert source.read_bytes()==b'authored held fixture'


def test_archiver_rejects_outside_root_before_open(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, 'ROOT', tmp_path)
    row = {'workspace': 'synthetic-workspace', 'input_id': 'synthetic-input-id',
           'source_path': str(Path('D:/sealed/never-open-this.img'))}
    with pytest.raises(ValueError, match='PRIVACY_PATH_OUTSIDE'):
        lifecycle._archive_fresh_input(row)


def test_policy_keeps_user_defaults_and_batch_bounded():
    assert lifecycle.POLICY == {
        'fresh_inference_input_hours': 24, 'abandoned_staging_hours': 24,
        'application_log_days': 30, 'event_replay_days': 7, 'audit_days': 90,
        'unpinned_artifact_days': 180, 'workspace_live_access_days_after_delete': 7,
        'backup_expiry_days': 30,
    }
    with pytest.raises(ValueError, match='PRIVACY_BATCH_BOUND'):
        lifecycle.run_privacy_pass(object(), max_items=21)


def test_workspace_bundle_retirement_moves_opaque_directory_without_member_reads():
    source=Path(__file__).parents[1]/'fieldwork'/'privacy_lifecycle.py'
    module=ast.parse(source.read_text(encoding='utf-8'))
    funcs={node.name:ast.unparse(node) for node in module.body if isinstance(node,ast.FunctionDef)}
    archive=funcs['_archive_deleted_bundle']
    checkpoint=funcs['_archive_checkpoint_directory']
    inventory=funcs['_register_workspace_delete_files']
    assert 'os.replace(source, target)' in archive
    assert '_hash_regular' not in archive and 'read_bytes' not in archive and 'open(' not in archive
    assert 'os.replace(source, target)' in checkpoint
    assert '_hash_regular' not in checkpoint and 'read_bytes' not in checkpoint and 'open(' not in checkpoint
    assert 'bundle.rglob' not in inventory
    assert 'artifact_result' in inventory and 'bundle_digest' in inventory




def test_deletion_tombstone_is_durable_and_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, 'ROOT', tmp_path)
    monkeypatch.setattr(lifecycle, 'DELETION_LEDGER_ROOT', tmp_path / '.local' / 'privacy-deletions')
    deleted = datetime(2026,11,2,tzinfo=timezone.utc)
    lifecycle.append_deletion_tombstone('synthetic-workspace','11111111-1111-1111-1111-111111111111',deleted)
    assert lifecycle.workspace_deleted_locally('synthetic-workspace') is True
    path = lifecycle._deletion_ledger_path('synthetic-workspace')
    path.write_text('{"tampered":true}',encoding='utf-8')
    with pytest.raises(lifecycle.PrivacyDeletionLedgerError):
        lifecycle.workspace_deleted_locally('synthetic-workspace')


def test_backup_deletion_ledger_package_is_hash_verified(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, 'ROOT', tmp_path)
    monkeypatch.setattr(lifecycle, 'DELETION_LEDGER_ROOT', tmp_path / '.local' / 'privacy-deletions')
    lifecycle.append_deletion_tombstone('synthetic-workspace','22222222-2222-2222-2222-222222222222',
        datetime(2026,11,2,tzinfo=timezone.utc))
    package=tmp_path/'backup'/'privacy-deletions'
    package.parent.mkdir(mode=0o700)
    receipt=lifecycle.export_deletion_ledger(package)
    assert receipt['file_count']==1
    assert (package/'manifest.json').is_file()
    (package/lifecycle._deletion_ledger_path('synthetic-workspace').name).write_text('tampered')
    with pytest.raises(lifecycle.PrivacyDeletionLedgerError):
        lifecycle.verify_apply_deletion_ledger(object(),package)


class _Rows:
    def __init__(self, one=None, many=()):self.one,self.many=one,list(many)
    def fetchone(self):return self.one
    def fetchall(self):return self.many


class _RestoreStore:
    def __init__(self,existing=()):self.existing=list(existing);self.statements=[]
    def connect(self):return self
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def execute(self,query,params=None):
        self.statements.append((query,params))
        if 'to_regclass' in query:return _Rows({'ready':True})
        if 'SELECT workspace,request_id,deleted_utc' in query:return _Rows(many=self.existing)
        return _Rows()


class _IntentConnection:
    def __init__(self,store):self.store=store;self.failed_commit=False
    def __enter__(self):return self
    def __exit__(self,exc_type,exc,tb):
        if exc_type:return False
        if self.store.fail_next_commit:
            self.store.fail_next_commit=False
            raise RuntimeError('synthetic commit failure')
        return False
    def execute(self,query,params=None):
        query=' '.join(str(query).split())
        if 'pg_advisory_xact_lock(hashtextextended' in query:return _Rows()
        if 'AS tombstones' in query and 'AS control' in query:
            return _Rows({'tombstones':True,'control':True})
        if 'SELECT restore_generation::text FROM public.fw_control' in query:
            return _Rows({'restore_generation':self.store.restore_generation})
        if 'SELECT 1 FROM public.fw_privacy_workspace_tombstones' in query:
            return _Rows(self.store.tombstones.get(params[0]))
        if 'to_regclass' in query or 'to_regprocedure' in query:return _Rows({'ready':True})
        if 'SELECT request_id,deleted_utc FROM public.fw_privacy_workspace_tombstones' in query:
            row=self.store.tombstones.get(params[0]);return _Rows(row)
        if 'INSERT INTO public.fw_privacy_workspace_tombstones' in query:
            workspace,request_id,actor,revision,deleted,_=params
            self.store.tombstones[workspace]={'request_id':request_id,'deleted_utc':deleted}
            return _Rows()
        if 'SELECT id FROM public.fw_runs' in query:return _Rows(many=[])
        if 'DELETE FROM public.fw_sessions' in query:return _Rows()
        return _Rows()


class _IntentStore:
    def __init__(self):self.tombstones={};self.fail_next_commit=False;self.restore_generation='99999999-9999-9999-9999-999999999999'
    def connect(self):return _IntentConnection(self)


def test_restore_applies_verified_tombstone_before_access(tmp_path,monkeypatch):
    monkeypatch.setattr(lifecycle,'ROOT',tmp_path)
    monkeypatch.setattr(lifecycle,'DELETION_LEDGER_ROOT',tmp_path/'.local'/'privacy-deletions')
    lifecycle.append_deletion_tombstone('synthetic-workspace','33333333-3333-3333-3333-333333333333',
        datetime(2026,11,2,tzinfo=timezone.utc))
    package=tmp_path/'backup'/'privacy-deletions';package.parent.mkdir(mode=0o700)
    lifecycle.export_deletion_ledger(package)
    store=_RestoreStore()
    receipt=lifecycle.verify_apply_deletion_ledger(store,package)
    assert receipt=={'status':'verified_and_applied','ledger_entries':1,'restored_tombstones':1}
    sql=' '.join(statement for statement,_ in store.statements)
    assert 'INSERT INTO public.fw_privacy_workspace_tombstones' in sql
    assert 'DELETE FROM public.fw_sessions' in sql


def test_restore_fails_closed_when_database_tombstone_has_no_external_marker(tmp_path,monkeypatch):
    monkeypatch.setattr(lifecycle,'ROOT',tmp_path)
    monkeypatch.setattr(lifecycle,'DELETION_LEDGER_ROOT',tmp_path/'.local'/'privacy-deletions')
    package=tmp_path/'backup'/'privacy-deletions';package.mkdir(parents=True,mode=0o700)
    lifecycle.export_deletion_ledger(package)
    store=_RestoreStore([{'workspace':'synthetic-workspace','request_id':'44444444-4444-4444-4444-444444444444',
                          'deleted_utc':datetime(2026,11,2,tzinfo=timezone.utc)}])
    with pytest.raises(lifecycle.PrivacyDeletionLedgerError,match='INCOMPLETE'):
        lifecycle.verify_apply_deletion_ledger(store,package)
    assert not any('INSERT INTO' in statement or 'DELETE FROM' in statement for statement,_ in store.statements)


def test_commit_failure_after_prepared_intent_reconciles_to_committed(tmp_path,monkeypatch):
    monkeypatch.setattr(lifecycle,'ROOT',tmp_path)
    monkeypatch.setattr(lifecycle,'DELETION_LEDGER_ROOT',tmp_path/'.local'/'privacy-deletions')
    store=_IntentStore();store.fail_next_commit=True
    deleted=datetime(2026,11,2,tzinfo=timezone.utc)
    with pytest.raises(RuntimeError,match='synthetic commit failure'):
        with store.connect():
            lifecycle.append_deletion_tombstone('synthetic-workspace','55555555-5555-5555-5555-555555555555',
                deleted,requested_by='synthetic-owner',expected_revision=7)
    assert store.tombstones=={}
    assert lifecycle.workspace_deleted_locally('synthetic-workspace') is True
    recovered=lifecycle.reconcile_deletion_intents(store,workspace='synthetic-workspace')
    assert recovered['status']=='complete' and recovered['committed']==1
    assert store.tombstones['synthetic-workspace']['request_id']=='55555555-5555-5555-5555-555555555555'
    marker=lifecycle._read_deletion_tombstone(lifecycle._deletion_ledger_path('synthetic-workspace'),'synthetic-workspace')
    assert marker['intents'][0]['state']=='committed'
    assert lifecycle.workspace_deleted_locally('synthetic-workspace') is True


def test_response_loss_reconcile_promotes_matching_database_tombstone(tmp_path,monkeypatch):
    monkeypatch.setattr(lifecycle,'ROOT',tmp_path)
    monkeypatch.setattr(lifecycle,'DELETION_LEDGER_ROOT',tmp_path/'.local'/'privacy-deletions')
    deleted=datetime(2026,11,2,tzinfo=timezone.utc)
    lifecycle.append_deletion_tombstone('synthetic-workspace','66666666-6666-6666-6666-666666666666',deleted)
    store=_IntentStore();store.tombstones['synthetic-workspace']={
        'request_id':'66666666-6666-6666-6666-666666666666','deleted_utc':deleted}
    receipt=lifecycle.reconcile_deletion_intents(store,workspace='synthetic-workspace')
    assert receipt['status']=='complete' and receipt['committed']==1
    assert lifecycle.workspace_deleted_locally('synthetic-workspace') is True


def test_aborted_intent_is_recorded_but_committed_marker_cannot_be_aborted(tmp_path,monkeypatch):
    monkeypatch.setattr(lifecycle,'ROOT',tmp_path)
    monkeypatch.setattr(lifecycle,'DELETION_LEDGER_ROOT',tmp_path/'.local'/'privacy-deletions')
    store=_IntentStore()
    lifecycle.append_deletion_tombstone('synthetic-workspace','77777777-7777-7777-7777-777777777777',
        datetime(2026,11,2,tzinfo=timezone.utc),restore_generation=store.restore_generation)
    lifecycle.abort_deletion_intent(store,'synthetic-workspace','77777777-7777-7777-7777-777777777777')
    assert lifecycle.workspace_deleted_locally('synthetic-workspace') is False
    lifecycle.append_deletion_tombstone('synthetic-workspace','88888888-8888-8888-8888-888888888888',
        datetime(2026,11,3,tzinfo=timezone.utc),restore_generation=store.restore_generation)
    lifecycle.set_deletion_intent_state('synthetic-workspace','88888888-8888-8888-8888-888888888888','committed')
    with pytest.raises(lifecycle.ValueError if hasattr(lifecycle,'ValueError') else ValueError):
        lifecycle.set_deletion_intent_state('synthetic-workspace','88888888-8888-8888-8888-888888888888','aborted')
    assert lifecycle.workspace_deleted_locally('synthetic-workspace') is True


def test_restore_generation_change_prevents_abort_of_prepared_intent(tmp_path,monkeypatch):
    monkeypatch.setattr(lifecycle,'ROOT',tmp_path)
    monkeypatch.setattr(lifecycle,'DELETION_LEDGER_ROOT',tmp_path/'.local'/'privacy-deletions')
    store=_IntentStore()
    lifecycle.append_deletion_tombstone('synthetic-workspace','99999999-9999-9999-9999-999999999998',
        datetime(2026,11,2,tzinfo=timezone.utc),restore_generation=store.restore_generation)
    store.restore_generation='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    with pytest.raises(lifecycle.PrivacyDeletionLedgerError,match='ABORT_UNVERIFIED'):
        lifecycle.abort_deletion_intent(store,'synthetic-workspace','99999999-9999-9999-9999-999999999998')
    assert lifecycle.workspace_deleted_locally('synthetic-workspace') is True
    source=(Path(__file__).parents[1]/'fieldwork'/'privacy_lifecycle.py').read_text(encoding='utf-8')
    assert "restore_generation::text FROM public.fw_control WHERE id=1 FOR UPDATE" in source
    assert "current_intent['state']!='prepared'" in source


def test_auth_and_scheduler_sources_keep_tombstone_and_heartbeat_fences():
    api=ast.parse((Path(__file__).parents[1]/'fieldwork'/'api.py').read_text(encoding='utf-8'))
    defs={node.name:ast.unparse(node) for node in api.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
    assert '_local_privacy_tombstone' in defs['login'] and 'fw_privacy_workspace_deleted_v1' in defs['login']
    assert '_local_privacy_tombstone' in defs['session'] and 'fw_privacy_workspace_deleted_v1' in defs['session']
    retention=ast.parse((Path(__file__).parents[1]/'fieldwork'/'real_retention.py').read_text(encoding='utf-8'))
    loop=next(node for node in retention.body if isinstance(node,ast.FunctionDef) and node.name=='retention_loop')
    assert 'privacy_loop' in ast.unparse(loop)


def test_managed_log_destinations_rotate_or_write_sanitized_errors_only():
    root=Path(__file__).parents[1]
    launcher=(root/'tools'/'restart_api.py').read_text(encoding='utf-8')
    assert 'PrivateTimedRotatingFileHandler' in launcher
    assert "'when':'midnight'" in launcher and "'backupCount':0" in launcher
    intake=(root/'tools'/'activate_intake_decoder_v2.py').read_text(encoding='utf-8')
    assert 'stdout=subprocess.DEVNULL' in intake and 'stderr=subprocess.DEVNULL' in intake
    worker=(root/'fieldwork'/'newintake_worker.py').read_text(encoding='utf-8')
    assert "intake-worker-errors.log" in worker and "secret_printed':False" in worker


def test_synthetic_frozen_sample_membership_retains_only_protected_or_held_samples():
    frozen_workspace=[
        {'sample':'ordinary-A','protected':False,'legal_hold':False,'pinned':False},
        {'sample':'protected-B','protected':True,'legal_hold':False,'pinned':False},
        {'sample':'held-C','protected':False,'legal_hold':True,'pinned':False},
    ]
    eligible=[row['sample'] for row in frozen_workspace if lifecycle.dataset_retention_eligible(
        protected=row['protected'],legal_hold=row['legal_hold'],pinned=row['pinned'])]
    assert eligible==['ordinary-A']
    migration=(Path(__file__).parents[1]/'migrations'/'017_privacy_lifecycle.sql').read_text(encoding='utf-8')
    assert "ALTER TABLE public.fw_samples ADD COLUMN privacy_protected boolean NOT NULL DEFAULT false" in migration
    assert 'jsonb_path_query(version_manifest' in migration and 'privacy_protected=true' in migration
    assert "AND NOT s.privacy_protected" in ast.unparse(ast.parse(
        (Path(__file__).parents[1]/'fieldwork'/'privacy_lifecycle.py').read_text(encoding='utf-8')))
    assert 'fw_privacy_seal_version_members_v1' in (Path(__file__).parents[1]/'fieldwork'/'dataset_versions.py').read_text(encoding='utf-8')


def test_deletion_cancel_capability_is_tombstone_only_and_keeps_fences():
    migration=(Path(__file__).parents[1]/'migrations'/'017_privacy_lifecycle.sql').read_text(encoding='utf-8')
    assert 'fw_privacy_cancel_deleted_run_v1' in migration
    body=migration.split('CREATE FUNCTION public.fw_privacy_cancel_deleted_run_v1',1)[1].split('$fn$;',1)[0]
    assert 'fw_privacy_workspace_tombstones' in body
    assert "r.state IN ('succeeded','failed','cancelled','cancel_requested')" in body
    assert "fence=fence+1,revision=revision+1" in body and 'cancel_generation=next_generation' in body
    assert "INSERT INTO public.fw_events" in body
    assert 'GRANT EXECUTE ON FUNCTION public.fw_privacy_cancel_deleted_run_v1(text,text) TO fieldwork_api' in migration
    assert 'store.cancel(' not in (Path(__file__).parents[1]/'fieldwork'/'privacy_lifecycle.py').read_text(encoding='utf-8')
    lifecycle_source=(Path(__file__).parents[1]/'fieldwork'/'privacy_lifecycle.py').read_text(encoding='utf-8')
    assert "fieldwork-workspace-delete:' + workspace" in lifecycle_source
    assert "fieldwork-workspace-delete:' + payload['workspace']" in lifecycle_source
