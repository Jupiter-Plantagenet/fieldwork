"""Scoped durable consumer for ``fw_real_intake_queue``.

The runtime login is a dedicated ``fieldwork_intake_worker`` capability, never the
application's operator DSN.  The worker processes only server-staged archives and
calls the existing bounded ``intake.run_intake`` implementation. Queue leases are
fenced; import transactions are serialized per workspace and validate the current
lease at commit. A source-linked terminal intake batch is recovered before any
retry, so a commit followed by lost acknowledgement does not create new records.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

import psycopg
from psycopg.rows import dict_row

from . import intake
from .acquisition import sha256_file
from .container_decoder import ContainerDecoder, IMAGE_ID_RE
from .rights import RightsService
from .rights_decision import DecisionRejected
from .rights_registry import load_trusted_registry
from .rights_store import RightsRepository
from .scoped_authority import check_private
from .store import ROOT

AUTHORITY_SCHEMA = 'fieldwork.real-intake-worker/v2'
LOGIN = 'fieldwork_intake_worker'
MAX_ATTEMPTS = 5
LEASE_SECONDS = 120
HEARTBEAT_SECONDS = 20
COMMIT_LEASE_SECONDS = 600
ARCHIVE_LIMIT = 512 * 1024 * 1024


class LeaseLost(RuntimeError):
    pass


class IntakeRefused(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _json_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('DUPLICATE_AUTHORITY_KEY')
        out[key] = value
    return out


def _safe_root(raw: str, *, must_exist: bool) -> Path:
    path = Path(raw)
    if not path.is_absolute() or path.drive.upper() != 'C:':
        raise ValueError('INTAKE_PATH_MUST_BE_ON_C')
    current = path.anchor and Path(path.anchor) or Path('C:/')
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            if must_exist:
                raise ValueError('INTAKE_PATH_NOT_FOUND') from None
            continue
        if current.is_symlink() or getattr(info, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
            raise ValueError('INTAKE_PATH_REPARSE_POINT')
    target = path.resolve(strict=must_exist)
    try:
        target.relative_to(ROOT.resolve())
    except ValueError:
        raise ValueError('INTAKE_PATH_OUTSIDE_PRODUCT_ROOT') from None
    if target.drive.upper() != 'C:':
        raise ValueError('INTAKE_PATH_MUST_BE_ON_C')
    if must_exist and not target.is_dir():
        raise ValueError('INTAKE_DIRECTORY_REQUIRED')
    return target


def _safe_file(raw: str | Path) -> Path:
    path = Path(raw)
    if not path.is_absolute() or path.drive.upper() != 'C:':
        raise ValueError('INTAKE_PATH_MUST_BE_ON_C')
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        raise ValueError('INTAKE_PATH_OUTSIDE_PRODUCT_ROOT') from None
    except OSError:
        raise ValueError('INTAKE_PATH_NOT_FOUND') from None
    if not resolved.is_file():
        raise ValueError('INTAKE_FILE_REQUIRED')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            raise ValueError('INTAKE_PATH_NOT_FOUND') from None
        if current.is_symlink() or getattr(info, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
            raise ValueError('INTAKE_PATH_REPARSE_POINT')
    return resolved


def load_authority(path: str | Path) -> dict:
    path = _safe_file(path)
    check_private(path)
    if path.stat().st_size > 65536:
        raise ValueError('INTAKE_AUTHORITY_TOO_LARGE')
    doc = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_json_pairs)
    expected = {'schema', 'connection', 'upload_root', 'spool_root', 'quarantine_root',
                'media_root', 'rights_registry_path', 'decoder_image_id'}
    if type(doc) is not dict or doc.keys() != expected or doc['schema'] != AUTHORITY_SCHEMA:
        raise ValueError('INTAKE_AUTHORITY_SCHEMA')
    c = doc['connection']
    if type(c) is not dict or c.keys() != {'host', 'port', 'dbname', 'user', 'password', 'sslmode'}:
        raise ValueError('INTAKE_AUTHORITY_CONNECTION')
    if c['host'] not in ('127.0.0.1', '::1') or c['user'] != LOGIN or c['sslmode'] not in ('disable', 'prefer', 'require'):
        raise ValueError('INTAKE_AUTHORITY_ENDPOINT')
    if type(c['port']) is not int or not 1 <= c['port'] <= 65535 or type(c['password']) is not str or not c['password']:
        raise ValueError('INTAKE_AUTHORITY_CREDENTIAL')
    if type(c['dbname']) is not str or not c['dbname']:
        raise ValueError('INTAKE_AUTHORITY_DATABASE')
    for field in ('upload_root', 'spool_root', 'quarantine_root', 'media_root'):
        doc[field] = str(_safe_root(doc[field], must_exist=True))
        check_private(doc[field])
    doc['rights_registry_path'] = str(_safe_file(doc['rights_registry_path']))
    check_private(doc['rights_registry_path'])
    if type(doc['decoder_image_id']) is not str or not IMAGE_ID_RE.fullmatch(doc['decoder_image_id']):
        raise ValueError('INTAKE_DECODER_IMAGE_ID')
    return doc


def _resolve_under(path: str | Path, root: str | Path) -> Path:
    base = Path(root).resolve(strict=True)
    candidate = Path(path).absolute()
    try:
        candidate.relative_to(Path(root).absolute())
        relative = candidate.relative_to(Path(root).absolute())
    except ValueError:
        raise IntakeRefused('ARCHIVE_PATH_OUTSIDE_UPLOAD_ROOT') from None
    current = Path(root).absolute()
    for part in ('.', *relative.parts):
        current = current if part == '.' else current / part
        try:
            info = current.lstat()
        except OSError:
            raise IntakeRefused('ARCHIVE_NOT_FOUND') from None
        if current.is_symlink() or getattr(info, 'st_file_attributes', 0) & getattr(os, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
            raise IntakeRefused('ARCHIVE_REPARSE_POINT')
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(base)
    except (ValueError, OSError):
        raise IntakeRefused('ARCHIVE_PATH_OUTSIDE_UPLOAD_ROOT') from None
    if not resolved.is_file() or resolved.stat().st_size > ARCHIVE_LIMIT:
        raise IntakeRefused('ARCHIVE_INVALID_SIZE')
    return resolved


def _spool_archive(row: dict, *, upload_root: Path, spool_root: Path) -> Path:
    try:
        if str(uuid.UUID(str(row['workspace']))) != str(row['workspace']):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise IntakeRefused('WORKSPACE_SCOPE_INVALID') from None
    source = _resolve_under(row['archive_path'], upload_root)
    sha, size = sha256_file(source)
    if sha != row['archive_sha256'] or size != row['archive_bytes']:
        raise IntakeRefused('ARCHIVE_DIGEST_MISMATCH')
    target_dir = spool_root / str(row['workspace']) / str(row['intake_id'])
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / (sha + '.archive')
    if target.is_symlink():
        raise IntakeRefused('SPOOL_REPARSE_POINT')
    if target.exists():
        existing_sha, existing_size = sha256_file(target)
        if existing_sha != sha or existing_size != size:
            raise IntakeRefused('SPOOL_DIGEST_MISMATCH')
        return target
    temp = target.with_name('.' + uuid.uuid4().hex + '.copying')
    digest = hashlib.sha256()
    copied = 0
    try:
        with source.open('rb') as src, temp.open('xb') as dst:
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > ARCHIVE_LIMIT:
                    raise IntakeRefused('ARCHIVE_INVALID_SIZE')
                digest.update(block)
                dst.write(block)
            dst.flush()
            os.fsync(dst.fileno())
        if copied != size or digest.hexdigest() != sha:
            raise IntakeRefused('ARCHIVE_DIGEST_MISMATCH')
        # The exclusive random staging file is completely checked before publish.
        os.replace(temp, target)
        return target
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def _connect(authority: dict):
    if any(k.startswith('PG') for k in os.environ):
        raise ValueError('LIBPQ_ENVIRONMENT_FORBIDDEN')
    c = authority['connection']
    return psycopg.connect(host=c['host'], port=c['port'], dbname=c['dbname'], user=c['user'],
                           password=c['password'], sslmode=c['sslmode'], connect_timeout=3,
                           row_factory=dict_row, options='-c search_path=pg_catalog,public',
                           application_name='fieldwork-real-intake')


def provision_worker(*, operator_file: str | Path, authority_file: str | Path,
                     workspaces: list[str], upload_root: str | Path, spool_root: str | Path,
                     quarantine_root: str | Path, media_root: str | Path,
                     rights_registry_path: str | Path, decoder_image_id: str) -> dict:
    """Provision a one-login DB capability and private runtime authority file.

    This operator-only command uses the existing private operator file for one
    local DDL transaction. The generated runtime authority contains only the
    narrowly granted intake login and is never printed or passed to the API.
    """
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict
    from .scoped_authority import _powershell

    operator_path = _safe_file(operator_file)
    check_private(operator_path)
    if operator_path.stat().st_size > 65536:
        raise ValueError('OPERATOR_FILE_TOO_LARGE')
    operator_doc = json.loads(operator_path.read_text(encoding='utf-8'), object_pairs_hook=_json_pairs)
    if type(operator_doc) is not dict or set(operator_doc) != {'dsn'} or type(operator_doc['dsn']) is not str:
        raise ValueError('OPERATOR_FILE_SCHEMA')
    params = conninfo_to_dict(operator_doc['dsn'])
    if params.get('host') not in ('127.0.0.1', '::1'):
        raise ValueError('OPERATOR_ENDPOINT_NOT_LOCAL')
    if not workspaces or any(type(w) is not str or len(w) != 36 for w in workspaces) or len(set(workspaces)) != len(workspaces):
        raise ValueError('WORKSPACE_SCOPE_INVALID')
    for w in workspaces:
        try:
            if str(uuid.UUID(w)) != w:
                raise ValueError()
        except ValueError:
            raise ValueError('WORKSPACE_SCOPE_INVALID') from None

    roots = {}
    for key, raw in (('upload_root', upload_root), ('spool_root', spool_root),
                     ('quarantine_root', quarantine_root), ('media_root', media_root)):
        path = _safe_root(str(raw), must_exist=True)
        check_private(path)
        roots[key] = str(path)
    registry_path = _safe_file(rights_registry_path)
    check_private(registry_path)
    if type(decoder_image_id) is not str or not IMAGE_ID_RE.fullmatch(decoder_image_id):
        raise ValueError('INTAKE_DECODER_IMAGE_ID')
    # Refuse to create an API-capable worker login until the exact reviewed
    # decoder image is already present in the local Docker engine.
    ContainerDecoder(decoder_image_id, private_dir=roots['spool_root']).close()

    target = Path(authority_file)
    if not target.is_absolute():
        raise ValueError('AUTHORITY_PATH_MUST_BE_ABSOLUTE')
    parent = target.parent
    if parent.exists():
        parent = _safe_root(str(parent), must_exist=True)
        check_private(parent)
    else:
        parent_parent = parent.parent
        if not parent_parent.exists():
            raise ValueError('AUTHORITY_PARENT_PARENT_REQUIRED')
        parent = _safe_root(str(parent_parent), must_exist=True) / parent.name
        parent.mkdir()
        if os.name == 'nt':
            safe = str(parent.resolve()).replace("'", "''")
            _powershell("$ErrorActionPreference='Stop'; $p='" + safe + "'; "
                        "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; "
                        "& icacls.exe $p /inheritance:r /grant:r ('*'+$sid.Value+':(OI)(CI)F') | Out-Null; "
                        "if($LASTEXITCODE -ne 0){throw 'ACL_FAILED'}")
        check_private(parent)
    target = parent / target.name
    try:
        target.relative_to((ROOT / '.local').resolve())
    except ValueError:
        raise ValueError('AUTHORITY_MUST_BE_UNDER_PRIVATE_LOCAL') from None
    if target.exists() or target.is_symlink():
        raise ValueError('AUTHORITY_ALREADY_EXISTS')

    import secrets
    secret = secrets.token_urlsafe(48)
    connection = {'host': params['host'], 'port': int(params.get('port', 5432)),
                  'dbname': params['dbname'], 'user': LOGIN, 'password': secret,
                  'sslmode': params.get('sslmode', 'disable')}
    authority = {'schema': AUTHORITY_SCHEMA, 'connection': connection, **roots,
                 'rights_registry_path': str(registry_path), 'decoder_image_id': decoder_image_id}
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(authority, stream, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        check_private(target)
        with psycopg.connect(operator_doc['dsn'], row_factory=dict_row, connect_timeout=3,
                             options='-c search_path=pg_catalog,pg_temp') as c:
            role = c.execute('''SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication,
                rolinherit,rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=%s''', (LOGIN,)).fetchone()
            if not role or any(role[k] for k in ('rolsuper','rolbypassrls','rolcreatedb','rolcreaterole','rolreplication','rolinherit','rolcanlogin')):
                raise ValueError('INTAKE_ROLE_NOT_SAFE_NOLOGIN')
            if c.execute('''SELECT 1 FROM pg_catalog.pg_auth_members m
                JOIN pg_catalog.pg_roles r ON r.oid=m.member OR r.oid=m.roleid WHERE r.rolname=%s''', (LOGIN,)).fetchone():
                raise ValueError('INTAKE_ROLE_MEMBERSHIP')
            ready = c.execute("""SELECT to_regclass('public.fw_intake_worker_scopes') IS NOT NULL AND
                to_regclass('public.fw_real_intake_queue') IS NOT NULL AND
                to_regclass('public.fw_intake_batches') IS NOT NULL AND
                to_regnamespace('fw_intake_cap_v1') IS NOT NULL ok""").fetchone()['ok']
            if not ready:
                raise ValueError('MIGRATION_006_REQUIRED')
            bad = c.execute('''SELECT has_schema_privilege(%s,'public','CREATE') OR
                has_database_privilege(%s,current_database(),'CREATE') OR
                has_database_privilege(%s,current_database(),'TEMP') OR
                EXISTS (SELECT 1 FROM pg_catalog.pg_class r JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
                  WHERE n.nspname='public' AND r.relkind IN ('r','p','v','m') AND
                    r.relname NOT IN ('fw_real_intake_queue','fw_intake_batches','fw_samples','fw_intake_members',
                      'fw_rights_datasets','fw_rights_assets','fw_rights_decisions') AND
                    (r.relname<>'fw_sample_perceptual_features' OR
                     has_table_privilege(%s,r.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,SELECT WITH GRANT OPTION')) AND
                    (has_table_privilege(%s,r.oid,'SELECT') OR has_table_privilege(%s,r.oid,'INSERT') OR
                     has_table_privilege(%s,r.oid,'UPDATE') OR has_table_privilege(%s,r.oid,'DELETE') OR
                     has_table_privilege(%s,r.oid,'TRUNCATE') OR has_table_privilege(%s,r.oid,'REFERENCES') OR
                     has_table_privilege(%s,r.oid,'TRIGGER'))) bad''',
                (LOGIN, LOGIN, LOGIN, LOGIN, LOGIN, LOGIN, LOGIN, LOGIN, LOGIN, LOGIN, LOGIN)).fetchone()['bad']
            if bad:
                raise ValueError('INTAKE_ROLE_EXCESS_PRIVILEGE')
            c.execute(sql.SQL('ALTER ROLE {} WITH LOGIN PASSWORD {}').format(sql.Identifier(LOGIN), sql.Literal(secret)))
            c.execute('DELETE FROM public.fw_intake_worker_scopes WHERE worker_login=%s', (LOGIN,))
            for workspace in workspaces:
                c.execute('INSERT INTO public.fw_intake_worker_scopes(worker_login,workspace,assigned_by) VALUES(%s,%s,%s)',
                          (LOGIN, workspace, str(params.get('user', 'operator'))))
    except BaseException:
        # Preserve the private authority file: after a lost DB acknowledgement it
        # may contain the only credential matching the committed ALTER ROLE.
        raise
    return {'provisioned': True, 'runtime_authority': str(target), 'workspaces': len(workspaces),
            'db_login': LOGIN, 'decoder_image_id': decoder_image_id, 'secret_printed': False}


class TenantIntakeStore:
    """Store adapter that fences every run_intake transaction at commit."""
    is_request = False

    def __init__(self, authority: dict, row: dict, *, before_commit: Callable):
        self.authority = authority
        self.row = row
        self.before_commit = before_commit

    @contextmanager
    def connect(self, *, isolation_level=None):
        c = _connect(self.authority)
        try:
            if isolation_level is not None:
                c.isolation_level = isolation_level
            c.execute("SELECT set_config('fieldwork.workspace',%s,true), set_config('fieldwork.intake_id',%s,true)",
                      (self.row['workspace'], str(self.row['intake_id'])))
            # RightsService opens read-only REPEATABLE READ repositories while the
            # import transaction is active. They do not take the catalog mutex.
            if isolation_level is None:
                c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                          ('fieldwork-real-intake:' + self.row['workspace'],))
                self._assert_current_lease(c, self.row, lock=False)
            yield c
            if isolation_level is None:
                self._renew_for_commit(c, self.row)
                self.before_commit(c, self.row)
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    @staticmethod
    def _assert_current_lease(c, row, *, lock):
        suffix = ' FOR UPDATE' if lock else ''
        current = c.execute('''SELECT lease_until FROM public.fw_real_intake_queue
            WHERE workspace=%s AND intake_id=%s AND state='running' AND lease_owner=%s AND lease_fence=%s
              AND lease_until>clock_timestamp()''' + suffix,
            (row['workspace'], row['intake_id'], row['lease_owner'], row['lease_fence'])).fetchone()
        if not current:
            raise LeaseLost('INTAKE_LEASE_LOST')

    @staticmethod
    def _renew_for_commit(c, row):
        # Renew only a still-live exact fence, atomically locking the queue row.
        # This is not an expiry bypass: a lease that has expired cannot be revived.
        current = c.execute('''UPDATE public.fw_real_intake_queue
            SET lease_until=clock_timestamp()+(%s * interval '1 second')
            WHERE workspace=%s AND intake_id=%s AND state='running' AND lease_owner=%s AND lease_fence=%s
              AND lease_until>clock_timestamp() RETURNING lease_until''',
            (COMMIT_LEASE_SECONDS, row['workspace'], row['intake_id'], row['lease_owner'], row['lease_fence'])).fetchone()
        if not current:
            raise LeaseLost('INTAKE_LEASE_LOST')

    def rights_repository(self):
        from .rights_store import rights_repository
        return rights_repository(self)


def _set_tenant(c, workspace: str):
    c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (workspace,))


class IntakeWorker:
    def __init__(self, authority: dict, *, worker_id: str | None = None,
                 connect_factory: Callable | None = None, run_import: Callable | None = None):
        self.authority = authority
        self.worker_id = worker_id or str(uuid.uuid4())
        self.connect_factory = connect_factory or (lambda: _connect(authority))
        self.run_import = run_import or intake.run_intake
        self.stopping = threading.Event()
        self.registry_path = authority['rights_registry_path']
        os.environ['FIELDWORK_RIGHTS_REVIEWERS_FILE'] = self.registry_path
        self.rights_service = None

    def _db(self):
        return self.connect_factory()

    def workspaces(self):
        with self._db() as c:
            row = c.execute('SELECT fw_intake_cap_v1.my_workspaces() AS workspaces').fetchone()
            return row['workspaces']

    def _mark_exhausted(self, c, workspace):
        c.execute("""UPDATE public.fw_real_intake_queue SET state='interrupted',
          lease_owner=NULL,lease_until=NULL,last_error_code='RETRY_LIMIT',
          result_worker_id=lease_owner,result_fence=lease_fence,finished_utc=clock_timestamp()
          WHERE workspace=%s AND state='running' AND lease_until<=clock_timestamp() AND attempts>=%s""",
          (workspace, MAX_ATTEMPTS))

    def claim(self):
        for workspace in self.workspaces():
            with self._db() as c:
                _set_tenant(c, workspace)
                self._mark_exhausted(c, workspace)
                row = c.execute('''WITH target AS (
                    SELECT intake_id FROM public.fw_real_intake_queue
                    WHERE workspace=%s AND attempts<%s AND
                      (state='queued' OR (state='running' AND lease_until<=clock_timestamp()))
                    ORDER BY created_utc,intake_id FOR UPDATE SKIP LOCKED LIMIT 1
                  )
                  UPDATE public.fw_real_intake_queue q SET state='running',
                    lease_fence=q.lease_fence+1,lease_owner=%s,
                    lease_until=clock_timestamp()+(%s * interval '1 second'),attempts=q.attempts+1,last_error_code=NULL
                  FROM target WHERE q.workspace=%s AND q.intake_id=target.intake_id RETURNING q.*''',
                  (workspace, MAX_ATTEMPTS, self.worker_id, LEASE_SECONDS, workspace)).fetchone()
                if row:
                    return row
        return None

    def heartbeat_once(self, row):
        with self._db() as c:
            _set_tenant(c, row['workspace'])
            updated = c.execute('''UPDATE public.fw_real_intake_queue
                SET lease_until=clock_timestamp()+(%s * interval '1 second')
                WHERE workspace=%s AND intake_id=%s AND state='running'
                  AND lease_owner=%s AND lease_fence=%s AND lease_until>clock_timestamp()
                RETURNING intake_id''',
                (LEASE_SECONDS, row['workspace'], row['intake_id'], self.worker_id, row['lease_fence'])).fetchone()
            return bool(updated)

    def _heartbeat_loop(self, row, lost: threading.Event, heartbeat_stop: threading.Event):
        while not heartbeat_stop.wait(HEARTBEAT_SECONDS):
            try:
                if not self.heartbeat_once(row):
                    lost.set()
                    return
            except psycopg.Error:
                # A later DB-clock commit fence is authoritative; do not claim the
                # renewal succeeded and never extend locally on database failure.
                continue

    def _completed_batch(self, row):
        with self._db() as c:
            _set_tenant(c, row['workspace'])
            return c.execute('''SELECT batch_id,state,report_sha256 FROM public.fw_intake_batches
                WHERE workspace=%s AND source_intake_id=%s AND archive_sha256=%s AND archive_bytes=%s
                  AND actor=%s AND rights_dataset_id=%s AND state IN ('complete','rejected')
                ORDER BY finished_utc DESC,batch_id LIMIT 1''',
                (row['workspace'], row['intake_id'], row['archive_sha256'], row['archive_bytes'],
                 row['actor'], row['rights_dataset_id'])).fetchone()

    def _mark_staging_interrupted(self, row):
        with self._db() as c:
            _set_tenant(c, row['workspace'])
            c.execute('''UPDATE public.fw_intake_batches SET state='interrupted',reason='WORKER_REPLAY',
                finished_utc=clock_timestamp() WHERE workspace=%s AND source_intake_id=%s AND state='staging'
                AND archive_sha256=%s AND archive_bytes=%s AND actor=%s AND rights_dataset_id=%s
                AND EXISTS (SELECT 1 FROM public.fw_real_intake_queue q WHERE q.workspace=%s AND q.intake_id=%s
                  AND q.state='running' AND q.lease_owner=%s AND q.lease_fence=%s
                  AND q.lease_until>clock_timestamp())''',
                (row['workspace'], row['intake_id'], row['archive_sha256'], row['archive_bytes'],
                 row['actor'], row['rights_dataset_id'], row['workspace'], row['intake_id'],
                 self.worker_id, row['lease_fence']))

    def _publish(self, row, batch=None, *, reject_code=None):
        state = 'rejected' if reject_code or batch['state'] == 'rejected' else 'complete'
        batch_id = batch['batch_id'] if batch else None
        report_sha = batch['report_sha256'] if batch else None
        with self._db() as c:
            _set_tenant(c, row['workspace'])
            result = c.execute('''UPDATE public.fw_real_intake_queue SET state=%s,
                lease_owner=NULL,lease_until=NULL,last_error_code=%s,result_worker_id=%s,result_fence=%s,
                result_batch_id=%s,result_sha256=%s,finished_utc=clock_timestamp()
                WHERE workspace=%s AND intake_id=%s AND state='running' AND lease_owner=%s AND lease_fence=%s
                  AND lease_until>clock_timestamp()
                RETURNING intake_id''',
                (state, reject_code, self.worker_id, row['lease_fence'], batch_id, report_sha,
                 row['workspace'], row['intake_id'], self.worker_id, row['lease_fence'])).fetchone()
            return bool(result)

    def _requeue(self, row, code):
        with self._db() as c:
            _set_tenant(c, row['workspace'])
            if row['attempts'] >= MAX_ATTEMPTS:
                state = 'interrupted'
                result_worker = self.worker_id
                result_fence = row['lease_fence']
                finished = 'clock_timestamp()'
            else:
                state = 'queued'
                result_worker = None
                result_fence = None
                finished = 'NULL'
            sql = f'''UPDATE public.fw_real_intake_queue SET state=%s,lease_owner=NULL,lease_until=NULL,
                last_error_code=%s,result_worker_id=%s,result_fence=%s,finished_utc={finished}
                WHERE workspace=%s AND intake_id=%s AND state='running' AND lease_owner=%s AND lease_fence=%s
                  AND lease_until>clock_timestamp()'''
            c.execute(sql, (state, code, result_worker, result_fence, row['workspace'], row['intake_id'],
                            self.worker_id, row['lease_fence']))

    def _rights_check(self, row, repo, member, raw_sha256, raw_bytes):
        c = repo.c
        if not c.execute('SELECT fw_intake_cap_v1.actor_allowed(%s,%s) ok',
                         (row['workspace'], row['actor'])).fetchone()['ok']:
            return 'WORKSPACE_PERMISSION'
        asset = repo.asset(row['workspace'], row['rights_dataset_id'], member)
        if not asset:
            return 'NOT_IN_RIGHTS_INVENTORY'
        if asset['asset_sha256'] != raw_sha256 or asset['asset_bytes'] != raw_bytes:
            return 'DIGEST_DIFFERS_FROM_RIGHTS_INVENTORY'
        raw = repo.decision(row['workspace'], row['rights_dataset_id'], member, 'local_private_training')
        if raw is None:
            return 'MISSING_DECISION'
        try:
            self.rights_service._verify(repo, row['workspace'], row['rights_dataset_id'], member,
                                        'local_private_training', raw)
        except DecisionRejected as exc:
            if exc.code == 'RIGHTS_DATABASE_DEPENDENCY':
                raise
            return exc.code
        return None

    def _final_commit_gate(self, c, row, accepted):
        if not c.execute('SELECT fw_intake_cap_v1.lock_actor(%s,%s) ok',
                         (row['workspace'], row['actor'])).fetchone()['ok']:
            raise IntakeRefused('ACTOR_AUTHORITY_REVOKED')
        repo = RightsRepository(c)
        reviewer_keys = set()
        for member, asset_sha256, asset_bytes in accepted:
            locked = c.execute('''SELECT fw_intake_cap_v1.lock_rights(%s,%s,%s,%s,%s) ok''',
                (row['workspace'], row['rights_dataset_id'], member, asset_sha256, asset_bytes)).fetchone()['ok']
            if not locked:
                raise IntakeRefused('RIGHTS_CHANGED_BEFORE_COMMIT')
            raw = repo.decision(row['workspace'], row['rights_dataset_id'], member, 'local_private_training')
            try:
                verified = self.rights_service._verify(repo, row['workspace'], row['rights_dataset_id'], member,
                                                       'local_private_training', raw)
            except DecisionRejected:
                raise IntakeRefused('RIGHTS_CHANGED_BEFORE_COMMIT') from None
            reviewer_keys.add((verified.reviewer_id, verified.key_id))
        try:
            registry = self.rights_service.registry_provider()
        except DecisionRejected:
            raise IntakeRefused('RIGHTS_REGISTRY_UNAVAILABLE') from None
        for reviewer_key in reviewer_keys:
            trusted = registry.get(reviewer_key)
            if not trusted or row['workspace'] not in trusted.workspace_ids or 'local_private_training' not in trusted.purposes:
                raise IntakeRefused('RIGHTS_REVIEWER_REVOKED_BEFORE_COMMIT')
        TenantIntakeStore._assert_current_lease(c, row, lock=False)

    def process(self, row):
        upload_root = Path(self.authority['upload_root'])
        spool_root = Path(self.authority['spool_root'])
        try:
            # A completed batch is tied to this queue UUID by the migration trigger.
            # This is the acknowledgement-loss recovery path; no second batch or
            # sample rows are created on replay.
            existing = self._completed_batch(row)
            if existing:
                return 'published' if self._publish(row, existing) else 'lease_lost'

            archive_path = _spool_archive(row, upload_root=upload_root, spool_root=spool_root)

            # Keep old staging records and label them before a fresh bounded retry.
            self._mark_staging_interrupted(row)
            self.rights_service = RightsService(None, load_trusted_registry)
            accepted = []
            # The real-data queue never uses the legacy host subprocess decoder.
            # Preflight the exact locally pinned image before run_intake creates
            # its next staging batch; absence or mismatch fails this lease closed.
            decoder = ContainerDecoder(self.authority['decoder_image_id'], private_dir=spool_root,
                                       session_id=self.worker_id)

            def before_commit(c, lease_row):
                self._final_commit_gate(c, lease_row, accepted)

            store = TenantIntakeStore(self.authority, row, before_commit=before_commit)

            def rights_check(member, raw_sha256, raw_bytes):
                with store.rights_repository() as repo:
                    error = self._rights_check(row, repo, member, raw_sha256, raw_bytes)
                if error is None:
                    accepted.append((member, raw_sha256, raw_bytes))
                return error

            # The environment points only at an operator-controlled public-key
            # registry; no archive-provided trust or arbitrary code is loaded.
            quarantine = Path(self.authority['quarantine_root']) / row['workspace'] / str(row['intake_id'])
            try:
                report = self.run_import(store, row['workspace'], row['actor'], archive_path,
                    quarantine_root=quarantine, media_root=self.authority['media_root'],
                    rights_check=rights_check, rights_dataset_id=row['rights_dataset_id'],
                    member_prefix='', label_of=None, report_dir=None,
                    decoder_factory=lambda: decoder, repair_missing_features=True)
            finally:
                decoder.close()
            batch = self._completed_batch(row)
            if not batch or str(batch['batch_id']) != str(report['batch_id']):
                raise IntakeRefused('INTAKE_RESULT_BINDING')
            return 'published' if self._publish(row, batch) else 'lease_lost'
        except LeaseLost:
            return 'lease_lost'
        except IntakeRefused as exc:
            if exc.code in ('ARCHIVE_DIGEST_MISMATCH', 'ARCHIVE_PATH_OUTSIDE_UPLOAD_ROOT',
                            'ARCHIVE_REPARSE_POINT', 'ARCHIVE_NOT_FOUND', 'ARCHIVE_INVALID_SIZE'):
                return 'rejected' if self._publish(row, reject_code=exc.code) else 'lease_lost'
            self._requeue(row, exc.code)
            return 'retry'
        except (DecisionRejected, psycopg.Error, OSError, TimeoutError) as exc:
            code = getattr(exc, 'code', None) or type(exc).__name__.upper()
            code = ''.join(ch if ch.isalnum() or ch == '_' else '_' for ch in code)[:64].strip('_') or 'INTAKE_FAILED'
            self._requeue(row, code)
            return 'retry'
        except Exception as exc:
            code = getattr(exc, 'code', None) or type(exc).__name__.upper()
            self._requeue(row, str(code)[:64])
            return 'retry'

    def run_once(self):
        row = self.claim()
        if not row:
            return 'idle'
        lost = threading.Event()
        heartbeat_stop = threading.Event()
        beat = threading.Thread(target=self._heartbeat_loop, args=(row, lost, heartbeat_stop), daemon=True)
        beat.start()
        try:
            result = self.process(row)
        finally:
            heartbeat_stop.set()
            beat.join(timeout=HEARTBEAT_SECONDS + 2)
        # Each mutating path already checks the database fence and lease. A
        # heartbeat can fail after a valid terminal publish because the row is
        # no longer running; that does not invalidate the published result.
        return result

    def serve(self, poll_seconds=2):
        while not self.stopping.is_set():
            result = self.run_once()
            if result == 'idle':
                self.stopping.wait(poll_seconds)
            elif result == 'retry':
                self.stopping.wait(min(30, poll_seconds * 2))


def _main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority-file', required=True)
    parser.add_argument('--provision', action='store_true', help='operator-only: provision the NOLOGIN role as a scoped runtime login')
    parser.add_argument('--operator-file')
    parser.add_argument('--workspace', action='append', default=[])
    parser.add_argument('--upload-root')
    parser.add_argument('--spool-root')
    parser.add_argument('--quarantine-root')
    parser.add_argument('--media-root')
    parser.add_argument('--rights-registry-path')
    parser.add_argument('--decoder-image-id', help='actual sha256 image ID from the reviewed local container build')
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args(argv)
    if args.provision:
        required = (args.operator_file, args.workspace, args.upload_root, args.spool_root,
                    args.quarantine_root, args.media_root, args.rights_registry_path,
                    args.decoder_image_id)
        if not all(required):
            parser.error('--provision requires operator-file, workspace, and all four data roots plus rights-registry-path')
        try:
            result = provision_worker(operator_file=args.operator_file, authority_file=args.authority_file,
                workspaces=args.workspace, upload_root=args.upload_root, spool_root=args.spool_root,
                quarantine_root=args.quarantine_root, media_root=args.media_root,
                rights_registry_path=args.rights_registry_path, decoder_image_id=args.decoder_image_id)
            print(json.dumps(result))
            return 0
        except Exception as exc:
            code = getattr(exc, 'code', None) or type(exc).__name__.upper()
            code=code if isinstance(code,str) and 1<=len(code)<=64 and code.isascii() and code.replace('_','').isalnum() and code.upper()==code else type(exc).__name__.upper()
            _append_worker_error(code)
            print(json.dumps({'status': 'refused', 'code': str(code)[:64], 'secret_printed': False}))
            return 2
    try:
        authority = load_authority(args.authority_file)
        worker = IntakeWorker(authority)
        def request_stop(_signal, _frame):
            worker.stopping.set()
        signal.signal(signal.SIGINT, request_stop)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, request_stop)
        if args.once:
            print(json.dumps({'result': worker.run_once(), 'worker_id': worker.worker_id}))
        else:
            worker.serve()
    except Exception as exc:
        code = getattr(exc, 'code', None) or type(exc).__name__.upper()
        code=code if isinstance(code,str) and 1<=len(code)<=64 and code.isascii() and code.replace('_','').isalnum() and code.upper()==code else type(exc).__name__.upper()
        _append_worker_error(code)
        print(json.dumps({'status': 'failed', 'code': str(code)[:64], 'secret_printed': False}))
        return 2
    return 0


def _append_worker_error(code: str) -> None:
    """Write one allowlisted failure code with a short-lived private file handle."""
    path=ROOT/'.local'/'app-logs'/'intake-worker-errors.log'
    parent=path.parent
    try:
        from .privacy_lifecycle import _check_c_ancestry
        _check_c_ancestry(parent,allow_missing_leaf=True)
        parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        _check_c_ancestry(parent);check_private(parent)
        _check_c_ancestry(path,allow_missing_leaf=True)
        if path.exists():check_private(path)
        payload=json.dumps({'status':'failed','code':code[:64],'secret_printed':False},separators=(',',':'))+'\n'
        flags=os.O_WRONLY|os.O_CREAT|os.O_APPEND|getattr(os,'O_BINARY',0)
        fd=os.open(path,flags,0o600)
        try:
            os.write(fd,payload.encode('utf-8'));os.fsync(fd)
        finally:
            os.close(fd)
        _check_c_ancestry(path);check_private(path)
    except Exception:
        # Failure diagnostics never change a worker decision or leak exception text.
        return


if __name__ == '__main__':
    raise SystemExit(_main())
