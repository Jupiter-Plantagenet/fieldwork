"""Scoped machine identity for the training worker (round 5).

Replaces the trusted-operator DSN for `python -m fieldwork.worker` when
FIELDWORK_WORKER_AUTHORITY names a private authority file.

Boundary:
* LOGIN `<login>`: NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT,
  no memberships, password VALID UNTIL <= 5 minutes, no privilege on ANY public table or
  sequence, EXECUTE only on the fixed fw_worker_cap_v1 API functions.
* NOLOGIN `<login>_definer`: owns the SECURITY DEFINER functions, holds only the column
  grants in worker_sql.DEFINER_GRANTS, and is confined by permissive+restrictive RLS
  policies to the approved workspaces in the protected scope row (bound to session_user).
* Attempt credentials (5 min, renewed only by heartbeat on a live assignment) and the
  rotating login password are described in worker_sql.

CLI (operator; never prints secrets):
  python -m fieldwork.worker_identity provision --operator-file .local.json --authority-file <private>/worker-authority.json --login fw_worker_v1 --workspace <ws> [--workspace ...]
  python -m fieldwork.worker_identity rotate    --operator-file .local.json --authority-file <...> [--ttl-seconds 300]
  python -m fieldwork.worker_identity serve     --operator-file .local.json --authority-file <...> --worker-heartbeat var/worker.json [--interval 60]
  python -m fieldwork.worker_identity revoke    --operator-file .local.json --authority-file <...>
  python -m fieldwork.worker_identity verify    --operator-file .local.json --authority-file <...>
"""
import argparse, json, os, re, secrets, sys, time
from datetime import datetime, timezone
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.conninfo import conninfo_to_dict
from psycopg.types.json import Jsonb
from . import worker_sql as W
from .artifact_state import ArtifactState, identity, alive
from .store import Store, Conflict, CancelGenerationConflict, ROOT

MODE = 'scoped-worker-v1'
MAX_TTL = 300
LOGIN_RE = re.compile(r'fw_worker_[a-z0-9_]{1,40}')


# ---------------------------------------------------------------- provisioning (operator)
def _definer(login):
    return login + '_definer'


def _create_function(c, name, owner):
    signature, returns, language, volatility, body = W.FUNCTIONS[name]
    c.execute(sql.SQL('CREATE FUNCTION ' + W.SCHEMA + '.' + name + '(' + signature + ') RETURNS ' + returns +
                      ' LANGUAGE ' + language + ' ' + volatility +
                      ' SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS {}').format(sql.Literal(body)))
    c.execute(sql.SQL('ALTER FUNCTION ' + W.SCHEMA + '.' + name + '(' + _types(signature) + ') OWNER TO {}').format(sql.Identifier(owner)))
    c.execute(sql.SQL('REVOKE ALL ON FUNCTION ' + W.SCHEMA + '.' + name + '(' + _types(signature) + ') FROM PUBLIC'))


def _types(signature):
    return ','.join(part.strip().split(' ', 1)[1] for part in signature.split(',') if part.strip())


def provision(c, login, password, workspaces, ttl=MAX_TTL):
    """One operator transaction. Never adopts pre-existing roles or schema."""
    if not LOGIN_RE.fullmatch(login):
        raise ValueError('WORKER_LOGIN_NAME')
    if not workspaces or any(not isinstance(w, str) or not w or w == '*' for w in workspaces) or len(set(workspaces)) != len(workspaces):
        raise ValueError('WORKER_SCOPE_INVALID')
    definer = _definer(login)
    for role in (login, definer):
        if c.execute('SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s', (role,)).fetchone():
            raise ValueError('EXISTING_WORKER_ROLE_NOT_ADOPTED')
    if c.execute('SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=%s', (W.SCHEMA,)).fetchone():
        raise ValueError('EXISTING_WORKER_SCHEMA_NOT_ADOPTED')
    if not c.execute("SELECT to_regclass('public.fw_control') IS NOT NULL ok").fetchone()['ok']:
        raise ValueError('MIGRATION_005_REQUIRED')
    L, D = sql.Identifier(login), sql.Identifier(definer)
    c.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD {} VALID UNTIL {}').format(
        L, sql.Literal(password), sql.Literal(_until(ttl))))
    c.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT').format(D))
    c.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(W.SCHEMA)))
    c.execute(sql.SQL('REVOKE ALL ON SCHEMA {} FROM PUBLIC').format(sql.Identifier(W.SCHEMA)))
    c.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}, {}').format(sql.Identifier(W.SCHEMA), L, D))
    c.execute('CREATE TABLE fw_worker_cap_v1.scope(principal text PRIMARY KEY, workspaces text[] NOT NULL, version int NOT NULL, definer text NOT NULL)')
    c.execute('CREATE TABLE fw_worker_cap_v1.credentials(token_hash text PRIMARY KEY, principal text NOT NULL, run text NOT NULL, attempt text NOT NULL, expires_at timestamptz NOT NULL, created timestamptz NOT NULL DEFAULT now())')
    c.execute('INSERT INTO fw_worker_cap_v1.scope VALUES(%s,%s,1,%s)', (login, list(workspaces), definer))
    c.execute(sql.SQL('GRANT SELECT ON fw_worker_cap_v1.scope TO {}').format(D))
    c.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON fw_worker_cap_v1.credentials TO {}').format(D))
    for g in W.DEFINER_GRANTS:
        c.execute(sql.SQL(g.replace('{d}', '{}')).format(D))
    for name in W.FUNCTIONS:
        _create_function(c, name, definer)
    for table, expression in W.POLICY_TABLES.items():
        for mode, suffix in (('PERMISSIVE', 'p'), ('RESTRICTIVE', 'r')):
            c.execute(sql.SQL('CREATE POLICY {} ON public.{} AS ' + mode + ' FOR ALL TO {} USING (' + expression + ') WITH CHECK (' + expression + ')').format(
                sql.Identifier('fw_worker_' + suffix), sql.Identifier(table), D))
    for name in W.PUBLIC_API:
        c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION ' + W.SCHEMA + '.' + name + '(' + _types(W.FUNCTIONS[name][0]) + ') TO {}').format(L))
    c.execute(sql.SQL('ALTER ROLE {} SET statement_timeout=15000').format(L))
    c.execute(sql.SQL('ALTER ROLE {} SET idle_in_transaction_session_timeout=30000').format(L))
    verify(c, login, workspaces)
    _grant_real_worker_api(c, login)


def _grant_real_worker_api(c, login):
    """Add the separate fixed real-run entry points when migration 007 is installed."""
    if not c.execute("SELECT to_regnamespace('fw_real_worker_cap_v1') AS n").fetchone()['n']:
        return
    expected = {
        'next_real_run': 'text[]',
        'claim_real': 'text,text,integer,doubleprecision,text',
        'next_real_artifact': 'text[]',
        'claim_real_artifacts': 'text,integer,doubleprecision',
        'real_inputs': 'text,text,text,integer,integer,uuid',
        'real_member_rights': 'text,text,text,integer,integer,uuid,text',
        'real_bundle_rights': 'text,text,text,integer,integer,uuid',
        'real_artifact_rights': 'text,integer,integer,doubleprecision',
        'real_inference_input': 'text,text,text,integer,integer,uuid',
        'complete_real_inference': 'text,text,text,integer,integer,uuid,jsonb,integer,doubleprecision,boolean',
    }
    fresh = c.execute("""SELECT to_regprocedure('fw_real_worker_cap_v1.real_image_inference_input(text,text,text,integer,integer,uuid,text)') IS NOT NULL AS input,
        to_regprocedure('fw_real_worker_cap_v1.complete_real_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text)') IS NOT NULL AS complete""").fetchone()
    if fresh['input'] != fresh['complete']:
        raise ValueError('REAL_IMAGE_CAPABILITY_SCHEMA_MISMATCH')
    if fresh['input']:
        expected.update({
            'real_image_inference_input': 'text,text,text,integer,integer,uuid,text',
            'complete_real_image_inference': 'text,text,text,integer,integer,uuid,jsonb,integer,doubleprecision,boolean,text,text,text',
        })
    qualified = c.execute("""SELECT to_regprocedure('fw_real_worker_cap_v1.qualified_image_inference_input(text,text,text,integer,integer,uuid,text)') IS NOT NULL AS input,
        to_regprocedure('fw_real_worker_cap_v1.complete_qualified_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text)') IS NOT NULL AS complete""").fetchone()
    if qualified['input'] != qualified['complete']:
        raise ValueError('QUALIFIED_IMAGE_CAPABILITY_SCHEMA_MISMATCH')
    if qualified['input']:
        expected.update({
            'qualified_image_inference_input': 'text,text,text,integer,integer,uuid,text',
            'complete_qualified_image_inference': 'text,text,text,integer,integer,uuid,jsonb,integer,doubleprecision,boolean,text,text,text',
        })
    retention = c.execute("""SELECT to_regprocedure('fw_real_worker_cap_v1.bundle_inference_blocked(text,text)') IS NOT NULL AS available""").fetchone()['available']
    if retention:
        expected['bundle_inference_blocked'] = 'text,text'
    for name, args in expected.items():
        if not c.execute('''SELECT 1 FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='fw_real_worker_cap_v1' AND p.proname=%s
              AND replace(pg_catalog.oidvectortypes(p.proargtypes),' ','')=%s''', (name, args)).fetchone():
            raise ValueError('REAL_WORKER_CAPABILITY_SCHEMA_MISMATCH')
    c.execute(sql.SQL('GRANT USAGE ON SCHEMA fw_real_worker_cap_v1 TO {}').format(sql.Identifier(login)))
    for name, signature in (
        ('next_real_run', 'text[]'),
        ('claim_real', 'text,text,integer,double precision,text'),
        ('next_real_artifact', 'text[]'),
        ('claim_real_artifacts', 'text,integer,double precision'),
        ('real_inputs', 'text,text,text,integer,integer,uuid'),
        ('real_member_rights', 'text,text,text,integer,integer,uuid,text'),
        ('real_bundle_rights', 'text,text,text,integer,integer,uuid'),
        ('real_artifact_rights', 'text,integer,integer,double precision'),
        ('real_inference_input', 'text,text,text,integer,integer,uuid'),
        ('complete_real_inference', 'text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean'),
    ):
        c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.{}(' + signature + ') TO {}')
                  .format(sql.Identifier(name), sql.Identifier(login)))
    if fresh['input']:
        for name, signature in (
            ('real_image_inference_input', 'text,text,text,integer,integer,uuid,text'),
            ('complete_real_image_inference', 'text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text'),
        ):
            c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.{}(' + signature + ') TO {}')
                      .format(sql.Identifier(name), sql.Identifier(login)))
    if qualified['input']:
        for name, signature in (
            ('qualified_image_inference_input', 'text,text,text,integer,integer,uuid,text'),
            ('complete_qualified_image_inference', 'text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text'),
        ):
            c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.{}(' + signature + ') TO {}')
                      .format(sql.Identifier(name), sql.Identifier(login)))
    if retention:
        c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION fw_real_worker_cap_v1.bundle_inference_blocked(text,text) TO {}')
                  .format(sql.Identifier(login)))


def _until(ttl):
    if not 1 <= ttl <= MAX_TTL:
        raise ValueError('CREDENTIAL_TTL_ABOVE_5_MINUTES')
    return datetime.fromtimestamp(time.time() + ttl, timezone.utc).isoformat()


def verify(c, login, workspaces=None):
    """Fail closed on drift: role flags, memberships, schema ACL/objects, function bodies,
    owners, search_path, EXECUTE grants, scope, and ANY public-table privilege of the login."""
    definer = _definer(login)
    for role, can_login in ((login, True), (definer, False)):
        f = c.execute('SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication,rolinherit,rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=%s', (role,)).fetchone()
        if not f or f['rolsuper'] or f['rolbypassrls'] or f['rolcreatedb'] or f['rolcreaterole'] or f['rolreplication'] or f['rolinherit'] or f['rolcanlogin'] != can_login:
            raise ValueError('WORKER_ROLE_UNSAFE')
    if c.execute('''SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member OR r.oid=m.roleid
                    WHERE r.rolname=ANY(%s)''', ([login, definer],)).fetchone():
        raise ValueError('WORKER_ROLE_MEMBERSHIP')
    schema = c.execute('''SELECT n.oid, r.rolsuper OR n.nspowner=d.datdba AS trusted FROM pg_catalog.pg_namespace n
        JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner JOIN pg_catalog.pg_database d ON d.datname=current_database()
        WHERE n.nspname=%s''', (W.SCHEMA,)).fetchone()
    if not schema or not schema['trusted']:
        raise ValueError('WORKER_SCHEMA_OWNER')
    if c.execute('''SELECT 1 FROM pg_catalog.pg_namespace n, LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
                    WHERE n.oid=%s AND a.privilege_type='CREATE' AND a.grantee<>n.nspowner''', (schema['oid'],)).fetchone():
        raise ValueError('WORKER_SCHEMA_CREATE_GRANTED')
    rows = c.execute('''SELECT p.proname, pg_catalog.pg_get_userbyid(p.proowner) owner, p.prosecdef, p.proconfig, p.prosrc,
        pg_catalog.has_function_privilege(%s,p.oid,'EXECUTE') login_exec,
        EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee=0) public_exec
        FROM pg_catalog.pg_proc p WHERE p.pronamespace=%s''', (login, schema['oid'])).fetchall()
    if sorted(r['proname'] for r in rows) != sorted(W.FUNCTIONS):
        raise ValueError('WORKER_SCHEMA_FOREIGN_OR_MISSING_FUNCTIONS')
    for r in rows:
        if (r['owner'] != definer or not r['prosecdef'] or r['proconfig'] != ['search_path=pg_catalog, pg_temp']
                or r['prosrc'] != W.FUNCTIONS[r['proname']][4] or r['public_exec']
                or r['login_exec'] != (r['proname'] in W.PUBLIC_API)):
            raise ValueError('WORKER_FUNCTION_MISMATCH:' + r['proname'])
    if c.execute('SELECT count(*) n FROM pg_catalog.pg_class WHERE relnamespace=%s AND relkind=%s', (schema['oid'], 'r')).fetchone()['n'] != 2:
        raise ValueError('WORKER_SCHEMA_FOREIGN_TABLES')
    scope = c.execute('SELECT principal,workspaces,version,definer FROM fw_worker_cap_v1.scope').fetchall()
    if len(scope) != 1 or scope[0]['principal'] != login or scope[0]['definer'] != definer or (workspaces is not None and scope[0]['workspaces'] != list(workspaces)):
        raise ValueError('WORKER_SCOPE_MISMATCH')
    for t in c.execute("SELECT c.oid, c.relname, c.relkind FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public',%s) AND c.relkind IN ('r','p','v','m','S')", (W.SCHEMA,)).fetchall():
        privileges = ['USAGE', 'SELECT', 'UPDATE'] if t['relkind'] == 'S' else ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']
        for p in privileges:
            check = 'has_sequence_privilege' if t['relkind'] == 'S' else 'has_table_privilege'
            if c.execute('SELECT pg_catalog.' + check + '(%s,%s::oid,%s) x', (login, t['oid'], p)).fetchone()['x']:
                raise ValueError('WORKER_LOGIN_TABLE_PRIVILEGE:' + t['relname'] + ':' + p)
        if t['relkind'] != 'S' and c.execute("SELECT pg_catalog.has_any_column_privilege(%s,%s::oid,'SELECT') OR pg_catalog.has_any_column_privilege(%s,%s::oid,'UPDATE') OR pg_catalog.has_any_column_privilege(%s,%s::oid,'INSERT') x",
                                             (login, t['oid'], login, t['oid'], login, t['oid'])).fetchone()['x']:
            raise ValueError('WORKER_LOGIN_COLUMN_PRIVILEGE:' + t['relname'])
    for table in W.POLICY_TABLES:
        row = c.execute('SELECT relrowsecurity,relforcerowsecurity FROM pg_catalog.pg_class WHERE oid=%s::regclass', ('public.' + table,)).fetchone()
        if not row or not all(row.values()):
            raise ValueError('WORKER_RLS_REQUIRED')
    return {'login': login, 'scope': scope[0]['workspaces'], 'functions': len(rows), 'verified': True}


def rotate(c, login, ttl=MAX_TTL):
    password = secrets.token_urlsafe(48)
    c.execute(sql.SQL('ALTER ROLE {} WITH LOGIN PASSWORD {} VALID UNTIL {}').format(sql.Identifier(login), sql.Literal(password), sql.Literal(_until(ttl))))
    return password


def revoke(c, login):
    """Definitive stop: NOLOGIN, expired password, terminate its sessions, drop attempt credentials."""
    c.execute(sql.SQL("ALTER ROLE {} WITH NOLOGIN VALID UNTIL '1970-01-01T00:00:00Z'").format(sql.Identifier(login)))
    c.execute('DELETE FROM fw_worker_cap_v1.credentials WHERE principal=%s', (login,))
    terminated = c.execute('SELECT count(pg_catalog.pg_terminate_backend(pid)) n FROM pg_catalog.pg_stat_activity WHERE usename=%s', (login,)).fetchone()['n']
    return {'revoked': True, 'sessions_terminated': terminated}


# ---------------------------------------------------------------- private authority file
def write_authority(path, authority):
    """Atomic private write; first creation goes through scoped_authority's private-dir/ACL path."""
    from .scoped_authority import check_private, _powershell
    path = Path(path)
    if not path.parent.exists():
        path.parent.mkdir(mode=0o700)
        if os.name == 'nt':
            p = str(path.parent.resolve()).replace("'", "''")
            _powershell("$ErrorActionPreference='Stop'; $p='" + p + "'; $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; "
                        "& icacls.exe $p /inheritance:r /grant:r ('*'+$sid.Value+':(OI)(CI)F') | Out-Null; if($LASTEXITCODE -ne 0){throw 'ACL_FAILED'}")
    check_private(path.parent)
    tmp = path.with_name(path.name + '.' + secrets.token_hex(6) + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(authority, f); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    check_private(path)


def read_authority(path):
    from .scoped_authority import check_private
    path = Path(path)
    check_private(path)
    a = json.loads(path.read_text())
    c = a.get('connection') or {}
    if a.get('authority_mode') != MODE or set(c) != {'host', 'port', 'dbname', 'user', 'password', 'sslmode'} or c['host'] not in ('127.0.0.1', '::1') or not LOGIN_RE.fullmatch(c['user']):
        raise ValueError('INVALID_WORKER_AUTHORITY')
    return a


def _operator(path):
    return psycopg.connect(json.loads(Path(path).read_text())['dsn'], row_factory=dict_row)


# ---------------------------------------------------------------- worker side
class WorkerStore(Store):
    """Store whose every DB access is a fw_worker_cap_v1 function call as the scoped login."""
    identity_mode = MODE

    def __init__(self, authority_path):
        self.authority_path = Path(authority_path)
        self.is_request = False
        self.blob_root = ROOT / 'var/checkpoints'
        self._tokens = {}
        # ACL check + parse once at start (fail closed); afterwards only when the file
        # changes (rotation). Live incident 2026-10-31: re-running the PowerShell ACL check
        # on every connect timed out under host memory pressure and killed the worker.
        self._authority = read_authority(self.authority_path)
        self._authority_mtime = self.authority_path.stat().st_mtime_ns

    def _current_authority(self):
        try:
            mtime = self.authority_path.stat().st_mtime_ns
            if mtime != self._authority_mtime:
                self._authority = read_authority(self.authority_path); self._authority_mtime = mtime
        except Exception as exc:  # transient ACL-check/IO failure: keep the last verified credential
            print(json.dumps({'code': 'AUTHORITY_RELOAD_DEFERRED', 'error': type(exc).__name__}), flush=True)
        return self._authority

    @staticmethod
    def _password_authentication_refused(exc):
        """Classify only a PostgreSQL password rejection as a rotatable failure.

        Some libpq/psycopg builds expose SQLSTATE 28P01 at connect time; others
        leave it unset and include the server's fixed password-authentication
        phrase in the exception. Never log or return that exception text.
        """
        if getattr(exc, 'sqlstate', None) == '28P01':
            return True
        try:
            return 'password authentication failed' in str(exc).casefold()
        except Exception:
            return False

    def _force_authority_reload(self):
        """Reload and validate the private authority independent of cached mtime.

        The issuer atomically publishes its new password before ALTER ROLE. A
        connect can therefore hold a stale snapshot across the commit. After
        confirmed password-auth failures only, force one fresh ACL/schema read;
        reject endpoint, identity or scope changes before using the replacement.
        """
        before = self.authority_path.stat()
        refreshed = read_authority(self.authority_path)  # includes private ACL + schema checks
        after = self.authority_path.stat()
        if ((before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size)
                or refreshed.get('authority_mode') != self._authority.get('authority_mode')
                or refreshed.get('workspaces') != self._authority.get('workspaces')):
            raise ValueError('WORKER_AUTHORITY_RELOAD_REFUSED') from None
        old_connection = self._authority.get('connection') or {}
        new_connection = refreshed.get('connection') or {}
        stable_fields = ('host', 'port', 'dbname', 'user', 'sslmode')
        if any(new_connection.get(key) != old_connection.get(key) for key in stable_fields):
            raise ValueError('WORKER_AUTHORITY_RELOAD_REFUSED') from None
        self._authority = refreshed
        self._authority_mtime = after.st_mtime_ns
        return refreshed

    def connect(self, *, isolation_level=None):
        if any(k.startswith('PG') for k in os.environ):
            raise ValueError('LIBPQ_ENVIRONMENT_FORBIDDEN')
        # Connections are the only retried operation: no SQL has run yet. Keep
        # current+previous fallback, then force exactly one fully validated file
        # reload if both fail specifically as password authentication failures.
        # Each connect retains its 3s bound; network, NOLOGIN and other auth errors
        # are not retried as if a password rotation could repair them.
        authority = self._current_authority()
        last = None
        for snapshot in range(2):
            connection = authority['connection']
            passwords = [connection['password']]
            previous = authority.get('previous_password')
            if previous and previous not in passwords:
                passwords.append(previous)
            auth_failures = 0
            for password in passwords:
                try:
                    return psycopg.connect(host=connection['host'], port=connection['port'],
                        dbname=connection['dbname'], user=connection['user'], password=password,
                        sslmode=connection['sslmode'], connect_timeout=3, row_factory=dict_row,
                        options='-c search_path=pg_catalog,pg_temp',
                        application_name='fieldwork-scoped-worker')
                except psycopg.OperationalError as exc:
                    last = exc
                    if not self._password_authentication_refused(exc):
                        raise
                    auth_failures += 1
            if snapshot == 0 and auth_failures == len(passwords):
                authority = self._force_authority_reload()
                continue
            break
        raise last

    def migrate(self):
        return None  # the scoped login can run no DDL

    def _call(self, name, *args, c=None):
        placeholders = ','.join(['%s'] * len(args))
        statement = 'SELECT ' + W.SCHEMA + '.' + name + '(' + placeholders + ') AS v'
        try:
            if c is not None:
                return c.execute(statement, args).fetchone()['v']
            with self.connect() as conn:
                return conn.execute(statement, args).fetchone()['v']
        except psycopg.errors.RaiseException as exc:
            code = exc.diag.message_primary or 'WORKER_CAPABILITY_REFUSED'
            detail = {}
            try:
                detail = json.loads(exc.diag.message_detail or '{}')
            except ValueError:
                pass
            if code.startswith('CANCEL_GENERATION') or code == 'WRONG_GENERATION':
                raise CancelGenerationConflict(code, detail.get('state'), detail.get('current_generation')) from None
            raise Conflict(code) from None

    def _token(self, attempt):
        return self._tokens.get(attempt, '')

    @staticmethod
    def _jsonb(value):
        return Jsonb(value)

    # reads
    def get(self, rid, workspace=None):
        return self._call('get_run', rid)

    def next_run(self, blocked=()):
        return self._call('next_run', [f'{rid}@{rev}' for rid, rev in blocked])

    def resume_checkpoint(self, rid, epoch, attempt=None):
        return self._call('get_checkpoint', rid, epoch)

    def checkpoints(self, rid):
        raise NotImplementedError('not part of the worker capability')

    # ML-Claim / ML-Start / heartbeat / checkpoint / complete / fail
    def claim(self, rid, expected_cancel_generation=None, *, start=True, worker_id=None, key=None, actor=None):
        pid, created = identity()
        r = self._call('claim', rid, True, expected_cancel_generation, worker_id or 'worker', pid, created, key)
        self._tokens[r['attempt']] = r.pop('credential')
        if start:
            started = self.start(rid, r['attempt'], r['fence'], r['cancel_generation'], r['digest'], restore_generation=r['restore_generation'])
            r.update(state=started['state'], revision=started['revision'])
        return r

    def start(self, rid, attempt, fence, cancel_generation, resolved_config_digest, *, restore_generation=None, key=None, actor=None):
        return self._call('start', self._token(attempt), rid, attempt, fence, cancel_generation, resolved_config_digest, restore_generation, key)

    def heartbeat(self, rid, fence, cancel_generation, *, attempt=None, restore_generation=None, key=None, actor=None):
        out = self._call('heartbeat', self._token(attempt), rid, attempt, fence, cancel_generation, restore_generation, key)
        return {**out, 'cancel_generation': cancel_generation}

    def publish(self, rid, fence, cancel_generation, path, metrics, *, attempt=None, restore_generation=None, key=None, actor=None):
        from .ml import validate_checkpoint
        from .checkpoint_store import promote
        # Refuse a fenced worker before writing blobs: a heartbeat-free liveness probe.
        run = self.get(rid)
        if not run or run['state'] != 'running' or run['fence'] != fence or run['attempt'] != attempt:
            raise Conflict('FENCED_OR_EXPIRED_OR_CANCELLED')
        path, md = promote(path, self.blob_root)
        meta = json.loads((Path(path) / 'state.json').read_text())
        with self.connect() as c:
            out = self._call('publish', self._token(attempt), rid, attempt, fence, cancel_generation, restore_generation,
                             metrics['epoch'], md, str(path), Jsonb(metrics), Jsonb(meta), key, c=c)
            # Review F2: re-validate the committed blob inside the same transaction.
            validate_checkpoint(path, md)
        return out

    def complete(self, rid, fence, cancel_generation, result, *, attempt=None, restore_generation=None, key=None, actor=None):
        slot = self._call('slot_status'); pid, created = identity()
        exited = not slot['launching'] and not alive(slot['pid'], slot['child_created'])
        return self._call('complete', self._token(attempt), rid, attempt, fence, cancel_generation, restore_generation,
                          Jsonb(result), pid, created, exited, key)

    def fail(self, rid, attempt, fence, error_code, retryable, diagnostics_digest, *, restore_generation=None, key=None, actor=None):
        return self._call('fail', self._token(attempt), rid, attempt, fence, error_code, bool(retryable), diagnostics_digest, restore_generation, key)

    def acknowledge_cancel(self, rid, fence, cancel_generation, *, exit_receipt=None, lease_expired=False, key=None, actor=None):
        return self.release_slot(rid, fence=fence, cancel_generation=cancel_generation, exit_receipt=exit_receipt, lease_expired=lease_expired, key=key)

    def release_slot(self, rid, fence=None, *, cancel_generation=None, exit_receipt=None, lease_expired=False, key=None, actor=None):
        slot = self._call('slot_status'); pid, created = identity()
        exited = not alive(slot['pid'], slot['child_created'])
        return self._call('release_slot', rid, fence, cancel_generation, self.exit_receipt_digest(exit_receipt), bool(lease_expired), pid, created, exited, key)

    # physical slot bookkeeping (process facts are the worker's own; the DB cannot see processes)
    def begin_child(self, rid, fence, artifact=False):
        slot = self._call('slot_status'); pid, created = identity()
        self._call('begin_child', rid, fence, pid, created, alive(slot['pid'], slot['child_created']), artifact)

    def register_child(self, rid, fence, child):
        import psutil
        pid, created = identity()
        try:
            birth = psutil.Process(child.pid).create_time()
        except psutil.NoSuchProcess:
            if child.poll() is None:
                raise
            birth = None
        self._call('register_child', rid, fence, pid, created, child.pid, birth)

    def child_spawn_failed(self, rid, fence):
        pid, created = identity()
        self._call('child_spawn_failed', rid, fence, pid, created)

    def _slot_expected(self, slot):
        return Jsonb({k: slot[k] for k in ('run', 'fence', 'owner_pid', 'owner_created', 'pid', 'child_created', 'launching')})

    def reconcile_training_slot(self):
        slot = self._call('slot_status')
        if slot['run'] is None:
            return None
        if not slot['run_in_scope']:
            return 'OUT_OF_SCOPE'
        if slot['run_state'] == 'succeeded' and slot['artifact_status'] in ('pending', 'building', 'inference', 'retry_pending'):
            return 'ARTIFACT_RECOVERY_OWNS_SLOT'
        if slot['owner_pid'] is None or slot['owner_created'] is None:
            return 'OWNER_IDENTITY_UNKNOWN'
        if alive(slot['owner_pid'], slot['owner_created']):
            return 'OWNER_ALIVE'
        if slot['launching']:
            return 'CHILD_EXIT_UNCONFIRMED'
        if alive(slot['pid'], slot['child_created']):
            return 'CHILD_ALIVE'
        from .real_container_guard import model_cleanup_pending
        if model_cleanup_pending():return 'REAL_MODEL_CLEANUP_REQUIRED'
        return self._call('slot_release_if', self._slot_expected(slot), 'OWNER_AND_CHILD_EXIT_CONFIRMED')

    def release_own_slot(self):
        slot = self._call('slot_status')
        if slot['run'] is None or (slot['owner_pid'], slot['owner_created']) != identity():
            return None
        if slot['launching']:
            return 'CHILD_EXIT_UNCONFIRMED'
        if alive(slot['pid'], slot['child_created']):
            return 'CHILD_ALIVE'
        from .real_container_guard import model_cleanup_pending
        if model_cleanup_pending():return 'REAL_MODEL_CLEANUP_REQUIRED'
        return self._call('slot_release_if', self._slot_expected(slot), 'OWNER_RELEASED_AFTER_CHILD_EXIT')

    # artifacts
    def claim_artifacts(self, rid):
        pid, created = identity()
        return self._call('claim_artifacts', rid, pid, created)

    def artifact_heartbeat(self, rid, fence):
        pid, created = identity()
        self._call('artifact_heartbeat', rid, fence, pid, created)

    def artifact_transition(self, rid, fence, status, detail):
        slot = self._call('slot_status'); pid, created = identity()
        self._call('artifact_transition', rid, fence, status, Jsonb(detail), pid, created, not alive(slot['pid'], slot['child_created']))

    def recover_artifacts(self):
        from .real_container_guard import model_cleanup_pending
        if model_cleanup_pending():return []
        data = self._call('artifact_orphans'); slot = data['slot']; recovered = []
        for r in data['rows']:
            if alive(r['artifact_owner_pid'], r['artifact_owner_created']):
                continue
            owns = slot['run'] == r['id']
            exact = owns and slot['fence'] == r['fence'] and (slot['owner_pid'], slot['owner_created']) == (r['artifact_owner_pid'], r['artifact_owner_created'])
            if owns and not exact:
                continue
            if r['artifact_status'] in ('failed', 'verified'):
                if not exact or slot['owner_pid'] is None or slot['owner_created'] is None:
                    continue
                if alive(slot['owner_pid'], slot['owner_created']) or slot['launching'] or alive(slot['pid'], slot['child_created']):
                    continue
                if (r['artifact_result'] or {}).get('code') == 'ARTIFACT_CHILD_EXIT_UNCONFIRMED':
                    continue
                if self._call('artifact_recover', r['id'], r['fence'], None, None, True, self._slot_expected(slot)):
                    recovered.append(r['id'])
                continue
            if owns and alive(slot['pid'], slot['child_created']):
                continue
            if owns and slot['launching']:
                status = 'failed'; detail = {'code': 'ARTIFACT_CHILD_EXIT_UNCONFIRMED', 'automatic_retry': False}; clear = False
            else:
                status = 'retry_pending' if r['artifact_attempts'] < 3 else 'failed'
                detail = {'code': 'ARTIFACT_OWNER_DIED' if status == 'retry_pending' else 'ARTIFACT_ATTEMPT_BUDGET', 'automatic_retry': status == 'retry_pending'}
                clear = owns
            if self._call('artifact_recover', r['id'], r['fence'], status, Jsonb(detail), clear, self._slot_expected(slot)):
                recovered.append(r['id'])
        return recovered

    def event(self, *args, **kwargs):
        raise NotImplementedError('events are written only by capability functions')


# ---------------------------------------------------------------- CLI
def _heartbeat_live(path, max_age=120):
    """Renew only while the registered worker process is alive and heartbeating."""
    try:
        beat = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return False, 'NO_WORKER_HEARTBEAT'
    age = time.time() - datetime.fromisoformat(beat['as_of']).timestamp()
    if age > max_age:
        return False, 'WORKER_HEARTBEAT_STALE'
    if beat.get('identity') != MODE:
        return False, 'WORKER_NOT_SCOPED'
    if not alive(beat.get('pid'), beat.get('create_time')):
        return False, 'WORKER_PROCESS_GONE'
    return True, 'WORKER_LIVE'


def _rotate_file(operator_file, authority_file, ttl):
    a = read_authority(authority_file)
    new = secrets.token_urlsafe(48)
    staged = dict(a, previous_password=a['connection']['password'], connection=dict(a['connection'], password=new),
                  valid_until=_until(ttl), rotated_utc=datetime.now(timezone.utc).isoformat())
    write_authority(authority_file, staged)  # file first, then ALTER ROLE (worker tries both)
    try:
        with _operator(operator_file) as c:
            c.execute(sql.SQL('ALTER ROLE {} WITH LOGIN PASSWORD {} VALID UNTIL {}').format(sql.Identifier(a['connection']['user']), sql.Literal(new), sql.Literal(staged['valid_until'])))
    except Exception:
        write_authority(authority_file, a)  # ALTER not applied: the file must keep the live password
        raise
    return {'rotated': True, 'valid_until': staged['valid_until'], 'secret_printed': False}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('action', choices=['provision', 'rotate', 'serve', 'revoke', 'verify'])
    ap.add_argument('--operator-file', default=str(ROOT / '.local.json'))
    ap.add_argument('--authority-file', required=True)
    ap.add_argument('--login')
    ap.add_argument('--workspace', action='append')
    ap.add_argument('--ttl-seconds', type=int, default=MAX_TTL)
    ap.add_argument('--interval', type=int, default=60)
    ap.add_argument('--worker-heartbeat', default=str(ROOT / 'var/worker.json'))
    a = ap.parse_args(argv)
    if a.action == 'provision':
        dsn = conninfo_to_dict(json.loads(Path(a.operator_file).read_text())['dsn'])
        password = secrets.token_urlsafe(48)
        authority = {'authority_mode': MODE, 'connection': {'host': dsn.get('host', '127.0.0.1'), 'port': int(dsn.get('port', 5432)), 'dbname': dsn['dbname'],
                     'user': a.login, 'password': password, 'sslmode': 'disable'}, 'workspaces': a.workspace, 'valid_until': _until(a.ttl_seconds)}
        if Path(a.authority_file).exists():
            raise SystemExit('AUTHORITY_FILE_EXISTS')
        write_authority(a.authority_file, authority)
        with _operator(a.operator_file) as c:
            provision(c, a.login, password, a.workspace, a.ttl_seconds)
        print(json.dumps({'provisioned': True, 'login': a.login, 'workspaces': a.workspace, 'secret_printed': False}))
    elif a.action == 'rotate':
        print(json.dumps(_rotate_file(a.operator_file, a.authority_file, a.ttl_seconds)))
    elif a.action == 'verify':
        auth = read_authority(a.authority_file)
        with _operator(a.operator_file) as c:
            print(json.dumps(verify(c, auth['connection']['user'], auth.get('workspaces'))))
    elif a.action == 'revoke':
        auth = read_authority(a.authority_file)
        with _operator(a.operator_file) as c:
            print(json.dumps(revoke(c, auth['connection']['user'])))
    else:
        while True:
            live, reason = _heartbeat_live(a.worker_heartbeat)
            try:
                out = _rotate_file(a.operator_file, a.authority_file, a.ttl_seconds) if live else {'rotated': False, 'reason': reason}
            except Exception as exc:  # DB down / ACL check timeout: never die, retry next interval
                out = {'rotated': False, 'reason': 'ROTATION_FAILED', 'error': type(exc).__name__}
            print(json.dumps({**out, 'at': datetime.now(timezone.utc).isoformat()}), flush=True)
            time.sleep(a.interval)


if __name__ == '__main__':
    sys.exit(main())
