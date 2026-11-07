"""Isolated migrated chain 003..020 with the REAL request principal (`fieldwork_api`).

Used only by the leak/isolation matrices. It builds a throwaway `fieldwork_test_*` database in the
isolated verification cluster, installs the retained roles/capabilities in the retained order and applies
every authored migration. Cluster-global roles that the chain creates are dropped afterwards.
"""
import json, secrets, uuid
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
MIG = ROOT / 'migrations'
# Fixed names required by migrations 018/019 and created by the chain (global to the cluster).
CHAIN_ROLES = ['fw_worker_v1', 'fw_worker_v1_definer', 'fieldwork_real_worker_definer',
               'fw_lease_machine_v1', 'fw_lease_machine_v1_owner', 'fieldwork_intake_worker', 'fieldwork']


def _apply(s, name):
    with s.connect() as c:
        c.execute((MIG / name).read_text(encoding='utf-8'))


def drop_chain_roles(admin_dsn, keep=()):
    """Drop the chain's cluster-global roles when nothing in any database still depends on them.

    The roles are test-only and local to the isolated verification cluster (port 5552). A role that is still
    referenced (for example by the retained verification database) is left alone, so this never breaks it; the
    chain then reports the precondition failure instead of adopting it.
    """
    with psycopg.connect(admin_dsn, autocommit=True) as c:
        for role in [r for r in CHAIN_ROLES if r not in keep]:
            row = c.execute('SELECT oid FROM pg_roles WHERE rolname=%s', (role,)).fetchone()
            if not row:
                continue
            if c.execute('SELECT 1 FROM pg_shdepend WHERE refobjid=%s LIMIT 1', (row[0],)).fetchone():
                continue
            try:
                c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
            except psycopg.Error:
                pass


def api_dsn_for(db_name):
    """DSN of the retained request principal `fieldwork_api` (isolated cluster password) for one test database."""
    private = json.loads((ROOT / '.local-api.json').read_text())
    params = conninfo_to_dict(private['dsn'])
    assert params['user'] == 'fieldwork_api' and str(params['port']) == str(conninfo_to_dict(
        json.loads((ROOT / '.local.json').read_text())['dsn'])['port'])
    params['dbname'] = db_name
    return make_conninfo(**params), params['password']


def _install_checkpoint_read_existing_owner(c, login):
    """checkpoint_read.install minus CREATE ROLE (the global owner role already exists); same grants/body/verify."""
    from fieldwork import checkpoint_read as CR
    owner = login + '_cp_lock'
    assert c.execute('SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s', (owner,)).fetchone(), 'cp_lock owner role missing'
    ident = sql.Identifier
    c.execute(sql.SQL('CREATE SCHEMA {}').format(ident(CR.SCHEMA)))
    c.execute(sql.SQL('REVOKE ALL ON SCHEMA {} FROM PUBLIC').format(ident(CR.SCHEMA)))
    c.execute(sql.SQL('GRANT USAGE ON SCHEMA public,{} TO {}').format(ident(CR.SCHEMA), ident(owner)))
    c.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(ident(CR.SCHEMA), ident(login)))
    c.execute(sql.SQL('GRANT SELECT ON public.fw_runs TO {}').format(ident(owner)))
    c.execute(sql.SQL('GRANT SELECT ON public.fw_checkpoints TO {}').format(ident(owner)))
    c.execute(sql.SQL('GRANT UPDATE(digest) ON public.fw_checkpoints TO {}').format(ident(owner)))
    c.execute(sql.SQL('CREATE FUNCTION ' + CR.SIGNATURE.replace('(text,integer,text)', '(p_run text,p_epoch integer,p_workspace text)')
                      + ' RETURNS TABLE(digest text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS {}').format(
        sql.Literal(CR._body(login).as_string(c))))
    c.execute(sql.SQL('ALTER FUNCTION ' + CR.SIGNATURE + ' OWNER TO {}').format(ident(owner)))
    c.execute(sql.SQL('REVOKE ALL ON FUNCTION ' + CR.SIGNATURE + ' FROM PUBLIC'))
    c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION ' + CR.SIGNATURE + ' TO {}').format(ident(login)))
    CR.verify(c, login)


def create_chain(admin_dsn):
    """Create and migrate; any failure drops the half-built database so nothing is leaked in the cluster."""
    holder = {}
    try:
        return _create_chain(admin_dsn, holder)
    except BaseException:
        if holder.get('name'):
            destroy_chain(admin_dsn, holder['name'])
        raise


def _create_chain(admin_dsn, holder):
    """Create the throwaway database and apply the retained chain 003..020 as the retained owner role `fieldwork`.

    Migrations 015/018/019 name the live owner role `fieldwork`, which does not exist in the isolated verification
    cluster (superuser `fwverify`). A disposable superuser `fieldwork` is therefore created for the duration and
    dropped by `destroy_chain`. Returns (dba_store, request_store, name) where request_store is the retained
    nonowner/non-BYPASSRLS request principal `fieldwork_api`.
    """
    from fieldwork import db_security, worker_identity as WI, scoped_authority as SA, checkpoint_read
    from fieldwork.store import Store
    params = conninfo_to_dict(admin_dsn)
    assert params['host'] == '127.0.0.1' and str(params['port']) == '5552', 'chain only runs in the isolated cluster'
    owner_password = secrets.token_urlsafe(24)
    name = 'fieldwork_test_chain_' + uuid.uuid4().hex[:12]
    drop_chain_roles(admin_dsn, keep=('fieldwork',))
    with psycopg.connect(admin_dsn, autocommit=True) as c:
        if c.execute("SELECT 1 FROM pg_roles WHERE rolname='fieldwork'").fetchone():
            c.execute(sql.SQL('ALTER ROLE fieldwork LOGIN SUPERUSER PASSWORD {}').format(sql.Literal(owner_password)))
        else:
            c.execute(sql.SQL('CREATE ROLE fieldwork LOGIN SUPERUSER PASSWORD {}').format(sql.Literal(owner_password)))
        c.execute(sql.SQL('CREATE DATABASE {} OWNER fieldwork').format(sql.Identifier(name)))
    holder['name'] = name
    owner = dict(params, user='fieldwork', password=owner_password, dbname=name)
    s = Store(dsn=make_conninfo(**owner))
    s.migrate()
    for n in ('004_cancel_generation.sql', '005_restore_generation_guards.sql', '003_signed_rights.sql'):
        _apply(s, n)
    api_dsn, api_password = api_dsn_for(name)
    original = checkpoint_read.install
    # `fieldwork_api_cp_lock` is a permanent global role of the verification cluster; reuse it for this database.
    checkpoint_read.install = _install_checkpoint_read_existing_owner
    try:
        db_security.install(s, 'fieldwork_api', api_password)
    finally:
        checkpoint_read.install = original
    _apply(s, '006_real_data_api.sql')
    s.worker_password = secrets.token_urlsafe(24)
    with s.connect() as c:
        WI.provision(c, 'fw_worker_v1', s.worker_password, ['chain-support-unused-scope'])
    for n in ['007_real_run_worker.sql', '008_predecode_intake_results.sql', '009_fresh_image_inference.sql',
              '010_workspace_controls.sql', '011_real_artifact_retention.sql', '012_qualified_release_inference.sql',
              '013_intake_perceptual_features.sql', '014_real_worker_rights_encoding.sql',
              '015_rights_row_lock_capability.sql', '016_real_worker_rights_member_bundle_encoding.sql']:
        _apply(s, n)
    authority = {'purpose': 'fieldwork-training-lease-controller', 'authority_mode': SA.MODE,
                 'connection': {'host': owner['host'], 'port': int(owner['port']), 'dbname': name,
                                'user': 'fw_lease_machine_v1', 'password': secrets.token_urlsafe(24), 'sslmode': 'disable'},
                 'capability_schema': 'fw_lease_cap_v1', 'capability_version': 1, 'workspaces': ['*']}
    SA.provision(s.connect, authority)
    for n in ['017_privacy_lifecycle.sql', '018_worker_privacy_guard_execute.sql',
              '019_lease_privacy_guard_execute.sql', '020_real_digest_rotation.sql', '022_rights_evidence_digests.sql',
              '023_privacy_tombstone_policy_once_per_statement.sql']:
        _apply(s, n)
    request = Store(dsn=api_dsn, request=True)
    request.admin = s
    return s, request, name


def destroy_chain(admin_dsn, name):
    # Heavy matrices can exhaust the Windows ephemeral port pool for 127.0.0.1:5552 for a short while; retry.
    for attempt in range(12):
        try:
            with psycopg.connect(admin_dsn, autocommit=True) as c:
                c.execute(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(sql.Identifier(name)))
            break
        except psycopg.OperationalError:
            time.sleep(10)
    else:
        raise RuntimeError('CHAIN_DATABASE_NOT_DROPPED:' + name)
    drop_chain_roles(admin_dsn)


# ---------------------------------------------------------------------------------------------- shared helpers
import hashlib, os, tempfile, time
from types import SimpleNamespace
import pytest

ORIGIN = 'http://127.0.0.1:5102'
PASSWORD = 'fixture-password-' + 'x' * 8


def worker_scope(dba, workspaces):
    """Replace the provisioned worker's workspace scope (operator action in the throwaway database)."""
    with dba.connect() as c:
        c.execute('UPDATE fw_worker_cap_v1.scope SET workspaces=%s WHERE principal=%s', (list(workspaces), 'fw_worker_v1'))


@pytest.fixture(scope='module')
def chain():
    """Module-scoped retained chain; fieldwork.api is pointed at it for the module and restored afterwards."""
    from fieldwork.store import Store
    import fieldwork.api as api
    admin_dsn = Store().dsn  # in the canonical mirror this is the isolated verification cluster (asserted below)
    dba, request, name = create_chain(admin_dsn)
    old_dsn = api.store.dsn
    had_admin = hasattr(api.store, 'admin')
    api.store.dsn = request.dsn
    api.store.admin = dba
    api._PRIVACY_FENCE_SEEN = None
    mp = pytest.MonkeyPatch()
    runs = tempfile.mkdtemp(prefix='chain-runs-')
    mp.setattr(api, 'RUNS', __import__('pathlib').Path(runs))
    try:
        yield SimpleNamespace(dba=dba, request=request, name=name, api=api, admin_dsn=admin_dsn, runs=runs)
    finally:
        mp.undo()
        api.store.dsn = old_dsn
        if not had_admin:
            del api.store.admin
        api._PRIVACY_FENCE_SEEN = None
        destroy_chain(admin_dsn, name)


def make_account(chain, name, role, workspace, password=PASSWORD):
    chain.api.create_account(name, password, workspace, role)


def login(client, name, password=PASSWORD):
    r = client.post('/auth/session', json={'name': name, 'password': password})
    assert r.status_code == 200, r.text
    return {'Origin': ORIGIN, 'X-CSRF-Token': r.json()['csrf']}


def real_worker(chain, tmp_path, workspaces):
    """Scoped real-run worker (migration 007 capability) limited to `workspaces`; returns RealWorkerStore."""
    from fieldwork import worker_identity as WI
    from fieldwork.real_worker_identity import RealWorkerStore
    from datetime import datetime, timezone
    worker_scope(chain.dba, workspaces)
    d = conninfo_to_dict(chain.dba.dsn)
    with chain.dba.connect() as c:  # the scoped login password is valid for 5 minutes; refresh for this probe
        c.execute(sql.SQL('ALTER ROLE fw_worker_v1 VALID UNTIL {}').format(sql.Literal(WI._until(WI.MAX_TTL))))
    authority = {'authority_mode': WI.MODE, 'connection': {'host': '127.0.0.1', 'port': int(d['port']), 'dbname': d['dbname'],
                 'user': 'fw_worker_v1', 'password': chain.dba.worker_password, 'sslmode': 'disable'}, 'workspaces': list(workspaces)}
    path = tmp_path / ('private-' + uuid.uuid4().hex[:6]) / 'worker-authority.json'
    WI.write_authority(path, authority)
    w = RealWorkerStore(path)
    w.blob_root = tmp_path / 'blobs'
    return w
