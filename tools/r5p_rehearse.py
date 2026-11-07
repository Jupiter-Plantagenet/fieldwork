"""Round-5 retained-change rehearsal on a RESTORED COPY (disposable cluster 5552 only).

Restores the given retained pg_dump into a new database on fieldwork-pg-verify, then runs
exactly the round-5 retained sequence against the copy:
  1. tools.activate_round5 (migration 005 + API column grants), verifying no run row changes;
  2. scoped worker identity provisioning + WorkerStore smoke (scope, refusal of other tenants);
  3. lease-controller capability upgrade (leased state, ['*'] scope) and ONE scan pass,
     recording which stale runs the proper expiry path moves.
Receipt: docs/parallel-round5-logs/rehearsal-<UTC>.json (exclusive). The copy database and
the rehearsal-only roles are dropped at the end unless --keep. Never prints secrets.

Usage: python -B -m tools.r5p_rehearse <dump> --worker-workspaces-from-queue
"""
import argparse, hashlib, json, secrets, subprocess, sys, tempfile, time
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.conninfo import conninfo_to_dict, make_conninfo

ROOT = Path(__file__).resolve().parents[1]
MIRROR = ROOT / '.cache/round5-mirror'
CONTAINER = 'fieldwork-pg-verify'


def tables(c):
    out = {}
    for t in c.execute("SELECT schemaname||'.'||tablename t FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY 1").fetchall():
        rows = c.execute(sql.SQL('SELECT md5(coalesce(string_agg(x::text, \'|\' ORDER BY x::text),\'\')) h, count(*) n FROM {} x').format(sql.SQL(t['t']))).fetchone()
        out[t['t']] = [rows['n'], rows['h']]
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('dump'); ap.add_argument('--keep', action='store_true')
    a = ap.parse_args()
    admin = conninfo_to_dict(json.loads((MIRROR / '.local.json').read_text())['dsn'])
    assert str(admin['port']) == '5552', 'refusing: not the disposable cluster'
    api = conninfo_to_dict(json.loads((MIRROR / '.local-api.json').read_text())['dsn'])
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()); db = 'fw_r5_rehearsal_' + stamp.lower()
    rep = {'dump': a.dump, 'dump_sha256': hashlib.sha256(Path(a.dump).read_bytes()).hexdigest(), 'target': {'port': 5552, 'database': db}, 'at': stamp}
    lease_pw = secrets.token_urlsafe(32); created_roles = []
    with psycopg.connect(make_conninfo(**dict(admin, dbname='postgres')), autocommit=True, row_factory=dict_row) as c:
        for role, login in [('fieldwork', False), ('fw_lease_machine_v1', True), ('fw_lease_machine_v1_owner', False)]:
            if not c.execute('SELECT 1 FROM pg_roles WHERE rolname=%s', (role,)).fetchone():
                c.execute(sql.SQL('CREATE ROLE {} ' + ('LOGIN PASSWORD {}' if login else 'NOLOGIN') + ' NOINHERIT').format(sql.Identifier(role), *( [sql.Literal(lease_pw)] if login else [])))
                created_roles.append(role)
            elif login:
                c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(sql.Identifier(role), sql.Literal(lease_pw)))
        c.execute(sql.SQL('CREATE DATABASE {} OWNER fieldwork').format(sql.Identifier(db)))
    rep['rehearsal_roles_created'] = created_roles
    r = subprocess.run(['docker', 'exec', '-i', CONTAINER, 'pg_restore', '-U', admin['user'], '-d', db], input=Path(a.dump).read_bytes(), capture_output=True)
    rep['pg_restore_exit'] = r.returncode; rep['pg_restore_error_lines'] = [l for l in r.stderr.decode(errors='replace').splitlines() if 'error' in l.lower()][:20]
    op = make_conninfo(**dict(admin, dbname=db)); apidsn = make_conninfo(**dict(api, dbname=db))
    sys.path.insert(0, str(MIRROR))
    try:
        with psycopg.connect(op, row_factory=dict_row) as c:
            before = tables(c)
        from tools.activate_round5 import activate
        rep['activate_round5'] = activate(op, apidsn)
        rep['activate_round5_repeat'] = activate(op, apidsn)['migration_005']
        with psycopg.connect(op, row_factory=dict_row) as c:
            after = tables(c)
        rep['preexisting_tables_unchanged'] = {t: before[t] == after.get(t) for t in before}
        rep['new_tables'] = sorted(set(after) - set(before))
        # 2. scoped worker identity
        from fieldwork import worker_identity as WI
        login = 'fw_worker_rh' + secrets.token_hex(4); created_roles += [login, login + '_definer']
        with psycopg.connect(op, row_factory=dict_row) as c:
            scope = [x['workspace'] for x in c.execute("SELECT DISTINCT workspace FROM fw_runs WHERE state='queued' AND config->>'scope'='synthetic-execution-only' ORDER BY 1").fetchall()]
            other = c.execute("SELECT id FROM fw_runs WHERE NOT (workspace=ANY(%s)) ORDER BY id LIMIT 1", (scope,)).fetchone()['id']
            pw = secrets.token_urlsafe(32); WI.provision(c, login, pw, scope)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'private' / 'authority.json'
            WI.write_authority(path, {'authority_mode': WI.MODE, 'connection': {'host': '127.0.0.1', 'port': 5552, 'dbname': db, 'user': login, 'password': pw, 'sslmode': 'disable'}, 'workspaces': scope})
            w = WI.WorkerStore(path)
            nxt = w.next_run([])
            rep['worker_identity'] = {'scope_workspaces': len(scope), 'next_run_in_scope': bool(nxt), 'out_of_scope_run_visible': w.get(other) is not None,
                                      'slot': {k: v for k, v in w._call('slot_status').items() if k in ('run', 'run_in_scope')}}
            with w.connect() as c:
                try:
                    c.execute('SELECT 1 FROM public.fw_runs LIMIT 1'); rep['worker_identity']['direct_select'] = 'ALLOWED'
                except psycopg.errors.InsufficientPrivilege:
                    rep['worker_identity']['direct_select'] = 'denied'
        # 3. lease-controller capability upgrade and one proper-path expiry pass
        from fieldwork import scoped_authority as SA
        from fieldwork.lease_recovery import scan_once
        with psycopg.connect(op, row_factory=dict_row) as c:
            rep['lease_scope_before'] = c.execute('SELECT workspaces FROM fw_lease_cap_v1.scope').fetchone()['workspaces']
            stale = c.execute("SELECT id,workspace,state,fence,revision FROM fw_runs WHERE state IN ('leased','running','cancel_requested') AND lease<=now()").fetchall()
        authority = {'purpose': 'fieldwork-training-lease-controller', 'authority_mode': SA.MODE, 'capability_schema': SA.SCHEMA, 'capability_version': 1,
                     'workspaces': rep['lease_scope_before'], 'connection': {'host': '127.0.0.1', 'port': 5552, 'dbname': db, 'user': 'fw_lease_machine_v1', 'password': lease_pw, 'sslmode': 'disable'}}
        new = SA.upgrade(lambda: psycopg.connect(op, row_factory=dict_row), authority, ['*'])
        rep['lease_scope_after'] = new['workspaces']
        result = scan_once(SA.MachineBackend(new))
        rep['scan_once'] = result
        with psycopg.connect(op, row_factory=dict_row) as c:
            rep['stale_runs'] = [{'before': dict(s), 'after': dict(c.execute('SELECT state,fence,revision FROM fw_runs WHERE id=%s', (s['id'],)).fetchone()),
                                  'events': [e['kind'] for e in c.execute('SELECT kind FROM fw_events WHERE run=%s ORDER BY seq DESC LIMIT 1', (s['id'],)).fetchall()]} for s in stale]
    finally:
        if not a.keep:
            with psycopg.connect(make_conninfo(**dict(admin, dbname='postgres')), autocommit=True) as c:
                c.execute(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(sql.Identifier(db)))
                for role in reversed(created_roles):
                    c.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))
            rep['cleanup'] = 'database and rehearsal roles dropped'
        out = ROOT / 'docs/parallel-round5-logs' / f'rehearsal-{stamp}.json'
        with out.open('x') as f:
            json.dump(rep, f, indent=1, default=str)
        print(out)


if __name__ == '__main__':
    main()
