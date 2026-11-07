"""Operator activation of round 5 (expand-only): migrations/005 + narrowed API-login grants,
in ONE transaction, then read-only verification. Idempotent: re-running detects an applied
005 (fw_control present) and only re-verifies. Never prints DSNs, logins or secrets.

Usage (from fieldwork/, backup FIRST):
  python -B -m tools.activate_round5 [--operator-dsn-file .local.json] [--api-dsn-file .local-api.json] [--out receipt.json]
"""
import argparse, hashlib, json, sys, time
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / 'migrations/005_restore_generation_guards.sql'


def state(c, login):
    q = lambda s, *a: c.execute(s, a).fetchone()
    return {
        'fw_control': q("SELECT to_regclass('public.fw_control') IS NOT NULL x")['x'],
        'fw_command_receipts': q("SELECT to_regclass('public.fw_command_receipts') IS NOT NULL x")['x'],
        'attempt_columns': q("SELECT count(*) n FROM information_schema.columns WHERE table_schema='public' AND table_name='fw_attempts' AND column_name IN ('restore_generation','worker_id','started_at','ended_at','exit_receipt_digest')")['n'],
        'guard_trigger': q("SELECT count(*) n FROM pg_trigger WHERE tgname='fw_runs_guard' AND NOT tgisinternal")['n'],
        'api_table_update_on_fw_runs': q("SELECT has_table_privilege(%s,'public.fw_runs','UPDATE') x", login)['x'],
        'api_column_update': sorted(r['attname'] for r in c.execute("SELECT a.attname FROM pg_attribute a WHERE a.attrelid='public.fw_runs'::regclass AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(%s,'public.fw_runs',a.attname,'UPDATE')", (login,)).fetchall()),
        'runs': q('SELECT count(*) n FROM fw_runs')['n'],
        'runs_digest': hashlib.sha256(json.dumps([dict(r) for r in c.execute('SELECT id,state,fence,revision,cancel_generation,epoch,lease::text FROM fw_runs ORDER BY id').fetchall()], default=str).encode()).hexdigest(),
    }


def activate(operator_dsn, api_dsn):
    login = conninfo_to_dict(api_dsn)['user']
    out = {'migration_005_sha256': hashlib.sha256(MIGRATION.read_bytes()).hexdigest()}
    with psycopg.connect(operator_dsn, row_factory=dict_row) as c:
        c.execute("SET lock_timeout='5s'")
        before = state(c, login); out['before'] = before
        if not before['fw_control']:
            c.execute(MIGRATION.read_text().replace('BEGIN;', '', 1).rsplit('COMMIT;', 1)[0])
            out['migration_005'] = 'applied'
        else:
            out['migration_005'] = 'already_applied'
        # Review F5: API login loses table-level UPDATE on fw_runs; keeps cancel/resume columns.
        c.execute(sql.SQL('REVOKE UPDATE ON public.fw_runs FROM {}').format(sql.Identifier(login)))
        c.execute(sql.SQL('GRANT UPDATE (state, fence, revision, cancel_generation) ON public.fw_runs TO {}').format(sql.Identifier(login)))
        out['after'] = after = state(c, login)
        if after['runs_digest'] != before['runs_digest']:
            raise SystemExit('RUN_ROWS_CHANGED_ABORT')  # expand-only: no row may change
    with psycopg.connect(api_dsn, row_factory=dict_row) as c:
        c.execute('SET TRANSACTION READ ONLY')
        from fieldwork.checkpoint_read import verify
        verify(c, c.execute('SELECT session_user AS l').fetchone()['l']); out['checkpoint_helper_verify_as_api'] = 'passed'
    out['at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    return out


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--operator-dsn-file', default=str(ROOT / '.local.json')); ap.add_argument('--api-dsn-file', default=str(ROOT / '.local-api.json')); ap.add_argument('--out')
    a = ap.parse_args(); sys.path.insert(0, str(ROOT))
    result = activate(json.load(open(a.operator_dsn_file))['dsn'], json.load(open(a.api_dsn_file))['dsn'])
    if a.out:
        with open(a.out, 'x') as f: json.dump(result, f, indent=1)
    print(json.dumps(result))
