"""Apply migration 024 (intake worker row-lock capability on fw_samples) with the 020-023 discipline.

  --rehearse : verified pg_dump -> restore into a throwaway DB -> apply -> verify -> drop.
  --apply    : shared host lock + verified pg_dump backup -> apply to the retained DB -> verify -> receipt.
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_digest_rotation_020 as base  # noqa: E402

ROOT = base.ROOT
MIGRATION = ROOT / 'migrations/024_intake_sample_row_lock_capability.sql'
TABLES = ('fw_runs', 'fw_events', 'fw_versions', 'fw_rights_assets', 'fw_rights_decisions', 'fw_samples')


def facts(c, applied):
    q = lambda sql: c.execute(sql).fetchone()  # noqa: E731
    out = {'samples': q('SELECT count(*) n FROM public.fw_samples')['n'],
           'table_update': q("SELECT has_table_privilege('fieldwork_intake_worker','public.fw_samples','UPDATE') v")['v'],
           'acl': q("SELECT relacl::text a FROM pg_class WHERE oid='public.fw_samples'::regclass")['a'],
           'policies': [r['policyname'] for r in c.execute("SELECT policyname FROM pg_policies WHERE tablename='fw_samples' ORDER BY 1").fetchall()]}
    if applied:
        out['cap_update'] = q("SELECT has_column_privilege('fieldwork_intake_worker','public.fw_samples','row_lock_capability','UPDATE') v")['v']
        out['raw_update'] = q("SELECT has_column_privilege('fieldwork_intake_worker','public.fw_samples','raw_sha256','UPDATE') v")['v']
        out['trigger'] = q("SELECT count(*) n FROM pg_trigger WHERE tgrelid='public.fw_samples'::regclass AND tgname='fw024_reject_row_lock_capability'")['n']
        out['all_false'] = q('SELECT bool_and(NOT row_lock_capability) OR count(*)=0 v FROM public.fw_samples')['v']
    return out


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--rehearse', action='store_true')
    g.add_argument('--apply', action='store_true')
    a = ap.parse_args()
    d = base.dsn_parts()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    mode = 'rehearse' if a.rehearse else 'apply'
    receipt = {'schema': 'fieldwork.migration-024/v1', 'mode': mode, 'started': base.now(),
               'migration_sha256': base.sha(MIGRATION.read_bytes())}
    out = ROOT / '.local/migration-024'
    out.mkdir(parents=True, exist_ok=True)
    path = out / ('%s-%s.json' % (mode, stamp))
    if not base.product_lock.acquire('fieldwork', 'migration-024-' + mode):
        print('LOCK HELD', base.product_lock.read_owner())
        return 4
    scratch = None
    try:
        receipt['backup'] = base.backup(d, ROOT / '.local/backups' / ('fieldwork-pre-024-%s.dump' % stamp))
        live = base.admin_dsn('fieldwork')
        with psycopg.connect(live, row_factory=dict_row) as c:
            receipt['before'] = facts(c, False)
        if a.rehearse:
            scratch = 'fw_rehearse_024_' + stamp.lower()
            with psycopg.connect(live, autocommit=True) as c:
                c.execute('CREATE DATABASE %s' % scratch)
            r = subprocess.run(['docker', '--context', 'default', 'exec', '-i', '-e', 'PGPASSWORD', base.CONTAINER, 'pg_restore',
                                '-U', d['user'], '-d', scratch, '--exit-on-error'],
                               input=Path(receipt['backup']['path']).read_bytes(), capture_output=True, env=base.pg_env(d))
            receipt['restore_rc'] = r.returncode
            if r.returncode != 0:
                raise RuntimeError('scratch restore failed: ' + r.stderr.decode('utf-8', 'replace')[-300:])
            target = base.admin_dsn(scratch)
        else:
            target = live
        with psycopg.connect(target, autocommit=True) as c:
            c.execute(MIGRATION.read_text(encoding='utf-8'))
        with psycopg.connect(target, row_factory=dict_row) as c:
            after = facts(c, True)
        receipt['after'] = after
        b = receipt['before']
        ok = (after['samples'] == b['samples'] and after['policies'] == b['policies'] and not after['table_update']
              and after['cap_update'] and not after['raw_update'] and after['trigger'] == 1 and after['all_false'])
        receipt['result'] = 'PASS' if ok else 'FAIL'
    except BaseException as exc:  # noqa: BLE001
        receipt['result'] = 'ERROR'
        receipt['error'] = type(exc).__name__ + ': ' + str(exc)[:300]
    finally:
        if scratch:
            try:
                with psycopg.connect(base.admin_dsn('fieldwork'), autocommit=True) as c:
                    c.execute('DROP DATABASE IF EXISTS %s WITH (FORCE)' % scratch)
                receipt['scratch_dropped'] = scratch
            except Exception as exc:  # noqa: BLE001
                receipt['scratch_drop_error'] = str(exc)[:200]
        receipt['finished'] = base.now()
        path.write_text(json.dumps(receipt, indent=2, default=str), encoding='utf-8')
        base.product_lock.release()
    print(receipt['result'], receipt.get('error', ''), str(path))
    return 0 if receipt['result'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
