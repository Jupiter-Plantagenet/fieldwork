"""Apply migration 023 (privacy tombstone policy evaluated once per statement) with the 020-022 discipline.

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
MIGRATION = ROOT / 'migrations/023_privacy_tombstone_policy_once_per_statement.sql'
TABLES = ('fw_runs', 'fw_events', 'fw_versions', 'fw_rights_assets', 'fw_rights_decisions', 'fw_samples')


def facts(c, applied):
    pol = c.execute("""SELECT tablename,policyname,permissive,roles::text r,cmd,qual,with_check FROM pg_policies
        WHERE schemaname='public' AND policyname LIKE 'fw_privacy_tombstone_fw_%' ORDER BY tablename""").fetchall()
    out = {'policies': [(p['tablename'], p['permissive'], p['r'], p['cmd']) for p in pol],
           'counts': {t: c.execute('SELECT count(*) n FROM public.%s' % t).fetchone()['n'] for t in TABLES}}
    if applied:
        out['all_case_form'] = all('CASE' in p['qual'] and 'CASE' in p['with_check'] for p in pol)
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
    receipt = {'schema': 'fieldwork.migration-023/v1', 'mode': mode, 'started': base.now(),
               'migration_sha256': base.sha(MIGRATION.read_bytes())}
    out = ROOT / '.local/migration-023'
    out.mkdir(parents=True, exist_ok=True)
    path = out / ('%s-%s.json' % (mode, stamp))
    if not base.product_lock.acquire('fieldwork', 'migration-023-' + mode):
        print('LOCK HELD', base.product_lock.read_owner())
        return 4
    scratch = None
    try:
        receipt['backup'] = base.backup(d, ROOT / '.local/backups' / ('fieldwork-pre-023-%s.dump' % stamp))
        live = base.admin_dsn('fieldwork')
        with psycopg.connect(live, row_factory=dict_row) as c:
            receipt['before'] = facts(c, False)
        if a.rehearse:
            scratch = 'fw_rehearse_023_' + stamp.lower()
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
        ok = (after['policies'] == b['policies'] and len(after['policies']) >= 14 and after['all_case_form']
              and after['counts'] == b['counts'])
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
