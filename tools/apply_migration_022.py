"""Apply migration 022 (stored rights-evidence digests) with the same discipline as 020/021.

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
MIGRATION = ROOT / 'migrations/022_rights_evidence_digests.sql'
COLUMNS = ('canonical_license', 'license_text', 'source_evidence', 'attribution')


def facts(c, applied):
    out = {'rows': c.execute('SELECT count(*) n FROM public.fw_rights_assets').fetchone()['n'],
           'decisions': c.execute('SELECT count(*) n FROM public.fw_rights_decisions').fetchone()['n'],
           'acl': c.execute("SELECT relacl::text a FROM pg_class WHERE oid='public.fw_rights_assets'::regclass").fetchone()['a']}
    if applied:
        for col in COLUMNS:
            out[col + '_mismatch'] = c.execute(
                "SELECT count(*) n FROM public.fw_rights_assets WHERE %s_sha256 IS DISTINCT FROM encode(sha256(%s),'hex')" % (col, col)
            ).fetchone()['n']
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
    receipt = {'schema': 'fieldwork.migration-022/v1', 'mode': mode, 'started': base.now(),
               'migration_sha256': base.sha(MIGRATION.read_bytes())}
    out = ROOT / '.local/migration-022'
    out.mkdir(parents=True, exist_ok=True)
    path = out / ('%s-%s.json' % (mode, stamp))
    if not base.product_lock.acquire('fieldwork', 'migration-022-' + mode):
        print('LOCK HELD', base.product_lock.read_owner())
        return 4
    scratch = None
    try:
        receipt['backup'] = base.backup(d, ROOT / '.local/backups' / ('fieldwork-pre-022-%s.dump' % stamp))
        live = base.admin_dsn('fieldwork')
        with psycopg.connect(live, row_factory=dict_row) as c:
            receipt['before'] = facts(c, False)
        if a.rehearse:
            scratch = 'fw_rehearse_022_' + stamp.lower()
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
        ok = (after['rows'] == b['rows'] and after['decisions'] == b['decisions'] and after['acl'] == b['acl']
              and all(after[col + '_mismatch'] == 0 for col in COLUMNS))
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
