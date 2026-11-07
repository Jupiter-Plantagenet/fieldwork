"""Rehearse or apply migration 020 (real-training digest rotation).

  --rehearse : fresh pg_dump -> restore into a throwaway DB in the same cluster -> apply -> verify -> drop.
  --apply    : shared host lock + verified pg_dump backup -> apply to the retained DB -> verify -> receipt.

No secret is printed or written. The DSN password is passed to docker exec via environment only.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / 'tools'))
sys.path.insert(0, str(ROOT / 'tools'))
import product_lock  # noqa: E402
from round4_common import admin_dsn  # noqa: E402

MIGRATION = ROOT / 'migrations/020_real_digest_rotation.sql'
CONTAINER = 'fieldwork-postgres'
OLD_RECIPE = '22ad675cf61ef7bb3b315563652addf47fa7669667488777a15399c25f9a24fa'
OLD_PRE = '1392785edc35eef504d62e4d9b90bb6aa438127d52e83869853b4eb8ebd34d92'
PROBE_RUN = '5a1ccc83-3ff4-45d4-849d-1ae0ba7120da'
PROFILE = 'fw_real_worker_cap_v1.profile_ok(jsonb,text,text)'


def sha(b):
    return hashlib.sha256(b).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def dsn_parts():
    d = conninfo_to_dict(admin_dsn('fieldwork'))
    return d


def docker(*args, env=None, stdin=None, stdout=None, check=True):
    cmd = ['docker', '--context', 'default', *args]
    r = subprocess.run(cmd, stdin=stdin, stdout=stdout if stdout else subprocess.PIPE,
                       stderr=subprocess.PIPE, env=env or os.environ.copy())
    if check and r.returncode != 0:
        raise RuntimeError('docker %s failed rc=%s: %s' % (args[0], r.returncode, r.stderr.decode('utf-8', 'replace')[-300:]))
    return r


def pg_env(d):
    env = os.environ.copy()
    env['PGPASSWORD'] = d.get('password', '')
    return env


def backup(d, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, 'xb') as f:
        r = subprocess.run(['docker', '--context', 'default', 'exec', '-e', 'PGPASSWORD', CONTAINER, 'pg_dump',
                            '-U', d['user'], '-Fc', '-d', 'fieldwork'], stdout=f, stderr=subprocess.PIPE, env=pg_env(d))
    if r.returncode != 0:
        raise RuntimeError('pg_dump failed: ' + r.stderr.decode('utf-8', 'replace')[-300:])
    raw = dest.read_bytes()
    lst = subprocess.run(['docker', '--context', 'default', 'exec', '-i', CONTAINER, 'pg_restore', '--list'],
                         input=raw, capture_output=True)
    entries = [l for l in lst.stdout.decode('utf-8', 'replace').splitlines() if l and not l.startswith(';')]
    if lst.returncode != 0 or len(entries) < 50:
        raise RuntimeError('backup verification failed')
    return {'path': str(dest), 'bytes': len(raw), 'sha256': sha(raw), 'toc_entries': len(entries)}


def counts(c):
    runs = c.execute("select state,count(*) n from public.fw_runs group by state order by state").fetchall()
    q = c.execute("select workspace,id from public.fw_runs where state='queued' order by workspace,id").fetchall()
    return {'runs_by_state': {r['state']: r['n'] for r in runs},
            'queued_digest': sha('\n'.join(r['workspace'] + '|' + r['id'] for r in q).encode())}


def fn_facts(c):
    return c.execute("""select pg_catalog.pg_get_userbyid(p.proowner) owner, coalesce(p.proacl::text,'') acl, p.prosecdef secdef,
        p.proconfig cfg, pg_catalog.pg_get_functiondef(p.oid) def from pg_catalog.pg_proc p where p.oid=%s::regprocedure""",
                     (PROFILE,)).fetchone()


def profile_probe(c):
    from fieldwork.real_run_profile import RECIPE_DIGEST, PREPROCESS_DIGEST
    row = c.execute("select config::jsonb cfg, workspace, actor from public.fw_runs where id=%s", (PROBE_RUN,)).fetchone()
    cfg = row['cfg']
    out = {}

    def call(config):
        return c.execute('select ' + PROFILE.replace('(jsonb,text,text)', '') + '(%s::jsonb,%s,%s) ok',
                         (json.dumps(config), row['workspace'], row['actor'])).fetchone()['ok']
    out['recorded_config_old_digests'] = call(cfg)
    new = dict(cfg, recipe_digest=RECIPE_DIGEST, preprocess_digest=PREPROCESS_DIGEST)
    out['current_source_digests'] = call(new)
    out['bogus_recipe_digest'] = call(dict(cfg, recipe_digest='0' * 64))
    out['bogus_preprocess_digest'] = call(dict(cfg, preprocess_digest='0' * 64))
    out['recorded_cfg_digests'] = {'recipe': cfg.get('recipe_digest') == OLD_RECIPE, 'preprocess': cfg.get('preprocess_digest') == OLD_PRE}
    return out


def apply_sql(dsn):
    sql = MIGRATION.read_text(encoding='utf-8')
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(sql)


def verify_applied(dsn):
    with psycopg.connect(dsn, row_factory=dict_row) as c:
        c.read_only = True
        f = fn_facts(c)
        from fieldwork.real_run_profile import RECIPE_DIGEST, PREPROCESS_DIGEST
        facts = {'owner': f['owner'], 'secdef': f['secdef'], 'config': f['cfg'],
                 'has_old_recipe': OLD_RECIPE in f['def'], 'has_new_recipe': RECIPE_DIGEST in f['def'],
                 'has_new_preprocess': PREPROCESS_DIGEST in f['def'], 'has_old_preprocess': OLD_PRE in f['def']}
        return facts, profile_probe(c), counts(c)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--rehearse', action='store_true')
    g.add_argument('--apply', action='store_true')
    a = ap.parse_args()
    d = dsn_parts()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    base = dict(d)
    receipt = {'schema': 'fieldwork.digest-rotation-020/v1', 'mode': 'rehearse' if a.rehearse else 'apply',
               'started': now(), 'migration_sha256': sha(MIGRATION.read_bytes())}
    out_dir = ROOT / '.local/digest-rotation-020'
    out_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = out_dir / ('%s-%s.json' % (receipt['mode'], stamp))

    def save():
        receipt_path.write_text(json.dumps(receipt, indent=2, default=str), encoding='utf-8')

    if not product_lock.acquire('fieldwork', 'digest-rotation-020-' + receipt['mode']):
        print('LOCK HELD', product_lock.read_owner())
        return 4
    scratch = None
    try:
        receipt['backup'] = backup(d, ROOT / '.local/backups' / ('fieldwork-pre-020-%s.dump' % stamp))
        live = admin_dsn('fieldwork')
        with psycopg.connect(live, row_factory=dict_row) as c:
            c.read_only = True
            receipt['before'] = {'counts': counts(c), 'profile_ok': {k: fn_facts(c)[k] for k in ('owner', 'acl', 'secdef', 'cfg')}}
            receipt['before']['probe'] = profile_probe(c)
        if a.rehearse:
            scratch = 'fw_rehearse_020_' + stamp.lower()
            with psycopg.connect(live, autocommit=True) as c:
                c.execute('CREATE DATABASE %s' % scratch)
            raw = Path(receipt['backup']['path']).read_bytes()
            r = subprocess.run(['docker', '--context', 'default', 'exec', '-i', '-e', 'PGPASSWORD', CONTAINER, 'pg_restore',
                                '-U', d['user'], '-d', scratch, '--exit-on-error'], input=raw, capture_output=True, env=pg_env(d))
            receipt['restore'] = {'rc': r.returncode, 'stderr_tail': r.stderr.decode('utf-8', 'replace')[-400:]}
            if r.returncode != 0:
                raise RuntimeError('scratch restore failed')
            target = admin_dsn(scratch)
        else:
            target = live
        apply_sql(target)
        facts, probe, cnt = verify_applied(target)
        receipt['after'] = {'profile_ok': facts, 'probe': probe, 'counts': cnt}
        ok = (facts['has_old_recipe'] and facts['has_new_recipe'] and facts['has_new_preprocess'] and facts['has_old_preprocess']
              and probe['recorded_config_old_digests'] and probe['current_source_digests']
              and not probe['bogus_recipe_digest'] and not probe['bogus_preprocess_digest']
              and facts['owner'] == receipt['before']['profile_ok']['owner']
              and cnt == receipt['before']['counts'])
        receipt['result'] = 'PASS' if ok else 'FAIL'
    except BaseException as exc:  # noqa: BLE001
        receipt['result'] = 'ERROR'
        receipt['error'] = type(exc).__name__ + ': ' + str(exc)[:300]
    finally:
        if scratch:
            try:
                with psycopg.connect(admin_dsn('fieldwork'), autocommit=True) as c:
                    c.execute('DROP DATABASE IF EXISTS %s WITH (FORCE)' % scratch)
                receipt['scratch_dropped'] = scratch
            except Exception as exc:  # noqa: BLE001
                receipt['scratch_drop_error'] = str(exc)[:200]
        receipt['finished'] = now()
        save()
        product_lock.release()
    print(receipt['result'], receipt.get('error', ''), str(receipt_path))
    return 0 if receipt['result'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
