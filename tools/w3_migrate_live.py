"""Back up and rehearse the additive real-data schema; apply only under host lock.

Run with --rehearse, then --apply --receipt <rehearsal receipt>. Never rewrites an
applied migration or resets a retained database. Credentials remain in memory.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MIGRATIONS = ('003_signed_rights.sql', '006_real_data_api.sql')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def counts(c):
    tables = c.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1").fetchall()
    return {t[0]: c.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(t[0]))).fetchone()[0]
            for t in tables}


def apply(c):
    for name in MIGRATIONS:
        c.execute((ROOT/'migrations'/name).read_text(encoding='utf-8'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--rehearse', action='store_true')
    group.add_argument('--apply', action='store_true')
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    dsn = json.loads((ROOT/'.local.json').read_text())['dsn']
    params = conninfo_to_dict(dsn)
    if params.get('host') != '127.0.0.1' or params.get('dbname') != 'fieldwork' or params.get('user') != 'fieldwork':
        raise RuntimeError('RETAINED_IDENTITY_REFUSED')
    pins = {n: sha((ROOT/'migrations'/n).read_bytes()) for n in MIGRATIONS}
    if args.apply:
        sys.path.insert(0, str(ROOT.parent/'tools'))
        import product_lock
        import psutil
        owner = product_lock.read_owner(ROOT.parent/'.cache/product-build.lock') or {}
        ancestors = [(p.pid, p.create_time()) for p in psutil.Process().parents()]
        if (owner.get('product') != 'fieldwork' or
                owner.get('purpose') != 'w3-retained-real-data-migration' or
                (owner.get('pid'), owner.get('create_time')) not in ancestors):
            raise RuntimeError('HOST_LOCK_REQUIRED')
        receipt = json.loads(args.receipt.read_text())
        if receipt.get('status') != 'rehearsed' or receipt.get('migrations') != pins:
            raise RuntimeError('REHEARSAL_SOURCE_MISMATCH')
        dump = Path(receipt['backup'])
        if sha(dump.read_bytes()) != receipt['backup_sha256']:
            raise RuntimeError('BACKUP_DIGEST_MISMATCH')
        with psycopg.connect(dsn, autocommit=True) as c:
            before = counts(c)
            if before != receipt['retained_counts']:
                raise RuntimeError('RETAINED_POPULATION_CHANGED_REBACKUP_REQUIRED')
            apply(c)
            after = counts(c)
            if any(after.get(k) != v for k, v in before.items()):
                raise RuntimeError('RETAINED_POPULATION_MISMATCH')
        receipt.update(status='applied', applied_utc=datetime.now(timezone.utc).isoformat(), after_counts=after)
        out = args.receipt.with_name('applied.json')
    else:
        folder = ROOT/'.local/backups'/('w3-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
        folder.mkdir(parents=True)
        for name in MIGRATIONS:
            (folder/name).write_bytes((ROOT/'migrations'/name).read_bytes())
        dump = folder/'database.dump'
        with dump.open('xb') as stream:
            subprocess.run(['docker', 'exec', 'fieldwork-postgres', 'pg_dump', '-U', params['user'],
                            '-d', params['dbname'], '-Fc'], stdout=stream, stderr=subprocess.PIPE, check=True)
        scratch = 'fieldwork_w3_rehearsal_'+uuid.uuid4().hex[:12]
        created = False
        try:
            with psycopg.connect(dsn, autocommit=True) as c:
                if c.execute("SELECT 1 FROM pg_roles WHERE rolname='fieldwork_intake_worker'").fetchone():
                    raise RuntimeError('WORKER_ROLE_PREEXISTS')
                before = counts(c)
                c.execute(sql.SQL('CREATE DATABASE {} OWNER fieldwork TEMPLATE template0').format(sql.Identifier(scratch)))
                created = True
            subprocess.run(['docker', 'exec', '-i', 'fieldwork-postgres', 'pg_restore', '-U', params['user'],
                            '-d', scratch, '--no-owner', '--exit-on-error'], input=dump.read_bytes(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            with psycopg.connect(make_conninfo(dsn, dbname=scratch), autocommit=True) as c:
                if counts(c) != before:
                    raise RuntimeError('RESTORE_POPULATION_MISMATCH')
                apply(c)
                after = counts(c)
                if any(after.get(k) != v for k, v in before.items()):
                    raise RuntimeError('REHEARSAL_POPULATION_MISMATCH')
            receipt = dict(status='rehearsed', migrations=pins, backup=str(dump),
                           backup_sha256=sha(dump.read_bytes()), retained_counts=before,
                           after_counts=after, at_utc=datetime.now(timezone.utc).isoformat())
        finally:
            with psycopg.connect(dsn, autocommit=True) as c:
                if created:
                    c.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(scratch)))
                    c.execute('DROP ROLE IF EXISTS fieldwork_intake_worker')
        out = folder/'rehearsal.json'
    with out.open('x', encoding='utf-8') as stream:
        json.dump(receipt, stream, indent=2)
    print(json.dumps({'status': receipt['status'], 'receipt': str(out), 'migrations': pins}))


if __name__ == '__main__':
    main()
