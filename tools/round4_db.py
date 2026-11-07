"""Create the isolated, disposable round-4 PostgreSQL database (tests/conftest.py pattern).

Usage: python -I -B tools/round4_db.py create|drop|status
It never touches the retained `fieldwork` database: it only creates/drops a separate
database on the same local cluster and applies the authored migrations to IT.
"""
import sys
from round4_common import ROOT, ISOLATED_DB, admin_dsn, write_json, EVIDENCE
import psycopg
from psycopg import sql

API_GRANTS = [
    'GRANT CONNECT ON DATABASE {db} TO fieldwork_api',
    'GRANT USAGE ON SCHEMA public TO fieldwork_api',
    'GRANT SELECT ON fw_accounts TO fieldwork_api',
    'GRANT SELECT ON fw_rights_datasets, fw_rights_assets TO fieldwork_api',
    'GRANT SELECT, INSERT, UPDATE ON fw_rights_decisions TO fieldwork_api',
]


def create():
    with psycopg.connect(admin_dsn('postgres'), autocommit=True) as c:
        if c.execute('SELECT 1 FROM pg_database WHERE datname=%s', (ISOLATED_DB,)).fetchone():
            raise SystemExit('ALREADY_EXISTS ' + ISOLATED_DB)
        c.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(ISOLATED_DB)))
    from fieldwork.store import Store
    s = Store(dsn=admin_dsn())
    s.migrate()
    applied = []
    with s.connect() as c:
        for name in ['003_signed_rights.sql', '004_cancel_generation.sql']:
            c.execute((ROOT / 'migrations' / name).read_text())
            applied.append(name)
        from fieldwork.intake import INTAKE_SCHEMA, INTAKE_API_GRANTS
        c.execute(INTAKE_SCHEMA)
        for g in API_GRANTS + INTAKE_API_GRANTS:
            c.execute(g.format(db=ISOLATED_DB))
        tables = [r['tablename'] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1").fetchall()]
    write_json(EVIDENCE / 'db/isolated-db-created.json', {'database': ISOLATED_DB, 'migrations_applied': applied,
               'intake_schema': 'fieldwork.intake.INTAKE_SCHEMA', 'tables': tables,
               'note': 'Disposable database on the local fieldwork cluster; retained fieldwork DB untouched.'})
    print('created', ISOLATED_DB, tables)


def drop():
    with psycopg.connect(admin_dsn('postgres'), autocommit=True) as c:
        c.execute(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(sql.Identifier(ISOLATED_DB)))
    print('dropped', ISOLATED_DB)


if __name__ == '__main__':
    {'create': create, 'drop': drop}[sys.argv[1]]()
