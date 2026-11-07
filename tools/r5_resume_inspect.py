"""Read-only resume inventory. Never serializes credential profiles or holdout rows."""
import json
from pathlib import Path
import psycopg
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]


def main():
    profile = json.loads((ROOT / '.local.json').read_text())
    with psycopg.connect(profile['dsn'], row_factory=dict_row) as c:
        c.execute('SET TRANSACTION READ ONLY')
        result = {
            'run_states': c.execute('SELECT state,count(*) n FROM fw_runs GROUP BY state ORDER BY state').fetchall(),
            'queued': c.execute("SELECT id,workspace,config->>'scope' scope,config->>'recipe' recipe,revision FROM fw_runs WHERE state='queued' ORDER BY id LIMIT 20").fetchall(),
            'tables': [r['tablename'] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")],
            'migrations': c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name LIKE '%migration%'").fetchall(),
        }
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()
