"""Round-5 retained upgrade of the scoped lease controller capability (operator).

Reads the private authority file in memory, replaces the fixed capability function bodies
(adds 'leased', supports the ['*'] all-workspaces scope), sets the scope, verifies as the
machine login, and atomically rewrites the private authority file with the new scope.
Stop the running controller BEFORE this and restart it on the new source after.
Usage: python -B -m tools.r5p_lease_upgrade --authority-file <private>/authority.json --workspace '*'
"""
import argparse, json
from pathlib import Path
import psycopg
from psycopg.rows import dict_row
from fieldwork import scoped_authority as SA
from fieldwork.worker_identity import write_authority

ROOT = Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser(); ap.add_argument('--authority-file', required=True); ap.add_argument('--workspace', action='append', required=True)
a = ap.parse_args()
SA.check_private(a.authority_file)
authority = json.loads(Path(a.authority_file).read_text())
before = list(authority['workspaces'])
operator = json.loads((ROOT / '.local.json').read_text())['dsn']
new = SA.upgrade(lambda: psycopg.connect(operator, row_factory=dict_row, options='-c search_path=pg_catalog,pg_temp'), authority, a.workspace)
write_authority(a.authority_file, new)
print(json.dumps({'upgraded': True, 'scope_before': before, 'scope_after': new['workspaces'], 'verified_as_machine_login': True, 'secret_printed': False}))
