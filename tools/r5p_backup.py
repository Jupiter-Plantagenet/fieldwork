"""pg_dump (custom format) + globals of the retained Fieldwork DB via docker exec, written to
var/snapshots/<label>-<UTC>.{dump,-globals.sql,json} with exclusive creation. Uses the
container-local connection (no password passed anywhere). Never prints secrets.

Usage: python -B -m tools.r5p_backup <label> [container]
"""
import hashlib, json, os, subprocess, sys, time
from pathlib import Path
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).resolve().parents[1]


def main():
    label = sys.argv[1]; container = sys.argv[2] if len(sys.argv) > 2 else 'fieldwork-postgres'
    p = conninfo_to_dict(json.loads((ROOT / '.local.json').read_text())['dsn'])
    ts = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()); snapshot_root=ROOT/'var/snapshots'
    from fieldwork.privacy_lifecycle import _check_c_ancestry,export_deletion_ledger
    _check_c_ancestry(snapshot_root,allow_missing_leaf=True)
    snapshot_root.mkdir(parents=True,exist_ok=True,mode=0o700)
    _check_c_ancestry(snapshot_root)
    from fieldwork.scoped_authority import check_private
    check_private(snapshot_root)
    base = snapshot_root / f'{label}-{ts}'

    def run(cmd, path):
        _check_c_ancestry(Path(path),allow_missing_leaf=True)
        with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:
            r = subprocess.run(['docker', 'exec', container, *cmd], stdout=f, stderr=subprocess.PIPE)
        if r.returncode:
            raise SystemExit('BACKUP_FAILED ' + r.stderr.decode(errors='replace')[-300:])
        _check_c_ancestry(Path(path));check_private(Path(path))
        b = Path(path).read_bytes()
        return {'path': str(Path(path).relative_to(ROOT)).replace('\\', '/'), 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}

    ledger=export_deletion_ledger(Path(str(base)+'-privacy-deletions'))
    res = {'container': container, 'database': p['dbname'], 'at': ts,
           'privacy_deletion_ledger':ledger,
           'db': run(['pg_dump', '-U', p['user'], '-d', p['dbname'], '-Fc'], str(base) + '.dump'),
           'globals': run(['pg_dumpall', '-U', p['user'], '--globals-only'], str(base) + '-globals.sql')}
    toc = subprocess.run(['docker', 'exec', '-i', container, 'pg_restore', '-l'], input=(ROOT / res['db']['path']).read_bytes(), capture_output=True)
    res['toc_tables'] = sorted({l.split()[-2] for l in toc.stdout.decode(errors='replace').splitlines() if ' TABLE public ' in l and 'TABLE DATA' not in l})
    receipt_path=Path(str(base)+'.json')
    _check_c_ancestry(receipt_path,allow_missing_leaf=True)
    with os.fdopen(os.open(str(receipt_path),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:
        json.dump(res, f, indent=2)
    _check_c_ancestry(receipt_path);check_private(receipt_path)
    print(json.dumps(res))


if __name__ == '__main__':
    main()
