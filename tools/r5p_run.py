"""Round-5 platform suite runner with provenance (review: logs must record the command, test
IDs, target DB/port and source SHA256).

Usage (from fieldwork/):
  .venv/Scripts/python.exe -B tools/r5p_run.py <label> [--mirror .cache/round5-mirror] [--env K=V ...] -- <pytest args>

* syncs nothing itself (run .cache/r5-platform/sync.sh first);
* takes the shared host lock through C:/Users/user/portfolio-build/tools/product_lock.py,
  waiting (never stealing) until it is free, and always releases it;
* writes docs/parallel-round5-logs/<label>-<UTC>.log with exclusive creation (never
  overwrites): header JSON (command, cwd, collected node IDs, DB host/port/dbname from the
  mirror's .local.json without credentials, SHA256 of every source file in the mirror),
  then the full pytest output.
"""
import argparse, hashlib, importlib.util, json, os, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGS = ROOT / 'docs/parallel-round5-logs'


def product_lock():
    path = ROOT / 'tools/product_lock.py'
    spec = importlib.util.spec_from_file_location('product_lock', path); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def source_hashes(mirror):
    out = {}
    for d in ['fieldwork', 'tests', 'migrations', 'tools']:
        for p in sorted((mirror / d).rglob('*.py')) + sorted((mirror / d).rglob('*.sql')):
            if '__pycache__' in p.parts:
                continue
            out[str(p.relative_to(mirror)).replace('\\', '/')] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def target(mirror):
    from psycopg.conninfo import conninfo_to_dict
    d = conninfo_to_dict(json.loads((mirror / '.local.json').read_text())['dsn'])
    return {k: d.get(k) for k in ('host', 'port', 'dbname')}


def main():
    argv = sys.argv[1:]
    split = argv.index('--') if '--' in argv else len(argv)
    ap = argparse.ArgumentParser(); ap.add_argument('label'); ap.add_argument('--mirror', default='.cache/round5-mirror'); ap.add_argument('--env', action='append', default=[])
    ap.add_argument('--isolated-no-host-lock', action='store_true', help='Isolated suites use coordinator heavy slots, not the exclusive live-resource lock')
    a = ap.parse_args(argv[:split]); pytest_args = argv[split + 1:]
    mirror = (ROOT / a.mirror).resolve()
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    for item in a.env:
        k, v = item.split('=', 1); env[k] = v
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    LOGS.mkdir(parents=True, exist_ok=True)
    log = LOGS / f'{a.label}-{stamp}.log'
    py = str(ROOT / '.venv/Scripts/python.exe')
    lock = product_lock(); waited = 0; held = False
    if a.isolated_no_host_lock:
        if target(mirror).get('port') != '5552' or mirror not in ((ROOT/'.cache/round5-mirror').resolve(), (ROOT/'.cache/round5-mirror-startup').resolve()):
            raise SystemExit('ISOLATED_MIRROR_PORT_5552_REQUIRED')
    else:
        while not lock.acquire('fieldwork', 'round5 platform suite ' + a.label):
            time.sleep(20); waited += 20
        held = True
    try:
        collect = subprocess.run([py, '-B', '-m', 'pytest', '--collect-only', '-q', '-p', 'no:cacheprovider', *pytest_args], cwd=mirror, env=env, capture_output=True, text=True)
        ids = [l for l in collect.stdout.splitlines() if '::' in l]
        header = {'label': a.label, 'utc': stamp, 'command': [py, '-B', '-m', 'pytest', '-p', 'no:cacheprovider', *pytest_args],
                  'cwd': str(mirror), 'env_overrides': sorted(k for k in (i.split('=', 1)[0] for i in a.env)),
                  'target_db': target(mirror), 'lock_waited_seconds': waited, 'host_lock_held': held, 'collected': len(ids), 'test_ids': ids,
                  'source_sha256': source_hashes(mirror)}
        t0 = time.time()
        run = subprocess.run([py, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', *pytest_args], cwd=mirror, env=env, capture_output=True, text=True)
        header['exit_code'] = run.returncode; header['seconds'] = round(time.time() - t0, 1)
        with log.open('x', encoding='utf-8') as f:
            f.write(json.dumps(header, indent=1) + '\n----- pytest output -----\n' + run.stdout + run.stderr)
    finally:
        if held:lock.release()
    tail = (run.stdout + run.stderr).strip().splitlines()[-1:] if run.stdout or run.stderr else []
    print(json.dumps({'log': str(log.relative_to(ROOT)), 'exit_code': run.returncode, 'tail': tail}))
    return run.returncode


if __name__ == '__main__':
    sys.exit(main())
