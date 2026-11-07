"""Prepare current-source isolated mirrors; run the bounded W1 light/startup packet."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import httpx
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).resolve().parents[1]
PY = ROOT / '.venv/Scripts/python.exe'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('stage', choices=['light', 'startup', 'identity', 'diagnosis'])
    ap.add_argument('--tests', nargs='+', help='light stage only: run just these test paths (relative to the project)')
    a = ap.parse_args()
    mirror = ROOT / ('.cache/round5-mirror-startup' if a.stage == 'startup' else '.cache/round5-mirror')
    for directory in ('fieldwork', 'tests', 'migrations', 'tools'):
        for p in (ROOT / directory).rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py', '.sql'):
                q = mirror / p.relative_to(ROOT)
                q.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, q)
    db = conninfo_to_dict(json.loads((mirror / '.local.json').read_text())['dsn'])
    assert db['host'] == '127.0.0.1' and str(db['port']) == '5552'
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    scratch = ROOT / '.local/round5-resume' / (a.stage + '-' + stamp)
    scratch.mkdir(parents=True)
    (scratch/'fwr').mkdir()
    (scratch/'fwm').mkdir()
    env = dict(os.environ, PYTHONPATH=str(mirror), PYTHONDONTWRITEBYTECODE='1', FIELDWORK_PG_CONTAINER='fieldwork-pg-verify')
    args = [str(PY), '-B', 'tools/r5p_run.py', 'resume-' + a.stage,
            '--mirror', str(mirror.relative_to(ROOT)), '--isolated-no-host-lock']
    extra = []
    if a.stage == 'light':
        extra = ['FW_SECOND_PACKET=s29d2', 'FW_SECOND_ROLE=fieldwork_api', 'FW_SECOND_DATABASE=' + db['dbname'],
                 'FWR_EVIDENCE=' + str(scratch / 'fwr'), 'FWM_EVIDENCE=' + str(scratch / 'fwm'),
                 'FIELDWORK_LIVE_BASE=http://127.0.0.1:8112']
        tests = ['tests']
        ignores = ['test_replay', 'test_optimization', 'test_bundle', 'test_worker', 'test_worker_faults', 'test_artifact_stages',
                   'test_postfix_recovery', 'test_checkpoint_integrity', 'test_live_worker_api',
                   'test_checkpoint_read_capability', 'test_checkpoint_startup', 'test_checkpoint_robustness',
                   'test_atomic_crash_edges', 'test_dataset_round5']
        tests += ['--ignore=tests/' + name + '.py' for name in ignores]
        if a.tests:
            tests = list(a.tests)
    elif a.stage == 'startup':
        extra = ['FW_STARTUP_PACKET=s29c1a', 'FW_STARTUP_MIRROR=' + str(mirror), 'FW_STARTUP_DATABASE=' + db['dbname']]
        tests = ['tests/test_checkpoint_startup.py', 'tests/test_checkpoint_robustness.py']
    else:
        tests = ['tests/test_worker_identity.py'] if a.stage=='identity' else [
            'tests/test_worker_identity.py', 'tests/test_event_receipt_privacy.py',
            'tests/test_cancel_ack_postgres.py',
            'tests/test_scoped_authority.py::test_strict_machine_configuration',
            'tests/test_scoped_authority.py::test_generate_new_private_fixture_authority_and_operator_cli',
            'tests/test_lease_recovery_physical.py::test_canonical_45_second_lease_independent_loop_while_execution_blocked',
            'tests/test_slot_reconcile.py::test_killed_owner_without_child_releases_slot_and_keeps_run_state']
        extra=['FWR_EVIDENCE='+str(scratch/'fwr'),'FWM_EVIDENCE='+str(scratch/'fwm')]
    for item in extra:
        args += ['--env', item]
    args += ['--', *tests, '--basetemp=' + str(scratch / 'pytest')]
    api = None
    try:
        if a.stage == 'light':
            log = (scratch / 'api.log').open('xb')
            api = subprocess.Popen([str(PY), '-B', '-m', 'uvicorn', 'fieldwork.api:app', '--host', '127.0.0.1', '--port', '8112', '--no-access-log'],
                                   cwd=mirror, env=env, stdout=log, stderr=subprocess.STDOUT)
            for _ in range(60):
                try:
                    if httpx.get('http://127.0.0.1:8112/health/ready', timeout=1).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if api.poll() is not None:
                    raise RuntimeError('ISOLATED_API_EXITED_SEE_PRIVATE_LOG')
                time.sleep(.5)
            else:
                raise RuntimeError('ISOLATED_API_NOT_READY')
        return subprocess.run(args, cwd=ROOT, env=env).returncode
    finally:
        if api is not None:
            api.terminate()
            api.wait(timeout=15)


if __name__ == '__main__':
    sys.exit(main())
