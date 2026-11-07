"""Run the focused, self-contained repository checks and save an execution receipt."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
COMMANDS = [['PYTHON', '-m', 'pip', 'check'], ['PYTHON', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/test_metrics.py', 'tests/test_full_metrics.py', 'tests/test_manifest.py', 'tests/test_standalone_dependencies.py', 'tests/test_real_worker_liveness_refresh.py'], ['npm', '--prefix', 'apps/web', 'run', 'build']]

def main():
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    python = ROOT / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE='1')
    report = {'started_utc': datetime.now(timezone.utc).isoformat(), 'checks': [],
              'scope': 'Focused checks in the current checkout', 'passed': False}
    output = ROOT / '.local' / 'review-checks'
    output.mkdir(parents=True, exist_ok=True)
    for index, command in enumerate(COMMANDS):
        command = list(command)
        if command[0] == 'PYTHON':
            executable = str(python) if python.is_file() else None
        else:
            name = command[0] + ('.cmd' if os.name == 'nt' and command[0] == 'npm' else '')
            executable = shutil.which(name)
        if not executable:
            print('Missing dependency for ' + command[0] + '. See docs/reproduction.md.')
            report['checks'].append({'command': command, 'status': 'missing_dependency'})
            break
        result = subprocess.run([executable, *command[1:]], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding='utf8', errors='replace')
        log = output / (str(index + 1).zfill(2) + '.log')
        log.write_text(result.stdout, encoding='utf8')
        print(result.stdout)
        report['checks'].append({'command': command, 'exit_code': result.returncode,
                                 'log': log.relative_to(ROOT).as_posix()})
        if result.returncode:
            break
    report['passed'] = len(report['checks']) == len(COMMANDS) and all(
        entry.get('exit_code') == 0 for entry in report['checks'])
    report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    receipt = output / 'report.json'
    receipt.write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')
    print(str(receipt))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    sys.exit(main())
