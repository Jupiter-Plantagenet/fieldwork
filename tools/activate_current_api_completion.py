"""Back up retained Fieldwork and activate the reviewed current API once."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import activate_real_worker as operator


def main():
    operator.require_lock()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = ROOT / '.local/real-data/activation' / ('completion-api-' + stamp)
    out.mkdir(exist_ok=False)
    from fieldwork.scoped_authority import check_private
    check_private(out)
    sources = [*sorted((ROOT / 'fieldwork').glob('*.py')),
               *sorted((ROOT / 'migrations').glob('*.sql')), ROOT / 'tools/restart_api.py']
    files = {}
    for source in sources:
        if source.is_symlink() or source.is_junction():
            raise RuntimeError('SOURCE_REPARSE_REFUSED')
        files[source.relative_to(ROOT).as_posix()] = hashlib.sha256(source.read_bytes()).hexdigest()
    pinfile = out / 'source-pins.json'
    pinfile.write_text(json.dumps({'schema': 'fieldwork.current-activation-source-pins/v1',
                                   'files': files}, indent=2) + '\n', encoding='utf-8')
    label = 'completion-api-before-' + stamp
    backup = subprocess.run([sys.executable, '-B', '-m', 'tools.r5p_backup', label],
                            cwd=ROOT, capture_output=True, timeout=180)
    if backup.returncode:
        raise RuntimeError('FRESH_API_BACKUP_FAILED')
    matches = list((ROOT / 'var/snapshots').glob(label + '-*.json'))
    if len(matches) != 1:
        raise RuntimeError('API_BACKUP_NOT_UNIQUE')
    manifest = json.loads(matches[0].read_text(encoding='utf-8'))
    for part in ('db', 'globals'):
        source = ROOT / manifest[part]['path']
        if hashlib.sha256(source.read_bytes()).hexdigest() != manifest[part]['sha256']:
            raise RuntimeError('API_BACKUP_HASH_MISMATCH')
    result = operator.restart_api(SimpleNamespace(source_pins=pinfile,
        pixel_image_id='sha256:b42e39dfea7adbace1be7766fc071e94ff3424ac175485c633986ac8ae883dcd',
        model_image_id='sha256:41c680046133d0920a217adbfb951b8c77e4cec7e3ea7763646b19c5f4e7dfdc'))
    receipt = {'status': 'activated', 'at_utc': datetime.now(timezone.utc).isoformat(),
               'backup_manifest': str(matches[0].relative_to(ROOT)),
               'backup_db_sha256': manifest['db']['sha256'],
               'backup_globals_sha256': manifest['globals']['sha256'],
               'source_pin_file_sha256': hashlib.sha256(pinfile.read_bytes()).hexdigest(),
               'result': result}
    path = out / 'receipt.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'activated', 'receipt': str(path.relative_to(ROOT)),
                      'source_files': len(files), 'backup_db_sha256': manifest['db']['sha256']}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status': 'refused', 'error_class': type(exc).__name__}))
        sys.exit(2)
