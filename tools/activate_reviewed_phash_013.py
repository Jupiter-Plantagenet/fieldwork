"""Coordinator-reviewed one-shot 013 activation; no worker or API restart."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    from tools import apply_perceptual_013 as apply
    apply.require_lock()
    if sha(ROOT / 'tools/apply_perceptual_013.py') != '63d35de584b114b6887709615a8d25c0a90fe536f0b518f3a29a5c79d37b5837':
        raise ValueError('REVIEWED_OPERATOR_CHANGED')
    if sha(apply.MIGRATION) != 'e595aac22ceae2df189911ea90cd6514a260a19ee6c276d9902912205d65dcf7':
        raise ValueError('REVIEWED_MIGRATION_CHANGED')
    if sha(apply.MANIFEST) != 'd07c1b02b1f3a9346c831a1db83738ca759e727d9a344decf9c16d96b665af82':
        raise ValueError('REVIEWED_SOURCE_MANIFEST_CHANGED')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = ROOT / '.local/real-data/activation' / ('phash013-' + stamp)
    out.mkdir(exist_ok=False)
    backup_label = 'perceptual013-reviewed-' + stamp
    backup = subprocess.run([sys.executable, '-B', '-m', 'tools.r5p_backup', backup_label],
                            cwd=ROOT, capture_output=True, timeout=180)
    if backup.returncode:
        raise RuntimeError('FRESH_BACKUP_FAILED')
    manifests = list((ROOT / 'var/snapshots').glob(backup_label + '-*.json'))
    if len(manifests) != 1:
        raise RuntimeError('FRESH_BACKUP_MANIFEST_NOT_UNIQUE')
    manifest = json.loads(manifests[0].read_text(encoding='utf-8'))
    for kind in ('db', 'globals'):
        if sha(ROOT / manifest[kind]['path']) != manifest[kind]['sha256']:
            raise RuntimeError('FRESH_BACKUP_HASH_MISMATCH')
    cfg = json.loads((ROOT / '.local.json').read_text(encoding='utf-8'))
    from psycopg import connect
    from psycopg.rows import dict_row
    with connect(cfg['dsn'], row_factory=dict_row) as conn:
        counts = apply.public_counts(conn)
    receipt = {'status': 'approved_for_live_013',
               'approved_by': 'root coordinator; standing user authorization',
               'approved_utc': datetime.now(timezone.utc).isoformat(),
               'review': 'docs/independent-review-phash-013-delta-20261102.md',
               'operator_review': 'Parent corrected dict-row lookup, source rehash and atomic postcondition transaction; reviewed exact operator hash.',
               'operator_sha256': sha(ROOT / 'tools/apply_perceptual_013.py'),
               'migration_sha256': sha(apply.MIGRATION),
               'source_manifest_sha256': sha(apply.MANIFEST),
               'scratch_report_sha256': sha(apply.SCRATCH_REPORT),
               'backup_database': manifest['database'], 'backup_utc': manifest['at'],
               'backup_dump': manifest['db']['path'],
               'backup_dump_sha256': manifest['db']['sha256'],
               'backup_globals_sha256': manifest['globals']['sha256'],
               'backup_manifest': str(manifests[0].relative_to(ROOT)),
               'retained_public_counts_before': counts}
    approval = out / 'coordinator-review.json'
    approval.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    sys.argv = [str(ROOT / 'tools/apply_perceptual_013.py'), str(approval)]
    code = apply.main()
    print(json.dumps({'status': 'applied' if code == 0 else 'failed',
                      'review_receipt': str(approval.relative_to(ROOT)),
                      'backup_sha256': receipt['backup_dump_sha256']}))
    return code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(json.dumps({'status': 'refused', 'error_class': type(exc).__name__}))
        sys.exit(2)
