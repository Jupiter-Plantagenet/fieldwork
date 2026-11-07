"""Relocate dataset-lane data off the failing D: drive to real C: directories (2026-10-31).

copy   : copy every needed file from D: to C: staging, verify each by SHA-256 (source == dest),
         write the relocation manifest. Pure duplicates are NOT copied, with digests recorded:
           tf_flowers/extracted/**  (byte-identical members of archive/flower_photos.tgz)
           commons_r5/downloads/**  (byte-identical members of archive/commons_r5.tar, verified)
           commons_r5/annotation/sheets/*.png (anonymised contact sheets; labels + index kept)
switch : (after `cmd /c rmdir` of the var/datasets junction) rename staging into place and
         re-verify; update fw_samples.media_path of the Commons batch (operator write).
D: copies are left in place for the parent to clean up.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_TF = Path('D:/portfolio-build-data/fieldwork/datasets')
SRC_C5 = Path('D:/portfolio-build-data/fieldwork/commons_r5')
DST_TF_STAGE = ROOT / 'var/datasets-c-staging'
DST_TF = ROOT / 'var/datasets'
DST_C5 = ROOT / 'var/commons_r5'
MANIFEST = ROOT / 'evidence/ml/round5/tests/db/relocation-d-to-c.json'


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def skip(rel):
    r = rel.replace('\\', '/')
    return (r.startswith('tf_flowers/extracted/') or r.startswith('downloads/') or (r.startswith('annotation/sheets/') and r.endswith('.png')))


def copy():
    out = {'copied': [], 'skipped_duplicates': []}
    for src, dst in ((SRC_TF, DST_TF_STAGE), (SRC_C5, DST_C5)):
        for p in sorted(src.rglob('*')):
            if not p.is_file():
                continue
            rel = p.relative_to(src).as_posix()
            if skip(rel):
                out['skipped_duplicates'].append({'root': str(src), 'path': rel, 'sha256': sha(p), 'bytes': p.stat().st_size})
                continue
            q = dst / rel
            q.parent.mkdir(parents=True, exist_ok=True)
            data = p.read_bytes()
            q.write_bytes(data)
            s1, s2 = hashlib.sha256(data).hexdigest(), sha(q)
            if s1 != s2 or sha(p) != s1:
                raise SystemExit('VERIFY_FAILED ' + rel)
            out['copied'].append({'root': str(src), 'path': rel, 'sha256': s1, 'bytes': len(data)})
    out['copied_files'] = len(out['copied'])
    out['copied_bytes'] = sum(x['bytes'] for x in out['copied'])
    out['skipped_files'] = len(out['skipped_duplicates'])
    out['skipped_bytes'] = sum(x['bytes'] for x in out['skipped_duplicates'])
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if not isinstance(v, list)}))


def switch():
    if os.path.lexists(DST_TF) and Path(os.path.realpath(DST_TF)).drive.upper() == 'D:':
        raise SystemExit('JUNCTION_STILL_PRESENT')
    if not DST_TF.exists():
        DST_TF_STAGE.rename(DST_TF)
    m = json.loads(MANIFEST.read_text())
    bad = 0
    for x in m['copied']:
        base = DST_TF if x['root'] == str(SRC_TF) else DST_C5
        if sha(base / x['path']) != x['sha256']:
            bad += 1
    sys.path.insert(0, str(ROOT / 'tools'))
    from round5_common import admin_dsn, context
    import psycopg
    ws = context()['workspace_id']
    with psycopg.connect(admin_dsn()) as c:
        c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (ws,))
        n = c.execute(r"""UPDATE fw_samples SET media_path=replace(media_path,'D:\portfolio-build-data\fieldwork\commons_r5\','"""
                      + str(DST_C5).replace('/', '\\') + r"""\') WHERE workspace=%s AND media_path LIKE 'D:%%'""", (ws,)).rowcount
        left = c.execute("SELECT count(*) FROM fw_samples WHERE workspace=%s AND media_path LIKE 'D:%%'", (ws,)).fetchone()[0]
        missing = sum(1 for (p,) in c.execute('SELECT media_path FROM fw_samples WHERE workspace=%s', (ws,)).fetchall() if not Path(p).is_file())
    m.update(after_switch={'reverify_mismatches': bad, 'fw_samples_paths_updated': n, 'fw_samples_paths_still_on_D': left,
                           'fw_samples_media_missing': missing, 'var_datasets_realpath': os.path.realpath(DST_TF)})
    MANIFEST.write_text(json.dumps(m, indent=1))
    print(json.dumps(m['after_switch']))


if __name__ == '__main__':
    {'copy': copy, 'switch': switch}[sys.argv[1]]()
