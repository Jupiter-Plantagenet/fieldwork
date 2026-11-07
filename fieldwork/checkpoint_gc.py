"""Checkpoint blob orphan GC (ML-T-ATOMIC: "orphan GC safe after 24h and live-reference check").

Candidates are entries directly under the blob root that are either abandoned
`.staging-*` directories or digest-named directories that no fw_checkpoints row
references. A candidate is removed only when its newest mtime is older than the
grace period (default 24h) AND, for digest directories, a re-check under a
SHARE lock on fw_checkpoints (blocking concurrent publish commits) still finds
no reference. Default is a dry run; pass --apply to delete.

Usage: python -m fieldwork.checkpoint_gc [--blob-root DIR] [--grace-hours 24] [--apply]
"""
import argparse,json,re,shutil,time
from pathlib import Path
from .store import Store,ROOT

DIGEST=re.compile(r'[0-9a-f]{64}')


def _newest_mtime(path):
    newest=path.lstat().st_mtime
    for p in path.rglob('*'):newest=max(newest,p.lstat().st_mtime)
    return newest


def collect(store,blob_root,grace_seconds=24*3600,apply=False,now=None):
    blob_root=Path(blob_root);now=time.time() if now is None else now
    report={'blob_root_exists':blob_root.exists(),'kept_referenced':0,'kept_young':0,'kept_unknown':0,'removed':[],'candidates':[]}
    if not blob_root.exists():return report
    with store.connect() as c:
        # SHARE lock conflicts with publish's INSERT (ROW EXCLUSIVE): no commit can
        # add a new reference between the live-reference check and deletion.
        c.execute('LOCK TABLE fw_checkpoints IN SHARE MODE')
        referenced={Path(r['path']).name for r in c.execute('SELECT path FROM fw_checkpoints').fetchall()}
        for entry in sorted(blob_root.iterdir()):
            staging=entry.name.startswith('.staging-')
            if not staging and not DIGEST.fullmatch(entry.name):report['kept_unknown']+=1;continue
            if not staging and entry.name in referenced:report['kept_referenced']+=1;continue
            if now-_newest_mtime(entry)<grace_seconds:report['kept_young']+=1;continue
            report['candidates'].append(entry.name)
            if apply:
                for p in entry.rglob('*'):p.chmod(0o666)
                shutil.rmtree(entry);report['removed'].append(entry.name)
    return report


def main():
    p=argparse.ArgumentParser();p.add_argument('--blob-root',default=str(ROOT/'var/checkpoints'))
    p.add_argument('--grace-hours',type=float,default=24.0);p.add_argument('--apply',action='store_true')
    a=p.parse_args()
    if a.grace_hours<24:raise SystemExit('GRACE_BELOW_24H_REFUSED')
    print(json.dumps(collect(Store(),a.blob_root,a.grace_hours*3600,a.apply)))

if __name__=='__main__':main()
