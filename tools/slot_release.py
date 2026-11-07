"""Operator tool (review F6): release a stranded host training slot only with proof that its
owner and child processes are gone. See Store.operator_release_slot.

Usage (from fieldwork/): python -B -m tools.slot_release --operator <name> [--dry-run]
Exit 0 released or slot free; 3 refused (prints the reason; nothing changed).
"""
import argparse, json, sys
import psutil
from fieldwork.store import Store, ROOT


def launch_scan(run):
    """Live processes whose command line names var/runs/<run> (where every child is pointed)."""
    needle = str(ROOT / 'var' / 'runs' / run).lower().replace('\\', '/')
    found = []
    for p in psutil.process_iter(['pid', 'cmdline', 'create_time']):
        try:
            cmd = ' '.join(p.info['cmdline'] or []).lower().replace('\\', '/')
        except psutil.Error:
            continue
        if needle in cmd:
            found.append({'pid': p.info['pid'], 'create_time': p.info['create_time']})
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument('--operator', required=True); ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args(argv); s = Store()
    if a.dry_run:
        with s.connect() as c:
            slot = c.execute('SELECT * FROM fw_slot WHERE id=1').fetchone()
        print(json.dumps({'slot': slot, 'candidate_children': launch_scan(slot['run']) if slot['run'] else []}, default=str)); return 0
    out = s.operator_release_slot(a.operator, launch_scan)
    print(json.dumps(out, default=str))
    return 0 if out['released'] or out['reason'] == 'SLOT_FREE' else 3


if __name__ == '__main__':
    sys.exit(main())
