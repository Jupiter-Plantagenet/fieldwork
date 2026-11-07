"""ML-T-SPLIT on current source: independent re-verification of the retained frozen real version (read-only).

Checks the frozen manifest itself rather than trusting the round-4 report:
  1. no sample / raw sha256 / pixel sha256 / group in more than one split; quarantined members in no split;
  2. perceptual hash (the product's phash-dct64/v1) recomputed for every admitted image: no pair within the
     near-duplicate radius (Hamming <= 6) sits in two different groups or two different splits;
  3. every intake member reconciles: admitted into the manifest, linked as a duplicate of an admitted sample,
     quarantined with a reason, or rejected with a reason;
  4. holdout and validation groups cannot migrate: the real freeze check refuses a derived manifest that moves a
     protected group into train, and one that drops a protected group.

  .venv/Scripts/python -B tools/verify_split_current.py --version <frozen version id> --out <json>
"""
import argparse
import collections
import copy
import json
import sys
from pathlib import Path

import numpy as np
import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fieldwork.dataset_versions import check_real_manifest  # noqa: E402
from fieldwork.splits import NEAR_DUP_MAX_HAMMING, integrity, phash  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--version', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    local = json.loads((ROOT / '.local.json').read_text(encoding='utf-8'))
    p = conninfo_to_dict(local['dsn'])
    with psycopg.connect(**p, row_factory=dict_row) as c:
        c.read_only = True
        v = c.execute('SELECT workspace,state,revision,manifest FROM fw_versions WHERE id=%s', (a.version,)).fetchone()
        m = v['manifest']
        members = c.execute('''SELECT member,disposition,reason,raw_sha256,pixel_sha256,sample_id,linked_sample_id
            FROM fw_intake_members WHERE workspace=%s AND batch_id=%s''', (v['workspace'], m['intake_batch'])).fetchall()
    samples = m['samples']
    report = {'schema': 'fieldwork.split-verification/v1', 'version': a.version, 'state': v['state'], 'revision': v['revision'],
              'manifest_digest': m['digest'], 'split_counts': dict(collections.Counter(s['split'] for s in samples))}

    # 1. exact / pixel / group / quarantine overlap (the product's own integrity rule, re-applied here)
    by_split = collections.defaultdict(list)
    for s in samples:
        by_split[s['split']].append({'sample_id': s['id'], 'raw_sha256': s['sha256'], 'pixel_sha256': s['pixel_sha256'],
                                     'group_id': s['group']})
    groups = [{'group_id': g} for g in {s['group'] for s in samples}]
    report['overlap_problems'] = integrity(by_split, groups, None, m.get('quarantine', []))

    # 2. near-duplicates recomputed from the admitted media
    ids, hashes, missing = [], [], []
    for s in samples:
        f = Path(s['file'])
        if not f.is_file():
            missing.append(s['id'])
            continue
        ids.append(s['id'])
        hashes.append(phash(f))
    h = np.array(hashes, dtype=np.uint64)
    meta = {s['id']: s for s in samples}
    cross_group, cross_split, near_pairs = [], [], 0
    for i in range(len(h)):
        d = np.bitwise_count(h[i + 1:] ^ h[i])
        for j in np.nonzero(d <= NEAR_DUP_MAX_HAMMING)[0].tolist():
            near_pairs += 1
            x, y = meta[ids[i]], meta[ids[i + 1 + j]]
            if x['group'] != y['group']:
                cross_group.append((x['id'], y['id'], int(d[j])))
            if x['split'] != y['split']:
                cross_split.append((x['id'], y['id'], x['split'], y['split'], int(d[j])))
    report['near_duplicates'] = {'images_hashed': len(ids), 'media_missing': len(missing), 'radius': NEAR_DUP_MAX_HAMMING,
                                 'pairs_within_radius': near_pairs, 'pairs_in_different_groups': len(cross_group),
                                 'pairs_in_different_splits': len(cross_split), 'examples': cross_split[:10] or cross_group[:10]}

    # 3. intake reconciliation
    # Intake sample ids and manifest ids are different id spaces; reconcile on the source member path.
    in_manifest = {s['source_member'] for s in samples}
    quarantined_members = {src for g in m.get('quarantine', []) for src in g.get('member_sources', [])}
    quarantined = {mid for g in m.get('quarantine', []) for mid in g['members']}
    member_of = {r['sample_id']: r['member'] for r in members if r['sample_id']}
    disp = collections.Counter(r['disposition'] for r in members)
    unreconciled = []
    for r in members:
        if r['disposition'] == 'accepted':
            if r['member'] not in in_manifest and r['member'] not in quarantined_members:
                unreconciled.append((r['member'], 'accepted_not_in_manifest_or_quarantine'))
        elif r['disposition'] == 'duplicate':
            target = member_of.get(r['linked_sample_id'])
            if target is None or (target not in in_manifest and target not in quarantined_members):
                unreconciled.append((r['member'], 'duplicate_link_missing'))
            if not r['reason']:
                unreconciled.append((r['member'], 'duplicate_without_reason'))
        elif not r['reason']:
            unreconciled.append((r['member'], 'omission_without_reason'))
    total_ok = len(members) == sum(disp.values()) and disp['accepted'] == len(in_manifest) + len(quarantined_members)
    if not total_ok:
        unreconciled.append(('*', 'source_total != accepted+rejected+duplicate+noop or accepted != manifest+quarantine'))
    report['intake'] = {'members': len(members), 'dispositions': dict(disp), 'quarantined_samples': len(quarantined),
                        'unreconciled': len(unreconciled), 'examples': unreconciled[:10]}

    # 4. protected groups cannot migrate (real freeze check, rights map satisfied so only the split rules decide)
    verified = {s['source_member']: s['sha256'] for s in samples}
    hold = next(s for s in samples if s['split'] == 'holdout')
    moved = copy.deepcopy(m)
    for s in moved['samples']:
        if s['group'] == hold['group']:
            s['split'] = 'train'
    dropped = copy.deepcopy(m)
    dropped['samples'] = [s for s in dropped['samples'] if s['group'] != hold['group']]
    baseline, _ = check_real_manifest(copy.deepcopy(m), verified, parent=m)
    moved_problems, _ = check_real_manifest(moved, verified, parent=m)
    dropped_problems, _ = check_real_manifest(dropped, verified, parent=m)
    report['protected_migration'] = {
        'baseline_problems': baseline,
        'moved_group_refused': any(x.startswith('PROTECTED_GROUP_MIGRATED') for x in moved_problems),
        'dropped_group_refused': any(x.startswith('PROTECTED_GROUPS_DROPPED') for x in dropped_problems)}

    ok = (not report['overlap_problems'] and not missing and not cross_group and not cross_split
          and not unreconciled and not baseline and report['protected_migration']['moved_group_refused']
          and report['protected_migration']['dropped_group_refused'])
    report['pass'] = bool(ok)
    Path(a.out).write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('split_counts', 'overlap_problems', 'near_duplicates', 'intake',
                                             'protected_migration', 'pass')}, indent=1)[:2500])
    return 0 if ok else 3


if __name__ == '__main__':
    sys.exit(main())
