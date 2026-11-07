"""Round-4 milestone 3b: grouping, quarantine, split, dataset version review + freeze.

Also exercises ML-T-SPLIT protections: a derived v2 draft that migrates holdout
groups into train must be refused by freeze_real.
"""
import collections
import copy
import json

from round4_common import EVIDENCE, MANIFESTS, STEWARD_LABEL, admin_dsn, context, request_store, set_registry_env, write_json
from fieldwork import annotations
from fieldwork.data import canonical, digest
from fieldwork.dataset_versions import REAL_SCOPE, check_real_manifest, freeze_real
from fieldwork.intake import TAXONOMY
from fieldwork.rights import RightsService
from fieldwork.rights_registry import load_trusted_registry
from fieldwork.splits import (NEAR_DUP_MAX_HAMMING, PHASH, SPLIT_POLICY, assign_splits, build_groups, integrity,
                              near_duplicate_edges, phash)
from fieldwork.store import Store

OUT = EVIDENCE / 'split'


def main():
    ctx = context()
    ws = ctx['workspace_id']
    set_registry_env()
    op = Store(dsn=admin_dsn())
    req = request_store(ws)
    service = RightsService(req, load_trusted_registry)
    with op.connect() as c:
        batch = c.execute("SELECT batch_id FROM fw_intake_batches WHERE workspace=%s AND archive_name='flower_photos.tgz' AND state='complete' ORDER BY started_utc LIMIT 1", (ws,)).fetchone()['batch_id']
        rows = c.execute('SELECT * FROM fw_samples WHERE workspace=%s AND first_batch=%s ORDER BY sample_id', (ws, batch)).fetchall()
        dups = c.execute("SELECT member,linked_sample_id,claimed_label,reason FROM fw_intake_members WHERE workspace=%s AND batch_id=%s AND disposition='duplicate' ORDER BY ordinal", (ws, batch)).fetchall()
    samples = {str(r['sample_id']): r for r in rows}
    labels = {sid: r['source_label'] for sid, r in samples.items()}
    claims = [(str(d['linked_sample_id']), d['claimed_label'], d['member'], d['reason']) for d in dups if str(d['linked_sample_id']) in samples]
    edges = []
    by_photo = collections.defaultdict(list)
    for sid, r in samples.items():
        by_photo[r['source_member'].split('/', 1)[1].split('_', 1)[0]].append(sid)
    for pid, ids in by_photo.items():
        for other in ids[1:]:
            edges.append((ids[0], other, 'same_flickr_photo_id', pid))
    ids = sorted(samples)
    hashes = [phash(samples[s]['media_path']) for s in ids]
    near = near_duplicate_edges(ids, hashes)
    for a, b, d in near:
        edges.append((a, b, 'phash_near_duplicate', d))
    groups, quarantined = build_groups(labels, claims, edges)
    assignment = assign_splits(groups, len(TAXONOMY))
    group_of = {m: g['group_id'] for g in groups for m in g['members']}
    manifest_samples = []
    for g in groups:
        for sid in g['members']:
            r = samples[sid]
            manifest_samples.append({'id': sid, 'label': g['label'], 'split': assignment[g['group_id']], 'group': g['group_id'],
                                     'file': r['media_path'], 'sha256': r['raw_sha256'], 'pixel_sha256': r['pixel_sha256'],
                                     'source_member': r['source_member']})
    manifest_samples.sort(key=lambda s: s['id'])
    edge_rows = [{'a': a, 'b': b, 'kind': k, 'detail': d, 'a_member': samples[a]['source_member'], 'b_member': samples[b]['source_member'],
                  'labels': [labels[a], labels[b]], 'decision': 'linked (conservative: same group)', 'reviewer': 'ai-steward (AI, simulated human review)'}
                 for a, b, k, d in edges]
    m = {'schema': 1, 'scope': REAL_SCOPE, 'dataset': 'tf_flowers', 'rights_dataset_id': ctx['rights_dataset_eligible'],
         'intake_batch': str(batch), 'classes': [t['name'] for t in TAXONOMY], 'taxonomy': TAXONOMY,
         'rights': 'Per-image CC BY 2.0 (tf_flowers LICENSE.txt); attribution in ATTRIBUTION.txt; signed AI-steward decisions per member.',
         'group_policy': {'phash': PHASH, 'max_hamming': NEAR_DUP_MAX_HAMMING, 'edge_kinds': ['intake raw/pixel duplicate links', 'same_flickr_photo_id', 'phash_near_duplicate'],
                          'candidate_resolution': 'all candidates linked; label-conflicting groups quarantined'},
         'split_policy': SPLIT_POLICY, 'samples': manifest_samples,
         'quarantine': [{'group_id': g['group_id'], 'members': g['members'], 'reason': g['quarantine_reason'],
                         'member_sources': [samples[s]['source_member'] for s in g['members']], 'extra_claims': g['extra_claims']} for g in quarantined]}
    m['digest'] = digest(canonical(m))
    by_split = collections.defaultdict(list)
    for s in manifest_samples:
        by_split[s['split']].append({'sample_id': s['id'], 'raw_sha256': s['sha256'], 'pixel_sha256': s['pixel_sha256'], 'group_id': s['group']})
    problems = integrity(by_split, groups, assignment, m['quarantine'])

    # Dataset version through the application's annotation/version workflow.
    v = annotations.create(op, ws, ctx['actors']['steward'], m)
    vid = v['id']
    browser_view_samples = len(v['manifest']['samples'])
    reviewed = annotations.review_version(op, ws, vid, ctx['actors']['reviewer'], v['revision'], v['digest'],
                                          'AI-simulated reviewer: group/quarantine/split report and rights linkage checked; ' + STEWARD_LABEL)
    frozen = freeze_real(op, ws, vid, reviewed['revision'], rights_service=service, actor=ctx['actors']['steward'])
    with op.connect() as c:
        fm = c.execute('SELECT manifest FROM fw_versions WHERE workspace=%s AND id=%s', (ws, vid)).fetchone()['manifest']
    (MANIFESTS / 'version-v1.json').write_bytes(canonical(fm))

    # Protection: a derived v2 that moves holdout groups into train is refused.
    v2m = copy.deepcopy(fm)
    for k in ('version_id', 'review_digest', 'parent_digest', 'support', 'rights_decision_digests_sha256'):
        v2m.pop(k, None)
    moved = sorted({s['group'] for s in v2m['samples'] if s['split'] == 'holdout'})[:3]
    for s in v2m['samples']:
        if s['group'] in moved:
            s['split'] = 'train'
    v2m['digest'] = digest(canonical({k: x for k, x in v2m.items() if k != 'digest'}))
    v2 = annotations.create(op, ws, ctx['actors']['steward'], v2m)
    r2 = annotations.review_version(op, ws, v2['id'], ctx['actors']['reviewer'], v2['revision'], v2['digest'], 'AI-simulated reviewer: protection test draft')
    try:
        freeze_real(op, ws, v2['id'], r2['revision'], rights_service=service, actor=ctx['actors']['steward'], parent_manifest=fm)
        migration = 'UNEXPECTED_FROZEN'
    except annotations.Rejection as exc:
        migration = {'status': exc.status, 'code': str(exc)}
    # Request-principal style view of v1: holdout members absent, file paths absent.
    view = annotations.get(op, ws, vid)
    leaked = [s for s in view['manifest']['samples'] if s['split'] == 'holdout' or 'file' in s]

    counts = {sp: {'samples': sum(1 for s in manifest_samples if s['split'] == sp)} for sp in ('train', 'validation', 'holdout')}
    summary = {'version_id': vid, 'version_digest_frozen': fm['digest'], 'draft_manifest_digest': m['digest'], 'intake_batch': str(batch),
               'catalog_samples_from_real_batch': len(samples), 'duplicate_member_claims': [dict(member=d['member'], linked=str(d['linked_sample_id']), claimed_label=d['claimed_label'], reason=d['reason']) for d in dups],
               'edges': {'total': len(edges), 'by_kind': dict(collections.Counter(e[2] for e in edges)),
                         'phash_distance_histogram': dict(sorted(collections.Counter(d for _, _, d in near).items())),
                         'cross_label_edges': sum(1 for a, b, _, _ in edges if labels[a] != labels[b])},
               'groups': {'count': len(groups), 'multi_member': sum(1 for g in groups if len(g['members']) > 1),
                          'largest': max(len(g['members']) for g in groups)},
               'quarantined_groups': len(quarantined), 'quarantined_samples': sum(len(g['members']) for g in quarantined),
               'quarantine': m['quarantine'], 'split_counts': counts, 'support': fm['support'],
               'per_class_split_counts': {sp: dict(collections.Counter(TAXONOMY[s['label']]['name'] for s in manifest_samples if s['split'] == sp)) for sp in ('train', 'validation', 'holdout')},
               'integrity_problems': problems, 'freeze_state': frozen['state'],
               'rights_decision_digests_sha256': fm['rights_decision_digests_sha256'],
               'protection_holdout_migration_v2': migration, 'moved_groups_in_v2_attempt': moved,
               'version_view': {'samples_shown': len(view['manifest']['samples']), 'holdout_or_file_leaks': len(leaked), 'create_view_samples': browser_view_samples}}
    write_json(OUT / 'split-summary.json', summary)
    write_json(OUT / 'edges.json', edge_rows)
    write_json(OUT / 'groups.json', [{'group_id': g['group_id'], 'label': g['label'], 'split': assignment[g['group_id']], 'members': g['members']} for g in groups])
    (OUT / 'version-v1-manifest.sha256').write_text(fm['digest'] + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in ('quarantine', 'duplicate_member_claims')}, indent=1))


if __name__ == '__main__':
    main()
