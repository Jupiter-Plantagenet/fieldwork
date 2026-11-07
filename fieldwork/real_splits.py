"""Initial, reviewed train/validation split plan for an intake-backed draft.

The API selects the eligible pool rows already pinned in the draft. This plan
assigns whole server-recorded groups to train, validation or continued pool;
quarantined label-conflict components remain outside the version membership, and
the plan never creates or reads a holdout population.
"""
from __future__ import annotations

import copy

from .data import canonical, digest
from .dataset_versions import REAL_SCOPE
from .splits import assign_splits

MAX_SPLIT_SAMPLES = 10_000
MIN_TRAIN_GROUPS_PER_CLASS = 2
MIN_VALIDATION_GROUPS_PER_CLASS = 2
INITIAL_SPLIT_POLICY = {
    'targets': {'train': 0.70, 'validation': 0.15, 'pool': 0.15},
    'seed': 42,
    'tie_order': ['train', 'validation', 'pool'],
    'unit': 'group',
    'stratify': 'effective candidate label',
}


class SplitPlanRejected(ValueError):
    pass


def _support(manifest: dict) -> dict:
    out = {}
    for split in ('train', 'validation', 'pool'):
        rows = [s for s in manifest['samples'] if s['split'] == split and not s.get('quarantined')]
        out[split] = {str(c): {
            'samples': sum(1 for s in rows if s['label'] == c),
            'groups': len({s['group'] for s in rows if s['label'] == c}),
        } for c in range(len(manifest['classes']))}
    return out


def assign_initial_splits(manifest: dict, proposal_rows: list[dict], source_version_digest: str) -> dict:
    """Return a new plan-bound manifest or reject an unsafe/incomplete draft."""
    if (manifest.get('scope') != REAL_SCOPE
            or manifest.get('parent_version_id')
            or manifest.get('split_policy') != {'status': 'unassigned', 'pool_only': True}
            or not manifest.get('samples')
            or len(manifest['samples']) > MAX_SPLIT_SAMPLES):
        raise SplitPlanRejected('INITIAL_POOL_DRAFT_REQUIRED')
    audit = manifest.get('group_audit')
    if (not isinstance(audit, dict) or audit.get('audit_complete') is not True
            or audit.get('status') != 'complete'):
        raise SplitPlanRejected('GROUP_AUDIT_REQUIRED')
    if any(s.get('split') != 'pool' or 'holdout_population' in s or s.get('protected') is True
           for s in manifest['samples']):
        raise SplitPlanRejected('INITIAL_POOL_DRAFT_REQUIRED')
    if digest(canonical({k: value for k, value in manifest.items() if k != 'digest'})) != manifest['digest']:
        raise SplitPlanRejected('DRAFT_MANIFEST_DIGEST_MISMATCH')

    latest = {row['sample']: row for row in proposal_rows}
    if any(row.get('decision') is None for row in latest.values()):
        raise SplitPlanRejected('ANNOTATION_REVIEW_REQUIRED')
    planned = copy.deepcopy(manifest)
    samples = planned['samples']
    class_count = len(planned.get('classes') or [])
    if not class_count:
        raise SplitPlanRejected('TAXONOMY_REQUIRED')

    by_group: dict[str, list[dict]] = {}
    persisted_quarantine = {str(item.get('group')) for item in manifest.get('quarantine', [])
                            if isinstance(item, dict)}
    for sample in samples:
        proposal = latest.get(sample['id'])
        if proposal and proposal.get('decision') == 'approved':
            sample['label'] = proposal['label']
            sample['annotation_digest'] = proposal['digest']
        if sample.get('group') in persisted_quarantine or sample.get('quarantined') is True:
            sample['quarantined'] = True
            sample['split'] = 'pool'
            continue
        label = sample.get('label')
        if type(label) is not int or not 0 <= label < class_count:
            raise SplitPlanRejected('LABEL_REVIEW_REQUIRED')
        group = sample.get('group')
        if not isinstance(group, str) or not group:
            raise SplitPlanRejected('GROUP_ID_REQUIRED')
        by_group.setdefault(group, []).append(sample)

    groups = []
    newly_quarantined = []
    for group_id, rows in sorted(by_group.items()):
        labels = {row['label'] for row in rows}
        if len(labels) != 1:
            for row in rows:
                row['quarantined'] = True
                row['split'] = 'pool'
            newly_quarantined.append({'group': group_id,
                                      'members': sorted(row['id'] for row in rows),
                                      'reason': 'LABEL_CONFLICT', 'labels': sorted(labels),
                                      'source_claims': []})
            continue
        groups.append({'group_id': group_id, 'label': next(iter(labels)),
                       'members': sorted(row['id'] for row in rows)})
    assignments = assign_splits(groups, class_count, INITIAL_SPLIT_POLICY)
    if len(assignments) != len(groups):
        raise SplitPlanRejected('CLASS_GROUP_SUPPORT_REQUIRED')
    for sample in samples:
        if not sample.get('quarantined'):
            sample['split'] = assignments[sample['group']]
    if newly_quarantined:
        removed_ids = {sid for group in newly_quarantined for sid in group['members']}
        planned['samples'] = [row for row in samples if row['id'] not in removed_ids]
        samples = planned['samples']
        planned['quarantine'] = sorted(
            [*planned.get('quarantine', []), *newly_quarantined], key=lambda row: row['group'])

    support = _support(planned)
    for label in range(class_count):
        train = support['train'][str(label)]
        validation = support['validation'][str(label)]
        if train['samples'] == 0 or train['groups'] < MIN_TRAIN_GROUPS_PER_CLASS:
            raise SplitPlanRejected('CLASS_GROUP_SUPPORT_REQUIRED')
        if validation['samples'] == 0 or validation['groups'] < MIN_VALIDATION_GROUPS_PER_CLASS:
            raise SplitPlanRejected('CLASS_GROUP_SUPPORT_REQUIRED')

    member_plan = [{'id': row['id'], 'group': row['group'], 'split': row['split']}
                   for row in sorted(samples, key=lambda row: row['id'])]
    policy = copy.deepcopy(INITIAL_SPLIT_POLICY)
    planned['split_policy'] = {
        'id': 'group-stratified-candidate/v1',
        'status': 'assigned',
        'purpose': 'candidate-training-only',
        **policy,
        'source_manifest_digest': manifest['digest'],
        'source_version_digest': source_version_digest,
        'group_policy_id': planned.get('group_policy', {}).get('id'),
        'split_plan_digest': digest(canonical(member_plan)),
        'protected_holdout_created': False,
    }
    planned.pop('digest', None)
    planned['digest'] = digest(canonical(planned))
    return planned
