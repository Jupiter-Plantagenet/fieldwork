"""Server-side constructors for rights-cleared working dataset versions.

Clients identify only an accepted intake receipt or an exact frozen real parent.
The service owns sample selection, split inheritance, file references and digest
construction; browser requests never provide member lists or paths.
"""
from __future__ import annotations

import copy

from .data import canonical, digest
from .dataset_versions import REAL_SCOPE
from .intake import TAXONOMY
from .perceptual_grouping import group_new_samples

FROZEN_RECEIPT_FIELDS = {
    'version_id', 'parent_digest', 'review_digest', 'support',
    'protected_population_support', 'rights_decision_digests_sha256',
    'rights_decision_commitments',
}


def intake_draft_manifest(*, batch_id: str, rights_dataset_id: str, samples: list[dict],
                          label_claims: list[dict] | None = None) -> dict:
    """Build an unassigned pool draft from accepted sample rows for one intake batch."""
    if not samples:
        raise ValueError('EMPTY_ACCEPTED_INTAKE')
    classes = [item['name'] for item in TAXONOMY]
    members = []
    for row in samples:
        if row['rights_dataset_id'] != rights_dataset_id:
            raise ValueError('INTAKE_RIGHTS_DATASET_MISMATCH')
        if row['source_label'] is not None and not 0 <= row['source_label'] < len(classes):
            raise ValueError('INTAKE_LABEL_OUTSIDE_TAXONOMY')
        sample_id = str(row['sample_id'])
        member = {
            'id': sample_id,
            'label': row['source_label'],
            'split': 'pool',
            'group': '',
            'file': row['media_path'],
            'sha256': row['raw_sha256'],
            'pixel_sha256': row['pixel_sha256'],
            'source_member': row['source_member'],
            'raw_bytes': row['raw_bytes'],
            'rights_dataset_id': rights_dataset_id,
        }
        if row.get('phash_algorithm') is not None or row.get('phash_hex') is not None:
            member['phash'] = {
                'algorithm': row.get('phash_algorithm'), 'hex': row.get('phash_hex'),
                'raw_sha256': row.get('phash_raw_sha256'),
                'pixel_sha256': row.get('phash_pixel_sha256'),
                'decoder': row.get('phash_decoder'),
            }
        members.append(member)
    grouping_rows = [{
        'id': row['id'], 'label': row['label'], 'source_member': row['source_member'],
        'raw_sha256': row['sha256'], 'pixel_sha256': row['pixel_sha256'],
        **({'phash': row['phash']} if row.get('phash') else {}),
    } for row in members]
    grouping = group_new_samples(grouping_rows, label_claims, require_complete=False)
    for row in members:
        result = grouping['membership'][row['id']]
        row['group'] = result['group']
        if result['quarantined']:
            row['quarantined'] = True
    quarantined_ids = {sid for group in grouping['quarantine'] for sid in group['members']}
    members = [row for row in members if row['id'] not in quarantined_ids]
    manifest = {
        'schema': 1,
        'scope': REAL_SCOPE,
        'dataset': 'accepted-real-intake',
        'intake_batch': str(batch_id),
        'rights_dataset_id': rights_dataset_id,
        'rights_dataset_ids': [rights_dataset_id],
        'rights': 'Real image records accepted by the workspace rights-reviewed intake.',
        'classes': classes,
        'taxonomy': TAXONOMY,
        'group_policy': grouping['policy'],
        'group_audit': {
            'status': 'complete' if grouping['audit_complete'] else 'incomplete',
            'audit_complete': grouping['audit_complete'],
            'missing_feature_samples': grouping['missing_feature_samples'],
            'edges': grouping['edges'],
        },
        'split_policy': {'status': 'unassigned', 'pool_only': True},
        'samples': sorted(members, key=lambda item: item['id']),
        'quarantine': grouping['quarantine'],
    }
    manifest['digest'] = digest(canonical(manifest))
    return manifest


def child_draft_manifest(parent: dict, parent_version_id: str) -> dict:
    """Copy a frozen real manifest while retaining its protected membership exactly."""
    if parent.get('scope') != REAL_SCOPE or not parent.get('digest'):
        raise ValueError('FROZEN_REAL_PARENT_REQUIRED')
    manifest = copy.deepcopy(parent)
    for field in FROZEN_RECEIPT_FIELDS | {'digest'}:
        manifest.pop(field, None)
    if not manifest.get('rights_dataset_ids') and manifest.get('rights_dataset_id'):
        manifest['rights_dataset_ids'] = [manifest['rights_dataset_id']]
    manifest['parent_version_id'] = parent_version_id
    manifest['parent_version_digest'] = parent['digest']
    manifest['digest'] = digest(canonical(manifest))
    return manifest
