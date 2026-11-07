"""Pure checks for server-constructed real drafts; no database or media reads."""
from copy import deepcopy
from hashlib import sha256

from fieldwork.protected_population import check_child
from fieldwork.real_versions import child_draft_manifest, intake_draft_manifest
from fieldwork.real_splits import SplitPlanRejected, assign_initial_splits
from fieldwork.dataset_versions import check_real_manifest
from fieldwork.data import canonical, digest


def test_intake_draft_is_pool_only_and_server_references_accepted_rows():
    rows = [
        {'sample_id': 'sample-1', 'source_label': None, 'rights_dataset_id': 'rights-dataset',
         'media_path': 'C:/fieldwork/private-media/sample.jpg', 'raw_sha256': 'a' * 64,
         'raw_bytes': 123, 'pixel_sha256': 'b' * 64, 'source_member': 'flower/sample.jpg'},
        {'sample_id': 'sample-2', 'source_label': 1, 'rights_dataset_id': 'rights-dataset',
         'media_path': 'C:/fieldwork/private-media/other.jpg', 'raw_sha256': 'c' * 64,
         'raw_bytes': 456, 'pixel_sha256': 'd' * 64, 'source_member': 'flower/123456_variant.jpg'},
        {'sample_id': 'sample-3', 'source_label': 1, 'rights_dataset_id': 'rights-dataset',
         'media_path': 'C:/fieldwork/private-media/other-2.jpg', 'raw_sha256': 'e' * 64,
         'raw_bytes': 456, 'pixel_sha256': 'f' * 64, 'source_member': 'flower/123456_other.jpg'},
    ]
    manifest = intake_draft_manifest(batch_id='batch-1', rights_dataset_id='rights-dataset', samples=rows)
    assert manifest['scope'] == 'real-rights-cleared'
    assert all(sample['split'] == 'pool' for sample in manifest['samples'])
    by_id = {sample['id']: sample for sample in manifest['samples']}
    assert by_id['sample-1']['label'] is None
    assert by_id['sample-1']['file'] == rows[0]['media_path']
    assert by_id['sample-2']['group'] == by_id['sample-3']['group']
    assert by_id['sample-1']['group'] != by_id['sample-2']['group']
    assert manifest['group_audit']['status'] == 'incomplete'
    assert manifest['group_audit']['audit_complete'] is False
    assert manifest['split_policy'] == {'status': 'unassigned', 'pool_only': True}


def test_intake_draft_transitively_quarantines_conflicting_hash_group():
    rows = []
    for sample_id, label, value in (('a', 0, 0), ('b', 1, 0x3f), ('c', 1, 0xfff)):
        raw = sha256((sample_id + '-raw').encode()).hexdigest()
        pixel = sha256((sample_id + '-pixels').encode()).hexdigest()
        rows.append({'sample_id': sample_id, 'source_label': label,
            'rights_dataset_id': 'rights-dataset', 'media_path': f'private/{sample_id}.jpg',
            'raw_sha256': raw, 'raw_bytes': 100, 'pixel_sha256': pixel,
            'source_member': f'flower/{sample_id}.jpg', 'phash_algorithm': 'phash-dct64/v1',
            'phash_hex': f'{value:016x}', 'phash_raw_sha256': raw,
            'phash_pixel_sha256': pixel, 'phash_decoder': 'fixture-pinned-decoder/v2'})
    manifest = intake_draft_manifest(batch_id='batch-2', rights_dataset_id='rights-dataset',
                                      samples=rows)
    assert manifest['group_audit']['audit_complete'] is True
    assert manifest['samples'] == []
    assert len(manifest['quarantine']) == 1
    assert manifest['quarantine'][0]['members'] == ['a', 'b', 'c']


def test_initial_plan_is_deterministic_group_disjoint_and_never_creates_holdout():
    samples = []
    verified = {}
    for label in range(5):
        for group_index in range(20):
            for variant in range(2):
                sample_id = f'sample-{label}-{group_index}-{variant}'
                member = f'flower/{label}/{group_index}_{variant}.jpg'
                raw = sha256(sample_id.encode()).hexdigest()
                samples.append({'id': sample_id, 'label': label, 'split': 'pool',
                    'group': f'group-{label}-{group_index}', 'sha256': raw,
                    'pixel_sha256': sha256((sample_id + '-pixel').encode()).hexdigest(),
                    'source_member': member, 'file': 'private-media/' + sample_id + '.jpg'})
                verified[member] = raw
    manifest = {'scope': 'real-rights-cleared', 'classes': [str(i) for i in range(5)],
        'split_policy': {'status': 'unassigned', 'pool_only': True},
        'group_policy': {'id': 'raw-pixel-source-phash-transitive/v1'},
        'group_audit': {'status': 'complete', 'audit_complete': True, 'missing_feature_samples': [], 'edges': []},
        'samples': samples}
    manifest['digest'] = digest(canonical(manifest))
    first = assign_initial_splits(manifest, [], 'd' * 64)
    second = assign_initial_splits(manifest, [], 'd' * 64)
    assert first == second
    assert first['split_policy']['protected_holdout_created'] is False
    assert all(s['split'] in {'train', 'validation', 'pool'} for s in first['samples'])
    by_group = {}
    for sample in first['samples']:
        by_group.setdefault(sample['group'], set()).add(sample['split'])
    assert all(len(splits) == 1 for splits in by_group.values())
    assert check_real_manifest(first, verified)[0] == []


def test_initial_plan_refuses_a_draft_without_complete_phash_coverage():
    sample = {'id': 'sample', 'label': 0, 'split': 'pool', 'group': 'group-sample'}
    manifest = {'scope': 'real-rights-cleared', 'classes': ['a'],
        'split_policy': {'status': 'unassigned', 'pool_only': True},
        'group_policy': {'id': 'raw-pixel-source-phash-transitive/v1'},
        'group_audit': {'status': 'incomplete', 'audit_complete': False,
                        'missing_feature_samples': ['sample'], 'edges': []},
        'samples': [sample]}
    manifest['digest'] = digest(canonical(manifest))
    try:
        assign_initial_splits(manifest, [], 'b' * 64)
    except SplitPlanRejected as exc:
        assert str(exc) == 'GROUP_AUDIT_REQUIRED'
    else:
        raise AssertionError('a partial grouping graph cannot be split or frozen')


def test_initial_plan_requires_reviewed_labels_and_cannot_touch_parent_or_protected_data():
    manifest = {'scope': 'real-rights-cleared', 'classes': ['a'],
        'split_policy': {'status': 'unassigned', 'pool_only': True},
        'group_audit': {'status': 'complete', 'audit_complete': True,
                        'missing_feature_samples': [], 'edges': []}, 'samples': [
            {'id': 'sample', 'label': 0, 'split': 'pool', 'group': 'opaque-group'}]}
    manifest['digest'] = digest(canonical(manifest))
    pending = [{'sample': 'sample', 'decision': None}]
    try:
        assign_initial_splits(manifest, pending, 'b' * 64)
    except SplitPlanRejected as exc:
        assert str(exc) == 'ANNOTATION_REVIEW_REQUIRED'
    else:
        raise AssertionError('pending proposal must block split assignment')
    parent = deepcopy(manifest)
    parent['parent_version_id'] = 'frozen-parent'
    try:
        assign_initial_splits(parent, [], 'b' * 64)
    except SplitPlanRejected as exc:
        assert str(exc) == 'INITIAL_POOL_DRAFT_REQUIRED'
    else:
        raise AssertionError('parent split assignment must be immutable')


def test_initial_plan_ignores_superseded_pending_proposals_after_latest_review():
    samples = []
    for label in range(5):
        for group_index in range(10):
            sample_id = f'sample-{label}-{group_index}'
            samples.append({'id': sample_id, 'label': label, 'split': 'pool',
                'group': f'group-{label}-{group_index}'})
    manifest = {'scope': 'real-rights-cleared', 'classes': [str(i) for i in range(5)],
        'split_policy': {'status': 'unassigned', 'pool_only': True},
        'group_policy': {'id': 'raw-pixel-source-phash-transitive/v1'},
        'group_audit': {'status': 'complete', 'audit_complete': True, 'missing_feature_samples': [], 'edges': []},
        'samples': samples}
    manifest['digest'] = digest(canonical(manifest))
    proposals = [
        {'sample': 'sample-0-0', 'decision': None, 'label': 1, 'digest': 'a' * 64},
        {'sample': 'sample-0-0', 'decision': 'approved', 'label': 0, 'digest': 'b' * 64},
    ]
    planned = assign_initial_splits(manifest, proposals, 'c' * 64)
    revised = next(sample for sample in planned['samples'] if sample['id'] == 'sample-0-0')
    assert revised['label'] == 0
    assert revised['annotation_digest'] == 'b' * 64


def test_child_draft_preserves_parent_split_and_protected_manifest_membership():
    parent = {'scope': 'real-rights-cleared', 'digest': 'c' * 64, 'samples': [
        {'id': 'train', 'split': 'train', 'label': 0, 'group': 'g1', 'sha256': 'a' * 64},
        {'id': 'sealed', 'split': 'holdout', 'holdout_population': 'consumed-r4',
         'label': 1, 'group': 'g2', 'sha256': 'b' * 64, 'file': 'private.jpg'},
    ], 'support': {'train': {'0': {'samples': 1}}, 'holdout': {'1': {'samples': 1}}},
       'protected_population_support': {'consumed-r4': {'1': {'samples': 1}}}}
    child = child_draft_manifest(parent, 'parent-1')
    assert child['parent_version_id'] == 'parent-1'
    assert child['parent_version_digest'] == parent['digest']
    assert child['samples'] == parent['samples']
    assert 'support' not in child and 'protected_population_support' not in child


def _well_supported_parent():
    samples = []
    verified = {}
    for label in range(5):
        for split, count in (('train', 2), ('validation', 1), ('holdout', 50)):
            for index in range(count):
                sample_id = f'{split}-{label}-{index}'
                raw = sha256(sample_id.encode()).hexdigest()
                member = f'member/{sample_id}.jpg'
                row = {'id': sample_id, 'label': label, 'split': split,
                       'group': f'group-{sample_id}', 'sha256': raw,
                       'pixel_sha256': sha256((sample_id + '-pixel').encode()).hexdigest(),
                       'source_member': member}
                if split == 'holdout':
                    row['holdout_population'] = 'consumed-r4'
                samples.append(row)
                verified[member] = raw
    return {'scope': 'real-rights-cleared', 'classes': [str(i) for i in range(5)],
            'samples': samples}, verified


def test_annotated_child_allows_only_reviewed_train_or_pool_label_edits():
    parent, verified = _well_supported_parent()
    child = deepcopy(parent)
    sample = next(row for row in child['samples'] if row['id'] == 'train-0-0')
    sample['label'] = 1
    sample['annotation_digest'] = 'd' * 64
    proposal = {'sample': sample['id'], 'decision': 'approved', 'label': 1, 'digest': 'd' * 64}
    problems, _, _ = check_child(child, verified, parent, None, {sample['id']: proposal})
    assert not any('PARENT_MEMBER_CHANGED' in issue or 'PROTECTED_PARENT' in issue for issue in problems)
    assert not any('UNREVIEWED_PARENT_LABEL_CHANGE' in issue for issue in problems)

    unreviewed = deepcopy(child)
    problems, _, _ = check_child(unreviewed, verified, parent, None, {})
    assert any('UNREVIEWED_PARENT_LABEL_CHANGE' in issue for issue in problems)


def test_annotated_child_cannot_change_or_reseal_protected_members():
    parent, verified = _well_supported_parent()
    child = deepcopy(parent)
    protected = next(row for row in child['samples'] if row['id'] == 'holdout-0-0')
    protected['label'] = 1
    protected['holdout_population'] = 'new-unseen-tag'
    problems, _, _ = check_child(child, verified, parent, None, {})
    assert any('PROTECTED_PARENT_MEMBER_CHANGED' in issue for issue in problems)

