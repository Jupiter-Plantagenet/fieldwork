"""Audited duplicate edges for new, unprotected intake drafts.

This module consumes server-recorded digests, source-member names, and pHash
features. It never opens media. The hash feature is produced by the fixed,
bounded intake decoder and bound to the accepted sample by migration 013.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

PHASH_ALGORITHM = 'phash-dct64/v1'
MAX_HAMMING = 6
MAX_CANDIDATE_EDGES = 100_000
GROUP_POLICY_ID = 'raw-pixel-source-phash-transitive/v1'
_HEX16 = re.compile(r'^[0-9a-f]{16}$')


class GroupingUnavailable(ValueError):
    """Required server-side feature data is absent or malformed."""


class _UnionFind:
    def __init__(self, items):
        self.parent = {item: item for item in items}

    def find(self, item):
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            nxt = self.parent[item]
            self.parent[item] = root
            item = nxt
        return root

    def union(self, left, right):
        a, b = self.find(left), self.find(right)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


def _photo_identity(source_member: str) -> str | None:
    """Use the existing numeric source-photo basename rule, case preserving."""
    leaf = source_member.replace('\\', '/').rsplit('/', 1)[-1]
    stem = leaf.rsplit('.', 1)[0]
    identity = stem.split('_', 1)[0]
    return identity if identity.isdecimal() else None


def _feature_hex(row: dict) -> str:
    feature = row.get('phash')
    if not isinstance(feature, dict) or feature.get('algorithm') != PHASH_ALGORITHM:
        raise GroupingUnavailable('GROUP_AUDIT_FEATURE_MISSING')
    value = feature.get('hex')
    if not isinstance(value, str) or not _HEX16.fullmatch(value):
        raise GroupingUnavailable('GROUP_AUDIT_FEATURE_INVALID')
    if feature.get('raw_sha256') != row.get('raw_sha256') or feature.get('pixel_sha256') != row.get('pixel_sha256'):
        raise GroupingUnavailable('GROUP_AUDIT_FEATURE_BINDING_MISMATCH')
    if not isinstance(feature.get('decoder'), str) or not feature['decoder']:
        raise GroupingUnavailable('GROUP_AUDIT_FEATURE_PROVENANCE_MISSING')
    return value


def group_new_samples(samples: list[dict], label_claims: list[dict] | None = None,
                      *, require_complete: bool = True) -> dict:
    """Build deterministic transitive groups and label-conflict quarantine.

    Complete audit mode requires the pHash feature produced by the accepted
    intake decoder. In incomplete mode, absent features are recorded and the
    caller must block split/freeze. ``label_claims`` are source claims linked to
    a member sample by server-owned intake duplicate records; the client cannot
    supply them. Returned edge records disclose only these new-draft members.
    """
    if not samples:
        raise GroupingUnavailable('EMPTY_ACCEPTED_INTAKE')
    ordered = sorted(samples, key=lambda row: str(row['id']))
    ids = [str(row['id']) for row in ordered]
    if len(ids) != len(set(ids)):
        raise GroupingUnavailable('DUPLICATE_SAMPLE_ID')
    by_id = {str(row['id']): row for row in ordered}
    hashes, missing_features = {}, []
    for sid, row in by_id.items():
        try:
            hashes[sid] = _feature_hex(row)
        except GroupingUnavailable as exc:
            if require_complete or str(exc) != 'GROUP_AUDIT_FEATURE_MISSING':
                raise
            missing_features.append(sid)
    edges: dict[tuple[str, str, str, str], dict] = {}

    def add(left, right, kind, detail=''):
        a, b = sorted((str(left), str(right)))
        if a == b:
            return
        key = (a, b, kind, str(detail))
        if key not in edges and len(edges) >= MAX_CANDIDATE_EDGES:
            raise GroupingUnavailable('GROUP_AUDIT_EDGE_LIMIT')
        edges[key] = {'a': a, 'b': b, 'kind': kind, 'detail': str(detail),
                      'decision': 'linked'}

    for field, kind in (('raw_sha256', 'raw_equal'), ('pixel_sha256', 'pixel_equal')):
        seen = {}
        for sid, row in by_id.items():
            value = row.get(field)
            if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
                raise GroupingUnavailable('GROUP_AUDIT_DIGEST_INVALID')
            if value in seen:
                add(seen[value], sid, kind, value)
            else:
                seen[value] = sid

    by_photo = defaultdict(list)
    for sid, row in by_id.items():
        identity = _photo_identity(row.get('source_member', ''))
        if identity is not None:
            by_photo[identity].append(sid)
    for identity, members in sorted(by_photo.items()):
        for sid in members[1:]:
            add(members[0], sid, 'same_source_photo_id', identity)

    # A BK-tree indexes the 64-bit Hamming metric without changing candidate
    # semantics. Query results are still checked against the exact <=6 cutoff.
    # Iterative traversal avoids recursion depth growth for dense hash buckets.
    root = None
    for sid in (sid for sid in ids if sid in hashes):
        value = int(hashes[sid], 16)
        if root is None:
            root = [value, sid, {}]
            continue
        stack = [root]
        while stack:
            node = stack.pop()
            distance = (value ^ node[0]).bit_count()
            if distance <= MAX_HAMMING:
                add(sid, node[1], 'phash_near_duplicate', distance)
            low, high = distance - MAX_HAMMING, distance + MAX_HAMMING
            stack.extend(child for edge, child in node[2].items() if low <= edge <= high)
        node = root
        while True:
            distance = (value ^ node[0]).bit_count()
            child = node[2].get(distance)
            if child is None:
                node[2][distance] = [value, sid, {}]
                break
            node = child

    claims = label_claims or []
    for claim in claims:
        sample_id = str(claim.get('sample_id', ''))
        label = claim.get('label')
        if sample_id not in by_id or type(label) is not int or label < 0:
            raise GroupingUnavailable('GROUP_AUDIT_CLAIM_INVALID')

    uf = _UnionFind(ids)
    edge_rows = sorted(edges.values(), key=lambda e: (e['a'], e['b'], e['kind'], e['detail']))
    for edge in edge_rows:
        uf.union(edge['a'], edge['b'])
    groups_by_root = defaultdict(list)
    for sid in ids:
        groups_by_root[uf.find(sid)].append(sid)
    labels_by_root = defaultdict(set)
    claims_by_root = defaultdict(list)
    for sid, row in by_id.items():
        label = row.get('label')
        if type(label) is int and label >= 0:
            labels_by_root[uf.find(sid)].add(label)
    for claim in claims:
        sid = str(claim['sample_id'])
        root = uf.find(sid)
        labels_by_root[root].add(claim['label'])
        claims_by_root[root].append({k: claim[k] for k in ('sample_id', 'label', 'source_member') if k in claim})

    membership = {}
    quarantined = []
    for root, members in sorted(groups_by_root.items()):
        members.sort()
        group_id = 'group-' + hashlib.sha256(('members:' + '\n'.join(members)).encode()).hexdigest()[:32]
        labels = sorted(labels_by_root[root])
        conflict = len(labels) > 1
        for sid in members:
            membership[sid] = {'group': group_id, 'quarantined': conflict}
        if conflict:
            quarantined.append({'group': group_id, 'members': members,
                                'reason': 'LABEL_CONFLICT', 'labels': labels,
                                'source_claims': sorted(claims_by_root[root], key=lambda x: (x.get('sample_id', ''), x.get('label', -1)))})
    return {'policy': {'id': GROUP_POLICY_ID, 'phash': PHASH_ALGORITHM,
                       'definition': 'EXIF-transposed grayscale before alpha composite; '
                                     'Pillow 32x32 bilinear; float64 DCT-II; first 8x8 '
                                     'coefficients; median of 63 AC values; row-major '
                                     'threshold bits with DC bit zero',
                       'max_hamming': MAX_HAMMING,
                       'max_candidate_edges': MAX_CANDIDATE_EDGES,
                       'edges': ['raw_equal', 'pixel_equal', 'same_source_photo_id', 'phash_near_duplicate'],
                       'transitive': True,
                       'candidate_resolution': 'link-all; quarantine label-conflicting components'},
            'membership': membership, 'edges': edge_rows, 'quarantine': quarantined,
            'audit_complete': not missing_features,
            'missing_feature_samples': missing_features}
