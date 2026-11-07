"""Duplicate grouping, label-conflict quarantine and group-stratified splitting.

Group policy (blueprint section 4):
- raw-equal and normalized-pixel-equal content always link (intake records these
  as `duplicate` members linked to the sample that owns the content);
- the same Flickr photo identity under two members links (source identity);
- near-duplicate candidates: perceptual hash `phash-dct64/v1` Hamming <= 6. Every
  candidate edge is RESOLVED AS LINKED (conservative: never assumed independent);
- transitive connected components form groups; any group carrying more than one
  claimed label is quarantined (excluded from every split) with its reason.
Split: group-stratified 70/15/15, seed 42, classes in taxonomy order, groups
shuffled per class from a sorted base order, each assigned whole to the split with
the largest remaining deficit (tie: train, validation, holdout). Actual counts/IDs
are recorded; target counts are never manufactured.
"""
import random
from collections import defaultdict

import numpy as np
from PIL import Image, ImageOps

PHASH = 'phash-dct64/v1 (L, 32x32 bilinear, DCT-II, 8x8 low band, median of 63 AC)'
NEAR_DUP_MAX_HAMMING = 6
SPLIT_POLICY = {'targets': {'train': 0.70, 'validation': 0.15, 'holdout': 0.15}, 'seed': 42,
                'tie_order': ['train', 'validation', 'holdout'], 'unit': 'group', 'stratify': 'group label'}
_N = 32
_DCT = np.array([[np.cos(np.pi * (2 * x + 1) * u / (2 * _N)) for x in range(_N)] for u in range(_N)], dtype=np.float64)


def phash(path):
    with Image.open(path) as im:
        im = ImageOps.exif_transpose(im).convert('L').resize((_N, _N), Image.Resampling.BILINEAR)
        a = np.asarray(im, dtype=np.float64)
    d = _DCT @ a @ _DCT.T
    low = d[:8, :8].flatten()
    med = np.median(low[1:])
    bits = (low > med).astype(np.uint8)
    bits[0] = 0
    return int(''.join(map(str, bits.tolist())), 2)


def near_duplicate_edges(ids, hashes, max_distance=NEAR_DUP_MAX_HAMMING):
    h = np.array(hashes, dtype=np.uint64)
    edges = []
    for i in range(len(h)):
        d = np.bitwise_count(h[i + 1:] ^ h[i])
        for j in np.nonzero(d <= max_distance)[0].tolist():
            edges.append((ids[i], ids[i + 1 + j], int(d[j])))
    return edges


class _UF:
    def __init__(self, items):
        self.p = {x: x for x in items}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        a, b = self.find(a), self.find(b)
        if a != b:
            self.p[max(a, b)] = min(a, b)


def build_groups(samples, claims, edges):
    """samples: {sample_id: label}; claims: [(sample_id, claimed_label, member, why)];
    edges: [(a, b, kind, detail)]. Returns (groups, quarantined)."""
    uf = _UF(samples)
    for a, b, _, _ in edges:
        uf.union(a, b)
    members = defaultdict(list)
    for s in samples:
        members[uf.find(s)].append(s)
    labels = defaultdict(set)
    for s, lab in samples.items():
        labels[uf.find(s)].add(lab)
    claim_rows = defaultdict(list)
    for sid, lab, member, why in claims:
        labels[uf.find(sid)].add(lab)
        claim_rows[uf.find(sid)].append({'sample_id': sid, 'claimed_label': lab, 'member': member, 'claim': why})
    groups, quarantined = [], []
    for root, ms in members.items():
        ms = sorted(ms)
        g = {'group_id': 'G-' + ms[0], 'members': ms, 'labels': sorted(labels[root]), 'extra_claims': claim_rows[root]}
        if len(labels[root]) != 1:
            g['quarantine_reason'] = 'LABEL_CONFLICT: group carries labels ' + str(sorted(labels[root]))
            quarantined.append(g)
        else:
            g['label'] = next(iter(labels[root]))
            groups.append(g)
    groups.sort(key=lambda g: g['group_id'])
    quarantined.sort(key=lambda g: g['group_id'])
    return groups, quarantined


def assign_splits(groups, n_classes, policy=SPLIT_POLICY):
    rng = random.Random(policy['seed'])
    order = policy['tie_order']
    assignment = {}
    for label in range(n_classes):
        gs = [g for g in groups if g['label'] == label]
        gs.sort(key=lambda g: g['group_id'])
        rng.shuffle(gs)
        total = sum(len(g['members']) for g in gs)
        count = {k: 0 for k in order}
        for g in gs:
            deficit = {k: policy['targets'][k] * total - count[k] for k in order}
            best = max(order, key=lambda k: (deficit[k], -order.index(k)))
            assignment[g['group_id']] = best
            count[best] += len(g['members'])
    return assignment


def integrity(samples_by_split, groups, assignment, quarantined):
    """Zero cross-split sample/content/group overlap; quarantined never in a split."""
    problems = []
    seen = {}
    for split, rows in samples_by_split.items():
        for r in rows:
            for key in ('sample_id', 'raw_sha256', 'pixel_sha256', 'group_id'):
                k = (key, r[key])
                if k in seen and seen[k] != split:
                    problems.append(f'{key} {r[key]} in {seen[k]} and {split}')
                seen[k] = split
    q = {m for g in quarantined for m in g['members']}
    for split, rows in samples_by_split.items():
        for r in rows:
            if r['sample_id'] in q:
                problems.append(f'quarantined {r["sample_id"]} in {split}')
    for g in groups:
        splits = {s for s, rows in samples_by_split.items() for r in rows if r['group_id'] == g['group_id']}
        if len(splits) > 1:
            problems.append(f'group {g["group_id"]} spans {sorted(splits)}')
    return problems
