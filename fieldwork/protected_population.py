"""Child dataset version that adds a NEW, genuinely disjoint protected holdout population.

Blueprint section 4: "Subsequent dataset versions inherit sealed holdout and validation
groups"; "Further tuning after seeing results requires a new genuinely disjoint protected
plan/population; old holdout reports remain historical, never resealed."

Design: the child manifest keeps every parent sample with its parent split and group (the
consumed round-4 holdout stays in split `holdout`, tagged `holdout_population=<old tag>`,
never trained on and never re-used as unseen). New protected members also use split
`holdout` (so every existing holdout protection -- version view filtering, training-input
refusal, export exclusion -- applies to them unchanged) and carry
`holdout_population=<new tag>`. The protected plan locks ONLY the new tagged population.

Freeze requirements (in addition to `dataset_versions.check_real_manifest`, which this
calls with rights merged across inventories): signed `local_private_training` decisions
verified NOW for every member of EVERY rights inventory the version draws from; new
members only enter the new protected population; per-population support >= 50 samples
and >= 20 groups per class; zero cross-split / cross-population content or group overlap.
"""
import copy
import hashlib
import re

from psycopg.types.json import Jsonb

from .annotations import Rejection, locked, proposals, version_digest, view
from .data import canonical, digest
from .dataset_versions import (HOLDOUT_MIN_GROUPS, HOLDOUT_MIN_SAMPLES,
                               check_real_manifest, seal_frozen_privacy_members)


def population_members(manifest, tag):
    """Sorted protected population used by the holdout plan + its digest (steward side only)."""
    members = [{'id': s['id'], 'label': s['label'], 'sha256': s['sha256'], 'group': s['group']}
               for s in sorted(manifest['samples'], key=lambda s: s['id'])
               if s['split'] == 'holdout' and s.get('holdout_population') == tag]
    return members, hashlib.sha256(canonical(members)).hexdigest()


def population_support(manifest, tag):
    rows = [s for s in manifest['samples'] if s['split'] == 'holdout' and s.get('holdout_population') == tag]
    return {str(c): {'samples': sum(1 for s in rows if s['label'] == c), 'groups': len({s['group'] for s in rows if s['label'] == c})}
            for c in range(len(manifest['classes']))}


def population_content_identities(manifest, tag):
    """Private immutable content keys for one tagged protected population.

    Evaluation membership digests remain unchanged and continue binding labels,
    IDs and groups. This separate identity deliberately excludes those mutable
    review/row fields. Raw and normalized-pixel hashes are compared within their
    own namespaces; any shared member digest is enough to reject reuse.
    """
    raw, pixels, assets = set(), set(), set()
    for sample in manifest.get('samples', []):
        if sample.get('split') != 'holdout' or sample.get('holdout_population') != tag:
            continue
        raw_digest = sample.get('sha256')
        if isinstance(raw_digest, str) and re.fullmatch(r'[0-9a-f]{64}', raw_digest):
            raw.add(raw_digest)
        pixel_digest = sample.get('pixel_sha256')
        if isinstance(pixel_digest, str) and re.fullmatch(r'[0-9a-f]{64}', pixel_digest):
            pixels.add(pixel_digest)
        asset_id = sample.get('asset_identity') or sample.get('asset_id')
        if not asset_id and sample.get('source_member'):
            dataset_id = sample.get('rights_dataset_id', manifest.get('rights_dataset_id'))
            if dataset_id:
                asset_id = {'rights_dataset_id': dataset_id, 'source_member': sample['source_member']}
        if isinstance(asset_id, str) and asset_id:
            assets.add(hashlib.sha256(canonical({'asset_identity': asset_id})).hexdigest())
        elif isinstance(asset_id, dict) and asset_id:
            assets.add(hashlib.sha256(canonical({'asset_identity': asset_id})).hexdigest())
    return {'raw': frozenset(raw), 'pixels': frozenset(pixels), 'assets': frozenset(assets)}


def content_identity_overlap(left, right):
    """Whether two protected populations share any immutable content identity."""
    return any(left[k] & right[k] for k in ('raw', 'pixels', 'assets'))


class PopulationHistoryIncomplete(ValueError):
    pass


def overlaps_exposed_population(candidate_manifest, candidate_tag, exposures):
    """Match prior plan digests to frozen tagged sets, then compare content only.

    `exposures` contains DB manifests for plans with exposures or a consumed
    timestamp. Missing/unmatchable historical snapshots fail closed without
    disclosing their contents.
    """
    candidate = population_content_identities(candidate_manifest, candidate_tag)
    if not any(candidate.values()):
        raise PopulationHistoryIncomplete('PROTECTED_CONTENT_IDENTITY_UNAVAILABLE')
    for exposure in exposures:
        manifest = exposure.get('manifest')
        if not isinstance(manifest, dict) or exposure.get('state') != 'frozen':
            raise PopulationHistoryIncomplete('PROTECTED_HISTORY_SNAPSHOT_UNAVAILABLE')
        matched = False
        tags = {sample.get('holdout_population') for sample in manifest.get('samples', [])
                if sample.get('split') == 'holdout' and isinstance(sample.get('holdout_population'), str)}
        for prior_tag in tags:
            _, prior_digest = population_members(manifest, prior_tag)
            if prior_digest != exposure.get('population_digest'):
                continue
            matched = True
            prior = population_content_identities(manifest, prior_tag)
            if content_identity_overlap(candidate, prior):
                return True
        if not matched:
            raise PopulationHistoryIncomplete('PROTECTED_HISTORY_POPULATION_UNAVAILABLE')
    return False


def researcher_view(manifest):
    """Training/selection input: train + validation rows only, never protected rows."""
    return {'digest': manifest.get('digest'), 'version_id': manifest.get('version_id'),
            'samples': [dict(s) for s in manifest['samples'] if s['split'] in ('train', 'validation')]}


def check_child(manifest, verified, parent, new_tag, proposals_by_sample=None):
    problems, sup = check_real_manifest(manifest, verified, parent)
    parent_ids = {s['id']: s for s in parent['samples']}
    current_ids = [s['id'] for s in manifest['samples']]
    if len(current_ids) != len(set(current_ids)):
        problems.append('DUPLICATE_SAMPLE_ID')
    latest = proposals_by_sample or {}
    for s in manifest['samples']:
        p = parent_ids.get(s['id'])
        if p is None:
            if not new_tag or s['split'] != 'holdout' or s.get('holdout_population') != new_tag:
                problems.append('NEW_MEMBER_OUTSIDE_NEW_PROTECTED_POPULATION:' + s['id'])
            continue
        # Parent split, content identity, group and source are immutable. Labels
        # can change only through an approved train/pool proposal. Validation
        # and every protected holdout remain byte-for-byte membership snapshots.
        changed = {k for k in set(p) | set(s) if p.get(k) != s.get(k)}
        if p['split'] in ('validation', 'holdout'):
            # Older frozen manifests can predate the explicit population tag.
            # A child may add a historical tag once, but cannot retag an already
            # tagged population or assign the new unseen tag to a parent member.
            legacy_tag = ('holdout_population' in changed
                          and 'holdout_population' not in p
                          and s.get('holdout_population') is not None
                          and s.get('holdout_population') != new_tag)
            protected_changes = changed - ({'holdout_population'} if legacy_tag else set())
            if protected_changes:
                problems.append('PROTECTED_PARENT_MEMBER_CHANGED:' + s['id'])
        elif changed - {'label', 'annotation_digest'}:
            problems.append('PARENT_MEMBER_CHANGED:' + s['id'])
        elif changed & {'label', 'annotation_digest'}:
            proposal = latest.get(s['id'])
            if (proposal is None or proposal['decision'] != 'approved'
                    or s.get('label') != proposal['label']
                    or s.get('annotation_digest') != proposal['digest']):
                problems.append('UNREVIEWED_PARENT_LABEL_CHANGE:' + s['id'])
        if new_tag and s.get('holdout_population') == new_tag:
            problems.append('PARENT_MEMBER_RESEALED:' + s['id'])
    labels_by_group = {}
    for sample in manifest['samples']:
        if sample.get('label') is not None:
            labels_by_group.setdefault(sample['group'], set()).add(sample['label'])
    for group, labels in labels_by_group.items():
        if len(labels) > 1:
            problems.append('GROUP_LABEL_CONFLICT:' + group)
    missing = set(parent_ids) - set(current_ids)
    if missing:
        problems.append(f'PARENT_MEMBERS_DROPPED:{len(missing)}')
    if new_tag:
        new_groups = {s['group'] for s in manifest['samples'] if s.get('holdout_population') == new_tag}
        old_groups = {s['group'] for s in parent['samples']}
        if new_groups & old_groups:
            problems.append(f'NEW_POPULATION_SHARES_GROUPS_WITH_PARENT:{len(new_groups & old_groups)}')
        psup = population_support(manifest, new_tag)
        for c, v in psup.items():
            if v['samples'] < HOLDOUT_MIN_SAMPLES or v['groups'] < HOLDOUT_MIN_GROUPS:
                problems.append(f'NEW_POPULATION_SUPPORT class {c}: {v}')
    else:
        psup = {}
        if set(current_ids) != set(parent_ids):
            problems.append('ANNOTATION_CHILD_MEMBERSHIP_CHANGED')
    return problems, sup, psup


def _freeze_child(store, w, vid, revision, *, rights_service, actor, parent_manifest, new_tag):
    with store.connect() as c:
        v = locked(c, w, vid, revision)
        rows = proposals(c, w, vid)
        if v['state'] == 'frozen':
            return view(v, rows)
        if v['state'] != 'reviewed' or v['reviewed_digest'] != version_digest(v, rows):
            raise Rejection(422, 'EXACT_VERSION_REVIEW_REQUIRED')
        m = copy.deepcopy(v['manifest'])
        latest = {p['sample']: p for p in rows}
        for s in m['samples']:
            p = latest.get(s['id'])
            if p and p['decision'] == 'approved':
                s['label'] = p['label']
                s['annotation_digest'] = p['digest']
        verified, commitments = {}, {}
        dataset_ids = m.get('rights_dataset_ids') or [m.get('rights_dataset_id')]
        if not dataset_ids or any(not ds for ds in dataset_ids):
            raise Rejection(423, 'REAL_FREEZE_BLOCKED:RIGHTS_DATASET')
        m['rights_dataset_ids'] = dataset_ids
        for ds in dataset_ids:
            decisions = rights_service.require(w, ds, actor, 'local_private_training')
            for d in decisions:
                if d.member_id in verified:
                    raise Rejection(423, 'REAL_FREEZE_BLOCKED:MEMBER_ID_COLLISION')
                verified[d.member_id] = d.asset_sha256
            commitments[ds] = digest(canonical(sorted(d.decision_digest for d in decisions)))
        for s in m['samples']:
            if s.get('rights_dataset_id', m.get('rights_dataset_id')) not in m['rights_dataset_ids']:
                raise Rejection(423, 'REAL_FREEZE_BLOCKED:RIGHTS_DATASET')
        problems, sup, psup = check_child(m, verified, parent_manifest, new_tag, latest)
        if problems:
            raise Rejection(423, 'REAL_FREEZE_BLOCKED:' + ';'.join(problems[:5]))
        m.pop('digest')
        m.update(parent_digest=v['parent_digest'], version_id=vid, review_digest=v['reviewed_digest'], support=sup,
                 protected_population_support=({new_tag: psup} if new_tag else parent_manifest.get('protected_population_support', {})),
                 rights_decision_digests_sha256=digest(canonical(commitments)), rights_decision_commitments=commitments)
        m['digest'] = digest(canonical(m))
        c.execute("UPDATE fw_versions SET state='frozen',manifest=%s,revision=revision+1 WHERE workspace=%s AND id=%s", (Jsonb(m), w, vid))
        seal_frozen_privacy_members(c,w,vid)
        return view(locked(c, w, vid), rows)


def freeze_child(store, w, vid, revision, *, rights_service, actor, parent_manifest, new_tag):
    """Freeze a child that adds one genuinely new protected population."""
    if not new_tag:
        raise Rejection(422, 'NEW_PROTECTED_POPULATION_REQUIRED')
    return _freeze_child(store, w, vid, revision, rights_service=rights_service,
                         actor=actor, parent_manifest=parent_manifest, new_tag=new_tag)


def freeze_annotated_child(store, w, vid, revision, *, rights_service, actor, parent_manifest):
    """Freeze an annotation child with exact inherited protected membership.

    It carries the parent's protected population forward as history. It does not
    mint or label a new unseen holdout population.
    """
    return _freeze_child(store, w, vid, revision, rights_service=rights_service,
                         actor=actor, parent_manifest=parent_manifest, new_tag=None)
