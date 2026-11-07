"""Freeze for rights-cleared real-image dataset versions.

`annotations.freeze` deliberately refuses non-synthetic scopes (423). This is the
separate real-data freeze: it requires (1) the exact reviewed version digest, (2)
a current signed `local_private_training` decision for EVERY member, bound to the
exact asset digest, verified through RightsService at freeze time, (3) zero
cross-split sample/content/group overlap and no quarantined member in a split,
(4) candidate-only real versions may freeze with train/validation/pool and no
holdout; if a protected holdout exists it still requires >=50 samples and >=20
groups per class, and (5) inherited validation/holdout groups stay unchanged.
"""
import copy

from psycopg.types.json import Jsonb

from .annotations import Rejection, locked, proposals, version_digest, view
from .data import canonical, digest
from .splits import integrity

REAL_SCOPE = 'real-rights-cleared'
HOLDOUT_MIN_SAMPLES = 50
HOLDOUT_MIN_GROUPS = 20
SELECTION_MIN_GROUPS = 2


def seal_frozen_privacy_members(c, workspace, version_id):
    ready=c.execute("SELECT to_regprocedure('public.fw_privacy_seal_version_members_v1(text,text)') IS NOT NULL AS ready").fetchone()['ready']
    if not ready:raise Rejection(503,'PRIVACY_LIFECYCLE_SCHEMA_REQUIRED')
    c.execute('SELECT public.fw_privacy_seal_version_members_v1(%s,%s)',(workspace,version_id))


def support(manifest):
    out = {}
    for split in ('train', 'validation', 'holdout', 'pool'):
        rows = [s for s in manifest['samples'] if s['split'] == split]
        out[split] = {str(c): {'samples': sum(1 for s in rows if s['label'] == c),
                               'groups': len({s['group'] for s in rows if s['label'] == c})}
                      for c in range(len(manifest['classes']))}
    return out


def check_real_manifest(manifest, verified, parent=None):
    """verified: {member_id: asset_sha256} from RightsService.require()."""
    problems = []
    if manifest.get('scope') != REAL_SCOPE:
        problems.append('SCOPE')
    for s in manifest['samples']:
        if verified.get(s['source_member']) != s['sha256']:
            problems.append('RIGHTS:' + s['source_member'])
    by_split = {}
    for s in manifest['samples']:
        by_split.setdefault(s['split'], []).append({'sample_id': s['id'], 'raw_sha256': s['sha256'],
                                                    'pixel_sha256': s['pixel_sha256'], 'group_id': s['group']})
    groups = [{'group_id': g} for g in {s['group'] for s in manifest['samples']}]
    problems += integrity(by_split, groups, None, manifest.get('quarantine', []))
    sup = support(manifest)
    has_holdout = any(s['split'] == 'holdout' for s in manifest['samples'])
    if has_holdout:
        for c, v in sup['holdout'].items():
            if v['samples'] < HOLDOUT_MIN_SAMPLES or v['groups'] < HOLDOUT_MIN_GROUPS:
                problems.append(f'HOLDOUT_SUPPORT class {c}: {v}')
    else:
        # A no-holdout real freeze is only a train/validation candidate. Its
        # reviewed initial split plan is digest-bound and explicitly creates no
        # protected evaluation population.
        plan = manifest.get('split_policy') or {}
        planned_members = [{'id': s['id'], 'group': s['group'], 'split': s['split']}
                           for s in sorted(manifest['samples'], key=lambda s: s['id'])]
        if (plan.get('id') != 'group-stratified-candidate/v1'
                or plan.get('status') != 'assigned'
                or plan.get('purpose') != 'candidate-training-only'
                or plan.get('protected_holdout_created') is not False
                or plan.get('split_plan_digest') != digest(canonical(planned_members))):
            problems.append('REVIEWED_INITIAL_SPLIT_PLAN_REQUIRED')
        if any(s['split'] not in ('train', 'validation', 'pool')
               or 'holdout_population' in s or s.get('protected') is True for s in manifest['samples']):
            problems.append('CANDIDATE_SPLIT_SCOPE')
    for split in ('train', 'validation'):
        for c, v in sup[split].items():
            if v['samples'] == 0 or v['groups'] < SELECTION_MIN_GROUPS:
                problems.append(f'{split.upper()}_CLASS_GROUP_SUPPORT {c}')
    if parent is not None:
        old = {s['group']: s['split'] for s in parent['samples'] if s['split'] in ('validation', 'holdout')}
        for s in manifest['samples']:
            if s['group'] in old and s['split'] != old[s['group']]:
                problems.append('PROTECTED_GROUP_MIGRATED:' + s['group'])
        gone = set(old) - {s['group'] for s in manifest['samples']}
        if gone:
            problems.append(f'PROTECTED_GROUPS_DROPPED:{len(gone)}')
    return problems, sup


def freeze_real(store, w, vid, revision, *, rights_service, actor, parent_manifest=None):
    with store.connect() as c:
        v = locked(c, w, vid, revision)
        rows = proposals(c, w, vid)
        if v['state'] == 'frozen':
            return view(v, rows)
        if v['state'] != 'reviewed' or v['reviewed_digest'] != version_digest(v, rows):
            raise Rejection(422, 'EXACT_VERSION_REVIEW_REQUIRED')
        m = copy.deepcopy(v['manifest'])
        # Check the exact labels that will be frozen, including approved edits.
        # Checking the original manifest first could admit a post-review label
        # change that removes a class or introduces a conflicting duplicate group.
        latest = {p['sample']: p for p in rows}
        for s in m['samples']:
            p = latest.get(s['id'])
            if p and p['decision'] == 'approved':
                s['label'] = p['label']; s['annotation_digest'] = p['digest']
        decisions = rights_service.require(w, m['rights_dataset_id'], actor, 'local_private_training')
        verified = {d.member_id: d.asset_sha256 for d in decisions}
        problems, sup = check_real_manifest(m, verified, parent_manifest)
        if problems:
            raise Rejection(423, 'REAL_FREEZE_BLOCKED:' + ';'.join(problems[:5]))
        m.pop('digest')
        m.update(parent_digest=v['parent_digest'], version_id=vid, review_digest=v['reviewed_digest'], support=sup,
                 rights_decision_digests_sha256=digest(canonical(sorted(d.decision_digest for d in decisions))))
        m['digest'] = digest(canonical(m))
        c.execute("UPDATE fw_versions SET state='frozen',manifest=%s,revision=revision+1 WHERE workspace=%s AND id=%s", (Jsonb(m), w, vid))
        seal_frozen_privacy_members(c,w,vid)
        return view(locked(c, w, vid), rows)
