"""Rights + attribution payload for a real-data model export (CC BY 2.0 obligations).

`attach` re-verifies signed `model_bundle` decisions for EVERY member whose pixels
trained or selected the model (train + validation; holdout members never enter a
researcher export), then writes:
  rights/ATTRIBUTION.txt  creator, source URL, license URL and modification notice per image
  rights/LICENSE.txt      the canonical tf_flowers LICENSE.txt bytes
  rights/review.json      purposes, steward identity label, decision digest commitment, counts
No image bytes are included in the export. The independent qualified-release gate
is NOT opened by this; it only satisfies the rights/attribution precondition.
"""
import hashlib
import json
from pathlib import Path

from .data import canonical


def attach(out, *, service, workspace, dataset, actor, version_manifest, rights_manifest, license_raw, steward_label):
    out = Path(out)
    (out / 'rights').mkdir(parents=True, exist_ok=True)
    decisions = service.require(workspace, dataset, actor, 'model_bundle')
    verified = {d.member_id: d for d in decisions}
    used = [s for s in version_manifest['samples'] if s['split'] in ('train', 'validation')]
    missing = [s['source_member'] for s in used if s['source_member'] not in verified or verified[s['source_member']].asset_sha256 != s['sha256']]
    if missing:
        raise ValueError('MODEL_BUNDLE_RIGHTS_MISSING:%d' % len(missing))
    assets = {a['member_id']: a for a in rights_manifest['assets']}
    lines = ['Attribution for images used to train/select this model (tf_flowers, CC BY 2.0).',
             'License: Creative Commons Attribution 2.0 Generic, https://creativecommons.org/licenses/by/2.0/',
             'Changes: images were decoded, resized, cropped and used as training/validation inputs; this export contains model weights only and no images.',
             'No endorsement by any photographer is implied.', '']
    for s in sorted(used, key=lambda s: s['source_member']):
        lines.append(assets[s['source_member']]['attribution'])
    text = ('\n'.join(lines) + '\n').encode('utf-8')
    (out / 'rights/ATTRIBUTION.txt').write_bytes(text)
    (out / 'rights/LICENSE.txt').write_bytes(license_raw)
    review = {'schema': 'fieldwork.export-rights/v1', 'purpose_verified': 'model_bundle', 'members_credited': len(used),
              'decisions_verified': len(decisions), 'reviewer_label': steward_label,
              'decision_digests_sha256': hashlib.sha256(canonical(sorted(d.decision_digest for d in decisions))).hexdigest(),
              'attribution_sha256': hashlib.sha256(text).hexdigest(), 'license_sha256': hashlib.sha256(license_raw).hexdigest(),
              'images_included': False, 'holdout_members_included': False, 'share_alike_assets': 0,
              'qualified_release': 'not opened by rights; separate gate'}
    (out / 'rights/review.json').write_bytes(canonical(review))
    return review
