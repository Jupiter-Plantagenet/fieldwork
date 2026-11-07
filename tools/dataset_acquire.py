"""Round-4 milestone 1: stage the downloaded tf_flowers archive and build manifests.

Run with: .venv/Scripts/python.exe -I -B tools/dataset_acquire.py
(the archive was downloaded separately with curl; provenance files sit beside it).
Writes canonical JSON to var/datasets/tf_flowers/manifests/ and an evidence copy to
evidence/ml/round4/tests/rights/.
"""
import collections
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fieldwork.acquisition import (LICENSE_HEADER_URL, attribution_line, parse_license,  # noqa: E402
                                   sha256_file, stage_tar)
from fieldwork.data import canonical, digest  # noqa: E402

DS = ROOT / 'var/datasets/tf_flowers'
EXTRACTED = DS / 'extracted'
OUT = DS / 'manifests'
EVIDENCE = ROOT / 'evidence/ml/round4/tests/rights'
RESEARCH = Path('C:/Users/user/portfolio-build/rights-research')
SOURCE_URL = 'https://storage.googleapis.com/download.tensorflow.org/example_images/flower_photos.tgz'
EXPECTED_ARCHIVE_SHA256 = '4c54ace7911aaffe13a365c34f650e71dd5bf1be0a58b464e5a7183e3e595d9c'
EXPECTED_ARCHIVE_BYTES = 228813984
EXPECTED_LICENSE_SHA256 = '701e91b9e9f46d1f9623fc793a00fd444fe2821f66b01f3a0ff4a73d82f49507'
CLASS_DIRS = ['daisy', 'dandelion', 'roses', 'sunflowers', 'tulips']

# Prior-research conflicts (rights-research/CANONICAL-VERIFICATION-ADDENDUM.md and
# creator-corroboration-20261030-r196/README.md). Excluded, never "repaired".
KNOWN_CONFLICTS = {
    'daisy/11439894966_dca877f0cd.jpg': 'LICENSE_CONFLICT_BY_SA: Microsoft-preserved LICENSE copy and creator page say BY-SA 2.0; canonical row says CC-BY',
    'tulips/12949131454_4d3392f4dd_n.jpg': 'LICENSE_CONFLICT_BY_SA: creator page (r196 source 18) currently asserts BY-SA 2.0; canonical row says CC-BY',
}


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical(obj)
    path.write_bytes(data)
    return digest(data)


def main():
    archive = DS / 'archive/flower_photos.tgz'
    a_sha, a_bytes = sha256_file(archive)
    if a_sha != EXPECTED_ARCHIVE_SHA256 or a_bytes != EXPECTED_ARCHIVE_BYTES:
        raise SystemExit(f'ARCHIVE_DIGEST_MISMATCH {a_sha} {a_bytes}')
    prov = DS / 'provenance'
    headers = (prov / 'response-headers.txt').read_text(encoding='utf-8', errors='replace')
    writeout = (prov / 'curl-writeout.txt').read_text().split()
    if EXTRACTED.exists():
        shutil.rmtree(EXTRACTED)
    inventory = stage_tar(archive, EXTRACTED)
    staged = {m['path']: m for m in inventory['members'] if m['disposition'] == 'staged'}
    lic_path = 'flower_photos/LICENSE.txt'
    lic_raw = (EXTRACTED / lic_path).read_bytes()
    lic_sha = digest(lic_raw)
    if lic_sha != EXPECTED_LICENSE_SHA256:
        raise SystemExit('LICENSE_DIGEST_MISMATCH ' + lic_sha)
    parsed = parse_license(lic_raw)
    prior = {r['member']: r for r in json.loads((RESEARCH / 'canonical-rights-inventory.json').read_text(encoding='utf-8'))['records']}

    acquisition = {
        'schema': 'fieldwork.acquisition/v1', 'dataset': 'tf_flowers (TensorFlow flower_photos)',
        'source_url': SOURCE_URL, 'final_url': writeout[0], 'http_status': int(writeout[1]),
        'redirects': int(writeout[3]),
        'retrieval_started_utc': (prov / 'retrieval_started_utc.txt').read_text().strip(),
        'retrieval_finished_utc': (prov / 'retrieval_finished_utc.txt').read_text().strip(),
        'response_headers_raw': headers,
        'archive_sha256': a_sha, 'archive_bytes': a_bytes,
        'expected_from_prior_research': {'sha256': EXPECTED_ARCHIVE_SHA256, 'bytes': EXPECTED_ARCHIVE_BYTES,
                                         'source': 'rights-research/CANONICAL-VERIFICATION-ADDENDUM.md + checksums.tsv'},
        'archive_digest_matches_prior_research': True,
        'extraction': {k: v for k, v in inventory.items() if k != 'members'},
        'members': inventory['members'],
        'license_member': lic_path, 'license_sha256': lic_sha, 'license_bytes': len(lic_raw),
    }
    disp = collections.Counter(m['disposition'] for m in inventory['members'])
    acquisition['member_dispositions'] = dict(disp)

    # Join every staged JPEG with exactly one LICENSE row.
    rows = collections.defaultdict(list)
    for r in parsed['records']:
        rows['flower_photos/' + r['member']].append(r)
    assets = []
    excluded = collections.Counter()
    for path, m in sorted(staged.items()):
        if path == lic_path:
            continue
        member = path.split('/', 1)[1]
        rec = {'member_id': member, 'archive_path': path, 'class_dir': member.split('/', 1)[0],
               'asset_sha256': m['sha256'], 'asset_bytes': m['size']}
        reasons = []
        if not path.lower().endswith('.jpg') or rec['class_dir'] not in CLASS_DIRS:
            reasons.append('NOT_A_CLASS_IMAGE')
        lr = rows.get(path, [])
        if len(lr) != 1:
            reasons.append('NO_UNIQUE_LICENSE_ROW' if not lr else 'DUPLICATE_LICENSE_ROWS')
        else:
            lr = lr[0]
            rec.update(license_label=lr['license_label'], license_line_number=lr['line_number'],
                       raw_record=lr['raw_record'], author=lr['author'], source_url=lr['source_url'],
                       source_kind=lr['source_kind'], license_url=LICENSE_HEADER_URL,
                       license_id='CC-BY-2.0', attribution=attribution_line(lr))
            if lr['license_label'] != 'CC-BY':
                reasons.append('NOT_CC_BY')
            if lr['source_kind'] != 'photo_page':
                reasons.append('AMBIGUOUS_SOURCE_PROFILE_ONLY: LICENSE row gives a photographer profile, not the specific photo page; work cannot be identified for attribution')
        if member in KNOWN_CONFLICTS:
            reasons.append(KNOWN_CONFLICTS[member])
        p = prior.get(member)
        if p is None:
            reasons.append('NOT_IN_PRIOR_RIGHTS_INVENTORY')
        elif p['asset_sha256'] != m['sha256'] or p['asset_bytes'] != m['size']:
            reasons.append('ASSET_DIGEST_DIFFERS_FROM_PRIOR_MEASUREMENT')
        rec['prior_inventory_digest_match'] = bool(p and p['asset_sha256'] == m['sha256'])
        rec['rights_state'] = 'excluded' if reasons else 'permissive_cc_by'
        rec['exclusion_reasons'] = reasons
        for reason in reasons:
            excluded[reason.split(':')[0]] += 1
        assets.append(rec)
    staged_members = {a['archive_path'] for a in assets}
    orphan_rows = [r['raw_record'] for r in parsed['records'] if 'flower_photos/' + r['member'] not in staged_members]

    eligible = [a for a in assets if a['rights_state'] == 'permissive_cc_by']
    rights = {
        'schema': 'fieldwork.rights-manifest/v1', 'archive_sha256': a_sha,
        'license_member': lic_path, 'license_sha256': lic_sha, 'license_header': parsed['header'],
        'license_header_url': LICENSE_HEADER_URL,
        'counts': {'jpeg_members': len(assets), 'license_rows': len(parsed['records']),
                   'unparsed_license_lines': len(parsed['unparsed']), 'orphan_license_rows': len(orphan_rows),
                   'eligible_cc_by': len(eligible), 'excluded': len(assets) - len(eligible),
                   'exclusion_reason_counts': dict(excluded),
                   'eligible_by_class': dict(collections.Counter(a['class_dir'] for a in eligible)),
                   'license_labels': dict(collections.Counter(a.get('license_label') for a in assets))},
        'unparsed_license_lines': parsed['unparsed'], 'orphan_license_rows': orphan_rows,
        'assets': assets,
        'notes': ['Author names, URLs and labels are literal LICENSE.txt values; nothing repaired.',
                  'The LICENSE header asserts CC BY 2.0 for all images; rows say CC-BY. Prior research (r196) '
                  'corroborated 16/20 sampled creator pages as BY 2.0, 3 HTTP 404, 1 BY-SA (excluded here).',
                  'This manifest records license facts; use clearances are separate signed decisions.'],
    }
    OUT.mkdir(parents=True, exist_ok=True)
    acq_digest = write(OUT / 'acquisition-manifest.json', acquisition)
    rights_digest = write(OUT / 'rights-manifest.json', rights)
    (OUT / 'LICENSE.txt').write_bytes(lic_raw)
    attribution = '\n'.join(['Attribution for tf_flowers images used by Fieldwork (CC BY 2.0, https://creativecommons.org/licenses/by/2.0/).',
                             'Source archive: ' + SOURCE_URL + ' sha256 ' + a_sha,
                             'Images were decoded, resized and cropped for model training. No endorsement by the photographers is implied.', ''] +
                            [a['attribution'] for a in eligible]) + '\n'
    (OUT / 'ATTRIBUTION.txt').write_bytes(attribution.encode('utf-8'))  # LF bytes; digest recorded below
    summary = {'acquisition_manifest_sha256': acq_digest, 'rights_manifest_sha256': rights_digest,
               'attribution_sha256': digest(attribution.encode('utf-8')),
               'archive_sha256': a_sha, 'license_sha256': lic_sha,
               'member_dispositions': dict(disp), 'counts': rights['counts']}
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for name in ['acquisition-manifest.json', 'rights-manifest.json', 'ATTRIBUTION.txt', 'LICENSE.txt']:
        shutil.copyfile(OUT / name, EVIDENCE / name)
    write(EVIDENCE / 'acquisition-summary.json', summary)
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
