"""Assemble the real-data candidate export (weights + rights/attribution), rights-gated.

Usage: python -B tools/candidate_export.py --tag cfg1
"""
import argparse
import hashlib
import json

from round4_common import DS, EVIDENCE, MANIFESTS, STEWARD_LABEL, admin_dsn, context, request_store, set_registry_env, write_json
from fieldwork.data import canonical
from fieldwork.export_rights import attach
from fieldwork.rights import RightsService
from fieldwork.rights_registry import load_trusted_registry
from fieldwork.store import Store


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tag', required=True)
    a = ap.parse_args()
    ctx = context()
    ws = ctx['workspace_id']
    set_registry_env()
    with Store(dsn=admin_dsn()).connect() as c:
        manifest = c.execute("SELECT manifest FROM fw_versions WHERE workspace=%s AND state='frozen' AND manifest->>'scope'='real-rights-cleared'", (ws,)).fetchone()['manifest']
    cand = DS / 'candidates' / a.tag
    service = RightsService(request_store(ws), load_trusted_registry)
    review = attach(cand, service=service, workspace=ws, dataset=manifest['rights_dataset_id'], actor=ctx['actors']['steward'],
                    version_manifest=manifest, rights_manifest=json.loads((MANIFESTS / 'rights-manifest.json').read_text(encoding='utf-8')),
                    license_raw=(MANIFESTS / 'LICENSE.txt').read_bytes(), steward_label=STEWARD_LABEL)
    files = {p.relative_to(cand).as_posix(): {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size}
             for p in sorted(cand.rglob('*')) if p.is_file() and p.name != 'manifest.json'}
    m = {'schema': 1, 'purpose': 'internal_candidate_real_data', 'dataset_digest': manifest['digest'], 'files': files,
         'images_included': False, 'qualified_release': False}
    (cand / 'manifest.json').write_bytes(canonical(m))
    # A reviewer-role account cannot pass the model_bundle rights check.
    try:
        attach(DS / 'candidates' / (a.tag + '-negative'), service=service, workspace=ws, dataset=manifest['rights_dataset_id'],
               actor=ctx['actors']['reviewer'], version_manifest=manifest, rights_manifest={'assets': []}, license_raw=b'', steward_label='')
        neg = 'UNEXPECTED_ALLOW'
    except Exception as exc:
        neg = getattr(exc, 'code', str(exc))
    out = {'tag': a.tag, 'review': review, 'manifest_sha256': hashlib.sha256(canonical(m)).hexdigest(), 'files': files,
           'reviewer_role_attempt': neg}
    write_json(EVIDENCE / 'rights' / f'export-{a.tag}.json', out)
    print(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
