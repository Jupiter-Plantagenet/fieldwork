"""Round-4 milestone 2: persist rights facts and record AI-steward signed decisions.

Uses the application's real RightsService (request principal fieldwork_api, RLS
tenant, REPEATABLE READ repository, registry file reload, Ed25519 verifier).
"""
import collections
import hashlib
import json
import time
from round4_common import (DS, EVIDENCE, MANIFESTS, RESEARCH, RIGHTS_DIR, STEWARD_LABEL, admin_dsn, context,
                           request_store, set_registry_env, write_json)
import psycopg
from psycopg.rows import dict_row
from fieldwork.rights import RightsService
from fieldwork.rights_decision import DecisionRejected
from fieldwork.rights_registry import load_trusted_registry
from fieldwork.rights_operator import StewardSigner, asset_documents, persist_inventory

GRANTED = ['local_private_training', 'private_thumbnail_ui', 'model_bundle', 'image_export']
NOT_GRANTED = {'public_commercial_portfolio': 'Public/commercial publication is outside the user authorization (local completion only); no decision recorded.'}
ARCHIVE_URL = 'https://storage.googleapis.com/download.tensorflow.org/example_images/flower_photos.tgz'


def corroboration_map():
    out = {}
    for r in json.loads((RESEARCH / 'creator-corroboration-20261030-r196/records.json').read_text(encoding='utf-8'))['records']:
        out[r['member_literal']] = {'packet': 'r196', 'state': r['state'], 'license_uri': r.get('license_uri')}
    for r in json.loads((RESEARCH / 'creator-metadata-20261030-r127/REVIEW-CANDIDATES.json').read_text(encoding='utf-8'))['records']:
        out.setdefault(r['member'], {'packet': 'r127', 'state': r['disposition'], 'license_uri': (r.get('current_license_urls') or [None])[0]})
    return out


def accounts(ctx):
    import secrets
    with psycopg.connect(admin_dsn()) as c:
        for role, name in [('owner', ctx['actors']['steward']), ('researcher', ctx['actors']['researcher']), ('reviewer', ctx['actors']['reviewer'])]:
            salt = secrets.token_hex(16)
            hashed = hashlib.scrypt(secrets.token_bytes(32), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
            c.execute('INSERT INTO fw_accounts(name,salt,password_hash,workspace,role) VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING',
                      (name, salt, hashed, ctx['workspace_id'], role))


def with_retry(fn, counter):
    for attempt in range(6):
        try:
            return fn()
        except DecisionRejected as exc:
            if exc.code != 'RIGHTS_DATABASE_DEPENDENCY' or attempt == 5:
                raise
            counter['RIGHTS_DATABASE_DEPENDENCY'] += 1
            time.sleep(2 * (attempt + 1))


def main():
    retries = collections.Counter()
    ctx = context()
    ws = ctx['workspace_id']
    rights = json.loads((MANIFESTS / 'rights-manifest.json').read_text(encoding='utf-8'))
    acquisition_sha = hashlib.sha256((MANIFESTS / 'acquisition-manifest.json').read_bytes()).hexdigest()
    license_raw = (MANIFESTS / 'LICENSE.txt').read_bytes()
    legalcode = (RESEARCH / 'license-legalcode.raw').read_bytes()
    corr = corroboration_map()
    assets = rights['assets']
    eligible = [a for a in assets if a['rights_state'] == 'permissive_cc_by']
    docs = {a['member_id']: asset_documents(a, license_raw=license_raw, license_header=rights['license_header'],
                                            legalcode_raw=legalcode, archive_sha256=rights['archive_sha256'], archive_url=ARCHIVE_URL,
                                            license_sha256=rights['license_sha256'], corroboration=corr.get(a['member_id']))
            for a in eligible}
    accounts(ctx)
    with psycopg.connect(admin_dsn(), row_factory=dict_row) as c:
        # Full acquisition inventory (includes the 11 excluded members as `conflicting`).
        persist_inventory(c, ws, ctx['rights_dataset_full'], acquisition_sha, assets, docs)
    with psycopg.connect(admin_dsn(), row_factory=dict_row) as c:
        # Eligible-only inventory used by intake/training.
        persist_inventory(c, ws, ctx['rights_dataset_eligible'], acquisition_sha, eligible, docs)

    signer = StewardSigner(ctx['steward_reviewer_id'], ctx['steward_key_id'], [ws], GRANTED)
    registry_doc = {'schema': 1, 'reviewers': [signer.public_registry_entry()]}
    RIGHTS_DIR.mkdir(parents=True, exist_ok=True)
    (RIGHTS_DIR / 'reviewers.json').write_text(json.dumps(registry_doc, indent=1))
    write_json(RIGHTS_DIR / 'reviewer-identity.json', {'reviewer_id': signer.reviewer_id, 'key_id': signer.key_id,
               'public_key_hex': signer.public_key_hex, 'label': STEWARD_LABEL, 'private_key_retained': False,
               'purposes_signed': GRANTED, 'purposes_not_signed': NOT_GRANTED})
    set_registry_env()
    store = request_store(ws)
    service = RightsService(store, load_trusted_registry)
    actor = ctx['actors']['steward']
    results = collections.Counter()
    t0 = time.monotonic()
    for purpose in GRANTED:
        with (RIGHTS_DIR / f'decisions-{purpose}.jsonl').open('w', encoding='utf-8') as out:
            for a in eligible:
                # Full-acquisition inventory is signed for model_bundle only, to show that
                # quarantined members still block it even when every eligible member is signed.
                for dataset in (ctx['rights_dataset_eligible'],) + ((ctx['rights_dataset_full'],) if purpose == 'model_bundle' else ()):
                    raw = signer.sign(member_id=a['member_id'], asset_sha256=a['asset_sha256'], asset_bytes=a['asset_bytes'],
                                      documents=docs[a['member_id']], dataset_id=dataset, workspace_id=ws, purpose=purpose)
                    r = with_retry(lambda: service.intake(ws, dataset, a['member_id'], actor, purpose, raw), retries)
                    results[(purpose, dataset == ctx['rights_dataset_eligible'], r['code'])] += 1
                    out.write(json.dumps({'dataset_id': dataset, 'member_id': a['member_id'], 'envelope': raw.decode()}) + '\n')
    signer.discard()
    elapsed = time.monotonic() - t0

    checks = {}
    for purpose in GRANTED + list(NOT_GRANTED):
        for label, dataset in (('eligible', ctx['rights_dataset_eligible']), ('full', ctx['rights_dataset_full'])):
            try:
                decisions = with_retry(lambda: service.require(ws, dataset, actor, purpose), retries)
                checks[f'{label}:{purpose}'] = {'status': 'verified', 'members': len(decisions),
                                                'unique_decision_digests': len({d.decision_digest for d in decisions})}
            except DecisionRejected as exc:
                checks[f'{label}:{purpose}'] = {'status': 'denied', 'code': exc.code}
    # Negative controls through the same service.
    neg = {}
    excluded = [a for a in assets if a['rights_state'] != 'permissive_cc_by']
    tamper_signer = StewardSigner(ctx['steward_reviewer_id'], ctx['steward_key_id'], [ws], GRANTED)  # NOT registered
    one = eligible[0]
    forged = tamper_signer.sign(member_id=one['member_id'], asset_sha256=one['asset_sha256'], asset_bytes=one['asset_bytes'],
                                documents=docs[one['member_id']], dataset_id=ctx['rights_dataset_full'], workspace_id=ws, purpose='public_commercial_portfolio')
    neg['unregistered_key_signature'] = service.intake(ws, ctx['rights_dataset_full'], one['member_id'], actor, 'public_commercial_portfolio', forged)
    ex = excluded[0]
    fake_docs = {k: b'x' for k in ('canonical_license', 'license_text', 'source_evidence', 'attribution')}
    neg['excluded_member_decision'] = {'member': ex['member_id'], **service.intake(
        ws, ctx['rights_dataset_full'], ex['member_id'], actor, 'public_commercial_portfolio',
        tamper_signer.sign(member_id=ex['member_id'], asset_sha256=ex['asset_sha256'], asset_bytes=ex['asset_bytes'], documents=fake_docs,
                           dataset_id=ctx['rights_dataset_full'], workspace_id=ws, purpose='public_commercial_portfolio'))}
    try:
        service.require(ws, ctx['rights_dataset_eligible'], ctx['actors']['reviewer'], 'model_bundle')
        neg['reviewer_role_model_bundle'] = 'UNEXPECTED_ALLOW'
    except DecisionRejected as exc:
        neg['reviewer_role_model_bundle'] = exc.code
    tamper_signer.discard()
    summary = {'workspace_id': ws, 'rights_dataset_full': ctx['rights_dataset_full'], 'rights_dataset_eligible': ctx['rights_dataset_eligible'],
               'acquisition_manifest_sha256': acquisition_sha, 'eligible_members': len(eligible), 'excluded_members': len(excluded),
               'excluded': [{'member_id': a['member_id'], 'reasons': a['exclusion_reasons']} for a in excluded],
               'steward': {'reviewer_id': ctx['steward_reviewer_id'], 'key_id': ctx['steward_key_id'], 'label': STEWARD_LABEL,
                           'private_key_retained': False},
               'purposes_signed': GRANTED, 'purposes_not_signed': NOT_GRANTED,
               'intake_results': {f'{p}|{"eligible" if e else "full"}|{code}': n for (p, e, code), n in sorted(results.items())},
               'intake_elapsed_s': round(elapsed, 1), 'transient_db_retries': dict(retries), 'require_checks': checks, 'negative_controls': neg,
               'service_path': 'fieldwork.rights.RightsService via Store(request=True) as fieldwork_api with RLS tenant on isolated DB'}
    write_json(EVIDENCE / 'rights/rights-workflow-summary.json', summary)
    import shutil
    shutil.copyfile(RIGHTS_DIR / 'reviewer-identity.json', EVIDENCE / 'rights/reviewer-identity.json')
    shutil.copyfile(RIGHTS_DIR / 'reviewers.json', EVIDENCE / 'rights/reviewers-public-registry.json')
    print(json.dumps({k: v for k, v in summary.items() if k != 'excluded'}, indent=1))


if __name__ == '__main__':
    main()
