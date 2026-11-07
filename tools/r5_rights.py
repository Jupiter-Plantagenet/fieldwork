"""Round-5 milestone 2: per-asset Commons rights manifest + AI-steward signed decisions.

Real product path, as round 4: operator persists independent facts into
fw_rights_datasets/assets (new inventory `rights_dataset_commons`); a NEW in-memory
Ed25519 steward key signs `local_private_training` decisions (the platform's local
private ML-use purpose; the protected holdout is used only for one local evaluation);
every envelope goes through fieldwork.rights.RightsService.intake as fieldwork_api with
the RLS tenant set. Not signed: private_thumbnail_ui (protected holdout media is never
shown), model_bundle / image_export (holdout never enters an export),
public_commercial_portfolio (outside the user authorization).
"""
import collections
import hashlib
import json
import time
import urllib.request

import psycopg
from psycopg.rows import dict_row
from round5_common import (CANDIDATES, EVIDENCE, R4_RIGHTS, REGISTRY5, RIGHTS5, STEWARD_LABEL, USER_AGENT, admin_dsn, context,
                           request_store, set_registry_env, write_json)
from fieldwork.rights import RightsService
from fieldwork.rights_decision import DecisionRejected
from fieldwork.rights_operator import StewardSigner, canonical_bytes
from fieldwork.rights_registry import load_trusted_registry

GRANTED = ['local_private_training']
NOT_GRANTED = {'private_thumbnail_ui': 'Protected holdout media is never displayed to researchers.',
               'model_bundle': 'Holdout members never enter a model bundle or export.',
               'image_export': 'Holdout members never enter a model bundle or export.',
               'public_commercial_portfolio': 'Publication is outside the user authorization.'}
LABEL5 = STEWARD_LABEL.replace('AI steward', 'AI steward (round 5 key)')


def legalcode_url(row):
    u = row['license_url'].replace('http://', 'https://')
    if row['license_kind'] == 'cc0':
        return 'https://creativecommons.org/publicdomain/zero/1.0/legalcode'
    if row['license_kind'] == 'cc-by':
        return u.rstrip('/') + '/legalcode'
    return None


def fetch(url):
    for attempt in range(4):
        try:
            time.sleep(1.0)
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, r.geturl(), r.read(4 * 1024 * 1024)
        except OSError:
            time.sleep(5 * (attempt + 1))
    return None, None, None


def attribution(r):
    title = r['title'][len('File:'):]
    lic = r['license_short_name'] or r['license_id']
    url = f' ({r["license_url"]})' if r['license_url'] else ''
    return (f'"{title}" by {r["author"]}, {lic}{url}, via Wikimedia Commons: {r["file_page_url"]}. '
            f'Changes: Wikimedia thumbnail ({r["thumb_width"]} px wide) decoded, resized and centre-cropped for local evaluation.')


def main():
    ctx = context()
    ws = ctx['workspace_id']
    cand = json.loads((CANDIDATES / 'candidates.json').read_text(encoding='utf-8'))
    dl = json.loads((CANDIDATES / 'download-log.json').read_text(encoding='utf-8'))
    ok = {x['pageid']: x for x in dl['records'] if x['outcome'] == 'OK'}
    rows = [r for r in cand['rows'] if r.get('selected_for_download') and r['pageid'] in ok]
    # Legal code bytes per distinct licence.
    legal = {}
    (RIGHTS5 / 'legalcode').mkdir(parents=True, exist_ok=True)
    for u in sorted({legalcode_url(r) for r in rows} - {None}):
        status, final, body = fetch(u)
        rec = {'url': u, 'status': status, 'final_url': final}
        if status == 200 and body:
            rec['sha256'] = hashlib.sha256(body).hexdigest()
            rec['bytes'] = len(body)
            (RIGHTS5 / 'legalcode' / (rec['sha256'] + '.raw')).write_bytes(body)
            legal[u] = body
        idx_path = RIGHTS5 / 'legalcode' / 'index.json'
        idx = json.loads(idx_path.read_text()) if idx_path.exists() else {}
        idx[u] = rec
        write_json(idx_path, idx)
    assets, excluded = [], []
    for r in rows:
        x = ok[r['pageid']]
        member = f'commons_r5/{r["pageid"]}{x["ext"]}'
        reasons = []
        lu = legalcode_url(r)
        if lu is not None and lu not in legal:
            reasons.append('LEGALCODE_UNAVAILABLE')
        if r['license_kind'] == 'pd' and not r['usage_terms']:
            reasons.append('PD_STATEMENT_MISSING')
        a = {'member_id': member, 'asset_sha256': x['sha256'], 'asset_bytes': x['bytes'], 'pageid': r['pageid'], 'title': r['title'],
             'file_page_url': r['file_page_url'], 'author': r['author'], 'author_group': r['author_group'], 'uploader': r['uploader'],
             'license_kind': r['license_kind'], 'license_id': r['license_id'], 'license_short_name': r['license_short_name'],
             'license_url': r['license_url'], 'usage_terms': r['usage_terms'], 'attribution_required': r['attribution_required'],
             'original_url': r['original_url'], 'original_sha1': r['original_sha1'], 'thumb_url': r['thumb_url'],
             'thumb_final_url': x.get('final_url'), 'thumb_etag': x.get('etag'), 'flickr_ids': r['flickr_ids'],
             'category_class': r['category_class'], 'legalcode_url': lu,
             'legalcode_sha256': hashlib.sha256(legal[lu]).hexdigest() if lu in legal else None,
             'attribution': attribution(r), 'exclusion_reasons': reasons,
             'rights_state': 'permissive_cc_by' if not reasons else 'excluded'}  # state token consumed by the operator persist path
        (assets if not reasons else excluded).append(a)
    manifest = {'schema': 'fieldwork.commons-rights-manifest/v1', 'source': 'Wikimedia Commons API (imageinfo extmetadata)',
                'licence_policy': 'accept CC0, PD, CC BY (any version); exclude CC BY-SA, other, missing author/licence, NonFree, Restrictions',
                'crawl_finished_utc': cand['crawl_finished_utc'], 'download_archive_sha256': dl['archive_sha256'],
                'assets': sorted(assets + excluded, key=lambda a: a['member_id'])}
    write_json(RIGHTS5 / 'rights-manifest.json', manifest)
    attribution_txt = '\n'.join(a['attribution'] for a in sorted(assets, key=lambda a: a['member_id'])) + '\n'
    (RIGHTS5 / 'ATTRIBUTION-commons-r5.txt').write_text(attribution_txt, encoding='utf-8')
    acquisition_sha = hashlib.sha256(canonical_bytes({'candidates': hashlib.sha256((CANDIDATES / 'candidates.json').read_bytes()).hexdigest(),
                                                      'download_log': hashlib.sha256((CANDIDATES / 'download-log.json').read_bytes()).hexdigest()})).hexdigest()
    docs = {}
    for a in assets:
        lic_doc = {'license_kind': a['license_kind'], 'license_id': a['license_id'], 'license_short_name': a['license_short_name'],
                   'license_url': a['license_url'], 'usage_terms': a['usage_terms'], 'attribution_required': a['attribution_required']}
        docs[a['member_id']] = {
            'canonical_license': canonical_bytes(lic_doc),
            'license_text': legal[a['legalcode_url']] if a['legalcode_url'] else ('Public domain statement (Commons UsageTerms): ' + a['usage_terms']).encode('utf-8'),
            'source_evidence': canonical_bytes({'schema': 'fieldwork.commons-source-evidence/v1', **{k: a[k] for k in (
                'member_id', 'asset_sha256', 'asset_bytes', 'pageid', 'title', 'file_page_url', 'author', 'uploader', 'original_url',
                'original_sha1', 'thumb_url', 'thumb_final_url', 'thumb_etag', 'flickr_ids', 'legalcode_url', 'legalcode_sha256')},
                'acquisition_sha256': acquisition_sha}),
            'attribution': a['attribution'].encode('utf-8')}
    dataset = ctx['rights_dataset_commons']
    with psycopg.connect(admin_dsn(), row_factory=dict_row) as c:
        c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (ws,))
        if c.execute('SELECT 1 FROM fw_rights_datasets WHERE workspace=%s AND dataset_id=%s', (ws, dataset)).fetchone():
            raise SystemExit('COMMONS_INVENTORY_ALREADY_PERSISTED')
        c.execute('INSERT INTO fw_rights_datasets(workspace,dataset_id,acquisition_sha256,member_count,state) VALUES(%s,%s,%s,%s,%s)',
                  (ws, dataset, acquisition_sha, len(assets), 'pending'))
        for a in assets:
            d = docs[a['member_id']]
            c.execute('''INSERT INTO fw_rights_assets(workspace,dataset_id,member_id,asset_sha256,asset_bytes,canonical_license,license_text,
                source_evidence,attribution,rights_state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'reviewed')''',
                      (ws, dataset, a['member_id'], a['asset_sha256'], a['asset_bytes'], d['canonical_license'], d['license_text'],
                       d['source_evidence'], d['attribution']))
        c.execute("UPDATE fw_rights_datasets SET state='authenticated' WHERE workspace=%s AND dataset_id=%s", (ws, dataset))
    signer = StewardSigner(ctx['steward5_reviewer_id'], ctx['steward5_key_id'], [ws], GRANTED)
    old = json.loads((R4_RIGHTS / 'reviewers.json').read_text())
    REGISTRY5.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY5.write_text(json.dumps({'schema': 1, 'reviewers': old['reviewers'] + [signer.public_registry_entry()]}, indent=1))
    write_json(RIGHTS5 / 'reviewer-identity.json', {'reviewer_id': signer.reviewer_id, 'key_id': signer.key_id, 'public_key_hex': signer.public_key_hex,
               'label': LABEL5, 'private_key_retained': False, 'purposes_signed': GRANTED, 'purposes_not_signed': NOT_GRANTED,
               'registry_also_contains': 'round-4 public entry (so round-4 decisions keep verifying)'})
    set_registry_env()
    store = request_store(ws)
    service = RightsService(store, load_trusted_registry)
    actor = ctx['actors']['steward']
    results = collections.Counter()
    with (RIGHTS5 / 'decisions-local_private_training.jsonl').open('w', encoding='utf-8') as out:
        for a in assets:
            raw = signer.sign(member_id=a['member_id'], asset_sha256=a['asset_sha256'], asset_bytes=a['asset_bytes'], documents=docs[a['member_id']],
                              dataset_id=dataset, workspace_id=ws, purpose='local_private_training')
            r = service.intake(ws, dataset, a['member_id'], actor, 'local_private_training', raw)
            results[r['code']] += 1
            out.write(json.dumps({'dataset_id': dataset, 'member_id': a['member_id'], 'envelope': raw.decode()}) + '\n')
    signer.discard()
    checks = {}
    for p in GRANTED + list(NOT_GRANTED):
        try:
            ds = service.require(ws, dataset, actor, p)
            checks[p] = {'status': 'verified', 'members': len(ds), 'unique_decision_digests': len({d.decision_digest for d in ds})}
        except DecisionRejected as exc:
            checks[p] = {'status': 'denied', 'code': exc.code}
    try:
        old_ok = len(service.require(ws, ctx['rights_dataset_eligible'], actor, 'local_private_training'))
    except DecisionRejected as exc:
        old_ok = exc.code
    neg = {}
    rogue = StewardSigner(ctx['steward5_reviewer_id'], ctx['steward5_key_id'], [ws], GRANTED)   # NOT registered
    one = assets[0]
    neg['unregistered_key_for_unsigned_purpose'] = service.intake(ws, dataset, one['member_id'], actor, 'private_thumbnail_ui', rogue.sign(
        member_id=one['member_id'], asset_sha256=one['asset_sha256'], asset_bytes=one['asset_bytes'], documents=docs[one['member_id']],
        dataset_id=dataset, workspace_id=ws, purpose='private_thumbnail_ui'))
    rogue.discard()
    try:
        service.require(ws, dataset, ctx['actors']['reviewer'], 'local_private_training')
        neg['reviewer_role_require'] = 'UNEXPECTED_ALLOW'
    except DecisionRejected as exc:
        neg['reviewer_role_require'] = exc.code
    summary = {'workspace_id': ws, 'rights_dataset_commons': dataset, 'acquisition_sha256': acquisition_sha,
               'rights_manifest_sha256': hashlib.sha256((RIGHTS5 / 'rights-manifest.json').read_bytes()).hexdigest(),
               'attribution_sha256': hashlib.sha256(attribution_txt.encode('utf-8')).hexdigest(),
               'downloaded': len(rows), 'eligible_persisted': len(assets), 'excluded_after_download': len(excluded),
               'excluded_reasons': dict(collections.Counter(x for a in excluded for x in a['exclusion_reasons'])),
               'eligible_by_license_kind': dict(collections.Counter(a['license_kind'] for a in assets)),
               'eligible_by_license_id': dict(collections.Counter(a['license_id'] for a in assets)),
               'eligible_by_category_class': dict(collections.Counter(a['category_class'] for a in assets)),
               'legalcode_index': json.loads((RIGHTS5 / 'legalcode' / 'index.json').read_text()) if (RIGHTS5 / 'legalcode' / 'index.json').exists() else {},
               'steward': {'reviewer_id': ctx['steward5_reviewer_id'], 'key_id': ctx['steward5_key_id'], 'label': LABEL5, 'private_key_retained': False},
               'purposes_signed': GRANTED, 'purposes_not_signed': NOT_GRANTED, 'intake_results': dict(results), 'require_checks': checks,
               'round4_inventory_still_verifies_local_private_training': old_ok, 'negative_controls': neg,
               'service_path': 'fieldwork.rights.RightsService via Store(request=True) as fieldwork_api with RLS tenant on isolated DB'}
    write_json(EVIDENCE / 'rights/commons-rights-summary.json', summary)
    write_json(EVIDENCE / 'rights/reviewer-identity-r5.json', json.loads((RIGHTS5 / 'reviewer-identity.json').read_text()))
    print(json.dumps({k: v for k, v in summary.items() if k != 'legalcode_index'}, indent=1))


if __name__ == '__main__':
    main()
