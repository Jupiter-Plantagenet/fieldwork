"""Shared fixtures for the leak/isolation matrices: a real frozen version with a protected holdout population.

Everything is written through the operator (DBA) connection of the throwaway chain database and read back through
the real API / real SQL capabilities. The frozen manifest has exactly the shape `dataset_versions`/
`protected_population` emit at freeze (support, protected_population_support, rights commitments, digest) and is
sealed with the real migration-017 helper, but it is inserted directly: the signed-rights freeze path itself is
covered by its own tests. Holdout members are SENTINELS so any leak of an id, digest, source name, group, path or
perceptual hash is detectable by substring search.
"""
import hashlib, json, secrets, uuid
from psycopg.types.json import Jsonb
from fieldwork.data import canonical, digest
from fieldwork.intake import TAXONOMY
from fieldwork.dataset_versions import support as manifest_support
from fieldwork.protected_population import population_members, population_support

SPLITS = (('train', 10), ('validation', 10), ('pool', 2), ('holdout', 10))
HOLDOUT_TAG = 'holdout-sealed-population-A'


def _hex():
    return secrets.token_hex(32)


def build_world(chain, ws, *, prefix):
    """Create rights rows, samples, accounts and one frozen real version for workspace `ws`."""
    dba = chain.dba
    rights_dataset = str(uuid.uuid4())
    members = []
    for split, count in SPLITS:
        for i in range(count):
            sid = str(uuid.uuid4())
            raw, pix = _hex(), _hex()
            label = i % 5
            members.append({
                'id': sid, 'label': label, 'split': split, 'group': f'{prefix}-grp-{split}-{i}-{secrets.token_hex(3)}',
                'file': f'{prefix}-media/{split}/{secrets.token_hex(6)}.jpg', 'sha256': raw, 'pixel_sha256': pix,
                'source_member': f'{prefix}-{split}-{secrets.token_hex(5)}.jpg', 'raw_bytes': 1000 + i,
                'rights_dataset_id': rights_dataset,
                'phash': {'algorithm': 'phash-dct64/v1', 'hex': secrets.token_hex(8), 'raw_sha256': raw,
                          'pixel_sha256': pix, 'decoder': 'fixture'},
                **({'holdout_population': HOLDOUT_TAG} if split == 'holdout' else {})})
    holdout = [m for m in members if m['split'] == 'holdout']
    train_val = [m for m in members if m['split'] in ('train', 'validation')]
    pool = [m for m in members if m['split'] == 'pool']
    vid = f'{prefix}-v-' + uuid.uuid4().hex[:12]
    manifest = {
        'schema': 1, 'scope': 'real-rights-cleared', 'dataset': 'accepted-real-intake',
        'intake_batch': str(uuid.uuid4()), 'rights_dataset_id': rights_dataset, 'rights_dataset_ids': [rights_dataset],
        'rights': 'fixture', 'classes': [t['name'] for t in TAXONOMY], 'taxonomy': TAXONOMY,
        'group_policy': {'id': 'fixture'},
        'group_audit': {'status': 'complete', 'audit_complete': True, 'missing_feature_samples': [],
                        'edges': [{'a': holdout[0]['id'], 'b': holdout[1]['id'], 'distance': 1}]},
        'split_policy': {'status': 'assigned'},
        'quarantine': [{'group': holdout[0]['group'], 'members': [holdout[0]['id']], 'reason': 'LABEL_CONFLICT',
                        'labels': [0, 1], 'source_claims': [holdout[0]['source_member']]}],
        'samples': sorted(members, key=lambda m: m['id'])}
    manifest.update(parent_digest='0' * 64, version_id=vid, review_digest='1' * 64,
                    support=manifest_support(manifest),
                    protected_population_support={HOLDOUT_TAG: population_support(manifest, HOLDOUT_TAG)},
                    rights_decision_digests_sha256=_hex(), rights_decision_commitments={rights_dataset: _hex()})
    manifest['digest'] = digest(canonical(manifest))
    pop_members, pop_digest = population_members(manifest, HOLDOUT_TAG)
    with dba.connect() as c:
        c.execute('''INSERT INTO fw_rights_datasets(workspace,dataset_id,acquisition_sha256,member_count,state)
            VALUES(%s,%s,%s,%s,'authenticated')''', (ws, rights_dataset, _hex(), len(members)))
        first_batch = uuid.uuid4()
        for m in members:
            c.execute('''INSERT INTO fw_rights_assets(workspace,dataset_id,member_id,asset_sha256,asset_bytes,
                canonical_license,license_text,source_evidence,attribution,rights_state)
                VALUES(%s,%s,%s,%s,%s,'\\x01','\\x02','\\x03','\\x04','reviewed')''',
                      (ws, rights_dataset, m['source_member'], m['sha256'], m['raw_bytes']))
            c.execute('''INSERT INTO fw_rights_decisions(workspace,dataset_id,member_id,purpose,envelope,last_result)
                VALUES(%s,%s,%s,'local_private_training','\\x0a','ok')''', (ws, rights_dataset, m['source_member']))
            c.execute('''INSERT INTO fw_samples(workspace,sample_id,raw_sha256,raw_bytes,pixel_sha256,width,height,format,
                decoder,media_path,source_member,source_label,rights_dataset_id,first_batch)
                VALUES(%s,%s,%s,%s,%s,64,64,'jpeg','fixture',%s,%s,%s,%s,%s)''',
                      (ws, m['id'], m['sha256'], m['raw_bytes'], m['pixel_sha256'], m['file'], m['source_member'],
                       m['label'], rights_dataset, first_batch))
        # A sample that shares a protected pixel digest but is NOT a manifest member (content-identity alias).
        alias_id = str(uuid.uuid4())
        c.execute('''INSERT INTO fw_samples(workspace,sample_id,raw_sha256,raw_bytes,pixel_sha256,width,height,format,
            decoder,media_path,source_member,source_label,rights_dataset_id,first_batch)
            VALUES(%s,%s,%s,1,%s,64,64,'jpeg','fixture','alias.jpg',%s,0,%s,%s)''',
                  (ws, alias_id, _hex(), holdout[2]['pixel_sha256'], f'{prefix}-alias.jpg', rights_dataset, first_batch))
        # A plain sample that is in no frozen version (ordinary, unprotected): rights absent -> a known 403.
        plain_id = str(uuid.uuid4())
        c.execute('''INSERT INTO fw_samples(workspace,sample_id,raw_sha256,raw_bytes,pixel_sha256,width,height,format,
            decoder,media_path,source_member,source_label,rights_dataset_id,first_batch)
            VALUES(%s,%s,%s,1,%s,64,64,'jpeg','fixture','plain.jpg',%s,0,%s,%s)''',
                  (ws, plain_id, _hex(), _hex(), f'{prefix}-plain.jpg', rights_dataset, first_batch))
        c.execute('''INSERT INTO fw_versions(workspace,id,author,parent_digest,state,revision,manifest,reviewed_digest,reviewer,review_reason)
            VALUES(%s,%s,'fixture-author',%s,'frozen',4,%s,%s,'fixture-reviewer','fixture review')''',
                  (ws, vid, manifest['parent_digest'], Jsonb(manifest), manifest['review_digest']))
        c.execute('SELECT public.fw_privacy_seal_version_members_v1(%s,%s)', (ws, vid))
    sentinels = set()
    for m in holdout:
        sentinels |= {m['id'], m['sha256'], m['pixel_sha256'], m['source_member'], m['group'], m['file'],
                      m['phash']['hex']}
    return {'workspace': ws, 'version_id': vid, 'manifest': manifest, 'rights_dataset': rights_dataset,
            'holdout': holdout, 'train_val': train_val, 'pool': pool, 'alias_id': alias_id, 'plain_id': plain_id,
            'population': pop_members, 'population_digest': pop_digest, 'sentinels': sentinels,
            'holdout_ids': {m['id'] for m in holdout}}
