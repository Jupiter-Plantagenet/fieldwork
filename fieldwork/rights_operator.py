"""Acquisition/rights OPERATOR side: persist independent facts and sign steward decisions.

This is deliberately separate from the request path (`rights.RightsService`), which
only verifies. The operator connection writes `fw_rights_datasets/assets`; the API
principal must never hold that authority (docs/SIGNED-RIGHTS.md).

Steward signing: the Ed25519 private key is generated in process memory, used, and
discarded. Only the PUBLIC key is written to the operator registry file. Decision
envelopes are retained so they can be re-submitted through the live HTTP route.
Every decision payload is produced from persisted facts, never from a request.
"""
import json
import uuid
from datetime import datetime, timezone
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .rights_decision import DOMAIN, SCHEMA, canonical_payload


def canonical_bytes(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def asset_documents(asset, *, license_raw, license_header, legalcode_raw, archive_sha256, archive_url, license_sha256, corroboration=None):
    """Exact per-member evidence bytes for fw_rights_assets.

    canonical_license: the exact LICENSE.txt header lines plus this member's exact
    row (substrings of the canonical file; full-file digest bound in source_evidence).
    license_text: the CC BY 2.0 legal code bytes as retrieved by prior research.
    """
    lines = license_raw.decode('utf-8').splitlines()
    row = lines[asset['license_line_number'] - 1]
    if row != asset['raw_record']:
        raise ValueError('LICENSE_ROW_MISMATCH')
    canonical_license = ('\n'.join(license_header) + '\n' + row + '\n').encode('utf-8')
    evidence = {
        'schema': 'fieldwork.rights-source-evidence/v1',
        'member_id': asset['member_id'], 'asset_sha256': asset['asset_sha256'], 'asset_bytes': asset['asset_bytes'],
        'archive_url': archive_url, 'archive_sha256': archive_sha256,
        'license_member': 'flower_photos/LICENSE.txt', 'license_file_sha256': license_sha256,
        'license_line_number': asset['license_line_number'], 'license_row': row,
        'license_id': asset['license_id'], 'license_url': asset['license_url'],
        'author_literal': asset['author'], 'source_url_literal': asset['source_url'], 'source_kind': asset['source_kind'],
        'prior_inventory_digest_match': asset['prior_inventory_digest_match'],
        'creator_page_corroboration': corroboration,
    }
    return {'canonical_license': canonical_license, 'license_text': legalcode_raw,
            'source_evidence': canonical_bytes(evidence), 'attribution': asset['attribution'].encode('utf-8')}


def persist_inventory(connection, workspace, dataset_id, acquisition_sha256, assets, documents):
    """Operator write of one authenticated inventory. `assets` includes excluded ones.

    Excluded/ambiguous members are persisted as `conflicting` (no evidence bytes) so
    the inventory is complete and `require()` over it denies; eligible ones are
    `reviewed` with all four evidence documents.
    """
    c = connection
    c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (workspace,))
    c.execute('INSERT INTO fw_rights_datasets(workspace,dataset_id,acquisition_sha256,member_count,state) VALUES(%s,%s,%s,%s,%s)',
              (workspace, dataset_id, acquisition_sha256, len(assets), 'pending'))
    for a in assets:
        if a['rights_state'] == 'permissive_cc_by':
            d = documents[a['member_id']]
            c.execute('''INSERT INTO fw_rights_assets(workspace,dataset_id,member_id,asset_sha256,asset_bytes,
                canonical_license,license_text,source_evidence,attribution,rights_state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'reviewed')''',
                      (workspace, dataset_id, a['member_id'], a['asset_sha256'], a['asset_bytes'],
                       d['canonical_license'], d['license_text'], d['source_evidence'], d['attribution']))
        else:
            c.execute('''INSERT INTO fw_rights_assets(workspace,dataset_id,member_id,asset_sha256,asset_bytes,rights_state)
                VALUES(%s,%s,%s,%s,%s,'conflicting')''', (workspace, dataset_id, a['member_id'], a['asset_sha256'], a['asset_bytes']))
    c.execute("UPDATE fw_rights_datasets SET state='authenticated' WHERE workspace=%s AND dataset_id=%s", (workspace, dataset_id))


class StewardSigner:
    """In-memory Ed25519 steward key. `public_registry_entry` is all that persists."""

    def __init__(self, reviewer_id, key_id, workspace_ids, purposes):
        self._key = Ed25519PrivateKey.generate()
        self.reviewer_id = reviewer_id
        self.key_id = key_id
        self.workspace_ids = sorted(workspace_ids)
        self.purposes = sorted(purposes)
        self.public_key_hex = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def public_registry_entry(self):
        return {'reviewer_id': self.reviewer_id, 'key_id': self.key_id, 'public_key_hex': self.public_key_hex,
                'workspace_ids': self.workspace_ids, 'purposes': self.purposes}

    def sign(self, *, member_id, asset_sha256, asset_bytes, documents, dataset_id, workspace_id, purpose, decision='allow', reviewed_utc=None):
        payload = {
            'schema': SCHEMA, 'member_id': member_id, 'asset_sha256': asset_sha256, 'asset_bytes': asset_bytes,
            'canonical_license_sha256': sha256(documents['canonical_license']).hexdigest(),
            'license_text_sha256': sha256(documents['license_text']).hexdigest(),
            'source_evidence_sha256': sha256(documents['source_evidence']).hexdigest(),
            'attribution_sha256': sha256(documents['attribution']).hexdigest(),
            'dataset_id': dataset_id, 'workspace_id': workspace_id, 'purpose': purpose,
            'reviewer_id': self.reviewer_id, 'key_id': self.key_id,
            'reviewed_utc': reviewed_utc or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'decision': decision,
        }
        signature = self._key.sign(DOMAIN + canonical_payload(payload)).hex()
        return json.dumps({'payload': payload, 'signature_hex': signature}, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def discard(self):
        self._key = None


def new_uuid():
    return str(uuid.uuid4())
