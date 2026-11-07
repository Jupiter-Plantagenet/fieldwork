"""Real signed rights decisions for a leak world (tests/leak_world.py).

leak_world inserts placeholder decision envelopes (one byte), which is enough for the routes that refuse before
rights are verified. The real-scope submit route and the real bundle routes verify every Ed25519 envelope against
the trusted reviewer registry, so these helpers sign REAL `fieldwork.rights-decision/v1` envelopes over the exact
persisted facts (asset digest/bytes and the four evidence digests) with a freshly generated fixture key, and write
the matching public-key registry file read by `fieldwork.rights_registry.load_trusted_registry`.

The reviewer key is a fixture key (no human reviewer is claimed). The same key is assigned to the
*simulated AI steward* by the holdout leak test.
"""
import json, uuid
from dataclasses import asdict
from hashlib import sha256

EVIDENCE = {'canonical_license': b'\x01', 'license_text': b'\x02', 'source_evidence': b'\x03', 'attribution': b'\x04'}


class Signer:
    def __init__(self, registry_path):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.key = Ed25519PrivateKey.generate()
        self.reviewer_id, self.key_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.path = registry_path
        self.workspaces = []
        self.purposes = ['local_private_training', 'model_bundle']

    def write_registry(self):
        self.path.write_text(json.dumps({'schema': 1, 'reviewers': [{
            'reviewer_id': self.reviewer_id, 'key_id': self.key_id,
            'public_key_hex': self.key.public_key().public_bytes_raw().hex(),
            'workspace_ids': list(self.workspaces), 'purposes': list(self.purposes)}]}))

    def envelope(self, *, workspace, dataset, member, asset_sha256, asset_bytes, purpose):
        from fieldwork.rights_decision import DOMAIN, SCHEMA, ExpectedFacts, canonical_payload
        facts = ExpectedFacts(member_id=member, asset_sha256=asset_sha256, asset_bytes=asset_bytes,
                              canonical_license_sha256=sha256(EVIDENCE['canonical_license']).hexdigest(),
                              license_text_sha256=sha256(EVIDENCE['license_text']).hexdigest(),
                              source_evidence_sha256=sha256(EVIDENCE['source_evidence']).hexdigest(),
                              attribution_sha256=sha256(EVIDENCE['attribution']).hexdigest(),
                              dataset_id=dataset, workspace_id=workspace, purpose=purpose)
        payload = dict(asdict(facts), schema=SCHEMA, reviewer_id=self.reviewer_id, key_id=self.key_id,
                       reviewed_utc='2026-11-03T00:00:00Z', decision='allow')
        return json.dumps({'payload': payload,
                           'signature_hex': self.key.sign(DOMAIN + canonical_payload(payload)).hex()}).encode()

    def sign_world(self, chain, world):
        """Replace the placeholder envelopes of every inventory member with real signed allow decisions."""
        ws, dataset = world['workspace'], world['rights_dataset']
        if ws not in self.workspaces:
            self.workspaces.append(ws)
        self.write_registry()
        with chain.dba.connect() as c:
            rows = c.execute('''SELECT member_id,asset_sha256,asset_bytes FROM fw_rights_assets
                WHERE workspace=%s AND dataset_id=%s''', (ws, dataset)).fetchall()
            assert len(rows) == len(world['manifest']['samples'])
            for r in rows:
                for purpose in self.purposes:
                    raw = self.envelope(workspace=ws, dataset=dataset, member=r['member_id'],
                                        asset_sha256=r['asset_sha256'], asset_bytes=r['asset_bytes'], purpose=purpose)
                    c.execute('''INSERT INTO fw_rights_decisions(workspace,dataset_id,member_id,purpose,envelope,last_result)
                        VALUES(%s,%s,%s,%s,%s,'VERIFIED')
                        ON CONFLICT(workspace,dataset_id,member_id,purpose)
                        DO UPDATE SET envelope=excluded.envelope,last_result=excluded.last_result''',
                              (ws, dataset, r['member_id'], purpose, raw))
        return len(rows)
