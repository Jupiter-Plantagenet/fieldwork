"""Signed-rights admission. Evidence/permissions come from persistence, never JSON.

An intake result or preflight is informational, not a capability. Consequential
callers must require() again; release/isolation/holdout gates remain independent.
"""
import threading
from collections import OrderedDict
from hashlib import sha256
from .rights_decision import DecisionRejected, ExpectedFacts, PURPOSES, verify_decision


def require_bundle_rights(manifest, *, service=None, workspace=None, dataset=None, actor=None):
    """Pre-write build boundary. Existing trusted synthetic path stays internal-only.

    Scope is NOT an acquisition proof. The fixture path is not exposed as a real
    upload route; no real-image execution is enabled by this compatibility case.
    """
    if manifest.get('scope') == 'synthetic-execution-only':
        return
    if service is None or not all((workspace, dataset, actor)):
        raise DecisionRejected('MISSING_TRUST_CONTEXT')
    service.require(workspace, dataset, actor, 'model_bundle')
    # Rights do not supply sandbox/decoder/quality/holdout admission.
    raise DecisionRejected('NATURAL_IMAGE_EXECUTION_NOT_ENABLED')


_VERIFIED = OrderedDict()
_VERIFIED_LOCK = threading.Lock()
_VERIFIED_LIMIT = 50000


def _registry_fingerprint(registry):
    return tuple(sorted((key, r.public_key_hex, tuple(sorted(r.workspace_ids)), tuple(sorted(r.purposes)))
                        for key, r in registry.items()))


def _verify_memo(raw, registry, expected):
    """verify_decision() is a pure function of (envelope bytes, trusted registry contents, expected facts): it reads
    no clock and no database. Memoize successful results on exactly those inputs. Every require() still re-reads the
    persisted envelope/evidence and reloads the registry file, so a removed key, an edited or replaced decision, or
    changed evidence produces a different key and is verified from scratch; rejections are never memoized."""
    try:
        key = (sha256(raw).hexdigest() if type(raw) is bytes else None, _registry_fingerprint(registry), expected)
        hash(key)
    except Exception:
        return verify_decision(raw, registry=registry, expected=expected)
    with _VERIFIED_LOCK:
        hit = _VERIFIED.get(key)
        if hit is not None:
            _VERIFIED.move_to_end(key)
            return hit
    result = verify_decision(raw, registry=registry, expected=expected)
    with _VERIFIED_LOCK:
        _VERIFIED[key] = result
        if len(_VERIFIED) > _VERIFIED_LIMIT:
            _VERIFIED.popitem(last=False)
    return result


class RightsService:
    MAX_EXPLICIT_MEMBERS = 10000

    def __init__(self, store, registry_provider):
        self.store = store
        self.registry_provider = registry_provider

    def _authorize(self, repo, workspace, actor, purpose):
        if purpose not in PURPOSES:
            raise DecisionRejected('FORMAT')
        if not repo.authorize(workspace, actor, purpose):
            raise DecisionRejected('WORKSPACE_PERMISSION')

    def _verify(self, repo, workspace, dataset, member, purpose, raw, *, asset_row=None, registry=None):
        row = asset_row if asset_row is not None else repo.asset(workspace, dataset, member)
        if not row or row['rights_state'] != 'reviewed':
            raise DecisionRejected('RIGHTS_QUARANTINED')
        docs = {}
        for column in ('canonical_license', 'license_text', 'source_evidence', 'attribution'):
            if column + '_sha256' in row:  # hashed by the database (bulk path): same digest, no blob transfer
                digest, size = row[column + '_sha256'], row[column + '_bytes']
                if type(digest) is not str or len(digest) != 64 or type(size) is not int or size < 1:
                    raise DecisionRejected('MISSING_EVIDENCE')
                docs[column + '_sha256'] = digest
                continue
            value = row[column]
            if not isinstance(value, (bytes, memoryview)) or not value:
                raise DecisionRejected('MISSING_EVIDENCE')
            docs[column + '_sha256'] = sha256(value).hexdigest()
        expected = ExpectedFacts(member_id=member, asset_sha256=row['asset_sha256'],
            asset_bytes=row['asset_bytes'], dataset_id=dataset, workspace_id=workspace,
            purpose=purpose, **docs)
        if registry is None:
            registry = self._registry()
        return _verify_memo(raw, registry, expected)

    def _registry(self):
        try:
            return self.registry_provider()
        except Exception:
            raise DecisionRejected('TRUST_REGISTRY') from None

    def intake(self, workspace, dataset, member, actor, purpose, raw):
        with self.store.rights_repository() as repo:
            self._authorize(repo, workspace, actor, purpose)
            # Unknown inventory never becomes an acquisition row via an envelope.
            if not repo.asset(workspace, dataset, member):
                raise DecisionRejected('RIGHTS_QUARANTINED')
            try:
                verified = self._verify(repo, workspace, dataset, member, purpose, raw)
                code = 'VERIFIED'
            except DecisionRejected as exc:
                code = exc.code
                verified = None
            # Persist bounded transport only; no "allow" flag trusted at future use.
            from .rights_decision import MAX_ENVELOPE_BYTES
            if type(raw) is bytes and 0 < len(raw) <= MAX_ENVELOPE_BYTES:
                repo.save(workspace, dataset, member, purpose, raw, code)
            else:
                # Oversized/empty replacement must not leave an earlier allow active.
                repo.save(workspace, dataset, member, purpose, b'', code)
            return {'status': 'verified' if verified else 'quarantined', 'code': code,
                    'use_permitted': False}

    def require(self, workspace, dataset, actor, purpose):
        with self.store.rights_repository() as repo:
            self._authorize(repo, workspace, actor, purpose)
            members = repo.members(workspace, dataset)
            if not members:
                raise DecisionRejected('RIGHTS_QUARANTINED')
            # One snapshot read of every asset + decision, then the same per-member checks and signature
            # verification in member order; the trust registry is loaded once per call. Nothing is cached
            # across calls, so a revoked or edited decision still takes effect on the next require().
            bulk = repo.assets_with_decisions(workspace, dataset, purpose)
            registry = None
            results = []
            for member in members:
                row, raw = bulk.get(member, (None, None))
                if raw is None:
                    raise DecisionRejected('MISSING_DECISION')
                if row is None:
                    raise DecisionRejected('RIGHTS_QUARANTINED')
                if registry is None:  # same error precedence as before: decision presence first
                    registry = self._registry()
                results.append(self._verify(repo, workspace, dataset, member, purpose, raw, asset_row=row,
                                            registry=registry))
            return results

    def require_members(self, workspace, dataset, actor, purpose, member_ids):
        """Verify only an explicit bounded member set without enumerating inventory IDs."""
        if type(member_ids) not in (list, tuple) or not member_ids or len(member_ids) > self.MAX_EXPLICIT_MEMBERS:
            raise DecisionRejected('RIGHTS_MEMBER_SCOPE')
        if any(type(member) is not str or not 1 <= len(member) <= 512
               or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in member)
               for member in member_ids):
            raise DecisionRejected('FORMAT')
        if len(set(member_ids)) != len(member_ids):
            raise DecisionRejected('DUPLICATE_RIGHTS_MEMBER')
        with self.store.rights_repository() as repo:
            self._authorize(repo, workspace, actor, purpose)
            repo.authenticated_inventory(workspace, dataset)
            results = []
            for member in member_ids:
                row = repo.asset(workspace, dataset, member)
                if not row or row.get('member_id') != member or row.get('rights_state') != 'reviewed':
                    raise DecisionRejected('RIGHTS_QUARANTINED')
                raw = repo.decision(workspace, dataset, member, purpose)
                if raw is None:
                    raise DecisionRejected('MISSING_DECISION')
                results.append(self._verify(repo, workspace, dataset, member, purpose, raw, asset_row=row))
            return results

    def require_real_inference_members(self, workspace, dataset, actor, member_id,
                                       asset_sha256, asset_bytes):
        """Read-only admission for one input bound to current registered rights.

        Reviewers may use an already authorized model on registered input. The
        signed training and bundle decisions are checked independently; this does
        not grant training, rights-intake, or export authority.
        """
        with self.store.rights_repository() as repo:
            if not repo.authorize(workspace, actor, 'read_only_real_inference'):
                raise DecisionRejected('WORKSPACE_PERMISSION')
            repo.authenticated_inventory(workspace, dataset)
            row = repo.asset(workspace, dataset, member_id)
            if (not row or row.get('member_id') != member_id or row.get('rights_state') != 'reviewed'
                    or row.get('asset_sha256') != asset_sha256
                    or asset_bytes is not None and row.get('asset_bytes') != asset_bytes):
                raise DecisionRejected('RIGHTS_ASSET_MISMATCH')
            verified = []
            for purpose in ('local_private_training', 'model_bundle'):
                raw = repo.decision(workspace, dataset, member_id, purpose)
                if raw is None:
                    raise DecisionRejected('MISSING_DECISION')
                verified.append(self._verify(repo, workspace, dataset, member_id, purpose, raw,
                                             asset_row=row))
            return verified
