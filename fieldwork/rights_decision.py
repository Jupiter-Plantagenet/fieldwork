"""Pure per-use signed decision verifier proposal; not legal certification/intake.

No I/O, key generation, signing or private-key interface. Trust is exclusively
caller-supplied. See CONTRACT.md before integrating. Never pass untrusted payload
facts as `expected` or construct the registry from an envelope.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from datetime import datetime
from collections.abc import Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA='fieldwork.rights-decision/v1'
DOMAIN=b'fieldwork.rights-decision/v1\x00'
MAX_ENVELOPE_BYTES=16384
PURPOSES=frozenset({'local_private_training','private_thumbnail_ui','model_bundle','image_export','public_commercial_portfolio'})

class DecisionRejected(ValueError):
    """Redacted, stable code only. No payload/key material in diagnostics."""
    def __init__(self,code):
        self.code=code
        super().__init__(code)

@dataclass(frozen=True,slots=True)
class TrustedReviewer:
    public_key_hex: str
    workspace_ids: frozenset[str]
    purposes: frozenset[str]

@dataclass(frozen=True,slots=True)
class ExpectedFacts:
    member_id: str
    asset_sha256: str
    asset_bytes: int
    canonical_license_sha256: str
    license_text_sha256: str
    source_evidence_sha256: str
    attribution_sha256: str
    dataset_id: str
    workspace_id: str
    purpose: str

@dataclass(frozen=True,slots=True)
class VerifiedDecision:
    member_id: str
    asset_sha256: str
    asset_bytes: int
    canonical_license_sha256: str
    license_text_sha256: str
    source_evidence_sha256: str
    attribution_sha256: str
    dataset_id: str
    workspace_id: str
    purpose: str
    reviewer_id: str
    key_id: str
    reviewed_utc: str
    decision_digest: str

_FACTS=tuple(ExpectedFacts.__dataclass_fields__)
_FIELDS=frozenset((*_FACTS,'schema','reviewer_id','key_id','reviewed_utc','decision'))
_UUID=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
_HASH_FIELDS=('asset_sha256','canonical_license_sha256','license_text_sha256','source_evidence_sha256','attribution_sha256')

def _token(value,pattern):
    if type(value) is not str or re.fullmatch(pattern,value) is None:
        raise DecisionRejected('FORMAT')

def _facts(facts):
    member=facts['member_id']
    if type(member) is not str or not 1<=len(member)<=512 or any(ord(c)<32 or 0xD800<=ord(c)<=0xDFFF for c in member):
        raise DecisionRejected('FORMAT')
    for name in _HASH_FIELDS:_token(facts[name],r'[0-9a-f]{64}')
    for name in ('dataset_id','workspace_id'):_token(facts[name],_UUID)
    if type(facts['asset_bytes']) is not int or not 1<=facts['asset_bytes']<=9223372036854775807:
        raise DecisionRejected('FORMAT')
    if type(facts['purpose']) is not str or facts['purpose'] not in PURPOSES:
        raise DecisionRejected('FORMAT')

def _payload(payload):
    if type(payload) is not dict or payload.keys()!=_FIELDS:
        raise DecisionRejected('FORMAT')
    if type(payload['schema']) is not str or payload['schema']!=SCHEMA:
        raise DecisionRejected('FORMAT')
    _facts(payload)
    for name in ('reviewer_id','key_id'):_token(payload[name],_UUID)
    _token(payload['reviewed_utc'],r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
    try:datetime.strptime(payload['reviewed_utc'],'%Y-%m-%dT%H:%M:%SZ')
    except ValueError:raise DecisionRejected('FORMAT') from None
    if type(payload['decision']) is not str or payload['decision'] not in {'allow','deny'}:
        raise DecisionRejected('FORMAT')

def canonical_payload(payload):
    """Validated v1 payload -> exact UTF-8; sorted keys, literal Unicode, no spaces.

    This is a closed flat integer/string profile, NOT a general JSON canonicalizer.
    No Unicode, case, whitespace, UUID or token normalization is performed.
    """
    _payload(payload)
    return json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')

def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise DecisionRejected('FORMAT')
        result[key]=value
    return result

def _no_number(value):
    raise DecisionRejected('FORMAT')

def _integer(value):
    if len(value)>19:raise DecisionRejected('FORMAT')
    return int(value)

def verify_decision(raw,*,registry,expected):
    """Verify one use against independent trusted context, or raise redacted code.

    Revalidate the registry on every call (removal revokes future verifications).
    Metadata is not a reusable admission token: caller must recheck at actual use.
    """
    if type(raw) is not bytes or not 0<len(raw)<=MAX_ENVELOPE_BYTES:
        raise DecisionRejected('ENVELOPE_BOUNDS')
    if not isinstance(registry,Mapping) or type(expected) is not ExpectedFacts:
        raise DecisionRejected('MISSING_TRUST_CONTEXT')
    facts={name:getattr(expected,name) for name in _FACTS}
    _facts(facts)
    try:
        envelope=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_float=_no_number,parse_constant=_no_number,parse_int=_integer)
        if type(envelope) is not dict or envelope.keys()!={'payload','signature_hex'}:
            raise DecisionRejected('FORMAT')
        payload=envelope['payload']
        _payload(payload)
        # Every untrusted token is validated before lookup or hex decoding.
        _token(envelope['signature_hex'],r'[0-9a-f]{128}')
        try:reviewer=registry.get((payload['reviewer_id'],payload['key_id']))
        except Exception:raise DecisionRejected('TRUST_REGISTRY') from None
        if type(reviewer) is not TrustedReviewer:raise DecisionRejected('UNTRUSTED_REVIEWER')
        _token(reviewer.public_key_hex,r'[0-9a-f]{64}')
        if type(reviewer.workspace_ids) is not frozenset or type(reviewer.purposes) is not frozenset:
            raise DecisionRejected('TRUST_REGISTRY')
        for workspace in reviewer.workspace_ids:_token(workspace,_UUID)
        if any(type(p) is not str or p not in PURPOSES for p in reviewer.purposes):
            raise DecisionRejected('TRUST_REGISTRY')
        if payload['workspace_id'] not in reviewer.workspace_ids or payload['purpose'] not in reviewer.purposes:
            raise DecisionRejected('REVIEWER_SCOPE')
        signed=DOMAIN+canonical_payload(payload)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(reviewer.public_key_hex)).verify(bytes.fromhex(envelope['signature_hex']),signed)
        if payload['decision']!='allow':raise DecisionRejected('NOT_ALLOWED')
        if any(payload[name]!=facts[name] for name in _FACTS):
            raise DecisionRejected('CONTEXT_MISMATCH')
        return VerifiedDecision(**{k:payload[k] for k in VerifiedDecision.__dataclass_fields__ if k!='decision_digest'},decision_digest=hashlib.sha256(signed).hexdigest())
    except DecisionRejected:raise
    except InvalidSignature:raise DecisionRejected('INVALID_SIGNATURE') from None
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
        raise DecisionRejected('FORMAT') from None
