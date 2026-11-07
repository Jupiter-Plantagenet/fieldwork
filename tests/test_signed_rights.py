"""Light, NONPHOTO metadata only; ephemeral keys never leave process memory."""
import importlib.util
import json
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
import pytest

WORKSPACE='11111111-1111-1111-1111-111111111111'
DATASET='22222222-2222-2222-2222-222222222222'
REVIEWER='33333333-3333-3333-3333-333333333333'
KEY='44444444-4444-4444-4444-444444444444'
MEMBER='AUTHORED-NONPHOTO-TEST'


class MemoryRepository:
    """Independent unit-test persistence seam; NOT a PostgreSQL test."""
    def __init__(self):
        self.assets={MEMBER:dict(member_id=MEMBER,asset_sha256=sha256(b'NONPHOTO').hexdigest(),asset_bytes=8,canonical_license=b'NONPHOTO archive license',license_text=b'NONPHOTO governing license',source_evidence=b'NONPHOTO source evidence',attribution=b'NONPHOTO complete notices',rights_state='reviewed')}
        self.decisions={}
        self.role='researcher'
        self.inventory_state='authenticated'
        self.inventory_count=None

    @contextmanager
    def rights_repository(self):
        yield self

    def authorize(self,workspace,actor,purpose):
        return workspace==WORKSPACE and actor=='test-author' and self.role in ('owner','researcher')

    def asset(self,workspace,dataset,member):
        return self.assets.get(member) if workspace==WORKSPACE and dataset==DATASET else None

    def members(self,workspace,dataset):
        return sorted(self.assets) if workspace==WORKSPACE and dataset==DATASET else []

    def authenticated_inventory(self,workspace,dataset):
        from fieldwork.rights_decision import DecisionRejected
        if workspace!=WORKSPACE or dataset!=DATASET or self.inventory_state!='authenticated':
            raise DecisionRejected('RIGHTS_QUARANTINED')
        expected=len(self.assets) if self.inventory_count is None else self.inventory_count
        if expected!=len(self.assets):
            raise DecisionRejected('INCOMPLETE_INVENTORY')
        if expected<1:
            raise DecisionRejected('RIGHTS_QUARANTINED')
        return expected

    def decision(self,workspace,dataset,member,purpose):
        return self.decisions.get((member,purpose))

    def assets_with_decisions(self,workspace,dataset,purpose):
        if workspace!=WORKSPACE or dataset!=DATASET:
            return {}
        return {m:(dict(row),self.decisions.get((m,purpose))) for m,row in self.assets.items()}

    def save(self,workspace,dataset,member,purpose,raw,code):
        self.decisions[member,purpose]=raw


def fixture_context(purpose='local_private_training'):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fieldwork.rights_decision import DOMAIN,SCHEMA,ExpectedFacts,TrustedReviewer,canonical_payload
    repo=MemoryRepository(); row=repo.assets[MEMBER]
    facts=ExpectedFacts(member_id=MEMBER,asset_sha256=row['asset_sha256'],asset_bytes=row['asset_bytes'],canonical_license_sha256=sha256(row['canonical_license']).hexdigest(),license_text_sha256=sha256(row['license_text']).hexdigest(),source_evidence_sha256=sha256(row['source_evidence']).hexdigest(),attribution_sha256=sha256(row['attribution']).hexdigest(),dataset_id=DATASET,workspace_id=WORKSPACE,purpose=purpose)
    key=Ed25519PrivateKey.generate()
    registry={(REVIEWER,KEY):TrustedReviewer(key.public_key().public_bytes_raw().hex(),frozenset({WORKSPACE}),frozenset({purpose}))}
    def sign(**changes):
        payload=dict(asdict(facts),schema=SCHEMA,reviewer_id=REVIEWER,key_id=KEY,reviewed_utc='2026-10-30T00:00:00Z',decision='allow');payload.update(changes)
        return json.dumps(dict(payload=payload,signature_hex=key.sign(DOMAIN+canonical_payload(payload)).hex())).encode()
    return repo,registry,facts,sign


def test_intake_rechecks_persisted_evidence_at_actual_use():
    assert importlib.util.find_spec('fieldwork.rights') is not None
    from fieldwork.rights import RightsService
    from fieldwork.rights_decision import DecisionRejected
    repo,registry,facts,sign=fixture_context()
    service=RightsService(repo,lambda:registry)
    result=service.intake(WORKSPACE,DATASET,MEMBER,'test-author',facts.purpose,sign())
    assert result['status']=='verified' and result['use_permitted'] is False
    assert service.require(WORKSPACE,DATASET,'test-author',facts.purpose)[0].member_id==MEMBER
    repo.assets[MEMBER]['license_text']=b'changed independent license'
    with pytest.raises(DecisionRejected,match='CONTEXT_MISMATCH'):
        service.require(WORKSPACE,DATASET,'test-author',facts.purpose)


def test_require_members_checks_only_explicit_ids_without_inventory_enumeration():
    from fieldwork.rights import RightsService
    repo,registry,facts,sign=fixture_context()
    service=RightsService(repo,lambda:registry)
    service.intake(WORKSPACE,DATASET,MEMBER,'test-author',facts.purpose,sign())
    repo.members=lambda *args:pytest.fail('scoped verification must not enumerate inventory members')
    decisions=service.require_members(WORKSPACE,DATASET,'test-author',facts.purpose,[MEMBER])
    assert len(decisions)==1 and decisions[0].member_id==MEMBER


@pytest.mark.parametrize('members,code',[
    ([], 'RIGHTS_MEMBER_SCOPE'),
    ([MEMBER,MEMBER], 'DUPLICATE_RIGHTS_MEMBER'),
    ([None], 'FORMAT'),
])
def test_require_members_rejects_empty_duplicate_and_malformed_scope(members,code):
    from fieldwork.rights import RightsService
    from fieldwork.rights_decision import DecisionRejected
    repo,registry,facts,sign=fixture_context()
    with pytest.raises(DecisionRejected,match=code):
        RightsService(repo,lambda:registry).require_members(
            WORKSPACE,DATASET,'test-author',facts.purpose,members)


@pytest.mark.parametrize('mutation,code',[
    ('unknown','RIGHTS_QUARANTINED'),
    ('missing_decision','MISSING_DECISION'),
    ('mismatched_decision','CONTEXT_MISMATCH'),
    ('quarantined_inventory','RIGHTS_QUARANTINED'),
    ('partial_inventory','INCOMPLETE_INVENTORY'),
    ('revoked_actor','WORKSPACE_PERMISSION'),
    ('revoked_registry','UNTRUSTED_REVIEWER'),
])
def test_require_members_fails_closed_for_inventory_actor_and_decision(mutation,code):
    from fieldwork.rights import RightsService
    from fieldwork.rights_decision import DecisionRejected
    repo,registry,facts,sign=fixture_context()
    service=RightsService(repo,lambda:registry)
    if mutation not in ('unknown','missing_decision'):
        envelope=sign(asset_sha256='a'*64) if mutation=='mismatched_decision' else sign()
        service.intake(WORKSPACE,DATASET,MEMBER,'test-author',facts.purpose,envelope)
    member='UNKNOWN-NONPHOTO' if mutation=='unknown' else MEMBER
    if mutation=='quarantined_inventory':repo.inventory_state='pending'
    if mutation=='partial_inventory':repo.inventory_count=2
    if mutation=='revoked_actor':repo.role='viewer'
    if mutation=='revoked_registry':registry.clear()
    with pytest.raises(DecisionRejected,match=code):
        service.require_members(WORKSPACE,DATASET,'test-author',facts.purpose,[member])


@pytest.mark.parametrize('mutation,code',[
    ('pending','RIGHTS_QUARANTINED'),('conflicting','RIGHTS_QUARANTINED'),
    ('missing_notice','MISSING_EVIDENCE'),('revoked','UNTRUSTED_REVIEWER'),
    ('wrong_purpose','CONTEXT_MISMATCH'),('wrong_workspace','WORKSPACE_PERMISSION'),
    ('wrong_role','WORKSPACE_PERMISSION'),('missing_decision','MISSING_DECISION'),
    ('empty_dataset','RIGHTS_QUARANTINED'),('tampered','INVALID_SIGNATURE'),
])
def test_use_fails_closed(mutation,code):
    from fieldwork.rights import RightsService
    from fieldwork.rights_decision import DecisionRejected
    repo,registry,facts,sign=fixture_context(); raw=sign()
    service=RightsService(repo,lambda:registry)
    service.intake(WORKSPACE,DATASET,MEMBER,'test-author',facts.purpose,raw)
    workspace=WORKSPACE
    if mutation in ('pending','conflicting'):repo.assets[MEMBER]['rights_state']=mutation
    if mutation=='missing_notice':repo.assets[MEMBER]['attribution']=b''
    if mutation=='revoked':registry.clear() # sign BEFORE deletion: no historical helper lookup bug
    if mutation=='wrong_purpose':
        repo.decisions[MEMBER,facts.purpose]=sign(purpose='model_bundle')
        # Add registry scope so mismatch (not scope ceiling) is exercised.
        from fieldwork.rights_decision import TrustedReviewer
        old=registry[REVIEWER,KEY];registry[REVIEWER,KEY]=TrustedReviewer(old.public_key_hex,old.workspace_ids,frozenset({facts.purpose,'model_bundle'}))
    if mutation=='wrong_workspace':workspace=DATASET
    if mutation=='wrong_role':repo.role='viewer'
    if mutation=='missing_decision':repo.decisions.clear()
    if mutation=='empty_dataset':repo.assets.clear()
    if mutation=='tampered':
        doc=json.loads(raw);doc['payload']['asset_bytes']=9;repo.decisions[MEMBER,facts.purpose]=json.dumps(doc).encode()
    with pytest.raises(DecisionRejected,match=code):service.require(workspace,DATASET,'test-author',facts.purpose)


@pytest.mark.parametrize('changes',[{'decision':'deny'},{'asset_bytes':9}])
def test_denied_or_mismatched_intake_replaces_prior_allow(changes):
    from fieldwork.rights import RightsService
    from fieldwork.rights_decision import DecisionRejected
    repo,registry,facts,sign=fixture_context(); service=RightsService(repo,lambda:registry)
    service.intake(WORKSPACE,DATASET,MEMBER,'test-author',facts.purpose,sign())
    assert service.intake(WORKSPACE,DATASET,MEMBER,'test-author',facts.purpose,sign(**changes))['status']=='quarantined'
    with pytest.raises(DecisionRejected):service.require(WORKSPACE,DATASET,'test-author',facts.purpose)


def test_complete_inventory_not_just_signed_subset():
    from fieldwork.rights import RightsService
    from fieldwork.rights_decision import DecisionRejected
    repo,registry,facts,sign=fixture_context(); service=RightsService(repo,lambda:registry)
    service.intake(WORKSPACE,DATASET,MEMBER,'test-author',facts.purpose,sign())
    repo.assets['unsigned-member']=dict(repo.assets[MEMBER],member_id='unsigned-member')
    with pytest.raises(DecisionRejected,match='MISSING_DECISION'):
        service.require(WORKSPACE,DATASET,'test-author',facts.purpose)


@pytest.mark.parametrize('field,value',[
    ('member_id','OTHER-NONPHOTO'),('asset_sha256','a'*64),('asset_bytes',9),
    ('canonical_license_sha256','a'*64),('license_text_sha256','a'*64),
    ('source_evidence_sha256','a'*64),('attribution_sha256','a'*64),
    ('dataset_id',WORKSPACE),('workspace_id',DATASET),('purpose','model_bundle'),
])
def test_all_exact_facts_are_bound(field,value):
    from fieldwork.rights_decision import verify_decision,DecisionRejected,TrustedReviewer
    repo,registry,facts,sign=fixture_context()
    reviewer=registry[REVIEWER,KEY]
    registry[REVIEWER,KEY]=TrustedReviewer(reviewer.public_key_hex,frozenset({WORKSPACE,DATASET}),frozenset({facts.purpose,'model_bundle'}))
    with pytest.raises(DecisionRejected,match='CONTEXT_MISMATCH'):
        verify_decision(sign(**{field:value}),registry=registry,expected=facts)


@pytest.mark.parametrize('kind',['duplicate','embedded_key','bad_hex','uppercase_id','empty','oversized'])
def test_malformed_envelopes_cannot_supply_trust(kind):
    from fieldwork.rights_decision import verify_decision,DecisionRejected
    repo,registry,facts,sign=fixture_context();raw=sign();doc=json.loads(raw)
    if kind=='duplicate':raw=raw.replace(b'"payload":',b'"payload":{},"payload":',1)
    if kind=='embedded_key':doc['public_key_hex']='a'*64;raw=json.dumps(doc).encode()
    if kind=='bad_hex':doc['signature_hex']='A'*128;raw=json.dumps(doc).encode()
    if kind=='uppercase_id':doc['payload']['dataset_id']='AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA';raw=json.dumps(doc).encode()
    if kind=='empty':raw=b''
    if kind=='oversized':raw=b' '*16385
    with pytest.raises(DecisionRejected):verify_decision(raw,registry=registry,expected=facts)


def test_bundle_boundary_requires_current_export_decisions():
    from fieldwork import rights
    assert callable(getattr(rights,'require_bundle_rights',None))
    from fieldwork.rights import RightsService
    from fieldwork.rights_decision import DecisionRejected
    repo,registry,facts,sign=fixture_context('model_bundle');service=RightsService(repo,lambda:registry)
    context=dict(service=service,workspace=WORKSPACE,dataset=DATASET,actor='test-author')
    with pytest.raises(DecisionRejected,match='MISSING_DECISION'):
        rights.require_bundle_rights({'scope':'real-data'},**context)
    service.intake(WORKSPACE,DATASET,MEMBER,'test-author','model_bundle',sign())
    with pytest.raises(DecisionRejected,match='NATURAL_IMAGE_EXECUTION_NOT_ENABLED'):
        rights.require_bundle_rights({'scope':'real-data'},**context)
    assert rights.require_bundle_rights({'scope':'synthetic-execution-only'}) is None


def test_real_store_has_rights_repository():
    from fieldwork.store import Store
    assert callable(getattr(Store,'rights_repository',None))


def test_reviewed_verifier_is_in_application():
    assert importlib.util.find_spec('fieldwork.rights_decision') is not None


def test_bulk_require_memo_never_hides_a_revocation_or_edit():
    """The require() fast path memoizes only the pure signature check; every input is re-read on every call."""
    import fieldwork.rights as rights
    from fieldwork.rights import RightsService
    from fieldwork.rights_decision import DecisionRejected
    rights._VERIFIED.clear()
    repo,registry,facts,sign=fixture_context('model_bundle')
    live={'registry':dict(registry)}
    service=RightsService(repo,lambda:live['registry'])
    repo.decisions[MEMBER,'model_bundle']=sign()
    assert service.require(WORKSPACE,DATASET,'test-author','model_bundle')
    assert service.require(WORKSPACE,DATASET,'test-author','model_bundle')  # memo hit, same result
    assert len(rights._VERIFIED)==1
    live['registry']={}  # reviewer key removed by the operator: the next use must be refused
    with pytest.raises(DecisionRejected) as e:
        service.require(WORKSPACE,DATASET,'test-author','model_bundle')
    assert e.value.code=='UNTRUSTED_REVIEWER'
    live['registry']=dict(registry)
    repo.decisions[MEMBER,'model_bundle']=sign(decision='deny')  # replaced decision
    with pytest.raises(DecisionRejected) as e:
        service.require(WORKSPACE,DATASET,'test-author','model_bundle')
    assert e.value.code=='NOT_ALLOWED'
    repo.decisions[MEMBER,'model_bundle']=sign()
    repo.assets[MEMBER]=dict(repo.assets[MEMBER],attribution=b'edited notices')  # evidence changed after signing
    with pytest.raises(DecisionRejected) as e:
        service.require(WORKSPACE,DATASET,'test-author','model_bundle')
    assert e.value.code=='CONTEXT_MISMATCH'
    repo.role='viewer'  # membership/role is still checked live
    with pytest.raises(DecisionRejected):
        service.require(WORKSPACE,DATASET,'test-author','model_bundle')
