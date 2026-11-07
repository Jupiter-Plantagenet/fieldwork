"""ml-contracts identities and event envelope (pure)."""
import uuid
from datetime import datetime,timezone
from fieldwork import identities as ids


def _row(kind,payload,run='0b5d1f7e-58d4-4c58-9c4a-0d4c7f1c2a11'):
    return dict(seq=42,event_id=uuid.uuid4(),run=run,kind=kind,payload=payload,created=datetime(2026,10,30,tzinfo=timezone.utc),object_revision=7)


def test_identities_are_stable_uuid5_and_digest_bound():
    a=ids.evaluation_id('w','r','d'*64);assert a==ids.evaluation_id('w','r','d'*64)
    assert uuid.UUID(a).version==5 and a!=ids.evaluation_id('w','r','e'*64) and a!=ids.evaluation_id('w2','r','d'*64)
    s=ids.slice_id(a,{'actual':0,'predicted':1,'bucket':'cell'})
    assert s==ids.slice_id(a,{'bucket':'cell','predicted':1,'actual':0}) and s!=ids.slice_id(a,{'actual':0,'predicted':2,'bucket':'cell'})
    ws='76f15066-31e2-4602-9cd5-ee154e27c469';assert ids.workspace_id(ws)==ws and uuid.UUID(ids.workspace_id('synthetic-lab')).version==5


def test_envelope_types_and_required_fields():
    base={'schema_version','event_id','workspace_id','sequence','occurred_at','object_id','revision','correlation_id','type'}
    run=ids.envelope(_row('claimed',{'attempt':str(uuid.uuid4()),'fence':3,'cancel_generation':0}),'w')
    # Legacy claim (pre-ML-Start) moved the run to running; never a non-state like 'claimed'.
    assert base<=set(run) and run['type']=='ML-RunChanged' and run['state']=='running' and run['fence']==3 and run['sequence']=='42'
    assert run['occurred_at']=='2026-10-30T00:00:00Z' and run['revision']==7 and run['correlation_derived'] is True
    cancel=ids.envelope(_row('cancel_requested',{'state':'cancel_requested'}),'w');assert cancel['state']=='cancel_requested'
    cp=ids.envelope(_row('epoch_committed',{'epoch':2,'manifest_digest':'a'*64}),'w')
    assert cp['type']=='ML-CheckpointCommitted' and cp['checkpoint_id']==ids.checkpoint_id(cp['run_id'],2) and cp['manifest_digest']=='a'*64
    # Without a recorded evaluation id an artifact event is a bundle change, never an
    # ML-EvaluationChanged with evaluation_id null.
    ev=ids.envelope(_row('artifact_verified',{'status':'verified'}),'w');assert ev['type']=='ML-BundleChanged' and ev['status']=='verified' and uuid.UUID(ev['bundle_id'])
    eid=ids.evaluation_id('w','r','d'*64)
    ev=ids.envelope(_row('artifact_verified',{'status':'verified','evaluation_id':eid}),'w')
    assert ev['type']=='ML-EvaluationChanged' and ev['evaluation_id']==eid==ev['object_id']
    corr=str(uuid.uuid4());assert ids.envelope(_row('queued',{'correlation_id':corr}),'w')['correlation_id']==corr


def test_round5_envelope_contract_fixes():
    """Review F7: valid ML-Run state enum, non-null integer revision, UTC occurred_at,
    no workspace aliasing."""
    from datetime import timedelta
    states=set()
    for kind,payload in [('claimed',{'state':'leased'}),('started',{'state':'running'}),('resume_requested',{'replay_epoch':9}),
                         ('slot_reconciled',{'state':'interrupted'}),('expired',{'state':'interrupted'}),('failed',{'code':'X'}),
                         ('restore_fenced',{'state':'interrupted'})]:
        states.add(ids.envelope(_row(kind,payload),'w')['state'])
    assert states<=ids.RUN_STATES and None not in states
    assert ids.envelope(_row('resume_requested',{}),'w')['state']=='queued'
    legacy=_row('queued',{});legacy['object_revision']=None
    env=ids.envelope(legacy,'w');assert env['revision']==0 and env['revision_legacy'] is True
    kst=_row('queued',{});kst['created']=datetime(2026,10,30,9,tzinfo=timezone(timedelta(hours=9)))
    assert ids.envelope(kst,'w')['occurred_at']=='2026-10-30T00:00:00Z'
    ws='76f15066-31e2-4602-9cd5-ee154e27c469'
    aliases={ids.workspace_id(x) for x in [ws.upper(),'{'+ws+'}','urn:uuid:'+ws]}
    assert ws not in aliases and len(aliases)==3
    derived=ids.workspace_id('team-a');assert ids.workspace_id(derived)!=derived
