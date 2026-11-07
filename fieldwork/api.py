"""Loopback-only synthetic execution development API; release gates stay closed."""
import hashlib,hmac,json,secrets,uuid,os,time
from .operator_overrides import required_free_bytes
from contextlib import asynccontextmanager
from pathlib import Path
from decimal import Decimal
from fastapi import FastAPI,Request,HTTPException,Depends,Query
from .rights import RightsService
from .rights_registry import load_trusted_registry
from .rights_decision import DecisionRejected,MAX_ENVELOPE_BYTES
from fastapi.responses import FileResponse,JSONResponse,Response
from pydantic import BaseModel,Field,ConfigDict
from .store import Store,Conflict,ROOT,TENANT,GenerationSchemaRequired
from .data import generate,digest,canonical
from . import annotations
import psutil,shutil
DATA=ROOT/'var/images';RUNS=ROOT/'var/runs';WORKSPACE='synthetic-lab'
store=Store(request=True)


def create_account(name,password,workspace=WORKSPACE,role='owner'):
    # A request store may carry its isolated administrator (tests); production uses the operator profile.
    admin=getattr(store,'admin',None) or (Store() if store.is_request else store)
    admin.migrate();salt=secrets.token_hex(16)
    hashed=hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()
    with admin.connect() as c:c.execute('INSERT INTO fw_accounts(name,salt,password_hash,workspace,role) VALUES(%s,%s,%s,%s,%s)',(name,salt,hashed,workspace,role))

def checkpoint_dependency():
    """Read-only mandatory v1 contract; installation is an operator action."""
    import psycopg
    from .checkpoint_read import SIGNATURE,verify
    try:
        with store.connect() as c:
            c.execute('SET TRANSACTION READ ONLY')
            if not c.execute('SELECT pg_catalog.to_regprocedure(%s) AS helper',(SIGNATURE,)).fetchone()['helper']:
                raise RuntimeError('CHECKPOINT_READ_V1_REQUIRED')
            login=c.execute('SELECT session_user AS login').fetchone()['login']
            verify(c,login)
            return c.execute('SELECT version() v').fetchone()['v']
    except ValueError as exc:
        raise RuntimeError('CHECKPOINT_READ_V1_DEPENDENCY:'+str(exc)) from exc
    except psycopg.Error as exc:
        raise RuntimeError('CHECKPOINT_READ_V1_DATABASE_DEPENDENCY') from exc


@asynccontextmanager
async def lifespan(app):
    checkpoint_dependency();generate(DATA);RUNS.mkdir(parents=True,exist_ok=True);yield

app=FastAPI(title='Fieldwork local CPU control plane',version='0.1.0',lifespan=lifespan)

@app.exception_handler(DecisionRejected)
async def rights_rejected(request,exc):
    return JSONResponse(status_code=503 if exc.code=='RIGHTS_DATABASE_DEPENDENCY' else 403,
                        content={'code':exc.code,'rights_status':'quarantined','use_permitted':False})

@app.exception_handler(annotations.Rejection)
async def rejected(request,exc):return JSONResponse(status_code=exc.status,content={'code':str(exc),'message':str(exc)})

@app.exception_handler(GenerationSchemaRequired)
async def generation_schema_required(request,exc):
    # migrations/004 not applied: fail closed, no receipt was written, never DDL here.
    return JSONResponse(status_code=503,content={'code':str(exc),'message':str(exc),'correlation_id':str(uuid.uuid4()),'retryable':False})

@app.exception_handler(Conflict)
async def conflict(request,exc):return JSONResponse(status_code=429 if str(exc)=='QUEUE_FULL' else 409,content={'code':str(exc),'message':str(exc),'correlation_id':str(uuid.uuid4())},headers={'Retry-After':'30'} if str(exc)=='QUEUE_FULL' else {})

@app.middleware('http')
async def security_headers(request,call_next):
    parts=request.url.path.split('/')
    token=TENANT.set(parts[4] if len(parts)>4 and parts[1:4]==['api','v1','workspaces'] else '')
    try:response=await call_next(request)
    finally:TENANT.reset(token)
    response.headers['X-Content-Type-Options']='nosniff';response.headers['Cache-Control']='no-store';response.headers['X-Frame-Options']='DENY'
    return response

class Login(BaseModel):
    model_config=ConfigDict(extra='forbid')
    name:str=Field(min_length=1,max_length=100)
    password:str=Field(min_length=1,max_length=200)

failed_logins={}
def _local_privacy_tombstone(workspace:str)->bool:
    from .privacy_lifecycle import workspace_deleted_locally,PrivacyDeletionLedgerError
    try:return workspace_deleted_locally(workspace)
    except PrivacyDeletionLedgerError:raise HTTPException(503,'PRIVACY_DELETION_LEDGER_UNAVAILABLE') from None

@app.post('/auth/session')
def login(body:Login,request:Request):
    key=(request.client.host if request.client else 'local',body.name)
    failures=failed_logins.get(key,[]);failures=[t for t in failures if time.monotonic()-t<60]
    if len(failures)>=10:raise HTTPException(429,'LOGIN_RATE_LIMIT')
    with store.connect() as c:r=c.execute('SELECT * FROM fw_accounts WHERE name=%s',(body.name,)).fetchone()
    if not r or not hmac.compare_digest(hashlib.scrypt(body.password.encode(),salt=bytes.fromhex(r['salt']),n=16384,r=8,p=1).hex(),r['password_hash']):
        failed_logins[key]=failures+[time.monotonic()];raise HTTPException(401,'SESSION')
    if _local_privacy_tombstone(r['workspace']):
        raise HTTPException(403,'WORKSPACE_PRIVACY_TOMBSTONED')
    with store.connect() as c:
        privacy_fence = c.execute("SELECT to_regprocedure('public.fw_privacy_workspace_deleted_v1(text)') IS NOT NULL AS ready").fetchone()['ready']
        if privacy_fence and c.execute('SELECT public.fw_privacy_workspace_deleted_v1(%s) AS deleted',(r['workspace'],)).fetchone()['deleted']:
            raise HTTPException(403,'WORKSPACE_PRIVACY_TOMBSTONED')
    token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
    with store.connect() as c:
        c.execute('DELETE FROM fw_sessions WHERE token_hash=%s',(digest(request.cookies.get('fieldwork_session','').encode()),))
        c.execute("INSERT INTO fw_sessions(token_hash,name,csrf,expires,issued_role,issued_workspace) VALUES(%s,%s,%s,now()+interval '12 hours',%s,%s)",(digest(token.encode()),body.name,csrf,r['role'],r['workspace']))
    response=JSONResponse({'name':r['name'],'workspace':r['workspace'],'role':r['role'],'csrf':csrf})
    response.set_cookie('fieldwork_session',token,httponly=True,samesite='strict',secure=False,max_age=43200)
    return response

_PRIVACY_FENCE_SEEN=None  # (id(store), dsn) of the store that already answered positively

def session(request:Request):
    global _PRIVACY_FENCE_SEEN
    token=request.cookies.get('fieldwork_session','')
    with store.connect() as c:
        # A migration never removes the fence function, so only a positive answer is remembered.
        fence_key=(id(store),getattr(store,'dsn',None))
        privacy_fence=_PRIVACY_FENCE_SEEN==fence_key or c.execute("SELECT to_regprocedure('public.fw_privacy_workspace_deleted_v1(text)') IS NOT NULL AS ready").fetchone()['ready']
        if privacy_fence:_PRIVACY_FENCE_SEEN=fence_key
        sql="SELECT a.name,a.workspace,a.role,s.csrf FROM fw_sessions s JOIN fw_accounts a ON a.name=s.name WHERE s.token_hash=%s AND s.expires>clock_timestamp() AND s.last_seen>clock_timestamp()-interval '30 minutes' AND s.issued_role=a.role AND s.issued_workspace=a.workspace"
        if privacy_fence:sql+=" AND NOT public.fw_privacy_workspace_deleted_v1(a.workspace)"
        r=c.execute(sql+" FOR UPDATE OF s",(digest(token.encode()),)).fetchone()
        if r and _local_privacy_tombstone(r['workspace']):
            c.execute('DELETE FROM fw_sessions WHERE token_hash=%s',(digest(token.encode()),));r=None
        if r:c.execute('UPDATE fw_sessions SET last_seen=clock_timestamp() WHERE token_hash=%s',(digest(token.encode()),))
    if not r:raise HTTPException(401,'SESSION')
    return r

@app.get('/auth/session')
def who(user=Depends(session)):return user

def scoped(workspace_id:str,user=Depends(session)):
    if workspace_id!=user['workspace']:raise HTTPException(404,'OBJECT_OR_MEMBERSHIP')
    return user

def writer(request:Request,user=Depends(scoped)):
    if request.headers.get('origin') not in ['http://127.0.0.1:5102','http://127.0.0.1:8102'] or not hmac.compare_digest(request.headers.get('x-csrf-token',''),user['csrf']):raise HTTPException(403,'CSRF_OR_ORIGIN')
    if user['role'] not in ['owner','researcher']:raise HTTPException(403,'ROLE')
    return user

@app.post('/auth/logout')
def logout(request:Request,user=Depends(session)):
    if not hmac.compare_digest(request.headers.get('x-csrf-token',''),user['csrf']):raise HTTPException(403,'CSRF')
    with store.connect() as c:c.execute('DELETE FROM fw_sessions WHERE token_hash=%s',(digest(request.cookies.get('fieldwork_session','').encode()),))
    response=JSONResponse({'status':'logged_out'});response.delete_cookie('fieldwork_session');return response

@app.get('/health/live')
def live():return {'status':'live','scope':'local-synthetic-execution'}

@app.get('/health/ready')
def ready():
    try:version=checkpoint_dependency()
    except RuntimeError as exc:
        return JSONResponse(status_code=503,content={'status':'unavailable','component':'checkpoint-read-v1','code':str(exc)})
    return {'status':'ready','database':version,'worker':'separate CLI; no running progress without worker','qualified_release':'blocked'}

BASE='/api/v1/workspaces/{workspace_id}'


def rights_service():
    return RightsService(store,load_trusted_registry)


def real_capabilities():
    import re
    with store.connect() as c:
        schema=c.execute("SELECT to_regclass('public.fw_real_intake_queue') IS NOT NULL AS intake, "
                         "to_regnamespace('fw_real_worker_cap_v1') IS NOT NULL AS runs, "
                         "to_regclass('public.fw_real_image_inputs') IS NOT NULL AS image_inputs, "
                         "to_regclass('public.fw_workspace_settings') IS NOT NULL AS workspace_controls").fetchone()
    images=all(re.fullmatch(r'sha256:[0-9a-f]{64}',os.environ.get(name,''))
               for name in ('FIELDWORK_REAL_PIXEL_IMAGE_ID','FIELDWORK_REAL_MODEL_IMAGE_ID'))
    return {'real_intake':bool(schema['intake']), 'real_runs':bool(schema['runs'] and images),
            'real_image_inference':bool(schema['runs'] and schema['image_inputs'] and images),
            'workspace_controls':bool(schema['workspace_controls'])}


@app.get(BASE+'/datasets/{dataset_id}/rights/preflight')
def rights_preflight(workspace_id:str,dataset_id:str,purpose:str,user=Depends(scoped)):
    decisions=rights_service().require(workspace_id,dataset_id,user['name'],purpose)
    return {'rights_status':'verified','members':len(decisions),'purpose':purpose,
            'use_permitted':False,'other_gates_required':True}


@app.post(BASE+'/datasets/{dataset_id}/rights/{purpose}')
async def rights_intake(workspace_id:str,dataset_id:str,purpose:str,request:Request,
                        member_id:str=Query(min_length=1,max_length=512),user=Depends(writer)):
    # Stream a bounded envelope; never accept embedded authority/evidence as trust.
    raw=bytearray()
    async for chunk in request.stream():
        if len(raw)+len(chunk)>MAX_ENVELOPE_BYTES:
            # Record quarantine/invalidate a prior decision without retaining input.
            return rights_service().intake(workspace_id,dataset_id,member_id,user['name'],purpose,b'')
        raw.extend(chunk)
    return rights_service().intake(workspace_id,dataset_id,member_id,user['name'],purpose,bytes(raw))


def clean_run(r):
    if (r.get('config') or {}).get('scope') in ('real-training/v1','real-inference/v1','real-image-inference/v1','qualified-release-image-inference/v1'):
        from .real_runs_api import _public_run
        return _public_run(r)
    return {k:v for k,v in r.items() if k not in ['checkpoint','lease','idem','actor']}


def fixture_run(workspace_id,run_id,*,allow_absent=False):
    row=store.get(run_id,workspace_id)
    if not row:
        # Cancel keeps its documented contract: an absent run reaches the store, which
        # records the 404 durably against the idempotency key and replays it exactly.
        if allow_absent:return None
        raise HTTPException(404,'OBJECT')
    if row['config'].get('scope')!='synthetic-execution-only':
        raise HTTPException(409,'REAL_RUN_ROUTE_REQUIRED')
    return row

@app.get(BASE+'/snapshot')
def snapshot(workspace_id:str,user=Depends(scoped)):
    m=generate(DATA);point=store.snapshot(workspace_id);rows=point['runs']
    capabilities={'revisioned_cancel':True,'evaluation_flags':True,**real_capabilities()}
    return {'schema':1,'capabilities':capabilities,'last_sequence':point['last_sequence'],
        'workspace':workspace_id,'role':user['role'],'name':user['name'],'scope':m['scope'],
        'classes':m['classes'],'dataset_digest':m['digest'],
        'samples':[{k:v for k,v in s.items() if k!='file'} for s in m['samples'] if s['split']!='holdout'],
        'counts':{split:sum(s['split']==split for s in m['samples']) for split in ['train','validation','holdout']},
        'runs':[clean_run(r) for r in rows],'rights':m['rights'],
        'release':'Local use; final release review pending.',
        'preflight':{'free_ram_bytes':psutil.virtual_memory().available,
            'free_disk_bytes':shutil.disk_usage(ROOT).free,'environment':'Local CPU training'},
        'annotation_workflow':('Proposals, independent review and frozen versions; rights-reviewed image intake is available.'
            if capabilities['real_intake'] else 'Proposals, independent review and frozen versions.'),
        'worker':json.loads((ROOT/'var/worker.json').read_text()) if (ROOT/'var/worker.json').exists() else None}

class Config(BaseModel):
    model_config=ConfigDict(extra='forbid')
    epochs:int=Field(default=10,ge=1,le=100)
    seed:int=Field(default=42,ge=0,le=4294967295)
    batch_size:int=Field(default=8,ge=1,le=32)
    learning_rate:Decimal=Field(default=Decimal('.001'),ge=Decimal('.00001'),le=Decimal('.1'))

@app.post(BASE+'/runs',status_code=202)
def submit(workspace_id:str,body:Config,request:Request,user=Depends(writer)):
    key=request.headers.get('Idempotency-Key')
    if not key or len(key)>200:raise HTTPException(422,'IDEMPOTENCY_KEY_REQUIRED')
    m=generate(DATA);cfg=body.model_dump(mode='json');cfg.update(dataset_digest=m['digest'],recipe='compact-cnn/v1',scope='synthetic-execution-only')
    prior=store.existing_submission(workspace_id,user['name'],key,cfg)
    if prior:return clean_run(prior)
    if (psutil.virtual_memory().available<6*1024**3 and os.environ.get('FIELDWORK_OPERATOR_RAM_OVERRIDE')!='accept-low-available-ram') or shutil.disk_usage(ROOT).free<required_free_bytes(12*1024**3):raise HTTPException(423,'RESOURCE_PREFLIGHT')
    return clean_run(store.submit(workspace_id,user['name'],key,cfg))

@app.get(BASE+'/runs/{run_id}')
def run(workspace_id:str,run_id:str,user=Depends(scoped)):
    r=store.get(run_id,workspace_id)
    if not r:raise HTTPException(404,'OBJECT')
    checkpoints=store.checkpoints(run_id)
    if r['config'].get('scope') in ('real-training/v1','real-inference/v1','real-image-inference/v1','qualified-release-image-inference/v1'):
        checkpoints=[{k:v for k,v in c.items() if k in ('epoch','digest')} for c in checkpoints]
    return {'run':clean_run(r),'checkpoints':checkpoints}

class CancelCommand(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    expected_revision:int=Field(ge=1,le=2147483647)
    reason:str=Field(min_length=1,max_length=2000)


@app.post(BASE+'/runs/{run_id}/cancel')
def cancel(workspace_id:str,run_id:str,body:CancelCommand,request:Request,user=Depends(writer)):
    fixture_run(workspace_id,run_id,allow_absent=True)
    key=request.headers.get('Idempotency-Key','')
    try:
        if len(key)!=36 or str(uuid.UUID(key))!=key.lower():raise ValueError()
    except ValueError:raise HTTPException(422,'IDEMPOTENCY_KEY_REQUIRED')
    if request.headers.get('If-Match')!=f'"{body.expected_revision}"':
        raise HTTPException(428 if not request.headers.get('If-Match') else 422,'IF_MATCH_EXPECTED_REVISION_REQUIRED')
    if not body.reason.strip():raise HTTPException(422,'REASON_REQUIRED')
    status,payload=store.cancel_command(workspace_id,user['name'],key,run_id,body.expected_revision,body.reason)
    return Response(payload,status_code=status,media_type='application/json')

class Resume(BaseModel):
    model_config=ConfigDict(extra='forbid')
    replay_epoch:int=Field(ge=1,le=100)

@app.post(BASE+'/runs/{run_id}/resume',status_code=202)
def resume(workspace_id:str,run_id:str,body:Resume,user=Depends(writer)):
    fixture_run(workspace_id,run_id)
    store.resume(workspace_id,run_id,body.replay_epoch);return {'state':'queued','replay_epoch':body.replay_epoch}

@app.get(BASE+'/samples/{sample_id}/media')
def media(workspace_id:str,sample_id:str,user=Depends(scoped)):
    m=generate(DATA);s=next((s for s in m['samples'] if s['id']==sample_id),None)
    if not s:raise HTTPException(404,'OBJECT')
    if s['split']=='holdout':raise HTTPException(403,'HOLDOUT_SEALED')
    return FileResponse(DATA/s['file'],media_type='image/png',headers={'Cache-Control':'private,no-store'})

@app.get(BASE+'/events')
def events(workspace_id:str,request:Request,after:int|None=None,replay_only:bool=False,user=Depends(scoped)):
    if 'text/event-stream' in request.headers.get('accept',''):return event_stream(workspace_id,request,replay_only,user)
    from .identities import envelope
    return {'items':[{**row,**envelope(row,workspace_id)} for row in store.events(workspace_id,after)],'transport':'durable polling; request Accept: text/event-stream for SSE'}

@app.get(BASE+'/events/stream')
def event_stream(workspace_id:str,request:Request,replay_only:bool=False,user=Depends(scoped)):
    from .events import replay,stream
    from fastapi.responses import StreamingResponse
    cursor=request.headers.get('last-event-id')
    if cursor is not None and (not cursor.isdecimal() or len(cursor)>19 or int(cursor)>9223372036854775807):raise Conflict('EVENT_CURSOR_INVALID')
    after=int(cursor) if cursor else 0
    initial=replay(store,workspace_id,after,check_expiry=bool(cursor))
    return StreamingResponse(stream(store,workspace_id,request,session,after,initial,replay_only),media_type='text/event-stream',headers={'Cache-Control':'no-store','X-Accel-Buffering':'no'})

def evaluation_core(workspace_id,run_id):
    # Digest-bound content: slices, flags and evaluation_id all hash exactly these bytes.
    from .evidence_snapshot import parse
    _,_,files,_=verified_evidence(workspace_id,run_id)
    return {k:parse(files[f'evaluation/{f}.json']) for k,f in [('metrics','metrics'),('population','population'),('independent','independent-report')]}

@app.get(BASE+'/runs/{run_id}/evaluation')
def evaluation(workspace_id:str,run_id:str,user=Depends(scoped)):
    from .identities import evaluation_id,run_uuid
    core=evaluation_core(workspace_id,run_id);evaluation_digest=digest(canonical(core))
    return {**core,'evaluation_id':evaluation_id(workspace_id,run_id,evaluation_digest),'evaluation_digest':evaluation_digest,
            'run_id':run_uuid(run_id),'split':'validation','status':'complete'}

@app.get(BASE+'/runs/{run_id}/records')
def records(workspace_id:str,run_id:str,user=Depends(scoped)):
    _,_,files,_=verified_evidence(workspace_id,run_id)
    return Response(files['evaluation/predictions.jsonl'],media_type='application/x-ndjson',headers={'Content-Disposition':'attachment; filename="validation-predictions.jsonl"'})

@app.get(BASE+'/runs/{run_id}/slices')
def slices(workspace_id:str,run_id:str,actual:int=0,predicted:int=0,offset:int=0,limit:int=3,bucket:str='cell',cursor:str|None=None,user=Depends(scoped)):
    from . import cursors
    if not 0<=actual<5 or not 0<=predicted<5 or offset<0 or not 1<=limit<=20 or bucket not in ('cell','missing'):raise HTTPException(422,'FILTER')
    ev=evaluation_core(workspace_id,run_id)
    ids=ev['metrics']['cells'][f'{actual}:{predicted}'] if bucket=='cell' else [p['id'] for p in ev['population'] if p['label']==actual and p['id'] in ev['metrics']['missing']]
    ids=sorted(ids);predicate={'actual':actual,'predicted':predicted if bucket=='cell' else None,'bucket':bucket}
    binding={'workspace':workspace_id,'run':run_id,'evaluation':digest(canonical(ev)),'predicate':predicate,'limit':limit}
    if cursor is not None:offset=cursors.decode(cursor,binding)
    next_offset=offset+limit if offset+limit<len(ids) else None
    from .identities import evaluation_id,slice_id
    eid=evaluation_id(workspace_id,run_id,binding['evaluation'])
    return {'sample_ids':ids[offset:offset+limit],'total':len(ids),'membership_digest':digest(canonical(ids)),'next_offset':next_offset,'next_cursor':cursors.encode(binding,next_offset) if next_offset is not None else None,'predicate':predicate,'evaluation_digest':binding['evaluation'],'evaluation_id':eid,'slice_id':slice_id(eid,predicate)}

class FlagCommand(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    expected_revision:int=Field(ge=1,le=2147483647)
    actual:int=Field(ge=0,le=4)
    predicted:int|None=Field(default=None,ge=0,le=4)
    bucket:str=Field(pattern='^(cell|missing)$')
    slice_digest:str=Field(pattern='^[a-f0-9]{64}$')
    evaluation_digest:str=Field(pattern='^[a-f0-9]{64}$')
    reason:str=Field(min_length=10,max_length=2000)


def flag_writer(request:Request,user=Depends(scoped)):
    if request.headers.get('origin') not in ['http://127.0.0.1:5102','http://127.0.0.1:8102'] or not hmac.compare_digest(request.headers.get('x-csrf-token',''),user['csrf']):raise HTTPException(403,'CSRF_OR_ORIGIN')
    if user['role'] not in ['owner','researcher','reviewer']:raise HTTPException(403,'ROLE')
    return user


@app.post(BASE+'/runs/{run_id}/flags',status_code=201)
def flag_evaluation(workspace_id:str,run_id:str,body:FlagCommand,request:Request,user=Depends(flag_writer)):
    from .evaluation_flags import create
    key=request.headers.get('Idempotency-Key','')
    try:
        if len(key)!=36 or str(uuid.UUID(key))!=key:raise ValueError()
    except ValueError:raise HTTPException(422,'IDEMPOTENCY_KEY_REQUIRED')
    if request.headers.get('If-Match')!=f'"{body.expected_revision}"':
        raise HTTPException(428 if not request.headers.get('If-Match') else 422,'IF_MATCH_EXPECTED_REVISION_REQUIRED')
    if len(body.reason.strip())<10:raise HTTPException(422,'REASON_REQUIRED')
    if (body.bucket=='cell' and body.predicted is None) or (body.bucket=='missing' and body.predicted is not None):raise HTTPException(422,'FILTER')
    result=create(store,workspace_id,run_id,user['name'],key,body.model_dump(),lambda:evaluation_core(workspace_id,run_id))
    return Response(result,status_code=201,media_type='application/json')


@app.get(BASE+'/runs/{run_id}/flags')
def evaluation_flag_history(workspace_id:str,run_id:str,user=Depends(scoped)):
    from .evaluation_flags import list_flags
    return {'items':list_flags(store,workspace_id,run_id)}


@app.get(BASE+'/runs/{run_id}/artifacts')
def artifacts(workspace_id:str,run_id:str,user=Depends(scoped)):
    r,manifest,_,receipt=verified_evidence(workspace_id,run_id)
    return {'manifest':manifest,'receipt':receipt,'artifact_status':r['artifact_status'],'artifact_result':r['artifact_result'],'download_allowed':False,'browser_inference_allowed':False}


def verified_evidence(workspace_id,run_id):
    fixture_run(workspace_id,run_id)
    from .evidence_snapshot import accepted_evidence
    try:return accepted_evidence(store,RUNS,run_id,workspace_id)
    except LookupError as exc:
        if isinstance(exc,KeyError):raise HTTPException(409,'ARTIFACT_INTEGRITY') from exc
        raise HTTPException(404,'OBJECT') from exc
    except (OSError,ValueError,TypeError,AttributeError) as exc:raise HTTPException(409,'ARTIFACT_INTEGRITY') from exc


@app.get(BASE+'/bundles/{bundle_id}/download')
def download(workspace_id:str,bundle_id:str,user=Depends(scoped)):
    # Existing IDs are run-owned internal candidates, never generic file paths.
    run=store.get(bundle_id,workspace_id)
    if not run or run['config'].get('scope')=='synthetic-execution-only':
        raise HTTPException(403,'INTERNAL_CANDIDATE_NOT_DOWNLOADABLE')
    dataset=run['config'].get('dataset_id')
    if not dataset:raise DecisionRejected('RIGHTS_QUARANTINED')
    rights_service().require(workspace_id,dataset,user['name'],'model_bundle')
    # Current export evidence cannot substitute for independent release approval.
    raise HTTPException(403,'QUALIFIED_RELEASE_REQUIRED')

@app.post(BASE+'/inferences')
def ordinary_inference(user=Depends(writer)):raise HTTPException(403,'QUALIFIED_RELEASE_REQUIRED')

def revision(request):
    value=request.headers.get('If-Match','').strip('"')
    if not value.isdecimal():raise HTTPException(428,'IF_MATCH_REQUIRED')
    return int(value)


def reviewer(request:Request,user=Depends(scoped)):
    if request.headers.get('origin') not in ['http://127.0.0.1:5102','http://127.0.0.1:8102'] or not hmac.compare_digest(request.headers.get('x-csrf-token',''),user['csrf']):raise HTTPException(403,'CSRF_OR_ORIGIN')
    if user['role'] not in ['owner','reviewer']:raise HTTPException(403,'ROLE')
    return user


class EmptyCommand(BaseModel):
    model_config=ConfigDict(extra='forbid')

class Proposal(BaseModel):
    model_config=ConfigDict(extra='forbid')
    sample_id:str=Field(min_length=1,max_length=100)
    label:int=Field(ge=0,le=4)
    reason:str=Field(min_length=10,max_length=2000)

class ReviewVersion(BaseModel):
    model_config=ConfigDict(extra='forbid')
    digest:str=Field(pattern='^[a-f0-9]{64}$')
    reason:str=Field(min_length=10,max_length=2000)

class ReviewProposal(ReviewVersion):
    approve:bool

@app.post(BASE+'/versions',status_code=201)
def new_version(workspace_id:str,body:EmptyCommand,user=Depends(writer)):
    return annotations.create(store,workspace_id,user['name'],generate(DATA))

# Serialized /versions bodies keyed by a cheap per-workspace token. Every version mutation bumps fw_versions.revision
# (propose, review, freeze, split-plan), so (id, revision) identifies the exact payload. The token is read first, so a
# racing write can only make a cached body newer than its label, never older. Responses stay Cache-Control: no-store.
_VERSIONS_CACHE={}
_VERSIONS_CACHE_LIMIT=64

@app.get(BASE+'/versions')
def versions(workspace_id:str,user=Depends(scoped)):
    with store.connect() as c:
        token=c.execute("SELECT md5(coalesce(string_agg(id||':'||revision,',' ORDER BY id),'')) AS t FROM fw_versions WHERE workspace=%s",(workspace_id,)).fetchone()['t']
    cached=_VERSIONS_CACHE.get(workspace_id)
    if cached and cached[0]==token:body=cached[1]
    else:
        from fastapi.encoders import jsonable_encoder
        body=JSONResponse(jsonable_encoder({'items':annotations.list_versions(store,workspace_id)})).body
        if len(_VERSIONS_CACHE)>=_VERSIONS_CACHE_LIMIT:_VERSIONS_CACHE.clear()
        _VERSIONS_CACHE[workspace_id]=(token,body)
    return Response(body,media_type='application/json')

@app.get(BASE+'/versions/{version_id}')
def version(workspace_id:str,version_id:str,user=Depends(scoped)):
    return annotations.get(store,workspace_id,version_id)

@app.post(BASE+'/versions/{version_id}/proposals',status_code=201)
def proposal(workspace_id:str,version_id:str,body:Proposal,request:Request,user=Depends(writer)):
    return annotations.propose(store,workspace_id,version_id,user['name'],revision(request),body.sample_id,body.label,body.reason)

@app.post(BASE+'/proposals/{proposal_id}/review')
def review_proposal(workspace_id:str,proposal_id:str,body:ReviewProposal,user=Depends(reviewer)):
    return annotations.review_proposal(store,workspace_id,proposal_id,user['name'],body.digest,body.approve,body.reason)

@app.post(BASE+'/versions/{version_id}/review')
def review_version(workspace_id:str,version_id:str,body:ReviewVersion,request:Request,user=Depends(reviewer)):
    return annotations.review_version(store,workspace_id,version_id,user['name'],revision(request),body.digest,body.reason)

@app.post(BASE+'/versions/{version_id}/freeze')
def freeze_version(workspace_id:str,version_id:str,body:EmptyCommand,request:Request,user=Depends(writer)):
    return annotations.freeze(store,workspace_id,version_id,revision(request))

# Read-only UI screen projections (round 5 UI lane); same session/membership/RLS chain.
from .api_screens import router as screens_router
app.include_router(screens_router)

# Real data uses the same session, CSRF, workspace context and request principal.
# Decoding remains queued to the separately scoped container-backed intake worker.
from .real_api import create_router as create_real_router
app.include_router(create_real_router(
    store=store, session_dependency=session, writer_dependency=writer,
    rights_service=rights_service(),
    media_root=ROOT/'.local/real-data/media',
    upload_root=ROOT/'.local/real-data/uploads',
))
from .real_runs_api import create_router as create_real_runs_router
app.include_router(create_real_runs_router(
    store=store,session_dependency=session,writer_dependency=writer,rights_service=rights_service(),
))
from .real_workspace_api import create_router as create_real_workspace_router
app.include_router(create_real_workspace_router(
    store=store, session_dependency=session, rights_service=rights_service(),
))

if __name__=='__main__':
    import getpass
    name=input('Local account name: ');password=getpass.getpass('Password (not stored in plaintext): ')
    create_account(name,password);print('Local owner created. Loopback development only.')
