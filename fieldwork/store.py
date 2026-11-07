"""PostgreSQL canonical control plane. No SQLite/in-memory fallback."""
import json, uuid
from contextvars import ContextVar
from pathlib import Path
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .data import digest,canonical
ROOT=Path(__file__).resolve().parents[1]

class Conflict(ValueError): pass

class CancelGenerationConflict(Conflict):
    """Typed refusal: caller's issued or acknowledged cancel generation is not current.

    `state`/`current_generation` are the locked row's values, so a cancelled worker
    can name exactly the cancel it observed in its exit acknowledgement.
    """
    def __init__(self,code,state=None,current_generation=None):
        super().__init__(code);self.code=code;self.state=state;self.current_generation=current_generation

class GenerationSchemaRequired(RuntimeError):
    """migrations/004 absent: fail closed. Application code never performs DDL/repair."""

def checked_generation(value):
    # Explicit int only: never coerce None/bool/str, never default an omitted value.
    if type(value) is not int or not 0<=value<=2147483647:raise ValueError('CANCEL_GENERATION_REQUIRED')
    return value

def row_generation(r):
    # dict_row exposes every column: an absent key means the migration is absent,
    # whereas a present NULL is a legacy (pre-generation) row handled explicitly.
    if 'cancel_generation' not in r:raise GenerationSchemaRequired('CANCEL_GENERATION_SCHEMA_REQUIRED')
    return r['cancel_generation']

UNOBSERVED=object()

def _iso(value):
    return value.isoformat() if hasattr(value,'isoformat') else str(value)

class RestoreGenerationSchemaRequired(RuntimeError):
    """migrations/005 absent: fail closed (no claim without a restore generation)."""

# A restore raises fw_control.fence_floor this far above every fence present in the
# restored snapshot. Fences only grow by one per claim/cancel/expiry/failure/artifact
# retry, and a run has at most 3 training + 3 artifact attempts, so the lost lineage after
# a <=24 h RPO cannot approach this gap; attempt ids (uuid4) and the restore generation
# are checked independently of the gap.
RESTORE_FENCE_GAP=1_000_000
RUN_STATES=('queued','leased','running','interrupted','cancel_requested','cancelled','succeeded','failed')

TENANT=ContextVar('fieldwork_workspace',default='')

# Private durable command replay is not a workspace event feed. Keep rows intact;
# exclude them before LIMIT, expiry and snapshot-watermark calculation.
PUBLIC_EVENT_FILTER="kind IS DISTINCT FROM 'command_receipt' AND kind IS DISTINCT FROM 'evaluation_flag'"

from .artifact_state import ArtifactState,identity,alive

class _PooledConnection(psycopg.Connection):
    """Request-principal connection that goes back to its pool at the end of a `with` block.

    The block still ends exactly like psycopg's: commit on success, rollback on error. Instead of closing, the
    connection is reset (isolation level, read-only flag, RESET ALL) and parked, so API requests stop opening a fresh
    TCP + SCRAM connection for every query block (which also exhausted Windows ephemeral ports under load)."""
    _fw_pool=None
    def __exit__(self,exc_type,exc_val,exc_tb):
        if self.closed:return
        try:
            if exc_type:self.rollback()
            else:self.commit()
        except Exception:
            super().close()
            raise
        pool=self._fw_pool
        if pool is None or not pool.give_back(self):super().close()


class _ConnectionPool:
    MAX_IDLE=16
    MAX_IDLE_SECONDS=60.0
    # Role/database-level settings (ALTER ROLE/DATABASE ... SET, e.g. an operator making the API read-only) are
    # session defaults fixed at connect time. Every checkout re-reads them on the open connection and drops a pooled
    # connection whose settings changed, so such a lever takes effect on the next request exactly as without a pool.
    SETTINGS_SQL=("SELECT coalesce(array_agg(array_to_string(setconfig,',') ORDER BY setdatabase,setrole),'{}') v "
                  "FROM pg_catalog.pg_db_role_setting WHERE setrole IN (0,(SELECT oid FROM pg_catalog.pg_roles "
                  "WHERE rolname=current_user)) AND setdatabase IN (0,(SELECT oid FROM pg_catalog.pg_database "
                  "WHERE datname=current_database()))")
    def __init__(self,dsn):
        import threading
        self.dsn=dsn;self.idle=[];self.lock=threading.Lock()
    def _settings(self,c):
        v=c.execute(self.SETTINGS_SQL).fetchone()
        c.commit()
        return v['v'] if isinstance(v,dict) else v[0]
    def take(self):
        import time
        now=time.monotonic()
        while True:
            with self.lock:
                if not self.idle:break
                c,since,settings=self.idle.pop()
            if now-since>self.MAX_IDLE_SECONDS or c.closed or c.info.transaction_status!=psycopg.pq.TransactionStatus.IDLE:
                psycopg.Connection.close(c);continue
            try:
                if self._settings(c)==settings:return c  # also proves the server still has the connection
            except Exception:
                pass
            psycopg.Connection.close(c)
        c=psycopg.connect(self.dsn,row_factory=dict_row)
        if type(c) is psycopg.Connection:  # adopt real connections; anything else (test doubles) stays unpooled
            c.__class__=_PooledConnection
            c._fw_pool=self
            try:c._fw_settings=self._settings(c)
            except Exception:c._fw_settings=None
        return c
    def give_back(self,c):
        import time
        try:
            if c.closed or c.info.transaction_status!=psycopg.pq.TransactionStatus.IDLE:return False
            if c.isolation_level is not None:c.isolation_level=None
            if c.read_only is not None:c.read_only=None
            if c.autocommit:c.autocommit=False
            c.execute('RESET ALL');c.commit()
        except Exception:
            return False
        if getattr(c,'_fw_settings',None) is None:return False
        with self.lock:
            if len(self.idle)>=self.MAX_IDLE:return False
            self.idle.append((c,time.monotonic(),c._fw_settings))
        return True


class Store(ArtifactState):
    def __init__(self,dsn=None,request=False):
        self.is_request=request
        self.dsn=dsn or json.loads((ROOT/('.local-api.json' if request else '.local.json')).read_text())['dsn']
    def connect(self,*,isolation_level=None):
        if self.is_request:
            # Pool keyed by the DSN in use (tests repoint stores at isolated databases).
            pool=getattr(self,'_pool',None)
            if pool is None or pool.dsn!=self.dsn:
                pool=self._pool=_ConnectionPool(self.dsn)
            c=pool.take()
        else:
            c=psycopg.connect(self.dsn,row_factory=dict_row)
        if isolation_level is not None:c.isolation_level=isolation_level
        if self.is_request:c.execute("SELECT set_config('fieldwork.workspace',%s,true)",(TENANT.get(),))
        return c
    def rights_repository(self):
        from .rights_store import rights_repository
        return rights_repository(self)
    def migrate(self):
        if self.is_request:return  # Request principal is deliberately unable to run DDL.
        with self.connect() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS fw_runs (
            id text PRIMARY KEY, workspace text NOT NULL, actor text NOT NULL, idem text NOT NULL, digest text NOT NULL,
            config jsonb NOT NULL, state text NOT NULL DEFAULT 'queued', fence int NOT NULL DEFAULT 0, epoch int NOT NULL DEFAULT 0,
            revision int NOT NULL DEFAULT 1, attempt text, lease timestamptz, checkpoint text, result jsonb,
            UNIQUE(workspace,actor,idem));
            CREATE TABLE IF NOT EXISTS fw_attempts(id text PRIMARY KEY, run text REFERENCES fw_runs(id), fence int NOT NULL, created timestamptz DEFAULT now(), UNIQUE(run,fence));
            CREATE TABLE IF NOT EXISTS fw_checkpoints(run text REFERENCES fw_runs(id), epoch int, attempt text REFERENCES fw_attempts(id), digest text NOT NULL, path text NOT NULL, metrics jsonb NOT NULL, PRIMARY KEY(run,epoch));
            CREATE TABLE IF NOT EXISTS fw_events(seq bigserial PRIMARY KEY, workspace text NOT NULL, run text REFERENCES fw_runs(id), kind text, payload jsonb, created timestamptz DEFAULT now());
            CREATE TABLE IF NOT EXISTS fw_accounts(name text PRIMARY KEY, salt text NOT NULL, password_hash text NOT NULL, workspace text NOT NULL, role text NOT NULL);
            CREATE TABLE IF NOT EXISTS fw_sessions(token_hash text PRIMARY KEY, name text REFERENCES fw_accounts(name), csrf text NOT NULL, expires timestamptz NOT NULL);
            CREATE TABLE IF NOT EXISTS fw_slot(id int PRIMARY KEY, run text, pid int);
            INSERT INTO fw_slot(id) VALUES(1) ON CONFLICT DO NOTHING;
            ALTER TABLE fw_events ADD COLUMN IF NOT EXISTS event_id uuid NOT NULL DEFAULT gen_random_uuid();
            ALTER TABLE fw_events ADD COLUMN IF NOT EXISTS object_revision int;
            ALTER TABLE fw_runs ADD COLUMN IF NOT EXISTS artifact_status text NOT NULL DEFAULT 'not_started';
            ALTER TABLE fw_runs ADD COLUMN IF NOT EXISTS artifact_result jsonb;
            ALTER TABLE fw_runs ADD COLUMN IF NOT EXISTS artifact_attempts int NOT NULL DEFAULT 0;
            ALTER TABLE fw_runs ADD COLUMN IF NOT EXISTS artifact_owner_pid int;
            ALTER TABLE fw_runs ADD COLUMN IF NOT EXISTS artifact_owner_created double precision;
            ALTER TABLE fw_slot ADD COLUMN IF NOT EXISTS owner_pid int;
            ALTER TABLE fw_slot ADD COLUMN IF NOT EXISTS owner_created double precision;
            ALTER TABLE fw_slot ADD COLUMN IF NOT EXISTS child_created double precision;
            ALTER TABLE fw_slot ADD COLUMN IF NOT EXISTS fence int;
            ALTER TABLE fw_slot ADD COLUMN IF NOT EXISTS launching boolean NOT NULL DEFAULT false;
            ALTER TABLE fw_sessions ADD COLUMN IF NOT EXISTS last_seen timestamptz NOT NULL DEFAULT now();
            ALTER TABLE fw_sessions ADD COLUMN IF NOT EXISTS issued_role text;
            ALTER TABLE fw_sessions ADD COLUMN IF NOT EXISTS issued_workspace text;
            UPDATE fw_sessions s SET issued_role=a.role,issued_workspace=a.workspace FROM fw_accounts a WHERE a.name=s.name AND s.issued_role IS NULL;
            CREATE TABLE IF NOT EXISTS fw_versions(
                workspace text NOT NULL,id text NOT NULL,author text NOT NULL,parent_digest text NOT NULL,
                state text NOT NULL DEFAULT 'draft',revision int NOT NULL DEFAULT 1,manifest jsonb NOT NULL,
                reviewed_digest text,reviewer text,review_reason text,PRIMARY KEY(workspace,id));
            CREATE TABLE IF NOT EXISTS fw_proposals(
                workspace text NOT NULL,id text NOT NULL,version text NOT NULL,sample text NOT NULL,
                author text NOT NULL,label int NOT NULL,reason text NOT NULL,digest text NOT NULL,
                ordinal bigserial,decision text,reviewer text,review_reason text,
                PRIMARY KEY(workspace,id),FOREIGN KEY(workspace,version) REFERENCES fw_versions(workspace,id));''')
    def event(self,c,r,kind,payload):
        revision=c.execute('SELECT revision FROM fw_runs WHERE id=%s',(r['id'],)).fetchone()['revision']
        c.execute('INSERT INTO fw_events(workspace,run,kind,payload,object_revision) VALUES(%s,%s,%s,%s,%s)',(r['workspace'],r['id'],kind,Jsonb(payload),revision))
    def snapshot(self,workspace):
        with self.connect() as c:
            return c.execute("SELECT (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM fw_runs r WHERE workspace=%s) AS runs,(SELECT coalesce(max(seq),0)::text FROM fw_events WHERE workspace=%s AND "+PUBLIC_EVENT_FILTER+") AS last_sequence",(workspace,workspace)).fetchone()
    def existing_submission(self,workspace,actor,key,config):
        with self.connect() as c:r=c.execute('SELECT * FROM fw_runs WHERE workspace=%s AND actor=%s AND idem=%s',(workspace,actor,key)).fetchone()
        if r and r['digest']!=digest(canonical(config)):raise Conflict('IDEMPOTENCY_CONFLICT')
        return r
    def submit(self,workspace,actor,key,config):
        h=digest(canonical(config));rid=str(uuid.uuid4())
        with self.connect() as c:
            c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(workspace,))
            prior=c.execute('SELECT * FROM fw_runs WHERE workspace=%s AND actor=%s AND idem=%s',(workspace,actor,key)).fetchone()
            if prior:
                if prior['digest']!=h:raise Conflict('IDEMPOTENCY_CONFLICT')
                return prior
            if c.execute("SELECT count(*) n FROM fw_runs WHERE workspace=%s AND state='queued'",(workspace,)).fetchone()['n']>=20:raise Conflict('QUEUE_FULL')
            c.execute('INSERT INTO fw_runs(id,workspace,actor,idem,digest,config) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(workspace,actor,idem) DO NOTHING',(rid,workspace,actor,key,h,Jsonb(config)))
            r=c.execute('SELECT * FROM fw_runs WHERE workspace=%s AND actor=%s AND idem=%s',(workspace,actor,key)).fetchone()
            if r['digest']!=h: raise Conflict('IDEMPOTENCY_CONFLICT')
            if r['id']==rid: self.event(c,r,'queued',{'state':'queued'})
            return r
    def get(self,rid,workspace=None):
        with self.connect() as c:
            return c.execute('SELECT * FROM fw_runs WHERE id=%s'+(' AND workspace=%s' if workspace else ''),(rid,workspace) if workspace else (rid,)).fetchone()
    def list(self,workspace):
        with self.connect() as c: return c.execute('SELECT * FROM fw_runs WHERE workspace=%s ORDER BY id',(workspace,)).fetchall()
    @staticmethod
    def control(c,lock=None):
        """fw_control row (migrations/005). FOR SHARE serializes claims with a restore."""
        try:row=c.execute('SELECT restore_generation,fence_floor FROM fw_control WHERE id=1'+(' FOR '+lock if lock else '')).fetchone()
        except psycopg.errors.UndefinedTable:raise RestoreGenerationSchemaRequired('RESTORE_GENERATION_SCHEMA_REQUIRED') from None
        if not row:raise RestoreGenerationSchemaRequired('RESTORE_GENERATION_SCHEMA_REQUIRED')
        return row
    def claim(self,rid,expected_cancel_generation=UNOBSERVED,*,start=True,worker_id=None,key=None,actor='fieldwork-scheduler'):
        """ML-Claim: issue a fenced, leased attempt plus the run's current cancel generation.

        The run becomes `leased` (contract ML-Claim then ML-Start). With `start=True` (the
        compatibility composite for direct Store callers) ML-Start then moves it to
        `running` in a second transaction; the worker uses `start=False` and calls start()
        itself once its child is registered. The returned row carries `restore_generation`.
        The worker carries `attempt`, `fence`, `cancel_generation` and `restore_generation`
        on every later start/heartbeat/checkpoint/complete call.
        `expected_cancel_generation`, when the caller observed one while selecting the
        run, must still be current (ML-Claim: queued and cancel_generation unchanged).
        The fence is issued above fw_control.fence_floor, so fences issued before a
        restore can never recur after it (review F1).
        """
        if expected_cancel_generation is not UNOBSERVED and expected_cancel_generation is not None:checked_generation(expected_cancel_generation)
        with self.connect() as c:
            control=self.control(c,'SHARE')
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            r=c.execute('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE',(rid,)).fetchone()
            request={'run_id':rid,'worker_id':worker_id,'expected_cancel_generation':None if expected_cancel_generation is UNOBSERVED else expected_cancel_generation}
            prior=self._receipt(c,r['workspace'] if r else '',actor,'ML-Claim',key,request)
            if prior is not None:return self._claimed_row(c,prior)
            if not r or r['state']!='queued' or slot['run'] is not None: raise Conflict('NOT_QUEUED_OR_SLOT_BUSY')
            current=row_generation(r)
            if expected_cancel_generation is not UNOBSERVED and current!=expected_cancel_generation:
                raise CancelGenerationConflict('CANCEL_GENERATION_CHANGED',r['state'],current)
            # Legacy NULL on a queued row is issued 0: cancelling queued/interrupted is
            # terminal and cancel_requested never re-queues, so no tracked cancel preceded it.
            generation=0 if current is None else current
            aid=str(uuid.uuid4());fence=max(r['fence'],control['fence_floor'])+1;restore_generation=str(control['restore_generation'])
            c.execute('INSERT INTO fw_attempts(id,run,fence,cancel_generation,restore_generation,worker_id) VALUES(%s,%s,%s,%s,%s,%s)',(aid,rid,fence,generation,restore_generation,worker_id))
            pid,created=identity()
            c.execute('UPDATE fw_slot SET run=%s,fence=%s,owner_pid=%s,owner_created=%s,pid=NULL,child_created=NULL,launching=false WHERE id=1',(rid,fence,pid,created))
            r=c.execute("UPDATE fw_runs SET state='leased',fence=%s,attempt=%s,cancel_generation=%s,lease=clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=%s RETURNING *",(fence,aid,generation,rid)).fetchone()
            self.event(c,r,'claimed',{'state':'leased','attempt':aid,'fence':fence,'cancel_generation':generation,'restore_generation':restore_generation})
            self._store_receipt(c,r['workspace'],actor,'ML-Claim',key,request,{'attempt_id':aid,'fence':fence,'lease_expires_at':_iso(r['lease']),'job_manifest_digest':r['digest'],'cancel_generation':generation,'restore_generation':restore_generation},rid)
        r=dict(r,restore_generation=restore_generation)
        if start:
            started=self.start(rid,aid,fence,generation,r['digest'],restore_generation=restore_generation)
            r=dict(r,state=started['state'],revision=started['revision'],lease=started['lease_expires_at'])
        return r
    def _claimed_row(self,c,prior):
        body=json.loads(prior[1]);r=c.execute('SELECT * FROM fw_runs WHERE attempt=%s',(body['attempt_id'],)).fetchone()
        if r is None:raise Conflict('FENCED_OR_EXPIRED_OR_CANCELLED')
        return dict(r,restore_generation=body['restore_generation'])
    # ---- internal-command idempotency receipts (ml-contracts: unique(workspace,actor,command,key)) ----
    @staticmethod
    def _key_identity(key):
        try:
            if not isinstance(key,str) or len(key)!=36:raise ValueError()
            identity_=str(uuid.UUID(key))
            if identity_!=key.lower():raise ValueError()
            return identity_
        except ValueError:raise ValueError('IDEMPOTENCY_KEY_REQUIRED') from None
    def _receipt(self,c,workspace,actor,command,key,request):
        """Replay a stored internal-command receipt, or None to execute.

        Same key and canonical request digest returns the saved (status, body); a changed
        digest is 409 IDEMPOTENCY_CONFLICT. Only committed successes are bound to a key:
        a refused command rolls back and binds nothing, and re-executing it is refused
        again because fence/generation/state only move forward. Receipts are kept (no TTL),
        which exceeds the contract's 90-day tombstone.
        """
        if key is None:return None
        k=self._key_identity(key);request_digest=digest(canonical(request))
        c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(canonical([workspace,actor,command,k]).decode(),))
        prior=c.execute('SELECT request_digest,status,response FROM fw_command_receipts WHERE workspace=%s AND actor=%s AND command=%s AND key=%s',(workspace,actor,command,k)).fetchone()
        if prior is None:return None
        if prior['request_digest']!=request_digest:raise Conflict('IDEMPOTENCY_CONFLICT')
        return prior['status'],canonical(prior['response']).decode()
    def _store_receipt(self,c,workspace,actor,command,key,request,body,run=None,status=200):
        if key is None:return
        c.execute('INSERT INTO fw_command_receipts(workspace,actor,command,key,request_digest,status,response,run) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',
                  (workspace,actor,command,self._key_identity(key),digest(canonical(request)),status,Jsonb(body),run))
    def start(self,rid,attempt,fence,cancel_generation,resolved_config_digest,*,restore_generation=None,key=None,actor='fieldwork-worker'):
        """ML-Start (internal://ml/attempts/{attempt_id}/start): leased -> running.

        Requires the current attempt, fence, cancel generation, live lease, the run's
        resolved config digest and (when supplied) the current restore generation.
        Errors: 409 FENCED, 410 LEASE_EXPIRED; a cancel requested while leased is the
        typed CANCEL_GENERATION_FENCED refusal naming the generation to acknowledge.
        """
        checked_generation(cancel_generation)
        with self.connect() as c:
            control=self.control(c,'SHARE')
            r=c.execute('SELECT *,lease>clock_timestamp() AS live FROM fw_runs WHERE id=%s FOR UPDATE',(rid,)).fetchone()
            if not r:raise Conflict('FENCED')
            request={'attempt_id':attempt,'fence':fence,'cancel_generation':cancel_generation,'resolved_config_digest':resolved_config_digest,'restore_generation':restore_generation}
            prior=self._receipt(c,r['workspace'],actor,'ML-Start',key,request)
            if prior is not None:return json.loads(prior[1])
            current=row_generation(r)
            if current is None:raise CancelGenerationConflict('CANCEL_GENERATION_UNVERIFIABLE',r['state'],None)
            if current!=cancel_generation:raise CancelGenerationConflict('CANCEL_GENERATION_FENCED',r['state'],current)
            if r['state']!='leased' or r['fence']!=fence or r['attempt']!=attempt:raise Conflict('FENCED')
            self._attempt_generation(c,r,attempt,restore_generation,control)
            if not r['live']:raise Conflict('LEASE_EXPIRED')
            if resolved_config_digest!=r['digest']:raise Conflict('FENCED')
            r=c.execute("UPDATE fw_runs SET state='running',lease=clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=%s RETURNING *",(rid,)).fetchone()
            c.execute('UPDATE fw_attempts SET started_at=clock_timestamp() WHERE id=%s',(attempt,))
            self.event(c,r,'started',{'state':'running','attempt':attempt,'fence':fence})
            body={'state':'running','revision':r['revision'],'lease_expires_at':_iso(r['lease'])}
            self._store_receipt(c,r['workspace'],actor,'ML-Start',key,request,body,rid)
            return dict(body,lease_expires_at=r['lease'])
    def _attempt_generation(self,c,r,attempt,restore_generation,control=None):
        """The run's current attempt must carry the current restore generation (and match
        the caller's, when supplied). Pre-005 attempts (NULL generation) are refused."""
        control=control or self.control(c)
        current=str(control['restore_generation'])
        if restore_generation is not None and str(restore_generation)!=current:raise Conflict('RESTORE_GENERATION_FENCED')
        if r['attempt'] is None:raise Conflict('FENCED_OR_EXPIRED_OR_CANCELLED')
        if attempt is not None and attempt!=r['attempt']:raise Conflict('FENCED_OR_EXPIRED_OR_CANCELLED')
        row=c.execute('SELECT restore_generation FROM fw_attempts WHERE id=%s',(r['attempt'],)).fetchone()
        if not row or row['restore_generation'] is None or str(row['restore_generation'])!=current:raise Conflict('RESTORE_GENERATION_FENCED')
    def live(self,c,rid,fence,cancel_generation,attempt,restore_generation=None):
        # Generation is checked first under the run lock so a cancelled worker gets
        # the deterministic typed refusal (and the generation to acknowledge),
        # independently of the fence that cancellation also revokes. Review F1: the
        # attempt id (uuid4, never reused) and the attempt's restore generation are
        # checked too, so a worker from a lost (pre-restore) lineage is always refused.
        r=c.execute('SELECT *,lease>clock_timestamp() AS live FROM fw_runs WHERE id=%s FOR UPDATE',(rid,)).fetchone()
        if not r: raise Conflict('FENCED_OR_EXPIRED_OR_CANCELLED')
        current=row_generation(r)
        if current is None:raise CancelGenerationConflict('CANCEL_GENERATION_UNVERIFIABLE',r['state'],None)
        if current!=cancel_generation:raise CancelGenerationConflict('CANCEL_GENERATION_FENCED',r['state'],current)
        # The attempt id is mandatory: fence alone can recur across a point-in-time restore.
        if r['state']!='running' or r['fence']!=fence or not r['live'] or not attempt or attempt!=r['attempt']: raise Conflict('FENCED_OR_EXPIRED_OR_CANCELLED')
        self._attempt_generation(c,r,attempt,restore_generation)
        return r
    def heartbeat(self,rid,fence,cancel_generation,*,attempt,restore_generation=None,key=None,actor='fieldwork-worker'):
        checked_generation(cancel_generation)
        with self.connect() as c:
            r=self.live(c,rid,fence,cancel_generation,attempt,restore_generation)
            request={'attempt_id':r['attempt'],'fence':fence,'cancel_generation':cancel_generation}
            prior=self._receipt(c,r['workspace'],actor,'ML-Heartbeat',key,request)
            if prior is not None:return json.loads(prior[1])
            lease=c.execute("UPDATE fw_runs SET lease=clock_timestamp()+interval '45 seconds' WHERE id=%s RETURNING lease",(rid,)).fetchone()['lease']
            self._store_receipt(c,r['workspace'],actor,'ML-Heartbeat',key,request,{'lease_expires_at':_iso(lease),'cancel_requested':False},rid)
        # A matching generation means no cancel has been requested since issue.
        return {'lease_expires_at':lease,'cancel_requested':False,'cancel_generation':cancel_generation}
    def publish(self,rid,fence,cancel_generation,path,metrics,*,attempt,restore_generation=None,key=None,actor='fieldwork-worker'):
        checked_generation(cancel_generation)
        from .ml import validate_checkpoint
        from .checkpoint_store import promote
        # A fenced worker may still stage a digest blob here before the locked check below
        # refuses it; such a blob is unreferenced and is collected by checkpoint_gc (24 h).
        path,md=promote(path,getattr(self,'blob_root',ROOT/'var/checkpoints'));epoch=metrics['epoch']
        with self.connect() as c:
            r=self.live(c,rid,fence,cancel_generation,attempt,restore_generation)
            request={'attempt_id':r['attempt'],'fence':fence,'cancel_generation':cancel_generation,'epoch':epoch,'manifest_digest':md,'metrics':metrics}
            prior=self._receipt(c,r['workspace'],actor,'ML-CheckpointCommit',key,request)
            if prior is not None:return json.loads(prior[1])
            metadata=json.loads((path/'state.json').read_text())
            if metadata['dataset_digest']!=r['config'].get('dataset_digest') or metadata['epoch']!=epoch or metadata['next_epoch']!=epoch+1:raise Conflict('CHECKPOINT_LINEAGE')
            from decimal import Decimal
            if ('seed' in r['config'] and metadata['seed']!=r['config']['seed']) or ('learning_rate' in r['config'] and Decimal(str(metadata['groups'][0]['lr']))!=Decimal(str(r['config']['learning_rate']))) or metrics!={k:metadata[k] for k in ['epoch','train_loss','validation_loss','updates']}:raise Conflict('CHECKPOINT_LINEAGE_OR_METRICS')
            prior=c.execute('SELECT * FROM fw_checkpoints WHERE run=%s AND epoch=%s',(rid,epoch)).fetchone()
            if prior:
                if prior['digest']==md and prior['attempt']==r['attempt']:return
                raise Conflict('CHECKPOINT_CONFLICT')
            if epoch!=r['epoch']+1: raise Conflict('EPOCH_ORDER')
            c.execute('INSERT INTO fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES(%s,%s,%s,%s,%s,%s)',(rid,epoch,r['attempt'],md,str(path),Jsonb(metrics)))
            # Review F2: the INSERT holds ROW EXCLUSIVE on fw_checkpoints, so no GC pass
            # (SHARE) can start until commit. Re-validate the exact blob now; if a GC that
            # ran before the INSERT removed it, this raises and the pointer rolls back.
            validate_checkpoint(path,md)
            c.execute('UPDATE fw_runs SET epoch=%s,checkpoint=%s,revision=revision+1 WHERE id=%s',(epoch,str(path),rid))
            self.event(c,r,'epoch_committed',{**metrics,'manifest_digest':md,'attempt':r['attempt']})
            from .identities import checkpoint_id
            self._store_receipt(c,r['workspace'],actor,'ML-CheckpointCommit',key,request,{'checkpoint_id':checkpoint_id(rid,epoch),'state':'committed'},rid)
    def checkpoints(self,rid):
        with self.connect() as c: return c.execute('SELECT epoch,digest,metrics FROM fw_checkpoints WHERE run=%s ORDER BY epoch',(rid,)).fetchall()
    def complete(self,rid,fence,cancel_generation,result,*,attempt,restore_generation=None,key=None,actor='fieldwork-worker'):
        checked_generation(cancel_generation)
        with self.connect() as c:
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            r=self.live(c,rid,fence,cancel_generation,attempt,restore_generation)
            request={'attempt_id':r['attempt'],'fence':fence,'cancel_generation':cancel_generation,'epoch_report_digest':digest(canonical(result))}
            prior=self._receipt(c,r['workspace'],actor,'ML-Complete',key,request)
            if prior is not None:return json.loads(prior[1])
            if r['epoch']!=r['config']['epochs']:raise Conflict('INCOMPLETE')
            pid,created=identity()
            if slot['run']!=rid or slot['fence']!=fence or (slot['owner_pid'],slot['owner_created'])!=(pid,created) or slot['launching'] or alive(slot['pid'],slot['child_created']):raise Conflict('CHILD_EXIT_OR_OWNER_UNCONFIRMED')
            c.execute("UPDATE fw_runs SET state='succeeded',result=%s,artifact_status='pending',artifact_result=%s,artifact_attempts=1,artifact_owner_pid=%s,artifact_owner_created=%s,lease=clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=%s",(Jsonb(result),Jsonb({'code':'ARTIFACT_PENDING'}),pid,created,rid))
            c.execute('UPDATE fw_attempts SET ended_at=clock_timestamp() WHERE id=%s',(r['attempt'],))
            self.event(c,r,'succeeded',{'state':'succeeded','attempt':r['attempt'],'fence':fence})
            self.event(c,r,'artifact_pending',{'code':'ARTIFACT_PENDING'})
            revision=c.execute('SELECT revision FROM fw_runs WHERE id=%s',(rid,)).fetchone()['revision']
            self._store_receipt(c,r['workspace'],actor,'ML-Complete',key,request,{'state':'succeeded','revision':revision},rid)
            return {'state':'succeeded','revision':revision}
    def fail(self,rid,attempt,fence,error_code,retryable,diagnostics_digest,*,restore_generation=None,key=None,actor='fieldwork-worker'):
        """ML-Fail: current fence and attempt only (review F10: never an unfenced UPDATE).

        A retryable infrastructure failure with attempt budget left (< 3 attempts) moves
        the run to `interrupted` (explicit resume); otherwise `failed` (terminal). Accepts
        the attempt's run in leased/running. The lease need not be live: a worker
        reporting its own failure after a stall is still fenced by fence+attempt.
        """
        if not isinstance(error_code,str) or not error_code or len(error_code)>120:raise ValueError('ERROR_CODE_REQUIRED')
        if not isinstance(diagnostics_digest,str) or len(diagnostics_digest)!=64:raise ValueError('DIAGNOSTICS_DIGEST_REQUIRED')
        with self.connect() as c:
            control=self.control(c,'SHARE')
            r=c.execute('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE',(rid,)).fetchone()
            if not r:raise Conflict('FENCED')
            request={'attempt_id':attempt,'fence':fence,'error_code':error_code,'retryable':bool(retryable),'diagnostics_digest':diagnostics_digest}
            prior=self._receipt(c,r['workspace'],actor,'ML-Fail',key,request)
            if prior is not None:return json.loads(prior[1])
            if r['state'] not in ('leased','running') or r['fence']!=fence or r['attempt']!=attempt:raise Conflict('FENCED')
            self._attempt_generation(c,r,attempt,restore_generation,control)
            attempts=c.execute('SELECT count(*) n FROM fw_attempts WHERE run=%s',(rid,)).fetchone()['n']
            state='interrupted' if retryable and attempts<3 else 'failed'
            r=c.execute('UPDATE fw_runs SET state=%s,fence=fence+1,revision=revision+1 WHERE id=%s AND fence=%s AND attempt=%s RETURNING *',(state,rid,fence,attempt)).fetchone()
            c.execute('UPDATE fw_attempts SET ended_at=clock_timestamp() WHERE id=%s',(attempt,))
            self.event(c,r,state,{'state':state,'code':error_code,'retryable':bool(retryable),'attempt':attempt,'diagnostics_digest':diagnostics_digest})
            body={'state':state}
            self._store_receipt(c,r['workspace'],actor,'ML-Fail',key,request,body,rid)
            return body

    def cancel_command(self,workspace,actor,key,rid,expected_revision,reason):
        """Durable browser ML-Cancel, distinct from the internal cancel API.

        Receipts are append-only fw_events, NOT seven-day delivery replay. Keep
        them (including response bytes) indefinitely: no TTL may permit a key to
        execute again. The API role has SELECT/INSERT but no UPDATE/DELETE here.
        All callers use the command advisory lock before locking any run, so a
        key reused for another run cannot escape its original request binding.
        The run lock also serializes with complete/live/claim/internal cancel.
        """
        try:
            if not isinstance(key,str) or len(key)!=36:raise ValueError()
            key_identity=str(uuid.UUID(key))
            if key_identity!=key.lower():raise ValueError()
        except ValueError:raise ValueError('IDEMPOTENCY_KEY_REQUIRED') from None
        if type(expected_revision) is not int or not 1<=expected_revision<=2147483647:
            raise ValueError('EXPECTED_REVISION_INVALID')
        if not isinstance(reason,str) or not reason.strip() or len(reason)>2000:
            raise ValueError('REASON_INVALID')
        request_digest=digest(canonical({'run_id':rid,'expected_revision':expected_revision,'reason':reason}))
        # Preserve the supplied token in the receipt; only a validated UUID's
        # semantic identity is used for serialization and duplicate detection.
        scope=canonical([workspace,actor,'ML-Cancel',key_identity]).decode()
        with self.connect() as c:
            c.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(scope,))
            prior=c.execute("SELECT payload FROM fw_events WHERE workspace=%s AND kind=%s AND payload->>'command'='ML-Cancel' AND payload->>'actor'=%s AND COALESCE(payload->>'key_identity',LOWER(payload->>'key'))=%s ORDER BY seq LIMIT 1",(workspace,'command_receipt',actor,key_identity)).fetchone()
            if prior:
                receipt=prior['payload']
                if receipt['request_digest']!=request_digest:raise Conflict('IDEMPOTENCY_CONFLICT')
                return receipt['status'],receipt['response_body']
            r=c.execute('SELECT * FROM fw_runs WHERE id=%s AND workspace=%s FOR UPDATE',(rid,workspace)).fetchone()
            # Old schema: refuse before any receipt, so no outcome is durably bound
            # to the key without a generation. Prior receipts above still replay.
            generation=row_generation(r) if r else None
            status=200
            if not r:
                status=404;body={'code':'OBJECT','message':'OBJECT','correlation_id':str(uuid.uuid4()),'retryable':False}
            elif r['state'] not in ('succeeded','failed','cancelled','cancel_requested') and r['revision']!=expected_revision:
                # Review F10: an already-requested cancel is idempotent (200 cancel_requested)
                # whatever revision the retry carries; only a state-changing cancel is
                # bound to If-Match.
                status=412;body={'code':'STALE_REVISION','message':'STALE_REVISION','correlation_id':str(uuid.uuid4()),'object_revision':r['revision'],'retryable':False}
            else:
                state=r['state']
                if state not in ('succeeded','failed','cancelled','cancel_requested'):
                    state='cancel_requested' if state in ('running','leased') else 'cancelled'
                    generation=self._next_generation(generation)
                    # Revoke publication authority, never release a physical slot.
                    c.execute('UPDATE fw_runs SET state=%s,fence=fence+1,revision=revision+1,cancel_generation=%s WHERE id=%s',(state,generation,rid))
                    self.event(c,r,state,{'state':state,'actor':actor,'reason':reason,'cancel_generation':generation})
                body={'state':state,'completion_won':state=='succeeded'}
            response_body=canonical(body).decode()
            receipt={'command':'ML-Cancel','actor':actor,'key':key,'key_identity':key_identity,'request_digest':request_digest,
                     'status':status,'response_body':response_body,'run_id':rid,'reason':reason,
                     'expected_revision':expected_revision,'cancel_generation':generation}
            c.execute('INSERT INTO fw_events(workspace,run,kind,payload,object_revision) VALUES(%s,%s,%s,%s,%s)',
                      (workspace,rid if r else None,'command_receipt',Jsonb(receipt),
                       (r['revision']+(1 if status==200 and body['state']!=r['state'] else 0)) if r else None))
            return status,response_body

    @staticmethod
    def _next_generation(previous):
        """Exactly one increment per non-terminal -> cancel transition, under the run lock.

        Repeated cancels of cancel_requested/terminal rows never increment, so an
        acknowledgement naming the observed generation cannot be invalidated by a
        duplicate request. Legacy NULL counts as 0 tracked cancels (see claim).
        """
        return (0 if previous is None else previous)+1
    def cancel(self,workspace,rid):
        with self.connect() as c:
            r=c.execute('SELECT * FROM fw_runs WHERE id=%s AND workspace=%s FOR UPDATE',(rid,workspace)).fetchone()
            if not r: raise Conflict('NOT_FOUND')
            generation=row_generation(r)
            if r['state'] in ['succeeded','failed','cancelled','cancel_requested']: return r['state']
            state='cancel_requested' if r['state'] in ('running','leased') else 'cancelled';generation=self._next_generation(generation)
            c.execute('UPDATE fw_runs SET state=%s,fence=fence+1,revision=revision+1,cancel_generation=%s WHERE id=%s',(state,generation,rid));self.event(c,r,state,{'state':state,'cancel_generation':generation});return state
    def expire(self,rid):
        with self.connect() as c:
            r=c.execute('SELECT *,lease<clock_timestamp() AS expired FROM fw_runs WHERE id=%s FOR UPDATE',(rid,)).fetchone()
            if not r or not r['expired'] or r['state'] not in ['leased','running','cancel_requested']: raise Conflict('LEASE_RENEWED')
            state='cancelled' if r['state']=='cancel_requested' else 'interrupted'
            c.execute('UPDATE fw_runs SET state=%s,fence=fence+1,revision=revision+1 WHERE id=%s',(state,rid));self.event(c,r,'expired',{'state':state})
    def expire_for_test(self,rid):
        with self.connect() as c: c.execute("UPDATE fw_runs SET lease=now()-interval '1 second' WHERE id=%s",(rid,))
        self.expire(rid)
    @staticmethod
    def _acknowledgeable(r,cancel_generation):
        current=row_generation(r) if r else None
        if not r or current is None or current!=cancel_generation or r['state'] not in ('cancel_requested','cancelled'):
            raise CancelGenerationConflict('WRONG_GENERATION',r['state'] if r else None,current)
        return r
    def acknowledge_cancel(self,rid,fence,cancel_generation,*,exit_receipt=None,lease_expired=False,key=None,actor='fieldwork-worker'):
        """ML-AcknowledgeCancel: confirmed-exit slot release naming the observed generation.

        `exit_receipt` (the worker's canonical record of the observed child/owner exit) is
        hashed to `exit_receipt_digest` (hex SHA-256), stored on the attempt and in the
        'cancelled' event. `lease_expired` is recorded as reported.
        """
        return self.release_slot(rid,fence=fence,cancel_generation=checked_generation(cancel_generation),exit_receipt=exit_receipt,lease_expired=lease_expired,key=key,actor=actor)
    @staticmethod
    def exit_receipt_digest(exit_receipt):
        if exit_receipt is None:return None
        if not isinstance(exit_receipt,dict) or not exit_receipt:raise ValueError('EXIT_RECEIPT_INVALID')
        return digest(canonical(exit_receipt))
    def release_slot(self,rid,fence=None,*,cancel_generation=None,exit_receipt=None,lease_expired=False,key=None,actor='fieldwork-worker'):
        """Release the physical slot; with `cancel_generation`, also acknowledge that cancel.

        Lock order is slot then run, like claim/complete; cancel writers lock only
        the run. The acknowledgement must name the generation the worker actually
        observed (typed refusal or cancel_requested read). Only `cancel_requested`
        at exactly that generation becomes `cancelled` (+revision, one event). Same
        generation already `cancelled` (duplicate ack, or expiry won) is idempotent.
        Anything else is WRONG_GENERATION and rolls back, retaining slot and run.
        Without `cancel_generation` the slot is released and no run state changes.
        """
        if cancel_generation is not None:checked_generation(cancel_generation)
        exit_digest=self.exit_receipt_digest(exit_receipt)
        # Explicit fence is mandatory for production callers. Compatibility for
        # controller state tests still checks the exact owning process identity.
        with self.connect() as c:
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            ack_request={'run_id':rid,'fence':fence,'cancel_generation':cancel_generation,'exit_receipt_digest':exit_digest,'lease_expired':bool(lease_expired)}
            if cancel_generation is not None and key is not None:
                owner=c.execute('SELECT workspace FROM fw_runs WHERE id=%s',(rid,)).fetchone()
                prior=self._receipt(c,owner['workspace'] if owner else '',actor,'ML-AcknowledgeCancel',key,ack_request)
                if prior is not None:return json.loads(prior[1])['state']
            if slot['run']!=rid:
                if cancel_generation is None:return None
                # Slot already released: ownership/exit can no longer be checked, so
                # report only and never mutate ('cancelled' for a duplicate ack;
                # 'cancel_requested' stays pending until ML-Expire).
                return self._acknowledgeable(c.execute('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE',(rid,)).fetchone(),cancel_generation)['state']
            pid,created=identity()
            if (fence is not None and fence!=slot['fence']) or (slot['owner_pid'],slot['owner_created'])!=(pid,created):raise Conflict('SLOT_OWNER_FENCED')
            if slot['launching'] or alive(slot['pid'],slot['child_created']):raise Conflict('CHILD_EXIT_UNCONFIRMED')
            r=None
            if cancel_generation is not None:
                r=self._acknowledgeable(c.execute('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE',(rid,)).fetchone(),cancel_generation)
            c.execute('UPDATE fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL WHERE id=1')
            if r is None:return None
            if r.get('attempt') is not None and exit_digest is not None:
                c.execute('UPDATE fw_attempts SET exit_receipt_digest=coalesce(exit_receipt_digest,%s),ended_at=coalesce(ended_at,clock_timestamp()) WHERE id=%s',(exit_digest,r['attempt']))
            if r['state']!='cancelled':
                r=c.execute("UPDATE fw_runs SET state='cancelled',revision=revision+1 WHERE id=%s AND state='cancel_requested' AND cancel_generation=%s RETURNING *",(rid,cancel_generation)).fetchone()
                self.event(c,r,'cancelled',{'state':'cancelled','cancel_generation':cancel_generation,'attempt':r.get('attempt'),'exit_receipt_digest':exit_digest,'lease_expired':bool(lease_expired)})
            self._store_receipt(c,r['workspace'],actor,'ML-AcknowledgeCancel',key,ack_request,{'state':'cancelled','exit_receipt_digest':exit_digest},rid)
            return 'cancelled'

    def next_run(self,blocked=()):
        """Worker queue head: queued (or artifact retry) synthetic runs, skipping only
        (run, revision) pairs refused permanently (review F3)."""
        skip=[f'{rid}@{rev}' for rid,rev in blocked]
        with self.connect() as c:
            return c.execute("SELECT id,revision FROM fw_runs WHERE (state='queued' OR (state='succeeded' AND artifact_status='retry_pending')) AND config->>'scope'='synthetic-execution-only' AND NOT ((id||'@'||revision)=ANY(%s)) ORDER BY id LIMIT 1",(skip,)).fetchone()
    def resume_checkpoint(self,rid,epoch,attempt=None):
        with self.connect() as c:
            return c.execute('SELECT digest,path FROM fw_checkpoints WHERE run=%s AND epoch=%s',(rid,epoch)).fetchone()
    def release_own_slot(self):
        """Review F6: retry a release the worker's cleanup could not complete. Frees the
        slot only when THIS process owns it, nothing is launching and the registered child
        is proven not alive; otherwise returns a visible held reason. Never changes run
        state (a still-running run is left to ML-Expire)."""
        with self.connect() as c:
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            if slot['run'] is None:return None
            if (slot['owner_pid'],slot['owner_created'])!=identity():return None
            r=c.execute('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE',(slot['run'],)).fetchone()
            if r is not None and r['state'] in ('leased','running') and r['fence']==slot['fence']:return 'OWN_RUN_ACTIVE'
            if r is not None and r['state']=='succeeded' and r['artifact_status'] in ('pending','building','inference','retry_pending'):return 'ARTIFACT_RECOVERY_OWNS_SLOT'
            if slot['launching']:return 'CHILD_EXIT_UNCONFIRMED'
            if alive(slot['pid'],slot['child_created']):return 'CHILD_ALIVE'
            from .real_container_guard import model_cleanup_pending
            if model_cleanup_pending():return 'REAL_MODEL_CLEANUP_REQUIRED'
            c.execute('UPDATE fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL,launching=false WHERE id=1')
            if r is not None:
                r=c.execute('UPDATE fw_runs SET revision=revision+1 WHERE id=%s RETURNING *',(r['id'],)).fetchone()
                self.event(c,r,'slot_reconciled',{'code':'OWNER_RELEASED_AFTER_CHILD_EXIT','fence':slot['fence'],'state':r['state']})
            return 'RELEASED'
    def operator_release_slot(self,operator,launch_scan=None):
        """Review F6: operator recovery for a slot that reconcile_training_slot retains
        forever (launching=true after a crash between begin_child and register_child, or a
        registered child with unknown creation time). Releases ONLY with proof:
          * owner pid+creation time known and the owner process is gone; and
          * a registered child (pid+creation time) is gone, or, when launching / child
            identity unknown, `launch_scan()` finds NO live process whose command line
            names this run's output directory (the only place a fieldwork child is pointed).
        Unknown owner identity is refused. Writes an audited 'slot_operator_released'
        event with the proof and bumps the run revision. Never changes run state.
        """
        with self.connect() as c:
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            if slot['run'] is None:return {'released':False,'reason':'SLOT_FREE'}
            if slot['owner_pid'] is None or slot['owner_created'] is None:return {'released':False,'reason':'OWNER_IDENTITY_UNKNOWN','slot':dict(slot)}
            if alive(slot['owner_pid'],slot['owner_created']):return {'released':False,'reason':'OWNER_ALIVE','slot':dict(slot)}
            proof={'owner_pid':slot['owner_pid'],'owner_created':slot['owner_created'],'owner':'GONE'}
            if slot['pid'] is not None and slot['child_created'] is not None and not slot['launching']:
                if alive(slot['pid'],slot['child_created']):return {'released':False,'reason':'CHILD_ALIVE','slot':dict(slot)}
                proof['child']='REGISTERED_CHILD_GONE'
            else:
                if launch_scan is None:return {'released':False,'reason':'CHILD_EXIT_UNPROVEN','slot':dict(slot)}
                matches=launch_scan(slot['run'])
                if matches:return {'released':False,'reason':'CANDIDATE_CHILD_ALIVE','matches':matches,'slot':dict(slot)}
                proof['child']='NO_PROCESS_NAMES_RUN_DIRECTORY';proof['launching']=slot['launching']
            c.execute('UPDATE fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL,launching=false WHERE id=1')
            r=c.execute('UPDATE fw_runs SET revision=revision+1 WHERE id=%s RETURNING *',(slot['run'],)).fetchone()
            if r is not None:self.event(c,r,'slot_reconciled',{'code':'OPERATOR_PROVEN_EXIT','operator':operator,'fence':slot['fence'],'state':r['state'],'proof':proof})
            return {'released':True,'run':slot['run'],'proof':proof}
    def reconcile_training_slot(self):
        """Free the host slot ONLY when physical exit of its owner and child is proven.

        A killed worker otherwise strands the single heavy slot forever (every later
        claim gets NOT_QUEUED_OR_SLOT_BUSY). Proof required, else retain:
        owner identity (pid+creation time) known and not alive; not launching (a
        crash between spawn intent and child registration is ambiguous); child
        identity absent or not alive. Run state, fence, revision, attempts and
        checkpoints are untouched: a still-'running' run is left to lease expiry
        (ML-Expire), a cancel_requested run stays pending until expiry. Active
        artifact stages are left to recover_artifacts.
        """
        with self.connect() as c:
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            if slot['run'] is None:return None
            r=c.execute('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE',(slot['run'],)).fetchone()
            if r is not None and r['state']=='succeeded' and r['artifact_status'] in ('pending','building','inference','retry_pending'):return 'ARTIFACT_RECOVERY_OWNS_SLOT'
            if slot['owner_pid'] is None or slot['owner_created'] is None:return 'OWNER_IDENTITY_UNKNOWN'
            if alive(slot['owner_pid'],slot['owner_created']):return 'OWNER_ALIVE'
            if slot['launching']:return 'CHILD_EXIT_UNCONFIRMED'
            if alive(slot['pid'],slot['child_created']):return 'CHILD_ALIVE'
            from .real_container_guard import model_cleanup_pending
            if model_cleanup_pending():return 'REAL_MODEL_CLEANUP_REQUIRED'
            c.execute('UPDATE fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL,launching=false WHERE id=1')
            if r is not None:
                # Review F7: a public change gets a fresh object revision (no state change).
                r=c.execute('UPDATE fw_runs SET revision=revision+1 WHERE id=%s RETURNING *',(r['id'],)).fetchone()
                self.event(c,r,'slot_reconciled',{'code':'OWNER_AND_CHILD_EXIT_CONFIRMED','fence':slot['fence'],'state':r['state']})
            return 'RELEASED'

    def restore_fence(self,source=None):
        """Product restore fencing (ML-T-RESTORE; review F1). Run once on a restored
        database BEFORE any worker or controller is enabled.

        In one transaction: issue a new fw_control.restore_generation; raise fence_floor
        to RESTORE_FENCE_GAP above every fence in the snapshot (new claims are issued
        above it); move leased/running runs to interrupted and cancel_requested to
        cancelled with their fence raised to the floor; clear the restored physical slot
        row (it describes processes on the pre-restore host). Every attempt that existed
        before carries the old generation, so start/heartbeat/checkpoint/complete from any
        pre-restore worker are refused (RESTORE_GENERATION_FENCED or FENCED).
        """
        with self.connect() as c:
            old=self.control(c,'UPDATE')
            top=c.execute('SELECT coalesce(max(fence),0) m FROM fw_runs').fetchone()['m']
            floor=max(top,old['fence_floor'])+RESTORE_FENCE_GAP;generation=str(uuid.uuid4())
            c.execute('UPDATE fw_control SET restore_generation=%s,fence_floor=%s,restored_at=clock_timestamp(),restore_source=%s,updated=clock_timestamp() WHERE id=1',(generation,floor,source))
            moved=[]
            for r in c.execute("SELECT * FROM fw_runs WHERE state IN ('leased','running','cancel_requested') ORDER BY id FOR UPDATE").fetchall():
                state='cancelled' if r['state']=='cancel_requested' else 'interrupted'
                n=c.execute('UPDATE fw_runs SET state=%s,fence=%s,revision=revision+1 WHERE id=%s RETURNING *',(state,floor,r['id'])).fetchone()
                self.event(c,n,'restore_fenced',{'state':state,'previous_state':r['state'],'fence':floor,'restore_generation':generation})
                moved.append({'run':r['id'],'from':r['state'],'to':state})
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            c.execute('UPDATE fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL,launching=false WHERE id=1')
            # Revoke every outstanding worker attempt credential (scoped identity installed).
            revoked=0
            if c.execute("SELECT to_regclass('fw_worker_cap_v1.credentials') IS NOT NULL ok").fetchone()['ok']:
                revoked=c.execute('DELETE FROM fw_worker_cap_v1.credentials').rowcount
            return {'worker_credentials_revoked':revoked,'previous_restore_generation':str(old['restore_generation']),'restore_generation':generation,
                    'fence_floor':floor,'max_snapshot_fence':top,'runs_fenced':moved,'slot_cleared_run':slot['run']}

    def resume(self,workspace,rid,replay_epoch):
        from .ml import validate_checkpoint
        with self.connect() as c:
            r=c.execute('SELECT * FROM fw_runs WHERE id=%s AND workspace=%s FOR UPDATE',(rid,workspace)).fetchone()
            if not r or r['state']!='interrupted' or not r['checkpoint'] or replay_epoch!=r['epoch']+1: raise Conflict('REPLAY_OR_STATE')
            cp=c.execute('SELECT digest,path FROM fw_checkpoints WHERE run=%s AND epoch=%s',(rid,r['epoch'])).fetchone()
            if not cp or cp['path']!=r['checkpoint']:raise Conflict('CHECKPOINT_POINTER_MISMATCH')
            validate_checkpoint(r['checkpoint'],expected_digest=cp['digest'])
            if c.execute('SELECT count(*) n FROM fw_attempts WHERE run=%s',(rid,)).fetchone()['n']>=3: raise Conflict('ATTEMPT_BUDGET')
            c.execute("UPDATE fw_runs SET state='queued',revision=revision+1 WHERE id=%s",(rid,));self.event(c,r,'resume_requested',{'state':'queued','replay_epoch':replay_epoch})
    def events(self,workspace,after=None):
        from .events import replay
        # Omitted cursor is a fresh seven-day replay, not an expired resume.
        return replay(self,workspace,after if after is not None else 0,check_expiry=after is not None)
