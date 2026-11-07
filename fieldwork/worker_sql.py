"""Fixed SQL for the scoped training-worker machine identity (fw_worker_cap_v1).

Every function is SECURITY DEFINER, owned by a NOLOGIN NOINHERIT definer role, with
search_path pinned to pg_catalog,pg_temp and schema-qualified objects. They bind
`session_user` (the worker login) to the protected scope row. The worker login has no
privilege on any public table: every read and write goes through these functions.

Credential model (ml-blueprint section 6, "Worker credential lifetime<=5min, renewed only
for live assignment"):
* the login password has a PostgreSQL VALID UNTIL <= 5 min, rotated by the operator-side
  issuer (fieldwork.worker_identity serve) only while the registered worker process is
  alive. An expired login is refused by the server at authentication;
* each claimed attempt gets a random attempt credential (only its SHA-256 is stored),
  valid 5 min and renewed only by ML-Heartbeat on the live lease, fence, cancel generation
  and restore generation. start/heartbeat/checkpoint/complete/fail require it.
"""

SCHEMA = 'fw_worker_cap_v1'
CREDENTIAL_SECONDS = 300

# name -> (signature, returns, language, volatility, body)
FUNCTIONS = {}


def fn(name, signature, returns, body, language='plpgsql', volatility='VOLATILE'):
    FUNCTIONS[name] = (signature, returns, language, volatility, body)


fn('allowed', 'p_workspace text', 'boolean', '''SELECT EXISTS(SELECT 1 FROM fw_worker_cap_v1.scope s
    WHERE s.principal=session_user AND p_workspace=ANY(s.workspaces))''', 'sql', 'STABLE')

fn('hash_token', 'p_token text', 'text', '''SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(coalesce(p_token,''),'UTF8')),'hex')''', 'sql', 'IMMUTABLE')

fn('deny', 'p_code text, p_state text, p_generation integer', 'void', '''BEGIN
    RAISE EXCEPTION '%', p_code USING ERRCODE='P0001',
        DETAIL=pg_catalog.jsonb_build_object('state',p_state,'current_generation',p_generation)::text;
END''')

fn('receipt', 'p_workspace text, p_command text, p_key text, p_request jsonb', 'jsonb', '''DECLARE prior record;
BEGIN
    IF p_key IS NULL THEN RETURN NULL; END IF;
    IF p_key::uuid::text <> p_key THEN PERFORM fw_worker_cap_v1.deny('IDEMPOTENCY_KEY_REQUIRED',NULL,NULL); END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_workspace||'|'||session_user||'|'||p_command||'|'||p_key,0));
    SELECT * INTO prior FROM public.fw_command_receipts
     WHERE workspace=p_workspace AND actor=session_user AND command=p_command AND key=p_key;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF prior.request_digest <> fw_worker_cap_v1.hash_token(p_request::text) THEN
        PERFORM fw_worker_cap_v1.deny('IDEMPOTENCY_CONFLICT',NULL,NULL);
    END IF;
    RETURN prior.response;
END''')

fn('store_receipt', 'p_workspace text, p_command text, p_key text, p_request jsonb, p_response jsonb, p_run text', 'void', '''BEGIN
    IF p_key IS NULL THEN RETURN; END IF;
    INSERT INTO public.fw_command_receipts(workspace,actor,command,key,request_digest,status,response,run)
    VALUES(p_workspace,session_user,p_command,p_key,fw_worker_cap_v1.hash_token(p_request::text),200,p_response,p_run);
END''')

fn('event', 'p_run text, p_kind text, p_payload jsonb', 'void', '''DECLARE r record;
BEGIN
    SELECT id,workspace,revision INTO r FROM public.fw_runs WHERE id=p_run;
    INSERT INTO public.fw_events(workspace,run,kind,payload,object_revision) VALUES(r.workspace,r.id,p_kind,p_payload,r.revision);
END''')

fn('check_live', 'p_token text, p_run text, p_attempt text, p_fence integer, p_generation integer, p_restore uuid, p_states text[], p_fenced text, p_expired text',
   'public.fw_runs', '''DECLARE r public.fw_runs; current_restore uuid; attempt_restore uuid;
BEGIN
    SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
    IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny(p_fenced,NULL,NULL); END IF;
    IF NOT EXISTS(SELECT 1 FROM fw_worker_cap_v1.credentials c
                   WHERE c.token_hash=fw_worker_cap_v1.hash_token(p_token) AND c.principal=session_user
                     AND c.run=p_run AND c.attempt=p_attempt AND c.expires_at>pg_catalog.clock_timestamp()) THEN
        PERFORM fw_worker_cap_v1.deny('CREDENTIAL_EXPIRED_OR_INVALID',NULL,NULL);
    END IF;
    IF r.cancel_generation IS NULL THEN PERFORM fw_worker_cap_v1.deny('CANCEL_GENERATION_UNVERIFIABLE',r.state,NULL); END IF;
    IF r.cancel_generation <> p_generation THEN PERFORM fw_worker_cap_v1.deny('CANCEL_GENERATION_FENCED',r.state,r.cancel_generation); END IF;
    IF NOT (r.state = ANY(p_states)) OR r.fence <> p_fence OR r.attempt IS DISTINCT FROM p_attempt THEN
        PERFORM fw_worker_cap_v1.deny(p_fenced,r.state,NULL);
    END IF;
    SELECT restore_generation INTO current_restore FROM public.fw_control WHERE id=1;
    SELECT restore_generation INTO attempt_restore FROM public.fw_attempts WHERE id=p_attempt;
    IF current_restore IS NULL OR p_restore IS DISTINCT FROM current_restore OR attempt_restore IS DISTINCT FROM current_restore THEN
        PERFORM fw_worker_cap_v1.deny('RESTORE_GENERATION_FENCED',r.state,NULL);
    END IF;
    IF p_expired IS NOT NULL AND r.lease<=pg_catalog.clock_timestamp() THEN PERFORM fw_worker_cap_v1.deny(p_expired,r.state,NULL); END IF;
    RETURN r;
END''')

fn('next_run', 'p_skip text[]', 'jsonb', '''SELECT pg_catalog.jsonb_build_object('id',r.id,'revision',r.revision)
    FROM public.fw_runs r
    WHERE fw_worker_cap_v1.allowed(r.workspace)
      AND (r.state='queued' OR (r.state='succeeded' AND r.artifact_status='retry_pending'))
      AND r.config->>'scope'='synthetic-execution-only'
      AND NOT ((r.id||'@'||r.revision)=ANY(coalesce(p_skip,'{}')))
    ORDER BY r.id LIMIT 1''', 'sql', 'STABLE')

fn('get_run', 'p_run text', 'jsonb', '''SELECT pg_catalog.to_jsonb(r) FROM public.fw_runs r
    WHERE r.id=p_run AND fw_worker_cap_v1.allowed(r.workspace)''', 'sql', 'STABLE')

fn('get_checkpoint', 'p_run text, p_epoch integer', 'jsonb', '''SELECT pg_catalog.jsonb_build_object('digest',cp.digest,'path',cp.path)
    FROM public.fw_checkpoints cp JOIN public.fw_runs r ON r.id=cp.run
    WHERE cp.run=p_run AND cp.epoch=p_epoch AND fw_worker_cap_v1.allowed(r.workspace)''', 'sql', 'STABLE')

fn('claim', 'p_run text, p_check_generation boolean, p_expected_generation integer, p_worker text, p_owner_pid integer, p_owner_created double precision, p_key text',
   'jsonb', '''DECLARE r public.fw_runs; sl record; ctl record; req jsonb; prior jsonb; aid text; new_fence int; gen int; token text; resp jsonb;
BEGIN
    SELECT * INTO ctl FROM public.fw_control WHERE id=1;
    IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('RESTORE_GENERATION_SCHEMA_REQUIRED',NULL,NULL); END IF;
    SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
    SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
    IF NOT FOUND THEN PERFORM fw_worker_cap_v1.deny('NOT_QUEUED_OR_SLOT_BUSY',NULL,NULL); END IF;
    req := pg_catalog.jsonb_build_object('run_id',p_run,'worker_id',p_worker,'check_generation',p_check_generation,'expected_cancel_generation',p_expected_generation);
    prior := fw_worker_cap_v1.receipt(r.workspace,'ML-Claim',p_key,req);
    IF prior IS NOT NULL THEN
        -- Replay: the same attempt, if it is still this run's current leased attempt,
        -- gets a fresh attempt credential (only its hash is stored); never a new claim.
        IF r.attempt IS DISTINCT FROM prior->>'attempt_id' OR r.state NOT IN ('leased','running') THEN
            PERFORM fw_worker_cap_v1.deny('FENCED_OR_EXPIRED_OR_CANCELLED',r.state,NULL);
        END IF;
        aid := r.attempt;
    ELSE
        IF r.state<>'queued' OR sl.run IS NOT NULL THEN PERFORM fw_worker_cap_v1.deny('NOT_QUEUED_OR_SLOT_BUSY',r.state,NULL); END IF;
        IF r.config->>'scope' IS DISTINCT FROM 'synthetic-execution-only' THEN PERFORM fw_worker_cap_v1.deny('UNTRUSTED_PROFILE_BLOCKED',r.state,NULL); END IF;
        IF p_check_generation AND r.cancel_generation IS DISTINCT FROM p_expected_generation THEN
            PERFORM fw_worker_cap_v1.deny('CANCEL_GENERATION_CHANGED',r.state,r.cancel_generation);
        END IF;
        gen := coalesce(r.cancel_generation,0);
        aid := pg_catalog.gen_random_uuid()::text;
        new_fence := GREATEST(r.fence,ctl.fence_floor)+1;
        INSERT INTO public.fw_attempts(id,run,fence,cancel_generation,restore_generation,worker_id)
            VALUES(aid,p_run,new_fence,gen,ctl.restore_generation,session_user||':'||p_worker);
        UPDATE public.fw_slot SET run=p_run,fence=new_fence,owner_pid=p_owner_pid,owner_created=p_owner_created,
            pid=NULL,child_created=NULL,launching=false WHERE id=1;
        UPDATE public.fw_runs SET state='leased',fence=new_fence,attempt=aid,cancel_generation=gen,
            lease=pg_catalog.clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=p_run RETURNING * INTO r;
        PERFORM fw_worker_cap_v1.event(p_run,'claimed',pg_catalog.jsonb_build_object('state','leased','attempt',aid,'fence',new_fence,
            'cancel_generation',gen,'restore_generation',ctl.restore_generation,'worker',session_user));
        resp := pg_catalog.jsonb_build_object('attempt_id',aid,'fence',new_fence,'lease_expires_at',r.lease,
            'job_manifest_digest',r.digest,'cancel_generation',gen,'restore_generation',ctl.restore_generation);
        PERFORM fw_worker_cap_v1.store_receipt(r.workspace,'ML-Claim',p_key,req,resp,p_run);
    END IF;
    token := fw_worker_cap_v1.hash_token(pg_catalog.gen_random_uuid()::text||pg_catalog.gen_random_uuid()::text);
    INSERT INTO fw_worker_cap_v1.credentials(token_hash,principal,run,attempt,expires_at)
        VALUES(fw_worker_cap_v1.hash_token(token),session_user,p_run,aid,pg_catalog.clock_timestamp()+interval '300 seconds');
    RETURN pg_catalog.to_jsonb(r)||pg_catalog.jsonb_build_object('restore_generation',ctl.restore_generation,'credential',token);
END''')

fn('start', 'p_token text, p_run text, p_attempt text, p_fence integer, p_generation integer, p_digest text, p_restore uuid, p_key text',
   'jsonb', '''DECLARE r public.fw_runs; req jsonb; prior jsonb; resp jsonb; w text;
BEGIN
    SELECT workspace INTO w FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace);
    req := pg_catalog.jsonb_build_object('attempt_id',p_attempt,'fence',p_fence,'cancel_generation',p_generation,'resolved_config_digest',p_digest,'restore_generation',p_restore);
    prior := fw_worker_cap_v1.receipt(coalesce(w,''),'ML-Start',p_key,req);
    IF prior IS NOT NULL THEN RETURN prior; END IF;
    r := fw_worker_cap_v1.check_live(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,ARRAY['leased'],'FENCED','LEASE_EXPIRED');
    IF r.digest <> p_digest THEN PERFORM fw_worker_cap_v1.deny('FENCED',r.state,NULL); END IF;
    UPDATE public.fw_runs SET state='running',lease=pg_catalog.clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=p_run RETURNING * INTO r;
    UPDATE public.fw_attempts SET started_at=pg_catalog.clock_timestamp() WHERE id=p_attempt;
    PERFORM fw_worker_cap_v1.event(p_run,'started',pg_catalog.jsonb_build_object('state','running','attempt',p_attempt,'fence',p_fence));
    resp := pg_catalog.jsonb_build_object('state','running','revision',r.revision,'lease_expires_at',r.lease);
    PERFORM fw_worker_cap_v1.store_receipt(r.workspace,'ML-Start',p_key,req,resp,p_run);
    RETURN resp;
END''')

fn('heartbeat', 'p_token text, p_run text, p_attempt text, p_fence integer, p_generation integer, p_restore uuid, p_key text',
   'jsonb', '''DECLARE r public.fw_runs; req jsonb; prior jsonb; resp jsonb;
BEGIN
    r := fw_worker_cap_v1.check_live(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,ARRAY['running'],'FENCED_OR_EXPIRED_OR_CANCELLED','FENCED_OR_EXPIRED_OR_CANCELLED');
    req := pg_catalog.jsonb_build_object('attempt_id',p_attempt,'fence',p_fence,'cancel_generation',p_generation);
    prior := fw_worker_cap_v1.receipt(r.workspace,'ML-Heartbeat',p_key,req);
    IF prior IS NOT NULL THEN RETURN prior; END IF;
    UPDATE public.fw_runs SET lease=pg_catalog.clock_timestamp()+interval '45 seconds' WHERE id=p_run RETURNING * INTO r;
    -- Renewal only here: the assignment was just proven live.
    UPDATE fw_worker_cap_v1.credentials SET expires_at=pg_catalog.clock_timestamp()+interval '300 seconds'
     WHERE token_hash=fw_worker_cap_v1.hash_token(p_token) AND principal=session_user AND attempt=p_attempt;
    resp := pg_catalog.jsonb_build_object('lease_expires_at',r.lease,'cancel_requested',false);
    PERFORM fw_worker_cap_v1.store_receipt(r.workspace,'ML-Heartbeat',p_key,req,resp,p_run);
    RETURN resp;
END''')

fn('publish', 'p_token text, p_run text, p_attempt text, p_fence integer, p_generation integer, p_restore uuid, p_epoch integer, p_digest text, p_path text, p_metrics jsonb, p_meta jsonb, p_key text',
   'jsonb', '''DECLARE r public.fw_runs; req jsonb; prior jsonb; existing record; resp jsonb;
BEGIN
    r := fw_worker_cap_v1.check_live(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,ARRAY['running'],'FENCED_OR_EXPIRED_OR_CANCELLED','FENCED_OR_EXPIRED_OR_CANCELLED');
    req := pg_catalog.jsonb_build_object('attempt_id',p_attempt,'fence',p_fence,'cancel_generation',p_generation,'epoch',p_epoch,'manifest_digest',p_digest,'metrics',p_metrics);
    prior := fw_worker_cap_v1.receipt(r.workspace,'ML-CheckpointCommit',p_key,req);
    IF prior IS NOT NULL THEN RETURN prior; END IF;
    IF p_digest !~ '^[0-9a-f]{64}$' THEN PERFORM fw_worker_cap_v1.deny('FILE_DIGEST_OR_SCHEMA',r.state,NULL); END IF;
    IF p_meta->>'dataset_digest' IS DISTINCT FROM r.config->>'dataset_digest' OR (p_meta->>'epoch')::int IS DISTINCT FROM p_epoch
       OR (p_meta->>'next_epoch')::int IS DISTINCT FROM p_epoch+1 THEN
        PERFORM fw_worker_cap_v1.deny('CHECKPOINT_LINEAGE',r.state,NULL);
    END IF;
    IF (r.config ? 'seed' AND p_meta->'seed' IS DISTINCT FROM r.config->'seed')
       OR (r.config ? 'learning_rate' AND (p_meta->'groups'->0->>'lr')::numeric IS DISTINCT FROM (r.config->>'learning_rate')::numeric)
       OR p_metrics IS DISTINCT FROM pg_catalog.jsonb_build_object('epoch',p_meta->'epoch','train_loss',p_meta->'train_loss','validation_loss',p_meta->'validation_loss','updates',p_meta->'updates') THEN
        PERFORM fw_worker_cap_v1.deny('CHECKPOINT_LINEAGE_OR_METRICS',r.state,NULL);
    END IF;
    SELECT * INTO existing FROM public.fw_checkpoints WHERE run=p_run AND epoch=p_epoch;
    IF FOUND THEN
        IF existing.digest=p_digest AND existing.attempt=r.attempt THEN RETURN pg_catalog.jsonb_build_object('state','committed','path',existing.path); END IF;
        PERFORM fw_worker_cap_v1.deny('CHECKPOINT_CONFLICT',r.state,NULL);
    END IF;
    IF p_epoch <> r.epoch+1 THEN PERFORM fw_worker_cap_v1.deny('EPOCH_ORDER',r.state,NULL); END IF;
    INSERT INTO public.fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES(p_run,p_epoch,r.attempt,p_digest,p_path,p_metrics);
    UPDATE public.fw_runs SET epoch=p_epoch,checkpoint=p_path,revision=revision+1 WHERE id=p_run;
    PERFORM fw_worker_cap_v1.event(p_run,'epoch_committed',p_metrics||pg_catalog.jsonb_build_object('manifest_digest',p_digest,'attempt',r.attempt));
    resp := pg_catalog.jsonb_build_object('state','committed','path',p_path);
    PERFORM fw_worker_cap_v1.store_receipt(r.workspace,'ML-CheckpointCommit',p_key,req,resp,p_run);
    RETURN resp;
END''')

fn('complete', 'p_token text, p_run text, p_attempt text, p_fence integer, p_generation integer, p_restore uuid, p_result jsonb, p_owner_pid integer, p_owner_created double precision, p_child_exited boolean, p_key text',
   'jsonb', '''DECLARE r public.fw_runs; sl record; req jsonb; prior jsonb; resp jsonb;
BEGIN
    SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
    r := fw_worker_cap_v1.check_live(p_token,p_run,p_attempt,p_fence,p_generation,p_restore,ARRAY['running'],'FENCED_OR_EXPIRED_OR_CANCELLED','FENCED_OR_EXPIRED_OR_CANCELLED');
    req := pg_catalog.jsonb_build_object('attempt_id',p_attempt,'fence',p_fence,'cancel_generation',p_generation,'epoch_report_digest',fw_worker_cap_v1.hash_token(p_result::text));
    prior := fw_worker_cap_v1.receipt(r.workspace,'ML-Complete',p_key,req);
    IF prior IS NOT NULL THEN RETURN prior; END IF;
    IF r.epoch IS DISTINCT FROM (r.config->>'epochs')::int THEN PERFORM fw_worker_cap_v1.deny('INCOMPLETE',r.state,NULL); END IF;
    IF sl.run IS DISTINCT FROM p_run OR sl.fence IS DISTINCT FROM p_fence OR sl.owner_pid IS DISTINCT FROM p_owner_pid
       OR sl.owner_created IS DISTINCT FROM p_owner_created OR sl.launching OR NOT p_child_exited THEN
        PERFORM fw_worker_cap_v1.deny('CHILD_EXIT_OR_OWNER_UNCONFIRMED',r.state,NULL);
    END IF;
    UPDATE public.fw_runs SET state='succeeded',result=p_result,artifact_status='pending',artifact_result='{"code":"ARTIFACT_PENDING"}'::jsonb,
        artifact_attempts=1,artifact_owner_pid=p_owner_pid,artifact_owner_created=p_owner_created,
        lease=pg_catalog.clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=p_run RETURNING * INTO r;
    UPDATE public.fw_attempts SET ended_at=pg_catalog.clock_timestamp() WHERE id=p_attempt;
    DELETE FROM fw_worker_cap_v1.credentials WHERE attempt=p_attempt AND principal=session_user;
    PERFORM fw_worker_cap_v1.event(p_run,'succeeded',pg_catalog.jsonb_build_object('state','succeeded','attempt',p_attempt,'fence',p_fence));
    PERFORM fw_worker_cap_v1.event(p_run,'artifact_pending','{"code":"ARTIFACT_PENDING"}'::jsonb);
    resp := pg_catalog.jsonb_build_object('state','succeeded','revision',r.revision);
    PERFORM fw_worker_cap_v1.store_receipt(r.workspace,'ML-Complete',p_key,req,resp,p_run);
    RETURN resp;
END''')

fn('fail', 'p_token text, p_run text, p_attempt text, p_fence integer, p_code text, p_retryable boolean, p_diagnostics text, p_restore uuid, p_key text',
   'jsonb', '''DECLARE r public.fw_runs; req jsonb; prior jsonb; resp jsonb; n int; new_state text; gen int;
BEGIN
    SELECT cancel_generation INTO gen FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace);
    r := fw_worker_cap_v1.check_live(p_token,p_run,p_attempt,p_fence,coalesce(gen,-1),p_restore,ARRAY['leased','running'],'FENCED',NULL);
    req := pg_catalog.jsonb_build_object('attempt_id',p_attempt,'fence',p_fence,'error_code',p_code,'retryable',p_retryable,'diagnostics_digest',p_diagnostics);
    prior := fw_worker_cap_v1.receipt(r.workspace,'ML-Fail',p_key,req);
    IF prior IS NOT NULL THEN RETURN prior; END IF;
    IF p_diagnostics !~ '^[0-9a-f]{64}$' OR p_code IS NULL OR length(p_code) NOT BETWEEN 1 AND 120 THEN PERFORM fw_worker_cap_v1.deny('FAIL_REQUEST_INVALID',r.state,NULL); END IF;
    SELECT count(*) INTO n FROM public.fw_attempts WHERE run=p_run;
    new_state := CASE WHEN p_retryable AND n<3 THEN 'interrupted' ELSE 'failed' END;
    UPDATE public.fw_runs SET state=new_state,fence=fence+1,revision=revision+1 WHERE id=p_run AND fence=p_fence AND attempt=p_attempt RETURNING * INTO r;
    UPDATE public.fw_attempts SET ended_at=pg_catalog.clock_timestamp() WHERE id=p_attempt;
    DELETE FROM fw_worker_cap_v1.credentials WHERE attempt=p_attempt AND principal=session_user;
    PERFORM fw_worker_cap_v1.event(p_run,new_state,pg_catalog.jsonb_build_object('state',new_state,'code',p_code,'retryable',p_retryable,'attempt',p_attempt,'diagnostics_digest',p_diagnostics));
    resp := pg_catalog.jsonb_build_object('state',new_state);
    PERFORM fw_worker_cap_v1.store_receipt(r.workspace,'ML-Fail',p_key,req,resp,p_run);
    RETURN resp;
END''')

fn('release_slot', 'p_run text, p_fence integer, p_generation integer, p_exit_digest text, p_lease_expired boolean, p_owner_pid integer, p_owner_created double precision, p_child_exited boolean, p_key text',
   'text', '''DECLARE sl record; r public.fw_runs; req jsonb; prior jsonb; w text;
BEGIN
    SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
    SELECT workspace INTO w FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace);
    IF w IS NULL THEN PERFORM fw_worker_cap_v1.deny('SLOT_OWNER_FENCED',NULL,NULL); END IF;
    IF p_exit_digest IS NOT NULL AND p_exit_digest !~ '^[0-9a-f]{64}$' THEN PERFORM fw_worker_cap_v1.deny('EXIT_RECEIPT_INVALID',NULL,NULL); END IF;
    req := pg_catalog.jsonb_build_object('run_id',p_run,'fence',p_fence,'cancel_generation',p_generation,'exit_receipt_digest',p_exit_digest,'lease_expired',p_lease_expired);
    IF p_generation IS NOT NULL THEN
        prior := fw_worker_cap_v1.receipt(w,'ML-AcknowledgeCancel',p_key,req);
        IF prior IS NOT NULL THEN RETURN prior->>'state'; END IF;
    END IF;
    IF sl.run IS DISTINCT FROM p_run THEN
        IF p_generation IS NULL THEN RETURN NULL; END IF;
        SELECT * INTO r FROM public.fw_runs WHERE id=p_run FOR UPDATE;
        IF r.cancel_generation IS DISTINCT FROM p_generation OR r.state NOT IN ('cancel_requested','cancelled') THEN
            PERFORM fw_worker_cap_v1.deny('WRONG_GENERATION',r.state,r.cancel_generation);
        END IF;
        RETURN r.state;
    END IF;
    IF (p_fence IS NOT NULL AND p_fence IS DISTINCT FROM sl.fence) OR sl.owner_pid IS DISTINCT FROM p_owner_pid OR sl.owner_created IS DISTINCT FROM p_owner_created THEN
        PERFORM fw_worker_cap_v1.deny('SLOT_OWNER_FENCED',NULL,NULL);
    END IF;
    IF sl.launching OR NOT p_child_exited THEN PERFORM fw_worker_cap_v1.deny('CHILD_EXIT_UNCONFIRMED',NULL,NULL); END IF;
    IF p_generation IS NOT NULL THEN
        SELECT * INTO r FROM public.fw_runs WHERE id=p_run FOR UPDATE;
        IF r.cancel_generation IS DISTINCT FROM p_generation OR r.state NOT IN ('cancel_requested','cancelled') THEN
            PERFORM fw_worker_cap_v1.deny('WRONG_GENERATION',r.state,r.cancel_generation);
        END IF;
    END IF;
    UPDATE public.fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL WHERE id=1;
    IF p_generation IS NULL THEN RETURN NULL; END IF;
    IF r.attempt IS NOT NULL AND p_exit_digest IS NOT NULL THEN
        UPDATE public.fw_attempts SET exit_receipt_digest=coalesce(exit_receipt_digest,p_exit_digest),
            ended_at=coalesce(ended_at,pg_catalog.clock_timestamp()) WHERE id=r.attempt;
    END IF;
    IF r.state<>'cancelled' THEN
        UPDATE public.fw_runs SET state='cancelled',revision=revision+1 WHERE id=p_run AND state='cancel_requested' AND cancel_generation=p_generation;
        PERFORM fw_worker_cap_v1.event(p_run,'cancelled',pg_catalog.jsonb_build_object('state','cancelled','cancel_generation',p_generation,
            'attempt',r.attempt,'exit_receipt_digest',p_exit_digest,'lease_expired',p_lease_expired));
    END IF;
    DELETE FROM fw_worker_cap_v1.credentials WHERE run=p_run AND principal=session_user;
    PERFORM fw_worker_cap_v1.store_receipt(w,'ML-AcknowledgeCancel',p_key,req,pg_catalog.jsonb_build_object('state','cancelled','exit_receipt_digest',p_exit_digest),p_run);
    RETURN 'cancelled';
END''')

fn('artifact_lock', 'p_run text, p_fence integer, p_owner_pid integer, p_owner_created double precision, p_expired_ok boolean', 'public.fw_runs', '''DECLARE sl record; r public.fw_runs;
BEGIN
    SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
    SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
    IF NOT FOUND OR r.state<>'succeeded' OR r.fence<>p_fence OR sl.run IS DISTINCT FROM p_run OR sl.fence IS DISTINCT FROM p_fence
       OR sl.owner_pid IS DISTINCT FROM p_owner_pid OR sl.owner_created IS DISTINCT FROM p_owner_created
       OR (NOT p_expired_ok AND r.lease<=pg_catalog.clock_timestamp()) THEN
        PERFORM fw_worker_cap_v1.deny('ARTIFACT_FENCED_OR_EXPIRED_OR_OWNER',NULL,NULL);
    END IF;
    RETURN r;
END''')

fn('begin_child', 'p_run text, p_fence integer, p_owner_pid integer, p_owner_created double precision, p_child_alive boolean, p_artifact boolean', 'void', '''DECLARE sl record;
BEGIN
    SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
    IF NOT EXISTS(SELECT 1 FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace)) THEN PERFORM fw_worker_cap_v1.deny('CHILD_SLOT_BUSY_OR_FENCED',NULL,NULL); END IF;
    IF p_artifact THEN PERFORM fw_worker_cap_v1.artifact_lock(p_run,p_fence,p_owner_pid,p_owner_created,false); END IF;
    IF sl.run IS DISTINCT FROM p_run OR sl.fence IS DISTINCT FROM p_fence OR sl.owner_pid IS DISTINCT FROM p_owner_pid
       OR sl.owner_created IS DISTINCT FROM p_owner_created OR sl.launching OR p_child_alive THEN
        PERFORM fw_worker_cap_v1.deny('CHILD_SLOT_BUSY_OR_FENCED',NULL,NULL);
    END IF;
    UPDATE public.fw_slot SET launching=true,pid=NULL,child_created=NULL WHERE id=1;
END''')

fn('register_child', 'p_run text, p_fence integer, p_owner_pid integer, p_owner_created double precision, p_child_pid integer, p_child_created double precision', 'void', '''DECLARE sl record;
BEGIN
    SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
    IF sl.run IS DISTINCT FROM p_run OR sl.fence IS DISTINCT FROM p_fence OR sl.owner_pid IS DISTINCT FROM p_owner_pid
       OR sl.owner_created IS DISTINCT FROM p_owner_created OR NOT sl.launching THEN
        PERFORM fw_worker_cap_v1.deny('CHILD_REGISTRATION_FENCED',NULL,NULL);
    END IF;
    UPDATE public.fw_slot SET launching=false,pid=CASE WHEN p_child_created IS NULL THEN NULL ELSE p_child_pid END,child_created=p_child_created WHERE id=1;
END''')

fn('child_spawn_failed', 'p_run text, p_fence integer, p_owner_pid integer, p_owner_created double precision', 'void', '''BEGIN
    UPDATE public.fw_slot SET launching=false WHERE id=1 AND run=p_run AND fence=p_fence AND owner_pid=p_owner_pid AND owner_created=p_owner_created;
END''')

fn('slot_status', '', 'jsonb', '''SELECT pg_catalog.to_jsonb(s)||pg_catalog.jsonb_build_object(
        'run_in_scope',r.id IS NOT NULL,'run_state',r.state,'run_fence',r.fence,'artifact_status',r.artifact_status)
    FROM public.fw_slot s LEFT JOIN public.fw_runs r ON r.id=s.run AND fw_worker_cap_v1.allowed(r.workspace) WHERE s.id=1''', 'sql', 'STABLE')

fn('slot_release_if', 'p_expected jsonb, p_code text', 'text', '''DECLARE sl record; r public.fw_runs;
BEGIN
    IF p_code NOT IN ('OWNER_AND_CHILD_EXIT_CONFIRMED','OWNER_RELEASED_AFTER_CHILD_EXIT') THEN PERFORM fw_worker_cap_v1.deny('SLOT_CODE_INVALID',NULL,NULL); END IF;
    SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
    IF sl.run IS NULL THEN RETURN NULL; END IF;
    IF sl.run IS DISTINCT FROM p_expected->>'run' OR sl.fence IS DISTINCT FROM (p_expected->>'fence')::int
       OR sl.owner_pid IS DISTINCT FROM (p_expected->>'owner_pid')::int OR sl.owner_created IS DISTINCT FROM (p_expected->>'owner_created')::double precision
       OR sl.pid IS DISTINCT FROM (p_expected->>'pid')::int OR sl.child_created IS DISTINCT FROM (p_expected->>'child_created')::double precision
       OR sl.launching IS DISTINCT FROM (p_expected->>'launching')::boolean THEN
        RETURN 'SLOT_CHANGED';
    END IF;
    SELECT * INTO r FROM public.fw_runs WHERE id=sl.run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
    IF NOT FOUND THEN RETURN 'OUT_OF_SCOPE'; END IF;
    IF p_code='OWNER_RELEASED_AFTER_CHILD_EXIT' AND r.state IN ('leased','running') AND r.fence=sl.fence THEN RETURN 'OWN_RUN_ACTIVE'; END IF;
    IF r.state='succeeded' AND r.artifact_status IN ('pending','building','inference','retry_pending') THEN RETURN 'ARTIFACT_RECOVERY_OWNS_SLOT'; END IF;
    UPDATE public.fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL,launching=false WHERE id=1;
    UPDATE public.fw_runs SET revision=revision+1 WHERE id=r.id;
    PERFORM fw_worker_cap_v1.event(r.id,'slot_reconciled',pg_catalog.jsonb_build_object('code',p_code,'fence',sl.fence,'state',r.state));
    RETURN 'RELEASED';
END''')

fn('claim_artifacts', 'p_run text, p_owner_pid integer, p_owner_created double precision', 'jsonb', '''DECLARE sl record; r public.fw_runs; new_fence int;
BEGIN
    SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
    SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
    IF NOT FOUND OR r.state<>'succeeded' OR r.artifact_status NOT IN ('retry_pending','failed') OR sl.run IS NOT NULL THEN
        PERFORM fw_worker_cap_v1.deny('ARTIFACT_NOT_RETRYABLE_OR_SLOT_BUSY',NULL,NULL);
    END IF;
    IF r.artifact_attempts>=3 THEN PERFORM fw_worker_cap_v1.deny('ARTIFACT_ATTEMPT_BUDGET',NULL,NULL); END IF;
    new_fence := r.fence+1;
    UPDATE public.fw_slot SET run=p_run,fence=new_fence,owner_pid=p_owner_pid,owner_created=p_owner_created,pid=NULL,child_created=NULL,launching=false WHERE id=1;
    UPDATE public.fw_runs SET fence=new_fence,artifact_status='pending',artifact_result='{"code":"ARTIFACT_RETRY_PENDING"}'::jsonb,
        artifact_attempts=artifact_attempts+1,artifact_owner_pid=p_owner_pid,artifact_owner_created=p_owner_created,
        lease=pg_catalog.clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=p_run RETURNING * INTO r;
    PERFORM fw_worker_cap_v1.event(p_run,'artifact_pending',pg_catalog.jsonb_build_object('code','ARTIFACT_RETRY_PENDING','fence',new_fence));
    RETURN pg_catalog.to_jsonb(r);
END''')

fn('artifact_heartbeat', 'p_run text, p_fence integer, p_owner_pid integer, p_owner_created double precision', 'void', '''BEGIN
    PERFORM fw_worker_cap_v1.artifact_lock(p_run,p_fence,p_owner_pid,p_owner_created,false);
    UPDATE public.fw_runs SET lease=pg_catalog.clock_timestamp()+interval '45 seconds' WHERE id=p_run;
END''')

fn('artifact_transition', 'p_run text, p_fence integer, p_status text, p_detail jsonb, p_owner_pid integer, p_owner_created double precision, p_child_exited boolean', 'void', '''DECLARE r public.fw_runs; sl record; allowed_next text[];
BEGIN
    r := fw_worker_cap_v1.artifact_lock(p_run,p_fence,p_owner_pid,p_owner_created,p_status='failed');
    SELECT * INTO sl FROM public.fw_slot WHERE id=1;
    allowed_next := CASE r.artifact_status WHEN 'pending' THEN ARRAY['building','failed'] WHEN 'building' THEN ARRAY['inference','failed']
                                           WHEN 'inference' THEN ARRAY['verified','failed'] ELSE ARRAY[]::text[] END;
    IF NOT (p_status = ANY(allowed_next)) THEN PERFORM fw_worker_cap_v1.deny('ARTIFACT_STAGE_ORDER',NULL,NULL); END IF;
    IF p_status='verified' AND (sl.launching OR NOT p_child_exited) THEN PERFORM fw_worker_cap_v1.deny('ARTIFACT_CHILD_NOT_EXITED',NULL,NULL); END IF;
    UPDATE public.fw_runs SET artifact_status=p_status,artifact_result=p_detail,revision=revision+1 WHERE id=p_run;
    PERFORM fw_worker_cap_v1.event(p_run,'artifact_'||p_status,pg_catalog.jsonb_build_object('status',p_status)||p_detail);
    IF p_status IN ('failed','verified') AND NOT sl.launching AND p_child_exited THEN
        UPDATE public.fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL WHERE id=1;
    END IF;
END''')

fn('artifact_orphans', '', 'jsonb', '''SELECT pg_catalog.jsonb_build_object('slot',(SELECT pg_catalog.to_jsonb(s) FROM public.fw_slot s WHERE s.id=1),
    'rows',coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id',r.id,'fence',r.fence,'artifact_status',r.artifact_status,
        'artifact_attempts',r.artifact_attempts,'artifact_owner_pid',r.artifact_owner_pid,'artifact_owner_created',r.artifact_owner_created,
        'artifact_result',r.artifact_result) ORDER BY r.id)
      FROM public.fw_runs r WHERE fw_worker_cap_v1.allowed(r.workspace) AND r.state='succeeded'
        AND (r.artifact_status IN ('pending','building','inference')
             OR (r.id=(SELECT run FROM public.fw_slot WHERE id=1) AND r.artifact_status IN ('failed','verified')))
        AND r.lease<pg_catalog.clock_timestamp()),'[]'::jsonb))''', 'sql', 'STABLE')

fn('artifact_recover', 'p_run text, p_fence integer, p_status text, p_detail jsonb, p_clear_slot boolean, p_expected_slot jsonb', 'boolean', '''DECLARE sl record; r public.fw_runs;
BEGIN
    SELECT * INTO sl FROM public.fw_slot WHERE id=1 FOR UPDATE;
    SELECT * INTO r FROM public.fw_runs WHERE id=p_run AND fw_worker_cap_v1.allowed(workspace) FOR UPDATE;
    IF NOT FOUND OR r.fence<>p_fence OR r.state<>'succeeded' OR r.lease>=pg_catalog.clock_timestamp() THEN RETURN false; END IF;
    IF p_clear_slot AND (sl.run IS DISTINCT FROM p_expected_slot->>'run' OR sl.fence IS DISTINCT FROM (p_expected_slot->>'fence')::int
       OR sl.owner_pid IS DISTINCT FROM (p_expected_slot->>'owner_pid')::int OR sl.owner_created IS DISTINCT FROM (p_expected_slot->>'owner_created')::double precision
       OR sl.pid IS DISTINCT FROM (p_expected_slot->>'pid')::int OR sl.launching IS DISTINCT FROM (p_expected_slot->>'launching')::boolean) THEN
        RETURN false;
    END IF;
    IF p_status IS NULL THEN
        IF r.artifact_status NOT IN ('failed','verified') OR NOT p_clear_slot THEN RETURN false; END IF;
    ELSE
        IF r.artifact_status NOT IN ('pending','building','inference') OR p_status NOT IN ('retry_pending','failed') THEN RETURN false; END IF;
        UPDATE public.fw_runs SET fence=fence+1,artifact_status=p_status,artifact_result=p_detail,revision=revision+1 WHERE id=p_run;
        PERFORM fw_worker_cap_v1.event(p_run,'artifact_'||p_status,p_detail);
    END IF;
    IF p_clear_slot THEN
        UPDATE public.fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL WHERE id=1;
    END IF;
    RETURN true;
END''')

# Callable by the worker login. Everything else is an internal helper of the definer.
PUBLIC_API = ['next_run', 'get_run', 'get_checkpoint', 'claim', 'start', 'heartbeat', 'publish', 'complete', 'fail',
              'release_slot', 'begin_child', 'register_child', 'child_spawn_failed', 'slot_status', 'slot_release_if',
              'claim_artifacts', 'artifact_heartbeat', 'artifact_transition', 'artifact_orphans', 'artifact_recover']

DEFINER_GRANTS = [
    'GRANT USAGE ON SCHEMA public TO {d}',
    'GRANT SELECT ON public.fw_runs TO {d}',
    'GRANT UPDATE (state,fence,attempt,cancel_generation,lease,revision,epoch,checkpoint,result,artifact_status,artifact_result,artifact_attempts,artifact_owner_pid,artifact_owner_created) ON public.fw_runs TO {d}',
    'GRANT SELECT, INSERT ON public.fw_attempts TO {d}',
    'GRANT UPDATE (started_at,ended_at,exit_receipt_digest) ON public.fw_attempts TO {d}',
    'GRANT SELECT, INSERT ON public.fw_checkpoints TO {d}',
    'GRANT INSERT ON public.fw_events TO {d}',
    'GRANT USAGE ON SEQUENCE public.fw_events_seq_seq TO {d}',
    'GRANT SELECT, UPDATE ON public.fw_slot TO {d}',
    'GRANT SELECT ON public.fw_control TO {d}',
    'GRANT SELECT, INSERT ON public.fw_command_receipts TO {d}',
]
# fw_runs/fw_events carry workspace; attempts/checkpoints follow their run.
POLICY_TABLES = {'fw_runs': 'fw_worker_cap_v1.allowed(workspace)',
                 'fw_events': 'fw_worker_cap_v1.allowed(workspace)',
                 'fw_attempts': 'EXISTS(SELECT 1 FROM public.fw_runs r WHERE r.id=run AND fw_worker_cap_v1.allowed(r.workspace))',
                 'fw_checkpoints': 'EXISTS(SELECT 1 FROM public.fw_runs r WHERE r.id=run AND fw_worker_cap_v1.allowed(r.workspace))'}
