"""Supervisor owns DB publication. Model children receive no DB/session credentials."""
import json, time, uuid
from pathlib import Path


def command_key(attempt, command, *parts):
    """Deterministic internal-command Idempotency-Key: a retry after a lost response
    replays the stored receipt instead of repeating the effect."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'urn:fieldwork:internal:' + ':'.join([str(attempt), command, *map(str, parts)])))


def watch(store, attempt, process, output, stop_at_pause=False, timeout=180):
    # Carry the generation issued at claim on every publication call; never reread
    # the current one to authorize work. `observed_cancel_generation` is recorded on
    # the attempt only when a cancel is actually observed, for the caller's exit ack.
    output=Path(output);rid=attempt['id'];fence=attempt['fence'];generation=attempt['cancel_generation'];deadline=time.monotonic()+timeout;heartbeat=0;beats=0
    # Review F1: every publication call names the exact attempt and its restore generation.
    scope=dict(attempt=attempt.get('attempt'),restore_generation=attempt.get('restore_generation'))
    try:
        while True:
            if time.monotonic()>deadline: raise TimeoutError('training timeout')
            if time.monotonic()-heartbeat>10:
                beats+=1;store.heartbeat(rid,fence,generation,key=command_key(attempt.get('attempt'),'ML-Heartbeat',beats),**scope);heartbeat=time.monotonic()
            row=store.get(rid)
            if row['state']=='cancel_requested':
                attempt['observed_cancel_generation']=row.get('cancel_generation')
                process.kill();process.wait(timeout=10);return
            epoch=row['epoch']+1
            while (output/f'epoch-{epoch}'/'manifest.json').exists():
                meta=json.loads((output/f'epoch-{epoch}'/'state.json').read_text())
                metrics={k:meta[k] for k in ['epoch','train_loss','validation_loss','updates']}
                store.publish(rid,fence,generation,output/f'epoch-{epoch}',metrics,key=command_key(attempt.get('attempt'),'ML-CheckpointCommit',epoch),**scope);epoch+=1
            if stop_at_pause and (output/'paused.json').exists():return
            status=process.poll()
            if status is not None:
                if status!=0:raise RuntimeError('child exit '+str(status))
                store.complete(rid,fence,generation,json.loads((output/'result.json').read_text()),key=command_key(attempt.get('attempt'),'ML-Complete'),**scope);return
            time.sleep(.05)
    except BaseException as exc:
        # Typed generation refusal while cancel_requested names the cancel to acknowledge.
        if getattr(exc,'code',None)=='CANCEL_GENERATION_FENCED' and getattr(exc,'state',None)=='cancel_requested':
            attempt['observed_cancel_generation']=exc.current_generation
        if process.poll() is None:process.kill();process.wait(timeout=10)
        raise
