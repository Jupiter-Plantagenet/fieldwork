"""ML-T-ATOMIC: real process death at each checkpoint staging/fsync/rename/DB edge, plus disk full.

A separate Python process performs `Store.publish` against the isolated real
PostgreSQL database and is terminated with `os._exit` (no finally/atexit/
rollback in Python) at one exact edge. PostgreSQL must roll back any open
transaction of the dead connection; the parent then proves that no incomplete
checkpoint is visible as committed, the pointer only references a
digest-validated directory, orphans are inert, and a retry commits exactly once.
"""
import errno,json,os,subprocess,sys,uuid
from pathlib import Path
import pytest
from fieldwork.store import ROOT
from fieldwork.ml import validate_checkpoint

SOURCE=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0/run/epoch-1'

HARNESS=r'''
import json,os,sys
from pathlib import Path
args=json.loads(sys.argv[1])
from fieldwork.store import Store
import fieldwork.checkpoint_store as cs
s=Store(dsn=args['dsn']);s.blob_root=Path(args['blob'])
edge=args['edge'];die=lambda:os._exit(77)
if edge=='staged_first_file_fsync':
    real=cs.os.fsync;count={'n':0}
    def fsync(fd):
        real(fd);count['n']+=1
        if count['n']==1:die()
    cs.os.fsync=fsync
elif edge=='before_stage_rename':
    # checkpoint_store.promote publishes via fieldwork.fsops.durable_rename (which
    # binds os.rename itself), so intercept that call: die just before the
    # staging directory is renamed to its final digest name.
    import fieldwork.fsops as fo
    real=fo.durable_rename
    def durable_rename(source,target,*a,**k):
        if Path(source).name.startswith('.staging-'):die()
        return real(source,target,*a,**k)
    fo.durable_rename=durable_rename
elif edge=='after_rename_before_db':
    real=cs.promote
    def promote(*a,**k):
        out=real(*a,**k);die()
    cs.promote=promote
elif edge=='db_insert_before_commit':
    real=Store.event
    def event(self,c,r,kind,payload):
        if kind=='epoch_committed':die()
        return real(self,c,r,kind,payload)
    Store.event=event
s.publish(args['run'],args['fence'],args['generation'],Path(args['source']),args['metrics'],attempt=args['attempt'])
if edge=='after_commit':die()
os._exit(0)
'''

EDGES=['staged_first_file_fsync','before_stage_rename','after_rename_before_db','db_insert_before_commit','after_commit']


def _metrics():
    meta=json.loads((SOURCE/'state.json').read_text())
    return meta,{k:meta[k] for k in ['epoch','train_loss','validation_loss','updates']}


@pytest.mark.parametrize('edge',EDGES)
def test_process_death_at_checkpoint_edge_never_exposes_partial_commit(isolated_store,tmp_path,edge):
    s=isolated_store;meta,metrics=_metrics();blob=tmp_path/'blobs';s.blob_root=blob
    r=s.submit('atomic-edge-'+uuid.uuid4().hex,'a',str(uuid.uuid4()),{'epochs':1,'dataset_digest':meta['dataset_digest']})
    a=s.claim(r['id'])
    try:
        args={'dsn':s.dsn,'blob':str(blob),'edge':edge,'run':r['id'],'fence':a['fence'],'generation':a['cancel_generation'],'attempt':a['attempt'],'source':str(SOURCE),'metrics':metrics}
        child=subprocess.run([sys.executable,'-c',HARNESS,json.dumps(args)],cwd=ROOT,capture_output=True,text=True,timeout=120)
        assert child.returncode==77,child.stderr[-2000:]
        rows=s.checkpoints(r['id']);run=s.get(r['id'])
        if edge=='after_commit':
            assert [x['epoch'] for x in rows]==[1] and run['epoch']==1
        else:
            # Dead connection's transaction rolled back by PostgreSQL; nothing committed.
            assert rows==[] and run['epoch']==0 and run['checkpoint'] is None
            events=[e for e in s.events(r['workspace']) if e['kind']=='epoch_committed']
            assert events==[]
        # Every non-staging blob directory is complete and digest-valid; staging is inert.
        for entry in (blob.iterdir() if blob.exists() else []):
            if entry.name.startswith('.staging-'):continue
            validate_checkpoint(entry,entry.name)
        # Retry by the same live attempt commits exactly once (idempotent after commit).
        s.publish(r['id'],a['fence'],a['cancel_generation'],SOURCE,metrics,attempt=a['attempt'])
        s.publish(r['id'],a['fence'],a['cancel_generation'],SOURCE,metrics,attempt=a['attempt'])
        rows=s.checkpoints(r['id']);run=s.get(r['id'])
        assert [x['epoch'] for x in rows]==[1] and run['epoch']==1
        validate_checkpoint(run['checkpoint'],rows[0]['digest'])
        assert Path(run['checkpoint']).parent==blob and Path(run['checkpoint']).name==rows[0]['digest']
        assert len([e for e in s.events(r['workspace']) if e['kind']=='epoch_committed'])==1
        report={'edge':edge,'child_exit':child.returncode,'committed_after_crash':edge=='after_commit',
                'orphans':sorted(p.name[:9] for p in blob.iterdir() if p.name.startswith('.staging-')),'retry_committed_once':True}
        (tmp_path/'atomic-edge.json').write_text(json.dumps(report))
    finally:
        s.release_slot(r['id'])


def test_disk_full_during_staging_commits_nothing_and_cleans_stage(isolated_store,tmp_path,monkeypatch):
    import fieldwork.checkpoint_store as cs
    s=isolated_store;meta,metrics=_metrics();blob=tmp_path/'blobs';s.blob_root=blob
    r=s.submit('atomic-enospc-'+uuid.uuid4().hex,'a',str(uuid.uuid4()),{'epochs':1,'dataset_digest':meta['dataset_digest']})
    a=s.claim(r['id'])
    try:
        real=cs.os.fsync
        def full(fd):raise OSError(errno.ENOSPC,'No space left on device (injected)')
        monkeypatch.setattr(cs.os,'fsync',full)
        with pytest.raises(OSError):s.publish(r['id'],a['fence'],a['cancel_generation'],SOURCE,metrics,attempt=a['attempt'])
        assert s.checkpoints(r['id'])==[] and s.get(r['id'])['epoch']==0
        assert not [p for p in blob.iterdir() if p.name.startswith('.staging-')]
        monkeypatch.setattr(cs.os,'fsync',real)
        s.publish(r['id'],a['fence'],a['cancel_generation'],SOURCE,metrics,attempt=a['attempt'])
        assert [x['epoch'] for x in s.checkpoints(r['id'])]==[1]
    finally:
        s.release_slot(r['id'])


def test_orphan_gc_respects_24h_grace_and_live_references(isolated_store,tmp_path):
    import os,shutil,time
    from fieldwork.checkpoint_gc import collect
    s=isolated_store;meta,metrics=_metrics();blob=tmp_path/'blobs';s.blob_root=blob
    r=s.submit('atomic-gc-'+uuid.uuid4().hex,'a',str(uuid.uuid4()),{'epochs':1,'dataset_digest':meta['dataset_digest']})
    a=s.claim(r['id'])
    try:s.publish(r['id'],a['fence'],a['cancel_generation'],SOURCE,metrics,attempt=a['attempt'])
    finally:s.release_slot(r['id'])
    live=Path(s.get(r['id'])['checkpoint'])
    old_orphan=blob/('f'*64);shutil.copytree(SOURCE,old_orphan)
    young_orphan=blob/('e'*64);shutil.copytree(SOURCE,young_orphan)
    # copytree preserves the (now >24h old) source mtimes; the young orphan must really be young.
    for f in [young_orphan,*young_orphan.rglob('*')]:os.utime(f,None)
    stage=blob/'.staging-dead';stage.mkdir();(stage/'state.json').write_text('{}')
    old=time.time()-25*3600
    for p in [live,old_orphan,stage]:
        for f in [p,*p.rglob('*')]:os.utime(f,(old,old))
    dry=collect(s,blob,apply=False)
    assert sorted(dry['candidates'])==sorted([old_orphan.name,'.staging-dead']) and dry['removed']==[]
    applied=collect(s,blob,apply=True)
    assert sorted(applied['removed'])==sorted([old_orphan.name,'.staging-dead'])
    assert live.exists() and young_orphan.exists() and not old_orphan.exists() and not stage.exists()
    assert applied['kept_referenced']==1 and applied['kept_young']==1
    validate_checkpoint(live,s.checkpoints(r['id'])[0]['digest'])
