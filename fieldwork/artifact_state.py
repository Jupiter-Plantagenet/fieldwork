"""Fenced artifact work; lease expiry is not evidence of physical process exit."""
import os
import psutil
from psycopg.types.json import Jsonb


def identity():
    return os.getpid(),psutil.Process().create_time()


def alive(pid,created):
    if pid is None:return False
    # Unknown identity/permission is not permission to free the host slot.
    if created is None:return True
    try:return psutil.Process(pid).create_time()==created and psutil.Process(pid).is_running()
    except psutil.NoSuchProcess:return False
    except psutil.Error:return True


class ArtifactState:
    def _artifact_lock(self,c,rid,fence,expired_ok=False):
        from .store import Conflict
        slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
        r=c.execute('SELECT *,lease>clock_timestamp() AS live FROM fw_runs WHERE id=%s FOR UPDATE',(rid,)).fetchone()
        pid,created=identity()
        if not r or r['state']!='succeeded' or r['fence']!=fence or slot['run']!=rid or slot['fence']!=fence or slot['owner_pid']!=pid or slot['owner_created']!=created or (not expired_ok and not r['live']):raise Conflict('ARTIFACT_FENCED_OR_EXPIRED_OR_OWNER')
        return slot,r

    def artifact_heartbeat(self,rid,fence):
        with self.connect() as c:
            self._artifact_lock(c,rid,fence)
            c.execute("UPDATE fw_runs SET lease=clock_timestamp()+interval '45 seconds' WHERE id=%s",(rid,))

    def artifact_transition(self,rid,fence,status,detail):
        from .store import Conflict
        allowed={'pending':{'building','failed'},'building':{'inference','failed'},'inference':{'verified','failed'},'failed':set(),'verified':set()}
        with self.connect() as c:
            slot,r=self._artifact_lock(c,rid,fence,expired_ok=status=='failed')
            if status not in allowed.get(r['artifact_status'],set()):raise Conflict('ARTIFACT_STAGE_ORDER')
            exited=not slot['launching'] and not alive(slot['pid'],slot['child_created'])
            if status=='verified' and not exited:raise Conflict('ARTIFACT_CHILD_NOT_EXITED')
            c.execute('UPDATE fw_runs SET artifact_status=%s,artifact_result=%s,revision=revision+1 WHERE id=%s',(status,Jsonb(detail),rid))
            self.event(c,r,'artifact_'+status,dict(status=status,**detail))
            # Same locked transaction: no terminal-commit / finally-release gap.
            # Failed publication remains possible with an unknown/live child,
            # but never grants permission to release its physical compute slot.
            if status in ('failed','verified') and exited:
                c.execute('UPDATE fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL WHERE id=1')

    def claim_artifacts(self,rid):
        from .store import Conflict
        with self.connect() as c:
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            r=c.execute('SELECT * FROM fw_runs WHERE id=%s FOR UPDATE',(rid,)).fetchone()
            if not r or r['state']!='succeeded' or r['artifact_status'] not in ('retry_pending','failed') or slot['run'] is not None:raise Conflict('ARTIFACT_NOT_RETRYABLE_OR_SLOT_BUSY')
            if r['artifact_attempts']>=3:raise Conflict('ARTIFACT_ATTEMPT_BUDGET')
            pid,created=identity();fence=r['fence']+1
            c.execute('UPDATE fw_slot SET run=%s,fence=%s,owner_pid=%s,owner_created=%s,pid=NULL,child_created=NULL,launching=false WHERE id=1',(rid,fence,pid,created))
            r=c.execute("UPDATE fw_runs SET fence=%s,artifact_status='pending',artifact_result=%s,artifact_attempts=artifact_attempts+1,artifact_owner_pid=%s,artifact_owner_created=%s,lease=clock_timestamp()+interval '45 seconds',revision=revision+1 WHERE id=%s RETURNING *",(fence,Jsonb({'code':'ARTIFACT_RETRY_PENDING'}),pid,created,rid)).fetchone()
            self.event(c,r,'artifact_pending',{'code':'ARTIFACT_RETRY_PENDING','fence':fence});return r

    def recover_artifacts(self):
        """Scan only artifact orphans; never evict a live owner/child on expiry.

        A crash between begin_spawn and child registration is ambiguous: retain
        the slot and record explicit failure rather than guess physical exit.
        """
        from .real_container_guard import model_cleanup_pending
        if model_cleanup_pending():return []
        recovered=[]
        with self.connect() as c:
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            rows=c.execute("SELECT * FROM fw_runs WHERE state='succeeded' AND (artifact_status IN ('pending','building','inference') OR (id=%s AND artifact_status IN ('failed','verified'))) AND lease<clock_timestamp() ORDER BY id FOR UPDATE",(slot['run'],)).fetchall()
            for r in rows:
                if alive(r['artifact_owner_pid'],r['artifact_owner_created']):continue
                owns=slot['run']==r['id']
                exact=owns and slot['fence']==r['fence'] and (slot['owner_pid'],slot['owner_created'])==(r['artifact_owner_pid'],r['artifact_owner_created'])
                if owns and not exact:continue # Never clear a replacement owner's slot.
                if r['artifact_status'] in ('failed','verified'):
                    # Legacy terminal commits are cleanup only: preserve every
                    # run field, attestation, event, byte and attempt budget.
                    if not exact or slot['owner_pid'] is None or slot['owner_created'] is None:continue
                    if alive(slot['owner_pid'],slot['owner_created']) or slot['launching'] or alive(slot['pid'],slot['child_created']):continue
                    if (r['artifact_result'] or {}).get('code')=='ARTIFACT_CHILD_EXIT_UNCONFIRMED':continue
                    c.execute('UPDATE fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL WHERE id=1')
                    recovered.append(r['id']);continue
                if owns and alive(slot['pid'],slot['child_created']):continue
                if owns and slot['launching']:
                    status='failed';detail={'code':'ARTIFACT_CHILD_EXIT_UNCONFIRMED','automatic_retry':False}
                else:
                    status='retry_pending' if r['artifact_attempts']<3 else 'failed'
                    detail={'code':'ARTIFACT_OWNER_DIED' if status=='retry_pending' else 'ARTIFACT_ATTEMPT_BUDGET','automatic_retry':status=='retry_pending'}
                    if owns:c.execute('UPDATE fw_slot SET run=NULL,pid=NULL,child_created=NULL,owner_pid=NULL,owner_created=NULL,fence=NULL WHERE id=1')
                c.execute('UPDATE fw_runs SET fence=fence+1,artifact_status=%s,artifact_result=%s,revision=revision+1 WHERE id=%s',(status,Jsonb(detail),r['id']))
                self.event(c,r,'artifact_'+status,detail);recovered.append(r['id'])
        return recovered

    def begin_child(self,rid,fence,artifact=False):
        from .store import Conflict
        with self.connect() as c:
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            if artifact:self._artifact_lock(c,rid,fence)
            pid,created=identity()
            if slot['run']!=rid or slot['fence']!=fence or (slot['owner_pid'],slot['owner_created'])!=(pid,created) or slot['launching'] or alive(slot['pid'],slot['child_created']):raise Conflict('CHILD_SLOT_BUSY_OR_FENCED')
            c.execute('UPDATE fw_slot SET launching=true,pid=NULL,child_created=NULL WHERE id=1')

    def register_child(self,rid,fence,child):
        from .store import Conflict
        with self.connect() as c:
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            pid,created=identity()
            if slot['run']!=rid or slot['fence']!=fence or (slot['owner_pid'],slot['owner_created'])!=(pid,created) or not slot['launching']:raise Conflict('CHILD_REGISTRATION_FENCED')
            try:birth=psutil.Process(child.pid).create_time()
            except psutil.NoSuchProcess:
                if child.poll() is None:raise
                # Already waited/reaped: no live physical child to track.
                c.execute('UPDATE fw_slot SET launching=false,pid=NULL,child_created=NULL WHERE id=1');return
            c.execute('UPDATE fw_slot SET launching=false,pid=%s,child_created=%s WHERE id=1',(child.pid,birth))

    def child_spawn_failed(self,rid,fence):
        # Call ONLY if Popen raised without creating a process.
        pid,created=identity()
        with self.connect() as c:c.execute('UPDATE fw_slot SET launching=false WHERE id=1 AND run=%s AND fence=%s AND owner_pid=%s AND owner_created=%s',(rid,fence,pid,created))
