"""Durable authorized SSE transport; business state remains in PostgreSQL."""
import asyncio,json
import anyio
from fastapi import HTTPException
from .store import TENANT,PUBLIC_EVENT_FILTER
from .annotations import Rejection
from .identities import envelope


def replay(store,workspace,after,check_expiry=True):
    token=TENANT.set(workspace)
    try:
        with store.connect() as c:
            if check_expiry:
                expired=c.execute("SELECT max(seq) cutoff FROM fw_events WHERE workspace=%s AND "+PUBLIC_EVENT_FILTER+" AND created<clock_timestamp()-interval '7 days'",(workspace,)).fetchone()['cutoff']
                if expired is not None and after<=expired:raise Rejection(410,'EVENT_CURSOR_EXPIRED_RESNAPSHOT')
            return c.execute("SELECT seq,event_id,run,kind,payload,created,object_revision FROM fw_events WHERE workspace=%s AND seq>%s AND "+PUBLIC_EVENT_FILTER+" AND created>=clock_timestamp()-interval '7 days' ORDER BY seq LIMIT 500",(workspace,after)).fetchall()
    finally:TENANT.reset(token)


async def stream(store,workspace,request,authenticate,after,initial,replay_only=False):
    rows=initial
    while True:
        try:
            user=await anyio.to_thread.run_sync(authenticate,request)
            if user['workspace']!=workspace:raise HTTPException(403,'MEMBERSHIP_REVOKED')
        except HTTPException:
            yield 'event: access_revoked\ndata: {"code":"SESSION_OR_MEMBERSHIP_REVOKED"}\n\n';return
        for row in rows:
            after=row['seq'];cursor=str(after)
            # Legacy transport keys stay; ml-contracts envelope fields are added alongside.
            event={**row,'seq':str(after),'event_id':str(row['event_id']),'created':row['created'].isoformat().replace('+00:00','Z'),'schema':'1.0',**envelope(row,workspace)}
            yield 'id: '+cursor+'\nevent: domain\ndata: '+json.dumps(event,separators=(',',':'))+'\n\n'
        if replay_only:
            if len(rows)<500:return
        else:
            if await request.is_disconnected():return
            yield ': heartbeat\n\n'
            await asyncio.sleep(.5)
        try:rows=await anyio.to_thread.run_sync(replay,store,workspace,after,False)
        except Exception:
            yield 'event: resnapshot\ndata: {"code":"STREAM_UNAVAILABLE"}\n\n';return
