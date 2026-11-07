"""Immutable local annotation proposals; role checks stay at the API boundary."""
import copy,uuid
from psycopg.types.json import Jsonb
from .data import canonical,digest


class Rejection(ValueError):
    def __init__(self,status,code):self.status=status;super().__init__(code)


def locked(c,w,vid,revision=None):
    v=c.execute('SELECT * FROM fw_versions WHERE workspace=%s AND id=%s FOR UPDATE',(w,vid)).fetchone()
    if not v:raise Rejection(404,'OBJECT')
    if revision is not None and v['revision']!=revision:raise Rejection(412,'STALE_REVISION')
    return v


def proposals(c,w,vid):
    return c.execute('SELECT * FROM fw_proposals WHERE workspace=%s AND version=%s ORDER BY ordinal',(w,vid)).fetchall()


def version_digest(v,rows):
    if v['state']=='frozen':return v['manifest']['digest']
    return digest(canonical({'parent':v['parent_digest'],'manifest':v['manifest']['digest'],'proposals':rows}))


def view(v,rows):
    result=dict(v,digest=version_digest(v,rows),proposals=rows)
    # Full sealed snapshot remains private in DB, never in browser response.
    result['manifest']=copy.deepcopy(v['manifest'])
    protected_ids={str(s.get('id')) for s in v['manifest']['samples']
        if s['split']=='holdout' or 'holdout_population' in s or s.get('protected') is True}
    result['manifest']['samples']=[{k:x for k,x in s.items() if k!='file'} for s in v['manifest']['samples']
        if str(s.get('id')) not in protected_ids]
    if v['manifest'].get('scope') == 'real-rights-cleared':
        # Quarantine evidence can contain member names, linked IDs, labels and
        # source paths. It remains server-side; only aggregate support crosses.
        result['manifest'].pop('quarantine', None)
        # The detailed audit contains protected sample IDs, raw/pixel digests,
        # and stable source-photo identities. A frozen child may inherit those
        # rows verbatim, so redact the entire audit whenever this version has
        # protected members. The stored manifest and its digest stay untouched.
        if protected_ids:
            result['manifest'].pop('group_audit', None)
    return result


def create(store,w,actor,manifest,parent_digest=None):
    vid=str(uuid.uuid4())
    with store.connect() as c:
        c.execute('INSERT INTO fw_versions(workspace,id,author,parent_digest,manifest) VALUES(%s,%s,%s,%s,%s)',
                  (w,vid,actor,parent_digest or manifest['digest'],Jsonb(manifest)))
        v=locked(c,w,vid);return view(v,[])


def get(store,w,vid):
    with store.connect() as c:
        v=locked(c,w,vid);return view(v,proposals(c,w,vid))


def list_versions(store,w):
    with store.connect() as c:
        vs=c.execute('SELECT * FROM fw_versions WHERE workspace=%s ORDER BY id',(w,)).fetchall()
        return [view(v,proposals(c,w,v['id'])) for v in vs]


def propose(store,w,vid,actor,revision,sample,label,reason):
    with store.connect() as c:
        v=locked(c,w,vid,revision)
        if v['state']=='frozen':raise Rejection(409,'FROZEN_VERSION')
        source=next((s for s in v['manifest']['samples'] if s['id']==sample),None)
        if not source:raise Rejection(404,'OBJECT')
        if source['split'] not in ('train','pool') or 'holdout_population' in source or source.get('protected') is True:
            raise Rejection(403,'EVALUATION_READONLY')
        if not 0<=label<len(v['manifest']['classes']):raise Rejection(422,'TAXONOMY')
        pid=str(uuid.uuid4());body={'id':pid,'version':vid,'sample':sample,'author':actor,'label':label,'reason':reason,'base_revision':revision};h=digest(canonical(body))
        c.execute('INSERT INTO fw_proposals(workspace,id,version,sample,author,label,reason,digest) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',(w,pid,vid,sample,actor,label,reason,h))
        c.execute("UPDATE fw_versions SET revision=revision+1,state='draft',reviewed_digest=NULL,reviewer=NULL,review_reason=NULL WHERE workspace=%s AND id=%s",(w,vid))
        return dict(body,digest=h,revision=revision+1)


def review_proposal(store,w,pid,actor,expected,approve,reason):
    with store.connect() as c:
        p=c.execute('SELECT * FROM fw_proposals WHERE workspace=%s AND id=%s',(w,pid)).fetchone()
        if not p:raise Rejection(404,'OBJECT')
        v=locked(c,w,p['version'])
        p=c.execute('SELECT * FROM fw_proposals WHERE workspace=%s AND id=%s FOR UPDATE',(w,pid)).fetchone()
        if v['state']=='frozen':raise Rejection(409,'FROZEN_VERSION')
        if p['author']==actor:raise Rejection(403,'SELF_REVIEW')
        if p['digest']!=expected:raise Rejection(412,'PROPOSAL_CHANGED')
        if p['decision'] is not None:raise Rejection(409,'ALREADY_REVIEWED')
        latest=c.execute('SELECT id FROM fw_proposals WHERE workspace=%s AND version=%s AND sample=%s ORDER BY ordinal DESC LIMIT 1',(w,p['version'],p['sample'])).fetchone()
        if latest['id']!=pid:raise Rejection(412,'PROPOSAL_SUPERSEDED')
        c.execute('UPDATE fw_proposals SET decision=%s,reviewer=%s,review_reason=%s WHERE workspace=%s AND id=%s',('approved' if approve else 'rejected',actor,reason,w,pid))
        c.execute("UPDATE fw_versions SET revision=revision+1,state='draft',reviewed_digest=NULL,reviewer=NULL,review_reason=NULL WHERE workspace=%s AND id=%s",(w,p['version']))
        return view(locked(c,w,p['version']),proposals(c,w,p['version']))


def review_version(store,w,vid,actor,revision,expected,reason):
    with store.connect() as c:
        v=locked(c,w,vid,revision);rows=proposals(c,w,vid)
        if v['state']=='frozen':raise Rejection(409,'FROZEN_VERSION')
        if v['author']==actor or any(p['author']==actor for p in rows):raise Rejection(403,'SELF_REVIEW')
        if version_digest(v,rows)!=expected:raise Rejection(412,'VERSION_CHANGED')
        latest={p['sample']:p for p in rows}
        if any(p['decision'] is None for p in latest.values()):raise Rejection(422,'UNREVIEWED_PROPOSAL')
        c.execute("UPDATE fw_versions SET state='reviewed',reviewed_digest=%s,reviewer=%s,review_reason=%s,revision=revision+1 WHERE workspace=%s AND id=%s",(expected,actor,reason,w,vid))
        return view(locked(c,w,vid),rows)


def freeze(store,w,vid,revision):
    with store.connect() as c:
        v=locked(c,w,vid,revision);rows=proposals(c,w,vid)
        if v['state']=='frozen':return view(v,rows)
        if v['state']!='reviewed' or v['reviewed_digest']!=version_digest(v,rows):raise Rejection(422,'EXACT_VERSION_REVIEW_REQUIRED')
        # Current acquisition lane is author-generated fixtures only; no inferred flower grant.
        if v['manifest']['scope']!='synthetic-execution-only':raise Rejection(423,'RIGHTS_AND_SPLIT_REVIEW_REQUIRED')
        m=copy.deepcopy(v['manifest']);latest={p['sample']:p for p in rows}
        for s in m['samples']:
            p=latest.get(s['id'])
            if p and p['decision']=='approved':s['label']=p['label'];s['annotation_digest']=p['digest']
        m.pop('digest');m.update(parent_digest=v['parent_digest'],version_id=vid,review_digest=v['reviewed_digest']);m['digest']=digest(canonical(m))
        c.execute("UPDATE fw_versions SET state='frozen',manifest=%s,revision=revision+1 WHERE workspace=%s AND id=%s",(Jsonb(m),w,vid))
        return view(locked(c,w,vid),rows)
