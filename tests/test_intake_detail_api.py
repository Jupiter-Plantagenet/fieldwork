"""GET /real/intakes/{id} disposition detail on the retained chain with the real request principal (`fieldwork_api`).

The detail must report aggregate disposition counts and the non-accepted members (member name, disposition,
reason code) of the actor's own intake only. It must never include accepted member names, sample ids (own or
linked), digests, labels or split information, so protected (holdout) membership cannot be inferred.
"""
import uuid

import pytest
from fastapi.testclient import TestClient

from tests.chain_support import chain, make_account, login  # noqa: F401
from tests.leak_world import build_world


@pytest.fixture(scope='module')
def intake_world(chain):
    import fieldwork.api as api
    ws = str(uuid.uuid4())
    w = build_world(chain, ws, prefix='idet')
    tag = uuid.uuid4().hex[:8]
    w['researcher'], w['other'] = f'idet-r-{tag}', f'idet-o-{tag}'
    make_account(chain, w['researcher'], 'researcher', ws)
    make_account(chain, w['other'], 'researcher', ws)
    intake, batch, queued = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    report = 'e' * 64
    accepted_sample = w['train_val'][0]
    rows = [  # (member, disposition, reason, sample_id, linked_sample_id, raw)
        ('accepted-secret-member.jpg', 'accepted', 'ACCEPTED', accepted_sample['id'], None, accepted_sample['sha256']),
        ('dup-of-protected.jpg', 'duplicate', 'PIXEL_IDENTICAL_DIFFERENT_ENCODING', None, w['holdout'][0]['id'], w['holdout'][0]['sha256']),
        ('again-protected.jpg', 'noop', 'RAW_DIGEST_ALREADY_IMPORTED', None, w['holdout'][1]['id'], w['holdout'][1]['sha256']),
        ('again-train.jpg', 'noop', 'RAW_DIGEST_ALREADY_IMPORTED', None, w['train_val'][1]['id'], w['train_val'][1]['sha256']),
        ('notes.txt', 'rejected', 'NOT_AN_IMAGE_MEMBER', None, None, None),
    ]
    with chain.dba.connect() as c:
        for iid, sha in ((intake, 'a' * 64), (queued, 'b' * 64)):
            c.execute('''INSERT INTO fw_real_intake_queue(workspace,intake_id,actor,rights_dataset_id,archive_path,archive_sha256,archive_bytes)
                VALUES(%s,%s,%s,%s,'q.archive',%s,5)''', (ws, iid, w['researcher'], w['rights_dataset'], sha))
        # Legal transitions only (queue/batch guards): claim -> staging batch -> members -> complete batch -> complete queue.
        c.execute('''UPDATE fw_real_intake_queue SET state='running',lease_owner='t-worker',lease_until=clock_timestamp()+interval '5 minutes',
            lease_fence=1,attempts=1 WHERE workspace=%s AND intake_id=%s''', (ws, intake))
        c.execute('''INSERT INTO fw_intake_batches(workspace,batch_id,source_intake_id,archive_name,archive_sha256,archive_bytes,
            rights_dataset_id,policy,decoder,actor,state) VALUES(%s,%s,%s,'a.zip',%s,5,%s,'p','d',%s,'staging')''',
                  (ws, batch, intake, 'a' * 64, w['rights_dataset'], w['researcher']))
        for i, (member, disp, reason, sid, linked, raw) in enumerate(rows):
            c.execute('''INSERT INTO fw_intake_members(workspace,batch_id,ordinal,member,disposition,reason,raw_sha256,sample_id,linked_sample_id,claimed_label)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''', (ws, batch, i, member, disp, reason, raw, sid, linked, 1 if linked else None))
        c.execute('''UPDATE fw_intake_batches SET state='complete',source_total=5,accepted=1,rejected=1,duplicate=1,noop=2,
            report_sha256=%s,finished_utc=clock_timestamp() WHERE workspace=%s AND batch_id=%s''', (report, ws, batch))
        c.execute('''UPDATE fw_real_intake_queue SET state='complete',lease_owner=NULL,lease_until=NULL,result_worker_id='t-worker',
            result_fence=1,result_batch_id=%s,result_sha256=%s,finished_utc=clock_timestamp()
            WHERE workspace=%s AND intake_id=%s''', (batch, report, ws, intake))
    w.update(intake=intake, queued=queued, rows=rows, accepted_sample=accepted_sample)
    with TestClient(api.app) as client, TestClient(api.app) as other:
        w['client'], w['headers'] = client, login(client, w['researcher'])
        w['other_client'], w['other_headers'] = other, login(other, w['other'])
        yield w


def _get(w, intake, who='client'):
    return w[who].get(f"/api/v1/workspaces/{w['workspace']}/real/intakes/{intake}", headers=w['headers' if who == 'client' else 'other_headers'])


def test_detail_counts_and_non_accepted_members(intake_world):
    w = intake_world
    r = _get(w, w['intake'])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['state'] == 'complete'
    assert body['detail'] == {
        'batch_state': 'complete', 'source_total': 5, 'accepted': 1, 'rejected': 1, 'duplicate': 1, 'noop': 2,
        'new_sample_ids': 1, 'non_accepted_truncated': False,
        'non_accepted': [
            {'member': 'dup-of-protected.jpg', 'disposition': 'duplicate', 'reason': 'PIXEL_IDENTICAL_DIFFERENT_ENCODING'},
            {'member': 'again-protected.jpg', 'disposition': 'noop', 'reason': 'RAW_DIGEST_ALREADY_IMPORTED'},
            {'member': 'again-train.jpg', 'disposition': 'noop', 'reason': 'RAW_DIGEST_ALREADY_IMPORTED'},
            {'member': 'notes.txt', 'disposition': 'rejected', 'reason': 'NOT_AN_IMAGE_MEMBER'}]}


def test_detail_leaks_no_accepted_member_sample_ids_digests_labels_or_splits(intake_world):
    w = intake_world
    text = _get(w, w['intake']).text
    forbidden = {'accepted-secret-member.jpg', w['accepted_sample']['id'], w['accepted_sample']['sha256']}
    forbidden |= w['sentinels']  # every holdout id, digest, source member, group and file
    forbidden |= {m['id'] for m in w['train_val'] + w['pool']} | {m['sha256'] for m in w['train_val']}
    assert not [s for s in forbidden if s in text]
    import json
    detail = json.dumps({k: v for k, v in _get(w, w['intake']).json()['detail'].items() if k != 'new_sample_ids'}).lower()  # a count, by design
    for word in ('holdout', 'validation', 'split', 'sample', 'linked', 'label', 'sha256', 'train"', 'pool'):
        assert word not in detail, word
    import re
    assert not re.search(r'[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-', detail)  # no digest or uuid of any kind
    # Protected and unprotected duplicates are indistinguishable: same disposition, same reason, no target.
    rows = _get(w, w['intake']).json()['detail']['non_accepted']
    assert rows[1].keys() == rows[2].keys() and rows[1]['reason'] == rows[2]['reason']


def test_queued_intake_has_no_detail_and_other_actor_is_refused(intake_world):
    w = intake_world
    q = _get(w, w['queued'])
    assert q.status_code == 200 and q.json()['detail'] is None
    assert _get(w, w['intake'], who='other_client').status_code == 404
    assert w['client'].get(f"/api/v1/workspaces/{uuid.uuid4()}/real/intakes/{w['intake']}", headers=w['headers']).status_code in (403, 404)
