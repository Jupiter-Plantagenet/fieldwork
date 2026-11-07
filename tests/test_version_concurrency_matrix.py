"""ML-T-VERSION matrix on current source: concurrent proposal/review/freeze and previous-version reread.

Frozen pass condition: stale revision 412; self-review 403; unreviewed freeze 422; frozen canonical
digests/labels never change; reviewed digest invalidated by edits.

Store-level cases run `fieldwork.annotations` against the real isolated PostgreSQL with lock-barrier
orderings (tests/matrix_support.py). The HTTP cases go through the real FastAPI app under a real
non-owner request principal (RLS), including the /versions serialized-body cache keyed on (id, revision).
"""
import concurrent.futures
import copy
import json
import threading
import uuid

import pytest
from fastapi.testclient import TestClient

import fieldwork.api as api
from fieldwork import annotations
from fieldwork.annotations import Rejection
from fieldwork.data import canonical, digest, generate
from tests.isolated_api import use_isolated_api
from tests.matrix_support import code_of, run_ordered

W = 'vmatrix'
# Samples whose split is train (propose is refused for validation/holdout): checked in the first test.
TRAIN = ['SYN-0-%d' % i for i in range(6)] + ['SYN-1-0', 'SYN-1-1', 'SYN-1-2']
LOCK_VERSION = 'SELECT 1 FROM fw_versions WHERE workspace=%s AND id=%s FOR UPDATE'
REASON = 'Matrix regression reason, long enough.'


def manifest():
    return generate(api.DATA)


def draft(s, workspace=W):
    return annotations.create(s, workspace, 'author', manifest())


def proposed(s, vid, revision=1, sample='SYN-0-0', label=1, actor='author'):
    return annotations.propose(s, W, vid, actor, revision, sample, label, REASON)


def approved(s, p, reviewer='reviewer'):
    return annotations.review_proposal(s, W, p['id'], reviewer, p['digest'], True, REASON)


def reviewed_version(s):
    """draft(rev1) -> proposal(rev2) -> proposal approved(rev3) -> version reviewed(rev4)."""
    v = draft(s)
    p = proposed(s, v['id'])
    cur = approved(s, p)
    assert cur['revision'] == 3
    done = annotations.review_version(s, W, v['id'], 'reviewer', 3, cur['digest'], REASON)
    assert done['state'] == 'reviewed' and done['revision'] == 4
    return v['id'], p, done


def row(s, vid):
    with s.connect() as c:
        return c.execute('SELECT * FROM fw_versions WHERE workspace=%s AND id=%s', (W, vid)).fetchone()


def proposals(s, vid):
    with s.connect() as c:
        return c.execute('SELECT * FROM fw_proposals WHERE workspace=%s AND version=%s ORDER BY ordinal', (W, vid)).fetchall()


def assert_review_binding(s, vid):
    """The invariant behind 'reviewed digest invalidated by edits'."""
    v, rows = row(s, vid), proposals(s, vid)
    if v['state'] == 'reviewed':
        assert v['reviewed_digest'] == annotations.version_digest(v, rows)
    elif v['state'] == 'draft':
        assert v['reviewed_digest'] is None and v['reviewer'] is None
    else:
        assert v['state'] == 'frozen' and v['manifest']['review_digest'] == v['reviewed_digest']


# --------------------------------------------------------------------------- rules
def test_rule_matrix_stale_revision_self_review_unreviewed_freeze(isolated_store):
    s = isolated_store
    splits = {x['id']: x['split'] for x in manifest()['samples']}
    assert all(splits[x] == 'train' for x in TRAIN) and splits['SYN-0-8'] == 'holdout'
    v = draft(s)
    vid = v['id']
    p = proposed(s, vid)
    # stale revision -> 412 on every revision-bound command
    with pytest.raises(Rejection) as e:
        proposed(s, vid, revision=1, sample='SYN-0-1')
    assert (e.value.status, str(e.value)) == (412, 'STALE_REVISION')
    with pytest.raises(Rejection) as e:
        annotations.review_version(s, W, vid, 'reviewer', 1, v['digest'], REASON)
    assert (e.value.status, str(e.value)) == (412, 'STALE_REVISION')
    with pytest.raises(Rejection) as e:
        annotations.freeze(s, W, vid, 1)
    assert (e.value.status, str(e.value)) == (412, 'STALE_REVISION')
    # self-review -> 403 (proposal author, and the version author reviewing the version)
    with pytest.raises(Rejection) as e:
        annotations.review_proposal(s, W, p['id'], 'author', p['digest'], True, REASON)
    assert (e.value.status, str(e.value)) == (403, 'SELF_REVIEW')
    # unreviewed freeze -> 422 (still a draft with an unreviewed proposal)
    with pytest.raises(Rejection) as e:
        annotations.freeze(s, W, vid, p['revision'])
    assert (e.value.status, str(e.value)) == (422, 'EXACT_VERSION_REVIEW_REQUIRED')
    # version review with an unreviewed proposal -> 422; a reviewer's proposal blocks that reviewer (403)
    cur = annotations.get(s, W, vid)
    with pytest.raises(Rejection) as e:
        annotations.review_version(s, W, vid, 'reviewer', cur['revision'], cur['digest'], REASON)
    assert (e.value.status, str(e.value)) == (422, 'UNREVIEWED_PROPOSAL')
    cur = approved(s, p)
    with pytest.raises(Rejection) as e:
        annotations.review_version(s, W, vid, 'author', cur['revision'], cur['digest'], REASON)
    assert (e.value.status, str(e.value)) == (403, 'SELF_REVIEW')
    # a digest that is not the current exact version digest -> 412
    with pytest.raises(Rejection) as e:
        annotations.review_version(s, W, vid, 'reviewer', cur['revision'], 'a' * 64, REASON)
    assert (e.value.status, str(e.value)) == (412, 'VERSION_CHANGED')
    # evaluation data and taxonomy
    with pytest.raises(Rejection) as e:
        proposed(s, vid, revision=cur['revision'], sample='SYN-0-8')  # holdout
    assert (e.value.status, str(e.value)) == (403, 'EVALUATION_READONLY')
    with pytest.raises(Rejection) as e:
        proposed(s, vid, revision=cur['revision'], sample='SYN-0-2', label=9)
    assert (e.value.status, str(e.value)) == (422, 'TAXONOMY')
    # proposer cannot review the version they proposed into
    other = draft(s)
    q = proposed(s, other['id'], actor='reviewer')
    cur2 = approved(s, q, reviewer='other-reviewer')
    with pytest.raises(Rejection) as e:
        annotations.review_version(s, W, other['id'], 'reviewer', cur2['revision'], cur2['digest'], REASON)
    assert (e.value.status, str(e.value)) == (403, 'SELF_REVIEW')
    assert_review_binding(s, vid)


# ------------------------------------------------------------ concurrent proposals
@pytest.mark.parametrize('first_sample', ['SYN-0-0', 'SYN-0-1'])
def test_two_concurrent_proposals_same_revision_exactly_one_wins(isolated_store, first_sample):
    s = isolated_store
    v = draft(s)
    vid = v['id']
    samples = ['SYN-0-0', 'SYN-0-1']
    second_sample = [x for x in samples if x != first_sample][0]
    r1, r2 = run_ordered(s, LOCK_VERSION, (W, vid),
                         lambda st: annotations.propose(st, W, vid, 'author', 1, first_sample, 1, REASON),
                         lambda st: annotations.propose(st, W, vid, 'author2', 1, second_sample, 2, REASON))
    assert code_of(r1) == 'ok' and code_of(r2) == (412, 'STALE_REVISION')
    rows = proposals(s, vid)
    assert [p['sample'] for p in rows] == [first_sample]
    assert row(s, vid)['revision'] == 2


def test_eight_unordered_proposals_one_revision_never_double_apply(isolated_store):
    s = isolated_store
    vid = draft(s)['id']
    barrier = threading.Barrier(8)

    def attempt(i):
        st = type(s)(dsn=s.dsn)
        barrier.wait(timeout=15)
        try:
            annotations.propose(st, W, vid, 'author', 1, TRAIN[i], 1, REASON)
            return 'ok'
        except Rejection as exc:
            return (exc.status, str(exc))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count('ok') == 1 and results.count((412, 'STALE_REVISION')) == 7, results
    assert len(proposals(s, vid)) == 1 and row(s, vid)['revision'] == 2


# ---------------------------------------------- review vs propose, both lock orders
@pytest.mark.parametrize('first', ['review', 'propose'])
def test_version_review_versus_new_proposal_linearizes_and_keeps_binding(isolated_store, first):
    s = isolated_store
    v = draft(s)
    vid = v['id']
    p = proposed(s, vid)
    cur = approved(s, p)
    assert cur['revision'] == 3

    def review(st):
        return annotations.review_version(st, W, vid, 'reviewer', 3, cur['digest'], REASON)

    def propose(st):
        return annotations.propose(st, W, vid, 'author', 3, 'SYN-0-1', 2, REASON)

    ops = {'review': review, 'propose': propose}
    other = 'propose' if first == 'review' else 'review'
    r1, r2 = run_ordered(s, LOCK_VERSION, (W, vid), ops[first], ops[other])
    assert code_of(r1) == 'ok' and code_of(r2) == (412, 'STALE_REVISION')
    v_after = row(s, vid)
    assert v_after['revision'] == 4
    assert v_after['state'] == ('reviewed' if first == 'review' else 'draft')
    assert_review_binding(s, vid)
    if first == 'propose':
        # the reviewed digest was invalidated by the edit that won
        assert v_after['reviewed_digest'] is None
        with pytest.raises(Rejection) as e:
            annotations.freeze(s, W, vid, 4)
        assert (e.value.status, str(e.value)) == (422, 'EXACT_VERSION_REVIEW_REQUIRED')


# ----------------------------------------------- freeze vs propose / freeze vs freeze
@pytest.mark.parametrize('first', ['freeze', 'propose'])
def test_freeze_versus_new_proposal_linearizes(isolated_store, first):
    s = isolated_store
    vid, _p, done = reviewed_version(s)

    def freeze(st):
        return annotations.freeze(st, W, vid, 4)

    def propose(st):
        return annotations.propose(st, W, vid, 'author', 4, 'SYN-0-1', 2, REASON)

    ops = {'freeze': freeze, 'propose': propose}
    other = 'propose' if first == 'freeze' else 'freeze'
    r1, r2 = run_ordered(s, LOCK_VERSION, (W, vid), ops[first], ops[other])
    assert code_of(r1) == 'ok' and code_of(r2) == (412, 'STALE_REVISION')
    v_after = row(s, vid)
    assert v_after['revision'] == 5
    assert_review_binding(s, vid)
    if first == 'freeze':
        assert v_after['state'] == 'frozen'
        assert [p['sample'] for p in proposals(s, vid)] == ['SYN-0-0']  # the losing proposal left no row
    else:
        assert v_after['state'] == 'draft' and v_after['reviewed_digest'] is None
        assert 'review_digest' not in v_after['manifest']  # never frozen
        with pytest.raises(Rejection) as e:
            annotations.freeze(s, W, vid, 5)
        assert (e.value.status, str(e.value)) == (422, 'EXACT_VERSION_REVIEW_REQUIRED')


def test_two_concurrent_freezes_one_snapshot_one_revision(isolated_store):
    s = isolated_store
    vid, _p, _ = reviewed_version(s)
    r1, r2 = run_ordered(s, LOCK_VERSION, (W, vid), lambda st: annotations.freeze(st, W, vid, 4),
                         lambda st: annotations.freeze(st, W, vid, 4))
    assert code_of(r1) == 'ok' and code_of(r2) == (412, 'STALE_REVISION')
    v = row(s, vid)
    assert v['state'] == 'frozen' and v['revision'] == 5
    assert r1[1]['digest'] == v['manifest']['digest']
    # an idempotent retry of the winner with the CURRENT revision returns the same frozen view
    again = annotations.freeze(s, W, vid, 5)
    assert again['digest'] == v['manifest']['digest'] and row(s, vid)['revision'] == 5


@pytest.mark.parametrize('first', ['review', 'supersede'])
def test_proposal_review_versus_superseding_proposal(isolated_store, first):
    s = isolated_store
    v = draft(s)
    vid = v['id']
    p1 = proposed(s, vid)  # revision 2

    def review(st):
        return annotations.review_proposal(st, W, p1['id'], 'reviewer', p1['digest'], True, REASON)

    def supersede(st):
        return annotations.propose(st, W, vid, 'author', 2, 'SYN-0-0', 3, REASON)

    ops = {'review': review, 'supersede': supersede}
    other = 'supersede' if first == 'review' else 'review'
    r1, r2 = run_ordered(s, LOCK_VERSION, (W, vid), ops[first], ops[other])
    if first == 'review':
        assert code_of(r1) == 'ok' and code_of(r2) == (412, 'STALE_REVISION')
        assert [p['decision'] for p in proposals(s, vid)] == ['approved']
    else:
        assert code_of(r1) == 'ok' and code_of(r2) == (412, 'PROPOSAL_SUPERSEDED')
        assert [p['decision'] for p in proposals(s, vid)] == [None, None]
    assert_review_binding(s, vid)


def test_two_reviewers_same_proposal_second_is_already_reviewed(isolated_store):
    s = isolated_store
    v = draft(s)
    p = proposed(s, v['id'])
    r1, r2 = run_ordered(s, LOCK_VERSION, (W, v['id']),
                         lambda st: annotations.review_proposal(st, W, p['id'], 'rev-a', p['digest'], True, REASON),
                         lambda st: annotations.review_proposal(st, W, p['id'], 'rev-b', p['digest'], False, REASON))
    assert code_of(r1) == 'ok' and code_of(r2) == (409, 'ALREADY_REVIEWED')
    only = proposals(s, v['id'])[0]
    assert (only['decision'], only['reviewer']) == ('approved', 'rev-a')


# ------------------------------------------------------------ frozen immutability
def snapshot(s, vid):
    v = row(s, vid)
    return {'manifest': canonical(v['manifest']), 'state': v['state'], 'revision': v['revision'],
            'reviewed_digest': v['reviewed_digest'], 'reviewer': v['reviewer'],
            'proposals': [(p['id'], p['label'], p['decision'], p['digest']) for p in proposals(s, vid)]}


def test_frozen_digest_and_labels_never_change_under_concurrent_mutation(isolated_store):
    s = isolated_store
    vid, p, _ = reviewed_version(s)
    frozen = annotations.freeze(s, W, vid, 4)
    before = snapshot(s, vid)
    m = row(s, vid)['manifest']
    # canonical digest is reproducible from the stored snapshot, parent pointer and review digest are bound
    body = copy.deepcopy(m)
    body.pop('digest')
    assert digest(canonical(body)) == m['digest'] == frozen['digest']
    assert m['review_digest'] == row(s, vid)['reviewed_digest'] and m['parent_digest'] == row(s, vid)['parent_digest']
    assert {x['id']: x['label'] for x in m['samples']}['SYN-0-0'] == 1  # the approved relabel is sealed in

    barrier = threading.Barrier(12)

    def hit(i):
        st = type(s)(dsn=s.dsn)
        barrier.wait(timeout=15)
        try:
            kind = i % 4
            if kind == 0:
                annotations.propose(st, W, vid, 'author', 5, TRAIN[1 + i % 4], 2, REASON)
            elif kind == 1:
                annotations.review_proposal(st, W, p['id'], 'rev-x', p['digest'], False, REASON)
            elif kind == 2:
                annotations.review_version(st, W, vid, 'rev-x', 5, frozen['digest'], REASON)
            else:
                annotations.freeze(st, W, vid, 5)
            return 'ok'
        except Rejection as exc:
            return (exc.status, str(exc))

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(hit, range(12)))
    # only the idempotent re-freeze may "succeed"; every mutation is refused as frozen
    for i, res in enumerate(results):
        if i % 4 == 3:
            assert res == 'ok'
        else:
            assert res == (409, 'FROZEN_VERSION'), (i, res)
    assert snapshot(s, vid) == before
    assert annotations.get(s, W, vid)['digest'] == frozen['digest']
    # a stale-revision attempt against a frozen version is still refused without touching it
    with pytest.raises(Rejection) as e:
        proposed(s, vid, revision=1, sample='SYN-0-1')
    assert e.value.status == 412
    assert snapshot(s, vid) == before


# ------------------------------------------------ reviewed digest invalidated by edits
def test_reviewed_digest_is_invalidated_by_each_kind_of_edit(isolated_store):
    s = isolated_store
    vid, p, done = reviewed_version(s)
    old_digest = done['digest']
    assert row(s, vid)['reviewed_digest'] == old_digest
    # (a) a new proposal invalidates the review and the version digest changes
    p2 = annotations.propose(s, W, vid, 'author', 4, 'SYN-0-1', 2, REASON)
    v = row(s, vid)
    assert v['state'] == 'draft' and v['reviewed_digest'] is None and v['review_reason'] is None
    assert annotations.get(s, W, vid)['digest'] != old_digest
    with pytest.raises(Rejection) as e:
        annotations.freeze(s, W, vid, p2['revision'])
    assert (e.value.status, str(e.value)) == (422, 'EXACT_VERSION_REVIEW_REQUIRED')
    # (b) the old reviewed digest can no longer be used to review the edited version
    cur = annotations.get(s, W, vid)
    with pytest.raises(Rejection) as e:
        annotations.review_version(s, W, vid, 'reviewer', cur['revision'], old_digest, REASON)
    assert (e.value.status, str(e.value)) == (412, 'VERSION_CHANGED')
    # (c) approving the new proposal and re-reviewing succeeds with a NEW digest; rejecting then invalidates again
    after_p2 = approved(s, p2)
    new = annotations.review_version(s, W, vid, 'reviewer', after_p2['revision'], after_p2['digest'], REASON)
    assert new['state'] == 'reviewed' and new['digest'] != old_digest
    assert_review_binding(s, vid)
    p3 = annotations.propose(s, W, vid, 'author', new['revision'], 'SYN-0-2', 3, REASON)
    assert row(s, vid)['state'] == 'draft'
    rejected = annotations.review_proposal(s, W, p3['id'], 'reviewer', p3['digest'], False, REASON)
    assert rejected['state'] == 'draft' and row(s, vid)['reviewed_digest'] is None
    assert_review_binding(s, vid)


# ----------------------------------------------- HTTP: previous-version reread + cache
def login(client, name, password):
    r = client.post('/auth/session', json={'name': name, 'password': password})
    assert r.status_code == 200, r.text
    return {'Origin': 'http://127.0.0.1:5102', 'X-CSRF-Token': r.json()['csrf']}


def freeze_via_http(c, cr, base, author, reviewer, label, sample='SYN-0-0'):
    d = c.post(base + '/versions', json={}, headers=author).json()
    vid = d['id']
    p = c.post(base + f'/versions/{vid}/proposals', json={'sample_id': sample, 'label': label, 'reason': REASON},
               headers={**author, 'If-Match': str(d['revision'])})
    assert p.status_code == 201, p.text
    p = p.json()
    assert cr.post(base + f'/proposals/{p["id"]}/review', json={'digest': p['digest'], 'approve': True, 'reason': REASON},
                   headers=reviewer).status_code == 200
    cur = c.get(base + f'/versions/{vid}').json()
    rv = cr.post(base + f'/versions/{vid}/review', json={'digest': cur['digest'], 'reason': REASON},
                 headers={**reviewer, 'If-Match': str(cur['revision'])})
    assert rv.status_code == 200, rv.text
    fz = c.post(base + f'/versions/{vid}/freeze', json={}, headers={**author, 'If-Match': str(rv.json()['revision'])})
    assert fz.status_code == 200, fz.text
    return vid, fz.json()


def test_previous_frozen_version_rereads_byte_identical_and_cache_is_never_stale(isolated_store, monkeypatch):
    use_isolated_api(isolated_store, monkeypatch)
    pw = uuid.uuid4().hex
    api.create_account('hauthor', pw, 'vhttp', 'owner')
    api.create_account('hreviewer', pw, 'vhttp', 'reviewer')
    base = '/api/v1/workspaces/vhttp'
    api._VERSIONS_CACHE.clear()
    cr = TestClient(api.app)  # separate cookie jar: a second login on one client revokes the first session
    with TestClient(api.app) as c:
        author = login(c, 'hauthor', pw)
        reviewer = login(cr, 'hreviewer', pw)
        v1, f1 = freeze_via_http(c, cr, base, author, reviewer, label=1)
        reread1 = c.get(base + f'/versions/{v1}')
        listed = c.get(base + '/versions')
        assert [x['id'] for x in listed.json()['items']] == [v1]
        # build a second, different child from the same parent and freeze it
        v2, f2 = freeze_via_http(c, cr, base, author, reviewer, label=2)
        assert f2['digest'] != f1['digest'] and f2['parent_digest'] == f1['parent_digest']
        # previous version reread: byte-identical single read, same digest, same labels, same revision
        again1 = c.get(base + f'/versions/{v1}')
        assert again1.content == reread1.content
        got1 = again1.json()
        assert got1['digest'] == f1['digest'] and got1['revision'] == f1['revision'] and got1['state'] == 'frozen'
        lab = lambda v, sid: {x['id']: x['label'] for x in v['manifest']['samples']}[sid]  # noqa: E731
        assert lab(got1, 'SYN-0-0') == 1 and lab(c.get(base + f'/versions/{v2}').json(), 'SYN-0-0') == 2
        # list: cached body equals an uncached serialization; v1's list entry equals its single read exactly
        cached = c.get(base + '/versions')
        api._VERSIONS_CACHE.clear()
        fresh = c.get(base + '/versions')
        assert cached.content == fresh.content
        items = {x['id']: x for x in fresh.json()['items']}
        assert set(items) == {v1, v2} and items[v1] == got1
        # a frozen version cannot be edited through the API, and the refusal leaves list and detail unchanged
        refused = c.post(base + f'/versions/{v1}/proposals', json={'sample_id': 'SYN-0-1', 'label': 3, 'reason': REASON},
                         headers={**author, 'If-Match': str(got1['revision'])})
        assert refused.status_code == 409
        assert c.get(base + f'/versions/{v1}').content == reread1.content
        assert c.get(base + '/versions').content == fresh.content


def test_http_concurrent_mutations_vs_list_cache_read_your_writes_and_monotonic(isolated_store, monkeypatch):
    """Real HTTP clients in threads: concurrent same-revision proposals (one 201, rest 412) while
    other threads hammer GET /versions. After every completed write the very next list must show it
    (the (id, revision)-keyed cache never serves older than the write), and no reader ever sees a
    revision go backwards."""
    use_isolated_api(isolated_store, monkeypatch)
    pw = uuid.uuid4().hex
    api.create_account('cauthor', pw, 'vrace', 'owner')
    base = '/api/v1/workspaces/vrace'
    api._VERSIONS_CACHE.clear()
    with TestClient(api.app) as boot:
        h0 = login(boot, 'cauthor', pw)
        d = boot.post(base + '/versions', json={}, headers=h0).json()
    vid, rev0 = d['id'], d['revision']

    def client():
        cl = TestClient(api.app)
        return cl, login(cl, 'cauthor', pw)

    clients = [client() for _ in range(6)]
    barrier = threading.Barrier(4)
    stop = threading.Event()
    seen = {}

    def writer(i):
        cl, h = clients[i]
        barrier.wait(timeout=20)
        r = cl.post(base + f'/versions/{vid}/proposals', json={'sample_id': 'SYN-0-%d' % i, 'label': 1, 'reason': REASON},
                    headers={**h, 'If-Match': str(rev0)})
        return r.status_code

    def reader(i):
        cl, _h = clients[4 + i]
        last = 0
        barrier.wait(timeout=20)
        while not stop.is_set():
            items = cl.get(base + '/versions').json()['items']
            revision = items[0]['revision']
            assert revision >= last, 'reader saw revision go backwards'
            last = revision
            seen[i] = last
        return last

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        # 2 writers + 2 readers behind a 4-party barrier
        wf = [pool.submit(writer, i) for i in range(2)]
        rf = [pool.submit(reader, i) for i in range(2)]
        codes = sorted(f.result(timeout=60) for f in wf)
        stop.set()
        for f in rf:
            f.result(timeout=60)
    assert codes == [201, 412]
    cl, h = clients[4]
    after_first = cl.get(base + '/versions').json()['items'][0]
    assert after_first['revision'] == rev0 + 1 and len(after_first['proposals']) == 1
    # read-your-writes for each following write
    for n in range(2, 5):
        r = cl.post(base + f'/versions/{vid}/proposals', json={'sample_id': 'SYN-0-%d' % n, 'label': 2, 'reason': REASON},
                    headers={**h, 'If-Match': str(cl.get(base + f'/versions/{vid}').json()['revision'])})
        assert r.status_code == 201, r.text
        listed = cl.get(base + '/versions').json()['items'][0]
        assert listed['revision'] == r.json()['revision'] and len(listed['proposals']) == n
    cached = cl.get(base + '/versions').content
    api._VERSIONS_CACHE.clear()
    assert cl.get(base + '/versions').content == cached
