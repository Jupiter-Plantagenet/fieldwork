"""ML-T-EVENTS matrix on current source: duplicate/out-of-order delivery, 7-day replay, cursor expiry (410 ->
authorized resnapshot), disconnect/reconnect and membership revocation (stream closes within 30 s).

Real FastAPI app + real SSE generator (`fieldwork.events.stream`) + real PostgreSQL events table under the real
nonowner request principal and forced RLS. Revocation is exercised over a live streaming HTTP response (Starlette
TestClient stream, consumer in a thread) for every revocation path the product has.
"""
import json, re, threading, time, uuid
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from tests.chain_support import chain, make_account, login, PASSWORD, ORIGIN  # noqa: F401
from tests.test_postfix_evidence import accepted_fixture

STATE = {}


def parse_sse(text):
    events, cur = [], {}
    for line in text.splitlines():
        if line == '':
            if cur:
                events.append(cur)
            cur = {}
        elif line.startswith(':'):
            cur.setdefault('comments', []).append(line)
        else:
            key, _, value = line.partition(': ')
            cur[key] = value
    if cur:
        events.append(cur)
    return events


def domain(text):
    return [{**json.loads(e['data']), '_id': e['id']} for e in parse_sse(text) if e.get('event') == 'domain']


@pytest.fixture(scope='module')
def world(chain, tmp_path_factory):
    import fieldwork.api as api
    tag = uuid.uuid4().hex[:8]
    ws = 'ev-' + tag
    other = 'ev-other-' + tag
    W = {'ws': ws, 'other': other, 'tag': tag}
    make_account(chain, 'ev-owner-' + tag, 'owner', ws)
    make_account(chain, 'ev-researcher-' + tag, 'researcher', ws)
    make_account(chain, 'ev-other-' + tag, 'researcher', other)
    W['dba'] = chain.dba
    run, _ = accepted_fixture(chain.dba, Path(chain.runs), ws)
    W['evidence_run'] = run['id']
    from contextlib import ExitStack
    with ExitStack() as stack:
        W['researcher'] = stack.enter_context(TestClient(api.app))
        W['researcher_h'] = login(W['researcher'], 'ev-researcher-' + tag)
        W['owner'] = stack.enter_context(TestClient(api.app))
        W['owner_h'] = login(W['owner'], 'ev-owner-' + tag)
        W['stranger'] = stack.enter_context(TestClient(api.app))
        W['stranger_h'] = login(W['stranger'], 'ev-other-' + tag)
        W['api'] = api
        W['chain'] = chain
        W['anon'] = stack.enter_context(TestClient(api.app))
        yield W


def base(world):
    return f"/api/v1/workspaces/{world['ws']}"


def produce_events(world, n=6):
    c, h = world['researcher'], world['researcher_h']
    ids = []
    for i in range(n):
        r = c.post(base(world) + '/runs', json={'epochs': 1}, headers={**h, 'Idempotency-Key': f'ev-{i}-{uuid.uuid4()}'})
        assert r.status_code in (202, 423), r.text  # 423 = host resource gate; fall back to the store below
        if r.status_code == 202:
            ids.append(r.json()['id'])
        else:
            ids.append(world['dba'].submit(world['ws'], 'ev-researcher-' + world['tag'], f'ev-store-{i}-{uuid.uuid4()}',
                                           {'epochs': 1, 'scope': 'synthetic-execution-only'})['id'])
    for run_id in ids[:3]:  # revision-bearing commands: cancel moves queued -> cancelled (revision 2)
        r = c.post(base(world) + f'/runs/{run_id}/cancel', headers={**h, 'Idempotency-Key': str(uuid.uuid4()), 'If-Match': '"1"', 'Content-Type': 'application/json'},
                   json={'expected_revision': 1, 'reason': 'events matrix cancel'})
        assert r.status_code in (200, 202), r.text
    return ids


# ----------------------------------------------------------------------------------------------- ordering
def test_workspace_sequence_is_strictly_ordered_and_polling_equals_sse(world):
    produce_events(world)
    c, h = world['researcher'], world['researcher_h']
    poll = c.get(base(world) + '/events?after=0', headers=h).json()['items']
    sse = domain(c.get(base(world) + '/events/stream?replay_only=true', headers=h).text)
    assert len(poll) >= 9 and len(sse) == len(poll)
    seqs = [int(e['seq']) for e in poll]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    assert [int(e['seq']) for e in sse] == seqs and [e['_id'] for e in sse] == [str(s) for s in seqs]
    assert [e['sequence'] for e in sse] == [str(s) for s in seqs]  # contract envelope repeats the durable sequence
    ids = [e['event_id'] for e in sse]
    assert len(set(ids)) == len(ids)  # event ids are unique: the dedup key
    # Per-object revisions never go backwards for one run.
    by_run = {}
    for e in sse:
        by_run.setdefault(e['run'], []).append(e['object_revision'])
    assert all(revs == sorted(revs) for revs in by_run.values())
    assert any(len(set(r)) > 1 for r in by_run.values())  # cancelled runs advanced past revision 1
    STATE['events_ordered'] = len(sse)


def test_every_resume_point_replays_exactly_the_suffix_without_gap_or_duplicate(world):
    c, h = world['researcher'], world['researcher_h']
    full = domain(c.get(base(world) + '/events/stream?replay_only=true', headers=h).text)
    for k in range(len(full)):
        got = domain(c.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': full[k]['_id']}).text)
        assert [e['event_id'] for e in got] == [e['event_id'] for e in full[k + 1:]], k
        poll = c.get(base(world) + f"/events?after={full[k]['seq']}", headers=h).json()['items']
        assert [e['event_id'] for e in poll] == [e['event_id'] for e in full[k + 1:]], k
    # Reconnecting twice from the same cursor yields byte-identical, duplicate-stable deliveries.
    mid = full[len(full) // 2]['_id']
    first = c.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': mid}).text
    second = c.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': mid}).text
    assert first == second
    # Overlapping windows intersect on identical (seq, event_id, revision): a consumer dedups by event_id.
    a = domain(c.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': full[1]['_id']}).text)
    b = domain(c.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': full[3]['_id']}).text)
    key = lambda e: (e['seq'], e['event_id'], e['object_revision'])
    overlap = {key(e) for e in a} & {key(e) for e in b}
    assert overlap == {key(e) for e in b}
    # A cursor beyond the head is a valid empty resume, not an error.
    assert domain(c.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': '9223372036854775807'}).text) == []
    STATE['resume_points'] = len(full)


def test_replay_pages_beyond_500_rows_without_gap_or_duplicate(world):
    run = world['evidence_run']
    dba = world['dba']
    with dba.connect() as c:
        before = c.execute("SELECT coalesce(max(seq),0) AS m FROM fw_events WHERE workspace=%s", (world['ws'],)).fetchone()['m']
        for i in range(1100):
            c.execute("INSERT INTO fw_events(workspace,run,kind,payload,object_revision) VALUES(%s,%s,'heartbeat',%s,%s)",
                      (world['ws'], run, json.dumps({'i': i}), 1))
    cl, h = world['researcher'], world['researcher_h']
    got = domain(cl.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': str(before)}).text)
    assert len(got) == 1100
    seqs = [int(e['seq']) for e in got]
    assert seqs == sorted(seqs) and len(set(seqs)) == 1100 and len({e['event_id'] for e in got}) == 1100
    with dba.connect() as c:
        db = [r['seq'] for r in c.execute("SELECT seq FROM fw_events WHERE workspace=%s AND seq>%s ORDER BY seq", (world['ws'], before)).fetchall()]
    assert seqs == db  # exactly the durable rows, in order
    STATE['paged_events'] = len(got)


def test_out_of_order_creation_times_never_reorder_delivery_and_revisions_are_exposed(world):
    dba, ws, run = world['dba'], world['ws'], world['evidence_run']
    with dba.connect() as c:
        first = c.execute("SELECT coalesce(max(seq),0) AS m FROM fw_events WHERE workspace=%s", (ws,)).fetchone()['m']
        # Higher seq written with an OLDER timestamp and a LOWER object revision: a late/duplicated command receipt.
        c.execute("INSERT INTO fw_events(workspace,run,kind,payload,object_revision,created) VALUES(%s,%s,'late_a',%s,5,clock_timestamp())", (ws, run, '{}'))
        c.execute("INSERT INTO fw_events(workspace,run,kind,payload,object_revision,created) VALUES(%s,%s,'late_b',%s,2,clock_timestamp()-interval '3 days')", (ws, run, '{}'))
        c.execute("INSERT INTO fw_events(workspace,run,kind,payload,object_revision,created) VALUES(%s,%s,'late_c',%s,NULL,clock_timestamp()-interval '2 days')", (ws, run, '{}'))
    cl, h = world['researcher'], world['researcher_h']
    got = domain(cl.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': str(first)}).text)
    assert [e['kind'] for e in got] == ['late_a', 'late_b', 'late_c']  # seq order, not timestamp order
    assert [e['revision'] for e in got] == [5, 2, 0] and [e['revision_legacy'] for e in got] == [False, False, True]
    assert [e['occurred_at'] for e in got][1] < [e['occurred_at'] for e in got][0]  # created times really are out of order
    # The lower revision still arrives (the server never hides it); consumers apply max(revision) per object.
    assert max(e['revision'] for e in got if e['revision_legacy'] is False) == 5


# ----------------------------------------------------------------------------------------------- idempotent commands (dedup of producers)
def test_duplicate_commands_with_the_same_key_produce_one_durable_event(world):
    c, h = world['researcher'], world['researcher_h']
    key = f'dup-{uuid.uuid4()}'
    hdr = {**h, 'Idempotency-Key': key}
    mark = c.get(base(world) + '/snapshot', headers=h).json()['last_sequence']  # the polling page is capped at 500 rows
    a = c.post(base(world) + '/runs', json={'epochs': 1}, headers=hdr)
    b = c.post(base(world) + '/runs', json={'epochs': 1}, headers=hdr)
    if a.status_code == 423:  # host RAM gate: exercise the same store path directly
        run = world['dba'].submit(world['ws'], 'ev-researcher-' + world['tag'], key, {'epochs': 1, 'scope': 'synthetic-execution-only'})
        run2 = world['dba'].submit(world['ws'], 'ev-researcher-' + world['tag'], key, {'epochs': 1, 'scope': 'synthetic-execution-only'})
        rid = run['id']; assert run2['id'] == rid
    else:
        assert a.status_code == b.status_code == 202 and a.json()['id'] == b.json()['id']
        rid = a.json()['id']
    items = c.get(base(world) + f'/events?after={mark}', headers=h).json()['items']
    assert sum(1 for e in items if e['run'] == rid and e['kind'] == 'queued') == 1
    cancel_key = str(uuid.uuid4())
    ch = {**h, 'Idempotency-Key': cancel_key, 'If-Match': '"1"'}
    r1 = c.post(base(world) + f'/runs/{rid}/cancel', headers=ch, json={'expected_revision': 1, 'reason': 'duplicate delivery probe'})
    r2 = c.post(base(world) + f'/runs/{rid}/cancel', headers=ch, json={'expected_revision': 1, 'reason': 'duplicate delivery probe'})
    assert r1.status_code == r2.status_code and r1.content == r2.content  # exact replay of the durable receipt
    items = c.get(base(world) + f'/events?after={mark}', headers=h).json()['items']
    assert sum(1 for e in items if e['run'] == rid and e['kind'] not in ('queued',)) == 1
    # Private receipts never enter the public feed.
    assert not [e for e in items if e['kind'] in ('command_receipt', 'evaluation_flag')]


# ----------------------------------------------------------------------------------------------- expiry / resnapshot
def test_cursor_expiry_returns_410_and_an_authorized_resnapshot_resumes_cleanly(world):
    dba, ws = world['dba'], world['ws']
    cl, h = world['researcher'], world['researcher_h']
    full = domain(cl.get(base(world) + '/events/stream?replay_only=true', headers=h).text)
    old_cut = int(full[2]['seq'])
    with dba.connect() as c:
        c.execute("UPDATE fw_events SET created=clock_timestamp()-interval '8 days' WHERE workspace=%s AND seq<=%s", (ws, old_cut))
    for cursor in (str(int(full[0]['seq'])), str(old_cut)):
        r = cl.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': cursor})
        assert r.status_code == 410 and r.json()['code'] == 'EVENT_CURSOR_EXPIRED_RESNAPSHOT'
        p = cl.get(base(world) + f'/events?after={cursor}', headers=h)
        assert p.status_code == 410
    # Without a cursor the feed is a fresh seven-day replay: expired rows are simply not served, no error.
    fresh = domain(cl.get(base(world) + '/events/stream?replay_only=true', headers=h).text)
    assert all(int(e['seq']) > old_cut for e in fresh) and fresh
    # Authorized resnapshot: only a member can obtain the watermark; resuming from it never 410s and loses nothing newer.
    snap = cl.get(base(world) + '/snapshot', headers=h)
    assert snap.status_code == 200
    watermark = snap.json()['last_sequence']
    assert watermark.isdecimal()
    world['dba'].submit(ws, 'ev-researcher-' + world['tag'], f'after-snap-{uuid.uuid4()}', {'epochs': 1, 'scope': 'synthetic-execution-only'})
    resumed = domain(cl.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': watermark}).text)
    assert len(resumed) == 1 and int(resumed[0]['seq']) > int(watermark)
    assert world['anon'].get(base(world) + '/snapshot').status_code == 401
    assert world['stranger'].get(base(world) + '/snapshot', headers=world['stranger_h']).status_code == 404
    STATE['expiry'] = 'ok'


def test_cursor_validation_and_workspace_binding(world):
    cl, h = world['researcher'], world['researcher_h']
    for bad in ('abc', '-1', '1.5', '9' * 20, '9223372036854775808', ' 7', '0x10'):
        r = cl.get(base(world) + '/events/stream?replay_only=true', headers={**h, 'Last-Event-ID': bad})
        assert r.status_code == 409 and r.json()['code'] == 'EVENT_CURSOR_INVALID', bad
    # The other tenant's session cannot use any cursor against this workspace, nor read its events.
    s, sh = world['stranger'], world['stranger_h']
    for cursor in ('0', '1', '99999'):
        assert s.get(base(world) + '/events/stream?replay_only=true', headers={**sh, 'Last-Event-ID': cursor}).status_code == 404
    assert s.get(base(world) + '/events?after=0', headers=sh).status_code == 404
    assert world['anon'].get(base(world) + '/events/stream?replay_only=true').status_code == 401


# ----------------------------------------------------------------------------------------------- revocation
class LiveStream:
    """A real streaming HTTP response consumed in a thread; records lines and the time each arrived."""

    def __init__(self, client, url, headers):
        self.lines, self.times, self.error, self.finished = [], [], None, threading.Event()
        self.got_domain = threading.Event()
        def run():
            try:
                with client.stream('GET', url, headers=headers) as response:
                    self.status = response.status_code
                    for line in response.iter_lines():
                        self.lines.append(line)
                        self.times.append(time.monotonic())
                        if line == 'event: domain':
                            self.got_domain.set()
            except Exception as exc:  # noqa: BLE001 - reported by the assertion
                self.error = repr(exc)
            finally:
                self.finished.set()
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()


def _revocation_case(world, label, revoke):
    chain, api = world['chain'], world['api']
    name = f"ev-rev-{label}-{world['tag']}".replace('_', '-')
    workspace = world['ws'] if label != 'tombstone' else 'ev-tomb-' + world['tag']
    make_account(chain, name, 'researcher', workspace)
    if label == 'tombstone':
        chain.dba.submit(workspace, name, 'k', {'epochs': 1, 'scope': 'synthetic-execution-only'})
    client = TestClient(api.app)
    client.__enter__()
    try:
        headers = login(client, name)
        stream = LiveStream(client, f'/api/v1/workspaces/{workspace}/events/stream', headers)
        assert stream.got_domain.wait(15), (label, stream.error)
        started = time.monotonic()
        revoke(name, workspace, headers, client)
        assert stream.finished.wait(30), f'{label}: stream still open 30 s after revocation'
        elapsed = time.monotonic() - started
        assert 'event: access_revoked' in stream.lines and stream.error is None, (label, stream.error, stream.lines[-3:])
        assert elapsed < 30
        return round(elapsed, 2)
    finally:
        client.__exit__(None, None, None)


def test_open_stream_closes_within_thirty_seconds_for_every_revocation_path(world):
    chain = world['chain']
    def sql(statement, args=()):
        with chain.dba.connect() as c:
            c.execute(statement, args)
    owner, oh = world['owner'], world['owner_h']
    revokers = {
        'logout': lambda n, w, h, c: c.post('/auth/logout', headers=h),
        'role_change_by_owner': lambda n, w, h, c: owner.put(f'/api/v1/workspaces/{w}/real/settings/members/{n}', headers=oh, json={'role': 'viewer'}),
        'workspace_moved': lambda n, w, h, c: sql('UPDATE fw_accounts SET workspace=%s WHERE name=%s', ('gone-' + n, n)),
        'session_expired': lambda n, w, h, c: sql("UPDATE fw_sessions SET expires=clock_timestamp()-interval '1 second' WHERE name=%s", (n,)),
        'idle_timeout': lambda n, w, h, c: sql("UPDATE fw_sessions SET last_seen=clock_timestamp()-interval '31 minutes' WHERE name=%s", (n,)),
        'session_deleted': lambda n, w, h, c: sql('DELETE FROM fw_sessions WHERE name=%s', (n,)),
        'tombstone': lambda n, w, h, c: sql('''INSERT INTO fw_privacy_workspace_tombstones(workspace,request_id,requested_by,expected_settings_revision,deleted_utc,archive_due_utc)
            VALUES(%s,%s,'events-matrix',1,now(),now()+interval '7 days')''', (w, str(uuid.uuid4()))),
    }
    times = {label: _revocation_case(world, label, fn) for label, fn in revokers.items()}
    STATE['revocation_seconds'] = times
    assert max(times.values()) < 30 and len(times) == 7


def test_stream_of_the_workspace_that_stays_open_is_unaffected_by_another_members_revocation(world):
    c, h = world['researcher'], world['researcher_h']
    stream = LiveStream(c, base(world) + '/events/stream', h)
    assert stream.got_domain.wait(15)
    time.sleep(2.5)
    assert not stream.finished.is_set() and 'event: access_revoked' not in stream.lines
    assert any(line.startswith(': heartbeat') for line in stream.lines)
    world['dba'].submit(world['ws'], 'ev-researcher-' + world['tag'], f'live-{uuid.uuid4()}', {'epochs': 1, 'scope': 'synthetic-execution-only'})
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and sum(1 for l in stream.lines if l == 'event: domain') < 2:
        time.sleep(.25)
    assert sum(1 for l in stream.lines if l == 'event: domain') >= 2  # live tail delivers new durable events
    c.post('/auth/logout', headers=h)  # end the stream; re-login for later tests
    assert stream.finished.wait(30)
    world['researcher_h'] = login(c, 'ev-researcher-' + world['tag'])


# ----------------------------------------------------------------------------------------------- metrics independent of delivery count
def test_metrics_are_computed_from_verified_evidence_never_from_event_delivery(world):
    c, h = world['researcher'], world['researcher_h']
    run = f"{base(world)}/runs/{world['evidence_run']}"
    before = c.get(run + '/evaluation', headers=h).json()
    with world['dba'].connect() as db:
        counts = {t: db.execute(f'SELECT count(*) AS n FROM {t}').fetchone()['n'] for t in ('fw_events', 'fw_runs', 'fw_checkpoints')}
    for _ in range(5):  # five full deliveries of every event, plus polls and a snapshot
        c.get(base(world) + '/events/stream?replay_only=true', headers=h)
        c.get(base(world) + '/events?after=0', headers=h)
        c.get(base(world) + '/snapshot', headers=h)
    after = c.get(run + '/evaluation', headers=h).json()
    with world['dba'].connect() as db:
        counts_after = {t: db.execute(f'SELECT count(*) AS n FROM {t}').fetchone()['n'] for t in counts}
    assert after == before and counts == counts_after  # delivery is read-only and never alters evaluation
    # And the producer of metrics has no dependency on the transport.
    import fieldwork.metrics as metrics, fieldwork.events as events
    msrc, esrc = Path(metrics.__file__).read_text(), Path(events.__file__).read_text()
    assert not re.search(r'^\s*(from|import)\s+.*\bevents\b', msrc, re.M)
    assert 'metrics' not in esrc and 'evaluate' not in esrc


def test_write_state_summary(world):
    out = Path(world['api'].ROOT) / 'var' / 'matrix-state-events.json'
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(STATE, default=str))
    assert STATE.get('events_ordered') and STATE.get('revocation_seconds')
