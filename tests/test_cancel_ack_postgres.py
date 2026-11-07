"""Real-PG cancellation transaction test; requires the authorized isolated_store.

No model/worker/child is launched. This does NOT prove physical exit or request-role
privileges. Do not run against retained databases or bypass fixture admission.
"""
import json
import uuid
from fieldwork.events import replay


def test_cancel_ack_commits_revision_and_replay_event_once(isolated_store):
    store = isolated_store
    workspace = 'authored-ack-' + uuid.uuid4().hex
    run = store.submit(workspace, 'authored-actor', str(uuid.uuid4()), {'epochs': 1})
    attempt = store.claim(run['id'])
    try:
        status, body = store.cancel_command(workspace, 'authored-actor', str(uuid.uuid4()),
                                            run['id'], attempt['revision'], 'Authored cancellation')
        assert status == 200 and json.loads(body)['state'] == 'cancel_requested'
        before = store.get(run['id'])
        cursor = max(event['seq'] for event in store.events(workspace))
        assert before['cancel_generation'] == attempt['cancel_generation'] + 1
        assert store.release_slot(run['id'], fence=attempt['fence'],
                                  cancel_generation=before['cancel_generation']) == 'cancelled'
        after = store.get(run['id'])
        events = replay(store, workspace, cursor, check_expiry=False)
        assert after['state'] == 'cancelled'
        assert after['revision'] == before['revision'] + 1
        assert after['fence'] == before['fence']
        assert len(events) == 1
        assert events[0]['kind'] == 'cancelled'
        assert events[0]['payload'] == {'state': 'cancelled', 'cancel_generation': before['cancel_generation'],
                                       'attempt':attempt['attempt'],'exit_receipt_digest':None,'lease_expired':False}
        assert events[0]['object_revision'] == after['revision']
        assert store.release_slot(run['id'], fence=attempt['fence'],
                                  cancel_generation=before['cancel_generation']) == 'cancelled'
        assert store.get(run['id']) == after
        assert replay(store, workspace, cursor, check_expiry=False) == events
    finally:
        store.release_slot(run['id'], fence=attempt['fence'])
