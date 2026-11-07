"""Exercise the REAL FastAPI rights routes (fieldwork.api) over ASGI against the isolated DB.

Not the live 8102 process: the retained DB has no fw_rights_* tables (003 unapplied),
so the live route would answer RIGHTS_DATABASE_DEPENDENCY. Here the module-level
`api.store` is swapped for a request-principal Store bound to the isolated database
and the session dependency is overridden (as tests/test_signed_rights_adapters.py
does). Origin/CSRF/writer-role checks and the route code itself are unchanged.
Envelopes are the retained AI-steward decisions (re-submitted; idempotent upsert).
"""
import json
import time

from round4_common import EVIDENCE, RIGHTS_DIR, context, request_store, set_registry_env, write_json


def main():
    ctx = context()
    ws = ctx['workspace_id']
    set_registry_env()
    from fastapi.testclient import TestClient
    from fieldwork import api
    api.store = request_store(ws)
    api.app.dependency_overrides[api.session] = lambda: dict(name=ctx['actors']['steward'], workspace=ws, role='owner', csrf='round4-csrf')
    client = TestClient(api.app)  # no `with`: lifespan (synthetic fixture/checkpoint helper) not started
    base = f'/api/v1/workspaces/{ws}/datasets/{ctx["rights_dataset_eligible"]}'
    hdr = {'origin': 'http://127.0.0.1:5102', 'x-csrf-token': 'round4-csrf'}
    rows = [json.loads(line) for line in (RIGHTS_DIR / 'decisions-model_bundle.jsonl').open(encoding='utf-8')]
    rows = [r for r in rows if r['dataset_id'] == ctx['rights_dataset_eligible']][:25]
    posted = []
    for r in rows:
        resp = client.post(base + '/rights/model_bundle', params={'member_id': r['member_id']}, content=r['envelope'].encode(), headers=hdr)
        posted.append([resp.status_code, resp.json()])
    # Forged signature (fresh unregistered key, granted purpose) via the route on the FULL
    # inventory: must quarantine and invalidate the earlier valid decision for that member.
    from fieldwork.rights_operator import StewardSigner
    full_rows = [json.loads(line) for line in (RIGHTS_DIR / 'decisions-model_bundle.jsonl').open(encoding='utf-8')]
    target = next(r for r in full_rows if r['dataset_id'] == ctx['rights_dataset_full'])
    payload = json.loads(target['envelope'])['payload']
    forger = StewardSigner(payload['reviewer_id'], payload['key_id'], [ws], ['model_bundle'])
    import hashlib
    docs_like = None  # payload digests are reused verbatim; only the signature is forged
    forged = json.dumps({'payload': payload, 'signature_hex': forger._key.sign(b'fieldwork.rights-decision/v1\x00' + __import__('fieldwork.rights_decision', fromlist=['canonical_payload']).canonical_payload(payload)).hex()},
                        sort_keys=True, separators=(',', ':')).encode()
    forger.discard()
    fb = f'/api/v1/workspaces/{ws}/datasets/{ctx["rights_dataset_full"]}'
    forged_resp = client.post(fb + '/rights/model_bundle', params={'member_id': target['member_id']}, content=forged, headers=hdr)
    from fieldwork.store import Store
    from round4_common import admin_dsn
    with Store(dsn=admin_dsn()).connect() as c:
        after = c.execute('SELECT last_result FROM fw_rights_decisions WHERE workspace=%s AND dataset_id=%s AND member_id=%s AND purpose=%s',
                          (ws, ctx['rights_dataset_full'], target['member_id'], 'model_bundle')).fetchone()['last_result']
    no_csrf = client.post(base + '/rights/model_bundle', params={'member_id': rows[0]['member_id']}, content=rows[0]['envelope'].encode())
    t0 = time.monotonic()
    pre = {}
    for purpose in ['local_private_training', 'private_thumbnail_ui', 'model_bundle', 'image_export', 'public_commercial_portfolio']:
        resp = client.get(base + '/rights/preflight', params={'purpose': purpose})
        pre[purpose] = [resp.status_code, resp.json()]
    full = client.get(f'/api/v1/workspaces/{ws}/datasets/{ctx["rights_dataset_full"]}/rights/preflight', params={'purpose': 'model_bundle'})
    out = {'mode': 'ASGI TestClient against fieldwork.api routes; isolated DB; session dependency overridden; NOT the live 8102 process',
           'resubmitted_envelopes': len(posted), 'resubmit_results': sorted({json.dumps(p) for p in posted}),
           'post_without_csrf_origin': [no_csrf.status_code, no_csrf.json()],
           'forged_signature_full_inventory': {'member': target['member_id'], 'response': [forged_resp.status_code, forged_resp.json()],
                                               'persisted_last_result_after': after},
           'preflight_eligible': pre, 'preflight_full_inventory_model_bundle': [full.status_code, full.json()],
           'preflight_seconds': round(time.monotonic() - t0, 1)}
    write_json(EVIDENCE / 'rights/http-route-exercise.json', out)
    print(json.dumps(out, indent=1))
    api.app.dependency_overrides.clear()


if __name__ == '__main__':
    main()
