"""Read-only screen projections for the Fieldwork web UI (round 5 UI lane).

Every route here is a GET, scoped exactly like fieldwork.api handlers: session ->
workspace membership (404 OBJECT_OR_MEMBERSHIP), RLS through the request store
(`api.store`, resolved per call so isolated tests can substitute it). Nothing is
written. Values that the database does not hold are returned as explicit
absences (empty lists / None / `*_supported: False`), never synthesized.
"""
import json
import os
from datetime import datetime, timezone

import psutil, shutil
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from .store import ROOT, PUBLIC_EVENT_FILTER
from .operator_overrides import required_free_bytes
from .data import canonical, digest, generate

BASE = '/api/v1/workspaces/{workspace_id}'
router = APIRouter()

ROLES = ('owner', 'researcher', 'reviewer', 'viewer', 'holdout_steward')
# Mirrors fieldwork.api.submit and fieldwork.worker.preflight admission literals.
REQUIRED_RAM_BYTES = 6 * 1024 ** 3
REQUIRED_DISK_BYTES = required_free_bytes(12 * 1024 ** 3)  # lowered only by the recorded operator space override
# worker.json is rewritten each supervisor loop (<=30 s back-off); a run in
# execution renews its DB lease instead, which is reported per run below.
WORKER_STALE_SECONDS = 90
ACTIVE_STATES = ('queued', 'leased', 'running', 'cancel_requested', 'interrupted')
TERMINAL_STATES = ('succeeded', 'failed', 'cancelled')


def _api():
    from . import api
    return api


def scoped(workspace_id: str, request: Request):
    """Same chain as api.scoped(Depends(api.session)), resolved at call time."""
    api = _api()
    return api.scoped(workspace_id, api.session(request))


def _now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.isoformat().replace('+00:00', 'Z') if value is not None else None


def _worker():
    path = ROOT / 'var/worker.json'
    if not path.exists():
        return {'status': 'none', 'heartbeat': None, 'age_seconds': None, 'stale_after_seconds': WORKER_STALE_SECONDS}
    try:
        beat = json.loads(path.read_text())
        at = datetime.fromisoformat(beat['as_of'])
    except (OSError, ValueError, KeyError, TypeError):
        return {'status': 'unreadable', 'heartbeat': None, 'age_seconds': None, 'stale_after_seconds': WORKER_STALE_SECONDS}
    age = max(0.0, (_now() - at).total_seconds())
    return {'status': 'fresh' if age <= WORKER_STALE_SECONDS else 'stale',
            'heartbeat': {k: beat.get(k) for k in ('pid', 'as_of', 'profile', 'hard_isolation')},
            'age_seconds': round(age, 1), 'stale_after_seconds': WORKER_STALE_SECONDS}


def _preflight():
    ram = psutil.virtual_memory().available
    disk = shutil.disk_usage(ROOT).free
    ram_override = os.environ.get('FIELDWORK_OPERATOR_RAM_OVERRIDE') == 'accept-low-available-ram'
    return {'free_ram_bytes': ram, 'required_ram_bytes': REQUIRED_RAM_BYTES, 'ram_ok': ram >= REQUIRED_RAM_BYTES,
            'free_disk_bytes': disk, 'required_disk_bytes': REQUIRED_DISK_BYTES, 'disk_ok': disk >= REQUIRED_DISK_BYTES,
            'admitted': (ram >= REQUIRED_RAM_BYTES or ram_override) and disk >= REQUIRED_DISK_BYTES,
            'operator_ram_override': ram_override,
            'code': None if ((ram >= REQUIRED_RAM_BYTES or ram_override) and disk >= REQUIRED_DISK_BYTES) else 'RESOURCE_PREFLIGHT',
            'checked_at': _iso(_now())}


def _display_state(state, lease_live, worker_status):
    if state == 'queued' and worker_status != 'fresh':
        return 'queued_no_worker'
    if state in ('running', 'leased', 'cancel_requested') and lease_live is False:
        return 'stale_heartbeat'
    return state


@router.get(BASE + '/screens/operations')
def operations(workspace_id: str, user=Depends(scoped)):
    """Queue, worker heartbeat, per-run lease freshness and resource gates."""
    store = _api().store
    worker = _worker()
    with store.connect() as c:
        rows = c.execute(
            "SELECT r.id,r.state,r.epoch,r.fence,r.revision,r.artifact_status,(r.config->>'epochs')::int AS epochs,"
            " r.lease IS NOT NULL AS has_lease, r.lease>clock_timestamp() AS lease_live,"
            " extract(epoch FROM r.lease-clock_timestamp()) AS lease_remaining,"
            " (SELECT count(*) FROM fw_attempts a WHERE a.run=r.id) AS attempts"
            " FROM fw_runs r WHERE r.workspace=%s ORDER BY r.id", (workspace_id,)).fetchall()
        interruptions = c.execute(
            "SELECT e.seq::text AS seq,e.run,e.created,e.payload->>'state' AS state,"
            " (SELECT max((p.payload->>'epoch')::int) FROM fw_events p WHERE p.workspace=e.workspace AND p.run=e.run"
            "   AND p.kind='epoch_committed' AND p.seq<e.seq) AS committed_epoch,"
            " (SELECT (q.payload->>'replay_epoch')::int FROM fw_events q WHERE q.workspace=e.workspace AND q.run=e.run"
            "   AND q.kind='resume_requested' AND q.seq>e.seq ORDER BY q.seq LIMIT 1) AS replay_epoch"
            " FROM fw_events e WHERE e.workspace=%s AND e.kind='expired'"
            " ORDER BY e.seq DESC LIMIT 20", (workspace_id,)).fetchall()
    runs = []
    for r in rows:
        live = None if not r['has_lease'] else bool(r['lease_live'])
        tracked = r['state'] in ('leased', 'running', 'cancel_requested')
        runs.append({'id': r['id'], 'state': r['state'], 'epoch': r['epoch'], 'epochs': r['epochs'], 'fence': r['fence'],
                     'revision': r['revision'], 'artifact_status': r['artifact_status'], 'attempts': r['attempts'],
                     'lease': ('live' if live else 'expired' if live is False else 'none') if tracked else 'not_applicable',
                     'lease_remaining_seconds': round(float(r['lease_remaining']), 1) if tracked and r['lease_remaining'] is not None else None,
                     'display_state': _display_state(r['state'], live if tracked else None, worker['status'])})
    counts = {s: sum(1 for r in runs if r['state'] == s) for s in ACTIVE_STATES + TERMINAL_STATES}
    other = sorted({r['state'] for r in runs} - set(counts))
    for s in other:
        counts[s] = sum(1 for r in runs if r['state'] == s)
    return {'as_of': _iso(_now()), 'worker': worker, 'queue_length': counts['queued'], 'counts': counts, 'runs': runs,
            'interruptions': [{**i, 'created': _iso(i['created'])} for i in interruptions],
            'preflight': _preflight()}


@router.get(BASE + '/screens/runs/{run_id}/lineage')
def lineage(workspace_id: str, run_id: str, user=Depends(scoped)):
    """Durable attempt lineage, committed checkpoints and the run's domain events.

    Unlike /events (seven-day delivery replay) this reads the retained history of
    one run. Command receipts and evaluation flags stay excluded."""
    store = _api().store
    with store.connect() as c:
        r = c.execute("SELECT id,state,epoch,fence,revision,attempt,checkpoint IS NOT NULL AS has_checkpoint,"
                      " (config->>'epochs')::int AS epochs, lease>clock_timestamp() AS lease_live"
                      " FROM fw_runs WHERE id=%s AND workspace=%s", (run_id, workspace_id)).fetchone()
        if not r:
            raise HTTPException(404, 'OBJECT')
        attempts = [row['a'] for row in c.execute('SELECT to_jsonb(a) AS a FROM fw_attempts a WHERE run=%s ORDER BY fence', (run_id,)).fetchall()]
        checkpoints = c.execute('SELECT epoch,attempt,digest,metrics FROM fw_checkpoints WHERE run=%s ORDER BY epoch', (run_id,)).fetchall()
        # Order by the bigint column, not the text alias (lexical order would put 20 before 5).
        events = c.execute('SELECT e.seq::text AS seq,e.kind,e.payload,e.created,e.object_revision FROM fw_events e'
                           ' WHERE e.workspace=%s AND e.run=%s AND ' + PUBLIC_EVENT_FILTER + ' ORDER BY e.seq', (workspace_id, run_id)).fetchall()
    keep = ('id', 'fence', 'created', 'cancel_generation')
    attempts = [{k: a.get(k) for k in keep if k in a} for a in attempts]
    for a in attempts:
        a['committed_epochs'] = [cp['epoch'] for cp in checkpoints if cp['attempt'] == a['id']]
        a['current'] = a['id'] == r['attempt']
    events = [{**e, 'created': _iso(e['created'])} for e in events]
    boundaries = []
    for i, e in enumerate(events):
        if e['kind'] != 'expired':
            continue
        committed = max([x['payload'].get('epoch') for x in events[:i] if x['kind'] == 'epoch_committed' and isinstance(x['payload'], dict)] or [0])
        resume = next((x for x in events[i + 1:] if x['kind'] == 'resume_requested'), None)
        claim = next((x for x in events[i + 1:] if x['kind'] == 'claimed'), None) if resume else None
        boundaries.append({'interrupted_seq': e['seq'], 'interrupted_at': e['created'], 'resulting_state': (e['payload'] or {}).get('state'),
                           'committed_epoch': committed,
                           'resume_seq': resume['seq'] if resume else None,
                           'replay_epoch': (resume['payload'] or {}).get('replay_epoch') if resume else None,
                           'new_attempt': (claim['payload'] or {}).get('attempt') if claim else None,
                           'new_fence': (claim['payload'] or {}).get('fence') if claim else None})
    budget = 3  # fieldwork.store.resume ATTEMPT_BUDGET literal
    resumable = (r['state'] == 'interrupted' and r['has_checkpoint']
                 and len(attempts) < budget and r['epoch'] < r['epochs'])
    reason = None if resumable else (
        'NOT_INTERRUPTED' if r['state'] != 'interrupted'
        else 'NO_COMMITTED_CHECKPOINT' if not r['has_checkpoint']
        else 'ATTEMPT_BUDGET' if len(attempts) >= budget
        else 'NO_REMAINING_EPOCHS')
    return {'run_id': r['id'], 'state': r['state'], 'epoch': r['epoch'], 'epochs': r['epochs'], 'fence': r['fence'],
            'revision': r['revision'], 'current_attempt': r['attempt'],
            'lease': None if r['lease_live'] is None else ('live' if r['lease_live'] else 'expired'),
            'attempts': attempts, 'checkpoints': checkpoints, 'events': events, 'boundaries': boundaries,
            'recovery': {'resumable': resumable, 'blocked_code': reason, 'next_replay_epoch': r['epoch'] + 1 if resumable else None,
                         'attempt_budget': budget, 'attempts_used': len(attempts)}}


def _real_validation_bundle(workspace_id, run_id, user):
    from .real_workspace_api import _lock_artifact, _real_training_run, _verified_bundle
    api = _api()
    store = api.store
    with store.connect() as c:
        _lock_artifact(c, workspace_id, run_id)
        run = _real_training_run(store, workspace_id, run_id)
        bundle, manifest = _verified_bundle(run, workspace_id, user['name'],
            api.rights_service(), store=store, allow_expired=True)
    return bundle, manifest, run


def _real_validation_bytes(bundle, manifest, name):
    from .real_workspace_api import _read_bound_file
    record = manifest.get('files', {}).get(name)
    if type(record) is not dict or type(record.get('bytes')) is not int or record['bytes'] > 32 * 1024 * 1024:
        raise HTTPException(409, 'REAL_VALIDATION_FILE_INVALID')
    try:
        return _read_bound_file(bundle / name, record['bytes'], record['sha256'])
    except Exception:
        raise HTTPException(409, 'REAL_VALIDATION_INTEGRITY') from None


def _real_validation_json(bundle, manifest, name):
    try:
        return json.loads(_real_validation_bytes(bundle, manifest, name).decode('utf-8'))
    except HTTPException:
        raise
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(409, 'REAL_VALIDATION_JSON_INVALID') from None


def _real_validation_digest(bundle_digest, manifest):
    record = manifest.get('files', {}).get('evaluation/metrics.json')
    if type(record) is not dict or not isinstance(record.get('sha256'), str):
        raise HTTPException(409, 'REAL_VALIDATION_METRICS_MISSING')
    return digest(canonical({'bundle_digest': bundle_digest, 'metrics_sha256': record['sha256'],
                             'scope': 'real-training/v1', 'split': 'validation'}))


@router.get(BASE + '/real/runs/{run_id}/validation')
def real_validation(workspace_id: str, run_id: str, response: Response, user=Depends(scoped)):
    """Verified aggregates for a completed real run's validation split only."""
    bundle, manifest, run = _real_validation_bundle(workspace_id, run_id, user)
    metrics = _real_validation_json(bundle, manifest, 'evaluation/metrics.json')
    independent = _real_validation_json(bundle, manifest, 'evaluation/independent-report.json')
    classes = _real_validation_json(bundle, manifest, 'classes.json')
    if type(classes) is not list or len(classes) != 5 or any(type(x) is not str for x in classes):
        raise HTTPException(409, 'REAL_VALIDATION_CLASSES_INVALID')
    from .real_bundle import metrics_agree
    if type(metrics) is not dict or not metrics_agree(independent, metrics):
        raise HTTPException(409, 'REAL_VALIDATION_VERIFICATION_MISMATCH')
    bundle_digest = (run.get('artifact_result') or {}).get('bundle_digest')
    if not isinstance(bundle_digest, str):
        raise HTTPException(409, 'REAL_VALIDATION_BUNDLE_BINDING')
    fields = ('n', 'ok', 'accuracy', 'coverage', 'matrix', 'support', 'precision',
              'recall', 'f1', 'macro_f1', 'cross_entropy', 'status',
              'disposition_counts', 'null_reasons', 'cross_entropy_complete')
    response.headers['Cache-Control'] = 'no-store'
    return {'run_id': run_id, 'scope': 'real-training/v1', 'split': 'validation',
            'evidence_scope': 'validation_only', 'classes': classes,
            'metrics': {key: metrics[key] for key in fields if key in metrics},
            'independent_metrics_match': True, 'bundle_digest': bundle_digest,
            'evaluation_digest': _real_validation_digest(bundle_digest, manifest)}


@router.get(BASE + '/real/runs/{run_id}/validation/slices')
def real_validation_slice(workspace_id: str, run_id: str,
                          response: Response,
                          actual: int = Query(ge=0, le=4),
                          predicted: int | None = Query(default=None, ge=0, le=4),
                          bucket: str = Query(default='cell', pattern=r'^(cell|missing)$'),
                          offset: int = Query(default=0, ge=0, le=100000),
                          limit: int = Query(default=24, ge=1, le=100),
                          user=Depends(scoped)):
    """Page exact error members from the verified validation population."""
    bundle, manifest, run = _real_validation_bundle(workspace_id, run_id, user)
    if (bucket == 'cell' and predicted is None) or (bucket == 'missing' and predicted is not None):
        raise HTTPException(422, 'REAL_VALIDATION_SLICE_PREDICATE')
    metrics = _real_validation_json(bundle, manifest, 'evaluation/metrics.json')
    if bucket == 'cell':
        ids = metrics.get('cells', {}).get(f'{actual}:{predicted}', [])
    else:
        by_class = metrics.get('missing_by_class', [])
        ids = by_class[actual] if len(by_class) == 5 else []
    if type(ids) is not list or any(type(x) is not str for x in ids) or ids != sorted(set(ids)):
        raise HTTPException(409, 'REAL_VALIDATION_SLICE_INVALID')
    records = {}
    for line in _real_validation_bytes(bundle, manifest, 'evaluation/predictions.jsonl').splitlines():
        if line:
            row = json.loads(line)
            if type(row) is not dict or not isinstance(row.get('id'), str):
                raise HTTPException(409, 'REAL_VALIDATION_RECORD_INVALID')
            records[row['id']] = row
    members = []
    for sample_id in ids[offset:offset + limit]:
        record = records.get(sample_id)
        if not record:
            raise HTTPException(409, 'REAL_VALIDATION_RECORD_MISSING')
        logits = record.get('logits')
        prediction = max(range(5), key=lambda i: logits[i]) if record.get('status') == 'ok' else None
        if (record.get('status') not in {'ok', 'missing', 'decode_failed', 'inference_failed'}
                or type(record.get('label')) is not int or record['label'] != actual
                or (bucket == 'cell' and prediction != predicted)
                or (bucket == 'missing' and record.get('status') == 'ok')):
            raise HTTPException(409, 'REAL_VALIDATION_RECORD_BINDING')
        members.append({'sample_id': sample_id, 'actual': actual,
                        'predicted': prediction, 'status': record['status']})
    bundle_digest = (run.get('artifact_result') or {}).get('bundle_digest')
    if not isinstance(bundle_digest, str):
        raise HTTPException(409, 'REAL_VALIDATION_BUNDLE_BINDING')
    response.headers['Cache-Control'] = 'no-store'
    return {'run_id': run_id, 'split': 'validation', 'bucket': bucket,
            'predicate': {'actual': actual, 'predicted': predicted}, 'total': len(ids),
            'offset': offset, 'limit': limit, 'members': members,
            'next_offset': offset + len(members) if offset + len(members) < len(ids) else None,
            'membership_digest': digest(canonical(ids)),
            'evaluation_digest': _real_validation_digest(bundle_digest, manifest)}


@router.get(BASE + '/screens/splits')
def split_report(workspace_id: str, user=Depends(scoped)):
    """Split accounting for the pinned generated manifest. Holdout: aggregates only."""
    from .splits import integrity
    api = _api()
    m = generate(api.DATA)
    classes = m['classes']
    by_split = {}
    for s in m['samples']:
        by_split.setdefault(s['split'], []).append(s)
    report = {}
    for split, rows in sorted(by_split.items()):
        report[split] = {'samples': len(rows), 'groups': len({s['group'] for s in rows}),
                         'per_class': [sum(1 for s in rows if s['label'] == i) for i in range(len(classes))],
                         'sealed': split == 'holdout',
                         # Membership digests are published for inspectable splits only.
                         'membership_digest': None if split == 'holdout' else digest(canonical(sorted(s['id'] for s in rows)))}
    problems = integrity({k: [{'sample_id': s['id'], 'raw_sha256': s['sha256'], 'pixel_sha256': s['pixel_sha256'], 'group_id': s['group']} for s in v]
                          for k, v in by_split.items()}, [{'group_id': g} for g in {s['group'] for s in m['samples']}], None, m.get('quarantine', []))
    store = api.store
    with store.connect() as c:
        versions = c.execute("SELECT id,state,manifest->>'scope' AS scope,manifest->>'digest' AS digest FROM fw_versions WHERE workspace=%s ORDER BY id", (workspace_id,)).fetchall()
    return {'manifest_digest': m['digest'], 'scope': m.get('scope'), 'classes': classes, 'splits': report,
            'integrity': {'problems': problems, 'status': 'integrity_blocked' if problems else 'group_disjoint',
                          'quarantined_groups': len(m.get('quarantine', []))},
            'evaluation_plan': {'validation': 'exploratory', 'holdout': 'sealed',
                                'authorizations': [], 'authorizations_supported': False},
            'versions': versions}


@router.get(BASE + '/screens/configure')
def configure(workspace_id: str, user=Depends(scoped)):
    """Inputs the submit command will actually resolve, plus server gates."""
    api = _api()
    m = generate(api.DATA)
    fields = api.Config.model_fields
    def bounds(name):
        meta = {type(x).__name__: x for x in fields[name].metadata}
        lo = getattr(meta.get('Ge'), 'ge', None); hi = getattr(meta.get('Le'), 'le', None)
        return {'min': str(lo) if lo is not None else None, 'max': str(hi) if hi is not None else None, 'default': str(fields[name].default)}
    return {'recipes': [{'id': 'compact-cnn/v1', 'scope': 'synthetic-execution-only'}],
            'dataset': {'digest': m['digest'], 'scope': m.get('scope'), 'classes': m['classes'],
                        'counts': {s: sum(x['split'] == s for x in m['samples']) for s in ('train', 'validation', 'holdout')},
                        'holdout_in_training': False},
            'bounds': {k: bounds(k) for k in ('epochs', 'batch_size', 'learning_rate', 'seed')},
            'may_submit': _allowed(api.writer, user['role']),
            'preflight': _preflight(), 'worker': _worker()}


class _ProbeRequest:
    headers = {'origin': 'http://127.0.0.1:5102', 'x-csrf-token': 'probe'}


def _allowed(guard, role):
    """Evaluate the enforcing api guard itself for a role (valid origin/CSRF)."""
    try:
        guard(_ProbeRequest(), {'role': role, 'csrf': 'probe'})
        return True
    except HTTPException:
        return False


@router.get(BASE + '/screens/access')
def access(workspace_id: str, user=Depends(scoped)):
    api = _api()
    store = api.store
    with store.connect() as c:
        members = c.execute('SELECT name,role FROM fw_accounts WHERE workspace=%s ORDER BY role,name', (workspace_id,)).fetchall()
    guards = [('Submit, cancel, resume, create/freeze version, propose label', api.writer),
              ('Review label proposal or exact version', api.reviewer),
              ('Flag an evaluation slice', api.flag_writer)]
    policy = [{'action': name, 'roles': [r for r in ROLES if _allowed(g, r)]} for name, g in guards]
    policy += [{'action': 'Read workspace records', 'roles': list(ROLES)},
               {'action': 'Sealed holdout media', 'roles': [], 'code': 'HOLDOUT_SEALED'},
               {'action': 'Internal candidate download', 'roles': [], 'code': 'INTERNAL_CANDIDATE_NOT_DOWNLOADABLE'},
               {'action': 'Qualified release download', 'roles': ['owner', 'researcher'],
                'code': 'CURRENT_MODEL_BUNDLE_RIGHTS_REQUIRED'},
               {'action': 'Qualified release inference', 'roles': ['owner', 'researcher', 'reviewer'],
                'code': 'CURRENT_READ_ONLY_INFERENCE_RIGHTS_REQUIRED'}]
    owners = sum(1 for m in members if m['role'] == 'owner')
    return {'me': {'name': user['name'], 'role': user['role'], 'workspace': workspace_id},
            'members': members, 'owner_count': owners,
            'policy': policy, 'roles_editable_in_browser': False,
            'session': {'idle_timeout_minutes': 30, 'absolute_hours': 12, 'cookie': 'HttpOnly; SameSite=Strict; loopback HTTP'},
            'support_export_supported': True, 'retention_policy_supported': False}


@router.get(BASE + '/screens/inference')
def inference(workspace_id: str, user=Depends(scoped)):
    api = _api()
    with api.store.connect() as c:
        rows = c.execute("SELECT id,state,artifact_status FROM fw_runs WHERE workspace=%s AND state='succeeded' AND config->>'scope'='real-training/v1' ORDER BY id", (workspace_id,)).fetchall()
    from .qualified_release import registered_release, require_consumed_plan
    qualified = registered_release('flowers-r5-small-residual-v1', workspace_id)
    if not qualified or not require_consumed_plan(api.store, qualified):
        qualified = None
    release_view = [] if not qualified else [{
        'release_id': qualified['release_id'], 'purpose': 'qualified_release',
        'recipe': 'small-residual/v1', 'bundle_digest': qualified['manifest_sha256'],
        'model_digest': qualified['model_digest'], 'plan_id': qualified['plan_id'],
        'aggregate': qualified['attestation']['aggregate'],
    }]
    runtime_ready = (bool(__import__('os').environ.get('FIELDWORK_REAL_PIXEL_IMAGE_ID'))
        and bool(__import__('os').environ.get('FIELDWORK_QUALIFIED_MODEL_IMAGE_ID'))
        and __import__('os').environ.get('FIELDWORK_QUALIFIED_MODEL_IMAGE_ID')
            == __import__('os').environ.get('FIELDWORK_REAL_MODEL_IMAGE_ID'))
    return {'candidates': [{'run_id': r['id'], 'artifact_status': r['artifact_status'], 'qualified_release': False} for r in rows],
            'qualified_releases': release_view,
            'ordinary_inference': {'allowed': bool(qualified and runtime_ready and user['role'] in {'owner','researcher','reviewer'}),
                'code': 'READY' if qualified and runtime_ready and user['role'] in {'owner','researcher','reviewer'} else 'QUALIFIED_RELEASE_REQUIRED'},
            'role_may_request': user['role'] in {'owner','researcher','reviewer'},
            'input_limits': {'max_bytes': 5 * 1024 * 1024, 'max_pixels': 20_000_000, 'types': ['image/png', 'image/jpeg', 'image/webp']},
            'records': [], 'records_supported': False}
