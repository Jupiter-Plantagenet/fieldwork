"""Shared paths/context for the round-4 dataset delivery drivers (dataset lane only)."""
import json
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

DS = ROOT / 'var/datasets/tf_flowers'
MANIFESTS = DS / 'manifests'
RIGHTS_DIR = DS / 'rights'
EVIDENCE = ROOT / 'evidence/ml/round4/tests'
CONTEXT = DS / 'round4-context.json'
ISOLATED_DB = 'fieldwork_round4_dataset'
RESEARCH = Path('C:/Users/user/portfolio-build/rights-research')
STEWARD_LABEL = ('AI steward (Claude, Anthropic model) acting under the user authorization in '
                 'goal-tracking/USER-AUTHORIZATION-20261030.md. Not a human reviewer and not legal advice.')


def _dsn(file, dbname):
    params = conninfo_to_dict(json.loads((ROOT / file).read_text())['dsn'])
    params['dbname'] = dbname
    return make_conninfo(**params)


def admin_dsn(dbname=ISOLATED_DB):
    return _dsn('.local.json', dbname)


def api_dsn(dbname=ISOLATED_DB):
    return _dsn('.local-api.json', dbname)


def context():
    if CONTEXT.exists():
        return json.loads(CONTEXT.read_text())
    ctx = {'workspace_id': str(uuid.uuid4()), 'rights_dataset_full': str(uuid.uuid4()),
           'rights_dataset_eligible': str(uuid.uuid4()), 'steward_reviewer_id': str(uuid.uuid4()),
           'steward_key_id': str(uuid.uuid4()), 'isolated_db': ISOLATED_DB,
           'actors': {'steward': 'ai-steward', 'researcher': 'sim-researcher', 'reviewer': 'sim-reviewer'}}
    CONTEXT.parent.mkdir(parents=True, exist_ok=True)
    CONTEXT.write_text(json.dumps(ctx, indent=1))
    return ctx


def write_json(path, obj, pretty=True):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=1 if pretty else None, sort_keys=True, ensure_ascii=False, default=str)
    path.write_text(data + '\n', encoding='utf-8')
    return path


def request_store(workspace):
    from fieldwork.store import Store, TENANT
    TENANT.set(workspace)
    return Store(dsn=api_dsn(), request=True)


def set_registry_env():
    os.environ['FIELDWORK_RIGHTS_REVIEWERS_FILE'] = str(RIGHTS_DIR / 'reviewers.json')
