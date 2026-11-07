"""Shared paths/context for the round-5 dataset/ML delivery drivers (dataset lane only).

Round 5 continues in the isolated database `fieldwork_round4_dataset` (same workspace,
catalog, rights inventories and frozen v1) so the new protected population can be
deduplicated against, and frozen as a child version of, the round-4 version.
"""
import json
import os
import uuid
from pathlib import Path

from round4_common import (DS, EVIDENCE as R4_EVIDENCE, MANIFESTS as R4_MANIFESTS, RIGHTS_DIR as R4_RIGHTS, ROOT, STEWARD_LABEL,  # noqa: F401
                           admin_dsn, api_dsn, context as r4_context, request_store, write_json)

# Separate directory for the untrusted Commons downloads and everything derived (real C: dir).
C5 = ROOT / 'var/commons_r5'   # relocated from failing D: on 2026-10-31 (tools/r5_relocate.py)
OLD_C5_PREFIX = 'D:/portfolio-build-data/fieldwork/commons_r5/'   # compared after normalising backslashes
DOWNLOADS = C5 / 'downloads'          # untrusted bytes, never executed, only read by bounded code
CANDIDATES = C5 / 'candidates'        # metadata/rights manifests (steward side)
RIGHTS5 = C5 / 'rights'
STEWARD = C5 / 'steward-sealed'       # per-item holdout content: steward area ONLY
ANNOTATION = C5 / 'annotation'        # blind annotator workspace (anonymised sheets + label files)
MEDIA5 = C5 / 'media'
QUARANTINE5 = C5 / 'quarantine'
EVIDENCE = ROOT / 'evidence/ml/round5/tests'
CONTEXT5 = C5 / 'round5-context.json'
REGISTRY5 = RIGHTS5 / 'reviewers.json'
USER_AGENT = 'FieldworkLocalEval/0.1 (private local ML evaluation; low request rate; no redistribution)'
CLASS_DIRS = ['daisy', 'dandelion', 'roses', 'sunflowers', 'tulips']   # taxonomy order (fieldwork.intake.TAXONOMY)


def context():
    base = r4_context()
    if CONTEXT5.exists():
        ctx = json.loads(CONTEXT5.read_text())
    else:
        ctx = {'rights_dataset_commons': str(uuid.uuid4()), 'steward5_reviewer_id': str(uuid.uuid4()),
               'steward5_key_id': str(uuid.uuid4())}
        CONTEXT5.parent.mkdir(parents=True, exist_ok=True)
        CONTEXT5.write_text(json.dumps(ctx, indent=1))
    return {**base, **ctx}


def set_registry_env():
    """Round-5 registry = round-4 public entry (old decisions keep verifying) + round-5 public entry."""
    os.environ['FIELDWORK_RIGHTS_REVIEWERS_FILE'] = str(REGISTRY5)


def resolve_media(path):
    """Frozen v2 manifest rows of commons-r5 carry their original D: path (digest-bound, immutable).
    Map them to the relocated C: copy; callers re-check the raw SHA-256 before use."""
    p = str(path).replace(chr(92), '/')
    if p.startswith(OLD_C5_PREFIX):
        return str(C5 / p[len(OLD_C5_PREFIX):])
    old_datasets='D:/portfolio-build-data/fieldwork/datasets/'
    if p.startswith(old_datasets):return str(ROOT/'var/datasets'/p[len(old_datasets):])
    if p[:2].lower()=='d:':raise ValueError('FAILING_DRIVE_PATH_NOT_MAPPED')
    return str(path)
