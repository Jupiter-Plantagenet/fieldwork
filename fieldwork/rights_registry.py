"""Operator-managed PUBLIC reviewer keys only. No enrollment or trust-from-payload.

Reload every verification so removing a key revokes subsequent use. The file and
its containing directory must be operator controlled, not writable by API users.
"""
import json
import os
from pathlib import Path
from .rights_decision import TrustedReviewer, DecisionRejected, PURPOSES, _token, _UUID


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecisionRejected('TRUST_REGISTRY')
        result[key] = value
    return result


def load_trusted_registry():
    path = os.environ.get('FIELDWORK_RIGHTS_REVIEWERS_FILE')
    if not path:
        return {}
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(262145)
        if len(raw) > 262144:
            raise ValueError()
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
        if type(doc) is not dict or doc.keys() != {'schema', 'reviewers'} or type(doc['schema']) is not int or doc['schema'] != 1 or type(doc['reviewers']) is not list:
            raise ValueError()
        registry = {}
        for entry in doc['reviewers']:
            if type(entry) is not dict or entry.keys() != {'reviewer_id','key_id','public_key_hex','workspace_ids','purposes'}:
                raise ValueError()
            for field in ('reviewer_id','key_id'):
                _token(entry[field], _UUID)
            _token(entry['public_key_hex'], r'[0-9a-f]{64}')
            if type(entry['workspace_ids']) is not list or type(entry['purposes']) is not list:
                raise ValueError()
            for workspace in entry['workspace_ids']:
                _token(workspace, _UUID)
            if any(type(p) is not str or p not in PURPOSES for p in entry['purposes']):
                raise ValueError()
            key = entry['reviewer_id'], entry['key_id']
            if key in registry:
                raise ValueError()
            registry[key] = TrustedReviewer(entry['public_key_hex'], frozenset(entry['workspace_ids']), frozenset(entry['purposes']))
        return registry
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise DecisionRejected('TRUST_REGISTRY') from None
