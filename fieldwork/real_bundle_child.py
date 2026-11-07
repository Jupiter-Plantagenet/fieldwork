"""Fixed, credential-free bundle builder child for the real-model image."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .real_bundle import build
from .data import canonical, digest

MAX_RIGHTS_INPUT = 1_000_000


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--expected-checkpoint-digest', required=True)
    parser.add_argument('--version-id', required=True)
    parser.add_argument('--version-digest', required=True)
    parser.add_argument('--classes-json', required=True)
    parser.add_argument('--model-image-id', required=True)
    args = parser.parse_args(argv)
    payload = __import__('sys').stdin.buffer.read(MAX_RIGHTS_INPUT + 1)
    if len(payload) > MAX_RIGHTS_INPUT:
        raise ValueError('REAL_BUNDLE_RIGHTS_INPUT_BOUNDS')
    rights = json.loads(payload.decode('ascii'))
    if (type(rights) is not list or not rights or len(rights) > 10_000
            or any(type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value)
                   for value in rights)):
        raise ValueError('REAL_BUNDLE_RIGHTS_INPUT_SCHEMA')
    classes = json.loads(args.classes_json)
    if type(classes) is not list or len(classes) != 5:
        raise ValueError('REAL_BUNDLE_CLASSES')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', args.model_image_id):
        raise ValueError('REAL_MODEL_IMAGE_ID')
    manifest = build(args.checkpoint, args.inputs, args.out,
        expected_checkpoint_digest=args.expected_checkpoint_digest,
        version_id=args.version_id, version_digest=args.version_digest,
        classes=classes, rights_decision_digests=rights,
        model_image_id=args.model_image_id)
    print(json.dumps({'schema': 'fieldwork.real-bundle-child/v1',
                      'bundle_digest': digest(canonical(manifest))},
                     separators=(',', ':')))


if __name__ == '__main__':
    main()
