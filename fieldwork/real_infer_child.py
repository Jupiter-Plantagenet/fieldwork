"""Fresh private real-bundle inference on a generated RGB8 pixel array."""
from __future__ import annotations
import argparse, hashlib, json, math, os, uuid
from pathlib import Path
import torch
from safetensors.torch import load_file
from .data import canonical, digest
from .ml import model
from .real_bundle import verify_real_bundle
from .real_train_child import _inside_file, center, tensor


def infer(bundle, pixel_root, sample_entry, expected_digest, expected_model_image_id,
          scope='real-inference/v1'):
    if (scope not in {'real-inference/v1', 'real-image-inference/v1'}
            or sample_entry.get('split') not in ({'train', 'validation'} if scope == 'real-inference/v1' else {'upload'})):
        raise ValueError('REAL_INFERENCE_SCOPE')
    bundle, pixel_root = Path(bundle), Path(pixel_root)
    manifest = verify_real_bundle(bundle, expected_digest=expected_digest,
                                  expected_lineage={'model_image_id': expected_model_image_id})
    net = model()
    net.load_state_dict(load_file(str(bundle / 'model.safetensors'), device='cpu'), strict=True)
    net.eval(); torch.set_num_threads(2)
    arr = _inside_file(pixel_root, sample_entry)
    with torch.inference_mode():
        logits = net(tensor([center(arr)]))[0]
        probs = logits.softmax(0)
    vector = logits.tolist()
    lineage = json.loads((bundle / 'lineage.json').read_text(encoding='utf-8'))
    result = {'schema': 'fieldwork.real-inference-receipt/v1',
              'scope': scope, 'pid': os.getpid(),
              'process_identity': str(uuid.uuid4()),
              'bundle_digest': digest((bundle / 'manifest.json').read_bytes()),
              'model_digest': lineage['model_digest'],
              'version_id': lineage['version_id'], 'version_digest': lineage['dataset_digest'],
              'sample_id': sample_entry['id'], 'sample_split': sample_entry['split'],
              'pixel_digest': sample_entry['decoded_pixel_sha256'],
              'logits': vector, 'probabilities': probs.tolist(),
              'top1': int(logits.argmax()), 'classes': json.loads((bundle / 'classes.json').read_text()),
              'public_export_authorized': False}
    result['receipt_digest'] = digest(canonical(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', required=True); parser.add_argument('--pixel-root', required=True)
    parser.add_argument('--sample-entry', required=True); parser.add_argument('--expected-bundle-digest', required=True)
    parser.add_argument('--expected-model-image-id', required=True)
    parser.add_argument('--scope', choices=['real-inference/v1','real-image-inference/v1'], default='real-inference/v1')
    args = parser.parse_args(argv)
    entry = json.loads(args.sample_entry)
    print(json.dumps(infer(args.bundle, args.pixel_root, entry, args.expected_bundle_digest,
                           args.expected_model_image_id, args.scope),
                     separators=(',', ':')))


if __name__ == '__main__': main()

