"""Fresh-process CPU inference from a verified qualified-release bundle (no warm model/cache).

Usage: python -I -B tools/r5_bundle_infer.py --bundle DIR --image FILE --expected-bundle-digest SHA256
Verifies the bundle with the stdlib verifier first, then constructs the trusted
small-residual/v1 architecture, strict-loads model.safetensors (no pickle), applies the
stored evaluation preprocessing and prints logits + a process receipt.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bundle', required=True)
    ap.add_argument('--image', required=True)
    ap.add_argument('--expected-bundle-digest', required=True)
    a = ap.parse_args()
    t0 = time.monotonic()
    v = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/verify_release_bundle.py'), a.bundle, a.expected_bundle_digest],
                       capture_output=True, text=True, timeout=600)
    if v.returncode != 0:
        raise SystemExit('BUNDLE_VERIFICATION_FAILED')
    image = Path(a.image)
    if image.stat().st_size > 5 * 1024 * 1024:
        raise SystemExit('IMAGE_TOO_LARGE')
    sys.path.insert(0, str(ROOT))
    import torch
    from safetensors.torch import load_file
    from fieldwork import residual_recipe as rr
    from fieldwork.real_training import center, load_resized, to_tensor
    b = Path(a.bundle)
    arch = json.loads((b / 'architecture.json').read_text())
    if arch['id'] != rr.RECIPE:
        raise SystemExit('RECIPE')
    torch.set_num_threads(2)
    net = rr.build(arch['dropout'])
    net.load_state_dict(load_file(str(b / 'model.safetensors'), device='cpu'), strict=True)
    net.eval()
    with torch.inference_mode():
        logits = net(to_tensor([center(load_resized(image))]))[0]
    import psutil
    out = {'pid': os.getpid(), 'process_create_time': psutil.Process().create_time(), 'process_identity': str(uuid.uuid4()),
           'bundle_digest': hashlib.sha256((b / 'manifest.json').read_bytes()).hexdigest(),
           'model_digest': hashlib.sha256((b / 'model.safetensors').read_bytes()).hexdigest(),
           'preprocess_digest': hashlib.sha256((b / 'preprocess.json').read_bytes()).hexdigest(),
           'input_digest': hashlib.sha256(image.read_bytes()).hexdigest(), 'logits': logits.tolist(),
           'probabilities': logits.softmax(0).tolist(), 'top1': int(logits.argmax()),
           'classes': [c['name'] for c in json.loads((b / 'classes.json').read_text())], 'elapsed_seconds': time.monotonic() - t0,
           'note': 'probabilities are not calibrated confidence or OOD detection'}
    print(json.dumps(out))


if __name__ == '__main__':
    main()
