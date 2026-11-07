"""Fresh CPU inference for the one stdlib-verified qualified R5 bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import uuid
from pathlib import Path

import torch
from safetensors.torch import load_file

APP = Path('/app')
if str(APP) not in __import__('sys').path:
    __import__('sys').path.insert(0, str(APP))

PINNED_BUNDLE = 'cf5c88be9addebcf1ade349710494464611e14e1627d44351116ce7a55b6742d'
PINNED_MODEL = 'c5b41d6a12cd2473abac7628ca23aa3abe6afad8304e21164fece14d58c16bde'
PINNED_PLAN = '9252ee17-1e80-4159-8dbf-b3f77d2bb674'
PINNED_RESULT = '6686d29ef0d2b6aa792bdc06508a84d3fdf9e4caa3a7b16165aae1b10cb4256c'
PINNED_RESULT_RECORD = '55d321a06bde245735126ecde5ff1047f779d8d8429591d84b9015a77cbaac6d'
PINNED_VERSION = '553eec3b-7173-442a-b99d-995ca63c18a5'
PINNED_VERSION_DIGEST = 'a298b6e702310a224370b21213edfb0925e005dd176ed98f177f31ad844c58f8'
PINNED_PREPROCESS = '865d7ea9790301672bbbbe61f73fa4653878f17c8eec4814ae75a80c51c59d76'


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def infer(bundle: Path, pixel_root: Path, entry: dict, *, expected_bundle: str,
          expected_model: str, expected_plan: str, expected_result: str,
          expected_model_image: str) -> dict:
    from tools.verify_release_bundle import check
    from fieldwork import residual_recipe as recipe
    from fieldwork.real_train_child import _inside_file, center, tensor
    if (expected_bundle != PINNED_BUNDLE or expected_model != PINNED_MODEL
            or expected_plan != PINNED_PLAN or expected_result != PINNED_RESULT
            or _sha(bundle / 'manifest.json') != expected_bundle):
        raise ValueError('QUALIFIED_RELEASE_PIN')
    check(bundle, expected_bundle)
    att = json.loads((bundle / 'evaluation/final-acceptance-attestation.json').read_text(encoding='utf-8'))
    manifest = json.loads((bundle / 'manifest.json').read_text(encoding='utf-8'))
    arch = json.loads((bundle / 'architecture.json').read_text(encoding='utf-8'))
    lineage = json.loads((bundle / 'lineage.json').read_text(encoding='utf-8'))
    if (att['plan_id'] != expected_plan or att['plan_result_sha256'] != expected_result
            or att['candidate_model_digest'] != expected_model or att['passed'] is not True
            or manifest['purpose'] != 'qualified_release' or manifest['recipe'] != recipe.RECIPE
            or set(arch) != {'schema','id','dropout','parameters','state_keys'}
            or arch['schema'] != 1 or arch['id'] != recipe.RECIPE
            or arch['dropout'] != '0.2' or arch['parameters'] != 1_227_685
            or lineage['model_digest'] != expected_model or lineage['version_id'] != PINNED_VERSION
            or lineage['dataset_digest'] != PINNED_VERSION_DIGEST
            or _sha(bundle / 'preprocess.json') != PINNED_PREPROCESS
            or type(entry) is not dict or set(entry) !=
                {'id','split','pixel_file','width','height','decoded_pixel_sha256'}
            or entry['split'] != 'upload' or type(entry['id']) is not str):
        raise ValueError('QUALIFIED_RELEASE_BINDING')
    torch.set_num_threads(2)
    network = recipe.build(float(arch['dropout']))
    network.load_state_dict(load_file(str(bundle / 'model.safetensors'), device='cpu'), strict=True)
    network.eval()
    pixels = _inside_file(pixel_root, entry)
    with torch.inference_mode():
        logits = network(tensor([center(pixels)]))[0]
        probabilities = logits.softmax(0)
    vector = logits.tolist()
    probs = probabilities.tolist()
    if (len(vector) != 5 or any(not math.isfinite(x) for x in vector + probs)
            or abs(sum(probs) - 1.0) > 1e-6):
        raise ValueError('QUALIFIED_INFERENCE_NUMERICS')
    classes = [row['name'] for row in json.loads((bundle / 'classes.json').read_text(encoding='utf-8'))]
    receipt = {'schema':'fieldwork.qualified-inference-receipt/v1',
        'scope':'qualified-release-image-inference/v1','pid':os.getpid(),
        'process_identity':str(uuid.uuid4()), 'release_id':'flowers-r5-small-residual-v1',
        'plan_id':expected_plan,'plan_result_sha256':expected_result,
        'result_record_sha256':PINNED_RESULT_RECORD,
        'bundle_digest':expected_bundle,'model_digest':expected_model,
        'version_id':PINNED_VERSION,'version_digest':PINNED_VERSION_DIGEST,
        'model_image_id':expected_model_image, 'sample_id':entry['id'],'sample_split':'upload',
        'pixel_digest':entry['decoded_pixel_sha256'],'logits':vector,'probabilities':probs,
        'top1':int(logits.argmax()),'classes':classes,'public_export_authorized':False}
    from fieldwork.data import canonical, digest
    receipt['receipt_digest'] = digest(canonical(receipt))
    return receipt


def main(argv=None):
    ap = argparse.ArgumentParser()
    for name in ('bundle','pixel-root','sample-entry','expected-bundle','expected-model',
                 'expected-plan','expected-result','expected-model-image'):
        ap.add_argument('--' + name, required=True)
    args = ap.parse_args(argv)
    entry = json.loads(args.sample_entry)
    result = infer(Path(args.bundle), Path(args.pixel_root), entry,
        expected_bundle=args.expected_bundle, expected_model=args.expected_model,
        expected_plan=args.expected_plan, expected_result=args.expected_result,
        expected_model_image=args.expected_model_image)
    print(json.dumps(result, separators=(',',':'), allow_nan=False))


if __name__ == '__main__':
    main()
