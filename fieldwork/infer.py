"""Internal candidate verification CLI, not browser inference authority."""
import argparse,json,os,time,uuid
from pathlib import Path
import torch
from safetensors.torch import load_file
from .bundle import verify_bundle
from .ml import model,pixels
from .data import digest,canonical


def infer(bundle,image,expected_bundle_digest=None):
    start=time.monotonic();bundle=Path(bundle);image=Path(image)
    if image.stat().st_size>5*1024*1024:raise ValueError('image size')
    verify_bundle(bundle,expected_digest=expected_bundle_digest);torch.set_num_threads(2);net=model()
    net.load_state_dict(load_file(str(bundle/'model.safetensors')),strict=True);net.eval()
    with torch.inference_mode():
        logits=net(pixels(image).unsqueeze(0))[0];scores=logits.softmax(0)
    result={'pid':os.getpid(),'process_identity':str(uuid.uuid4()),'bundle_digest':digest((bundle/'manifest.json').read_bytes()),'model_digest':digest((bundle/'model.safetensors').read_bytes()),'preprocess_digest':digest((bundle/'preprocess.json').read_bytes()),'input_digest':digest(image.read_bytes()),'logits':logits.tolist(),'probabilities':scores.tolist(),'top1':int(logits.argmax()),'classes':json.loads((bundle/'classes.json').read_text()),'elapsed_seconds':time.monotonic()-start,'scope':'synthetic-execution-only'}
    result['output_digest']=digest(canonical(result));return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bundle',required=True);p.add_argument('--image',required=True);p.add_argument('--expected-bundle-digest');a=p.parse_args();print(json.dumps(infer(a.bundle,a.image,a.expected_bundle_digest)))
