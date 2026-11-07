"""compact-cnn/v1 training on a FROZEN rights-cleared real dataset version (CPU fp32).

Recipe (blueprint section 5): RGB128, shorter edge 144 bilinear(antialiased) + center
crop 128 for validation/inference; train-only stateless random square crop
(area scale 0.8..1.0 of the shorter-edge square) resized to 128 + horizontal flip
p=0.5, seeded by sha256(run_seed, epoch, sample_id, occurrence). Pixels /255.
zero_grad -> forward -> finite loss -> backward -> finite grad norm -> AdamW
(lr 1e-3, wd 1e-4, betas .9/.999, eps 1e-8), no scheduler, batch 16, final short
batch kept, seeded epoch permutation, sample-weighted epoch loss. Every batch is
audited against frozen train IDs. Checkpoint each epoch via ml.checkpoint; the
lowest complete validation cross-entropy checkpoint is selected (ties earliest).

The caller (tools/real_train.py) checks the version is frozen and that signed
`local_private_training` rights verify before calling `train`.
"""
import hashlib
import json
import math
import os
import random
import time
from pathlib import Path

import numpy as np
import torch
from PIL import Image, ImageOps
from torch import nn

from .data import canonical, digest
from .ml import checkpoint, model, validate_checkpoint, weight_digest, write_bytes

PREPROCESS = {'schema': 'fieldwork.preprocess/real-v1', 'decode': 'PIL exif_transpose -> RGB',
              'resize': 'shorter edge 144, PIL BILINEAR (antialiased downscale)', 'eval_crop': 'center 128',
              'train_aug': 'stateless square crop area 0.8..1.0 of shorter-edge square, resize 128 BILINEAR, hflip p=0.5',
              'aug_seed': 'sha256(f"{run_seed}|{epoch}|{sample_id}|{occurrence}")', 'scale': 'float32 /255', 'normalization': None}


def load_resized(path):
    with Image.open(path) as im:
        im = ImageOps.exif_transpose(im).convert('RGB')
        w, h = im.size
        s = 144 / min(w, h)
        im = im.resize((max(144, round(w * s)), max(144, round(h * s))), Image.Resampling.BILINEAR)
        return np.asarray(im, dtype=np.uint8).copy()


def center(a):
    h, w, _ = a.shape
    y, x = (h - 128) // 2, (w - 128) // 2
    return a[y:y + 128, x:x + 128]


def augment(a, run_seed, epoch, sample_id, occurrence):
    r = random.Random(hashlib.sha256(f'{run_seed}|{epoch}|{sample_id}|{occurrence}'.encode()).digest())
    h, w, _ = a.shape
    side = max(1, round(math.sqrt(r.uniform(0.8, 1.0)) * min(h, w)))
    y, x = r.randint(0, h - side), r.randint(0, w - side)
    crop = Image.fromarray(a[y:y + side, x:x + side]).resize((128, 128), Image.Resampling.BILINEAR)
    out = np.asarray(crop, dtype=np.uint8)
    if r.random() < 0.5:
        out = out[:, ::-1]
    return out


def to_tensor(arrs):
    return torch.from_numpy(np.stack(arrs).astype(np.float32) / 255.0).permute(0, 3, 1, 2).contiguous()


def evaluate_logits(net, arrays, batch=64):
    net.eval()
    out = []
    with torch.inference_mode():
        for i in range(0, len(arrays), batch):
            out.append(net(to_tensor([center(a) for a in arrays[i:i + batch]])))
    return torch.cat(out)


def train(manifest, out, *, epochs=20, seed=42, learning_rate=0.001, batch_size=16, threads=2, log=print):
    torch.set_num_threads(threads)
    torch.use_deterministic_algorithms(True)
    torch.manual_seed(seed)
    random.seed(seed)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    train_rows = [s for s in manifest['samples'] if s['split'] == 'train']
    val_rows = [s for s in manifest['samples'] if s['split'] == 'validation']
    train_ids = {s['id'] for s in train_rows}
    if any(s['split'] == 'holdout' for s in train_rows + val_rows):
        raise ValueError('HOLDOUT_IN_TRAINING_INPUT')
    t0 = time.monotonic()
    tr = [load_resized(s['file']) for s in train_rows]
    va = [load_resized(s['file']) for s in val_rows]
    ty = torch.tensor([s['label'] for s in train_rows])
    vy = torch.tensor([s['label'] for s in val_rows])
    log(json.dumps({'event': 'loaded', 'train': len(tr), 'validation': len(va), 'seconds': round(time.monotonic() - t0, 1)}))
    net = model()
    opt = torch.optim.AdamW(net.parameters(), lr=learning_rate, weight_decay=0.0001, betas=(0.9, 0.999), eps=1e-8)
    g = torch.Generator().manual_seed(seed)
    initial = weight_digest(net)
    updates = 0
    best = None
    history = []
    occurrences = {}
    steps = (out / 'steps.jsonl').open('w')
    for epoch in range(1, epochs + 1):
        e0 = time.monotonic()
        net.train()
        order = torch.randperm(len(tr), generator=g)
        total, seen = 0.0, 0
        for b, idx in enumerate(order.split(batch_size), 1):
            idx = idx.tolist()
            ids = [train_rows[i]['id'] for i in idx]
            if not set(ids) <= train_ids:
                raise ValueError('NON_TRAIN_SAMPLE_IN_BATCH')
            arrs = []
            for i in idx:
                sid = train_rows[i]['id']
                occ = occurrences.get((epoch, sid), 0)
                occurrences[(epoch, sid)] = occ + 1
                arrs.append(augment(tr[i], seed, epoch, sid, occ))
            x = to_tensor(arrs)
            before = torch.cat([p.detach().flatten() for p in net.parameters()]).clone()
            opt.zero_grad()
            loss = nn.functional.cross_entropy(net(x), ty[idx])
            if not torch.isfinite(loss):
                raise ValueError('NONFINITE_LOSS')
            loss.backward()
            gnorm = float(torch.nn.utils.clip_grad_norm_(net.parameters(), float('inf')))
            if not math.isfinite(gnorm) or gnorm == 0.0:
                raise ValueError('NONFINITE_OR_ZERO_GRAD')
            opt.step()
            updates += 1
            unorm = float((torch.cat([p.detach().flatten() for p in net.parameters()]) - before).norm())
            total += float(loss.detach()) * len(idx)
            seen += len(idx)
            steps.write(json.dumps({'epoch': epoch, 'batch': b, 'n': len(idx), 'loss': float(loss.detach()), 'grad_norm': gnorm,
                                    'update_norm': unorm, 'ids': ids, 'split': 'train'}) + '\n')
        steps.flush()
        logits = evaluate_logits(net, va)
        vloss = float(nn.functional.cross_entropy(logits, vy))
        vacc = float((logits.argmax(1) == vy).float().mean())
        if not math.isfinite(vloss):
            raise ValueError('NONFINITE_VALIDATION')
        if best is None or vloss < best['loss']:
            best = {'epoch': epoch, 'loss': vloss}
        meta = dict(epoch=epoch, train_loss=total / seen, validation_loss=vloss, updates=updates, next_epoch=epoch + 1,
                    dataset_digest=manifest['digest'], seed=seed, best=best, initial_digest=initial)
        cdigest = checkpoint(out / f'epoch-{epoch}', net, opt, g, meta)
        row = {'epoch': epoch, 'train_loss': total / seen, 'validation_loss': vloss, 'validation_accuracy': vacc, 'updates': updates,
               'checkpoint_digest': cdigest, 'weight_digest': weight_digest(net), 'seconds': round(time.monotonic() - e0, 1)}
        history.append(row)
        log(json.dumps(row))
    steps.close()
    sel = min(history, key=lambda r: (r['validation_loss'], r['epoch']))
    validate_checkpoint(out / f'epoch-{sel["epoch"]}', expected_digest=sel['checkpoint_digest'])
    result = {'schema': 'fieldwork.real-train-result/v1', 'recipe': 'compact-cnn/v1', 'preprocess': PREPROCESS,
              'dataset_digest': manifest['digest'], 'version_id': manifest.get('version_id'),
              'config': {'epochs': epochs, 'seed': seed, 'learning_rate': str(learning_rate), 'weight_decay': '0.0001',
                         'batch_size': batch_size, 'threads': threads, 'optimizer': 'AdamW', 'scheduler': None, 'amp': None},
              'initial_digest': initial, 'final_digest': weight_digest(net), 'updates': updates, 'history': history,
              'selected': {'epoch': sel['epoch'], 'validation_loss': sel['validation_loss'], 'validation_accuracy': sel['validation_accuracy'],
                           'checkpoint_digest': sel['checkpoint_digest'], 'path': str(out / f'epoch-{sel["epoch"]}'), 'rule': 'min validation CE, ties earliest'},
              'train_count': len(tr), 'validation_count': len(va), 'pid': os.getpid(), 'torch': torch.__version__,
              'elapsed_s': round(time.monotonic() - t0, 1)}
    write_bytes(out / 'result.json', canonical(result))
    return result


def load_selected(path, expected_digest):
    """Load model weights from a validated checkpoint (no optimizer state)."""
    from safetensors.torch import load_file
    validate_checkpoint(path, expected_digest=expected_digest)
    tensors = load_file(str(Path(path) / 'state.safetensors'), device='cpu')
    net = model()
    net.load_state_dict({k: tensors['model.' + k] for k in net.state_dict()}, strict=True)
    net.eval()
    return net
