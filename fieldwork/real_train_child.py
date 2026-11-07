"""Trusted CPU trainer for isolated RGB8 pixel input (never opens source images).

This duplicates the reviewed real recipe's update loop behind a narrower input
contract: only bounded pixel arrays, labels and train/validation IDs are visible.
Checkpoints use the existing data-only safetensors codec and are supervisor-published.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from pathlib import Path

import numpy as np
import torch
from torch import nn

from .data import canonical
from .ml import checkpoint, model, restore, validate_checkpoint, weight_digest, write_bytes
from .real_run_profile import MAX_REAL_SAMPLES

MAX_ROWS = MAX_REAL_SAMPLES
MAX_DIMENSION = 1024
MAX_PIXEL_BYTES = MAX_DIMENSION * 144 * 3


def _read_json(path: Path, limit=16 * 1024 * 1024):
    if path.is_symlink() or path.stat().st_size > limit:
        raise ValueError('REAL_INPUT_MANIFEST_BOUNDS')
    value = json.loads(path.read_text(encoding='utf-8'))
    if type(value) is not dict:
        raise ValueError('REAL_INPUT_MANIFEST_SCHEMA')
    return value


def _inside_file(root: Path, entry: dict) -> np.ndarray:
    rel = entry.get('pixel_file')
    if type(rel) is not str or not rel or Path(rel).is_absolute() or '..' in Path(rel).parts:
        raise ValueError('REAL_PIXEL_PATH')
    path = root / rel
    if path.is_symlink() or not path.is_file():
        raise ValueError('REAL_PIXEL_FILE')
    resolved = path.resolve(strict=True)
    resolved.relative_to(root.resolve(strict=True))
    width, height = entry.get('width'), entry.get('height')
    if (type(width) is not int or type(height) is not int or not 144 <= width <= MAX_DIMENSION
            or not 144 <= height <= MAX_DIMENSION or min(width, height) != 144):
        raise ValueError('REAL_PIXEL_SHAPE')
    size = width * height * 3
    if size > MAX_PIXEL_BYTES or path.stat().st_size != size:
        raise ValueError('REAL_PIXEL_SIZE')
    raw = path.read_bytes()
    if hashlib.sha256(b'RGB8|%d|%d|' % (width, height) + raw).hexdigest() != entry.get('decoded_pixel_sha256'):
        raise ValueError('REAL_PIXEL_DIGEST')
    return np.frombuffer(raw, dtype=np.uint8).reshape(height, width, 3)


def center(a: np.ndarray) -> np.ndarray:
    h, w, _ = a.shape
    y, x = (h - 128) // 2, (w - 128) // 2
    return a[y:y + 128, x:x + 128]


def augment(a: np.ndarray, seed: int, epoch: int, sample_id: str, occurrence: int) -> np.ndarray:
    rng = random.Random(hashlib.sha256(f'{seed}|{epoch}|{sample_id}|{occurrence}'.encode()).digest())
    h, w, _ = a.shape
    side = max(1, round(math.sqrt(rng.uniform(0.8, 1.0)) * min(h, w)))
    y, x = rng.randint(0, h - side), rng.randint(0, w - side)
    from PIL import Image
    crop = Image.fromarray(a[y:y + side, x:x + side]).resize((128, 128), Image.Resampling.BILINEAR)
    out = np.asarray(crop, dtype=np.uint8)
    return out[:, ::-1].copy() if rng.random() < .5 else out.copy()


def tensor(arrays):
    return torch.from_numpy(np.stack(arrays).astype(np.float32) / 255.0).permute(0, 3, 1, 2).contiguous()


def train(input_dir: Path, out: Path, *, epochs: int, seed: int, batch_size: int,
          learning_rate: float, expected_dataset_digest: str,
          expected_recipe_digest: str, expected_preprocess_digest: str,
          expected_decoder_image_id: str,
          resume: Path | None = None, expected_checkpoint_digest: str | None = None,
          threads: int = 2):
    root = input_dir.resolve(strict=True)
    manifest = _read_json(root / 'inputs.json')
    if set(manifest) != {'schema', 'version_id', 'version_digest', 'recipe', 'recipe_digest',
                         'preprocess', 'preprocess_digest', 'decoder_image_id', 'classes', 'train', 'validation'}:
        raise ValueError('REAL_INPUT_MANIFEST_SCHEMA')
    if (manifest['schema'] != 'fieldwork.real-pixel-input/v1'
            or manifest['version_digest'] != expected_dataset_digest
            or manifest['recipe'] != 'compact-cnn/real-v1'
            or manifest['preprocess'] != 'short-edge144-rgb-v1'
            or manifest['recipe_digest'] != expected_recipe_digest
            or manifest['preprocess_digest'] != expected_preprocess_digest
            or manifest['decoder_image_id'] != expected_decoder_image_id):
        raise ValueError('REAL_INPUT_BINDING')
    if type(manifest['classes']) is not list or len(manifest['classes']) != 5:
        raise ValueError('REAL_CLASS_MAP')
    train_rows, val_rows = manifest['train'], manifest['validation']
    if (type(train_rows) is not list or type(val_rows) is not list or not train_rows or not val_rows
            or len(train_rows) + len(val_rows) > MAX_ROWS):
        raise ValueError('REAL_POPULATION_BOUNDS')
    if any(type(row) is not dict or row.get('split') != expected for rows, expected in
           ((train_rows, 'train'), (val_rows, 'validation')) for row in rows):
        raise ValueError('REAL_SPLIT_BOUNDARY')
    for row in train_rows + val_rows:
        if (type(row.get('id')) is not str or type(row.get('label')) is not int
                or not 0 <= row['label'] < 5):
            raise ValueError('REAL_ROW_SCHEMA')
    if len({r['id'] for r in train_rows}) != len(train_rows) or len({r['id'] for r in val_rows}) != len(val_rows):
        raise ValueError('REAL_DUPLICATE_SAMPLE')
    train_arrays = [_inside_file(root, row) for row in train_rows]
    val_arrays = [_inside_file(root, row) for row in val_rows]
    y = torch.tensor([row['label'] for row in train_rows], dtype=torch.long)
    vy = torch.tensor([row['label'] for row in val_rows], dtype=torch.long)

    torch.set_num_threads(threads)
    torch.use_deterministic_algorithms(True)
    torch.manual_seed(seed)
    random.seed(seed)
    out.mkdir(parents=True, exist_ok=False)
    net = model()
    opt = torch.optim.AdamW(net.parameters(), lr=learning_rate, weight_decay=.0001,
                            betas=(.9, .999), eps=1e-8)
    sampler = torch.Generator().manual_seed(seed)
    initial = weight_digest(net)
    start_epoch, updates, best = 1, 0, None
    if resume is not None:
        if not expected_checkpoint_digest:
            raise ValueError('REAL_RESUME_DIGEST_REQUIRED')
        state = restore(resume, net, opt, sampler, expected_dataset_digest,
                        expected_digest=expected_checkpoint_digest)
        if state['seed'] != seed:
            raise ValueError('REAL_RESUME_SEED_MISMATCH')
        start_epoch, updates, best = state['next_epoch'], state['updates'], state['best']
        initial = state['initial_digest']
    history = []
    occurrences: dict[tuple[int, str], int] = {}
    steps_path = out / 'steps.jsonl'
    for epoch in range(start_epoch, epochs + 1):
        net.train()
        order = torch.randperm(len(train_rows), generator=sampler)
        weighted_loss, seen = 0.0, 0
        with steps_path.open('a', encoding='utf-8') as steps:
            for batch_no, indices in enumerate(order.split(batch_size), 1):
                idx = indices.tolist()
                ids = [train_rows[i]['id'] for i in idx]
                arrays = []
                for i in idx:
                    sample_id = train_rows[i]['id']
                    occurrence = occurrences.get((epoch, sample_id), 0)
                    occurrences[(epoch, sample_id)] = occurrence + 1
                    arrays.append(augment(train_arrays[i], seed, epoch, sample_id, occurrence))
                x = tensor(arrays)
                before = torch.cat([p.detach().flatten() for p in net.parameters()]).clone()
                opt.zero_grad()
                loss = nn.functional.cross_entropy(net(x), y[idx])
                if not torch.isfinite(loss):
                    raise ValueError('REAL_NONFINITE_LOSS')
                loss.backward()
                grad_norm = float(torch.nn.utils.clip_grad_norm_(net.parameters(), float('inf')))
                if not math.isfinite(grad_norm) or grad_norm == 0.0:
                    raise ValueError('REAL_GRADIENT_INVALID')
                opt.step()
                updates += 1
                update_norm = float((torch.cat([p.detach().flatten() for p in net.parameters()]) - before).norm())
                weighted_loss += float(loss.detach()) * len(idx)
                seen += len(idx)
                steps.write(json.dumps({'epoch': epoch, 'batch': batch_no, 'n': len(idx),
                                        'loss': float(loss.detach()), 'grad_norm': grad_norm,
                                        'update_norm': update_norm, 'ids': ids, 'split': 'train'}) + '\n')
            steps.flush()
        net.eval()
        with torch.inference_mode():
            logits = torch.cat([net(tensor([center(a) for a in val_arrays[i:i + 64]]))
                                for i in range(0, len(val_arrays), 64)])
            val_loss = float(nn.functional.cross_entropy(logits, vy))
            val_acc = float((logits.argmax(1) == vy).float().mean())
        if not math.isfinite(val_loss):
            raise ValueError('REAL_VALIDATION_INVALID')
        if best is None or val_loss < best['loss']:
            best = {'epoch': epoch, 'loss': val_loss}
        row = {'epoch': epoch, 'train_loss': weighted_loss / seen, 'validation_loss': val_loss,
               'validation_accuracy': val_acc, 'updates': updates}
        # validate_checkpoint pins the exact state.json key set; validation_accuracy
        # stays in the history row only (as in real_training.py).
        meta = {k: v for k, v in row.items() if k != 'validation_accuracy'}
        meta.update(next_epoch=epoch + 1, dataset_digest=expected_dataset_digest,
                    seed=seed, best=best, initial_digest=initial)
        check_digest = checkpoint(out / f'epoch-{epoch}', net, opt, sampler, meta)
        history.append({**row, 'checkpoint_digest': check_digest,
                        'weight_digest': weight_digest(net)})
    if best is None:
        raise ValueError('REAL_CHECKPOINT_SELECTION_MISSING')
    selected = next((row for row in history if row['epoch'] == best['epoch']), None)
    if selected is not None:
        validate_checkpoint(out / f"epoch-{selected['epoch']}", expected_digest=selected['checkpoint_digest'])
    result = {'schema': 'fieldwork.real-train-result/v1', 'scope': 'real-training/v1',
              'recipe': 'compact-cnn/real-v1', 'preprocess': 'short-edge144-rgb-v1',
              'dataset_digest': expected_dataset_digest, 'version_id': manifest['version_id'],
              'config': {'epochs': epochs, 'seed': seed, 'learning_rate': str(learning_rate),
                         'weight_decay': '0.0001', 'batch_size': batch_size,
                         'optimizer': 'AdamW', 'scheduler': None, 'amp': None},
              'initial_digest': initial, 'final_digest': weight_digest(net),
              'updates': updates, 'history': history,
              'selected': {'epoch': best['epoch'], 'validation_loss': best['loss'],
                           'checkpoint_digest': selected['checkpoint_digest'] if selected is not None else None,
                           'rule': 'min validation CE, ties earliest'},
              'train_count': len(train_rows), 'validation_count': len(val_rows)}
    write_bytes(out / 'result.json', canonical(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--dataset-digest', required=True)
    parser.add_argument('--recipe-digest', required=True)
    parser.add_argument('--preprocess-digest', required=True)
    parser.add_argument('--decoder-image-id', required=True)
    parser.add_argument('--epochs', type=int, required=True)
    parser.add_argument('--seed', type=int, required=True)
    parser.add_argument('--batch-size', type=int, required=True)
    parser.add_argument('--learning-rate', type=float, required=True)
    parser.add_argument('--resume')
    parser.add_argument('--expected-checkpoint-digest')
    args = parser.parse_args(argv)
    train(Path(args.inputs), Path(args.out), epochs=args.epochs, seed=args.seed,
          batch_size=args.batch_size, learning_rate=args.learning_rate,
          expected_dataset_digest=args.dataset_digest,
          expected_recipe_digest=args.recipe_digest,
          expected_preprocess_digest=args.preprocess_digest,
          expected_decoder_image_id=args.decoder_image_id,
          resume=Path(args.resume) if args.resume else None,
          expected_checkpoint_digest=args.expected_checkpoint_digest)


if __name__ == '__main__':
    main()

