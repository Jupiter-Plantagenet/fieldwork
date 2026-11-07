"""`small-residual/v1`: the blueprint's second allowlisted recipe (section 5), separately versioned.

Same train / restore / evaluate / artifact contracts as `compact-cnn/v1`, own identity:
- architecture (fixed, no uploads): stem Conv3x3(3->32, stride 2)+BN+ReLU, then four basic
  residual blocks 32(s1) -> 64(s2) -> 128(s2) -> 256(s2) (two Conv3x3+BN, identity or
  Conv1x1(stride)+BN projection shortcut), global average pool, dropout, Linear(256->5).
  Initialised from a recorded seed (PyTorch default init). No transfer weights.
- evaluation/inference preprocessing IDENTICAL to compact-cnn/v1 (shorter edge 144
  bilinear, centre crop 128, /255, no normalisation).
- training augmentation profiles (train split only, stateless seed
  sha256(run_seed|epoch|sample_id|occurrence)): `basic-v1` (the v1 square crop + flip) or
  `rrc-jitter-v1` (random resized crop area 0.35..1.0, aspect 3/4..4/3, hflip 0.5,
  brightness/contrast/saturation factors 0.8..1.2; no hue change).
- optimiser AdamW (betas .9/.999, eps 1e-8); schedule `none` or `cosine` = a stateless
  function of the committed update count (linear warm-up, cosine to 0), so restore needs
  no scheduler tensors; the schedule spec is stored in every checkpoint.
- selection: lowest complete validation cross-entropy, ties earliest (unchanged rule).
Checkpoints are data-only (safetensors + canonical JSON + manifest) with a recipe-specific
validator: exact key set/shapes/dtypes, finite tensors, optimizer slots, RNG states.
"""
import hashlib
import json
import math
import os
import random
import re
import struct
import time
from pathlib import Path

import numpy as np
import torch
from PIL import Image, ImageEnhance
from safetensors.torch import load_file, save_file
from torch import nn

from .data import canonical, digest
from .real_training import PREPROCESS as EVAL_PREPROCESS_V1, center, load_resized, to_tensor

RECIPE = 'small-residual/v1'
CODEC_SCHEMA = 'fieldwork.checkpoint/small-residual-v1'
AUG_PROFILES = ('basic-v1', 'rrc-jitter-v1')
SCHEDULES = ('none', 'cosine')
PARAM_BUDGET = 2_000_000
PREPROCESS = {'schema': 'fieldwork.preprocess/small-residual-v1', 'eval': {k: EVAL_PREPROCESS_V1[k] for k in ('decode', 'resize', 'eval_crop', 'scale', 'normalization')},
              'eval_identical_to': EVAL_PREPROCESS_V1['schema'],
              'train_aug_profiles': {'basic-v1': EVAL_PREPROCESS_V1['train_aug'],
                                     'rrc-jitter-v1': 'random resized crop area 0.35..1.0 of image, log-uniform aspect 3/4..4/3 (10 tries, fallback centre square), resize 128 BILINEAR, hflip p=0.5, brightness/contrast/saturation factors U(0.8,1.2) in random order; no hue'},
              'aug_seed': EVAL_PREPROCESS_V1['aug_seed']}


class Block(nn.Module):
    def __init__(self, cin, cout, stride):
        super().__init__()
        self.conv1 = nn.Conv2d(cin, cout, 3, stride, 1, bias=False)
        self.bn1 = nn.BatchNorm2d(cout)
        self.conv2 = nn.Conv2d(cout, cout, 3, 1, 1, bias=False)
        self.bn2 = nn.BatchNorm2d(cout)
        self.proj = None
        if stride != 1 or cin != cout:
            self.proj = nn.Sequential(nn.Conv2d(cin, cout, 1, stride, bias=False), nn.BatchNorm2d(cout))

    def forward(self, x):
        y = torch.relu(self.bn1(self.conv1(x)))
        y = self.bn2(self.conv2(y))
        return torch.relu(y + (x if self.proj is None else self.proj(x)))


class SmallResidual(nn.Module):
    def __init__(self, dropout=0.2, classes=5):
        super().__init__()
        self.stem = nn.Sequential(nn.Conv2d(3, 32, 3, 2, 1, bias=False), nn.BatchNorm2d(32), nn.ReLU())
        self.blocks = nn.Sequential(Block(32, 32, 1), Block(32, 64, 2), Block(64, 128, 2), Block(128, 256, 2))
        self.drop = nn.Dropout(dropout)
        self.fc = nn.Linear(256, classes)

    def forward(self, x):
        x = self.blocks(self.stem(x))
        return self.fc(self.drop(torch.flatten(nn.functional.adaptive_avg_pool2d(x, 1), 1)))


def build(dropout=0.2):
    net = SmallResidual(dropout)
    n = sum(p.numel() for p in net.parameters())
    if n > PARAM_BUDGET:
        raise ValueError('PARAMETER_BUDGET')
    return net


def state_spec(net):
    """Trusted expected key -> (dtype, shape) for the model state (incl. BN buffers)."""
    out = {}
    for k, v in net.state_dict().items():
        out['model.' + k] = ({torch.float32: 'F32', torch.int64: 'I64'}[v.dtype], list(v.shape))
    return out


def weight_digest(net):
    return digest(b''.join(t.detach().cpu().numpy().tobytes() for t in net.state_dict().values()))


# ---------------------------------------------------------------- augmentation
def _rng(run_seed, epoch, sample_id, occurrence):
    return random.Random(hashlib.sha256(f'{run_seed}|{epoch}|{sample_id}|{occurrence}'.encode()).digest())


def augment(a, profile, run_seed, epoch, sample_id, occurrence):
    r = _rng(run_seed, epoch, sample_id, occurrence)
    h, w, _ = a.shape
    if profile == 'basic-v1':
        side = max(1, round(math.sqrt(r.uniform(0.8, 1.0)) * min(h, w)))
        y, x = r.randint(0, h - side), r.randint(0, w - side)
        crop = Image.fromarray(a[y:y + side, x:x + side]).resize((128, 128), Image.Resampling.BILINEAR)
        out = np.asarray(crop, dtype=np.uint8)
        return out[:, ::-1] if r.random() < 0.5 else out
    if profile != 'rrc-jitter-v1':
        raise ValueError('AUG_PROFILE')
    area = h * w
    box = None
    for _ in range(10):
        target = r.uniform(0.35, 1.0) * area
        ratio = math.exp(r.uniform(math.log(3 / 4), math.log(4 / 3)))
        cw, ch = round(math.sqrt(target * ratio)), round(math.sqrt(target / ratio))
        if 0 < cw <= w and 0 < ch <= h:
            box = (r.randint(0, h - ch), r.randint(0, w - cw), ch, cw)
            break
    if box is None:
        s = min(h, w)
        box = ((h - s) // 2, (w - s) // 2, s, s)
    y, x, ch, cw = box
    im = Image.fromarray(a[y:y + ch, x:x + cw]).resize((128, 128), Image.Resampling.BILINEAR)
    if r.random() < 0.5:
        im = im.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
    ops = [ImageEnhance.Brightness, ImageEnhance.Contrast, ImageEnhance.Color]
    factors = [r.uniform(0.8, 1.2) for _ in ops]
    order = list(range(3))
    r.shuffle(order)
    for i in order:
        im = ops[i](im).enhance(factors[i])
    return np.asarray(im, dtype=np.uint8)


# ---------------------------------------------------------------- schedule
def lr_at(update, spec):
    """LR for the optimizer step with 0-based index `update` (stateless)."""
    if spec['kind'] == 'none':
        return spec['peak_lr']
    if spec['kind'] != 'cosine':
        raise ValueError('SCHEDULE')
    w, total = spec['warmup_updates'], spec['total_updates']
    if update < w:
        return spec['peak_lr'] * (update + 1) / w
    progress = min(1.0, (update - w) / max(1, total - w))
    return spec['peak_lr'] * 0.5 * (1 + math.cos(math.pi * progress))


# ---------------------------------------------------------------- checkpoint codec
def _write(path, data):
    with Path(path).open('xb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())


def checkpoint(path, net, opt, generator, meta):
    final = Path(path)
    if final.exists():
        raise FileExistsError(str(final))
    stage = final.with_name('.staging-' + final.name + '-' + str(os.getpid()))
    stage.mkdir(parents=True, exist_ok=False)
    tensors = {'model.' + k: v.detach().clone().contiguous() for k, v in net.state_dict().items()}
    slots = {}
    for name, p in net.named_parameters():
        st = opt.state[p]
        slots[name] = {}
        for k, v in st.items():
            key = f'optimizer.{name}.{k}'
            tensors[key] = v.detach().clone().contiguous()
            slots[name][k] = {'tensor': key}
    tensors['rng.torch'] = torch.get_rng_state()
    tensors['rng.sampler'] = generator.get_state()
    save_file(tensors, str(stage / 'state.safetensors'))
    with (stage / 'state.safetensors').open('rb+') as f:
        os.fsync(f.fileno())
    meta = dict(meta, schema=CODEC_SCHEMA, recipe=RECIPE, optimizer='AdamW', slots=slots,
                param_names=[n for n, _ in net.named_parameters()],
                groups=[{k: v for k, v in g.items() if k != 'params'} for g in opt.param_groups],
                python_rng=random.getstate(), amp=None)
    _write(stage / 'state.json', canonical(meta))
    inv = {f: {'sha256': digest((stage / f).read_bytes()), 'bytes': (stage / f).stat().st_size} for f in ('state.safetensors', 'state.json')}
    _write(stage / 'manifest.json', canonical({'schema': 1, 'recipe': RECIPE, 'files': inv}))
    os.rename(stage, final)
    return digest((final / 'manifest.json').read_bytes())


_DT = {'F32': 4, 'U8': 1, 'I64': 8}


def tensor_header(path, expected, budget=4_000_000):
    """Bounded safetensors header parse BEFORE native allocation (exact key/dtype/shape/offsets)."""
    path = Path(path)
    size = path.stat().st_size
    if path.is_symlink() or size > 48 * 1024 * 1024 or size < 10:
        raise ValueError('tensor size')
    with path.open('rb') as f:
        n = struct.unpack('<Q', f.read(8))[0]
        if n > 256 * 1024 or n > size - 8:
            raise ValueError('tensor header size')
        from .safe_codec import unique_object
        header = json.loads(f.read(n), object_pairs_hook=unique_object)
    if not isinstance(header, dict) or set(header) != set(expected):
        raise ValueError('tensor header keys')
    ranges, elements = [], 0
    for name, entry in header.items():
        dt, shape = expected[name]
        if set(entry) != {'dtype', 'shape', 'data_offsets'} or entry['dtype'] != dt or entry['shape'] != shape:
            raise ValueError('tensor shape or dtype ' + name)
        count = math.prod(shape)
        elements += count
        a, b = entry['data_offsets']
        if type(a) is not int or type(b) is not int or a < 0 or b - a != count * _DT[dt]:
            raise ValueError('tensor offsets')
        ranges.append((a, b))
    if elements > budget:
        raise ValueError('tensor element budget')
    end = 0
    for a, b in sorted(ranges):
        if a != end:
            raise ValueError('tensor gap/overlap')
        end = b
    if end != size - n - 8:
        raise ValueError('tensor payload size')
    return header


def expected_checkpoint_tensors(net):
    spec = state_spec(net)
    for name, p in net.named_parameters():
        spec[f'optimizer.{name}.step'] = ('F32', [])
        spec[f'optimizer.{name}.exp_avg'] = ('F32', list(p.shape))
        spec[f'optimizer.{name}.exp_avg_sq'] = ('F32', list(p.shape))
    spec['rng.torch'] = ('U8', [5056])
    spec['rng.sampler'] = ('U8', [5056])
    return spec


def validate_checkpoint(path, expected_digest=None):
    from .safe_codec import read_json
    path = Path(path)
    if path.is_symlink() or {p.name for p in path.iterdir()} != {'manifest.json', 'state.json', 'state.safetensors'}:
        raise ValueError('checkpoint inventory')
    m = read_json(path / 'manifest.json', 64 * 1024)
    raw = (path / 'manifest.json').read_bytes()
    if expected_digest is not None and digest(raw) != expected_digest:
        raise ValueError('committed checkpoint digest')
    if set(m) != {'schema', 'recipe', 'files'} or m['schema'] != 1 or m['recipe'] != RECIPE or set(m['files']) != {'state.json', 'state.safetensors'}:
        raise ValueError('checkpoint manifest schema')
    for name, e in m['files'].items():
        f = path / name
        limit = 1024 * 1024 if name.endswith('.json') else 48 * 1024 * 1024
        if set(e) != {'bytes','sha256'} or f.is_symlink() or f.stat().st_size > limit or f.stat().st_size != e['bytes'] or digest(f.read_bytes()) != e['sha256']:
            raise ValueError('checkpoint digest or size')
    meta = read_json(path / 'state.json')
    need = {'schema', 'recipe', 'optimizer', 'slots', 'param_names', 'groups', 'python_rng', 'amp', 'epoch', 'train_loss',
            'validation_loss', 'updates', 'next_epoch', 'dataset_digest', 'seed', 'best', 'initial_digest', 'schedule', 'config'}
    if set(meta) != need or meta['schema'] != CODEC_SCHEMA or meta['recipe'] != RECIPE or meta['optimizer'] != 'AdamW' or meta['amp'] is not None:
        raise ValueError('checkpoint state schema')
    if meta['schedule']['kind'] not in SCHEDULES or meta['config']['augmentation'] not in AUG_PROFILES:
        raise ValueError('checkpoint schedule/augmentation')
    default_config(**meta['config'])
    if type(meta['updates']) is not int or not 1 <= meta['updates'] <= 2_000_000 or meta['seed'] != meta['config']['seed']:
        raise ValueError('checkpoint update/seed counters')
    for k in ('dataset_digest', 'initial_digest'):
        if not re.fullmatch('[a-f0-9]{64}', str(meta[k])):
            raise ValueError('checkpoint lineage')
    if not (type(meta['epoch']) is int and 1 <= meta['epoch'] <= 100 and meta['next_epoch'] == meta['epoch'] + 1):
        raise ValueError('checkpoint counters')
    if any(not math.isfinite(meta[k]) or meta[k] < 0 for k in ('train_loss', 'validation_loss')):
        raise ValueError('checkpoint finite metrics')
    net = build(meta['config']['dropout'])
    if meta['param_names'] != [n for n, _ in net.named_parameters()]:
        raise ValueError('checkpoint parameters')
    if set(meta['slots']) != set(meta['param_names']):raise ValueError('checkpoint optimizer slots')
    for name in meta['param_names']:
        if set(meta['slots'][name]) != {'step','exp_avg','exp_avg_sq'}:raise ValueError('checkpoint optimizer slots')
        for slot in ('step','exp_avg','exp_avg_sq'):
            if meta['slots'][name][slot] != {'tensor':f'optimizer.{name}.{slot}'}:
                raise ValueError('checkpoint optimizer tensor identity')
    g = meta['groups']
    if len(g) != 1 or g[0]['betas'] != [0.9, 0.999] or g[0]['eps'] != 1e-8 or g[0]['amsgrad'] is not False or g[0]['maximize'] is not False:
        raise ValueError('checkpoint optimizer variant')
    tensor_header(path / 'state.safetensors', expected_checkpoint_tensors(net))
    t = load_file(str(path / 'state.safetensors'), device='cpu')
    for k, v in t.items():
        if k.startswith('rng.'):
            continue
        if v.is_floating_point() and not torch.isfinite(v).all():
            raise ValueError('checkpoint nonfinite tensor')
        if k.endswith('.step') and int(v.item()) != meta['updates']:
            raise ValueError('checkpoint optimizer step')
    return meta


def load_model(path, expected_digest):
    meta = validate_checkpoint(path, expected_digest)
    t = load_file(str(Path(path) / 'state.safetensors'), device='cpu')
    net = build(meta['config']['dropout'])
    net.load_state_dict({k: t['model.' + k] for k in net.state_dict()}, strict=True)
    net.eval()
    return net


def restore(path, net, opt, generator, expected_digest, dataset_digest):
    meta = validate_checkpoint(path, expected_digest)
    if meta['dataset_digest'] != dataset_digest:
        raise ValueError('lineage')
    t = load_file(str(Path(path) / 'state.safetensors'), device='cpu')
    net.load_state_dict({k: t['model.' + k] for k in net.state_dict()}, strict=True)
    for group, saved in zip(opt.param_groups, meta['groups'], strict=True):
        group.update({k: (tuple(v) if k == 'betas' else v) for k, v in saved.items()})
    for name, p in net.named_parameters():
        opt.state[p] = {k: t[v['tensor']].clone() for k, v in meta['slots'][name].items()}

    def tuples(x):
        return tuple(tuples(i) for i in x) if isinstance(x, list) else x
    random.setstate(tuples(meta['python_rng']))   # RNG restored LAST
    torch.set_rng_state(t['rng.torch'])
    generator.set_state(t['rng.sampler'])
    return meta


# ---------------------------------------------------------------- training
def default_config(**kw):
    cfg = {'epochs': 40, 'seed': 42, 'batch_size': 32, 'peak_lr': 0.002, 'weight_decay': 0.05, 'schedule': 'cosine',
           'warmup_epochs': 2, 'augmentation': 'rrc-jitter-v1', 'dropout': 0.2, 'label_smoothing': 0.0, 'threads': 2}
    if set(kw)-set(cfg):raise ValueError('CONFIG_UNKNOWN_FIELDS')
    cfg.update(kw)
    if cfg['augmentation'] not in AUG_PROFILES or cfg['schedule'] not in SCHEDULES or not 1 <= cfg['batch_size'] <= 32 \
            or not 1 <= cfg['epochs'] <= 100 or not 1e-5 <= cfg['peak_lr'] <= 0.1:
        raise ValueError('CONFIG_OUT_OF_RECIPE_BOUNDS')
    for key in ('epochs','seed','batch_size','warmup_epochs','threads'):
        if type(cfg[key]) is not int:raise ValueError('CONFIG_INTEGER_REQUIRED')
    if not 0<=cfg['seed']<=4294967295 or not 0<=cfg['warmup_epochs']<=cfg['epochs'] or not 1<=cfg['threads']<=2:
        raise ValueError('CONFIG_OUT_OF_RECIPE_BOUNDS')
    for key in ('peak_lr','weight_decay','dropout','label_smoothing'):
        if type(cfg[key]) not in (int,float) or not math.isfinite(cfg[key]):raise ValueError('CONFIG_FINITE_REQUIRED')
    if not 0<=cfg['weight_decay']<=1 or not 0<=cfg['dropout']<1 or not 0<=cfg['label_smoothing']<1:
        raise ValueError('CONFIG_OUT_OF_RECIPE_BOUNDS')
    return cfg


def _evaluate(net, arrays, batch=64):
    net.eval()
    out = []
    with torch.inference_mode():
        for i in range(0, len(arrays), batch):
            out.append(net(to_tensor([center(a) for a in arrays[i:i + batch]])))
    return torch.cat(out)


def train(view, out, cfg, *, log=print, resume=None, stop_after_epoch=None, preloaded=None):
    """view: researcher training view {'digest', 'version_id', 'samples': train+validation rows only}.

    resume: (checkpoint_dir, checkpoint_digest) -> continue at next epoch (epoch-boundary replay).
    """
    cfg = default_config(**cfg)
    torch.set_num_threads(cfg['threads'])
    torch.use_deterministic_algorithms(True)
    torch.manual_seed(cfg['seed'])
    random.seed(cfg['seed'])
    out = Path(out)
    out.mkdir(parents=True, exist_ok=resume is not None)
    tr_rows = sorted((s for s in view['samples'] if s['split'] == 'train'), key=lambda s: s['id'])
    va_rows = sorted((s for s in view['samples'] if s['split'] == 'validation'), key=lambda s: s['id'])
    if any(s['split'] not in ('train', 'validation') for s in view['samples']):
        raise ValueError('PROTECTED_SPLIT_IN_TRAINING_VIEW')
    train_ids = {s['id'] for s in tr_rows}
    t0 = time.monotonic()
    if preloaded is None:
        for row in tr_rows+va_rows:
            if str(row['file'])[:2].lower()=='d:':raise ValueError('FAILING_DRIVE_PATH_FORBIDDEN')
            if digest(Path(row['file']).read_bytes())!=row['sha256']:raise ValueError('TRAINING_MEDIA_DIGEST_MISMATCH')
        tr = [load_resized(s['file']) for s in tr_rows]
        va = [load_resized(s['file']) for s in va_rows]
    else:
        tr, va = preloaded
    ty = torch.tensor([s['label'] for s in tr_rows])
    vy = torch.tensor([s['label'] for s in va_rows])
    log(json.dumps({'event': 'loaded', 'train': len(tr), 'validation': len(va), 'seconds': round(time.monotonic() - t0, 1)}))
    net = build(cfg['dropout'])
    opt = torch.optim.AdamW(net.parameters(), lr=cfg['peak_lr'], weight_decay=cfg['weight_decay'], betas=(0.9, 0.999), eps=1e-8)
    g = torch.Generator().manual_seed(cfg['seed'])
    steps_per_epoch = math.ceil(len(tr) / cfg['batch_size'])
    sched = {'kind': cfg['schedule'], 'peak_lr': cfg['peak_lr'], 'warmup_updates': cfg['warmup_epochs'] * steps_per_epoch,
             'total_updates': cfg['epochs'] * steps_per_epoch}
    initial = weight_digest(net)
    updates, best, history, start = 0, None, [], 1
    if resume is not None:
        meta = restore(resume[0], net, opt, g, resume[1], view['digest'])
        updates, best, start, initial = meta['updates'], meta['best'], meta['next_epoch'], meta['initial_digest']
        history = json.loads((out / 'history.json').read_text())[:meta['epoch']] if (out / 'history.json').exists() else []
        log(json.dumps({'event': 'restored', 'from_epoch': meta['epoch'], 'replay_epoch': start, 'updates': updates}))
    steps = (out / 'steps.jsonl').open('a')
    for epoch in range(start, cfg['epochs'] + 1):
        e0 = time.monotonic()
        net.train()
        order = torch.randperm(len(tr), generator=g)
        total, seen, occ = 0.0, 0, {}
        for b, idx in enumerate(order.split(cfg['batch_size']), 1):
            idx = idx.tolist()
            ids = [tr_rows[i]['id'] for i in idx]
            if not set(ids) <= train_ids:
                raise ValueError('NON_TRAIN_SAMPLE_IN_BATCH')
            arrs = []
            for i in idx:
                sid = tr_rows[i]['id']
                o = occ.get(sid, 0)
                occ[sid] = o + 1
                arrs.append(augment(tr[i], cfg['augmentation'], cfg['seed'], epoch, sid, o))
            x = to_tensor(arrs)
            lr = lr_at(updates, sched)
            for grp in opt.param_groups:
                grp['lr'] = lr
            before = torch.cat([p.detach().flatten() for p in net.parameters()]).clone()
            opt.zero_grad()
            loss = nn.functional.cross_entropy(net(x), ty[idx], label_smoothing=cfg['label_smoothing'])
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
            steps.write(json.dumps({'epoch': epoch, 'batch': b, 'n': len(idx), 'lr': lr, 'loss': float(loss.detach()), 'grad_norm': gnorm,
                                    'update_norm': unorm, 'ids': ids, 'split': 'train'}) + '\n')
        steps.flush()
        logits = _evaluate(net, va)
        vloss = float(nn.functional.cross_entropy(logits, vy))
        vacc = float((logits.argmax(1) == vy).float().mean())
        if not math.isfinite(vloss):
            raise ValueError('NONFINITE_VALIDATION')
        if best is None or vloss < best['loss']:
            best = {'epoch': epoch, 'loss': vloss}
        meta = dict(epoch=epoch, train_loss=total / seen, validation_loss=vloss, updates=updates, next_epoch=epoch + 1,
                    dataset_digest=view['digest'], seed=cfg['seed'], best=best, initial_digest=initial, schedule=sched, config=cfg)
        cd = checkpoint(out / f'epoch-{epoch}', net, opt, g, meta)
        row = {'epoch': epoch, 'train_loss': total / seen, 'validation_loss': vloss, 'validation_accuracy': vacc, 'updates': updates,
               'lr_last': lr, 'checkpoint_digest': cd, 'weight_digest': weight_digest(net), 'seconds': round(time.monotonic() - e0, 1)}
        history.append(row)
        (out / 'history.json').write_text(json.dumps(history))
        # Retention (blueprint K<=3): keep the selection-best checkpoint and the last two committed ones.
        keep = {best['epoch'], epoch, epoch - 1}
        for h in history:
            d = out / f'epoch-{h["epoch"]}'
            if h['epoch'] not in keep and d.exists():
                for f in d.iterdir():
                    f.unlink()
                d.rmdir()
                h['checkpoint_pruned'] = True
        log(json.dumps(row))
        if stop_after_epoch is not None and epoch >= stop_after_epoch:
            steps.close()
            return {'stopped_after_epoch': epoch, 'history': history}
    steps.close()
    sel = min(history, key=lambda r: (r['validation_loss'], r['epoch']))
    validate_checkpoint(out / f'epoch-{sel["epoch"]}', expected_digest=sel['checkpoint_digest'])
    result = {'schema': 'fieldwork.real-train-result/v2', 'recipe': RECIPE, 'preprocess': PREPROCESS, 'dataset_digest': view['digest'],
              'version_id': view.get('version_id'), 'config': {k: (str(v) if isinstance(v, float) else v) for k, v in cfg.items()},
              'schedule': sched, 'parameters': sum(p.numel() for p in net.parameters()), 'initial_digest': initial,
              'final_digest': weight_digest(net), 'updates': updates, 'history': history,
              'selected': {'epoch': sel['epoch'], 'validation_loss': sel['validation_loss'], 'validation_accuracy': sel['validation_accuracy'],
                           'checkpoint_digest': sel['checkpoint_digest'], 'path': str(out / f'epoch-{sel["epoch"]}'),
                           'rule': 'min validation CE, ties earliest'},
              'train_count': len(tr), 'validation_count': len(va), 'pid': os.getpid(), 'torch': torch.__version__,
              'elapsed_s': round(time.monotonic() - t0, 1)}
    _write(out / 'result.json', canonical(result))
    return result
