"""Trusted CPU recipe and data-only epoch checkpoint codec; no pickle."""
import json, os, random, time
from pathlib import Path
import numpy as np
import torch
from torch import nn
from PIL import Image, ImageOps
from safetensors.torch import save_file, load_file
from .data import canonical, digest, verify


def model():
    return nn.Sequential(nn.Conv2d(3,32,3,padding=1), nn.ReLU(), nn.MaxPool2d(2), nn.Conv2d(32,64,3,padding=1),nn.ReLU(),nn.MaxPool2d(2),nn.Conv2d(64,128,3,padding=1),nn.ReLU(),nn.MaxPool2d(2),nn.AdaptiveAvgPool2d(1),nn.Flatten(),nn.Linear(128,5))


def pixels(path):
    with Image.open(path) as im:
        if im.width*im.height>20_000_000 or getattr(im,'n_frames',1)!=1:
            raise ValueError('pixels')
        im=ImageOps.exif_transpose(im).convert('RGB').resize((144,144),Image.Resampling.BILINEAR).crop((8,8,136,136))
        return torch.from_numpy(np.asarray(im).copy()).permute(2,0,1).float()/255


def weight_digest(net):
    return digest(b''.join(t.detach().cpu().numpy().tobytes() for t in net.state_dict().values()))


def write_bytes(path, data):
    with Path(path).open('xb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())


def checkpoint(path, net, optimizer, generator, meta):
    # Stage in a sibling directory and rename once complete: the supervisor polls
    # for epoch-N/manifest.json, so it must never observe a torn/partial manifest.
    final=Path(path)
    if final.exists():raise FileExistsError(str(final))
    path=final.with_name('.staging-'+final.name+'-'+str(os.getpid())); path.mkdir(parents=True,exist_ok=False)
    result=_write_checkpoint(path, net, optimizer, generator, meta)
    from .fsops import durable_rename
    durable_rename(path, final)  # bounded Windows PermissionError retry; never replaces final
    return result


def _write_checkpoint(path, net, optimizer, generator, meta):
    tensors={'model.'+k:v.detach().clone().contiguous() for k,v in net.state_dict().items()}
    slots={}
    for name,p in net.named_parameters():
        state=optimizer.state[p]; slots[name]={}
        for k,v in state.items():
            key='optimizer.'+name+'.'+k
            if torch.is_tensor(v):
                tensors[key]=v.detach().clone().contiguous(); slots[name][k]={'tensor':key}
            else: slots[name][k]=v
    tensors['rng.torch']=torch.get_rng_state(); tensors['rng.sampler']=generator.get_state()
    save_file(tensors,str(path/'state.safetensors'))
    with (path/'state.safetensors').open('rb+') as f: os.fsync(f.fileno())
    meta=dict(meta,schema=1,recipe='compact-cnn/v1',optimizer='AdamW',slots=slots,param_names=[n for n,_ in net.named_parameters()],groups=[{k:v for k,v in g.items() if k!='params'} for g in optimizer.param_groups],python_rng=random.getstate(),scheduler=None,amp=None)
    write_bytes(path/'state.json',canonical(meta))
    inventory={f:{'sha256':digest((path/f).read_bytes()),'bytes':(path/f).stat().st_size} for f in ['state.safetensors','state.json']}
    write_bytes(path/'manifest.json',canonical({'schema':1,'files':inventory}))
    return digest((path/'manifest.json').read_bytes())


def validate_checkpoint(path,expected_digest=None):
    import math,re
    from .safe_codec import read_json,tensor_header,MODEL_SHAPES
    path=Path(path)
    if path.is_symlink():raise ValueError('checkpoint symlink')
    m=read_json(path/'manifest.json')
    if set(m)!= {'schema','files'} or m['schema']!=1 or set(m['files'])!={'state.json','state.safetensors'}:raise ValueError('checkpoint schema inventory')
    if expected_digest is not None and digest((path/'manifest.json').read_bytes())!=expected_digest:raise ValueError('committed checkpoint digest')
    if {p.name for p in path.iterdir()}!={'manifest.json','state.json','state.safetensors'}:raise ValueError('checkpoint unexpected files')
    for name,entry in m['files'].items():
        file=path/name;limit=1024*1024 if name.endswith('.json') else 32*1024*1024
        if set(entry)!={'bytes','sha256'} or file.is_symlink() or file.stat().st_size>limit or file.stat().st_size!=entry['bytes'] or digest(file.read_bytes())!=entry['sha256']:raise ValueError('checkpoint digest or size')
    meta=read_json(path/'state.json')
    fields={'schema','recipe','optimizer','slots','param_names','groups','python_rng','scheduler','amp','epoch','train_loss','validation_loss','updates','next_epoch','dataset_digest','seed','best','initial_digest'}
    if set(meta)!=fields or meta['schema']!=1 or meta['recipe']!='compact-cnn/v1' or meta['optimizer']!='AdamW' or meta['scheduler'] is not None or meta['amp'] is not None:raise ValueError('checkpoint state schema')
    for name in ['dataset_digest','initial_digest']:
        if not isinstance(meta[name],str) or re.fullmatch('[a-f0-9]{64}',meta[name]) is None:raise ValueError('checkpoint lineage')
    if type(meta['epoch']) is not int or not 1<=meta['epoch']<=100 or meta['next_epoch']!=meta['epoch']+1 or type(meta['updates']) is not int or not 1<=meta['updates']<=2_000_000 or type(meta['seed']) is not int or not 0<=meta['seed']<=4294967295:raise ValueError('checkpoint counters')
    if any(type(meta[k]) not in (int,float) or not math.isfinite(meta[k]) or meta[k]<0 for k in ['train_loss','validation_loss']):raise ValueError('checkpoint finite metrics')
    best=meta['best']
    if not isinstance(best,dict) or set(best)!={'epoch','loss'} or type(best['epoch']) is not int or not 1<=best['epoch']<=meta['epoch'] or type(best['loss']) not in (int,float) or not math.isfinite(best['loss']) or best['loss']<0:raise ValueError('checkpoint selection')
    if meta['param_names']!=list(MODEL_SHAPES) or set(meta['slots'])!=set(MODEL_SHAPES):raise ValueError('checkpoint parameters')
    expected={'model.'+k:('F32',shape) for k,shape in MODEL_SHAPES.items()}
    for name,shape in MODEL_SHAPES.items():
        if set(meta['slots'][name])!={'step','exp_avg','exp_avg_sq'}:raise ValueError('checkpoint optimizer slots')
        for slot in ('step','exp_avg','exp_avg_sq'):
            key='optimizer.'+name+'.'+slot
            if meta['slots'][name][slot]!={'tensor':key}:raise ValueError('checkpoint optimizer tensor identity')
            expected[key]=('F32',[] if slot=='step' else shape)
    expected.update({'rng.torch':('U8',[5056]),'rng.sampler':('U8',[5056])})
    groups=meta['groups'];keys={'amsgrad','betas','capturable','decoupled_weight_decay','differentiable','eps','foreach','fused','lr','maximize','weight_decay'}
    if not isinstance(groups,list) or len(groups)!=1 or set(groups[0])!=keys:raise ValueError('checkpoint optimizer groups')
    g=groups[0]
    if any(g[k] is not False for k in ['amsgrad','capturable','differentiable','maximize']) or g['decoupled_weight_decay'] is not True or g['foreach'] is not None or g['fused'] is not None or g['betas']!=[.9,.999] or g['eps']!=1e-8 or g['weight_decay']!=.0001 or type(g['lr']) not in (int,float) or not .00001<=g['lr']<=.1:raise ValueError('checkpoint optimizer variant')
    rng=meta['python_rng']
    if not isinstance(rng,list) or len(rng)!=3 or rng[0]!=3 or not isinstance(rng[1],list) or len(rng[1])!=625 or any(type(v) is not int or not 0<=v<=4294967295 for v in rng[1]) or rng[1][-1]>624 or (rng[2] is not None and (type(rng[2]) not in (int,float) or not math.isfinite(rng[2]))):raise ValueError('checkpoint Python RNG')
    tensor_header(path/'state.safetensors',expected)
    tensors=load_file(str(path/'state.safetensors'),device='cpu')
    try:
        for name in ['rng.torch','rng.sampler']:torch.Generator().set_state(tensors[name])
    except RuntimeError as exc:raise ValueError('checkpoint Torch RNG state') from exc
    for key,t in tensors.items():
        if key.startswith('rng.'):continue
        if not torch.isfinite(t).all():raise ValueError('checkpoint nonfinite tensor')
        if key.endswith('.step') and t.item()!=meta['updates']:raise ValueError('checkpoint optimizer step')
        if key.endswith('.exp_avg_sq') and (t<0).any():raise ValueError('checkpoint second moment')
    return m


def restore(path, net, optimizer, generator=None, dataset_digest=None, expected_digest=None):
    if expected_digest is None:raise ValueError('trusted expected checkpoint digest required')
    path=Path(path); validate_checkpoint(path,expected_digest=expected_digest)
    meta=json.loads((path/'state.json').read_text())
    if meta['schema']!=1 or meta['recipe']!='compact-cnn/v1' or meta['optimizer']!='AdamW' or meta['scheduler'] is not None or meta['amp'] is not None: raise ValueError('schema')
    if dataset_digest and meta['dataset_digest']!=dataset_digest: raise ValueError('lineage')
    if meta['param_names']!=[n for n,_ in net.named_parameters()]: raise ValueError('parameters')
    tensors=load_file(str(path/'state.safetensors'),device='cpu')
    expected={'model.'+k for k in net.state_dict()}|{'rng.torch','rng.sampler'}|{v['tensor'] for slots in meta['slots'].values() for v in slots.values() if isinstance(v,dict)}
    if set(tensors)!=expected: raise ValueError('tensor keys')
    for k,ref in net.state_dict().items():
        t=tensors['model.'+k]
        if t.shape!=ref.shape or t.dtype!=ref.dtype or not torch.isfinite(t).all(): raise ValueError('shape dtype finite')
    net.load_state_dict({k:tensors['model.'+k] for k in net.state_dict()},strict=True)
    for group,saved in zip(optimizer.param_groups,meta['groups'],strict=True): group.update(saved)
    for name,p in net.named_parameters():
        slots=meta['slots'][name]
        if set(slots)!={'step','exp_avg','exp_avg_sq'}: raise ValueError('optimizer slots')
        optimizer.state[p]={k:tensors[v['tensor']] if isinstance(v,dict) else v for k,v in slots.items()}
        for k in ['exp_avg','exp_avg_sq']:
            if optimizer.state[p][k].shape!=p.shape: raise ValueError('optimizer shape')
    def tuples(x): return tuple(tuples(i) for i in x) if isinstance(x,list) else x
    random.setstate(tuples(meta['python_rng']))
    torch.set_rng_state(tensors['rng.torch'])
    if generator is not None: generator.set_state(tensors['rng.sampler'])
    return meta


def train(data, out, epochs=10, seed=42, resume=None, pause_epoch=0, learning_rate=0.001, batch_size=8, expected_checkpoint_digest=None):
    torch.set_num_threads(2); torch.use_deterministic_algorithms(True)
    torch.manual_seed(seed); random.seed(seed)
    data=Path(data); out=Path(out); out.mkdir(parents=True,exist_ok=True)
    m=json.loads((data/'manifest.json').read_text()); verify(data,m)
    net=model(); opt=torch.optim.AdamW(net.parameters(),lr=learning_rate,weight_decay=0.0001)
    g=torch.Generator().manual_seed(seed)
    initial=weight_digest(net); start=1; updates=0; best=None
    if resume:
        state=restore(resume,net,opt,g,m['digest'],expected_digest=expected_checkpoint_digest); start=state['next_epoch']; updates=state['updates']; best=state['best']
        initial=state['initial_digest']
    train_rows=[s for s in m['samples'] if s['split']=='train']; val=[s for s in m['samples'] if s['split']=='validation']
    xs=torch.stack([pixels(data/s['file']) for s in train_rows]); ys=torch.tensor([s['label'] for s in train_rows])
    vx=torch.stack([pixels(data/s['file']) for s in val]); vy=torch.tensor([s['label'] for s in val])
    steps=[]; history=[]
    for epoch in range(start,epochs+1):
        net.train(); order=torch.randperm(len(xs),generator=g); total=0
        for batch,idx in enumerate(order.split(batch_size),1):
            opt.zero_grad(); loss=nn.functional.cross_entropy(net(xs[idx]),ys[idx]); loss.backward()
            norm=float(torch.nn.utils.clip_grad_norm_(net.parameters(),1e6))
            if not torch.isfinite(loss) or not np.isfinite(norm): raise ValueError('nonfinite')
            opt.step(); updates+=1; total+=float(loss.detach())*len(idx)
            step=dict(epoch=epoch,batch=batch,loss=float(loss.detach()),grad_norm=norm,ids=[train_rows[i]['id'] for i in idx.tolist()],split='train')
            steps.append(step)
            with (out/'steps.jsonl').open('a') as f: f.write(json.dumps(step)+'\n'); f.flush()
            if epoch==pause_epoch and batch==2:
                write_bytes(out/'paused.json',canonical({'epoch':epoch,'batch':batch,'pid':os.getpid()}))
                while True: time.sleep(.1)
        net.eval()
        with torch.inference_mode(): val_loss=float(nn.functional.cross_entropy(net(vx),vy))
        if best is None or val_loss<best['loss']: best={'epoch':epoch,'loss':val_loss}
        row=dict(epoch=epoch,train_loss=total/len(xs),validation_loss=val_loss,updates=updates)
        meta=dict(row,next_epoch=epoch+1,dataset_digest=m['digest'],seed=seed,best=best,initial_digest=initial)
        checkpoint(out/f'epoch-{epoch}',net,opt,g,meta)
        history.append(row)
    net.eval()
    with torch.inference_mode(): logits=net(vx).tolist()
    result=dict(scope=m['scope'],initial_digest=initial,final_digest=weight_digest(net),updates=updates,steps=steps,history=history,best=best,logits=logits,validation_ids=[s['id'] for s in val],pid=os.getpid())
    write_bytes(out/'result.json',canonical(result))
    return result


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(); p.add_argument('--data',required=True);p.add_argument('--out',required=True);p.add_argument('--epochs',type=int,default=10);p.add_argument('--resume');p.add_argument('--pause-epoch',type=int,default=0);p.add_argument('--learning-rate',type=float,default=.001);p.add_argument('--batch-size',type=int,default=8);p.add_argument('--seed',type=int,default=42)
    p.add_argument('--expected-checkpoint-digest')
    a=p.parse_args(); train(a.data,a.out,a.epochs,a.seed,a.resume,a.pause_epoch,a.learning_rate,a.batch_size,a.expected_checkpoint_digest)
