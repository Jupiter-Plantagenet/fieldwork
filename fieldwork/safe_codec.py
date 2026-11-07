"""Bounded data-only parsing before calling native tensor allocation code."""
import json,math,struct
from pathlib import Path

MODEL_SHAPES={'0.weight':[32,3,3,3],'0.bias':[32],'3.weight':[64,32,3,3],'3.bias':[64],'6.weight':[128,64,3,3],'6.bias':[128],'11.weight':[5,128],'11.bias':[5]}


def unique_object(pairs):
    value={}
    for k,v in pairs:
        if k in value:raise ValueError('duplicate JSON key')
        value[k]=v
    return value


def read_json(path,limit=1024*1024):
    path=Path(path)
    if path.is_symlink() or path.stat().st_size>limit:raise ValueError('JSON size or symlink')
    try:return json.loads(path.read_bytes(),object_pairs_hook=unique_object,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (UnicodeError,RecursionError,OverflowError) as exc:raise ValueError('JSON encoding or nesting') from exc


def tensor_header(path,expected):
    path=Path(path);size=path.stat().st_size
    if path.is_symlink() or size>32*1024*1024 or size<10:raise ValueError('tensor size')
    with path.open('rb') as f:
        length=struct.unpack('<Q',f.read(8))[0]
        if length>64*1024 or length>size-8:raise ValueError('tensor header size')
        try:header=json.loads(f.read(length),object_pairs_hook=unique_object)
        except (UnicodeError,json.JSONDecodeError,RecursionError) as exc:raise ValueError('tensor header JSON') from exc
    if not isinstance(header,dict) or set(header)!=set(expected) or len(header)>100:raise ValueError('tensor header keys')
    ranges=[];elements=0
    for name,entry in header.items():
        dtype,shape=expected[name]
        if not isinstance(entry,dict) or set(entry)!={'dtype','shape','data_offsets'} or entry['dtype']!=dtype or entry['shape']!=shape:raise ValueError('tensor header shape or dtype')
        if not all(type(d) is int and 0<=d<=2_000_000 for d in entry['shape']):raise ValueError('tensor dimension')
        count=math.prod(shape);elements+=count
        offsets=entry['data_offsets']
        if not isinstance(offsets,list) or len(offsets)!=2 or not all(type(x) is int for x in offsets) or offsets[0]<0 or offsets[1]-offsets[0]!=count*{'F32':4,'U8':1}[dtype]:raise ValueError('tensor offsets')
        ranges.append(tuple(offsets))
    if elements>2_000_000:raise ValueError('tensor element budget')
    end=0
    for start,stop in sorted(ranges):
        if start!=end:raise ValueError('tensor overlapping or gapped storage')
        end=stop
    if end!=size-length-8:raise ValueError('tensor payload size')
    return header
