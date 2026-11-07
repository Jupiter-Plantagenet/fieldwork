"""Bounded authenticated cursor codec; opaque to clients, not authority."""
import base64,hashlib,hmac,json,secrets,time
from .store import ROOT,Conflict
from .data import canonical
from .annotations import Rejection


def key():
    path=ROOT/'.local-cursors.json'
    try:
        with path.open('x') as f:json.dump({'key':secrets.token_hex(32)},f)
    except FileExistsError:pass
    return bytes.fromhex(json.loads(path.read_text())['key'])


def encode(binding,offset,ttl=300):
    body=canonical({'binding':binding,'offset':offset,'expires':int(time.time())+ttl})
    return base64.urlsafe_b64encode(body+hmac.digest(key(),body,'sha256')).decode().rstrip('=')


def decode(cursor,binding):
    if len(cursor)>4096:raise Conflict('CURSOR_INVALID')
    try:
        raw=base64.b64decode(cursor+'='*(-len(cursor)%4),altchars=b'-_',validate=True);body,signature=raw[:-32],raw[-32:]
        if not hmac.compare_digest(signature,hmac.digest(key(),body,'sha256')):raise ValueError('signature')
        value=json.loads(body)
        if value['binding']!=binding or type(value['offset']) is not int or value['offset']<0:raise ValueError('binding')
        if value['expires']<time.time():raise Rejection(410,'CURSOR_EXPIRED_RESNAPSHOT')
        return value['offset']
    except Rejection:raise
    except (ValueError,KeyError,TypeError):raise Conflict('CURSOR_INVALID_OR_SNAPSHOT_CHANGED')
