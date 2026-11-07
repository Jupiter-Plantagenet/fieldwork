"""FW-02: copied candidate files may not self-authorize forged evidence."""
import json,shutil
import pytest
from fieldwork.store import ROOT
from fieldwork.data import canonical,digest
from fieldwork.bundle import verify_bundle

SOURCE=ROOT/'evidence/internal-candidate'


def rehash(path):
    m=json.loads((path/'manifest.json').read_text())
    for name in m['files']:
        data=(path/name).read_bytes();m['files'][name]={'bytes':len(data),'sha256':digest(data)}
    (path/'manifest.json').write_bytes(canonical(m))


@pytest.mark.parametrize('forgery',['predictions','metrics','independent','scope','lineage'])
def test_fw02_rehashed_contradictory_or_unregistered_bundle_rejected(tmp_path,forgery):
    p=tmp_path/'candidate';shutil.copytree(SOURCE,p)
    if forgery=='predictions':(p/'evaluation/predictions.jsonl').write_text('')
    elif forgery in ('metrics','independent'):
        name='metrics' if forgery=='metrics' else 'independent-report';f=p/'evaluation'/(name+'.json');value=json.loads(f.read_text());value['accuracy']=1-value['accuracy'];f.write_bytes(canonical(value))
    elif forgery=='scope':
        f=p/'manifest.json';m=json.loads(f.read_text());m['scope']='forged-scope';f.write_bytes(canonical(m))
    else:
        f=p/'lineage.json';value=json.loads(f.read_text());value['checkpoint_digest']='unregistered';f.write_bytes(canonical(value))
    rehash(p)
    with pytest.raises(ValueError):verify_bundle(p,expected_digest=digest((p/'manifest.json').read_bytes()))


def test_fw02_verification_requires_external_trusted_digest_not_self_authorization():
    with pytest.raises(ValueError,match='trusted expected bundle digest required'):verify_bundle(SOURCE)
