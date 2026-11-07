"""Create separate local browser workflow test actors, not human review signoff."""
import json,secrets,uuid
from fieldwork.store import ROOT
from fieldwork.api import create_account


def main():
    path=ROOT/'.local-annotation-test.json'
    if path.exists():print('Existing private annotation-test actors retained');return
    workspace='annotation-browser-'+uuid.uuid4().hex
    actors={role:{'name':role+'-'+uuid.uuid4().hex,'password':secrets.token_urlsafe(32),'workspace':workspace} for role in ('owner','reviewer')}
    for role,actor in actors.items():create_account(actor['name'],actor['password'],workspace,role)
    with path.open('x') as f:json.dump(actors,f)
    print('Separate generated annotation browser actors created; credentials not printed')

if __name__=='__main__':main()
