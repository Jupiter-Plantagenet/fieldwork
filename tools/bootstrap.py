"""Project-local infrastructure; never touches sibling services."""
import json, pathlib, secrets, subprocess, urllib.request, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
if '--frontend' in sys.argv:
    packages={}
    for name in ['react','react-dom','vite','typescript','@types/react','@types/react-dom','@playwright/test']:
        data=json.load(urllib.request.urlopen('https://registry.npmjs.org/'+name+'/latest'))
        packages[name]=data['version']
    p={'name':'fieldwork-web','version':'0.1.0','private':True,'type':'module','scripts':{'dev':'vite --host 127.0.0.1 --port 5102 --strictPort','build':'tsc --noEmit && vite build','test':'playwright test'},'dependencies':{k:v for k,v in packages.items() if k in ['react','react-dom']},'devDependencies':{k:v for k,v in packages.items() if k not in ['react','react-dom']}}
    (ROOT/'apps/web/package.json').write_text(json.dumps(p,indent=2))
    print(json.dumps(packages))
    result=subprocess.run(['npm.cmd','install','--save-exact','--no-audit','--no-fund'],cwd=ROOT/'apps/web',capture_output=True,text=True)
    __import__('fieldwork.evidence_out',fromlist=['x']).write_evidence(ROOT,'install-frontend.log',result.stdout+result.stderr)
    sys.exit(result.returncode)
config=ROOT/'.local.json'
if not config.exists():
    config.write_text(json.dumps({'dsn':'postgresql://fieldwork:'+secrets.token_hex(24)+'@127.0.0.1:5542/fieldwork'}))
from urllib.parse import urlparse
u=urlparse(json.loads(config.read_text())['dsn'])
subprocess.run(['docker','run','-d','--name','fieldwork-postgres','--label','owner=fieldwork','-p','127.0.0.1:5542:5432','-e','POSTGRES_USER=fieldwork','-e','POSTGRES_PASSWORD='+u.password,'-e','POSTGRES_DB=fieldwork','-v','fieldwork-pgdata:/var/lib/postgresql/data','postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'],check=True)
