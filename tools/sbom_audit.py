"""ML-T-RIGHTS software inventory: SBOM with licenses + vulnerability review (OSV), archived as evidence.

Inventories (1) the host Python environment the API/worker run in, (2) the pinned model-image Python lock
(ops/requirements-real-model.lock) and (3) the web UI's npm lock (apps/web/package-lock.json). Each package/version is
checked against the OSV database (api.osv.dev querybatch; only package names and versions are sent). Writes
sbom.json, vulnerabilities.json and a summary to --out.

  .venv/Scripts/python -B tools/sbom_audit.py --out docs/evidence-rights-sbom-20261103
"""
import argparse
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def py_license(dist):
    meta = dist.metadata
    lic = (meta.get('License-Expression') or meta.get('License') or '').strip()
    classifiers = [c.split('::')[-1].strip() for c in (meta.get_all('Classifier') or []) if c.startswith('License ::')]
    if lic and len(lic) < 120:
        return lic
    return '; '.join(classifiers) or ('see package metadata' if lic else 'UNKNOWN')


def host_python():
    out = {}
    for d in metadata.distributions():
        name = (d.metadata.get('Name') or '').strip()
        if name:
            out[name.lower()] = {'ecosystem': 'PyPI', 'name': name, 'version': d.version, 'license': py_license(d),
                                 'source': 'host-venv'}
    return sorted(out.values(), key=lambda x: x['name'].lower())


def model_lock():
    rows = []
    path = ROOT / 'ops/requirements-real-model.lock'
    for line in path.read_text(encoding='utf-8').splitlines():
        m = re.match(r'^([A-Za-z0-9_.\-]+)==([^\s;\\]+)', line.strip())
        if m:
            rows.append({'ecosystem': 'PyPI', 'name': m.group(1), 'version': m.group(2).split('+')[0],
                         'license': 'see PyPI metadata (container lock)', 'source': 'model-image-lock'})
    return rows


def npm_lock():
    lock = json.loads((ROOT / 'apps/web/package-lock.json').read_text(encoding='utf-8'))
    rows = []
    for key, v in (lock.get('packages') or {}).items():
        if not key or 'version' not in v:
            continue
        name = v.get('name') or key.split('node_modules/')[-1]
        rows.append({'ecosystem': 'npm', 'name': name, 'version': v['version'], 'license': v.get('license') or 'UNKNOWN',
                     'dev': bool(v.get('dev')), 'source': 'apps/web/package-lock.json'})
    return rows


def osv(packages):
    results = []
    for i in range(0, len(packages), 500):
        chunk = packages[i:i + 500]
        body = json.dumps({'queries': [{'package': {'ecosystem': p['ecosystem'], 'name': p['name']}, 'version': p['version']}
                                       for p in chunk]}).encode()
        req = urllib.request.Request('https://api.osv.dev/v1/querybatch', data=body, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=60) as r:
            res = json.loads(r.read())['results']
        for p, hit in zip(chunk, res):
            ids = [v['id'] for v in hit.get('vulns', [])]
            if ids:
                results.append({**{k: p[k] for k in ('ecosystem', 'name', 'version', 'source')}, 'vulns': ids})
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=False)
    host, lock, web = host_python(), model_lock(), npm_lock()
    sbom = {'schema': 'fieldwork.sbom/v1', 'generated_utc': datetime.now(timezone.utc).isoformat(),
            'python_host': host, 'python_model_image_lock': lock, 'npm_web': web}
    vulns = osv(host + lock + web)
    unknown = [p for p in host + web if p['license'] in ('UNKNOWN', '')]
    (out / 'sbom.json').write_text(json.dumps(sbom, indent=1), encoding='utf-8')
    (out / 'vulnerabilities.json').write_text(json.dumps({'source': 'OSV querybatch', 'queried': len(host + lock + web),
                                                          'affected': vulns}, indent=1), encoding='utf-8')
    summary = {'packages': {'python_host': len(host), 'python_model_image_lock': len(lock), 'npm_web': len(web),
                            'npm_web_dev': sum(1 for p in web if p.get('dev'))},
               'license_unknown': [(p['ecosystem'], p['name'], p['version']) for p in unknown],
               'affected_packages': len(vulns), 'affected': [(v['source'], v['name'], v['version'], v['vulns']) for v in vulns],
               'sbom_sha256': hashlib.sha256((out / 'sbom.json').read_bytes()).hexdigest()}
    (out / 'summary.json').write_text(json.dumps(summary, indent=1), encoding='utf-8')
    print(json.dumps(summary, indent=1)[:4000])
    return 0


if __name__ == '__main__':
    sys.exit(main())
