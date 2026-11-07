"""Retain original verified bytes separately from intentionally corrupted test copy."""
from pathlib import Path
import json,shutil,hashlib
from fieldwork.store import ROOT
from fieldwork.data import canonical
source=ROOT/'evidence/bundle-proof/test_candidate_safe_inventory_0'
manifest=json.loads((source/'bundle/manifest.json').read_text());out=ROOT/'evidence/internal-candidate'
if not out.exists():
    shutil.copytree(source/'bundle',out)
    original=json.loads((source/'images/manifest.json').read_text())['classes']
    (out/'classes.json').write_bytes(canonical(original))
for name,entry in manifest['files'].items():
    data=(out/name).read_bytes()
    assert len(data)==entry['bytes'] and hashlib.sha256(data).hexdigest()==entry['sha256'],name
receipt=json.loads((source/'fresh-process.json').read_text())
assert hashlib.sha256((out/'manifest.json').read_bytes()).hexdigest()==receipt['bundle_digest']
report={'status':'all original candidate bytes reconciled to retained verified manifest','source':'negative test intentionally corrupts its own copy after successful inference','retained_candidate':str(out.relative_to(ROOT)),'bundle_digest':receipt['bundle_digest'],'fresh_process_receipt':str((source/'fresh-process.json').relative_to(ROOT)),'new_model_computation':False}
__import__('fieldwork.evidence_out',fromlist=['x']).write_evidence(ROOT,'candidate-retention.json',canonical(report));print(json.dumps(report))
