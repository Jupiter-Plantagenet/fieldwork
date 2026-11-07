"""Create ID-complete truthful acceptance ledger and local evidence inventory."""
import json,hashlib,platform,subprocess
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
contract=json.loads((ROOT.parent/'portfolio-engineering/ml-contracts.json').read_text())
notes={
'ML-T-FLOW':('partial','15 React routes/reloads and actual proof inspection passed in Edge. Annotation/review/freeze, qualified export and ordinary inference remain unavailable; queued-worker lane resource-blocked.',['08-browser-green.log','browser-results.json']),
'ML-T-INTAKE':('blocked','Author-generated fixtures only; no archive intake/quarantine/dedup workflow or rights-cleared natural images.',[]),
'ML-T-VERSION':('partial','Immutable generated manifest and corruption rejection pass; annotation/review/child-version concurrency missing.',['01-manifest-green.log']),
'ML-T-SPLIT':('partial','45 distinct generated raw/pixel identities, 30/10/5 fixed split. No natural-image near-duplicate human review/support plan.',['01-manifest-green.log']),
'ML-T-HOLDOUT':('partial','Sealed media and ordinary candidate inference/download denials pass. No final steward exposure authorization or qualified export; no holdout opened.',['07-api-green.log','05-replay-green.log']),
'ML-T-OPTIMIZE':('partial','Real compact CNN AdamW updates, finite nonzero gradients, train-only audit and changed weights executed on trusted synthetic fixtures. Not the rights-cleared natural-image acceptance population. Latest full-suite rerun resource-skipped.',['02-optimization-green.log','critical-proof/test_kill_restart_epoch9_repla0/attempt-b/result.json']),
'ML-T-USEFUL':('blocked','No flower corpus, no qualified holdout population or useful-model result. Fixture metrics do not count.',[]),
'ML-T-METRICS':('partial','Independent stdlib exact joins, missing denominator, tie, zero-support, identity/duplicate rejection and real raw-output recomputation pass. Full metric-schema null-reason/Wilson/group-interval release features missing.',['03-metrics-green.log','12-cells-green.log']),
'ML-T-CELL':('partial','Every one of 25 real fixture validation cells reconciled all one-item API pages, including empty cells and membership digests. Full missing-bucket/filter/cursor release contract incomplete.',['12-cells-green.log']),
'ML-T-QUEUE':('partial','PostgreSQL idempotency and payload conflict pass; real browser form submits or reports actual resource blocker. API restart persistence observed. 60-second response-loss/disconnected-worker acceptance not fully scheduled.',['04-control-green.log','07-api-green.log','08-browser-green.log']),
'ML-T-FENCE':('partial','45-second lease, actual child kill, injected DB server-time expiry, new attempt/fence, stale heartbeat/checkpoint/complete rejection and slot hold pass. No automatic 5-second expiry scanner/full competing-claim or restore-generation suite.',['05-replay-green.log','04-control-green.log']),
'ML-T-ATOMIC':('partial','Incomplete staging invisible; hashes verified before DB pointer; transaction lost-ack retry is no-op. No full crash-edge/disk-full/power-loss/GC acceptance.',['10-atomic-green.log','11-lineage-green.log']),
'ML-T-REPLAY':('partial','Actual kill in epoch9/batch2 after epoch8 commit; fresh-process replay9..10; model/optimizer/RNG/sampler restoration; final parameters/logits max abs 0.0; exact committed epochs1..10. Synthetic proof only; resource/isolation envelopes not fully accepted.',['05-replay-green.log','critical-proof/test_kill_restart_epoch9_repla0/replay-diff.json']),
'ML-T-CANCEL':('partial','Sequential cancel-first denies publication and retains slot; completion-first returns succeeded; terminal cancel cannot resume. Concurrent barrier suite/process-tree quarantine not proven.',['10-atomic-green.log','11-lineage-green.log']),
'ML-T-SAFE':('blocked','Data-only service-produced artifact inventory/digest/key/shape checks and corrupt/unexpected file rejection pass. OS memory/process/credential/filesystem/network denial and full hostile parser suite missing. Do not enable untrusted uploads.',['06-bundle-green.log']),
'ML-T-TENANT':('partial','Real session/role/workspace/CSRF/Origin negative HTTP tests pass. DB bootstrap superuser, non-owner RLS/composite tenant FKs, secure HTTPS/idle session lifecycle and revocation missing.',['07-api-green.log','12-cells-green.log']),
'ML-T-BUNDLE':('partial','Synthetic internal candidate safe inventory and fresh OS inference process matched actual training logits within1e-6; per-file digests retained. Qualified release, complete rights/SBOM and OS-isolated task credentials remain blocked.',['06-bundle-green.log','bundle-proof/test_candidate_safe_inventory_0/fresh-process.json','candidate-retention.json']),
'ML-T-UX':('partial','Original compositions, semantic controls, focus and mobile CSS; Edge route task and390px overflow automation pass. No complete manual keyboard/screen-reader/WCAG audit.',['08-browser-green.log','browser-mobile.png']),
'ML-T-BROWSER':('partial','Local Edge/Chromium automation only; all15 routes/reloads, gallery, proof training/evaluation and exact cell drilldown. No full Firefox/Safari/iOS/Android matrix.',['browser-results.json','08-browser-green.log']),
'ML-T-CAPACITY':('blocked','No3670-image/20epoch/10session15min capacity workload or latency/cost acceptance run.',[]),
'ML-T-INFERPERF':('blocked','One actual cold inference proof only; no30-process performance population or RSS/reference-host target acceptance.',['bundle-proof/test_candidate_safe_inventory_0/fresh-process.json']),
'ML-T-RESOURCE':('blocked','Live API/worker6GiB RAM12GiB disk gate implemented. Host RAM below gate at final run; worker integration correctly skipped. No hard RSS/time/write budget enforcement or allqueue/preflight requirements.',['environment.json','09-worker-green.log','full-suite.log']),
'ML-T-RESTORE':('blocked','No approved independent-volume encrypted backup/key or empty-host restoration exercise.',[]),
'ML-T-MIGRATE':('partial','Idempotent initial PostgreSQL schema exists and is exercised. No reviewed Alembic expansion/backfill/rollback on restored data.',['04-control-green.log']),
'ML-T-CLEAN':('blocked','Exact installed versions and npm lock retained; no empty-cache independent machine reproduction. Several inspection tests depend on retained proof artifacts.',['environment.json']),
'ML-T-RIGHTS':('blocked','No external image/weights acquired; author-generated fixture source/notice retained. Flower asset grants, dependency full license/CVE review/export rights not complete.',[]),
'ML-T-EVENTS':('partial','Transactional authorized PostgreSQL event log with polling exists. Not SSE, seven-day replay/cursor expiry/revocation acceptance.',['04-control-green.log']),
'ML-T-PRIVACY':('blocked','No images/secrets intentionally printed; local generated secrets ignored and browser traces disabled. Retention/deletion/backuptombstones scheduler not implemented.',[]),
'ML-T-DELIVERY':('blocked','Local working source/artifacts only; full gates, independent release owner, publication/license decision and clean repro missing.',[])
}
assert set(notes)=={t['id'] for t in contract['acceptance_tests']}
items=[]
for t in contract['acceptance_tests']:
    status,note,paths=notes[t['id']];items.append({'id':t['id'],'status':status,'scope':'local-synthetic-execution','observed':note,'evidence':['evidence/'+p for p in paths],'release_pass':False})
report={'generated_at':datetime.now(timezone.utc).isoformat(),'product':'Fieldwork','release_qualified':False,'full_acceptance_passes':0,'tests':items,'summary':{s:sum(i['status']==s for i in items) for s in ['partial','blocked']},'non_goals_not_claimed':['flower usefulness','final holdout acceptance','production security','public deployment','clean-host reproduction']}
__import__('fieldwork.evidence_out',fromlist=['x']).write_evidence(ROOT,'acceptance.json',report)
inputs=['portfolio-engineering/ml-blueprint.md','portfolio-engineering/ml-contracts.json','portfolio-mockups/ml.html','portfolio-mockups/ml-design-notes.md','PORTFOLIO-QUALITY-CHARTER.md','portfolio-engineering/PROGRAM-PLAN.md']
source_inventory={p:hashlib.sha256((ROOT.parent/p).read_bytes()).hexdigest() for p in inputs}
files=[]
for p in sorted((ROOT/'evidence').rglob('*')):
    if not p.is_file() or p.name in {'api-server.log','ui-server.log'} or p.name=='manifest.json' and p.parent==ROOT/'evidence' or any(part in ['tmp','suite','atomic'] for part in p.relative_to(ROOT/'evidence').parts):continue
    files.append({'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
manifest={'generated_at':report['generated_at'],'input_authority_sha256':source_inventory,'files':files,'source_commit':subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,capture_output=True,text=True).stdout.strip() or 'uncommitted-bootstrap','scope':'local synthetic execution; evidence is not independent signed release acceptance'}
__import__('fieldwork.evidence_out',fromlist=['x']).write_evidence(ROOT,'manifest.json',manifest)
print(json.dumps({'acceptance_ids':len(items),'summary':report['summary'],'inventoried_files':len(files),'release_qualified':False}))
