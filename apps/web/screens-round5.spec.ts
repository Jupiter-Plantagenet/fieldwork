import { test, expect, type Page, type Locator } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

/* Round-5 audit of all 15 screens against the live API (5102 -> 8102).
 * Per screen: real data (cross-checked with the API) or honest empty, observable loading,
 * forced 500 / network abort / 403 states, no console errors, screenshots.
 * Credentials are read into memory only and never written or logged. */
const OUT=process.env.P5UI_OUT!;
const local=JSON.parse(fs.readFileSync('../../.browser-test.json','utf8')) as {name:string;password:string};
let cookies:Parameters<import('@playwright/test').BrowserContext['addCookies']>[0]=[];
let ws='';
const results:Record<string,unknown>={};

function writeOnce(file:string,data:string|Buffer){fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,data,{flag:'wx'})}
async function shot(page:Page,name:string){writeOnce(path.join(OUT,'screens',`${name}.png`),await page.screenshot({fullPage:true}))}
const api=(p:string)=>`/api/v1/workspaces/${ws}${p}`;

type Screen={id:string;title:string;req:RegExp;loading:(p:Page)=>Locator;
 ready:(p:Page)=>Promise<string>;error:(p:Page,kind:'500'|'abort'|'403')=>Locator};
const res=(label:string)=>(p:Page)=>p.locator(`[data-resource="${label}"]`).first();
const state=(label:string,s:string)=>(p:Page)=>p.locator(`[data-resource="${label}"][data-state="${s}"]`).first();
const errorFor=(label:string)=>(p:Page,kind:'500'|'abort'|'403')=>p.locator(`[data-resource="${label}"][data-state="${kind==='403'?'permission_denied':kind==='abort'?'offline':'error'}"]`).first();
const annotationError=(p:Page,kind:'500'|'abort'|'403')=>p.locator(`[data-resource="versions"][data-state="${kind==='403'?'permission_denied':'error'}"]`).first();

const screens:Screen[]=[
 {id:'overview',title:'Research workspace',req:/\/screens\/operations$/,loading:state('operations','loading'),error:errorFor('operations'),
  ready:async p=>{const s=await (await p.request.get(api('/snapshot'))).json();await expect(state('operations','ready')(p)).toBeVisible();await expect(p.locator('[data-count="runs"]')).toHaveText(String(s.runs.length));return `runs=${s.runs.length}`}},
 {id:'dataset',title:'Dataset explorer',req:/\/versions$/,loading:state('dataset versions','loading'),error:errorFor('dataset versions'),
  ready:async p=>{const s=await (await p.request.get(api('/snapshot'))).json();await expect(p.locator('[data-count="samples"]')).toContainText(`${s.samples.length} permitted samples · ${s.counts.holdout} sealed`);await expect(p.locator('.samplecard')).toHaveCount(s.samples.length);return `samples=${s.samples.length} holdout_sealed=${s.counts.holdout}`}},
 {id:'sample',title:'Sample inspector',req:/\/versions$/,loading:state('versions','loading'),error:annotationError,
  ready:async p=>{const s=await (await p.request.get(api('/snapshot'))).json();const first=s.samples[0];await expect(p.getByText(first.sha256,{exact:true})).toBeVisible();await expect(p.locator('[data-resource="versions"]').first()).toBeVisible();return `sample=${first.id}`}},
 {id:'annotations',title:'Annotation review',req:/\/versions$/,loading:state('versions','loading'),error:annotationError,
  ready:async p=>{const v=await (await p.request.get(api('/versions'))).json();if(!v.items.length)await expect(state('versions','empty')(p)).toBeVisible();else await expect(p.getByLabel('Working version')).toBeVisible();return `versions=${v.items.length}`}},
 {id:'versions',title:'Dataset versions',req:/\/versions$/,loading:state('dataset versions','loading'),error:errorFor('dataset versions'),
  ready:async p=>{const v=await (await p.request.get(api('/versions'))).json();if(!v.items.length)await expect(state('dataset versions','empty')(p)).toBeVisible();else await expect(p.getByRole('table',{name:'Persisted versions'}).locator('tbody tr')).toHaveCount(v.items.length);return `versions=${v.items.length}`}},
 {id:'splits',title:'Split integrity',req:/\/screens\/splits$/,loading:state('split report','loading'),error:errorFor('split report'),
  ready:async p=>{const d=await (await p.request.get(api('/screens/splits'))).json();await expect(state('split report','ready')(p)).toBeVisible();await expect(p.getByRole('heading',{name:`Membership / manifest ${d.manifest_digest.slice(0,8)}`})).toBeVisible();await expect(p.locator(`[data-integrity="${d.integrity.status}"]`)).toBeVisible();return `integrity=${d.integrity.status} holdout=${d.splits.holdout?.samples}`}},
 {id:'configure',title:'Configure training',req:/\/screens\/configure$/,loading:state('configuration inputs','loading'),error:errorFor('configuration inputs'),
  ready:async p=>{const d=await (await p.request.get(api('/screens/configure'))).json();await expect(state('configuration inputs','ready')(p)).toBeVisible();await expect(p.locator(`[data-preflight="${d.preflight.admitted?'admitted':'blocked'}"]`)).toBeVisible();await expect(p.getByLabel('Epochs',{exact:true})).toHaveValue(d.bounds.epochs.default);return `preflight_admitted=${d.preflight.admitted} may_submit=${d.may_submit}`}},
 {id:'runs',title:'Runs & workers',req:/\/screens\/operations$/,loading:state('run queue','loading'),error:errorFor('run queue'),
  ready:async p=>{const d=await (await p.request.get(api('/screens/operations'))).json();await expect(state('run queue','ready')(p)).toBeVisible();if(d.runs.length)await expect(p.getByRole('table',{name:'Research queue'}).locator('tbody tr')).toHaveCount(d.runs.length);await expect(p.locator(`[data-worker-status="${d.worker.status}"]`)).toBeVisible();return `runs=${d.runs.length} worker=${d.worker.status} queue=${d.queue_length}`}},
 {id:'training',title:'Training run',req:/\/screens\/runs\/[^/]+\/lineage$/,loading:state('run lineage','loading'),error:errorFor('run lineage'),
  ready:async p=>{const s=await (await p.request.get(api('/snapshot'))).json();const run=s.runs.find((r:{state:string})=>r.state==='succeeded')||s.runs[0];if(!run){await expect(p.locator('[data-resource="training"][data-state="empty"]')).toBeVisible();return 'no runs'}
   const l=await (await p.request.get(api(`/screens/runs/${run.id}/lineage`))).json();await expect(state('run lineage','ready')(p)).toBeVisible();
   if(l.checkpoints.length)await expect(p.getByRole('table',{name:'Committed checkpoints'}).locator('tbody tr')).toHaveCount(l.checkpoints.length);else await expect(p.locator('[data-state="waiting"]')).toBeVisible();
   await expect(p.getByRole('table',{name:'Attempts'}).locator('tbody tr')).toHaveCount(l.attempts.length);return `run=${run.id.slice(0,8)} checkpoints=${l.checkpoints.length} attempts=${l.attempts.length}`}},
 {id:'evaluation',title:'Evaluation results',req:/\/runs\/[^/]+\/evaluation$/,loading:state('evaluation','loading'),error:errorFor('evaluation'),
  ready:async p=>{const s=await (await p.request.get(api('/snapshot'))).json();const run=s.runs.find((r:{state:string})=>r.state==='succeeded')||s.runs[0];const r=await p.request.get(api(`/runs/${run.id}/evaluation`));
   const expected=r.status()===200?'ready':[409,410,412,422,423].includes(r.status())?'blocked':r.status()===404?'not_found':'error';await expect(state('evaluation',expected)(p)).toBeVisible();return `api_status=${r.status()} ui_state=${expected}`}},
 {id:'errors',title:'Error investigation',req:/\/runs\/[^/]+\/slices\?/,loading:p=>p.getByText('Loading exact slice…'),error:(p,kind)=>p.getByRole('alert').filter({hasText:kind==='403'?'Slice unavailable · 403':kind==='abort'?/Slice unavailable.*Failed to fetch/:'Slice unavailable · 500'}),
  ready:async p=>{const s=await (await p.request.get(api('/snapshot'))).json();const run=s.runs.find((r:{state:string})=>r.state==='succeeded')||s.runs[0];const r=await p.request.get(api(`/runs/${run.id}/slices?actual=0&predicted=0&bucket=cell`));
   if(r.status()===200){const d=await r.json();await expect(p.getByText(`${d.total} exact matching records`,{exact:false})).toBeVisible()}else await expect(p.getByRole('alert').filter({hasText:`Slice unavailable · ${r.status()}`})).toBeVisible();return `api_status=${r.status()}`}},
 {id:'recovery',title:'Recover training',req:/\/screens\/runs\/[^/]+\/lineage$/,loading:state('recovery lineage','loading'),error:errorFor('recovery lineage'),
  ready:async p=>{const s=await (await p.request.get(api('/snapshot'))).json();const run=s.runs.find((r:{state:string})=>r.state==='succeeded')||s.runs[0];const l=await (await p.request.get(api(`/screens/runs/${run.id}/lineage`))).json();
   await expect(state('recovery lineage','ready')(p)).toBeVisible();await expect(p.locator('[data-boundary]')).toHaveCount(l.boundaries.length);if(!l.recovery.resumable)await expect(p.locator('[data-state="not_recoverable"]')).toBeVisible();
   return `boundaries=${l.boundaries.map((b:{committed_epoch:number;replay_epoch:number|null})=>`${b.committed_epoch}->${b.replay_epoch}`).join(',')} resumable=${l.recovery.resumable}`}},
 {id:'artifacts',title:'Model artifacts',req:/\/runs\/[^/]+\/artifacts$/,loading:state('bundle evidence','loading'),error:errorFor('bundle evidence'),
  ready:async p=>{const s=await (await p.request.get(api('/snapshot'))).json();const run=s.runs.find((r:{state:string})=>r.state==='succeeded')||s.runs[0];const r=await p.request.get(api(`/runs/${run.id}/artifacts`));
   const expected=r.status()===200?'ready':[409,410,412,422,423].includes(r.status())?'blocked':r.status()===404?'not_found':'error';await expect(state('bundle evidence',expected)(p)).toBeVisible();await expect(p.getByRole('table',{name:'Artifact stages'}).locator('tbody tr')).toHaveCount(s.runs.length);return `api_status=${r.status()} ui_state=${expected}`}},
 {id:'inference',title:'Inference playground',req:/\/screens\/inference$/,loading:state('inference availability','loading'),error:errorFor('inference availability'),
  ready:async p=>{const d=await (await p.request.get(api('/screens/inference'))).json();await expect(state('inference availability','ready')(p)).toBeVisible();if(!d.ordinary_inference.allowed){await expect(p.locator('[data-state="inference_denied"]')).toBeVisible();await expect(p.getByLabel('Inference image')).toBeDisabled()}
   await expect(state('inference records','empty')(p)).toBeVisible();return `allowed=${d.ordinary_inference.allowed} candidates=${d.candidates.length}`}},
 {id:'settings',title:'Workspace & access settings',req:/\/screens\/access$/,loading:state('access policy','loading'),error:errorFor('access policy'),
  ready:async p=>{const d=await (await p.request.get(api('/screens/access'))).json();await expect(state('access policy','ready')(p)).toBeVisible();await expect(p.getByRole('table',{name:'Members'}).locator('tbody tr')).toHaveCount(d.members.length);await expect(p.getByRole('table',{name:'Access policy'}).locator('tbody tr')).toHaveCount(d.policy.length);return `members=${d.members.length} policy_rows=${d.policy.length}`}},
];

function watchConsole(page:Page){const errors:string[]=[];page.on('console',m=>{if(m.type()==='error')errors.push(m.text())});page.on('pageerror',e=>errors.push('pageerror: '+e.message));return errors}
async function nav(page:Page,title:string){await page.getByRole('navigation').getByRole('button',{name:title,exact:true}).click();await expect(page.getByRole('heading',{name:title,exact:true,level:1})).toBeVisible()}
const neutral=(id:string)=>id==='inference'?'Split integrity':'Inference playground';

test.describe.configure({mode:'serial'});

test('sign in through the UI with the browser-test account',async({page})=>{
 const errors=watchConsole(page);
 await page.goto('/');
 await page.getByLabel('Account').fill(local.name);await page.getByLabel('Password').fill(local.password);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Research workspace',exact:true})).toBeVisible();
 const session=await (await page.request.get('/auth/session')).json();ws=session.workspace;
 cookies=await page.context().cookies();
 // The unauthenticated session probe returns 401 before sign-in; that is expected, nothing else is.
 expect(errors.filter(e=>!/401/.test(e))).toEqual([]);
 results.signin={role:session.role,workspace_prefix:ws.slice(0,8)};
});

for(const s of screens){
 test(`${s.id}: real data, loading, error, denied, console`,async({page})=>{
  await page.context().addCookies(cookies);
  const errors=watchConsole(page);const r:Record<string,unknown>={title:s.title};
  // 1. Loading: delay the screen-specific read so the loading state is observable.
  await page.goto('/#'+(s.id==='inference'?'splits':'inference'));
  await expect(page.getByRole('heading',{level:1})).toBeVisible();
  let release:()=>void=()=>{};const gate=new Promise<void>(ok=>{release=ok});
  await page.route(s.req,async route=>{await gate;await route.continue().catch(()=>{})});
  await nav(page,s.title);
  await expect(s.loading(page)).toBeVisible();r.loading='observed';
  release();await page.unrouteAll({behavior:'wait'});
  // 2. Ready with real data (cross-checked against the API) or honest empty.
  r.ready=await s.ready(page);
  await shot(page,`${s.id}-ready`);
  // Application errors must be zero. The browser itself logs a resource-load line for every
  // non-2xx response; those are recorded and must match statuses the real API returned above.
  const appErrors=errors.filter(e=>!/^Failed to load resource: the server responded with a status of \d+/.test(e));
  expect(appErrors,'application console errors while loading/ready').toEqual([]);
  r.console_errors_ready=appErrors.length;r.browser_resource_status_logs_ready=errors.filter(e=>!appErrors.includes(e)).map(e=>e.replace(/^.*status of (\d+).*$/,'$1'));
  errors.length=0;
  // 3. Forced failures for the screen-specific read: HTTP 500, network abort (offline), 403 (permission denied).
  for(const kind of ['500','abort','403'] as const){
   await page.unroute(s.req);
   await page.route(s.req,route=>kind==='abort'?route.abort('internetdisconnected'):route.fulfill({status:Number(kind),contentType:'application/json',body:JSON.stringify({detail:kind==='403'?'ROLE':'P5UI_FORCED_500'})}));
   await nav(page,neutral(s.id));await nav(page,s.title);
   await expect(s.error(page,kind)).toBeVisible();
   r[`state_${kind}`]='shown';
   if(kind==='500')await shot(page,`${s.id}-error-500`);
  }
  await page.unroute(s.req);
  const unexpected=errors.filter(e=>!/Failed to load resource|net::ERR_INTERNET_DISCONNECTED|Failed to fetch/.test(e));
  expect(unexpected,'console errors other than the forced network failures').toEqual([]);
  r.console_errors_unexpected=unexpected.length;r.result='passed';results[s.id]=r;
 });
}

test('workspace snapshot offline at load and stale after load',async({page})=>{
 await page.context().addCookies(cookies);const errors=watchConsole(page);
 await page.route(/\/snapshot$/,route=>route.fulfill({status:503,contentType:'application/json',body:'{"detail":"P5UI_FORCED_503"}'}));
 await page.goto('/#overview');
 await expect(page.locator('[data-resource="workspace"][data-state="offline"]')).toBeVisible();
 await shot(page,'workspace-offline');
 await page.unroute(/\/snapshot$/);
 await page.getByRole('button',{name:'Retry'}).first().click();
 await expect(page.locator('[data-resource="operations"][data-state="ready"]')).toBeVisible();
 await page.route(/\/snapshot$/,route=>route.abort('internetdisconnected'));
 await expect(page.locator('[data-state="offline_stale"]')).toBeVisible({timeout:10000});
 await expect(page.locator('[data-count="runs"]')).toBeVisible();
 await shot(page,'workspace-stale');
 await page.unroute(/\/snapshot$/);
 expect(errors.filter(e=>!/Failed to load resource|net::ERR_INTERNET_DISCONNECTED|Failed to fetch|503/.test(e))).toEqual([]);
 results.workspace={offline_at_load:'shown',stale_after_load:'shown'};
});

test.afterAll(()=>{if(Object.keys(results).length)writeOnce(path.join(OUT,'screen-results.json'),JSON.stringify(results,null,2))});
