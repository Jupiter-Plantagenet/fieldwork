// Mounted production App with AUTHOR-HTTP fixtures only; no real API/auth/DB.
import { chromium } from 'playwright';
import assert from 'node:assert/strict';
const browser = await chromium.launch({ channel: 'msedge', headless: true });
let page;
const hash = 'a'.repeat(64), membership = 'b'.repeat(64);
const user = { name: 'authored-researcher', workspace: 'authored-lab', role: 'researcher', csrf: 'authored-only' };
const snapshot = { capabilities: { revisioned_cancel: true, evaluation_flags: true }, workspace: user.workspace, name: user.name, role: user.role, scope: 'synthetic-execution-only', classes: ['A','B','C','D','E'], dataset_digest: hash,
 samples: [{id:'s1',label:0,split:'validation',group:'g',sha256:hash,pixel_sha256:hash}], counts:{train:0,validation:1,holdout:0}, runs:[{id:'run-a',state:'succeeded',epoch:1,fence:1,revision:7,attempt:'a',config:{epochs:1,seed:1},result:null}], rights:'Authored fixture, no real rights claim', release:'blocked', preflight:{free_ram_bytes:0,free_disk_bytes:0,environment:'AUTHOR-HTTP'},worker:null };
const metrics = { n:1,ok:1,accuracy:1,coverage:1,matrix:[[1,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0]],cells:{'0:0':['s1']},missing:[],support:[1,0,0,0,0],f1:[1,null,null,null,null],recall:[1,null,null,null,null],macro_f1:1,cross_entropy:0,status:'complete' };
let commands=[], flags=[], loseResponse=true;
let refusal=Number(process.argv[2]||401), refuseNext=false;
try {
 page = await browser.newPage();
 page.setDefaultTimeout(5000);
 await page.route('**/api/**', async route => {
  const req=route.request(), path=new URL(req.url()).pathname;
  let value;
  if(path.endsWith('/snapshot')) value=snapshot;
  else if(path.endsWith('/evaluation')) value={metrics,population:[{id:'s1',label:0,sha256:hash}],independent:metrics};
  else if(path.endsWith('/slices')) {
   const query=new URL(req.url()).searchParams;
   const missing=query.get('bucket')==='missing';
   const actual=Number(query.get('actual')||0), predicted=Number(query.get('predicted')||0);
   value={ sample_ids:actual===0?['s1']:[], total:actual===0?1:0, membership_digest:membership,next_offset:null,next_cursor:null,predicate:{actual,predicted:missing?null:predicted,bucket:missing?'missing':'cell'},evaluation_digest:hash };
  } else if(path.endsWith('/flags')) {
   if(req.method()==='POST') {
    commands.push({body:req.postData(),headers:req.headers()});
    if(refuseNext){refuseNext=false;await route.fulfill({status:refusal,json:{code:'SESSION_OR_ROLE_REFUSED'}});return;}
    const body=req.postDataJSON();
    const flag=flags[0]||{id:'authored-flag',run_id:'run-a',actor:user.name,reason:body.reason,predicate:{actual:body.actual,predicted:body.predicted,bucket:body.bucket},sample_ids:['s1'],slice_digest:body.slice_digest,evaluation_digest:body.evaluation_digest};
    if(flags.length)assert.equal(req.headers()['idempotency-key'],commands[0].headers['idempotency-key'],'must replay, not create a second flag');
    else flags.push(flag);
    if(loseResponse){loseResponse=false;refuseNext=true;await route.abort('failed');return;}
    value={flag_id:flag.id,flag,evaluation_mutated:false};
   } else value={items:flags};
  } else { await route.fulfill({status:409,json:{code:'AUTHOR_FIXTURE_NO_ARTIFACT'}}); return; }
  await route.fulfill({status:req.method()==='POST'?201:200,json:value});
 });
 await page.route('**/auth/session',route=>route.fulfill({json:user}));
 await page.goto('http://127.0.0.1:5102/#errors');
 await page.getByRole('img',{name:'Author-generated A geometric image s1'}).waitFor();
 await page.getByRole('textbox',{name:'Follow-up reason'}).fill('Review these examples in a future dataset plan');
 await page.getByRole('button',{name:'Flag exact slice'}).click();
 await page.getByText(/outcome unconfirmed/i).waitFor();
 // Polling changes the run; retries must retain the original revision/key/body.
 snapshot.runs[0].revision=8;
 await page.getByRole('button',{name:'Refresh records'}).click();
 await page.getByRole('button',{name:'Research workspace',exact:true}).click();
 await page.getByRole('button',{name:'Error investigation',exact:true}).click();
 await page.getByRole('button',{name:'Retry exact flag'}).click();
 await page.getByText(/access refused.*outcome unconfirmed/i).waitFor();
 assert.equal(await page.getByText(/Not saved/i).count(),0);
 await page.getByRole('button',{name:'Research workspace',exact:true}).click();
 await page.getByRole('button',{name:'Error investigation',exact:true}).click();
 await page.getByRole('button',{name:'Retry exact flag'}).click();
 await page.getByText(/Flag saved.*evaluation unchanged/i).waitFor();
 assert.equal(commands.length,3);
 for(const command of commands){
  assert.equal(command.body,commands[0].body);
  assert.equal(command.headers['idempotency-key'],commands[0].headers['idempotency-key']);
  assert.equal(command.headers['if-match'],'"7"');
 }
 assert.equal(flags.length,1);
 await page.getByRole('heading',{name:'Saved follow-up flags'}).waitFor();
 assert.equal(await page.getByText('authored-flag', {exact:true}).count(),1);
 await page.getByLabel('Prediction disposition').selectOption('missing');
 await page.getByRole('heading',{name:'A → Missing / failed'}).waitFor();
 await page.getByLabel('Reference label').selectOption('1');
 await page.getByText('No records in this slice',{exact:true}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Flag exact slice'}).isEnabled(),false);
 snapshot.capabilities.evaluation_flags=false;
 await page.getByRole('button',{name:'Refresh records'}).click();
 await page.getByText(/compatible backend.*flags/i).waitFor();
 assert.equal(await page.getByRole('button',{name:'Flag exact slice'}).count(),0);
 console.log(`PASS mounted AUTHOR-HTTP: committed/lost response → ${refusal} refusal → recovery/remount exact key/body/revision retry; one flag; missing/empty slices; compatibility gate`);
 console.log('Browser:',browser.version());
} finally { if(page)await page.goto('about:blank'); await browser.close(); }
