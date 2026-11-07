// Mounted production App; delayed authored HTTP, not DB/auth/model evidence.
import { chromium } from 'playwright';
import assert from 'node:assert/strict';
const browser=await chromium.launch({channel:'msedge',headless:true});
const page=await browser.newPage();page.setDefaultTimeout(5000);
const hash='a'.repeat(64), user={name:'author',workspace:'lab',role:'researcher',csrf:'author-only'};
const snapshot={capabilities:{evaluation_flags:true,revisioned_cancel:true},...user,scope:'AUTHOR-HTTP',classes:['A','B'],dataset_digest:hash,samples:[],counts:{train:0,validation:2,holdout:0},runs:['run-a','run-b'].map(id=>({id,state:'succeeded',epoch:1,revision:7,fence:1,attempt:'a',config:{epochs:1,seed:1},result:null})),rights:'No clearance claim',release:'blocked',preflight:{free_ram_bytes:0,free_disk_bytes:0,environment:'AUTHOR-HTTP'},worker:null};
let releaseA;const gate=new Promise(resolve=>releaseA=resolve);
let seen=0,readyA;const ready=new Promise(resolve=>readyA=resolve);
const metrics=n=>({n,ok:n,accuracy:1,coverage:1,matrix:[[n,0],[0,0]],cells:{'0:0':[]},missing:[],support:[n,0],f1:[1,null],recall:[1,null],macro_f1:1,cross_entropy:0,status:'complete'});
try{
 await page.route('**/auth/session',r=>r.fulfill({json:user}));
 await page.route('**/api/**',async route=>{
  const path=new URL(route.request().url()).pathname;let value;
  if(path.endsWith('/snapshot'))value=snapshot;
  else if(path.endsWith('/evaluation')||path.endsWith('/artifacts')){
   const a=path.includes('/run-a/');if(a){seen++;if(seen===2)readyA();await gate;}
   value=path.endsWith('/evaluation')?{metrics:metrics(a?1:2),population:[],independent:metrics(a?1:2)}:{manifest:{files:{[a?'A-only.json':'B-only.json']:{}}},receipt:null};
  }else if(path.endsWith('/flags'))value={items:[]};
  else if(path.endsWith('/slices'))value={sample_ids:[],total:0,membership_digest:hash,next_cursor:null,predicate:{actual:0,predicted:0,bucket:'cell'},evaluation_digest:hash};
  else{await route.fulfill({status:409,json:{code:'AUTHOR_ONLY'}});return;}
  await route.fulfill({json:value});
 });
 await page.goto('http://127.0.0.1:5102/#training');await ready;
 await page.getByLabel('Selected run').selectOption('run-b');
 await page.getByRole('button',{name:'Evaluation results',exact:true}).click();
 await page.getByRole('button',{name:'A predicted as A: 2 samples',exact:true}).waitFor();
 await page.getByRole('button',{name:'Model artifacts',exact:true}).click();
 await page.getByText('B-only.json',{exact:true}).waitFor();
 const responses=Promise.all(['evaluation','artifacts'].map(kind=>page.waitForResponse(r=>r.url().includes('/run-a/'+kind))));
 releaseA();await responses;
 // Drain actual response bodies, fetch continuations and React render frames.
 await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
 assert.equal(await page.getByText('A-only.json',{exact:true}).count(),0,'delayed A artifacts must not replace B');
 await page.getByText('B-only.json',{exact:true}).waitFor();
 await page.getByRole('button',{name:'Evaluation results',exact:true}).click();
 await page.getByRole('button',{name:'A predicted as A: 2 samples',exact:true}).waitFor();
 assert.equal(await page.getByRole('button',{name:'A predicted as A: 1 samples',exact:true}).count(),0);
 await page.getByRole('button',{name:'A predicted as A: 2 samples',exact:true}).click();
 await page.getByRole('heading',{name:'A → A',exact:true}).waitFor();
 console.log('PASS mounted App delayed A / fast B: selected-run matrix, artifacts and investigation remain B. Browser '+browser.version());
}finally{releaseA();await page.goto('about:blank');await browser.close();}
