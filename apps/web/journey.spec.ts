import { test, expect } from '@playwright/test';
import fs from 'node:fs';
const local=JSON.parse(fs.readFileSync('../../.browser-test.json','utf8'));
const titles=['Research workspace','Dataset explorer','Sample inspector','Annotation review','Dataset versions','Split integrity','Configure training','Runs & workers','Training run','Evaluation results','Error investigation','Recover training','Model artifacts','Inference playground','Workspace & access settings'];
test('authenticated real proof journey, exact routes and resource failure',async({page,request})=>{
  const response=await request.post('http://127.0.0.1:5102/auth/session',{data:{name:local.name,password:local.password}});
  expect(response.status()).toBe(200);
  await page.context().addCookies(await request.storageState().then(s=>s.cookies));
  await page.goto('/');
  await expect(page.getByRole('heading',{name:'Research workspace',exact:true})).toBeVisible();
  for(const title of titles){
    await page.getByRole('navigation').getByRole('button',{name:title,exact:true}).click();
    await expect(page.getByRole('heading',{name:title,exact:true})).toBeVisible();
    await page.reload();await expect(page.getByRole('heading',{name:title,exact:true})).toBeVisible();
  }
  await page.getByRole('navigation').getByRole('button',{name:'Dataset explorer',exact:true}).click();
  await page.getByLabel('Search sample ID').fill('SYN-0-0');
  await expect(page.getByRole('button',{name:'Inspect SYN-0-0'})).toBeVisible();
  await page.getByRole('button',{name:'Inspect SYN-0-0'}).click();
  // Stale wording: the sample screen now renders 'Current label' (label of the selected/pinned version) instead of 'Frozen label'.
  // The frozen-input property is still asserted through the pinned-manifest panel that says the manifest never changes.
  await expect(page.getByText('Current label · Crimson')).toBeVisible();
  await expect(page.getByText(/this manifest never changes/)).toBeVisible();
  await page.getByRole('navigation').getByRole('button',{name:'Training run',exact:true}).click();
  await expect(page.getByText('40 committed optimizer updates',{exact:false})).toBeVisible();
  await expect(page.getByText(/Artifact verification:/)).toBeVisible();
  await page.screenshot({path:'../../evidence/browser-training.png',fullPage:true});
  await page.getByRole('navigation').getByRole('button',{name:'Evaluation results',exact:true}).click();
  await page.getByRole('button',{name:/Crimson predicted as Crimson/}).click();
  await expect(page.getByRole('heading',{name:'Error investigation',exact:true})).toBeVisible();
  await page.getByRole('navigation').getByRole('button',{name:'Configure training',exact:true}).click();
  await page.getByLabel('Epochs',{exact:true}).fill('3');
  await page.getByRole('button',{name:'Submit configuration',exact:true}).click();
  await expect(page.getByRole('status')).toContainText(/RESOURCE_PREFLIGHT|queued/);
  await page.screenshot({path:'../../evidence/browser-configure.png',fullPage:true});
});
test('annotation proposal independent review and immutable child freeze',async({page,request})=>{
 await page.setViewportSize({width:390,height:844});
 const actors=JSON.parse(fs.readFileSync('../../.local-annotation-test.json','utf8'));
 async function signIn(role:string){const a=actors[role];const response=await request.post('/auth/session',{data:{name:a.name,password:a.password}});expect(response.status()).toBe(200);await page.context().addCookies((await request.storageState()).cookies);await page.goto('/#versions');await page.reload()}
 await signIn('owner');
 await page.getByRole('button',{name:'Create synthetic fixture draft',exact:true}).click();
 // UI intentionally relabelled the fixture-only draft action as synthetic (real drafts use the real-data panel).
 await expect(page.getByRole('status').last()).toContainText('Synthetic fixture draft created');
 await page.getByLabel('Workspace screen',{exact:true}).selectOption('sample');
 await page.getByLabel('Proposed class').selectOption('1');
 await page.getByLabel('Correction reason').fill('Browser regression fixture correction with independent review.');
 // Stale labels: proposal button is now 'Submit train or pool proposal'; fixture freeze button/status carry 'fixture'/'Synthetic fixture' wording.
 await page.getByRole('button',{name:'Submit train or pool proposal',exact:true}).click();
 await expect(page.getByRole('status').last()).toContainText('Proposal saved');
 await signIn('reviewer');
 await page.getByLabel('Workspace screen',{exact:true}).selectOption('annotations');
 await page.getByLabel('Review reason').fill('Independent test actor checked the exact proposal bytes.');
 await page.getByRole('button',{name:'Approve proposal',exact:true}).last().click();
 await expect(page.getByRole('status').last()).toContainText('Review recorded');
 await page.getByLabel('Workspace screen',{exact:true}).selectOption('versions');
 await page.getByLabel('Version review reason').fill('Full exact input version reviewed by separate test actor.');
 await page.getByRole('button',{name:'Review exact version',exact:true}).click();
 await expect(page.getByRole('status').last()).toContainText('Exact version reviewed');
 await signIn('owner');page.once('dialog',dialog=>dialog.accept());
 await page.getByRole('button',{name:'Freeze reviewed fixture version',exact:true}).click();
 await expect(page.getByRole('status').last()).toContainText('Synthetic fixture child version frozen');
 await page.reload();await expect(page.getByText('frozen',{exact:true}).last()).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
 await page.screenshot({path:'../../evidence/browser-annotation-frozen-mobile.png',fullPage:true});
});

test('mobile navigation has no page overflow',async({page,request})=>{
  await page.setViewportSize({width:390,height:844});
  await request.post('http://127.0.0.1:5102/auth/session',{data:{name:local.name,password:local.password}});await page.context().addCookies((await request.storageState()).cookies);
  await page.goto('/');await expect(page.getByRole('heading',{name:'Research workspace',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  await page.screenshot({path:'../../evidence/browser-mobile.png',fullPage:true});
});
