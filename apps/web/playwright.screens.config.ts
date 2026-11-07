import { defineConfig } from '@playwright/test';
// Round-5 screen audit. P5UI_OUT must be a fresh directory; nothing is written to evidence/.
const out=process.env.P5UI_OUT;
if(!out)throw new Error('P5UI_OUT (new, empty output directory) is required');
export default defineConfig({testDir:'.',testMatch:'screens-round5.spec.ts',workers:1,timeout:90000,outputDir:`${out}/test-results`,
 use:{baseURL:'http://127.0.0.1:5102',headless:true,channel:'msedge',trace:'off',viewport:{width:1360,height:900}},
 reporter:[['list'],['json',{outputFile:`${out}/playwright-results.json`}]]});
