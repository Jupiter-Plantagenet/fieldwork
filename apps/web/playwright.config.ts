import { defineConfig } from '@playwright/test';
export default defineConfig({testDir:'.',testMatch:['journey.spec.ts','real-run-selection.spec.ts'],workers:1,timeout:60000,use:{baseURL:'http://127.0.0.1:5102',headless:true,channel:'msedge',trace:'off'},reporter:[['list'],['json',{outputFile:'../../evidence/browser-results.json'}]]});
