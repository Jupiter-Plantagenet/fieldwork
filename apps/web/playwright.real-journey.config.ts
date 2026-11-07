import { defineConfig } from '@playwright/test';
// Real-record journey + executable UX/BROWSER checks. Live API/UI only (no mocks).
// REAL_OUT must be a NEW directory under docs/evidence-browser-real-20261103/ (nothing existing is overwritten).
// REAL_CHANNEL: 'msedge' (default) or 'chrome'. REAL_SPEC: 'real-journey' (default) or 'real-ux'.
const out = process.env.REAL_OUT;
if (!out) throw new Error('REAL_OUT (new, empty output directory) is required');
const channel = process.env.REAL_CHANNEL || 'msedge';
const spec = process.env.REAL_SPEC || 'real-journey';
export default defineConfig({
  testDir: '.', testMatch: `${spec}.spec.ts`, workers: 1, timeout: 30 * 60_000, fullyParallel: false,
  outputDir: `${out}/test-results`,
  use: { baseURL: 'http://127.0.0.1:5102', headless: true, channel, trace: 'off', viewport: { width: 1360, height: 900 }, actionTimeout: 30_000 } as any,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['json', { outputFile: `${out}/playwright-results-${spec}-${channel}.json` }]],
});
