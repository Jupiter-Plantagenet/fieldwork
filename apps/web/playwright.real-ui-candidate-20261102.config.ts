import { defineConfig } from '@playwright/test';

// Simulated API regression data; real browser and application source.
// All output is a fresh private run, never the existing release evidence.
const out = 'C:/Users/user/portfolio-build/fieldwork/.local/real-ui-browser-20261102T0708Z';
export default defineConfig({
  testDir: '.', testMatch: 'real-run-selection.spec.ts', workers: 1,
  timeout: 60000, outputDir: `${out}/test-results`,
  use: { baseURL: 'http://127.0.0.1:15102', headless: true, channel: 'msedge', trace: 'off' },
  webServer: {
    command: 'node node_modules/vite/bin/vite.js --host 127.0.0.1 --port 15102 --strictPort',
    url: 'http://127.0.0.1:15102', reuseExistingServer: false, timeout: 30000,
  },
  reporter: [['list'], ['json', { outputFile: `${out}/results.json` }]],
});
