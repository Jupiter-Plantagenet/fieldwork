// ML-T-CAPACITY browser leg: one loaded page measured while the load driver and a real training job run.
// Records Event Timing interaction durations (input -> next paint) and long tasks (>=50 ms) inside the page.
import { test, expect } from '@playwright/test';
import fs from 'node:fs';
const local = JSON.parse(fs.readFileSync('../../.browser-test.json', 'utf8'));
const titles = ['Research workspace','Dataset explorer','Sample inspector','Annotation review','Dataset versions','Split integrity','Configure training','Runs & workers','Training run','Evaluation results','Error investigation','Recover training','Model artifacts','Inference playground','Workspace & access settings'];
const SECONDS = Number(process.env.CAP_SECONDS || 840);
const OUT = process.env.CAP_OUT || '../../.local/real-data/capacity-browser.json';

test('loaded page interaction latency and long tasks', async ({ page, request }) => {
  test.setTimeout((SECONDS + 120) * 1000);
  const response = await request.post('http://127.0.0.1:5102/auth/session', { data: { name: local.name, password: local.password } });
  expect(response.status()).toBe(200);
  await page.context().addCookies((await request.storageState()).cookies);
  await page.addInitScript(() => {
    const w = window as any;
    w.__cap = { interactions: [], longtasks: [] };
    new PerformanceObserver(list => {
      for (const e of list.getEntries() as any[]) if (e.interactionId) w.__cap.interactions.push({ name: e.name, duration: e.duration, processing: e.processingEnd - e.processingStart });
    }).observe({ type: 'event', durationThreshold: 16, buffered: true } as any);
    new PerformanceObserver(list => {
      for (const e of list.getEntries()) w.__cap.longtasks.push({ duration: e.duration, start: e.startTime });
    }).observe({ type: 'longtask', buffered: true } as any);
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Research workspace', exact: true })).toBeVisible();
  const clickToHeading: { title: string; ms: number }[] = [];
  const t0 = Date.now();
  let i = 0;
  while (Date.now() - t0 < SECONDS * 1000) {
    const title = titles[i++ % titles.length];
    const started = Date.now();
    await page.getByRole('navigation').getByRole('button', { name: title, exact: true }).click();
    await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible({ timeout: 15000 });
    clickToHeading.push({ title, ms: Date.now() - started });
    if (i % 5 === 0) { await page.keyboard.press('Tab'); await page.keyboard.press('Tab'); } // keyboard interactions too
    await page.waitForTimeout(1500); // think time; the page is otherwise idle and polling
  }
  const cap = await page.evaluate(() => (window as any).__cap);
  const pct = (xs: number[], q: number) => { const s = [...xs].sort((a, b) => a - b); return s.length ? s[Math.max(0, Math.ceil(q * s.length) - 1)] : null; };
  const durations = cap.interactions.map((x: any) => x.duration);
  const report = {
    schema: 'fieldwork.capacity-browser/v1', browser: 'msedge (Playwright channel), Vite dev server on 5102', seconds: SECONDS,
    navigations: clickToHeading.length,
    interaction_event_timing: { count: durations.length, p50_ms: pct(durations, .5), p95_ms: pct(durations, .95), max_ms: pct(durations, 1) },
    click_to_heading_ms: { p50: pct(clickToHeading.map(x => x.ms), .5), p95: pct(clickToHeading.map(x => x.ms), .95), max: pct(clickToHeading.map(x => x.ms), 1),
      note: 'includes Playwright actionability checks and network fetch of the screen; reported separately from Event Timing' },
    long_tasks: { count: cap.longtasks.length, max_ms: cap.longtasks.reduce((m: number, x: any) => Math.max(m, x.duration), 0),
      over_100ms: cap.longtasks.filter((x: any) => x.duration > 100).length },
    samples: { interactions: cap.interactions.slice(0, 400), longtasks: cap.longtasks.slice(0, 400), clickToHeading },
  };
  fs.writeFileSync(OUT, JSON.stringify(report, null, 1));
  console.log(JSON.stringify({ ...report, samples: undefined }));
});
