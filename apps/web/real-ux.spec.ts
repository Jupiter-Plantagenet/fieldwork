// Executable UX / BROWSER checks over the live stack (real records, no mocks, GET-only).
// NOT covered here and never claimed: human assistive-technology testing (NVDA/VoiceOver), Firefox, Safari, iOS, Android
// (user-waived). Axe-core is an additional automated WCAG check, not a substitute for those.
import { test, expect, type Page, type BrowserContext } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RUN, SCREENS, api, browserFacts, h1, login, outDir } from './real-helpers';

const channel = process.env.REAL_CHANNEL || 'msedge';
test.setTimeout(40 * 60_000);

const state: Record<string, unknown> = {};
const save = (out: string) => {
  const file = path.join(out, `real-ux-results-${channel}.json`);
  let prior: Record<string, unknown> = {};
  try { prior = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* first write */ }
  fs.writeFileSync(file, JSON.stringify({ ...prior, ...state }, null, 2));
};

async function settle(page: Page) {
  await page.waitForFunction(() => !document.querySelector('.state-loading'), undefined, { timeout: 25_000 }).catch(() => undefined);
  await page.waitForTimeout(400);
}
async function gotoScreen(page: Page, id: string, title: string) {
  const mobileSelect = page.getByRole('combobox', { name: 'Workspace screen', exact: true });
  if (await mobileSelect.isVisible()) await mobileSelect.selectOption(id);
  else await page.getByRole('navigation').getByRole('button', { name: title, exact: true }).click();
  await expect(h1(page, title)).toBeVisible();
  await settle(page);
}
const overflow = (page: Page) => page.evaluate(() => {
  const el = document.scrollingElement as HTMLElement;
  const cw = el.clientWidth;
  const offenders: string[] = [];
  document.querySelectorAll<HTMLElement>('body *').forEach(e => {
    const r = e.getBoundingClientRect();
    const cs = getComputedStyle(e);
    if (r.width && r.right > cw + 1 && cs.position !== 'fixed' && !e.closest('.tablewrap,pre,.sr-only') && offenders.length < 6)
      offenders.push(`${e.tagName.toLowerCase()}${e.className ? '.' + String(e.className).split(' ')[0] : ''} right=${Math.round(r.right)}`);
  });
  return { scrollWidth: el.scrollWidth, clientWidth: cw, ok: el.scrollWidth <= cw, offenders };
});
const targets = (page: Page) => page.evaluate(() => {
  const bad: { el: string; w: number; h: number }[] = []; let total = 0;
  document.querySelectorAll<HTMLElement>('button,a[href],input:not([type=hidden]),select,textarea,summary,[role=button],[role=link],[tabindex]:not([tabindex="-1"])').forEach(e => {
    const r = e.getBoundingClientRect();
    const cs = getComputedStyle(e);
    if (!r.width || !r.height || cs.visibility === 'hidden' || cs.display === 'none' || e.closest('.sr-only') || r.width <= 2 || r.height <= 2) return;
    // a native checkbox/radio label wrapper would count its label; none exist here.
    total++;
    if (r.height < 43.5 || (['BUTTON', 'A'].includes(e.tagName) && r.width < 43.5))
      bad.push({ el: `${e.tagName.toLowerCase()}[${(e.getAttribute('aria-label') || e.textContent || e.getAttribute('placeholder') || '').trim().slice(0, 40)}]`, w: Math.round(r.width), h: Math.round(r.height) });
  });
  return { total, bad };
});

async function newSession(browser: import('@playwright/test').Browser, opts: { width: number; height: number; dsf?: number }) {
  const context = await browser.newContext({ baseURL: 'http://127.0.0.1:5102', viewport: { width: opts.width, height: opts.height }, deviceScaleFactor: opts.dsf ?? 1 });
  await login(context);
  const page = await context.newPage();
  await page.goto('/');
  await expect(h1(page, 'Research workspace')).toBeVisible({ timeout: 30_000 });
  return { context, page };
}

test(`environment [${channel}]`, async ({ page, context }) => {
  const out = outDir();
  await login(context);
  await page.goto('/');
  Object.assign(state, { generated_utc: new Date().toISOString(), channel, os: `${os.type()} ${os.release()} (${os.version()})`, ...(await browserFacts(page)) });
  save(out);
});

test(`keyboard-only traversal and focus handling [${channel}]`, async ({ page, context }) => {
  const out = outDir();
  await login(context);
  await page.goto('/');
  await expect(h1(page, 'Research workspace')).toBeVisible({ timeout: 30_000 });
  const active = () => page.evaluate(() => {
    const e = document.activeElement as HTMLElement; const cs = getComputedStyle(e);
    return { tag: e.tagName, text: (e.textContent || '').trim().slice(0, 60), label: e.getAttribute('aria-label') || '', inNav: !!e.closest('nav'),
      visible: (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0) || cs.boxShadow !== 'none' };
  });
  const result: Record<string, unknown> = {};
  // A. Tab order through the whole nav, with a visible focus indicator on each stop.
  await page.waitForTimeout(1500);
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  const stops: { text: string; visible: boolean }[] = [];
  await page.keyboard.press('Tab');
  const first = await active();
  result.first_stop = first.text;
  for (let i = 0; i < SCREENS.length; i++) { await page.keyboard.press('Tab'); const a = await active(); stops.push({ text: a.text, visible: a.visible && a.inNav }); }
  result.nav_stops = stops;
  const orderOk = stops.every((s, i) => s.text === SCREENS[i][1]);
  const ringOk = stops.every(s => s.visible);
  result.A_nav_tab_order_matches_15_screens = orderOk; result.A_focus_indicator_visible_on_every_nav_stop = ringOk;
  expect.soft(orderOk, 'nav tab order').toBeTruthy(); expect.soft(ringOk, 'focus indicator on nav stops').toBeTruthy();

  // B. Enter on a nav button routes and moves focus to the new heading (focus restored after navigation).
  const activation: Record<string, unknown>[] = [];
  for (const title of ['Runs & workers', 'Training run', 'Workspace & access settings']) {
    await page.goto('/#overview'); await page.reload(); await expect(h1(page, 'Research workspace')).toBeVisible({ timeout: 30_000 });
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    let hit = false;
    for (let i = 0; i < 40 && !hit; i++) { await page.keyboard.press('Tab'); const a = await active(); hit = a.inNav && a.text === title; }
    expect(hit, `reached nav button ${title} by Tab`).toBeTruthy();
    await page.keyboard.press('Enter');
    await expect(h1(page, title)).toBeVisible();
    await page.waitForFunction(() => document.activeElement?.tagName === 'H1', undefined, { timeout: 3000 }).catch(() => undefined);
    const after = await page.evaluate(() => ({ tag: document.activeElement?.tagName, text: (document.activeElement?.textContent || '').trim() }));
    activation.push({ title, focus_after_enter: after, hash: new URL(page.url()).hash });
    expect.soft(after.tag, `focus moves to the heading after ${title}`).toBe('H1');
    expect.soft(after.text).toBe(title);
  }
  result.B_enter_on_nav_moves_focus_to_heading = activation;

  // C. Skip link: must keep the route and move focus into the main content.
  await page.goto('/#overview'); await page.reload(); await expect(h1(page, 'Research workspace')).toBeVisible({ timeout: 30_000 });
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.keyboard.press('Tab');
  const skip = await active();
  await page.keyboard.press('Enter');
  await page.waitForTimeout(500);
  const afterSkip = await page.evaluate(() => ({ hash: location.hash, h1: document.querySelector('h1')?.textContent, unknown: !!Array.from(document.querySelectorAll('h2')).find(h => h.textContent === 'Unknown route'),
    focus: document.activeElement?.id || document.activeElement?.tagName, inMain: !!document.activeElement?.closest('main') }));
  result.C_skip_link = { stop: skip.text, ...afterSkip };
  const skipOk = skip.text === 'Skip to research content' && afterSkip.hash === '#overview' && !afterSkip.unknown && afterSkip.inMain;
  result.C_skip_link_ok = skipOk;
  expect.soft(skipOk, `skip link keeps route and focuses main: ${JSON.stringify(afterSkip)}`).toBeTruthy();

  // D. A keyboard-only flow with real data: choose the real run by typing, activate a button, focus lands on the new heading;
  //    an in-page action (Refresh records) keeps focus on its own control.
  await page.goto('/#runs'); await page.reload(); await expect(h1(page, 'Runs & workers')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole('combobox', { name: 'Selected real run', exact: true })).toBeVisible({ timeout: 30_000 });
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  let reached = false;
  for (let i = 0; i < 90 && !reached; i++) { await page.keyboard.press('Tab'); reached = await page.evaluate(() => { const e = document.activeElement as HTMLSelectElement; return e.tagName === 'SELECT' && !!e.closest('label')?.textContent?.startsWith('Selected real run'); }); }
  expect(reached, 'Tab reaches the real-run select').toBeTruthy();
  await page.keyboard.type(RUN.slice(0, 6));
  const chosen = await page.evaluate(() => (document.activeElement as HTMLSelectElement).value);
  expect(chosen).toBe(RUN);
  await expect(page.getByRole('button', { name: 'Open real run details' })).toBeVisible({ timeout: 30_000 });
  let openReached = false;
  for (let i = 0; i < 10 && !openReached; i++) { await page.keyboard.press('Tab'); openReached = (await active()).text === 'Open real run details'; }
  expect(openReached, 'Tab reaches Open real run details').toBeTruthy();
  await page.keyboard.press('Enter');
  await expect(h1(page, 'Training run')).toBeVisible();
  await page.waitForFunction(() => document.activeElement?.tagName === 'H1', undefined, { timeout: 3000 }).catch(() => undefined);
  const afterOpen = await page.evaluate(() => document.activeElement?.tagName);
  result.D_keyboard_flow_select_run_then_open = { selected: chosen, focus_after_open: afterOpen, hash: new URL(page.url()).hash };
  expect.soft(afterOpen).toBe('H1');
  await expect(page.locator('dt:text-is("Run ID") + dd')).toHaveText(RUN, { timeout: 30_000 });
  let refreshReached = false; await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  for (let i = 0; i < 60 && !refreshReached; i++) { await page.keyboard.press('Tab'); refreshReached = (await active()).text === 'Refresh records'; }
  expect(refreshReached, 'Tab reaches Refresh records').toBeTruthy();
  await page.keyboard.press('Enter'); await page.waitForTimeout(800);
  const afterRefresh = await active();
  result.D_focus_kept_on_in_page_action = { control: 'Refresh records', focus_after: afterRefresh.text };
  expect.soft(afterRefresh.text).toBe('Refresh records');
  result.D_dialog_focus_return = 'NOT RUN: the UI has no non-destructive modal dialog; the only dialogs are native confirm() prompts on the mutating Resume / Freeze-fixture actions, which are out of bounds for this read-only run.';
  state.keyboard = result; save(out);
});

test(`reflow, zoom and target size on all 15 screens [${channel}]`, async ({ browser }) => {
  const out = outDir();
  const shots = path.join(out, 'reflow'); fs.mkdirSync(shots, { recursive: true });
  const sizes = [{ name: '320', width: 320, height: 800, dsf: 1, targets: false }, { name: 'zoom200', width: 640, height: 450, dsf: 2, targets: false }, { name: '390', width: 390, height: 844, dsf: 1, targets: true }];
  const result: Record<string, any> = {};
  for (const size of sizes) {
    const { context, page } = await newSession(browser, size);
    const rows: any[] = [];
    const row_state: Record<string, string> = {};
    for (const [id, title] of SCREENS) {
      await gotoScreen(page, id, title);
      if (['training', 'recovery', 'evaluation', 'errors'].includes(id)) {
        const sel = page.getByRole('combobox', { name: 'Selected real run', exact: true });
        await sel.selectOption(RUN); await settle(page);
        if (id === 'evaluation') await page.locator('[data-real-run-screen="evaluation"] table.matrix, [data-real-run-screen="evaluation"] [role=alert]').first().waitFor({ timeout: 150_000 }).catch(() => undefined);
        if (id === 'errors') await page.locator('[data-real-run-screen="errors"] .gallery, [data-real-run-screen="errors"] [role=alert]').first().waitFor({ timeout: 150_000 }).catch(() => undefined);
        row_state[id] = await page.locator(`[data-real-run-screen="${id}"] [role=alert]`).count() ? 'server error state shown' : 'real data rendered';
      }
      const o = await overflow(page);
      const row: any = { screen: id, title, overflow: o, real_state: row_state[id] };
      if (size.targets) row.targets = await targets(page);
      if (size.name === '320' || size.name === '390') {
        const file = path.join(shots, `${String(rows.length + 1).padStart(2, '0')}-${id}-${size.name}-${channel}.png`);
        await page.screenshot({ path: file, fullPage: true }); row.screenshot = path.relative(out, file).replaceAll('\\', '/');
      }
      rows.push(row);
    }
    result[size.name] = { viewport: { cssWidth: size.width, deviceScaleFactor: size.dsf }, screens: rows,
      all_no_page_overflow: rows.every(r => r.overflow.ok), ...(size.targets ? { all_targets_44: rows.every(r => r.targets.bad.length === 0), total_targets_checked: rows.reduce((s, r) => s + r.targets.total, 0) } : {}) };
    await context.close();
  }
  state.reflow = result; save(out);
  for (const k of ['320', 'zoom200', '390']) expect.soft(result[k].all_no_page_overflow, `no page-wide overflow at ${k}: ${JSON.stringify(result[k].screens.filter((r: any) => !r.overflow.ok).map((r: any) => [r.screen, r.overflow]))}`).toBeTruthy();
  expect.soft(result['390'].all_targets_44, `44px targets at 390: ${JSON.stringify(result['390'].screens.filter((r: any) => r.targets.bad.length).map((r: any) => [r.screen, r.targets.bad.slice(0, 5)]))}`).toBeTruthy();
});

test(`mobile cell-pair selector and matrix at 390 px [${channel}]`, async ({ browser }) => {
  const out = outDir();
  const { context, page } = await newSession(browser, { width: 390, height: 844 });
  const result: Record<string, any> = {};
  // Real run: try to render the verified real matrix (the validation read re-verifies the bundle and can be slow).
  await gotoScreen(page, 'evaluation', 'Evaluation results');
  await page.getByRole('combobox', { name: 'Selected real run', exact: true }).selectOption(RUN);
  const real = page.locator('[data-real-run-screen="evaluation"] table.matrix');
  const alert = page.locator('[data-real-run-screen="evaluation"] [role=alert]');
  await Promise.race([real.waitFor({ timeout: 150_000 }), alert.waitFor({ timeout: 150_000 })]).catch(() => undefined);
  result.real_matrix_rendered = await real.count() > 0;
  result.real_matrix_state = result.real_matrix_rendered ? 'rendered' : (await alert.count() ? `error state: ${(await alert.first().innerText()).slice(0, 160)}` : 'not rendered');
  for (const [name, loc] of [['real', real], ['fixture', page.locator('table.matrix').last()]] as const) {
    if (!(await loc.count())) { result[`${name}_matrix`] = 'absent'; continue; }
    const box = await loc.boundingBox();
    const cells = await loc.locator('button').evaluateAll(els => els.map(e => { const r = e.getBoundingClientRect(); return { w: Math.round(r.width), h: Math.round(r.height) }; }));
    result[`${name}_matrix`] = { width: box && Math.round(box.width), displayed: await loc.isVisible(), within_viewport: !!box && box.x >= 0 && box.x + box.width <= 390, cells: cells.length, min_cell: { w: Math.min(...cells.map(c => c.w)), h: Math.min(...cells.map(c => c.h)) } };
  }
  result.page_overflow_evaluation = await overflow(page);
  await page.screenshot({ path: path.join(out, `mobile-evaluation-390-${channel}.png`), fullPage: true });
  // Error investigation: the pair selectors are the mobile way to reach any cell.
  await gotoScreen(page, 'errors', 'Error investigation');
  const sels = ['Actual class', 'Disposition', 'Predicted class'];
  const real2 = page.locator('[data-real-run-screen="errors"]');
  await real2.getByRole('combobox', { name: 'Selected real run', exact: true }).selectOption(RUN);
  await expect(real2.getByRole('combobox', { name: 'Actual class', exact: true })).toBeVisible({ timeout: 150_000 }).catch(() => undefined);
  const selectors: Record<string, any> = {};
  for (const name of sels) {
    const l = real2.getByRole('combobox', { name, exact: true });
    selectors[name] = (await l.count()) ? { visible: await l.isVisible(), height: Math.round((await l.boundingBox())?.height ?? 0) } : 'absent (run evidence did not load)';
  }
  const fixSel = page.getByRole('combobox', { name: 'Reference label', exact: true });
  selectors['fixture Reference label'] = (await fixSel.count()) ? { visible: await fixSel.isVisible(), height: Math.round((await fixSel.boundingBox())?.height ?? 0) } : 'absent';
  result.error_investigation_selectors = selectors;
  result.page_overflow_errors = await overflow(page);
  await page.screenshot({ path: path.join(out, `mobile-errors-390-${channel}.png`), fullPage: true });
  state.mobile_cell_pair = result; save(out);
  await context.close();
});

test(`offline keeps unsaved text and claims nothing was saved [${channel}]`, async ({ page, context }) => {
  const out = outDir();
  await login(context);
  await page.goto('/#versions'); await page.reload();
  await expect(h1(page, 'Dataset versions')).toBeVisible({ timeout: 30_000 });
  const sel = page.getByRole('combobox', { name: 'Working version', exact: true });
  await expect(sel.locator('option').nth(1)).toBeAttached({ timeout: 30_000 });
  const versions = (await api(context, '/versions')).json.items as any[];
  const reviewed = versions.find(v => v.state === 'reviewed') || versions[0];
  await sel.selectOption(reviewed.id);
  const box = page.getByLabel('Version review reason');
  const text = 'Unsaved draft: reviewer note typed while the network is down.';
  await box.fill(text);
  await context.setOffline(true);
  const result: Record<string, any> = { selected_version: `${reviewed.id.slice(0, 8)} ${reviewed.state}` };
  // The app polls every 2.5 s; the explicit refresh makes the offline attempt deterministic. Neither is a save.
  await page.getByRole('button', { name: 'Refresh records' }).click();
  await expect(page.getByRole('alert').filter({ hasText: /Offline or service unavailable/ }).first()).toBeVisible({ timeout: 30_000 });
  result.offline_banner = (await page.getByRole('alert').filter({ hasText: /Offline or service unavailable/ }).first().innerText()).slice(0, 140);
  result.text_retained_offline = (await box.inputValue()) === text;
  const statusText = (await page.locator('[role=status]').allInnerTexts()).join(' | ');
  result.status_regions_offline = statusText;
  result.claims_saved_while_offline = /(^|\W)(saved|recorded|queued|submitted|created)(\W|$)/i.test(statusText);
  expect.soft(result.text_retained_offline).toBeTruthy();
  expect.soft(result.claims_saved_while_offline).toBeFalsy();
  // A real server-side read-only action while offline must fail honestly (no stale 'saved' message appears).
  await context.setOffline(false);
  await expect(page.getByRole('alert').filter({ hasText: /Offline or service unavailable/ })).toHaveCount(0, { timeout: 30_000 });
  result.text_retained_after_reconnect = (await box.inputValue()) === text;
  expect.soft(result.text_retained_after_reconnect).toBeTruthy();
  // Server state untouched: the version is exactly as before (nothing was saved by this test).
  const after = (await api(context, '/versions')).json.items as any[];
  const same = JSON.stringify(after.find(v => v.id === reviewed.id)) === JSON.stringify(reviewed);
  result.server_version_unchanged = same;
  expect.soft(same).toBeTruthy();
  state.offline = result; save(out);
});

test(`axe-core WCAG 2.2 AA automated scan, all 15 screens, desktop [${channel}]`, async ({ page, context }) => {
  const out = outDir();
  await login(context);
  await page.goto('/');
  await expect(h1(page, 'Research workspace')).toBeVisible({ timeout: 30_000 });
  const axeSource = fs.readFileSync('test-vendor/axe-core-4.10.3/axe.min.js', 'utf8');
  const rows: any[] = [];
  for (const [id, title] of SCREENS) {
    await gotoScreen(page, id, title);
    if (['training', 'recovery'].includes(id)) { await page.getByRole('combobox', { name: 'Selected real run', exact: true }).selectOption(RUN); await settle(page); }
    await page.evaluate(axeSource);
    const r = await page.evaluate(async () => {
      const res = await (window as any).axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] } });
      return { violations: res.violations.map((v: any) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length, sample: v.nodes.slice(0, 3).map((n: any) => n.target.join(' ')) })), passes: res.passes.length, incomplete: res.incomplete.length };
    });
    rows.push({ screen: id, ...r });
  }
  state.axe = { version: '4.10.3', tags: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'], note: 'automated checks only; cannot establish WCAG conformance', screens: rows,
    total_violation_instances: rows.reduce((s, r) => s + r.violations.reduce((a: number, v: any) => a + v.nodes, 0), 0) };
  save(out);
});
