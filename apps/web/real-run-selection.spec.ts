import { test, expect } from '@playwright/test';

const workspace = 'workspace-real-run-test';
const base = `/api/v1/workspaces/${workspace}`;
const runId = (index: number) => `real-run-${String(index).padStart(2, '0')}`;
const run = (index: number) => ({ id: runId(index), state: 'succeeded', revision: 1, epoch: 2,
  scope: 'real-training/v1', artifact_status: 'verified', cancel_generation: null, version_id: 'version-real' });
const firstPage = { items: Array.from({ length: 50 }, (_, index) => run(index)), next_cursor: 'older-page' };
const olderPage = { items: [run(50)], next_cursor: null };
const metricRows = Array.from({ length: 5 }, () => Array(5).fill(0));
metricRows[1][2] = 1;
const validation = { run_id: runId(50), scope: 'real-training/v1', split: 'validation', evidence_scope: 'validation_only',
  classes: ['A', 'B', 'C', 'D', 'E'], metrics: { n: 1, ok: 1, accuracy: 0, coverage: 1,
    matrix: metricRows, support: [0, 1, 0, 0, 0], precision: [null, 0, 0, null, null],
    recall: [null, 0, null, null, null], f1: [null, 0, null, null, null], macro_f1: 0,
    cross_entropy: 1, status: 'complete', disposition_counts: { ok: 1 },
    null_reasons: {}, cross_entropy_complete: true }, independent_metrics_match: true,
  bundle_digest: 'a'.repeat(64), evaluation_digest: 'b'.repeat(64) };

test('real run selection and confusion cell survive screen navigation beyond page one', async ({ page }) => {
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (!path.startsWith('/api/') && !path.startsWith('/auth/')) return route.continue();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (path === '/auth/session' && route.request().method() === 'GET')
      return json({ name: 'reviewer', workspace, role: 'reviewer', csrf: 'csrf-test' });
    if (path === `${base}/snapshot`) return json({ workspace, name: 'reviewer', role: 'reviewer',
      scope: 'real-rights-cleared', release: 'fieldwork:test', classes: validation.classes,
      dataset_digest: 'c'.repeat(64), samples: [], counts: {}, runs: [], rights: 'cleared',
      preflight: { free_ram_bytes: 0, free_disk_bytes: 0, environment: 'test' }, worker: null,
      capabilities: { real_runs: true, real_intake: false, revisioned_cancel: false, evaluation_flags: false } });
    if (path === `${base}/versions`) return json({ items: [] });
    if (path === `${base}/real/runs` && route.request().method() === 'GET')
      return json(url.searchParams.has('after') ? olderPage : firstPage);
    const selected = path.match(new RegExp(`^${base}/real/runs/([^/]+)$`));
    if (selected && route.request().method() === 'GET') return json({ run: run(Number(selected[1].slice(-2))) });
    const lineage = path.match(new RegExp(`^${base}/screens/runs/([^/]+)/lineage$`));
    if (lineage) return json({ run_id: lineage[1], state: 'succeeded', epoch: 2, epochs: 2, fence: 1, revision: 1,
      current_attempt: null, lease: null, attempts: [], checkpoints: [], events: [], boundaries: [],
      recovery: { resumable: false, blocked_code: 'NOT_INTERRUPTED', next_replay_epoch: null, attempt_budget: 3, attempts_used: 0 } });
    const validationRun = path.match(new RegExp(`^${base}/real/runs/([^/]+)/validation$`));
    if (validationRun) {
      const partial = validationRun[1] === runId(0);
      return json({ ...validation, run_id: validationRun[1], metrics: { ...validation.metrics,
        status: partial ? 'incomplete' : 'complete', cross_entropy_complete: !partial,
        disposition_counts: partial ? { ok: 0, inference_failed: 1 } : { ok: 1 } } });
    }
    const sliceRun = path.match(new RegExp(`^${base}/real/runs/([^/]+)/validation/slices$`));
    if (sliceRun) return json({ run_id: sliceRun[1], split: 'validation',
      bucket: 'cell', predicate: { actual: 1, predicted: 2 }, total: 0, offset: 0, limit: 24, members: [],
      next_offset: null, membership_digest: 'd'.repeat(64), evaluation_digest: validation.evaluation_digest });
    if (path === `${base}/screens/operations`) return json({ runs: [], worker: { status: 'none' }, preflight: {} });
    return json({ code: 'TEST_ROUTE_UNAVAILABLE' }, 404);
  });

  await page.goto('/#runs');
  await expect(page.getByRole('heading', { name: 'Runs & workers' })).toBeVisible();
  await page.getByRole('button', { name: 'Load more real runs' }).click();
  const picker = page.getByLabel('Selected real run');
  await expect(picker.locator('option')).toHaveCount(52);
  await picker.selectOption(runId(50));
  await expect.poll(() => picker.inputValue()).toBe(runId(50));

  await page.getByRole('navigation').getByRole('button', { name: 'Training run' }).click();
  await expect(page.getByLabel('Selected real run')).toHaveValue(runId(50));
  await page.getByRole('navigation').getByRole('button', { name: 'Evaluation results' }).click();
  await expect(page.getByText('Validation report status: complete')).toBeVisible();
  await expect(page.getByRole('table', { name: 'Validation prediction dispositions' })).toContainText('ok');
  await expect(page.getByText('Cross entropy', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'B predicted as C: 1 validation samples' }).click();
  await expect(page.getByLabel('Actual class')).toHaveValue('1');
  await expect(page.getByRole('combobox', { name: /^Predicted class/ })).toHaveValue('2');

  await page.getByLabel('Selected real run').selectOption(runId(0));
  await expect(page.getByLabel('Actual class')).toBeVisible();
  await expect(page.getByLabel('Actual class')).toHaveValue('0');
  await expect(page.getByRole('combobox', { name: /^Predicted class/ })).toHaveValue('0');
  await expect(page.getByLabel('Selected real run')).toHaveValue(runId(0));
  await page.getByRole('navigation').getByRole('button', { name: 'Evaluation results' }).click();
  await expect(page.getByText('Validation report status: incomplete')).toBeVisible();
  await expect(page.getByText('This report is partial; the displayed counts and metrics do not represent a complete prediction set.')).toBeVisible();
  await expect(page.getByRole('table', { name: 'Validation prediction dispositions' })).toContainText('inference_failed');
});

test('real-run selection is cleared across sign-out and workspace switch', async ({ page }) => {
  const workspaceA = 'workspace-principal-a', workspaceB = 'workspace-principal-b';
  const userA = { name: 'researcher-a', workspace: workspaceA, role: 'researcher', csrf: 'csrf-a' };
  const userB = { name: 'researcher-b', workspace: workspaceB, role: 'researcher', csrf: 'csrf-b' };
  let unexpectedOldWorkspaceLookup = 0;
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (!path.startsWith('/api/') && !path.startsWith('/auth/')) return route.continue();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (path === '/auth/session' && route.request().method() === 'GET') return json(userA);
    if (path === '/auth/logout' && route.request().method() === 'POST') return json({ ok: true });
    if (path === '/auth/session' && route.request().method() === 'POST') return json(userB);
    const workspaceId = path.match(/^\/api\/v1\/workspaces\/([^/]+)/)?.[1];
    if (!workspaceId) return json({ code: 'TEST_ROUTE_UNAVAILABLE' }, 404);
    const base = `/api/v1/workspaces/${workspaceId}`;
    if (path === `${base}/snapshot`) {
      const principal = workspaceId === workspaceA ? userA : userB;
      return json({ workspace: workspaceId, name: principal.name, role: principal.role, scope: 'real-rights-cleared',
        release: 'fieldwork:test', classes: ['A', 'B', 'C', 'D', 'E'], dataset_digest: 'e'.repeat(64), samples: [], counts: {}, runs: [],
        rights: 'cleared', preflight: { free_ram_bytes: 0, free_disk_bytes: 0, environment: 'test' }, worker: null,
        capabilities: { real_runs: true, real_intake: false, revisioned_cancel: false, evaluation_flags: false } });
    }
    if (path === `${base}/versions`) return json({ items: [] });
    if (path === `${base}/real/runs` && route.request().method() === 'GET')
      return json({ items: [workspaceId === workspaceA ? run(7) : { ...run(8), id: 'other-workspace-run' }], next_cursor: null });
    const selected = path.match(new RegExp(`^${base}/real/runs/([^/]+)$`));
    if (selected && route.request().method() === 'GET') {
      const expected = workspaceId === workspaceA ? run(7).id : 'other-workspace-run';
      if (selected[1] !== expected) { unexpectedOldWorkspaceLookup += 1; return json({ code: 'OBJECT' }, 404); }
      return json({ run: { ...(workspaceId === workspaceA ? run(7) : run(8)), id: expected } });
    }
    if (path === `${base}/screens/runs/${workspaceId === workspaceA ? run(7).id : 'other-workspace-run'}/lineage`)
      return json({ run_id: workspaceId === workspaceA ? run(7).id : 'other-workspace-run', state: 'succeeded', epoch: 2, epochs: 2,
        fence: 1, revision: 1, current_attempt: null, lease: null, attempts: [], checkpoints: [], events: [], boundaries: [],
        recovery: { resumable: false, blocked_code: 'NOT_INTERRUPTED', next_replay_epoch: null, attempt_budget: 3, attempts_used: 0 } });
    return json({ code: 'TEST_ROUTE_UNAVAILABLE' }, 404);
  });

  await page.goto('/#training');
  await expect(page.getByLabel('Selected real run')).toHaveValue(run(7).id);
  await page.getByRole('navigation').getByRole('button', { name: 'Workspace & access settings' }).click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Research, with a trail.' })).toBeVisible();
  await page.getByLabel('Account').fill(userB.name);
  await page.getByLabel('Password').fill('test-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Workspace & access settings' })).toBeVisible();
  await page.getByRole('navigation').getByRole('button', { name: 'Training run' }).click();
  await expect(page.getByLabel('Selected real run')).toHaveValue('other-workspace-run');
  await expect.poll(() => unexpectedOldWorkspaceLookup).toBe(0);
});

test('a late prior-session snapshot cannot overwrite the newly signed-in workspace', async ({ page }) => {
  const workspaceA = 'workspace-snapshot-old', workspaceB = 'workspace-snapshot-new';
  const userA = { name: 'old-principal', workspace: workspaceA, role: 'researcher', csrf: 'csrf-old' };
  const userB = { name: 'new-principal', workspace: workspaceB, role: 'researcher', csrf: 'csrf-new' };
  let oldSnapshotCount = 0, oldRunLookupsInNewWorkspace = 0;
  let signalOldStarted!: () => void, releaseOldSnapshot!: () => void;
  const oldStarted = new Promise<void>(resolve => { signalOldStarted = resolve; });
  const oldSnapshotGate = new Promise<void>(resolve => { releaseOldSnapshot = resolve; });
  const json = (route: import('@playwright/test').Route, body: unknown, status = 200) =>
    route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  const snapshot = (workspaceId: string, principal: typeof userA) => ({ workspace: workspaceId, name: principal.name,
    role: principal.role, scope: workspaceId === workspaceA ? 'old-session-snapshot' : 'new-session-snapshot',
    release: 'fieldwork:test', classes: ['A', 'B', 'C', 'D', 'E'], dataset_digest: 'f'.repeat(64), samples: [], counts: {}, runs: [],
    rights: 'cleared', preflight: { free_ram_bytes: 0, free_disk_bytes: 0, environment: 'test' }, worker: null,
    capabilities: { real_runs: true, real_intake: false, revisioned_cancel: false, evaluation_flags: false } });

  await page.route('**/*', async route => {
    const url = new URL(route.request().url()), path = url.pathname;
    if (!path.startsWith('/api/') && !path.startsWith('/auth/')) return route.continue();
    if (path === '/auth/session' && route.request().method() === 'GET') return json(route, userA);
    if (path === '/auth/session' && route.request().method() === 'POST') return json(route, userB);
    const workspaceId = path.match(/^\/api\/v1\/workspaces\/([^/]+)/)?.[1];
    if (!workspaceId) return json(route, { code: 'TEST_ROUTE_UNAVAILABLE' }, 404);
    const base = `/api/v1/workspaces/${workspaceId}`;
    if (path === `${base}/snapshot` && workspaceId === workspaceA) {
      oldSnapshotCount += 1;
      if (oldSnapshotCount === 1) { signalOldStarted(); await oldSnapshotGate; return json(route, snapshot(workspaceA, userA)); }
      return json(route, { code: 'SESSION_EXPIRED' }, 401);
    }
    if (path === `${base}/snapshot` && workspaceId === workspaceB) return json(route, snapshot(workspaceB, userB));
    if (path === `${base}/versions`) return json(route, { items: [] });
    if (path === `${base}/real/runs` && route.request().method() === 'GET')
      return json(route, { items: [{ ...run(9), id: 'new-workspace-run' }], next_cursor: null });
    const detail = path.match(new RegExp(`^${base}/real/runs/([^/]+)$`));
    if (detail && route.request().method() === 'GET') {
      if (workspaceId !== workspaceB || detail[1] !== 'new-workspace-run') {
        oldRunLookupsInNewWorkspace += 1; return json(route, { code: 'OBJECT' }, 404);
      }
      return json(route, { run: { ...run(9), id: 'new-workspace-run' } });
    }
    if (path === `${base}/screens/runs/new-workspace-run/lineage`) return json(route, {
      run_id: 'new-workspace-run', state: 'succeeded', epoch: 2, epochs: 2, fence: 1, revision: 1,
      current_attempt: null, lease: null, attempts: [], checkpoints: [], events: [], boundaries: [],
      recovery: { resumable: false, blocked_code: 'NOT_INTERRUPTED', next_replay_epoch: null, attempt_budget: 3, attempts_used: 0 } });
    return json(route, { code: 'TEST_ROUTE_UNAVAILABLE' }, 404);
  });

  await page.goto('/#training');
  await oldStarted;
  await page.getByRole('button', { name: 'Refresh records' }).click();
  await expect(page.getByRole('heading', { name: 'Research, with a trail.' })).toBeVisible();
  await page.getByLabel('Account').fill(userB.name);
  await page.getByLabel('Password').fill('test-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByLabel('Selected real run')).toHaveValue('new-workspace-run');
  releaseOldSnapshot();
  await expect(page.getByLabel('Selected real run')).toHaveValue('new-workspace-run');
  await expect(page.locator('.banner')).toContainText('new-session-snapshot');
  await expect.poll(() => oldRunLookupsInNewWorkspace).toBe(0);
});

test('a CSRF-only session change remounts real-run state before loading the new list', async ({ page }) => {
  const principal = { name: 'same-principal', workspace: 'workspace-same-principal', role: 'researcher', csrf: 'csrf-v1' };
  const nextSession = { ...principal, csrf: 'csrf-v2' };
  let postLogin = false, holdNewList = false, signalNewList!: () => void, releaseNewList!: () => void;
  const newListStarted = new Promise<void>(resolve => { signalNewList = resolve; });
  const newListGate = new Promise<void>(resolve => { releaseNewList = resolve; });
  const json = (route: import('@playwright/test').Route, body: unknown) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/*', async route => {
    const url = new URL(route.request().url()), path = url.pathname;
    if (!path.startsWith('/api/') && !path.startsWith('/auth/')) return route.continue();
    if (path === '/auth/session' && route.request().method() === 'GET') return json(route, principal);
    if (path === '/auth/logout' && route.request().method() === 'POST') return json(route, { ok: true });
    if (path === '/auth/session' && route.request().method() === 'POST') { postLogin = true; return json(route, nextSession); }
    const workspaceId = path.match(/^\/api\/v1\/workspaces\/([^/]+)/)?.[1];
    if (!workspaceId) return route.fulfill({ status: 404, contentType: 'application/json', body: '{"code":"TEST_ROUTE_UNAVAILABLE"}' });
    const base = `/api/v1/workspaces/${workspaceId}`;
    if (path === `${base}/snapshot`) return json(route, { workspace: workspaceId, name: principal.name, role: principal.role,
      scope: 'real-rights-cleared', release: 'fieldwork:test', classes: ['A','B','C','D','E'], dataset_digest: '1'.repeat(64),
      samples: [], counts: {}, runs: [], rights: 'cleared', preflight: { free_ram_bytes: 0, free_disk_bytes: 0, environment: 'test' },
      worker: null, capabilities: { real_runs: true, real_intake: false, revisioned_cancel: false, evaluation_flags: false } });
    if (path === `${base}/versions`) return json(route, { items: [] });
    if (path === `${base}/real/runs` && route.request().method() === 'GET') {
      if (postLogin && holdNewList) { signalNewList(); await newListGate; }
      return json(route, { items: [{ ...run(10), id: postLogin ? 'new-session-run' : 'old-session-run' }], next_cursor: null });
    }
    const detail = path.match(new RegExp(`^${base}/real/runs/([^/]+)$`));
    if (detail && route.request().method() === 'GET') return json(route, { run: { ...run(10), id: detail[1] } });
    if (path.includes('/screens/runs/') && path.endsWith('/lineage')) return json(route, {
      run_id: path.split('/').at(-2), state: 'succeeded', epoch: 2, epochs: 2, fence: 1, revision: 1,
      current_attempt: null, lease: null, attempts: [], checkpoints: [], events: [], boundaries: [],
      recovery: { resumable: false, blocked_code: 'NOT_INTERRUPTED', next_replay_epoch: null, attempt_budget: 3, attempts_used: 0 } });
    return route.fulfill({ status: 404, contentType: 'application/json', body: '{"code":"TEST_ROUTE_UNAVAILABLE"}' });
  });

  await page.goto('/#training');
  await expect(page.getByLabel('Selected real run')).toHaveValue('old-session-run');
  await page.getByRole('navigation').getByRole('button', { name: 'Workspace & access settings' }).click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  holdNewList = true;
  await page.getByLabel('Account').fill(nextSession.name);
  await page.getByLabel('Password').fill('test-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await newListStarted;
  await page.getByRole('navigation').getByRole('button', { name: 'Training run' }).click();
  const picker = page.getByLabel('Selected real run');
  await expect(picker.locator('option')).toHaveCount(1);
  await expect(picker).toHaveValue('');
  releaseNewList();
  await expect(picker).toHaveValue('new-session-run');
});
