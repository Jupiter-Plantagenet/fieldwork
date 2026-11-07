// Authenticated 15-screen browser journey over REAL records (workspace 814830e3…, succeeded real run 52374741…).
// Live API only: no page.route fulfilment, no mocks. READ-ONLY: nothing is submitted, cancelled, resumed, frozen, drafted,
// uploaded, saved or downloaded. Every real-data fact asserted on screen is fetched independently from the API in the same test.
import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RUN, REPLAYED_RUN, REAL_VERSION, SCREENS, Recorder, api, bundleDir, browserFacts, canonicalDigest, h1, login, nav, outDir, settled, short } from './real-helpers';

const channel = process.env.REAL_CHANNEL || 'msedge';
const fixed = (v: number | null | undefined, d: number) => typeof v === 'number' && Number.isFinite(v) ? v.toFixed(d) : 'undefined';
const dd = (page: import('@playwright/test').Page, label: string) => page.locator(`dt:text-is("${label}") + dd`).first();

test.setTimeout(30 * 60_000);

test(`real-record journey over all 15 screens [${channel}]`, async ({ page, context }) => {
  const out = outDir();
  const shots = path.join(out, 'screens');
  fs.mkdirSync(shots, { recursive: true });
  const rec = new Recorder();
  const per: Record<string, { title: string; route: string; nav_ok: boolean; reload_ok: boolean; screenshot: string; assertions: string[] }> = {};
  const who = await login(context);
  const meta = { generated_utc: new Date().toISOString(), channel, os: `${os.type()} ${os.release()} (${os.version()})`, actor_role: who.role };
  await page.goto('/');
  await expect(h1(page, 'Research workspace')).toBeVisible({ timeout: 30_000 });
  const bf = await browserFacts(page);

  // Independent API baseline (GET only).
  const snap = (await api(context, '/snapshot')).json;
  const versions = (await api(context, '/versions')).json.items as any[];
  const real = versions.find(v => v.id === REAL_VERSION);
  const run = (await api(context, `/real/runs/${RUN}`)).json.run;
  const lineage = (await api(context, `/screens/runs/${RUN}/lineage`)).json;
  const classes: string[] = real.manifest.classes;
  const validationReply = await api(context, `/real/runs/${RUN}/validation`, 6);
  const validation = validationReply.status === 200 ? validationReply.json : null;
  const preds = fs.readFileSync(path.join(bundleDir(), 'evaluation/predictions.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  const diskMetrics = JSON.parse(fs.readFileSync(path.join(bundleDir(), 'evaluation/metrics.json'), 'utf8'));

  const start = (id: string, title: string) => { per[id] = { title, route: `/#${id}`, nav_ok: false, reload_ok: false, screenshot: '', assertions: per[id]?.assertions ?? [] }; };
  const note = (id: string, name: string) => per[id].assertions.push(name);
  const check = async (id: string, name: string, fn: () => Promise<{ expected?: unknown; observed?: unknown } | void>) => { note(id, name); await rec.check(id, name, fn); };
  const snapShot = async (id: string, idx: number) => {
    const file = path.join(shots, `${String(idx + 1).padStart(2, '0')}-${id}-${channel}.png`);
    await page.screenshot({ path: file, fullPage: true });
    per[id].screenshot = path.relative(out, file).replaceAll('\\', '/');
  };
  const pickRun = async (id: string, runId: string, label = 'Selected real run') => {
    await page.getByRole('combobox', { name: label, exact: true }).selectOption(runId);
  };
  const ops = async () => (await api(context, '/screens/operations')).json;
  let cellPair: number[] = [0, 0];
  let cellClick: any = null;
  const uiRetries: Record<string, number> = {};
  const snapErrors = async (name: string) => { await page.screenshot({ path: path.join(shots, name), fullPage: true }); };

  for (const [idx, [id, title]] of SCREENS.entries()) {
    start(id, title);
    // ---- visit by navigation
    await nav(page, title).click();
    await expect(h1(page, title)).toBeVisible();
    per[id].nav_ok = true;
    await check(id, 'URL hash is the exact route', async () => { expect(new URL(page.url()).hash).toBe(`#${id}`); return { expected: `#${id}`, observed: new URL(page.url()).hash }; });

    if (['training', 'evaluation', 'errors', 'recovery'].includes(id)) {
      const sel = page.getByRole('combobox', { name: 'Selected real run', exact: true });
      await expect(sel.locator(`option[value="${RUN}"]`)).toBeAttached({ timeout: 30_000 });
      if ((await sel.inputValue()) !== RUN) await sel.selectOption(RUN);
    }

    if (id === 'overview') {
      await check(id, 'worker heartbeat status and queue length equal GET /screens/operations', async () => settled(async () => {
        const o = await ops();
        await expect(page.locator('[data-worker-status]').first()).toHaveAttribute('data-worker-status', o.worker.status, { timeout: 20_000 });
        await expect(dd(page, 'Queue length')).toHaveText(String(o.queue_length));
        return { expected: { status: o.worker.status, queue: o.queue_length }, observed: 'matched' };
      }));
      await check(id, 'resource preflight admitted/blocked equals API', async () => settled(async () => {
        const o = await ops();
        await expect(page.locator('[data-preflight]').first()).toHaveAttribute('data-preflight', o.preflight.admitted ? 'admitted' : 'blocked');
        if (!o.preflight.admitted) await expect(page.locator('[data-preflight="blocked"]').first()).toContainText(o.preflight.code);
        return { expected: o.preflight.admitted ? 'admitted' : `blocked ${o.preflight.code}`, observed: 'matched' };
      }));
      await check(id, 'manifest image counter equals snapshot counts; persisted versions equals GET /versions', async () => {
        const total = Object.values(snap.counts as Record<string, number>).reduce((a, b) => a + b, 0);
        const stat = (t: string) => page.locator('[data-screen-data="overview-counters"] .stats > div').filter({ hasText: t }).locator('b');
        await expect(stat('manifest images')).toHaveText(String(total));
        await expect(stat('persisted versions')).toHaveText(String(versions.length));
        return { expected: { manifest_images: total, versions: versions.length }, observed: 'matched' };
      });
      await check(id, 'every interruption record from GET /screens/operations is shown with its event number and committed epoch', async () => {
        const o = await ops();
        expect(o.interruptions.length).toBeGreaterThan(0);
        for (const i of o.interruptions) {
          const li = page.locator('li').filter({ hasText: `Run ${short(i.run)} became ${i.state} at event ${i.seq}` });
          await expect(li).toContainText(`after committed epoch ${i.committed_epoch ?? 0}`);
          if (i.replay_epoch) await expect(li).toContainText(`replay of epoch ${i.replay_epoch}`);
        }
        return { expected: o.interruptions.map((i: any) => `${short(i.run)}@${i.seq}`), observed: 'all shown' };
      });
    }

    if (id === 'dataset') {
      await page.getByRole('combobox', { name: 'Dataset version', exact: true }).selectOption(REAL_VERSION);
      const n = real.manifest.samples.length, holdout = snap.counts.holdout || 0;
      await check(id, `real frozen version ${short(REAL_VERSION)} shows every manifest sample (API ${n}, sealed counter from snapshot ${holdout})`, async () => {
        await expect(page.locator('[data-count="samples"]')).toHaveText(`${n} permitted samples · ${holdout} sealed`, { timeout: 30_000 });
        return { expected: n, observed: n };
      });
      await page.getByRole('combobox', { name: 'Filter split', exact: true }).selectOption('validation');
      const val = real.manifest.samples.filter((s: any) => s.split === 'validation');
      await check(id, 'validation split filter count equals manifest validation members (API)', async () => {
        await expect(page.locator('[data-count="samples"]')).toHaveText(`${val.length} permitted samples · ${holdout} sealed`);
        return { expected: val.length, observed: val.length };
      });
      await page.getByRole('combobox', { name: 'Filter label', exact: true }).selectOption('0');
      const v0 = val.filter((s: any) => s.label === 0);
      await check(id, `validation + ${classes[0]} filter count equals API (${v0.length})`, async () => {
        await expect(page.locator('[data-count="samples"]')).toHaveText(`${v0.length} permitted samples · ${holdout} sealed`);
        return { expected: v0.length, observed: v0.length };
      });
      await check(id, 'real intake panel reflects GET /real/intakes and the archive queue control stays disabled (no upload performed)', async () => {
        const intakes = (await api(context, '/real/intakes')).json.items as any[];
        await expect(page.getByRole('heading', { name: 'Rights-cleared data intake' })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Queue archive' })).toBeDisabled();
        if (!intakes.length) await expect(page.locator('[role=status][data-state]').filter({ hasText: /^Intake/ })).toHaveCount(0);
        return { expected: `intakes=${intakes.length}`, observed: 'matched' };
      });
    }

    if (id === 'sample') {
      const first = real.manifest.samples.filter((s: any) => s.split === 'validation' && s.label === 0)[0];
      // Reach the real sample the way a user does: Dataset explorer (filters kept) -> Inspect card.
      await nav(page, 'Dataset explorer').click();
      await page.getByRole('combobox', { name: 'Dataset version', exact: true }).selectOption(REAL_VERSION);
      await page.getByRole('combobox', { name: 'Filter split', exact: true }).selectOption('validation');
      await page.getByRole('combobox', { name: 'Filter label', exact: true }).selectOption('0');
      await page.getByRole('button', { name: `Inspect ${first.id}` }).click();
      await expect(h1(page, title)).toBeVisible();
      await check(id, 'sample id, current label, split, group and hashes equal the manifest entry (API)', async () => {
        await expect(page.getByRole('heading', { level: 2, name: first.id, exact: true })).toBeVisible();
        await expect(page.getByText(`Current label · ${classes[first.label]}`, { exact: true })).toBeVisible();
        await expect(dd(page, 'Split')).toHaveText(first.split);
        await expect(dd(page, 'Group')).toHaveText(first.group);
        await expect(dd(page, 'Scope')).toHaveText('real-rights-cleared');
        await expect(dd(page, 'Raw SHA256')).toHaveText(first.sha256);
        await expect(dd(page, 'Pixels SHA256')).toHaveText(first.pixel_sha256);
        return { expected: { id: first.id, label: classes[first.label], split: first.split }, observed: 'matched' };
      });
      await check(id, 'rights-gated real media loads (decoded image, naturalWidth>0)', async () => {
        const img = page.locator(`img[alt="Sample ${first.id}"]`);
        await expect.poll(async () => img.evaluate((el: HTMLImageElement) => el.complete ? el.naturalWidth : 0), { timeout: 120_000 }).toBeGreaterThan(0);
      });
    }

    if (id === 'annotations' || id === 'versions') {
      if (id === 'versions') {
        await check(id, 'persisted versions table has one row per GET /versions item with state, revision and digest', async () => {
          const rows = page.getByRole('table', { name: 'Persisted versions' }).locator('tbody tr');
          await expect(rows).toHaveCount(versions.length);
          for (const v of versions) {
            const row = rows.filter({ hasText: short(v.id) });
            await expect(row).toContainText(v.digest);
            await expect(row).toContainText(String(v.revision));
            await expect(row).toContainText(v.reviewer || 'not reviewed');
          }
          return { expected: versions.map((v: any) => `${short(v.id)}:${v.state}:r${v.revision}`), observed: 'matched' };
        });
      }
      await page.getByRole('combobox', { name: 'Working version', exact: true }).selectOption(REAL_VERSION);
      await check(id, `selected real version shows state/revision/digest/parent/reviewer equal to API`, async () => {
        await expect(dd(page, 'State')).toHaveText(real.state);
        await expect(dd(page, 'Revision')).toHaveText(String(real.revision));
        await expect(dd(page, 'Exact digest')).toHaveText(real.digest);
        await expect(dd(page, 'Parent digest')).toHaveText(real.parent_digest);
        await expect(dd(page, 'Independent reviewer')).toHaveText(real.reviewer);
        return { expected: { state: real.state, revision: real.revision, reviewer: real.reviewer }, observed: 'matched' };
      });
      if (id === 'annotations') await check(id, 'proposal history equals API proposal count (no pending proposals shown, no review action possible)', async () => {
        expect(real.proposals.length).toBe(0);
        await expect(page.getByText('No pending proposals for this version.')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Approve proposal' })).toHaveCount(0);
      });
      if (id === 'versions') {
        await check(id, `proposal counter equals API (${real.proposals.length}) and the real freeze control for the frozen version is inert`, async () => {
          await expect(page.getByText(`${real.proposals.length} immutable proposals · 0 pending`)).toBeVisible();
          await page.getByRole('combobox', { name: 'Real dataset version', exact: true }).selectOption(REAL_VERSION);
          await expect(page.getByText(`Version ${short(REAL_VERSION)} · ${real.state} · revision ${real.revision}`)).toBeVisible();
          await expect(page.getByRole('button', { name: 'Already frozen' })).toBeDisabled();
        });
      }
    }

    if (id === 'splits') {
      const d = (await api(context, '/screens/splits')).json;
      await check(id, 'manifest digest, per-split sample/group counts, membership digests and integrity status equal GET /screens/splits', async () => {
        await expect(page.getByRole('heading', { name: `Membership / manifest ${short(d.manifest_digest)}` })).toBeVisible();
        for (const s of ['train', 'validation', 'holdout']) {
          await expect(page.locator('.legend')).toContainText(`${s} · ${d.splits[s].samples} samples · ${d.splits[s].groups} groups`);
          if (d.splits[s].membership_digest) await expect(page.getByText(`${s} membership SHA256 · ${d.splits[s].membership_digest}`)).toBeVisible();
        }
        await expect(page.locator('[data-integrity]')).toHaveAttribute('data-integrity', d.integrity.status);
        return { expected: { train: d.splits.train.samples, validation: d.splits.validation.samples, holdout: d.splits.holdout.samples, integrity: d.integrity.status }, observed: 'matched' };
      });
      await check(id, 'holdout stays sealed (aggregate only) and the real steward panel lists exactly the frozen real versions from GET /versions', async () => {
        const d2 = (await api(context, '/screens/splits')).json;
        await expect(page.getByText(`${d2.splits.holdout.samples} holdout members remain sealed.`)).toBeVisible();
        const frozen = versions.filter((v: any) => v.state === 'frozen' && v.manifest.scope === 'real-rights-cleared');
        const sel = page.locator('section[aria-labelledby="real-holdout-title"] select');
        await expect(sel.locator('option')).toHaveCount(frozen.length + 1);
        for (const v of frozen) await expect(sel).toContainText(`${short(v.id)} · revision ${v.revision}`);
        return { expected: frozen.map((v: any) => short(v.id)), observed: 'matched' };
      });
    }

    if (id === 'configure') {
      const c = (await api(context, '/screens/configure')).json;
      await check(id, 'resolved plan (train/validation counts, worker state) and resource preflight equal GET /screens/configure', async () => settled(async () => {
        const c2 = (await api(context, '/screens/configure')).json;
        await expect(dd(page, 'Train / validation')).toHaveText(`${c2.dataset.counts.train} / ${c2.dataset.counts.validation}`);
        await expect(dd(page, 'Worker')).toContainText(c2.worker.status === 'fresh' ? 'fresh heartbeat' : `${c2.worker.status}: queued runs will wait`);
        await expect(page.locator('[data-preflight]').first()).toHaveAttribute('data-preflight', c2.preflight.admitted ? 'admitted' : 'blocked');
        return { expected: { counts: c2.dataset.counts, worker: c2.worker.status, admitted: c2.preflight.admitted }, observed: 'matched' };
      }));
      await check(id, 'real queue form offers exactly the frozen real versions (API) and its submit control is disabled until a version is chosen (nothing queued)', async () => {
        const frozen = versions.filter((v: any) => v.state === 'frozen' && v.manifest.scope === 'real-rights-cleared');
        await expect(page.getByRole('heading', { name: 'Queue real-data training' })).toBeVisible();
        const sel = page.getByRole('combobox', { name: 'Frozen real version', exact: true });
        await expect(sel.locator('option')).toHaveCount(frozen.length + 1);
        await expect(page.getByRole('button', { name: 'Queue real training' })).toBeDisabled();
        return { expected: frozen.map((v: any) => short(v.id)), observed: 'matched' };
      });
      void c;
    }

    if (id === 'runs') {
      const list = (await api(context, '/real/runs')).json as { items: any[]; next_cursor: string | null };
      await check(id, `real run picker lists every GET /real/runs item with scope and state (${list.items.length} items)`, async () => settled(async () => {
        const fresh = (await api(context, '/real/runs')).json.items as any[];
        const sel = page.getByRole('combobox', { name: 'Selected real run', exact: true });
        await expect(sel.locator('option')).toHaveCount(fresh.length + 1, { timeout: 20_000 });
        for (const r of fresh) await expect(sel.locator(`option[value="${r.id}"]`)).toHaveText(`${short(r.id)} · ${String(r.scope).replace('/v1', '')} · ${r.state}`);
        return { expected: fresh.length, observed: fresh.length };
      }));
      await pickRun(id, RUN);
      await check(id, `selected real run ${short(RUN)}: state, revision, reported epoch and artifact status equal GET /real/runs/{id}`, async () => {
        const r = (await api(context, `/real/runs/${RUN}`)).json.run;
        await expect(page.locator('[data-run-state]').filter({ hasText: r.state.replace(/_/g, ' ') }).first()).toBeVisible();
        await expect(page.getByText(`Revision ${r.revision} · reported epoch ${r.epoch} · artifact ${r.artifact_status}`)).toBeVisible();
        expect(r.state).toBe('succeeded'); expect(r.epoch).toBe(2); expect(r.artifact_status).toBe('verified');
        return { expected: `${r.state} r${r.revision} epoch ${r.epoch} ${r.artifact_status}`, observed: 'matched' };
      });
      await check(id, 'terminal run offers no cancellation control (control state equals terminal state)', async () => {
        await expect(page.getByRole('button', { name: 'Request cancellation' })).toHaveCount(0);
      });
      await check(id, 'worker heartbeat and queue length equal GET /screens/operations', async () => settled(async () => {
        const o = await ops();
        await expect(page.locator('[data-worker-status]').first()).toHaveAttribute('data-worker-status', o.worker.status, { timeout: 20_000 });
        await expect(dd(page, 'Queue length')).toHaveText(String(o.queue_length));
        return { expected: { status: o.worker.status, queue: o.queue_length }, observed: 'matched' };
      }));
    }

    if (id === 'training') {
      await check(id, `run id, state, epoch, artifact status and revision equal GET /real/runs/${short(RUN)}`, async () => {
        await expect(dd(page, 'Run ID')).toHaveText(RUN);
        await expect(page.locator('dd [data-run-state]').first()).toHaveAttribute('data-run-state', run.state);
        await expect(dd(page, 'Reported epoch')).toHaveText(`${run.epoch} · database run state`);
        await expect(dd(page, 'Artifact status')).toHaveText(run.artifact_status);
        await expect(dd(page, 'Revision')).toHaveText(String(run.revision));
        return { expected: { state: run.state, epoch: run.epoch, artifact: run.artifact_status }, observed: 'matched' };
      });
      await check(id, 'committed checkpoint rows (epoch, losses, updates, attempt, full SHA256) equal GET lineage', async () => {
        await expect(page.getByRole('heading', { name: `Committed real checkpoints · ${lineage.checkpoints.length} of ${lineage.epochs}` })).toBeVisible();
        const rows = page.locator('table').filter({ hasText: 'Checkpoint SHA256' }).locator('tbody tr');
        await expect(rows).toHaveCount(lineage.checkpoints.length);
        for (const [i, cp] of lineage.checkpoints.entries()) {
          const row = rows.nth(i);
          await expect(row).toContainText(cp.digest);
          await expect(row.locator('td').nth(0)).toHaveText(cp.metrics.train_loss.toFixed(6));
          await expect(row.locator('td').nth(1)).toHaveText(cp.metrics.validation_loss.toFixed(6));
          await expect(row.locator('td').nth(2)).toHaveText(String(cp.metrics.updates));
        }
        return { expected: lineage.checkpoints.map((c: any) => `${c.epoch}:${c.digest.slice(0, 12)}`), observed: 'matched' };
      });
      await check(id, 'attempt lineage (id, fence, committed epochs, current) and run events equal GET lineage', async () => {
        for (const a of lineage.attempts) {
          const row = page.locator('table').filter({ hasText: 'Committed epochs' }).locator('tbody tr').filter({ hasText: a.id });
          await expect(row).toContainText(String(a.fence));
          await expect(row).toContainText(a.committed_epochs.join(', ') || 'none');
          await expect(row).toContainText(a.current ? 'yes' : 'no');
        }
        const events = page.locator('ol.events').last().locator('li');
        const tail = lineage.events.slice(-12);
        await expect(events).toHaveCount(tail.length);
        for (const [i, e] of tail.entries()) await expect(events.nth(i)).toContainText(`#${e.seq} ${e.kind}`);
        return { expected: { attempts: lineage.attempts.length, events: tail.length }, observed: 'matched' };
      });
      await check(id, 'terminal run offers no cancellation control', async () => {
        await expect(page.getByRole('button', { name: 'Request cancellation' })).toHaveCount(0);
      });
    }

    if (id === 'evaluation') {
      await check(id, 'GET /real/runs/{id}/validation answered (independent read)', async () => {
        expect(validationReply.status, `validation endpoint status ${validationReply.status}`).toBe(200);
        return { expected: 200, observed: validationReply.status };
      });
      if (validation) {
        await check(id, 'confusion matrix: all 25 cell counts equal GET validation metrics, and equal the matrix recomputed on disk from the immutable bundle', async () => {
          expect(validation.metrics.matrix).toEqual(diskMetrics.matrix);
          // The validation read re-verifies the bundle server-side and can fail transiently (see report); a user would press Retry.
          for (let i = 0; i < 4 && !(await page.locator('[data-real-run-screen="evaluation"] table.matrix').isVisible()); i++) {
            const retry = page.locator('[data-real-run-screen="evaluation"] [role=alert] button', { hasText: 'Retry' });
            await Promise.race([page.locator('[data-real-run-screen="evaluation"] table.matrix').waitFor({ timeout: 60_000 }), retry.waitFor({ timeout: 60_000 })]).catch(() => undefined);
            if (await retry.isVisible()) { uiRetries.evaluation = (uiRetries.evaluation || 0) + 1; await retry.click(); }
          }
          await expect(page.locator('[data-real-run-screen="evaluation"] table.matrix')).toBeVisible({ timeout: 90_000 });
          for (let a = 0; a < 5; a++) for (let p = 0; p < 5; p++)
            await expect(page.getByRole('button', { name: `${validation.classes[a]} predicted as ${validation.classes[p]}: ${validation.metrics.matrix[a][p]} validation samples`, exact: true })).toBeVisible();
          return { expected: validation.metrics.matrix, observed: 'all 25 matched' };
        });
        await check(id, 'summary (n, ok, accuracy, macro F1, coverage, verifier), dispositions, bundle and evaluation digests equal GET validation', async () => {
          const m = validation.metrics;
          const cell = (label: string) => page.locator(`th[scope=row]:text-is("${label}") + td`);
          await expect(cell('Expected validation records')).toHaveText(String(m.n));
          await expect(cell('Successful predictions')).toHaveText(String(m.ok));
          await expect(cell('Accuracy')).toHaveText(fixed(m.accuracy, 4));
          await expect(cell('Macro F1')).toHaveText(fixed(m.macro_f1, 4));
          await expect(cell('Coverage')).toHaveText(fixed(m.coverage, 4));
          await expect(cell('Independent verifier')).toHaveText('matches recomputation');
          for (const [k, v] of Object.entries(m.disposition_counts)) await expect(cell(k)).toHaveText(String(v));
          await expect(page.getByText(`bundle ${validation.bundle_digest}`)).toBeVisible();
          await expect(page.getByText(`Evaluation digest · ${validation.evaluation_digest}`)).toBeVisible();
          expect(m.n).toBe(550);
          expect(preds.length).toBe(550);
          return { expected: { n: m.n, accuracy: m.accuracy, bundle: validation.bundle_digest.slice(0, 16) }, observed: 'matched' };
        });
        await check(id, 'bundle digest on screen equals the digest in the run lineage verified-artifact event', async () => {
          const ev = lineage.events.find((e: any) => e.kind === 'artifact_verified');
          expect(ev.payload.bundle_digest).toBe(validation.bundle_digest);
          return { expected: ev.payload.bundle_digest, observed: validation.bundle_digest };
        });
      }
    }

    if (id === 'recovery') {
      await check(id, 'run state, committed checkpoints, attempts used, latest checkpoint digest and eligibility equal GET lineage', async () => {
        await expect(dd(page, 'Committed checkpoints')).toHaveText(`${lineage.checkpoints.length} of ${lineage.epochs}`);
        await expect(dd(page, 'Attempts')).toHaveText(`${lineage.recovery.attempts_used} of ${lineage.recovery.attempt_budget}`);
        await expect(dd(page, 'Latest checkpoint')).toHaveText(lineage.checkpoints.at(-1).digest);
        await expect(dd(page, 'Recovery eligibility')).toHaveText(lineage.recovery.resumable ? 'server reports resumable' : String(lineage.recovery.blocked_code));
        await expect(page.getByRole('button', { name: /^Resume at epoch/ })).toHaveCount(0);
        return { expected: { eligibility: lineage.recovery.blocked_code, latest: lineage.checkpoints.at(-1).digest.slice(0, 12) }, observed: 'matched' };
      });
      const rl = (await api(context, `/screens/runs/${REPLAYED_RUN}/lineage`)).json;
      await pickRun(id, REPLAYED_RUN);
      await check(id, `kill/replay run ${short(REPLAYED_RUN)}: interruption boundary, replay epoch, new attempt and fence, attempts used equal GET lineage`, async () => {
        expect(rl.boundaries.length).toBeGreaterThan(0);
        await expect(dd(page, 'Attempts')).toHaveText(`${rl.recovery.attempts_used} of ${rl.recovery.attempt_budget}`, { timeout: 30_000 });
        for (const b of rl.boundaries) {
          await expect(page.getByText(`Committed through epoch ${b.committed_epoch}`)).toBeVisible();
          if (b.replay_epoch) await expect(page.getByText(`Replay epoch ${b.replay_epoch}`)).toBeVisible();
          if (b.new_attempt) await expect(page.getByText(`Attempt ${short(b.new_attempt)} · fence ${b.new_fence}`)).toBeVisible();
        }
        await expect(dd(page, 'Latest checkpoint')).toHaveText(rl.checkpoints.at(-1).digest);
        await expect(page.getByRole('button', { name: /^Resume at epoch/ })).toHaveCount(0);
        return { expected: { attempts: rl.attempts.map((a: any) => `${short(a.id)}/f${a.fence}`), boundaries: rl.boundaries.length }, observed: 'matched' };
      });
      await pickRun(id, RUN);
    }

    if (id === 'artifacts') {
      await page.getByRole('combobox', { name: 'Verified real training run', exact: true }).selectOption(RUN);
      const b = await api(context, `/real/runs/${RUN}/bundle`, 6);
      await check(id, 'GET /real/runs/{id}/bundle answered (independent read)', async () => { expect(b.status, `bundle endpoint status ${b.status}`).toBe(200); return { expected: 200, observed: b.status }; });
      if (b.status === 200) {
        const bd = b.json;
        await check(id, 'verified bundle digest, scope, dataset version/digest on screen equal GET bundle', async () => {
          await expect(dd(page, 'Bundle digest')).toHaveText(bd.bundle_digest, { timeout: 90_000 });
          await expect(dd(page, 'Scope')).toHaveText(bd.scope);
          await expect(dd(page, 'Dataset version')).toHaveText(bd.lineage.version_id);
          await expect(dd(page, 'Dataset digest')).toHaveText(bd.lineage.dataset_digest);
          const ev = lineage.events.find((e: any) => e.kind === 'artifact_verified');
          expect(bd.bundle_digest).toBe(ev.payload.bundle_digest);
          return { expected: bd.bundle_digest, observed: bd.bundle_digest };
        });
        await check(id, 'bundle file table (names, bytes, SHA256) equals GET bundle manifest', async () => {
          const rows = page.locator('table').filter({ hasText: 'SHA256' }).filter({ hasText: 'Bytes' }).last().locator('tbody tr');
          const files = Object.entries(bd.manifest.files) as [string, { bytes: number; sha256: string }][];
          await expect(rows).toHaveCount(files.length);
          for (const [name, f] of files) {
            const row = rows.filter({ has: page.locator(`th[scope=row]:text-is("${name}")`) });
            await expect(row).toContainText(String(f.bytes));
            await expect(row).toContainText(f.sha256);
          }
          return { expected: files.map(([n]) => n), observed: 'matched' };
        });
      }
      await check(id, 'download control state: private candidate has no download control and says so; qualified release control presence equals API download_allowed (never clicked)', async () => {
        const q = (await api(context, '/qualified-releases')).json.items as any[];
        await expect(page.getByText('Private candidates are not downloadable or selectable by ordinary inference, regardless of workspace role.')).toBeVisible({ timeout: 90_000 });
        const allowed = q.filter(x => x.download_allowed).length;
        await expect(page.getByRole('button', { name: /download/i })).toHaveCount(allowed);
        for (const item of q) await expect(page.locator('dt:text-is("Bundle SHA256") + dd').filter({ hasText: item.bundle_digest })).toHaveCount(1);
        return { expected: { qualified_download_buttons: allowed }, observed: 'matched' };
      });
    }

    if (id === 'inference') {
      const inf = (await api(context, '/screens/inference')).json;
      const q = (await api(context, '/qualified-releases')).json.items as any[];
      await check(id, 'real qualified-release selector and run/bundle candidate state equal GET /screens/inference and /qualified-releases (no inference started)', async () => {
        await expect(page.locator(`[data-state="${inf.ordinary_inference.allowed ? 'qualified_release_ready' : 'inference_denied'}"]`).first()).toBeVisible();
        await expect(page.getByText(`${inf.qualified_releases.length} qualified release${inf.qualified_releases.length === 1 ? '' : 's'} are available`)).toBeVisible();
        const sel = page.getByRole('combobox', { name: 'Qualified model', exact: true });
        await expect(sel.locator('option')).toHaveCount(q.length);
        for (const x of q) await expect(sel).toContainText(`${x.recipe} · ${x.release_id}`);
        for (const c of inf.candidates) {
          const row = page.getByRole('table', { name: 'Internal candidates' }).locator('tbody tr').filter({ hasText: short(c.run_id) });
          await expect(row.locator('td').nth(1)).toHaveText(c.artifact_status);
          await expect(row.locator('td').nth(2)).toHaveText(c.qualified_release ? 'yes' : 'no');
        }
        await expect(page.getByRole('button', { name: 'Run qualified inference' })).toBeDisabled();
        if (!q[0]?.inference_allowed) await expect(page.getByText('Your role or the qualified pinned model runtime is not ready for inference.')).toBeVisible();
        return { expected: { releases: q.map(x => x.release_id), candidates: inf.candidates.length }, observed: 'matched' };
      });
    }

    if (id === 'settings') {
      const acc = (await api(context, '/screens/access')).json, st = (await api(context, '/real/settings')).json;
      await check(id, 'server-derived identity, member table, owner count, session policy equal GET /screens/access', async () => {
        await expect(dd(page, 'Signed-in account')).toHaveText(acc.me.name);
        await expect(dd(page, 'Server-derived role')).toHaveText(acc.me.role);
        await expect(dd(page, 'Workspace')).toHaveText(acc.me.workspace);
        const rows = page.getByRole('table', { name: 'Members' }).locator('tbody tr');
        await expect(rows).toHaveCount(acc.members.length);
        for (const m of acc.members) await expect(rows.filter({ hasText: m.name })).toContainText(m.role);
        await expect(page.getByText(`${acc.owner_count} owners.`)).toBeVisible();
        await expect(dd(page, 'Idle expiry')).toHaveText(`${acc.session.idle_timeout_minutes} minutes`);
        return { expected: { members: acc.members.length, owners: acc.owner_count }, observed: 'matched' };
      });
      await check(id, 'workspace policy revision and limits equal GET /real/settings (not saved)', async () => {
        await expect(page.getByRole('heading', { name: `Workspace policy · revision ${st.settings.revision}` })).toBeVisible();
        await expect(page.getByLabel('Minimum evidence retention (days)')).toHaveValue(String(st.settings.retention_days));
        await expect(page.getByLabel('Concurrent real run limit')).toHaveValue(String(st.settings.max_concurrent_runs));
        await expect(page.getByLabel('Maximum epochs per real run')).toHaveValue(String(st.settings.max_epochs));
        await expect(page.getByRole('heading', { name: `Members · ${st.owner_count} owner${st.owner_count === 1 ? '' : 's'}` })).toBeVisible();
        return { expected: st.settings, observed: 'matched' };
      });
    }

    if (id === 'errors') {
      const [ea, ep] = cellPair;
      await check(id, 'plain navigation to Error investigation keeps the selected real run and pair; count and membership digest equal the disk recomputation', async () => {
        const ids = preds.filter(r => r.status === 'ok' && r.label === ea && r.logits.indexOf(Math.max(...r.logits)) === ep).map(r => r.id).sort();
        await expect(page.getByRole('heading', { level: 3, name: `${classes[ea]} → ${classes[ep]}`, exact: true })).toBeVisible({ timeout: 120_000 });
        await expect(page.getByText(`${ids.length} exact validation members ·`)).toBeVisible();
        await expect(page.getByText(`Membership SHA256 · ${canonicalDigest(ids)}`)).toBeVisible();
        return { expected: { pair: `${classes[ea]}→${classes[ep]}`, total: ids.length }, observed: 'matched' };
      });
    }

    await snapShot(id, idx);

    // ---- direct route reload (state is client-side; the route and a reload-safe real fact must survive)
    await page.reload();
    await expect(h1(page, title)).toBeVisible({ timeout: 30_000 });
    per[id].reload_ok = true;
    await check(id, 'after a full reload the exact route is preserved', async () => { expect(new URL(page.url()).hash).toBe(`#${id}`); });
    if (id === 'overview' || id === 'runs') await check(id, 'after reload: worker status equals API', async () => settled(async () => {
      const o = await ops();
      if (id === 'runs') await expect(page.getByRole('combobox', { name: 'Selected real run', exact: true }).locator(`option[value="${RUN}"]`)).toHaveText(`${short(RUN)} · real-training · ${run.state}`, { timeout: 30_000 });
      await expect(page.locator('[data-worker-status]').first()).toHaveAttribute('data-worker-status', o.worker.status, { timeout: 20_000 });
    }));
    if (id === 'dataset') await check(id, 'after reload: the real version is offered with API state/revision', async () => {
      await expect(page.getByRole('combobox', { name: 'Dataset version', exact: true })).toContainText(`${short(REAL_VERSION)} · ${real.state} · rev ${real.revision}`, { timeout: 30_000 });
    });
    if (id === 'sample') await check(id, 'after reload: default sample is the first snapshot sample (API)', async () => {
      await expect(page.getByRole('heading', { level: 2, name: snap.samples[0].id, exact: true })).toBeVisible({ timeout: 30_000 });
    });
    if (id === 'versions') await check(id, 'after reload: persisted version rows equal API', async () => {
      await expect(page.getByRole('table', { name: 'Persisted versions' }).locator('tbody tr')).toHaveCount(versions.length, { timeout: 30_000 });
    });
    if (id === 'splits') await check(id, 'after reload: manifest digest equals API', async () => {
      const d = (await api(context, '/screens/splits')).json;
      await expect(page.getByRole('heading', { name: `Membership / manifest ${short(d.manifest_digest)}` })).toBeVisible({ timeout: 30_000 });
    });
    if (['training', 'evaluation', 'errors', 'recovery'].includes(id)) await check(id, 'after reload: the real-run picker lists the succeeded real run with API state', async () => {
      await expect(page.getByRole('combobox', { name: 'Selected real run', exact: true }).locator(`option[value="${RUN}"]`)).toHaveText(`${short(RUN)} · real-training · ${run.state}`, { timeout: 30_000 });
    });
    if (id === 'artifacts') await check(id, 'after reload: verified real run is offered', async () => {
      await expect(page.getByRole('combobox', { name: 'Verified real training run', exact: true }).locator(`option[value="${RUN}"]`)).toBeAttached({ timeout: 30_000 });
    });
    if (id === 'settings') await check(id, 'after reload: server-derived role equals API', async () => {
      await expect(dd(page, 'Server-derived role')).toHaveText(who.role, { timeout: 30_000 });
    });

    if (id === 'evaluation' && validation) {
      // Reached from Evaluation exactly as a user would: re-select the real run after the reload, click a nonzero error cell.
      const sel = page.getByRole('combobox', { name: 'Selected real run', exact: true });
      await expect(sel.locator(`option[value="${RUN}"]`)).toBeAttached({ timeout: 30_000 });
      await sel.selectOption(RUN);
      const m = validation.metrics.matrix as number[][];
      let best = { a: 0, p: 1, n: -1 };
      for (let a = 0; a < 5; a++) for (let p = 0; p < 5; p++) if (a !== p && m[a][p] > best.n) best = { a, p, n: m[a][p] };
      expect(best.n).toBeGreaterThan(0);
      await page.getByRole('button', { name: `${validation.classes[best.a]} predicted as ${validation.classes[best.p]}: ${best.n} validation samples`, exact: true }).click({ timeout: 120_000 });
      await expect(h1(page, 'Error investigation')).toBeVisible();
      const cellKey = `${best.a}:${best.p}`;
      cellPair = [best.a, best.p];
      const expectedIds = preds.filter(r => r.status === 'ok' && r.label === best.a && r.logits.indexOf(Math.max(...r.logits)) === best.p).map(r => r.id).sort();
      const sl = await api(context, `/real/runs/${RUN}/validation/slices?actual=${best.a}&predicted=${best.p}&bucket=cell&limit=100`, 6);
      const name = `cell click ${classes[best.a]}->${classes[best.p]} (${best.n}) opens Error investigation on that exact pair; count and membership digest equal API and disk recomputation`;
      if (!per.errors) start('errors', 'Error investigation');
      per.errors.assertions.push(name);
      await rec.check('errors', name, async () => {
        expect(sl.status).toBe(200);
        expect(diskMetrics.cells[cellKey]).toEqual(expectedIds);
        expect(sl.json.total).toBe(best.n);
        expect(expectedIds.length).toBe(best.n);
        expect(sl.json.membership_digest).toBe(canonicalDigest(expectedIds));
        await expect(page.getByRole('heading', { level: 3, name: `${validation.classes[best.a]} → ${validation.classes[best.p]}`, exact: true })).toBeVisible({ timeout: 120_000 });
        await expect(page.getByRole('combobox', { name: 'Actual class', exact: true })).toHaveValue(String(best.a));
        await expect(page.getByRole('combobox', { name: 'Predicted class', exact: true })).toHaveValue(String(best.p));
        await expect(page.getByText(`${best.n} exact validation members · ${Math.min(24, best.n)} loaded`)).toBeVisible();
        await expect(page.getByText(`Membership SHA256 · ${sl.json.membership_digest}`)).toBeVisible();
        await expect(page.getByText(`Evaluation SHA256 · ${validation.evaluation_digest}`)).toBeVisible();
        return { expected: { pair: `${classes[best.a]}->${classes[best.p]}`, total: best.n, digest: sl.json.membership_digest }, observed: 'matched' };
      });
      per.evaluation.assertions.push(`click matrix cell ${classes[best.a]}->${classes[best.p]} (count ${best.n}) navigates to Error investigation for that pair (asserted under errors)`);
      cellClick = { cell: cellKey, pair: `${classes[best.a]}->${classes[best.p]}`, count: best.n, membership_digest: sl.json.membership_digest };
      await snapErrors(`${String(SCREENS.findIndex(x => x[0] === 'errors') + 1).padStart(2, '0')}-errors-cell-click-${channel}.png`);
    }
  }

  fs.writeFileSync(path.join(out, `real-journey-results-${channel}.json`), JSON.stringify({
    ...meta, ...bf, workspace: '814830e3-55a0-4925-ad37-5d3dac7d4df8', real_run: RUN,
    note: 'Live API, real records, GET-only reads except sign-in. No mocks, no route fulfilment. Facts are asserted against independent API reads in the same test.',
    screens: per, cell_click: cellClick, ui_retry_clicks_after_server_500: uiRetries, totals: { assertions: rec.facts.length, passed: rec.facts.filter(f => f.pass).length, failed: rec.failures().length }, facts: rec.facts,
  }, null, 2));
  expect(rec.failures(), JSON.stringify(rec.failures(), null, 1)).toEqual([]);
});

test(`CELL drill-down: every confusion cell and missing bucket via the UI vs API vs disk [${channel}]`, async ({ page, context }) => {
  const out = outDir();
  const rec = new Recorder();
  await login(context);
  await page.goto('/#errors');
  await expect(h1(page, 'Error investigation')).toBeVisible({ timeout: 30_000 });
  const bf = await browserFacts(page);
  const run = (await api(context, `/real/runs/${RUN}`)).json.run;
  const preds = fs.readFileSync(path.join(bundleDir(), 'evaluation/predictions.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  const diskMetrics = JSON.parse(fs.readFileSync(path.join(bundleDir(), 'evaluation/metrics.json'), 'utf8'));
  const validation = (await api(context, `/real/runs/${RUN}/validation`, 6)).json;
  expect(validation?.run_id).toBe(RUN);
  const classes: string[] = validation.classes;
  await page.getByRole('combobox', { name: 'Selected real run', exact: true }).selectOption(RUN);
  await expect(page.getByRole('combobox', { name: 'Actual class', exact: true })).toBeVisible({ timeout: 90_000 });
  const argmax = (l: number[]) => l.indexOf(Math.max(...l));
  const rows: any[] = [];
  const buckets: { actual: number; predicted: number | null; bucket: 'cell' | 'missing' }[] = [];
  for (let a = 0; a < 5; a++) for (let p = 0; p < 5; p++) buckets.push({ actual: a, predicted: p, bucket: 'cell' });
  for (let a = 0; a < 5; a++) buckets.push({ actual: a, predicted: null, bucket: 'missing' });
  const allIds = new Set<string>();
  for (const b of buckets) {
    const expected = (b.bucket === 'cell'
      ? preds.filter(r => r.status === 'ok' && r.label === b.actual && argmax(r.logits) === b.predicted)
      : preds.filter(r => r.status !== 'ok' && r.label === b.actual)).map(r => r.id).sort();
    const name = `${classes[b.actual]} -> ${b.bucket === 'cell' ? classes[b.predicted!] : 'missing'}`;
    await rec.check('errors', `${name}: UI pages == API == disk predicate (count ${expected.length})`, async () => {
      if (b.bucket === 'cell') expect(diskMetrics.cells[`${b.actual}:${b.predicted}`]).toEqual(expected);
      else expect(diskMetrics.missing_by_class[b.actual]).toEqual(expected);
      if (b.bucket === 'cell') expect(validation.metrics.matrix[b.actual][b.predicted!]).toBe(expected.length);
      const digest = canonicalDigest(expected);
      // changed UI filters
      await page.getByRole('combobox', { name: 'Disposition', exact: true }).selectOption(b.bucket);
      await page.getByRole('combobox', { name: 'Actual class', exact: true }).selectOption(String(b.actual));
      if (b.bucket === 'cell') await page.getByRole('combobox', { name: 'Predicted class', exact: true }).selectOption(String(b.predicted));
      await expect(page.getByText(`Membership SHA256 · ${digest}`)).toBeVisible({ timeout: 120_000 });
      await expect(page.getByText(`${expected.length} exact validation members ·`)).toBeVisible();
      // pagination: load every page through the UI
      let guard = 0;
      while (await page.getByRole('button', { name: 'Load more validation members' }).count()) {
        const before = await page.locator('[role=group][aria-label^="Validation member"]').count();
        await page.getByRole('button', { name: 'Load more validation members' }).click();
        await expect.poll(() => page.locator('[role=group][aria-label^="Validation member"]').count(), { timeout: 120_000 }).toBeGreaterThan(before);
        if (++guard > 20) throw new Error('pagination did not terminate');
      }
      await expect(page.getByText(`${expected.length} exact validation members · ${expected.length} loaded`)).toBeVisible();
      const shown = await page.locator('[role=group][aria-label^="Validation member"]').evaluateAll(els => els.map(e => (e.getAttribute('aria-label') || '').replace('Validation member ', '')));
      expect(shown).toEqual(expected.map(short));
      expect(new Set(shown).size).toBe(shown.length);
      await expect(page.getByText(`Membership SHA256 · ${digest}`)).toBeVisible();
      // independent API read of the same bucket (single page, limit 100)
      const q = `actual=${b.actual}&bucket=${b.bucket}${b.bucket === 'cell' ? `&predicted=${b.predicted}` : ''}&limit=100`;
      const sl = await api(context, `/real/runs/${RUN}/validation/slices?${q}`, 6);
      expect(sl.status).toBe(200);
      expect(sl.json.members.map((m: any) => m.sample_id)).toEqual(expected);
      expect(sl.json.total).toBe(expected.length);
      expect(sl.json.membership_digest).toBe(digest);
      expected.forEach(i => allIds.add(i));
      rows.push({ bucket: name, count: expected.length, membership_digest: digest, pages_ui: Math.max(1, Math.ceil(expected.length / 24)) });
      return { expected: expected.length, observed: shown.length };
    });
  }
  await rec.check('errors', 'the 25 cells partition the 550 validation records exactly (no overlap, none missing)', async () => {
    expect(allIds.size).toBe(validation.metrics.n);
    expect(rows.filter(r => !r.bucket.endsWith('missing')).reduce((s, r) => s + r.count, 0)).toBe(validation.metrics.n);
  });
  fs.writeFileSync(path.join(out, `real-cell-drilldown-${channel}.json`), JSON.stringify({ generated_utc: new Date().toISOString(), channel, ...bf, run: RUN, run_state: run.state,
    validation_n: validation.metrics.n, evaluation_digest: validation.evaluation_digest, buckets: rows, facts: rec.facts,
    totals: { checks: rec.facts.length, passed: rec.facts.filter(f => f.pass).length, failed: rec.failures().length } }, null, 2));
  expect(rec.failures(), JSON.stringify(rec.failures(), null, 1)).toEqual([]);
});
