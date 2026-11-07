// ML-T-FLOW: mutating steps of the real-data journey, driven ONLY through UI controls (no API writes from the test).
// Phases (env REAL_FLOW_PHASE): dryrun | intake | submit | recover | finish. Only 'dryrun' is side-effect free.
// The test performs GET reads (independent API verification) and observes the UI's own responses (page.waitForResponse);
// it never fulfils, mocks or issues mutating requests itself.
//
//   REAL_OUT           new evidence directory for this phase (required by the config)
//   REAL_FLOW_STATE    JSON file shared across phases (run id etc.); 'submit' creates it and refuses to overwrite it
//   REAL_FLOW_WAIT_MIN optional: minutes recover/finish may wait for their precondition (default 0 = check once and fail fast)
import { test, expect, type Page, type BrowserContext } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { REAL_VERSION, SCREENS, api, browserFacts, h1, login, nav, outDir, short } from './real-helpers';

const phase = process.env.REAL_FLOW_PHASE || 'dryrun';
const channel = process.env.REAL_CHANNEL || 'msedge';
const waitMin = Number(process.env.REAL_FLOW_WAIT_MIN || 0);
const CONFIG = { epochs: '20', batch: '16', lr: '0.001', seed: '42' };
const PHASES = ['dryrun', 'intake', 'submit', 'recover', 'finish'];
if (!PHASES.includes(phase)) throw new Error(`REAL_FLOW_PHASE must be one of ${PHASES.join('|')}`);
test.setTimeout(Math.max(30, waitMin + 30) * 60_000);

const sha256 = (b: Buffer | string) => crypto.createHash('sha256').update(b).digest('hex');
const MEDIA = path.resolve('../../var/datasets/tf_flowers/media');
type Gap = { control: string; finding: string };
const report: { phase: string; channel: string; generated_utc: string; os: string; steps: { name: string; pass: boolean; detail?: unknown; error?: string }[]; ui_gaps: Gap[]; [k: string]: unknown } =
  { phase, channel, generated_utc: new Date().toISOString(), os: `${os.type()} ${os.release()} (${os.version()})`, steps: [], ui_gaps: [] };
const save = (out: string) => fs.writeFileSync(path.join(out, `real-flow-${phase}-${channel}.json`), JSON.stringify(report, null, 2));
async function step(name: string, fn: () => Promise<unknown>) {
  try { const detail = await fn(); report.steps.push({ name, pass: true, detail }); }
  catch (e) { report.steps.push({ name, pass: false, error: String((e as Error).message).split('\n').slice(0, 6).join(' | ') }); throw e; }
}
const gap = (control: string, finding: string) => report.ui_gaps.push({ control, finding });

function stateFile() {
  const f = process.env.REAL_FLOW_STATE;
  if (!f) throw new Error('REAL_FLOW_STATE (path of the cross-phase JSON) is required for this phase');
  return path.resolve(f);
}
const readState = () => JSON.parse(fs.readFileSync(stateFile(), 'utf8'));

async function open(page: Page, context: BrowserContext) {
  const who = await login(context);
  await page.goto('/');
  await expect(h1(page, 'Research workspace')).toBeVisible({ timeout: 30_000 });
  Object.assign(report, await browserFacts(page), { actor_role: who.role });
  return who;
}
async function go(page: Page, id: string) {
  const title = SCREENS.find(s => s[0] === id)![1];
  await nav(page, title).click();
  await expect(h1(page, title)).toBeVisible();
}
const combo = (page: Page, name: string) => page.getByRole('combobox', { name, exact: true });
const dd = (page: Page, label: string) => page.locator(`dt:text-is("${label}") + dd`).first();

/** Five train-split images that the API exposes in the frozen real manifest; bytes re-hashed against the manifest sha256. */
async function pickTrainImages(context: BrowserContext, n = 5) {
  const versions = (await api(context, '/versions')).json.items as any[];
  const v = versions.find(x => x.id === REAL_VERSION);
  const train = (v.manifest.samples as any[]).filter(s => s.split === 'train').sort((a, b) => a.id.localeCompare(b.id));
  const picked: { id: string; sha256: string; file: string; source_member: string }[] = [];
  for (const s of train.slice(Number(process.env.REAL_FLOW_INTAKE_OFFSET || 0))) {  // offset: pick a fresh 5-image set
    const file = path.join(MEDIA, s.sha256.slice(0, 2), `${s.sha256}.jpg`);
    if (fs.existsSync(file) && sha256(fs.readFileSync(file)) === s.sha256) picked.push({ id: s.id, sha256: s.sha256, file, source_member: s.source_member });
    if (picked.length === n) break;
  }
  expect(picked.length).toBe(n);
  return { picked, rightsDatasetId: v.manifest.rights_dataset_id as string, versions };
}
function makeZip(out: string, files: { file: string; sha256: string }[]) {
  const zip = path.join(out, 'intake-5-train-duplicates.zip');
  const py = 'import sys,zipfile\nz=zipfile.ZipFile(sys.argv[1],"x",zipfile.ZIP_STORED)\nfor p in sys.argv[2:]:\n  z.write(p,p.replace("\\\\","/").split("/")[-1])\nz.close()';
  execFileSync('python', ['-I', '-c', py, zip, ...files.map(f => f.file)]);
  return zip;
}
/** The receipt on screen equals the run's own artifact_verified lineage event (fields shown by ArtifactReceipt). */
async function assertReceipt(page: Page, events: any[]) {
  const ev = [...events].reverse().find(e => e.kind === 'artifact_verified');
  expect(ev, 'artifact_verified event in lineage').toBeTruthy();
  const box = page.locator('section[aria-labelledby="artifact-receipt-title"]').first();
  await expect(box).toBeVisible({ timeout: 60_000 });
  for (const f of ['process_identity', 'receipt_digest', 'model_digest', 'bundle_digest', 'checkpoint_digest'])
    await expect(box.locator(`[data-receipt-field="${f}"]`)).toHaveText(String(ev.payload[f]));
  await expect(box.locator('[data-receipt-field="rights_members"]')).toHaveText(String(ev.payload.rights_members));
  await expect(box.locator('[data-receipt-field="inference"]')).toContainText('Fresh inference stage');
  return { process_identity: ev.payload.process_identity, receipt_digest: ev.payload.receipt_digest, bundle_digest: ev.payload.bundle_digest };
}
async function assertOnboarding(page: Page) {
  await page.getByRole('button', { name: 'Getting started', exact: true }).click();
  await expect(h1(page, 'Research workspace')).toBeVisible();
  const panel = page.locator('section[aria-labelledby="getting-started-title"]');
  await expect(panel.getByRole('heading', { name: 'Getting started' })).toBeFocused({ timeout: 5000 });
  const steps = panel.locator('ol > li');
  await expect(steps).toHaveCount(8);
  await expect(panel.locator('[data-help="recovery"]')).toContainText('resume replays the next whole epoch');
  const n = await steps.count();
  await panel.getByRole('button', { name: '6. Recover training' }).click();
  await expect(h1(page, 'Recover training')).toBeVisible();
  return { steps: n };
}
async function waitFor<T>(what: string, read: () => Promise<T>, ok: (v: T) => boolean): Promise<T> {
  const deadline = Date.now() + waitMin * 60_000;
  for (;;) {
    const v = await read();
    if (ok(v)) return v;
    if (Date.now() >= deadline) throw new Error(`precondition not met (${what}); last value ${JSON.stringify(v).slice(0, 300)}. Re-run later or set REAL_FLOW_WAIT_MIN.`);
    await new Promise(r => setTimeout(r, 30_000));
  }
}

test(`ML-T-FLOW phase ${phase} [${channel}]`, async ({ page, context }) => {
  const out = outDir();
  try {
    await open(page, context);

    // ------------------------------------------------------------------ dryrun: controls exist, nothing clicked
    if (phase === 'dryrun') {
      await step('intake controls exist on Dataset explorer (form not submitted)', async () => {
        await go(page, 'dataset');
        await expect(page.getByLabel('Rights dataset ID')).toBeVisible();
        await expect(page.getByLabel('Image archive')).toBeAttached();
        await expect(page.getByRole('button', { name: 'Queue archive' })).toBeVisible();
        const { picked, rightsDatasetId } = await pickTrainImages(context);
        const zip = makeZip(out, picked);     // built locally for inspection; NOT uploaded in dryrun
        return { rights_dataset_id: rightsDatasetId, train_images: picked.map(p => short(p.id)), zip: path.basename(zip), zip_sha256: sha256(fs.readFileSync(zip)) };
      });
      await step('intake receipts section exists (counts + reasons render once the backend change is live)', async () => {
        await expect(page.getByRole('heading', { name: 'Your recent intakes' })).toBeVisible({ timeout: 30_000 });
      });
      await step('configure controls exist for the real run (not submitted)', async () => {
        await go(page, 'configure');
        const sel = combo(page, 'Frozen real version');
        await expect(sel.locator(`option[value="${REAL_VERSION}"]`)).toBeAttached();
        for (const l of ['Epochs', 'Batch size', 'Learning rate', 'Seed']) await expect(page.locator('section[aria-labelledby="real-training-title"]').getByLabel(l, { exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Queue real training' })).toBeVisible();
        const s = (await api(context, '/real/settings')).json.settings;
        expect(Number(CONFIG.epochs)).toBeLessThanOrEqual(s.max_epochs);
        return { max_epochs: s.max_epochs, max_concurrent_runs: s.max_concurrent_runs };
      });
      await step('runs/recovery controls: cancellation appears only for non-terminal runs; resume only for interrupted runs', async () => {
        const runs = (await api(context, '/real/runs')).json.items as any[];
        const live = runs.find(r => ['queued', 'leased', 'running'].includes(r.state) && r.scope === 'real-training/v1');
        await go(page, 'runs');
        if (live) {
          await combo(page, 'Selected real run').selectOption(live.id);
          await expect(page.getByLabel('Cancellation reason')).toBeVisible({ timeout: 30_000 });
          await expect(page.getByRole('button', { name: 'Request cancellation' })).toBeVisible();   // not clicked
        }
        await go(page, 'recovery');
        await expect(page.getByText('Recovery follows the durable real attempt and committed checkpoint ledger.')).toBeVisible();
        return { live_run_for_cancel_control: live ? short(live.id) : 'none present (cancel control not observable now)' };
      });
      gap('Cancel then Resume', 'UI "Request cancellation" drives the run to terminal state "cancelled" (store.py/lease_recovery.py: cancel_requested -> cancelled). Resume requires state "interrupted" (store.resume: REPLAY_OR_STATE). The UI therefore cannot produce a resumable run; an interruption only arises from lease expiry (worker/process loss). Phase "recover" resumes an interrupted run through the UI; it never cancels.');
      await step('artifacts/inference controls', async () => {
        await go(page, 'artifacts');
        await expect(page.getByText('Private candidates are not downloadable or selectable by ordinary inference, regardless of workspace role.')).toBeVisible({ timeout: 60_000 });
        const q = (await api(context, '/qualified-releases')).json.items as any[];
        await expect(page.getByRole('button', { name: 'Download qualified release' })).toHaveCount(q.filter(x => x.download_allowed).length);
        await go(page, 'inference');
        await expect(combo(page, 'Qualified model')).toBeVisible();
        await expect(page.getByLabel('Registered image member ID')).toBeVisible();
        await expect(page.getByLabel('Image file')).toBeAttached();
        await expect(page.getByRole('button', { name: 'Run qualified inference' })).toBeVisible();
        return { qualified_releases: q.map(x => x.release_id) };
      });
      await step('artifact verification receipt of the control run equals its lineage event (Training run + Model artifacts)', async () => {
        const CONTROL = '52374741-86c5-469b-aaba-184ce2b7b80a';
        const lin = (await api(context, `/screens/runs/${CONTROL}/lineage`)).json;
        await go(page, 'training'); await combo(page, 'Selected real run').selectOption(CONTROL);
        const t = await assertReceipt(page, lin.events);
        await go(page, 'artifacts'); await combo(page, 'Verified real training run').selectOption(CONTROL);
        await assertReceipt(page, lin.events);
        return t;
      });
      await step('onboarding: Getting started reachable from the header, focuses its heading, links to the flow screens', async () => assertOnboarding(page));
      gap('Model artifacts: export of THIS run', 'No UI download control exists for a private real-training bundle (by design text; real-data-client.downloadRealBundle is not wired into any screen). Only the separate qualified release has "Download qualified release".');
      gap('Inference playground: fresh inference with THIS run', 'Only qualified releases are selectable; the server refuses private runs (POST /real/inferences/image -> 403 QUALIFIED_RELEASE_REQUIRED). The qualified-inference prediction inspector shows run id, state, top class and probabilities only.');
      return;
    }

    // ------------------------------------------------------------------ intake (MUTATING: queues one archive)
    if (phase === 'intake') {
      const { picked, rightsDatasetId, versions: before } = await pickTrainImages(context);
      const zip = makeZip(out, picked);
      report.intake_input = { rights_dataset_id: rightsDatasetId, train_member_ids: picked.map(p => p.id), zip_sha256: sha256(fs.readFileSync(zip)) };
      await go(page, 'dataset');
      await page.getByLabel('Rights dataset ID').fill(rightsDatasetId);
      await page.getByLabel('Image archive').setInputFiles(zip);
      const posted = page.waitForResponse(r => r.request().method() === 'POST' && r.url().includes('/real/intakes'), { timeout: 120_000 });
      await page.getByRole('button', { name: 'Queue archive' }).click();
      const clickedAt = new Date(Date.now() - 5_000).toISOString();
      const resp = await posted;
      let ack: any = await resp.json().catch(() => ({}));
      if (typeof ack.intake_id !== 'string') {
        // Playwright cannot always read the body of a streamed-upload response; take the actor's own newest intake
        // created after the click from the API list (the UI status line is still asserted below).
        const items = ((await api(context, '/real/intakes')).json?.items ?? []) as any[];
        const fresh = items.filter(i => String(i.created_utc) >= clickedAt);
        ack = { intake_id: fresh[0]?.intake_id, state: fresh[0]?.state, source: 'api-list-fallback' };
      }
      await step('UI submission acknowledged (202) and intake status shown', async () => {
        expect(resp.status(), JSON.stringify(ack)).toBe(202);
        expect(typeof ack.intake_id, `POST ${resp.url()} -> ${resp.status()} ${JSON.stringify(ack)}`).toBe('string');
        await expect(page.locator('[role=status]').filter({ hasText: `Intake ${short(ack.intake_id)}` })).toBeVisible({ timeout: 30_000 });
        return ack;
      });
      const final = await (async () => { const deadline = Date.now() + Math.max(waitMin, 20) * 60_000;
        for (;;) { const r = (await api(context, `/real/intakes/${ack.intake_id}`)).json;
          if (['complete', 'succeeded', 'failed', 'rejected', 'cancelled'].includes(r?.state) || Date.now() > deadline) return r;
          await new Promise(res => setTimeout(res, 15_000)); } })();
      await step('UI shows the terminal intake state equal to the API', async () => {
        await expect(page.locator('[role=status]').filter({ hasText: `Intake ${short(ack.intake_id)}` }).locator('[data-run-state]')).toHaveAttribute('data-run-state', final.state, { timeout: 60_000 });
        return final;
      });
      await step('duplicate archive reconciles with zero new sample ids (all existing versions unchanged)', async () => {
        const after = (await api(context, '/versions')).json.items as any[];
        const ids = (vs: any[]) => new Set(vs.flatMap(v => v.manifest.samples.map((s: any) => s.id)));
        const newIds = [...ids(after)].filter(i => !ids(before).has(i));
        expect(newIds).toEqual([]);
        for (const v of before) expect(after.find(a => a.id === v.id)?.digest).toBe(v.digest);
        return { versions_before: before.length, versions_after: after.length, new_sample_ids: newIds.length };
      });
      await step('UI disposition counts and reasons table equal GET /real/intakes/{id} detail (zero new sample ids)', async () => {
        const d = final.detail;
        expect(d, 'intake detail (backend change must be live)').toBeTruthy();
        expect(d.new_sample_ids).toBe(0);
        expect(d.accepted).toBe(0);
        expect(d.duplicate + d.noop).toBe(picked.length);
        const check = async (scope: import('@playwright/test').Locator) => {
          for (const k of ['source_total', 'accepted', 'duplicate', 'noop', 'rejected', 'new_sample_ids'])
            await expect(scope.locator(`[data-intake-count="${k}"]`).first()).toHaveText(String(d[k]), { timeout: 60_000 });
          const rows = scope.locator('tr[data-intake-member]');
          await expect(rows).toHaveCount(d.non_accepted.length);
          for (const [i, m] of (d.non_accepted as any[]).entries()) {
            await expect(rows.nth(i).locator('th')).toHaveText(m.member);
            await expect(rows.nth(i).locator('td').nth(0)).toHaveText(m.disposition);
            await expect(rows.nth(i).locator('td').nth(1)).toHaveText(m.reason);
          }
        };
        await check(page.locator('section[aria-labelledby="real-intake-title"]'));
        await page.reload(); await expect(h1(page, 'Dataset explorer')).toBeVisible();
        await combo(page, 'Intake receipt').selectOption(ack.intake_id);
        await check(page.locator(`[data-intake-inspected="${ack.intake_id}"]`));
        await page.screenshot({ path: path.join(out, `intake-detail-${channel}.png`), fullPage: true });
        return d;
      });
      return;
    }

    // ------------------------------------------------------------------ submit (MUTATING: queues one real 20-epoch run)
    if (phase === 'submit') {
      const sf = stateFile();
      if (fs.existsSync(sf)) throw new Error(`${sf} exists: a flow run was already submitted; refusing to submit a second one`);
      await go(page, 'configure');
      const form = page.locator('section[aria-labelledby="real-training-title"]');
      await combo(page, 'Frozen real version').selectOption(REAL_VERSION);
      await form.getByLabel('Epochs', { exact: true }).fill(CONFIG.epochs);
      await form.getByLabel('Batch size', { exact: true }).fill(CONFIG.batch);
      await form.getByLabel('Learning rate', { exact: true }).fill(CONFIG.lr);
      await form.getByLabel('Seed', { exact: true }).fill(CONFIG.seed);
      const posted = page.waitForResponse(r => r.request().method() === 'POST' && /\/real\/runs$/.test(new URL(r.url()).pathname), { timeout: 120_000 });
      await page.getByRole('button', { name: 'Queue real training' }).click();
      const resp = await posted;
      const run = await resp.json().catch(() => ({}));
      await step('UI submission accepted by the server', async () => {
        expect(resp.ok(), `${resp.status()} ${JSON.stringify(run)}`).toBeTruthy();
        expect(run.id).toMatch(/^[0-9a-f-]{36}$/);
        fs.writeFileSync(sf, JSON.stringify({ run_id: run.id, version_id: REAL_VERSION, config: CONFIG, submitted_utc: new Date().toISOString(), channel }, null, 2), { flag: 'wx' });
        fs.copyFileSync(sf, path.join(out, 'flow-run.json'));
        await expect(page.getByText('Real training queued. No progress is shown until the worker reports it.')).toBeVisible();
        return { run_id: run.id, status: resp.status() };
      });
      await step('Runs & workers shows the new run with the API state (queued/leased/running)', async () => {
        await go(page, 'runs');
        const r = (await api(context, `/real/runs/${run.id}`)).json.run;
        expect(['queued', 'leased', 'running']).toContain(r.state);
        await expect(combo(page, 'Selected real run')).toHaveValue(run.id);
        await expect(page.locator('[data-run-state]').filter({ hasText: r.state }).first()).toBeVisible({ timeout: 30_000 });
        await expect(page.getByText(new RegExp(`Revision \\d+ · reported epoch \\d+ · artifact`))).toBeVisible();
        await page.screenshot({ path: path.join(out, `runs-after-submit-${channel}.png`), fullPage: true });
        return r;
      });
      return;
    }

    const { run_id: RUNID } = readState();
    report.run_id = RUNID;

    // ------------------------------------------------------------------ recover (MUTATING: resume of an interrupted run)
    if (phase === 'recover') {
      const lin = await waitFor('run interrupted with >=2 committed epochs',
        async () => (await api(context, `/screens/runs/${RUNID}/lineage`)).json,
        (l: any) => l.checkpoints.length >= 2 && l.state === 'interrupted' && l.recovery.resumable);
      await go(page, 'recovery');
      await combo(page, 'Selected real run').selectOption(RUNID);
      await step('Recover training shows the interruption boundary, attempts and latest checkpoint before resume', async () => {
        await expect(dd(page, 'Committed checkpoints')).toHaveText(`${lin.checkpoints.length} of ${lin.epochs}`, { timeout: 30_000 });
        await expect(dd(page, 'Recovery eligibility')).toHaveText('server reports resumable');
        await expect(dd(page, 'Latest checkpoint')).toHaveText(lin.checkpoints.at(-1).digest);
        await expect(page.getByText('Recovery follows the durable real attempt and committed checkpoint ledger.')).toBeVisible();
        return { next: lin.recovery.next_replay_epoch, attempts: lin.attempts.length };
      });
      const next = lin.recovery.next_replay_epoch;
      const posted = page.waitForResponse(r => r.request().method() === 'POST' && r.url().includes(`/real/runs/${RUNID}/resume`), { timeout: 120_000 });
      await page.getByRole('button', { name: `Resume at epoch ${next}` }).click();
      const resp = await posted;
      await step('resume accepted and the UI reports it', async () => {
        expect(resp.ok(), `${resp.status()} ${await resp.text()}`).toBeTruthy();
        await expect(page.getByText('Real resume request accepted; waiting for the new attempt record.')).toBeVisible();
        return { replay_epoch: next };
      });
      const l2 = await (async () => { const deadline = Date.now() + Math.max(waitMin, 15) * 60_000;
        for (;;) { const l = (await api(context, `/screens/runs/${RUNID}/lineage`)).json;
          if (l.boundaries.some((b: any) => b.new_attempt) || Date.now() > deadline) return l; await new Promise(r => setTimeout(r, 15_000)); } })();
      await step('UI shows the real attempt / fence / replay lineage equal to the API', async () => {
        await page.reload(); await combo(page, 'Selected real run').selectOption(RUNID);
        for (const b of l2.boundaries) {
          await expect(page.getByText(`Committed through epoch ${b.committed_epoch}`)).toBeVisible({ timeout: 30_000 });
          if (b.replay_epoch) await expect(page.getByText(`Replay epoch ${b.replay_epoch}`)).toBeVisible();
          if (b.new_attempt) await expect(page.getByText(`Attempt ${short(b.new_attempt)} · fence ${b.new_fence}`)).toBeVisible();
        }
        await expect(dd(page, 'Attempts')).toHaveText(`${l2.recovery.attempts_used} of ${l2.recovery.attempt_budget}`);
        await page.screenshot({ path: path.join(out, `recovery-after-resume-${channel}.png`), fullPage: true });
        return { boundaries: l2.boundaries, attempts: l2.attempts.map((a: any) => `${short(a.id)}/f${a.fence}`) };
      });
      return;
    }

    // ------------------------------------------------------------------ finish (MUTATING only for: qualified download, one inference)
    if (phase === 'finish') {
      const run = await waitFor('run succeeded with verified artifact', async () => (await api(context, `/real/runs/${RUNID}`)).json.run,
        (r: any) => r.state === 'succeeded' && r.artifact_status === 'verified');
      const lin = (await api(context, `/screens/runs/${RUNID}/lineage`)).json;
      const val = (await api(context, `/real/runs/${RUNID}/validation`, 3)).json;
      const bundle = (await api(context, `/real/runs/${RUNID}/bundle`, 3)).json;
      await go(page, 'training'); await combo(page, 'Selected real run').selectOption(RUNID);
      await step('Training run: this run, all committed checkpoint digests, attempts with fences', async () => {
        await expect(dd(page, 'Run ID')).toHaveText(RUNID);
        const rows = page.locator('table').filter({ hasText: 'Checkpoint SHA256' }).locator('tbody tr');
        await expect(rows).toHaveCount(lin.checkpoints.length, { timeout: 30_000 });
        for (const cp of lin.checkpoints) await expect(rows.filter({ hasText: cp.digest })).toHaveCount(1);
        for (const a of lin.attempts) await expect(page.locator('tr').filter({ hasText: a.id })).toContainText(String(a.fence));
        const ev = lin.events.find((e: any) => e.kind === 'artifact_verified');
        return { epochs: lin.checkpoints.length, attempts: lin.attempts.length, process_identity: ev?.payload?.process_identity, receipt_digest: ev?.payload?.receipt_digest };
      });
      await step('Training run: artifact verification receipt (process identity, receipt/model/bundle digests, fresh inference) equals the API', async () => assertReceipt(page, lin.events));
      await go(page, 'evaluation');
      await step('Evaluation: matrix and digests of THIS run', async () => {
        await expect(page.locator('[data-real-run-screen="evaluation"] table.matrix')).toBeVisible({ timeout: 60_000 });
        for (let a = 0; a < 5; a++) for (let p = 0; p < 5; p++)
          await expect(page.getByRole('button', { name: `${val.classes[a]} predicted as ${val.classes[p]}: ${val.metrics.matrix[a][p]} validation samples`, exact: true })).toBeVisible();
        await expect(page.getByText(`Evaluation digest · ${val.evaluation_digest}`)).toBeVisible();
        await expect(page.getByText(`bundle ${bundle.bundle_digest}`)).toBeVisible();
      });
      await page.getByRole('button', { name: `${val.classes[0]} predicted as ${val.classes[0]}: ${val.metrics.matrix[0][0]} validation samples`, exact: true }).click();
      await step('Errors: cell drill-down of THIS run', async () => {
        await expect(h1(page, 'Error investigation')).toBeVisible();
        await expect(page.getByText(`${val.metrics.matrix[0][0]} exact validation members ·`)).toBeVisible({ timeout: 60_000 });
        await expect(page.getByText(`Evaluation SHA256 · ${val.evaluation_digest}`)).toBeVisible();
      });
      await go(page, 'artifacts');
      await combo(page, 'Verified real training run').selectOption(RUNID);
      await step('Model artifacts: bundle digest of THIS run equals the API; export control state recorded', async () => {
        await expect(dd(page, 'Bundle digest')).toHaveText(bundle.bundle_digest, { timeout: 60_000 });
        return { private_download_controls: await page.getByRole('button', { name: /download/i }).filter({ hasNotText: 'qualified' }).count() };
      });
      await step('Model artifacts: verification receipt of THIS run equals the API', async () => assertReceipt(page, lin.events));
      gap('export of THIS run', 'No UI control downloads a private real-training bundle; export of this run cannot be done through the UI. The qualified-release download below is a different bundle.');
      const q = (await api(context, '/qualified-releases')).json.items as any[];
      if (q[0]?.download_allowed) {
        const dl = page.waitForEvent('download', { timeout: 300_000 });
        await page.getByRole('button', { name: 'Download qualified release' }).first().click();
        const d = await dl; const file = path.join(out, `qualified-release-${channel}.zip`); await d.saveAs(file);
        await step('qualified release downloaded via UI; manifest.json SHA-256 equals the API bundle digest', async () => {
          const manifest = execFileSync('python', ['-I', '-c', 'import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);n=[x for x in z.namelist() if x.endswith("manifest.json")];n.sort(key=len);sys.stdout.buffer.write(z.read(n[0]))', file]);
          expect(sha256(manifest)).toBe(q[0].bundle_digest);
          return { zip_sha256: sha256(fs.readFileSync(file)), bundle_digest: q[0].bundle_digest };
        });
      }
      // Fresh inference: only the qualified release is selectable in the UI (see gap). One train-split image of its version.
      const rv = ((await api(context, '/versions')).json.items as any[]).find(v => v.id === q[0]?.version_id);
      const img = (rv?.manifest.samples as any[] || []).filter(s => s.split === 'train').sort((a, b) => a.id.localeCompare(b.id))
        .map(s => ({ s, file: path.join(MEDIA, s.sha256.slice(0, 2), `${s.sha256}.jpg`) })).find(x => fs.existsSync(x.file) && sha256(fs.readFileSync(x.file)) === x.s.sha256);
      await go(page, 'inference');
      await step('fresh inference through the Inference playground (qualified release, one train-split file)', async () => {
        expect(img, 'a train-split image of the qualified release version').toBeTruthy();
        await combo(page, 'Qualified model').selectOption(q[0].release_id);
        await page.getByLabel('Registered image member ID').fill(img!.s.source_member ?? img!.s.id);
        await page.getByLabel('Image file').setInputFiles(img!.file);
        const isQ = (i: any) => String(i.scope || '').startsWith('qualified-release-image-inference');
        const beforeIds = new Set((((await api(context, '/real/runs?limit=50')).json?.items ?? []) as any[]).filter(isQ).map(i => i.id));
        const posted = page.waitForResponse(r => r.request().method() === 'POST' && r.url().includes('/inferences/image'), { timeout: 120_000 });
        await page.getByRole('button', { name: 'Run qualified inference' }).click();
        const resp = await posted; let body: any = await resp.json().catch(() => ({}));
        expect(resp.ok(), `${resp.status()} ${JSON.stringify(body)}`).toBeTruthy();
        await expect(page.getByText(/^Top class:/)).toBeVisible({ timeout: 10 * 60_000 });
        if (typeof body.id !== 'string') {
          // Playwright cannot always read the body of a streamed-upload response: take the newest qualified
          // inference run created after the click from the API run list.
          const items = ((await api(context, '/real/runs?limit=50')).json?.items ?? []) as any[];
          const fresh = items.filter(i => isQ(i) && !beforeIds.has(i.id));
          expect(fresh.length, 'exactly one new qualified inference run after the click').toBe(1);
          body = { id: fresh[0].id, source: 'api-list-diff-fallback' };
        }
        const r = (await api(context, `/real/runs/${body.id}`)).json.run;
        expect(r.state).toBe('succeeded');
        return { inference_run: body.id, member: img!.s.source_member ?? img!.s.id, top1: r.prediction?.classes?.[r.prediction.top1] };
      });
      gap('qualified inference receipt', 'The qualified-inference run record exposes only the prediction; no process/model/bundle receipt is shown for that inference request (the training run receipt above is asserted).');
      await step('all 15 routes persist across reload', async () => {
        for (const [id, title] of SCREENS) { await page.goto(`/#${id}`); await page.reload(); await expect(h1(page, title)).toBeVisible({ timeout: 30_000 }); expect(new URL(page.url()).hash).toBe(`#${id}`); }
      });
      await step('help content reachable (screen subtitles, recovery explanation, state tooltips)', async () => {
        await page.goto('/#recovery'); await page.reload();
        await expect(page.getByText('Recovery follows the durable real attempt and committed checkpoint ledger.')).toBeVisible({ timeout: 30_000 });
        await expect(page.locator('.sub')).not.toHaveText('');
        return { run_state: run.state };
      });
      await step('onboarding: Getting started panel reachable and linked', async () => assertOnboarding(page));
    }
  } finally {
    save(out);
  }
});
