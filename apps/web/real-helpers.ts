// Shared helpers for the real-record browser journey (real-journey.spec.ts / real-ux.spec.ts).
// READ-ONLY by construction: the only write is the sign-in POST. No route fulfilment/mocks are used anywhere.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { expect, type BrowserContext, type Page } from '@playwright/test';

export const BASE = 'http://127.0.0.1:5102';
export const WS = '814830e3-55a0-4925-ad37-5d3dac7d4df8';
export const RUN = '52374741-86c5-469b-aaba-184ce2b7b80a';
export const REPLAYED_RUN = '7c40ef06-222c-4ad1-b7f0-0e772279bae7';
export const REAL_VERSION = '01a0f1aa-90cd-4875-9060-8c8f0204520b';
export const SCREENS: [string, string][] = [['overview', 'Research workspace'], ['dataset', 'Dataset explorer'], ['sample', 'Sample inspector'],
  ['annotations', 'Annotation review'], ['versions', 'Dataset versions'], ['splits', 'Split integrity'], ['configure', 'Configure training'],
  ['runs', 'Runs & workers'], ['training', 'Training run'], ['evaluation', 'Evaluation results'], ['errors', 'Error investigation'],
  ['recovery', 'Recover training'], ['artifacts', 'Model artifacts'], ['inference', 'Inference playground'], ['settings', 'Workspace & access settings']];
export const short = (id: string) => id.slice(0, 8);
export const sha256 = (value: string | Buffer) => crypto.createHash('sha256').update(value).digest('hex');
/** Same canonical form as fieldwork.data.canonical for a list of strings (ids are ASCII UUIDs). */
export const canonicalDigest = (value: unknown) => sha256(JSON.stringify(value));

export function outDir(): string {
  const out = process.env.REAL_OUT;
  if (!out) throw new Error('REAL_OUT (fresh evidence directory) is required');
  fs.mkdirSync(out, { recursive: true });
  return out;
}

/** Sign in as the private real-data actor. The password is read from the private file and used only for this POST. */
export async function login(context: BrowserContext) {
  const actor = JSON.parse(fs.readFileSync('../../.local/real-data/local-completion-actor.private.json', 'utf8'));
  expect(actor.workspace).toBe(WS);
  const response = await context.request.post(`${BASE}/auth/session`, { data: { name: actor.name, password: actor.password } });
  expect(response.status()).toBe(200);
  const who = await response.json();
  expect(who.workspace).toBe(WS);
  return { name: String(who.name), role: String(who.role) };
}

/** Independent API read through the same cookie jar as the page (GET only). */
export async function api<T = any>(context: BrowserContext, p: string, attempts = 1): Promise<{ status: number; json: T }> {
  let last: { status: number; json: T } = { status: 0, json: null as T };
  for (let i = 0; i < attempts; i++) {
    const r = await context.request.get(`${BASE}/api/v1/workspaces/${WS}${p}`, { timeout: 90_000 });
    last = { status: r.status(), json: await r.json().catch(() => null) as T };
    if (last.status === 200) return last;
    await new Promise(res => setTimeout(res, 5000));
  }
  return last;
}

export type Fact = { screen: string; name: string; pass: boolean; expected?: unknown; observed?: unknown; error?: string };
export class Recorder {
  facts: Fact[] = [];
  /** Run one named assertion; the failure is recorded and the journey continues (reported at the end). */
  async check(screen: string, name: string, fn: () => Promise<{ expected?: unknown; observed?: unknown } | void>) {
    try {
      const r = (await fn()) || {};
      this.facts.push({ screen, name, pass: true, expected: r.expected, observed: r.observed });
    } catch (e) {
      this.facts.push({ screen, name, pass: false, error: String((e as Error).message).split('\n').slice(0, 6).join(' | ') });
    }
  }
  failures() { return this.facts.filter(f => !f.pass); }
}

/** Retry a UI-vs-API comparison whose live value may legitimately change between the two reads. */
export async function settled<T>(fn: () => Promise<T>, attempts = 3): Promise<T> {
  let err: unknown;
  for (let i = 0; i < attempts; i++) {
    try { return await fn(); } catch (e) { err = e; }
  }
  throw err;
}

export const nav = (page: Page, title: string) => page.getByRole('navigation').getByRole('button', { name: title, exact: true });
export const h1 = (page: Page, title: string) => page.getByRole('heading', { level: 1, name: title, exact: true });

export function bundleDir(run = RUN) {
  const root = path.resolve('../../var/runs', run);
  const leaf = fs.readdirSync(root).find(d => /^real-artifact-attempt-\d+$/.test(d));
  if (!leaf) throw new Error('no artifact attempt directory');
  return path.join(root, leaf, 'bundle');
}

export async function browserFacts(page: Page) {
  const browser = page.context().browser();
  return { browser: browser?.browserType().name(), version: browser?.version(), userAgent: await page.evaluate(() => navigator.userAgent) };
}
