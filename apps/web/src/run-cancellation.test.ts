import test from 'node:test';
import assert from 'node:assert/strict';
import { createCancellationAction } from './run-cancellation.ts';

// Ordinary frontend transport test. No API, database, account or worker is started.
// The fetch boundary is deliberately controlled; it does not establish backend
// enforcement of revision/idempotency; PostgreSQL integration is a separate gate.
test('confirmed cancellation posts the displayed revision once and refreshes before becoming idle', async () => {
  const calls: { url: string; options: RequestInit }[] = [];
  let release!: (response: Response) => void;
  let refreshed = 0;
  const action = createCancellationAction({
    base: '/api/v1/workspaces/synthetic-lab',
    run: { id: 'run-queued', state: 'queued', revision: 7 },
    role: 'researcher',
    csrf: 'test-session-csrf',
    key: () => '11111111-1111-4111-8111-111111111111',
    fetch: async (url: string, options: RequestInit) => {
      calls.push({ url, options });
      return new Promise<Response>(resolve => { release = resolve; });
    },
    refresh: async () => { refreshed += 1; },
  });

  const submitted = action.submit('Stop this queued experiment');
  assert.equal(action.busy, true);
  await action.submit('Stop this queued experiment');
  assert.equal(calls.length, 1, 'a second click must not send a second request');
  assert.equal(calls[0].url, '/api/v1/workspaces/synthetic-lab/runs/run-queued/cancel');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.credentials, 'same-origin');
  const headers = new Headers(calls[0].options.headers);
  assert.equal(headers.get('X-CSRF-Token'), 'test-session-csrf');
  assert.equal(headers.get('Idempotency-Key'), '11111111-1111-4111-8111-111111111111');
  assert.equal(headers.get('If-Match'), '"7"');
  assert.equal(headers.get('Content-Type'), 'application/json');
  assert.deepEqual(JSON.parse(String(calls[0].options.body)), {
    expected_revision: 7,
    reason: 'Stop this queued experiment',
  });
  release(new Response(JSON.stringify({ state: 'cancelled', completion_won: false }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  }));
  await submitted;
  assert.equal(refreshed, 1);
  assert.equal(action.busy, false);
  assert.match(action.message, /cancelled/i);
});
