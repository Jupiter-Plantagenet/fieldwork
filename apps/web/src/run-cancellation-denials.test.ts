import test from 'node:test';
import assert from 'node:assert/strict';
import { createCancellationAction } from './run-cancellation.ts';

test('response loss retries the exact original command and never claims a running child has exited', async () => {
  let minted = 0;
  const sent: RequestInit[] = [];
  const action = createCancellationAction({
    base: '/api/v1/workspaces/synthetic-lab',
    run: { id: 'unit-running', state: 'running', revision: 4 },
    role: 'researcher', csrf: 'unit-csrf',
    key: () => { minted += 1; return minted === 1 ? '11111111-1111-4111-8111-111111111111' : '22222222-2222-4222-8222-222222222222'; },
    fetch: async (_url, options) => {
      sent.push(options);
      if (sent.length === 1) throw new Error('response lost');
      return new Response(JSON.stringify({ state: 'cancel_requested', completion_won: false }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      });
    },
    refresh: async () => {},
  });
  await assert.rejects(action.submit('Stop this run'), /response lost/);
  assert.equal(action.busy, false);
  await assert.rejects(action.submit('Different command'), /ORIGINAL_COMMAND_REQUIRED/);
  assert.equal(sent.length, 1);
  await action.submit('Stop this run');
  assert.equal(minted, 1);
  assert.equal(sent.length, 2);
  assert.equal(new Headers(sent[0].headers).get('Idempotency-Key'), new Headers(sent[1].headers).get('Idempotency-Key'));
  assert.equal(sent[0].body, sent[1].body);
  assert.match(action.message, /waiting.*exit/i);
});

test('browser preserves accepted long reasons including non-BMP characters', async () => {
  for (const reason of ['x'.repeat(1500), '🌿'.repeat(1500)]) {
    let sent = 0;
    const action = createCancellationAction({
      base: '/api/v1/workspaces/synthetic-lab',
      run: { id: 'unit-run', state: 'queued', revision: 1 },
      role: 'researcher', csrf: 'unit-csrf', key: () => '11111111-1111-4111-8111-111111111111',
      fetch: async (_url, options) => {
        sent += 1;
        assert.equal(JSON.parse(String(options.body)).reason, reason);
        return new Response(JSON.stringify({ state: 'cancelled', completion_won: false }), {
          status: 200, headers: { 'Content-Type': 'application/json' },
        });
      },
      refresh: async () => {},
    });
    await action.submit(reason);
    assert.equal(sent, 1);
  }
});

test('a malformed success response is not presented as confirmed cancellation', async () => {
  let refreshed = 0;
  const action = createCancellationAction({
    base: '/api/v1/workspaces/synthetic-lab',
    run: { id: 'unit-run', state: 'queued', revision: 1 },
    role: 'researcher', csrf: 'unit-csrf', key: () => '11111111-1111-4111-8111-111111111111',
    fetch: async () => new Response(JSON.stringify({ state: 'running', completion_won: false }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }),
    refresh: async () => { refreshed += 1; },
  });
  await assert.rejects(action.submit('Stop'), /INVALID_CANCELLATION_RESPONSE/);
  assert.equal(refreshed, 0);
  assert.match(action.message, /not confirmed/i);
});

test('viewer, terminal run and blank reason cannot send a cancellation', async () => {
  for (const scenario of [
    { role: 'viewer', state: 'queued', reason: 'Stop', error: /ROLE_DENIED/ },
    { role: 'researcher', state: 'succeeded', reason: 'Stop', error: /RUN_NOT_CANCELLABLE/ },
    { role: 'researcher', state: 'cancel_requested', reason: 'Stop', error: /RUN_NOT_CANCELLABLE/ },
    { role: 'researcher', state: 'queued', reason: '   ', error: /REASON_REQUIRED/ },
    { role: 'researcher', state: 'queued', reason: 'x'.repeat(2001), error: /REASON_TOO_LONG/ },
    { role: 'researcher', state: 'queued', reason: '🌿'.repeat(2001), error: /REASON_TOO_LONG/ },
  ]) {
    let sent = 0;
    const action = createCancellationAction({
      base: '/api/v1/workspaces/synthetic-lab',
      run: { id: 'unit-run', state: scenario.state, revision: 1 },
      role: scenario.role, csrf: 'unit-csrf', key: () => 'unit-unused',
      fetch: async () => { sent += 1; throw new Error('MUST_NOT_SEND'); },
      refresh: async () => {},
    });
    await assert.rejects(action.submit(scenario.reason), scenario.error);
    assert.equal(sent, 0);
    assert.equal(action.busy, false);
  }
});
