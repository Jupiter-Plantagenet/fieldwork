import test from 'node:test';
import assert from 'node:assert/strict';
import { createCancellationSession } from './run-cancellation.ts';

test('pending command identity survives polling revisions and uses the original If-Match', async () => {
  const session = createCancellationSession();
  let minted = 0;
  const sent: RequestInit[] = [];
  const options = {
    base: '/api/v1/workspaces/authored-lab',
    run: { id: 'authored-run', state: 'running', revision: 7 },
    role: 'researcher', csrf: 'authored-csrf',
    key: () => { minted += 1; return `authored-key-${minted}`; },
    fetch: async (_url: string, request: RequestInit) => {
      sent.push(request);
      if (sent.length === 1) throw new Error('response lost');
      return new Response(JSON.stringify({ state: 'cancel_requested', completion_won: false }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      });
    },
    refresh: async () => {},
  };
  const first = session.action(options);
  await assert.rejects(first.submit('Stop this authored run'), /response lost/);
  const afterPoll = session.action({ ...options, run: { ...options.run, revision: 8 } });
  assert.equal(afterPoll, first, 'polling must retain the outstanding command');
  await afterPoll.submit('Stop this authored run');
  assert.equal(minted, 1);
  assert.equal(sent.length, 2);
  assert.equal(sent[0].body, sent[1].body);
  assert.equal(new Headers(sent[1].headers).get('If-Match'), '"7"');
});

test('a confirmed stale rejection refreshes records before a new explicit command', async () => {
  const session = createCancellationSession();
  let minted = 0, refreshed = 0;
  const sent: RequestInit[] = [];
  const options = {
    base: '/api/v1/workspaces/authored-lab',
    run: { id: 'authored-run', state: 'running', revision: 7 },
    role: 'researcher', csrf: 'authored-csrf',
    key: () => `authored-key-${++minted}`,
    fetch: async (_url: string, request: RequestInit) => {
      sent.push(request);
      return sent.length === 1
        ? new Response(JSON.stringify({ code: 'STALE_REVISION', object_revision: 8 }), { status: 412 })
        : new Response(JSON.stringify({ state: 'cancel_requested', completion_won: false }), { status: 200 });
    },
    refresh: async () => { refreshed += 1; },
  };
  const stale = session.action(options);
  await assert.rejects(stale.submit('Stop this authored run'), /STALE_REVISION/);
  assert.equal(sent.length, 1, 'a stale response must not automatically submit another command');
  assert.equal(refreshed, 1);
  const reviewed = session.action({ ...options, run: { ...options.run, revision: 8 } });
  assert.notEqual(reviewed, stale);
  await reviewed.submit('Stop this authored run');
  assert.equal(minted, 2);
  assert.equal(new Headers(sent[1].headers).get('If-Match'), '"8"');
  assert.equal(JSON.parse(sent[1].body as string).expected_revision, 8);
});
