import test from 'node:test';
import assert from 'node:assert/strict';
import { refreshWorkspace } from './workspace-refresh.ts';
import { createCancellationSession } from './run-cancellation.ts';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { RunCancellation } from './RunCancellation.ts';

test('a refused cancellation cannot describe a failed snapshot refresh as refreshed records', async () => {
  let finished = 0, reported = 0, applied = 0, sent = 0;
  const session = createCancellationSession();
  const refresh = () => refreshWorkspace(
    async () => { throw new Error('authored-snapshot-unavailable'); },
    () => { applied += 1; },
    () => { reported += 1; },
    () => { finished += 1; },
  );
  const options = {
    base: '/api/v1/workspaces/authored-lab',
    run: { id: 'authored-run', revision: 7, state: 'running' },
    role: 'researcher', csrf: 'authored-csrf', key: () => 'authored-key', refresh,
    fetch: async () => {
      sent += 1;
      return new Response(JSON.stringify({ code: 'STALE_REVISION', object_revision: 8 }), { status: 412 });
    },
  };
  const action = session.action(options);
  await assert.rejects(action.submit('Keep this original reason'), /authored-snapshot-unavailable/);
  assert.equal(finished, 1);
  assert.equal(reported, 1);
  assert.equal(applied, 0);
  assert.equal(sent, 1);
  assert.equal(action.pending, true);
  assert.equal(session.action({ ...options, run: { ...options.run, revision: 8 } }), action);
  assert.match(action.message, /refused.*refresh.*failed/i);
  assert.doesNotMatch(action.message, /review the refreshed records/i);
  const disabledView = renderToStaticMarkup(React.createElement(RunCancellation, {
    base: options.base, run: options.run, role: options.role, csrf: options.csrf,
    enabled: false, refresh, session,
  }));
  assert.doesNotMatch(disabledView, /<form/);
  assert.match(disabledView, /refused.*refresh.*failed/i,
    'the offline compatibility gate must not hide the known refusal and refresh failure');
});
