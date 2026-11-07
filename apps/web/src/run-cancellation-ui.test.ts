import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { RunCancellation } from './RunCancellation.ts';
import { createCancellationSession } from './run-cancellation.ts';

const props = {
  base: '/api/v1/workspaces/synthetic-lab',
  run: { id: 'unit-run', revision: 3, state: 'queued' },
  role: 'researcher', csrf: 'unit-only-csrf', enabled: true, refresh: async () => {},
};

test('eligible run exposes a required labelled reason and explicit cancellation action', () => {
  const html = renderToStaticMarkup(React.createElement(RunCancellation, props));
  assert.match(html, /Cancel this run/);
  assert.match(html, /<label[^>]+for="cancel-reason-unit-run"/);
  assert.match(html, /<textarea[^>]+id="cancel-reason-unit-run"[^>]+required/);
  assert.match(html, /maxlength="4000"/i);
  assert.match(html, /Request cancellation/);
});

test('a legacy or unavailable backend cannot expose the new cancellation form', () => {
  const html = renderToStaticMarkup(React.createElement(RunCancellation, { ...props, enabled: false }));
  assert.doesNotMatch(html, /<form/);
  assert.match(html, /compatible backend/i);
});

test('viewer and terminal run do not render an actionable cancellation form', () => {
  for (const change of [{ role: 'viewer' }, { run: { ...props.run, state: 'succeeded' } }]) {
    const html = renderToStaticMarkup(React.createElement(RunCancellation, { ...props, ...change }));
    assert.doesNotMatch(html, /<form/);
  }
});

test('cancel-requested state explains that physical worker exit is still pending', () => {
  const html = renderToStaticMarkup(React.createElement(RunCancellation, {
    ...props, run: { ...props.run, state: 'cancel_requested' },
  }));
  assert.doesNotMatch(html, /<form/);
  assert.match(html, /waiting for worker exit confirmation/);
});

test('a remounted view restores the unresolved command reason from its workspace session', async () => {
  const session = createCancellationSession();
  const action = session.action({
    ...props, key: () => 'authored-retry-key',
    fetch: async () => { throw new Error('response lost'); },
  });
  await assert.rejects(action.submit('Keep this original reason'), /response lost/);
  const html = renderToStaticMarkup(React.createElement(RunCancellation, {
    ...props, run: { ...props.run, revision: 4 }, session,
  }));
  assert.match(html, /<textarea[^>]*>Keep this original reason<\/textarea>/);
});
