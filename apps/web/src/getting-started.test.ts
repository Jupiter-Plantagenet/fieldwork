import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { GettingStarted, GETTING_STARTED_STEPS } from './getting-started.ts';

test('getting started lists the real flow in order with a keyboard-reachable button per screen', () => {
  assert.deepEqual(GETTING_STARTED_STEPS.map(s => s.screen),
    ['dataset', 'versions', 'splits', 'configure', 'runs', 'recovery', 'artifacts', 'inference']);
  const html = renderToStaticMarkup(React.createElement(GettingStarted, { go: () => {} }));
  assert.match(html, /<section[^>]+aria-labelledby="getting-started-title"/);
  assert.match(html, /<h2 id="getting-started-title" tabindex="-1">Getting started<\/h2>/);
  assert.equal((html.match(/<li/g) || []).length, GETTING_STARTED_STEPS.length);
  assert.equal((html.match(/<button type="button"/g) || []).length, GETTING_STARTED_STEPS.length);
  assert.match(html, /Qualified release/);
  assert.match(html, /resume replays the next whole epoch/i);
});

test('a step button navigates to its screen', () => {
  const seen: string[] = [];
  const el = GettingStarted({ go: (id: string) => seen.push(id) }) as React.ReactElement<any>;
  const list = (el.props.children as any[]).find((c: any) => c?.type === 'ol');
  const firstButton = list.props.children[0].props.children.find((c: any) => c?.type === 'button');
  firstButton.props.onClick();
  assert.deepEqual(seen, ['dataset']);
});
