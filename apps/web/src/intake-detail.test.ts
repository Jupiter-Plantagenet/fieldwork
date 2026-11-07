import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { IntakeDetail } from './intake-detail.ts';

const detail = { batch_state: 'complete', source_total: 5, accepted: 0, rejected: 1, duplicate: 1, noop: 3, new_sample_ids: 0,
  non_accepted_truncated: false, non_accepted: [
    { member: 'a.jpg', disposition: 'noop', reason: 'RAW_DIGEST_ALREADY_IMPORTED' },
    { member: 'b.jpg', disposition: 'duplicate', reason: 'PIXEL_IDENTICAL_DIFFERENT_ENCODING' },
    { member: 'notes.txt', disposition: 'rejected', reason: 'NOT_AN_IMAGE_MEMBER' }] };

test('counts and a reasons table for non-accepted members', () => {
  const html = renderToStaticMarkup(React.createElement(IntakeDetail, { detail }));
  for (const [k, v] of [['source_total', 5], ['accepted', 0], ['rejected', 1], ['duplicate', 1], ['noop', 3], ['new_sample_ids', 0]])
    assert.match(html, new RegExp(`data-intake-count="${k}"[^>]*>${v}<`));
  assert.match(html, /<caption>Members not accepted<\/caption>/);
  assert.match(html, /<th scope="row">notes\.txt<\/th><td>rejected<\/td><td>NOT_AN_IMAGE_MEMBER<\/td>/);
  assert.equal((html.match(/<tr data-intake-member/g) || []).length, 3);
});

test('pending detail and truncation are stated, never invented', () => {
  assert.match(renderToStaticMarkup(React.createElement(IntakeDetail, { detail: null })), /appear when processing finishes/);
  const html = renderToStaticMarkup(React.createElement(IntakeDetail, { detail: { ...detail, non_accepted_truncated: true } }));
  assert.match(html, /first 500/);
  assert.doesNotMatch(renderToStaticMarkup(React.createElement(IntakeDetail, { detail: { ...detail, non_accepted: [] } })), /<table/);
});
