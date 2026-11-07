import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ArtifactReceipt, artifactReceipt } from './real-receipt.ts';

const verified = { seq: '405', kind: 'artifact_verified', created: '2026-11-02T13:51:39Z', payload: {
  code: 'REAL_PRIVATE_BUNDLE_VERIFIED', scope: 'real-training/v1', status: 'verified', model_digest: 'm'.repeat(64),
  bundle_digest: 'b'.repeat(64), evidence_scope: 'validation_only', receipt_digest: 'r'.repeat(64), rights_members: 3108,
  process_identity: '71109b29-fa17-47b3-aae9-9fb4ed5ea642', checkpoint_digest: 'c'.repeat(64),
  artifact_directory: 'real-artifact-attempt-1', unexpected_private_field: 'SECRET-SHOULD-NOT-RENDER' } };
const inference = { seq: '404', kind: 'artifact_inference', created: '2026-11-02T13:51:15Z', payload: {
  code: 'REAL_FRESH_INFERENCE_PENDING', status: 'inference', bundle_digest: 'b'.repeat(64), checkpoint_digest: 'c'.repeat(64) } };

test('the verified receipt exposes exactly the whitelisted fields of the latest artifact_verified event', () => {
  const r = artifactReceipt([inference, verified]);
  assert.equal(r?.process_identity, '71109b29-fa17-47b3-aae9-9fb4ed5ea642');
  assert.equal(r?.receipt_digest, 'r'.repeat(64));
  assert.equal(r?.model_digest, 'm'.repeat(64));
  assert.equal(r?.bundle_digest, 'b'.repeat(64));
  assert.equal(r?.inference?.code, 'REAL_FRESH_INFERENCE_PENDING');
  const html = renderToStaticMarkup(React.createElement(ArtifactReceipt, { events: [inference, verified] }));
  for (const field of ['process_identity', 'receipt_digest', 'model_digest', 'bundle_digest', 'checkpoint_digest', 'rights_members', 'inference'])
    assert.match(html, new RegExp(`data-receipt-field="${field}"`));
  assert.match(html, /71109b29-fa17-47b3-aae9-9fb4ed5ea642/);
  assert.match(html, /Fresh inference/);
  assert.doesNotMatch(html, /SECRET-SHOULD-NOT-RENDER|real-artifact-attempt/);
});

test('no verified event: an honest pending/failed state and no fabricated receipt', () => {
  assert.equal(artifactReceipt([inference]), null);
  const html = renderToStaticMarkup(React.createElement(ArtifactReceipt, { events: [inference,
    { seq: '406', kind: 'artifact_failed', created: 'x', payload: { code: 'REAL_BUNDLE_INTEGRITY' } }] }));
  assert.match(html, /No artifact verification receipt/);
  assert.match(html, /REAL_BUNDLE_INTEGRITY/);
  assert.doesNotMatch(html, /data-receipt-field="process_identity"/);
});
