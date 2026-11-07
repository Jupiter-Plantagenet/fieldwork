import React from 'react';

type Ev = { seq: string; kind: string; created: string; payload: Record<string, unknown> | null };
export type Receipt = { code: string; process_identity: string; receipt_digest: string; model_digest: string; bundle_digest: string;
  checkpoint_digest: string; rights_members: number | null; evidence_scope: string; verified_at: string;
  inference: { code: string; bundle_digest: string; checkpoint_digest: string; at: string } | null };

const str = (v: unknown) => typeof v === 'string' ? v : '';
/** Whitelisted fields of the run's own latest artifact_verified event (public lineage events); nothing else is read. */
export function artifactReceipt(events: Ev[]): Receipt | null {
  const verified = [...events].reverse().find(e => e.kind === 'artifact_verified' && e.payload);
  if (!verified) return null;
  const p = verified.payload!;
  const inf = [...events].reverse().find(e => e.kind === 'artifact_inference' && e.payload && Number(e.seq) < Number(verified.seq));
  return { code: str(p.code), process_identity: str(p.process_identity), receipt_digest: str(p.receipt_digest), model_digest: str(p.model_digest),
    bundle_digest: str(p.bundle_digest), checkpoint_digest: str(p.checkpoint_digest), evidence_scope: str(p.evidence_scope),
    rights_members: typeof p.rights_members === 'number' ? p.rights_members : null, verified_at: verified.created,
    inference: inf ? { code: str(inf.payload!.code), bundle_digest: str(inf.payload!.bundle_digest), checkpoint_digest: str(inf.payload!.checkpoint_digest), at: inf.created } : null };
}

const h = React.createElement;
export function ArtifactReceipt({ events }: { events: Ev[] }) {
  const r = artifactReceipt(events);
  if (!r) {
    const last = [...events].reverse().find(e => e.kind.startsWith('artifact_'));
    const code = last?.payload && typeof last.payload.code === 'string' ? ` · ${last.payload.code}` : '';
    return h('div', { className: 'callout', 'data-state': 'receipt_unavailable' },
      h('b', null, 'No artifact verification receipt yet.'), ' ',
      last ? `Latest artifact event: ${last.kind}${code}.` : 'No artifact stage has started.');
  }
  const row = (field: string, label: string, value: React.ReactNode, hash = true) => [
    h('dt', { key: field + ':t' }, label),
    h('dd', { key: field + ':d', className: hash ? 'hash' : undefined, 'data-receipt-field': field }, value)];
  return h('section', { className: 'stack', 'aria-labelledby': 'artifact-receipt-title', 'data-receipt': r.code },
    h('h3', { id: 'artifact-receipt-title' }, 'Artifact verification receipt'),
    h('p', { className: 'inline-note' }, `${r.code} · verified ${r.verified_at} · evidence scope ${r.evidence_scope || 'not reported'}`),
    h('dl', { className: 'detail' },
      ...row('process_identity', 'Verifying process', r.process_identity),
      ...row('receipt_digest', 'Receipt SHA256', r.receipt_digest),
      ...row('model_digest', 'Model SHA256', r.model_digest),
      ...row('bundle_digest', 'Bundle SHA256', r.bundle_digest),
      ...row('checkpoint_digest', 'Checkpoint SHA256', r.checkpoint_digest),
      ...row('rights_members', 'Rights members checked', r.rights_members ?? 'not reported', false),
      ...row('inference', 'Fresh inference', r.inference
        ? `Fresh inference stage ${r.inference.code} at ${r.inference.at} on checkpoint ${r.inference.checkpoint_digest.slice(0, 12)}… → verified`
        : 'not reported', false)));
}
