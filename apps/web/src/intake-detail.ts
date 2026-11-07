import React from 'react';

export type IntakeDetailView = { batch_state: string; source_total: number | null; accepted: number | null; rejected: number | null;
  duplicate: number | null; noop: number | null; new_sample_ids: number | null; non_accepted_truncated: boolean;
  non_accepted: { member: string; disposition: string; reason: string }[] };
type CountKey = 'source_total' | 'accepted' | 'duplicate' | 'noop' | 'rejected' | 'new_sample_ids';
const h = React.createElement;
const COUNTS: [CountKey, string][] = [['source_total', 'Archive members'], ['accepted', 'Accepted'], ['duplicate', 'Duplicate'],
  ['noop', 'Already imported (no-op)'], ['rejected', 'Rejected'], ['new_sample_ids', 'New sample IDs']];

/** Aggregate dispositions and the reasons for members that were not accepted (the API never lists accepted members). */
export function IntakeDetail({ detail }: { detail: IntakeDetailView | null | undefined }) {
  if (!detail) return h('p', { className: 'inline-note', 'data-intake-detail': 'pending' }, 'Disposition counts and reasons appear when processing finishes.');
  return h('div', { className: 'stack', 'data-intake-detail': detail.batch_state },
    h('dl', { className: 'detail' }, ...COUNTS.flatMap(([k, label]) => [h('dt', { key: k + ':t' }, label),
      h('dd', { key: k + ':d', 'data-intake-count': k }, String(detail[k] ?? '—'))])),
    detail.non_accepted.length ? h('div', { className: 'tablewrap', tabIndex: 0, role: 'region', 'aria-label': 'Members not accepted (scrollable)' },
      h('table', null, h('caption', null, 'Members not accepted'),
        h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Member'), h('th', { scope: 'col' }, 'Disposition'), h('th', { scope: 'col' }, 'Reason code'))),
        h('tbody', null, ...detail.non_accepted.map((m, i) => h('tr', { key: i, 'data-intake-member': m.disposition },
          h('th', { scope: 'row' }, m.member), h('td', null, m.disposition), h('td', null, m.reason)))))) : null,
    detail.non_accepted_truncated ? h('p', { className: 'inline-note' }, 'Only the first 500 non-accepted members are listed; the counts above are complete.') : null);
}
