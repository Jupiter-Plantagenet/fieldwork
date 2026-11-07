import React from 'react';

export const GETTING_STARTED_STEPS = [
  { screen: 'dataset', title: 'Dataset explorer', text: 'Queue a rights-cleared image archive; the intake reports accepted, duplicate, no-op and rejected members with reasons.' },
  { screen: 'versions', title: 'Dataset versions', text: 'Create a real working draft from an accepted intake, have another account review the exact version, then freeze it.' },
  { screen: 'splits', title: 'Split integrity', text: 'Check group-disjoint train/validation membership; holdout stays sealed and shows aggregates only.' },
  { screen: 'configure', title: 'Configure training', text: 'Choose a frozen real version and parameters; the server rechecks rights and resource preflight before queueing.' },
  { screen: 'runs', title: 'Runs & workers', text: 'Follow the queued run; progress appears only when the worker commits it. Cancellation is final.' },
  { screen: 'recovery', title: 'Recover training', text: 'An interrupted run (lost worker or lease) resumes from its latest committed checkpoint.' },
  { screen: 'artifacts', title: 'Model artifacts', text: 'Inspect the verified private bundle and its verification receipt; private candidates are not exported.' },
  { screen: 'inference', title: 'Inference playground', text: 'Run fresh inference against the Qualified release on a rights-registered image.' },
] as const;

const h = React.createElement;
/** Short orientation for the real-data flow, with a keyboard-reachable button to each screen. */
export function GettingStarted({ go }: { go: (screen: string) => void }) {
  return h('section', { className: 'panel', 'aria-labelledby': 'getting-started-title', 'data-help': 'getting-started' },
    h('h2', { id: 'getting-started-title', tabIndex: -1 }, 'Getting started'),
    h('p', null, 'The real-data flow, in order. Every step is checked again by the server; nothing here is a shortcut.'),
    h('ol', { className: 'stack' }, GETTING_STARTED_STEPS.map((s, i) => h('li', { key: s.screen },
      h('button', { type: 'button', onClick: () => go(s.screen) }, `${i + 1}. ${s.title}`), ' ', h('span', null, s.text)))),
    h('p', { className: 'inline-note', 'data-help': 'recovery' }, 'Recovery help: a cancelled run is final. A run whose worker was lost becomes interrupted; resume replays the next whole epoch from the latest committed checkpoint, and partial work never counts.'));
}
