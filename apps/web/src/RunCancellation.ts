import React, { useRef, useState } from 'react';
import { createCancellationSession, type CancellationSession } from './run-cancellation.ts';

type Props = {
  base: string;
  run: { id: string; state: string; revision: number };
  role: string;
  csrf: string;
  enabled: boolean;
  session?: CancellationSession;
  refresh: () => Promise<void>;
};

export function RunCancellation({ base, run, role, csrf, enabled, refresh, session }: Props) {
  const localSession = useRef<CancellationSession | null>(null);
  if (!localSession.current) localSession.current = createCancellationSession();
  const commands = session ?? localSession.current;
  const [reason, setReason] = useState(() => commands.pendingReason(base, run.id) ?? '');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const pending = useRef(false);


  if (run.state === 'cancel_requested') {
    return React.createElement('p', { role: 'status' },
      'Cancellation requested; waiting for worker exit confirmation.');
  }
  if (!['researcher', 'owner'].includes(role) || !['queued', 'running', 'interrupted'].includes(run.state)) return null;
  if (!enabled) {
    const feedback = message || commands.pendingMessage(base, run.id);
    return React.createElement(React.Fragment, null,
      React.createElement('p', { role: 'status' },
        'Cancellation unavailable until current workspace records and a compatible backend are ready.'),
      feedback ? React.createElement('p', { role: 'status' }, feedback) : null);
  }

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!enabled || pending.current) return;
    const action = commands.action({
      base, run: { id: run.id, state: run.state, revision: run.revision }, role, csrf,
      key: () => crypto.randomUUID(), fetch: (url, options) => fetch(url, options), refresh,
    });
    if (action.busy) {
      setMessage('The original cancellation is still in flight. Wait before retrying.');
      return;
    }
    pending.current = true;
    setBusy(true);
    setMessage('');
    try {
      await action.submit(reason);
      setMessage(action.message);
    } catch (error) {
      setMessage(error instanceof Error && error.message === 'ORIGINAL_COMMAND_REQUIRED'
        ? 'The earlier outcome is unknown. Retry with the original reason, or refresh and review the run.'
        : action.message || String(error));
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }

  const id = `cancel-reason-${run.id}`;
  const count = Array.from(reason).length;
  return React.createElement('form', { onSubmit: submit, 'aria-label': 'Cancel this run' },
    React.createElement('h3', null, 'Cancel this run'),
    React.createElement('p', null, 'Queued work can stop immediately. Running work requires worker exit confirmation.'),
    React.createElement('label', { htmlFor: id }, 'Cancellation reason'),
    React.createElement('textarea', {
      id, name: 'reason', required: true, maxLength: 4000, value: reason, disabled: busy,
      'aria-describedby': `${id}-limit`,
      onChange: (event: React.ChangeEvent<HTMLTextAreaElement>) => setReason(event.target.value),
    }),
    React.createElement('p', { id: `${id}-limit` }, `${count} / 2000 characters`),
    React.createElement('button', { type: 'submit', disabled: busy || !reason.trim() || count > 2000 },
      busy ? 'Requesting cancellation…' : 'Request cancellation'),
    React.createElement('p', { role: 'status', 'aria-live': 'polite' }, message),
  );
}
