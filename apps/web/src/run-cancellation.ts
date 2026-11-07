type CancellationOptions = {
  base: string;
  run: { id: string; state: string; revision: number };
  role: string;
  csrf: string;
  key: () => string;
  fetch: (url: string, options: RequestInit) => Promise<Response>;
  refresh: () => Promise<void>;
};

/** Real browser transport. Server authorization and durable receipts remain required. */
export function createCancellationAction(options: CancellationOptions) {
  let busy = false;
  let pending = false;
  let message = '';
  let command: { key: string; reason: string; body: string } | undefined;
  return {
    get busy() { return busy; },
    get pending() { return pending; },
    get originalReason() { return command?.reason; },
    get message() { return message; },
    async submit(reason: string) {
      if (busy) return;
      if (!['researcher', 'owner'].includes(options.role)) throw new Error('ROLE_DENIED');
      if (!['queued', 'running', 'interrupted'].includes(options.run.state)) throw new Error('RUN_NOT_CANCELLABLE');
      if (!reason.trim()) throw new Error('REASON_REQUIRED');
      if (Array.from(reason).length > 2000) throw new Error('REASON_TOO_LONG');
      if (command && command.reason !== reason) throw new Error('ORIGINAL_COMMAND_REQUIRED');
      command ??= { key: options.key(), reason,
        body: JSON.stringify({ expected_revision: options.run.revision, reason }) };
      pending = true;
      busy = true;
      let staleRejected = false;
      try {
        const response = await options.fetch(`${options.base}/runs/${options.run.id}/cancel`, {
          method: 'POST', credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json', 'X-CSRF-Token': options.csrf,
            'Idempotency-Key': command.key, 'If-Match': `"${options.run.revision}"`,
          },
          body: command.body,
        });
        if (response.status === 412) {
          const refusal = await response.json() as { code?: unknown; object_revision?: unknown } | null;
          if (refusal?.code === 'STALE_REVISION'
            && typeof refusal.object_revision === 'number'
            && Number.isSafeInteger(refusal.object_revision) && refusal.object_revision > 0) {
            staleRejected = true;
            await options.refresh();
            pending = false;
            throw new Error('STALE_REVISION');
          }
        }
        if (!response.ok) throw new Error(`Cancellation failed (${response.status})`);
        const result = await response.json() as { state: string; completion_won: boolean } | null;
        if (!result || typeof result.state !== 'string'
          || !['cancelled', 'cancel_requested', 'succeeded', 'failed'].includes(result.state)
          || typeof result.completion_won !== 'boolean') {
          throw new Error('INVALID_CANCELLATION_RESPONSE');
        }
        await options.refresh();
        pending = false;
        message = result.state === 'cancel_requested'
          ? 'Cancellation requested; waiting for worker exit confirmation.'
          : `Run ${result.state}.`;
      } catch (error) {
        message = staleRejected
          ? pending
            ? 'Cancellation was refused because the run changed, and refreshing records failed. Retry the original command or refresh records.'
            : 'The run changed. Review the refreshed records before requesting cancellation again.'
          : 'Cancellation not confirmed. Retry the original command or refresh records.';
        throw error;
      } finally {
        busy = false;
      }
    },
  };
}

/** Own this at the signed-in workspace level, not at a polled row/view level. */
export function createCancellationSession() {
  const actions = new Map<string, {
    options: CancellationOptions;
    action: ReturnType<typeof createCancellationAction>;
  }>();
  return {
    pendingReason(base: string, runId: string) {
      const existing = actions.get(JSON.stringify([base, runId]));
      return existing?.action.pending ? existing.action.originalReason : undefined;
    },
    pendingMessage(base: string, runId: string) {
      const existing = actions.get(JSON.stringify([base, runId]));
      return existing?.action.pending ? existing.action.message : undefined;
    },
    action(options: CancellationOptions) {
      const identity = JSON.stringify([options.base, options.run.id]);
      const existing = actions.get(identity);
      if (existing?.action.pending) {
        // Authentication may refresh; command identity and displayed revision must not.
        existing.options.role = options.role;
        existing.options.csrf = options.csrf;
        existing.options.refresh = options.refresh;
        return existing.action;
      }
      const bound = { ...options, run: { ...options.run } };
      const action = createCancellationAction(bound);
      actions.set(identity, { options: bound, action });
      return action;
    },
  };
}

export type CancellationSession = ReturnType<typeof createCancellationSession>;
