export type PollScheduler = {
  schedule: (callback: () => void, delayMs: number) => number;
  cancel: (handle: number) => void;
};

const browserScheduler: PollScheduler = {
  schedule: (callback, delayMs) => window.setTimeout(callback, delayMs),
  cancel: handle => window.clearTimeout(handle),
};

/** Poll sequentially until terminal or error; an unchanged queued response still schedules the next read. */
export function startRunPolling<T>(options: {
  read: () => Promise<T>;
  onValue: (value: T) => void;
  onError: (error: unknown) => void;
  isTerminal: (value: T) => boolean;
  intervalMs?: number;
  immediate?: boolean;
  scheduler?: PollScheduler;
}): () => void {
  const scheduler = options.scheduler || browserScheduler;
  const delay = options.intervalMs ?? 1500;
  let active = true;
  let timer: number | undefined;
  const schedule = () => {
    if (active) timer = scheduler.schedule(() => { void poll(); }, delay);
  };
  const poll = async () => {
    if (!active) return;
    try {
      const value = await options.read();
      if (!active) return;
      options.onValue(value);
      if (!options.isTerminal(value)) schedule();
    } catch (error) {
      if (active) options.onError(error);
    }
  };
  if (options.immediate === false) schedule(); else void poll();
  return () => {
    active = false;
    if (timer !== undefined) scheduler.cancel(timer);
  };
}
