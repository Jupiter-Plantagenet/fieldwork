import test from 'node:test';
import assert from 'node:assert/strict';
import { startRunPolling, type PollScheduler } from './real-run-polling.ts';

function manualScheduler() {
  const tasks: (() => void)[] = [];
  const scheduler: PollScheduler = {
    schedule(callback) { tasks.push(callback); return tasks.length; },
    cancel() {},
  };
  return { scheduler, tasks };
}

test('unchanged queued response continues polling sequentially', async () => {
  const { scheduler, tasks } = manualScheduler();
  let reads = 0;
  let finish!: (value: { state: string; revision: number }) => void;
  const stop = startRunPolling({
    scheduler, immediate: false, intervalMs: 10,
    read: () => { reads += 1; return new Promise<{ state: string; revision: number }>(resolve => { finish = resolve; }); },
    onValue: () => {}, onError: error => { throw error; }, isTerminal: value => ['succeeded','failed','cancelled'].includes(value.state),
  });
  tasks.shift()!();
  assert.equal(reads, 1);
  assert.equal(tasks.length, 0, 'no second request overlaps the pending read');
  finish({ state: 'queued', revision: 1 });
  await Promise.resolve(); await Promise.resolve();
  assert.equal(tasks.length, 1, 'unchanged queued response schedules another poll');
  stop();
});

test('terminal response and selection cleanup stop future polling', async () => {
  const { scheduler, tasks } = manualScheduler();
  let reads = 0;
  const stop = startRunPolling({
    scheduler, immediate: false,
    read: async () => { reads += 1; return { state: 'succeeded' }; },
    onValue: () => {}, onError: error => { throw error; }, isTerminal: value => value.state === 'succeeded',
  });
  tasks.shift()!();
  await Promise.resolve(); await Promise.resolve();
  assert.equal(reads, 1);
  assert.equal(tasks.length, 0);
  stop();
});

test('a failed status read is visible to the caller and waits for explicit retry', async () => {
  const { scheduler, tasks } = manualScheduler();
  let errors = 0;
  const stop = startRunPolling({
    scheduler, immediate: false,
    read: async () => { throw new Error('status-read-failed'); },
    onValue: () => {}, onError: () => { errors += 1; }, isTerminal: () => false,
  });
  tasks.shift()!();
  await Promise.resolve(); await Promise.resolve();
  assert.equal(errors, 1);
  assert.equal(tasks.length, 0);
  stop();
});
