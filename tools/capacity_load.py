"""ML-T-CAPACITY load driver: N authenticated sessions, fixed aggregate read rate, periodic commands, 1 Hz host sampling.

Run while a real training job is executing (the heavy task). Everything measured is kept: every request
(success or failure) with client-side timing, every 1 s host sample, the training container's streamed
`docker stats`. p95 is nearest-rank. Timer boundaries: client monotonic clock from just before the request is
written to the socket until the response body is fully read (loopback; excludes TCP connect, which is made once
per session before the window opens). Reads are an open loop: each session sends on a fixed schedule and a late
send is recorded as lateness, not dropped.

  .venv/Scripts/python -B tools/capacity_load.py --run <run id> --seconds 900 --out <dir>
"""
import argparse
import http.client
import json
import math
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = '814830e3-55a0-4925-ad37-5d3dac7d4df8'
HOST, PORT = '127.0.0.1', 8102
ORIGIN = 'http://127.0.0.1:8102'


def pct(values, q):
    s = sorted(values)
    return s[max(0, math.ceil(q * len(s)) - 1)] if s else None


class Session:
    def __init__(self, actor, index):
        self.index = index
        self.conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
        body = json.dumps({'name': actor['name'], 'password': actor['password']})
        self.conn.request('POST', '/auth/session', body, {'Content-Type': 'application/json'})
        resp = self.conn.getresponse()
        raw = resp.read()
        if resp.status != 200:
            raise RuntimeError('LOGIN_%d' % resp.status)
        self.csrf = json.loads(raw)['csrf']
        cookie = resp.getheader('Set-Cookie').split(';')[0]
        self.headers = {'Cookie': cookie}

    def clone(self):
        twin = object.__new__(Session)
        twin.index, twin.csrf, twin.headers = self.index, self.csrf, dict(self.headers)
        twin.conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
        twin.stale_reconnects = 0
        return twin

    def call(self, method, path, body=None):
        rec, raw = self._call(method, path, body)
        # A browser transparently retries an idempotent GET whose reused keep-alive socket the server had
        # already closed. Mirror that once, count it, and keep the retry's latency in the sample.
        if (method == 'GET' and rec['error'] in ('ConnectionAbortedError', 'RemoteDisconnected', 'ConnectionResetError',
                                                  'BrokenPipeError') and rec['ms'] < 1000):
            self.stale_reconnects = getattr(self, 'stale_reconnects', 0) + 1
            first_ms = rec['ms']
            rec, raw = self._call(method, path, body)
            rec['ms'] += first_ms
            rec['stale_reconnect'] = True
        return rec, raw

    def _call(self, method, path, body=None):
        headers = dict(self.headers)
        etags = self.__dict__.setdefault('etags', {})  # browsers revalidate GETs that carried an ETag
        if method == 'GET' and path in etags:
            headers['If-None-Match'] = etags[path][0]
        data = None
        if body is not None:
            data = json.dumps(body)
            headers.update({'Content-Type': 'application/json', 'Origin': ORIGIN, 'X-CSRF-Token': self.csrf})
        t0 = time.perf_counter()
        status, err, size = None, None, 0
        try:
            self.conn.request(method, path, data, headers)
            resp = self.conn.getresponse()
            raw = resp.read()
            status, size = resp.status, len(raw)
            if method == 'GET' and resp.getheader('ETag'):
                if status == 200:
                    self.etags[path] = (resp.getheader('ETag'), raw)
                elif status == 304 and path in self.etags:
                    raw, status = self.etags[path][1], 200  # the browser cache serves the stored body
                    size = len(raw)
        except Exception as exc:  # recorded, never dropped
            err = type(exc).__name__
            self.conn.close()
            self.conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
        return {'ms': (time.perf_counter() - t0) * 1000, 'status': status, 'error': err, 'bytes': size}, \
            (raw if status == 200 else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run', required=True)
    ap.add_argument('--seconds', type=int, default=900)
    ap.add_argument('--sessions', type=int, default=10)
    ap.add_argument('--rate', type=float, default=20.0)
    ap.add_argument('--command-every', type=float, default=20.0)
    ap.add_argument('--out', required=True)
    ap.add_argument('--detail-run', help='verified real run whose validation/slice/bundle views join the read mix')
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    actor = json.loads((ROOT / '.local/real-data/local-completion-actor.private.json').read_text(encoding='utf-8'))
    sessions = [Session(actor, i) for i in range(args.sessions)]
    del actor
    base = '/api/v1/workspaces/' + WORKSPACE
    reads = [('list', base + '/real/runs?limit=50'), ('detail', base + '/real/runs/' + args.run),
             ('snapshot', base + '/snapshot'), ('settings', base + '/real/settings'),
             ('operations', base + '/screens/operations'), ('events', base + '/events'),
             ('versions', base + '/versions'), ('configure', base + '/screens/configure')]
    if args.detail_run:  # verified-run detail views: validation, a confusion slice and the bundle (rights re-verified per read)
        d = base + '/real/runs/' + args.detail_run
        reads += [('validation', d + '/validation'), ('slice', d + '/validation/slices?actual=3&predicted=4'),
                  ('bundle', d + '/bundle')]
    for s in sessions:  # first-use pass, recorded separately from the warm window
        first = [dict(kind=k, **s.call('GET', p)[0]) for k, p in reads]
        s.first = first
    results, commands, samples, phases = [], [], [], []
    lock = threading.Lock()
    stop = threading.Event()
    t_start = time.monotonic()
    wall_start = datetime.now(timezone.utc)
    per_session_period = args.sessions / args.rate

    def reader(s):
        k = 0
        due = t_start + s.index * per_session_period / args.sessions
        while not stop.is_set():
            now = time.monotonic()
            if now < due:
                stop.wait(due - now)
                if stop.is_set():
                    break
            kind, path = reads[(k + s.index) % len(reads)]
            lateness = max(0.0, time.monotonic() - due) * 1000
            rec, _ = s.call('GET', path)
            rec.update(kind=kind, session=s.index, t=round(time.monotonic() - t_start, 3), lateness_ms=round(lateness, 1))
            with lock:
                results.append(rec)
            k += 1
            due += per_session_period

    def commander():
        s = sessions[0].clone()  # same login, own socket (HTTPConnection is not thread-safe)
        while not stop.wait(args.command_every):
            rec, raw = s.call('GET', base + '/real/settings')
            if raw is None:
                continue
            cur = json.loads(raw)['settings']
            rec, _ = s.call('PUT', base + '/real/settings', {
                'expected_revision': cur['revision'], 'retention_days': cur['retention_days'],
                'max_concurrent_runs': cur['max_concurrent_runs'], 'max_epochs': cur['max_epochs']})
            rec.update(kind='command_settings_save', t=round(time.monotonic() - t_start, 3))
            with lock:
                commands.append(rec)

    def sampler():
        procs = {}
        while not stop.is_set():
            tick = time.monotonic()
            row = {'t': round(tick - t_start, 2), 'cpu_percent': psutil.cpu_percent(interval=None),
                   'avail_ram': psutil.virtual_memory().available, 'free_c': psutil.disk_usage('C:/').free}
            rss = {}
            for p in psutil.process_iter(['pid', 'cmdline', 'memory_info']):
                try:
                    c = ' '.join(p.info['cmdline'] or [])
                    tag = ('api' if 'uvicorn' in c and 'fieldwork.api:app' in c else
                           'worker' if 'fieldwork.worker' in c and '-m' in c else None)
                    if tag:
                        rss[tag] = rss.get(tag, 0) + p.info['memory_info'].rss
                except (psutil.Error, TypeError):
                    pass
            row['rss'] = rss
            row['load_lateness_max_ms'] = None
            samples.append(row)
            stop.wait(max(0.0, 1.0 - (time.monotonic() - tick)))

    docker_lines = []

    def docker_stats():
        fmt = '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}'
        proc = subprocess.Popen(['docker', '--context', 'default', 'stats', '--format', fmt], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
        try:
            for line in proc.stdout:
                if stop.is_set():
                    break
                if '|' in line:
                    docker_lines.append({'t': round(time.monotonic() - t_start, 2), 'line': line.strip()[-160:]})
        finally:
            proc.kill()

    def phase_watch():
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        local = json.loads((ROOT / '.local.json').read_text(encoding='utf-8'))
        p = conninfo_to_dict(local['dsn'])
        p['connect_timeout'] = 3
        while not stop.is_set():
            try:
                with psycopg.connect(**p) as c:
                    r = c.execute('SELECT state,epoch,artifact_status FROM public.fw_runs WHERE id=%s', (args.run,)).fetchone()
                phases.append({'t': round(time.monotonic() - t_start, 1), 'state': r[0], 'epoch': r[1], 'artifact': r[2]})
            except Exception as exc:
                phases.append({'t': round(time.monotonic() - t_start, 1), 'error': type(exc).__name__})
            stop.wait(10)

    threads = [threading.Thread(target=f, daemon=True) for f in (commander, sampler, docker_stats, phase_watch)]
    threads += [threading.Thread(target=reader, args=(s,), daemon=True) for s in sessions]
    psutil.cpu_percent(interval=None)
    for t in threads:
        t.start()
    time.sleep(args.seconds)
    stop.set()
    time.sleep(2)
    end = datetime.now(timezone.utc)
    with lock:
        ok = [r['ms'] for r in results if r['status'] == 200]
        bad = [r for r in results if r['status'] != 200]
        by_kind = {}
        for r in results:
            by_kind.setdefault(r['kind'], []).append(r['ms'])
        cmd_ok = [r['ms'] for r in commands if r['status'] == 200]
        summary = {
            'schema': 'fieldwork.capacity-load/v1', 'run': args.run, 'sessions': args.sessions, 'target_reads_per_s': args.rate,
            'window_seconds': args.seconds, 'started_utc': wall_start.isoformat(), 'ended_utc': end.isoformat(),
            'reads': {'count': len(results), 'ok': len(ok), 'errors': len(bad), 'error_rate': len(bad) / max(1, len(results)),
                      'achieved_per_s': round(len(results) / args.seconds, 2),
                      'p50_ms': pct([r['ms'] for r in results], .5), 'p95_ms': pct([r['ms'] for r in results], .95),
                      'p99_ms': pct([r['ms'] for r in results], .99), 'max_ms': max([r['ms'] for r in results], default=None),
                      'p95_by_kind_ms': {k: pct(v, .95) for k, v in by_kind.items()},
                      'max_lateness_ms': max([r['lateness_ms'] for r in results], default=None),
                      'error_samples': [{k: r[k] for k in ('kind', 'status', 'error', 't')} for r in bad[:20]]},
            'commands': {'count': len(commands), 'ok': len(cmd_ok), 'p95_ms': pct([r['ms'] for r in commands], .95),
                         'max_ms': max([r['ms'] for r in commands], default=None),
                         'statuses': sorted({str(r['status']) for r in commands})},
            'stale_keepalive_reconnects': sum(getattr(s, 'stale_reconnects', 0) for s in sessions),
            'first_use_p95_ms': pct([f['ms'] for s in sessions for f in s.first], .95),
            'first_use_count': sum(len(s.first) for s in sessions),
            'host': {'cpu_percent_max': max([x['cpu_percent'] for x in samples], default=None),
                     'cpu_percent_mean': round(sum(x['cpu_percent'] for x in samples) / max(1, len(samples)), 1),
                     'min_avail_ram': min([x['avail_ram'] for x in samples], default=None),
                     'min_free_c': min([x['free_c'] for x in samples], default=None),
                     'api_rss_max': max([x['rss'].get('api', 0) for x in samples], default=None),
                     'worker_rss_max': max([x['rss'].get('worker', 0) for x in samples], default=None),
                     'samples': len(samples)},
            'docker_stats_lines': len(docker_lines),
            'phases': phases[:: max(1, len(phases) // 40)],
        }
        (out / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        (out / 'requests.json').write_text(json.dumps({'reads': results, 'commands': commands}), encoding='utf-8')
        (out / 'samples.json').write_text(json.dumps({'host': samples, 'docker': docker_lines, 'phases': phases}), encoding='utf-8')
    print(json.dumps({k: summary[k] for k in ('reads', 'commands', 'first_use_p95_ms', 'host')}, indent=1)[:3500])
    return 0


if __name__ == '__main__':
    sys.exit(main())
