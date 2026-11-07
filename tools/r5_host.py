"""Round-5 host-resource protocol (mandatory before every training / heavy evaluation run).

1. Take C:/Users/user/portfolio-build/.cache/product-build.lock by atomic mkdir, recording
   pid + create-time + purpose. Never steal it; a held lock refuses this step.
2. Confirm Folio is idle: GET 127.0.0.1:18301/slots shows nothing busy and no Folio
   evaluation python process is running (a sealed Folio evaluation may hold the lock).
3. `PYTHONPATH=. .venv/Scripts/python.exe scripts/live_supervisor.py pause-model` from folio/.
4. Require >= 6 GiB available RAM (and the unchanged 12 GiB disk gate on the data volume).
5. Bind an owned pause marker to this exact lock process. Recover only a positively dead
   owner whose Folio marker names that owner; preserve a coordinator-owned pause.
6. `resume-model`, confirm Folio /health ok, archive the owned pause receipt, then release.
"""
import json
import importlib.util
import os
import hashlib
import math
import re
import tempfile
import shutil
import subprocess
import time
import urllib.request
import ctypes
import secrets
from ctypes import wintypes
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import psutil

LOCK = Path('C:/Users/user/portfolio-build/.cache/product-build.lock')
FOLIO = Path('C:/Users/user/portfolio-build/folio')
PAUSE_OWNER = Path('C:/Users/user/portfolio-build/fieldwork/.local/round5-resume/folio-pause-owner.json')
PAUSE_OWNER_ARCHIVE = PAUSE_OWNER.parent / 'pause-owner-archive'
HEADROOM = 6 * 1024 ** 3
DISK_MIN = 12 * 1024 ** 3
HOST_DISK_MIN = 50_000_000_000
FOLIO_SERVICES = ('folio.workbench', 'folio.target', 'folio.worker', 'serve_local.py', 'live_supervisor.py', 'model_serve.py')
JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_ACTIVE_PROCESS_FLAG = 0x00000008
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
JOB_OBJECT_QUERY = 0x0004
SYNCHRONIZE = 0x00100000
CPU_TIME_TICKS_PER_SECOND = 10_000_000


class _JobBasicLimit(ctypes.Structure):
    _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong), ('PerJobUserTimeLimit', ctypes.c_longlong),
                ('LimitFlags', wintypes.DWORD), ('MinimumWorkingSetSize', ctypes.c_size_t),
                ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessLimit', wintypes.DWORD),
                ('Affinity', ctypes.c_size_t), ('PriorityClass', wintypes.DWORD), ('SchedulingClass', wintypes.DWORD)]


class _IoCounters(ctypes.Structure):
    _fields_ = [('ReadOperationCount', ctypes.c_ulonglong), ('WriteOperationCount', ctypes.c_ulonglong),
                ('OtherOperationCount', ctypes.c_ulonglong), ('ReadTransferCount', ctypes.c_ulonglong),
                ('WriteTransferCount', ctypes.c_ulonglong), ('OtherTransferCount', ctypes.c_ulonglong)]


class _JobExtendedLimit(ctypes.Structure):
    _fields_ = [('BasicLimitInformation', _JobBasicLimit), ('IoInfo', _IoCounters),
                ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]


class _JobBasicAccounting(ctypes.Structure):
    _fields_ = [('TotalUserTime', ctypes.c_longlong), ('TotalKernelTime', ctypes.c_longlong),
                ('ThisPeriodTotalUserTime', ctypes.c_longlong), ('ThisPeriodTotalKernelTime', ctypes.c_longlong),
                ('TotalPageFaultCount', wintypes.DWORD), ('TotalProcesses', wintypes.DWORD),
                ('ActiveProcesses', wintypes.DWORD), ('TotalTerminatedProcesses', wintypes.DWORD)]


class WindowsCpuJob:
    """Own a child tree; close kills all members, and the job enforces a CPU-time limit."""
    def __init__(self, cpu_limit_seconds, *, active_process_limit=8):
        if os.name != 'nt' or type(cpu_limit_seconds) is not int or cpu_limit_seconds <= 0:
            raise RuntimeError('WINDOWS_CPU_JOB_UNAVAILABLE')
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        self.kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD]
        self.kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        self.kernel32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.TerminateJobObject.restype = wintypes.BOOL
        self.kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.name = 'Local\\FieldworkTraining-' + secrets.token_hex(32)
        ctypes.set_last_error(0)
        self.handle = self.kernel32.CreateJobObjectW(None, self.name)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), 'CreateJobObjectW')
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS: never join a prior run's job.
            self.close()
            raise RuntimeError('TRAINING_JOB_NAME_COLLISION')
        info = _JobExtendedLimit()
        info.BasicLimitInformation.PerJobUserTimeLimit = cpu_limit_seconds * CPU_TIME_TICKS_PER_SECOND
        info.BasicLimitInformation.ActiveProcessLimit = active_process_limit
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_TIME | JOB_OBJECT_LIMIT_ACTIVE_PROCESS_FLAG | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = self.kernel32.SetInformationJobObject(self.handle, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                                                   ctypes.byref(info), ctypes.sizeof(info))
        if not ok:
            err = ctypes.get_last_error()
            self.close()
            raise OSError(err, 'SetInformationJobObject')

    def assign(self, process_handle):
        handle = wintypes.HANDLE(int(process_handle))
        if not self.kernel32.AssignProcessToJobObject(self.handle, handle):
            raise OSError(ctypes.get_last_error(), 'AssignProcessToJobObject')

    def contains_pid(self, pid, expected_create_time=None):
        """Require an exact live PID to belong to this job, not merely any job."""
        if type(pid) is not int or pid <= 0 or not self.handle:
            return False
        kernel32 = self.kernel32
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        process_handle = kernel32.OpenProcess(0x1400, False, pid)  # QUERY_INFORMATION | QUERY_LIMITED_INFORMATION
        if not process_handle:
            raise OSError(ctypes.get_last_error(), 'OpenProcessForJobMembership')
        try:
            if expected_create_time is not None:
                kernel32.GetProcessTimes.restype = wintypes.BOOL
                kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
                    ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
                created = wintypes.FILETIME()
                exited = wintypes.FILETIME()
                kernel = wintypes.FILETIME()
                user = wintypes.FILETIME()
                if not kernel32.GetProcessTimes(process_handle, ctypes.byref(created), ctypes.byref(exited),
                                                ctypes.byref(kernel), ctypes.byref(user)):
                    raise OSError(ctypes.get_last_error(), 'GetProcessTimesForJobMembership')
                filetime = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
                created_unix = filetime / CPU_TIME_TICKS_PER_SECOND - 11644473600
                if abs(created_unix - expected_create_time) >= 0.01:
                    return False
            in_job = wintypes.BOOL()
            if not kernel32.IsProcessInJob(process_handle, self.handle, ctypes.byref(in_job)):
                raise OSError(ctypes.get_last_error(), 'IsProcessInJobForExactJob')
            return bool(in_job.value)
        finally:
            kernel32.CloseHandle(process_handle)

    def budget_receipt(self, max_reserved_cpu_seconds, identity, launch_nonce):
        """Read enforced limits from this exact Job handle and bind them to a child."""
        if (not self.handle or type(max_reserved_cpu_seconds) is not int or max_reserved_cpu_seconds <= 0
                or not isinstance(identity, dict) or not re.fullmatch('[a-f0-9]{64}', str(launch_nonce or ''))):
            raise RuntimeError('TRAINING_JOB_SCOPE_RECEIPT_INPUT_INVALID')
        info = _JobExtendedLimit()
        returned = wintypes.DWORD()
        if not self.kernel32.QueryInformationJobObject(self.handle, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(returned)):
            raise OSError(ctypes.get_last_error(), 'QueryInformationJobObjectExactTrainingJob')
        flags = int(info.BasicLimitInformation.LimitFlags)
        ticks = int(info.BasicLimitInformation.PerJobUserTimeLimit)
        if not flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:
            raise RuntimeError('TRAINING_JOB_KILL_ON_CLOSE_MISSING')
        if not flags & JOB_OBJECT_LIMIT_JOB_TIME or ticks <= 0:
            raise RuntimeError('TRAINING_JOB_CPU_LIMIT_MISSING')
        if ticks > max_reserved_cpu_seconds * CPU_TIME_TICKS_PER_SECOND:
            raise RuntimeError('TRAINING_JOB_CPU_LIMIT_EXCEEDS_RESERVATION')
        if not self.contains_pid(identity['child_pid'], identity['child_create_time']):
            raise RuntimeError('CHILD_READY_PROCESS_OUTSIDE_EXACT_JOB')
        return {'schema_version': 1, 'launch_nonce': launch_nonce, 'job_object_name': self.name,
                'child_pid': identity['child_pid'], 'child_create_time': identity['child_create_time'],
                'launcher_pid': identity['launcher_pid'], 'launcher_create_time': identity['launcher_create_time'],
                'in_exact_job': True, 'kill_on_close': True, 'limit_flags': flags,
                'cpu_limit_ticks': ticks, 'reserved_cpu_seconds': max_reserved_cpu_seconds,
                'job_scope_nonce': secrets.token_hex(32)}

    def accounting(self):
        info = _JobBasicAccounting()
        returned = wintypes.DWORD()
        ok = self.kernel32.QueryInformationJobObject(self.handle, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                                                     ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(returned))
        if not ok:
            raise OSError(ctypes.get_last_error(), 'QueryInformationJobObject')
        return {'user_seconds': info.TotalUserTime / CPU_TIME_TICKS_PER_SECOND,
                'kernel_seconds': info.TotalKernelTime / CPU_TIME_TICKS_PER_SECOND,
                'total_seconds': (info.TotalUserTime + info.TotalKernelTime) / CPU_TIME_TICKS_PER_SECOND,
                'active_processes': info.ActiveProcesses, 'total_processes': info.TotalProcesses,
                'terminated_processes': info.TotalTerminatedProcesses}

    def close(self):
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None

    def terminate(self, exit_code=91):
        if self.handle and not self.kernel32.TerminateJobObject(self.handle, exit_code):
            raise OSError(ctypes.get_last_error(), 'TerminateExactTrainingJob')


def verify_current_job_budget(max_reserved_cpu_seconds, *, job_name, launch_nonce=None,
                              launcher_pid=None, launcher_create_time=None):
    """Open the exact run's named job, verify membership/limits, and close query handle."""
    if (os.name != 'nt' or type(max_reserved_cpu_seconds) is not int or max_reserved_cpu_seconds <= 0
            or not isinstance(job_name, str) or not re.fullmatch(r'Local\\FieldworkTraining-[a-f0-9]{64}', job_name)):
        raise RuntimeError('WINDOWS_JOB_SCOPE_UNAVAILABLE')
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.OpenJobObjectW.restype = wintypes.HANDLE
    kernel32.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.IsProcessInJob.restype = wintypes.BOOL
    kernel32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID,
                                                   wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenJobObjectW(JOB_OBJECT_QUERY | SYNCHRONIZE, False, job_name)
    if not handle:
        raise OSError(ctypes.get_last_error(), 'OpenExactTrainingJobForQuery')
    try:
        current = kernel32.GetCurrentProcess()
        in_job = wintypes.BOOL()
        if not kernel32.IsProcessInJob(current, handle, ctypes.byref(in_job)) or not in_job.value:
            raise RuntimeError('TRAINING_CHILD_NOT_IN_EXACT_JOB')
        info = _JobExtendedLimit()
        returned = wintypes.DWORD()
        if not kernel32.QueryInformationJobObject(handle, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                                                  ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(returned)):
            raise OSError(ctypes.get_last_error(), 'QueryInformationJobObjectExactTrainingJob')
        flags = int(info.BasicLimitInformation.LimitFlags)
        ticks = int(info.BasicLimitInformation.PerJobUserTimeLimit)
        if not flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:
            raise RuntimeError('TRAINING_JOB_KILL_ON_CLOSE_MISSING')
        if not flags & JOB_OBJECT_LIMIT_JOB_TIME or ticks <= 0:
            raise RuntimeError('TRAINING_JOB_CPU_LIMIT_MISSING')
        max_ticks = max_reserved_cpu_seconds * CPU_TIME_TICKS_PER_SECOND
        if ticks > max_ticks:
            raise RuntimeError('TRAINING_JOB_CPU_LIMIT_EXCEEDS_RESERVATION')
        if launch_nonce is not None and not re.fullmatch('[a-f0-9]{64}', str(launch_nonce)):
            raise RuntimeError('TRAINING_JOB_SCOPE_NONCE_INVALID')
        if (type(launcher_pid) is not int or launcher_pid <= 0 or isinstance(launcher_create_time, bool)
                or not isinstance(launcher_create_time, (int, float)) or not math.isfinite(launcher_create_time)
                or launcher_create_time <= 0):
            raise RuntimeError('TRAINING_LAUNCHER_IDENTITY_INVALID')
        return {'in_exact_job': True, 'kill_on_close': True, 'job_time_limit': True,
                'cpu_limit_ticks': ticks, 'cpu_limit_seconds': ticks / CPU_TIME_TICKS_PER_SECOND,
                'reserved_cpu_seconds': max_reserved_cpu_seconds, 'limit_within_reservation': True,
                'limit_flags': flags, 'job_object_name': job_name}
    finally:
        # The Popen owner retains the only long-lived Job handle. This query
        # handle must close before data access so parent death still kills the job.
        kernel32.CloseHandle(handle)


def _ancestry_contains(pid, created, expected_pid, expected_created):
    try:
        current = psutil.Process(pid)
        if current.create_time() != created:
            return False
        for _ in range(32):
            if current.pid == expected_pid and current.create_time() == expected_created:
                return True
            parent = current.parent()
            if parent is None:
                return False
            current = parent
    except psutil.Error:
        return False
    return False


def _resolve_ready_process(root_pid, root_created, ready_path, expected_markers, expected_cwd, expected_nonce, job):
    """Resolve one exact leaf process reported by the gated module inside Popen's tree."""
    path = Path(ready_path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('CHILD_READY_RECORD_MISSING_OR_UNSAFE')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('CHILD_READY_RECORD_INVALID') from exc
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'pid', 'create_time', 'launch_nonce'}
            or value.get('schema_version') != 1 or type(value.get('pid')) is not int or value['pid'] <= 0
            or isinstance(value.get('create_time'), bool) or not isinstance(value.get('create_time'), (int, float))
            or value['create_time'] <= 0 or not isinstance(value.get('launch_nonce'), str)
            or value.get('launch_nonce') != expected_nonce
            or not expected_markers or any(not isinstance(marker, str) or not marker for marker in expected_markers)):
        raise RuntimeError('CHILD_READY_RECORD_INVALID')
    root = psutil.Process(root_pid)
    if root.create_time() != root_created:
        raise RuntimeError('CHILD_LAUNCH_ROOT_IDENTITY_CHANGED')
    try:
        candidates = [root, *root.children(recursive=True)]
    except psutil.NoSuchProcess as exc:
        raise RuntimeError('CHILD_LAUNCH_ROOT_EXITED_BEFORE_IDENTITY') from exc
    except psutil.Error as exc:
        raise RuntimeError('CHILD_LAUNCH_TREE_UNINSPECTABLE') from exc
    matches = []
    for candidate in candidates:
        try:
            if not candidate.is_running() or candidate.status() == psutil.STATUS_ZOMBIE:
                continue
            command_line = candidate.cmdline()
            command_text = '\\0'.join(command_line)
            if not all(marker in command_text for marker in expected_markers):
                continue
            if Path(candidate.cwd()).resolve() != Path(expected_cwd).resolve():
                continue
            created = candidate.create_time()
            if not _ancestry_contains(candidate.pid, created, root_pid, root_created):
                continue
            matches.append((candidate, created))
        except psutil.Error:
            continue
    if not matches:
        raise RuntimeError('CHILD_READY_PROCESS_NOT_IN_LAUNCH_TREE')
    leaves = []
    for process, created in matches:
        has_matching_descendant = False
        for other, other_created in matches:
            if other.pid == process.pid and other_created == created:
                continue
            if _ancestry_contains(other.pid, other_created, process.pid, created):
                has_matching_descendant = True
                break
        if not has_matching_descendant:
            leaves.append((process, created))
    if len(leaves) != 1:
        raise RuntimeError('CHILD_READY_PROCESS_LEAF_AMBIGUOUS')
    process, created = leaves[0]
    if (process.pid, created) != (value['pid'], value['create_time']):
        raise RuntimeError('CHILD_READY_PROCESS_IDENTITY_MISMATCH')
    if not job.contains_pid(process.pid, created):
        raise RuntimeError('CHILD_READY_PROCESS_OUTSIDE_EXACT_JOB')
    return {'child_pid': process.pid, 'child_create_time': created,
            'launcher_pid': root_pid, 'launcher_create_time': root_created}


def run_bounded_child(command, *, env, stdout, cpu_budget_seconds, parallelism_bound,
                      on_spawn, start_gate, poll_seconds=0.1, ready_path=None,
                      expected_markers=None, expected_cwd=None, expected_nonce=None):
    """Run a reviewed child tree with Job Object CPU+wall bounds and kill-on-close.

    When `ready_path` is supplied, the module first reports its own PID/birth while
    waiting at the closed gate. The parent resolves that identity to one exact leaf
    in the Popen PID/birth tree and exact Job Object before reserving the child PID.
    """
    if os.name != 'nt' or type(cpu_budget_seconds) is not int or cpu_budget_seconds <= 30 or type(parallelism_bound) is not int or parallelism_bound <= 0:
        raise RuntimeError('CPU_BUDGET_TOO_SMALL_OR_JOB_UNAVAILABLE')
    cpu_limit = cpu_budget_seconds - 30
    wall_limit = cpu_limit / parallelism_bound
    job = WindowsCpuJob(cpu_limit)
    proc = None
    root = None
    tracked = {}
    completed = False
    t0 = time.monotonic()
    identity = None
    try:
        proc = subprocess.Popen(command, cwd=str(FOLIO.parent / 'fieldwork'), env=env,
                                stdout=stdout, stderr=subprocess.STDOUT, close_fds=True)
        try:
            job.assign(proc._handle)
        except Exception:
            proc.kill()
            proc.wait(timeout=5)
            raise
        root = psutil.Process(proc.pid)
        tracked[(root.pid, root.create_time())] = {'process': root, 'create_time': root.create_time()}
        launcher_created = root.create_time()
        if ready_path is not None:
            if expected_cwd is None or not expected_markers or not isinstance(expected_nonce, str):
                raise RuntimeError('CHILD_READY_EXPECTED_SCOPE_REQUIRED')
            ready_deadline = min(t0 + wall_limit, time.monotonic() + 30)
            while identity is None:
                try:
                    launch_children = root.children(recursive=True)
                except psutil.NoSuchProcess:
                    launch_children = []
                for child in launch_children:
                    try:
                        tracked[(child.pid, child.create_time())] = {'process': child, 'create_time': child.create_time()}
                    except psutil.Error:
                        continue
                if Path(ready_path).exists():
                    try:
                        identity = _resolve_ready_process(proc.pid, launcher_created, ready_path,
                                    expected_markers, expected_cwd, expected_nonce, job)
                    except RuntimeError as exc:
                        if str(exc) != 'CHILD_READY_RECORD_INVALID':
                            raise
                        time.sleep(min(poll_seconds, 0.05))
                        continue
                    child_process = psutil.Process(identity['child_pid'])
                    tracked[(child_process.pid, identity['child_create_time'])] = {
                        'process': child_process, 'create_time': identity['child_create_time']}
                    break
                accounting = job.accounting()
                if accounting['total_seconds'] >= cpu_budget_seconds - 30 or time.monotonic() >= ready_deadline:
                    raise RuntimeError('CHILD_READY_IDENTITY_TIMEOUT')
                if proc.poll() is not None and accounting['active_processes'] == 0:
                    raise RuntimeError(f'CHILD_EXITED_BEFORE_READY:{proc.returncode}')
                time.sleep(min(poll_seconds, 0.05))
        else:
            identity = {'child_pid': proc.pid, 'child_create_time': launcher_created,
                        'launcher_pid': proc.pid, 'launcher_create_time': launcher_created}
        job_scope = None
        if ready_path is not None:
            job_scope = job.budget_receipt(cpu_budget_seconds, identity, expected_nonce)
        on_spawn(identity['child_pid'], identity['child_create_time'],
                 identity['launcher_pid'], identity['launcher_create_time'], job_scope)
        start_gate(job_scope)
        timed_out = False
        exceeded_cpu = False
        last_accounting = {'user_seconds': 0.0, 'kernel_seconds': 0.0, 'total_seconds': 0.0,
                           'active_processes': 1, 'total_processes': 1, 'terminated_processes': 0}
        while True:
            for base in [root, *[item['process'] for item in list(tracked.values())]]:
                try:
                    children = base.children(recursive=True)
                except psutil.Error:
                    continue
                for child in children:
                    try:
                        tracked[(child.pid, child.create_time())] = {'process': child, 'create_time': child.create_time()}
                    except psutil.Error:
                        continue
            last_accounting = job.accounting()
            elapsed = time.monotonic() - t0
            if last_accounting['total_seconds'] >= cpu_budget_seconds - 30:
                timed_out = exceeded_cpu = True
                break
            if elapsed >= wall_limit:
                timed_out = True
                break
            if last_accounting['active_processes'] == 0:
                break
            time.sleep(poll_seconds)
        if timed_out:
            # Explicit termination covers the brief case where a child is still
            # holding its query-only named-job handle; close-on-last-handle remains
            # the parent-death backstop after that handle closes.
            job.terminate()
            job.close()
        try:
            proc.wait(timeout=0 if proc.poll() is not None else 5)
        except subprocess.TimeoutExpired:
            if timed_out:
                proc.kill(); proc.wait(timeout=5)
            else:
                raise RuntimeError('CHILD_LAUNCH_ROOT_EXIT_UNPROVEN')
        else:
            if not timed_out and job.accounting()['active_processes']:
                job.close()
                psutil.wait_procs([item['process'] for (pid, _), item in tracked.items() if pid != proc.pid], timeout=5)
                raise RuntimeError('CHILD_TREE_REMAINS_AFTER_ROOT_EXIT')
        if job.handle:
            last_accounting = job.accounting()
        if timed_out:
            psutil.wait_procs([item['process'] for (pid, _), item in tracked.items() if pid != proc.pid], timeout=5)
        tracked_receipts = []
        for (pid, created), item in sorted(tracked.items()):
            if pid == proc.pid:
                gone = proc.poll() is not None
            else:
                try:
                    current = psutil.Process(pid).create_time()
                    gone = current != created
                except psutil.NoSuchProcess:
                    gone = True
                except psutil.Error:
                    gone = False
            tracked_receipts.append({'pid': pid, 'create_time': created, 'exit_proven': gone})
        if any(not item['exit_proven'] for item in tracked_receipts):
            raise RuntimeError('CHILD_TREE_EXIT_UNPROVEN')
        result = {'returncode': proc.returncode, 'timed_out': timed_out, 'cpu_limit_reached': exceeded_cpu,
                'wall_elapsed_seconds': time.monotonic() - t0, 'cpu_accounting': last_accounting,
                'root_pid': proc.pid, 'root_create_time': tracked[(proc.pid, root.create_time())]['create_time'],
                'child_pid': identity['child_pid'], 'child_create_time': identity['child_create_time'],
                'launcher_pid': identity['launcher_pid'], 'launcher_create_time': identity['launcher_create_time'],
                'job_scope': job_scope,
                'active_processes_at_exit': last_accounting['active_processes'],
                'process_exit_receipts': tracked_receipts,
                'job_kill_on_close': True, 'cpu_budget_seconds': cpu_budget_seconds,
                'wall_deadline_seconds': wall_limit}
        completed = True
        return result
    finally:
        if not completed and root is not None:
            try:
                for base in [root, *[item['process'] for item in list(tracked.values())]]:
                    try:
                        children = base.children(recursive=True)
                    except psutil.Error:
                        continue
                    for child in children:
                        try:
                            tracked[(child.pid, child.create_time())] = {'process': child, 'create_time': child.create_time()}
                        except psutil.Error:
                            continue
            except psutil.Error:
                pass
        termination_error = None
        if not completed and job.handle:
            try:
                job.terminate()
            except Exception as exc:
                termination_error = exc
        job.close()
        if not completed and proc is not None:
            if root is not None:
                try:
                    for base in [root, *[item['process'] for item in list(tracked.values())]]:
                        try:
                            children = base.children(recursive=True)
                        except psutil.Error:
                            continue
                        for child in children:
                            try:
                                tracked[(child.pid, child.create_time())] = {'process': child, 'create_time': child.create_time()}
                            except psutil.Error:
                                continue
                except psutil.Error:
                    pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            descendants = [item['process'] for (pid, _), item in tracked.items() if pid != proc.pid]
            if descendants:
                psutil.wait_procs(descendants, timeout=5)
            unproven = []
            for (pid, created), item in tracked.items():
                if pid == proc.pid:
                    continue  # Popen.wait() proves exit of this exact launch handle.
                try:
                    live_create = psutil.Process(pid).create_time()
                    if live_create == created:
                        unproven.append(pid)
                except psutil.NoSuchProcess:
                    pass
                except psutil.Error:
                    unproven.append(pid)
            if unproven:
                raise RuntimeError('CHILD_TREE_CLEANUP_UNPROVEN')
        if termination_error is not None:
            raise RuntimeError('CHILD_JOB_TERMINATION_UNPROVEN') from termination_error


def _get(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read()


def model_busy():
    try:
        _, body = _get('http://127.0.0.1:18301/slots')
        return any(s.get('is_processing') for s in json.loads(body))
    except Exception:
        return True  # Unknown model state is not evidence that it is idle.


def _module_invocation(argv, module):
    return any(argv[index] == '-m' and index + 1 < len(argv) and argv[index + 1] == module
               for index in range(len(argv)))


def folio_evaluations():
    out = []
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            argv = p.info['cmdline'] or []
            cmd = ' '.join(argv)
            cwd = p.cwd().lower().replace('\\', '/').rstrip('/')
        except Exception:
            continue
        low = cmd.lower().replace('\\', '/')
        is_folio = 'portfolio-build/folio/' in low or ' -m folio.' in low or cwd.endswith('portfolio-build/folio')
        is_ordinary_export_worker = _module_invocation(argv, 'folio.exportworker')
        if ('python' in (p.info['name'] or '').lower() and is_folio
                and not is_ordinary_export_worker and not any(m in cmd for m in FOLIO_SERVICES)):
            out.append({'pid': p.info['pid'], 'cmd': cmd[:160]})
    return out

def folio_health():
    res = {}
    for name, url in (('model', 'http://127.0.0.1:18301/health'), ('api', 'http://127.0.0.1:8101/health')):
        try:
            code, body = _get(url, timeout=10)
            res[name] = {'status': code, 'body': body[:200].decode('utf-8', 'replace')}
        except Exception as exc:
            res[name] = {'status': None, 'error': type(exc).__name__}
    return res


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', prefix='.pause-owner-', suffix='.tmp',
                                         dir=path.parent, delete=False) as f:
            tmp = Path(f.name)
            json.dump(value, f, sort_keys=True, separators=(',', ':'), allow_nan=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _read_pause_owner(path=PAUSE_OWNER):
    path = Path(path)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('PAUSE_OWNER_PATH_UNSAFE')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('PAUSE_OWNER_RECORD_UNREADABLE') from exc
    required = {'schema_version', 'state', 'pid', 'create_time', 'lock_owner', 'started_utc'}
    if not isinstance(value, dict) or set(value) - (required | {'marker_sha256', 'ended_utc'}) or not required <= set(value):
        raise RuntimeError('PAUSE_OWNER_RECORD_INVALID')
    if value['schema_version'] != 1 or value['state'] not in ('pause-intent', 'paused', 'resume-requested'):
        raise RuntimeError('PAUSE_OWNER_RECORD_INVALID')
    if type(value['pid']) is not int or value['pid'] <= 0 or not isinstance(value['create_time'], (int, float)) or not isinstance(value['lock_owner'], str) or not value['lock_owner']:
        raise RuntimeError('PAUSE_OWNER_IDENTITY_INVALID')
    return value


def _process_identity_state(pid, create_time):
    try:
        actual = psutil.Process(pid).create_time()
    except psutil.NoSuchProcess:
        return 'absent'
    except psutil.Error:
        return 'uninspectable'
    return 'reused' if actual != create_time else 'alive'


def _pause_marker(path=None):
    path = path or (FOLIO / '.local/live-round4/model.paused')
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('FOLIO_PAUSE_MARKER_UNSAFE')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('FOLIO_PAUSE_MARKER_UNREADABLE') from exc
    if not isinstance(value, dict) or not isinstance(value.get('by'), str) or not value.get('by'):
        raise RuntimeError('FOLIO_PAUSE_MARKER_OWNER_MISSING')
    return value


def _archive_pause_owner(owner_record, *, owner_path=PAUSE_OWNER, archive_dir=PAUSE_OWNER_ARCHIVE, disposition):
    owner_path, archive_dir = Path(owner_path), Path(archive_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    receipt = {'schema_version': 1, 'disposition': disposition,
               'prior_owner_pid': owner_record['pid'], 'prior_owner_create_time': owner_record['create_time'],
               'prior_lock_owner': owner_record['lock_owner'], 'prior_state': owner_record['state'],
               'archived_utc': datetime.now(timezone.utc).isoformat(),
               'marker_sha256': owner_record.get('marker_sha256'), 'prior_record': owner_record}
    target = archive_dir / (datetime.now(timezone.utc).strftime('pause-owner-%Y%m%dT%H%M%S%fZ') + '.json')
    with target.open('x', encoding='utf-8') as f:
        json.dump(receipt, f, sort_keys=True, separators=(',', ':'), allow_nan=False)
        f.flush()
        os.fsync(f.fileno())
    owner_path.unlink()
    return target


def recover_stale_pause(*, current_lock, supervisor, health, owner_path=PAUSE_OWNER, marker_path=None,
                        archive_dir=PAUSE_OWNER_ARCHIVE, log=lambda _: None):
    """Recover only a positively dead Fieldwork pause owner under the current host lock."""
    if not isinstance(current_lock, dict) or current_lock.get('pid') != os.getpid() or current_lock.get('create_time') != psutil.Process().create_time() or not current_lock.get('owner') or current_lock.get('product') != 'fieldwork':
        raise RuntimeError('STALE_PAUSE_RECOVERY_REQUIRES_CURRENT_LOCK')
    owner = _read_pause_owner(owner_path)
    if owner is None:
        return 'none'
    state = _process_identity_state(owner['pid'], owner['create_time'])
    if state in ('alive', 'uninspectable'):
        raise RuntimeError('PAUSE_OWNER_NOT_PROVEN_DEAD')
    marker = _pause_marker(marker_path)
    if marker is not None and marker['by'] == owner['lock_owner']:
        if state not in ('absent', 'reused'):
            raise RuntimeError('PAUSE_OWNER_NOT_PROVEN_DEAD')
        result = supervisor('resume-model')
        marker_after = _pause_marker(marker_path)
        health_after = health()
        if result != 0 or marker_after is not None or health_after.get('model', {}).get('status') != 200:
            raise RuntimeError('STALE_PAUSE_RESUME_UNVERIFIED')
        archived = _archive_pause_owner(owner, owner_path=owner_path, archive_dir=archive_dir,
                                        disposition='stale-owner-proven-dead-resumed')
        log(json.dumps({'event': 'stale_fieldwork_pause_recovered', 'identity_proof': state,
                        'archive': str(archived), 'model_ok': True}))
        return 'resumed-stale-fieldwork-pause'
    if marker is None and owner['state'] == 'pause-intent':
        health_after = health()
        if health_after.get('model', {}).get('status') != 200:
            raise RuntimeError('PAUSE_INTENT_NO_MARKER_MODEL_UNHEALTHY')
        archived = _archive_pause_owner(owner, owner_path=owner_path, archive_dir=archive_dir,
                                        disposition='stale-intent-no-pause-marker')
        log(json.dumps({'event': 'stale_pause_intent_archived', 'identity_proof': state,
                        'archive': str(archived)}))
        return 'archived-stale-intent'
    if marker is None and owner['state'] == 'resume-requested':
        health_after = health()
        if health_after.get('model', {}).get('status') != 200:
            raise RuntimeError('STALE_RESUME_MODEL_UNHEALTHY')
        archived = _archive_pause_owner(owner, owner_path=owner_path, archive_dir=archive_dir,
                                        disposition='stale-resume-already-complete')
        log(json.dumps({'event': 'stale_pause_resume_archived', 'identity_proof': state,
                        'archive': str(archived)}))
        return 'archived-stale-resume'
    # A marker owned by a different lock holder is coordinator-owned or drifted.
    # Never remove it or substitute the current process as its owner.
    raise RuntimeError('FOLIO_PAUSE_OWNERSHIP_MISMATCH')


def lock_identity(*, owner, purpose):
    helper = FOLIO.parent / 'tools/product_lock.py'
    spec = importlib.util.spec_from_file_location('portfolio_product_lock', helper)
    product_lock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product_lock)
    record = product_lock.read_owner(LOCK)
    if not product_lock.is_mine(record) or record.get('product') != 'fieldwork' or record.get('purpose') != purpose:
        raise RuntimeError('HOST_LOCK_IDENTITY_MISMATCH')
    if record.get('pid') != os.getpid() or record.get('create_time') != psutil.Process().create_time():
        raise RuntimeError('HOST_LOCK_PROCESS_IDENTITY_MISMATCH')
    if owner != f"fieldwork-dataset-round5-{purpose}-{os.getpid()}":
        raise RuntimeError('HOST_LOCK_OWNER_TOKEN_MISMATCH')
    return {'pid': record['pid'], 'create_time': record['create_time'], 'owner': owner,
            'product': 'fieldwork', 'purpose': purpose}


@contextmanager
def metadata_lock(purpose, log=lambda _: None):
    """Take the global product lock for small audited state recovery; no host pause."""
    owner = f'fieldwork-dataset-round5-{purpose}-{os.getpid()}'
    helper = FOLIO.parent / 'tools/product_lock.py'
    spec = importlib.util.spec_from_file_location('portfolio_product_lock', helper)
    product_lock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product_lock)
    if not product_lock.acquire('fieldwork', purpose, LOCK):
        raise RuntimeError('HOST_HEAVY_LOCK_BUSY')
    try:
        identity = lock_identity(owner=owner, purpose=purpose)
        log(json.dumps({'event': 'metadata_lock_acquired', 'purpose': purpose}))
        yield identity
    finally:
        if not product_lock.release(LOCK):
            raise RuntimeError('HOST_LOCK_RELEASE_REFUSED')
        log(json.dumps({'event': 'metadata_lock_released', 'purpose': purpose}))


@contextmanager
def heavy_slot(purpose, log, *, data_path):
    owner = f'fieldwork-dataset-round5-{purpose}-{os.getpid()}'
    held = False

    helper = FOLIO.parent / 'tools/product_lock.py'
    spec = importlib.util.spec_from_file_location('portfolio_product_lock', helper)
    product_lock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product_lock)

    def admission():
        commit = json.loads(subprocess.check_output([
            'powershell', '-NoProfile', '-Command',
            'Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | '
            'Select-Object CommittedBytes,CommitLimit,PercentCommittedBytesInUse | ConvertTo-Json'
        ], text=True))
        free = shutil.disk_usage('C:/').free
        data_free = shutil.disk_usage(os.path.realpath(data_path)).free
        available = psutil.virtual_memory().available
        admitted = free >= HOST_DISK_MIN and data_free >= DISK_MIN and available >= HEADROOM and commit['PercentCommittedBytesInUse'] < 85
        detail = {'event': 'host_admission', 'at': datetime.now(timezone.utc).isoformat(),
                  'c_free_bytes': free, 'data_free_bytes': data_free,
                  'available_ram_bytes': available, 'commit': commit,
                  'required_ram_bytes': HEADROOM, 'required_data_disk_bytes': DISK_MIN,
                  'required_c_disk_bytes': HOST_DISK_MIN, 'admitted': admitted}
        log(json.dumps(detail))
        return admitted

    def acquire():
        # The shared lock's purpose is the exact operation scope. The separate
        # owner token is used for the Fieldwork pause marker and remains bound
        # to this process in lock_identity().
        if not product_lock.acquire('fieldwork', purpose, LOCK):
            raise RuntimeError('HOST_HEAVY_LOCK_BUSY')
        log(json.dumps({'event': 'lock_acquired', 'owner': owner, 'lock_version': 2}))

    def release():
        if not product_lock.release(LOCK):
            raise RuntimeError('HOST_HEAVY_LOCK_RELEASE_REFUSED')
        log(json.dumps({'event': 'lock_released'}))

    def supervisor(action):
        env = dict(os.environ, PYTHONPATH='.')
        r = subprocess.run([str(FOLIO / '.venv/Scripts/python.exe'), 'scripts/live_supervisor.py', action, '--lock-owner', owner],
                           cwd=str(FOLIO), env=env, capture_output=True, text=True, timeout=900)
        log(json.dumps({'event': 'folio_' + action.replace('-', '_'), 'returncode': r.returncode,
                        'stdout_tail': r.stdout[-300:], 'stderr_tail': r.stderr[-300:]}))
        return r.returncode

    paused = False
    pause_record = None
    # Coordinator grants the heavy window before this function is entered. Do not
    # silently sleep/retry a resource refusal or perform a future unscheduled run.
    if not admission():
        raise RuntimeError('HOST_RESOURCE_ADMISSION_REFUSED')
    acquire(); held = True
    try:
        lock_record = product_lock.read_owner(LOCK)
        if not product_lock.is_mine(lock_record) or lock_record.get('product') != 'fieldwork' or lock_record.get('purpose') != purpose:
            raise RuntimeError('HOST_LOCK_IDENTITY_MISMATCH')
        current_lock = lock_identity(owner=owner, purpose=purpose)
        recover_stale_pause(current_lock=current_lock, supervisor=supervisor, health=folio_health,
                            owner_path=PAUSE_OWNER, archive_dir=PAUSE_OWNER_ARCHIVE, log=log)
        marker = _pause_marker()
        already_paused = marker is not None
        busy, evals = (False if already_paused else model_busy()), folio_evaluations()
        if busy or evals:
            log(json.dumps({'event': 'folio_not_idle', 'model_busy': busy, 'evaluation_process_count': len(evals)}))
            raise RuntimeError('FOLIO_NOT_IDLE')
        if not already_paused:
            pause_record = {'schema_version': 1, 'state': 'pause-intent', 'pid': lock_record['pid'],
                            'create_time': lock_record['create_time'], 'lock_owner': owner,
                            'started_utc': datetime.now(timezone.utc).isoformat()}
            _atomic_json(PAUSE_OWNER, pause_record)
            if supervisor('pause-model') != 0:
                # Keep the intent if a marker appeared; later recovery must prove
                # this owner dead and verify exact marker ownership before resuming.
                if _pause_marker() is None:
                    _archive_pause_owner(pause_record, disposition='pause-command-failed-no-marker')
                raise RuntimeError('PAUSE_MODEL_FAILED')
            marker = _pause_marker()
            if marker is None or marker['by'] != owner:
                raise RuntimeError('PAUSE_MARKER_OWNER_MISMATCH')
            pause_record['state'] = 'paused'
            pause_record['marker_sha256'] = hashlib.sha256((FOLIO / '.local/live-round4/model.paused').read_bytes()).hexdigest()
            _atomic_json(PAUSE_OWNER, pause_record)
            paused = True
        else:
            log(json.dumps({'event': 'folio_model_already_paused', 'resume_owned_by_coordinator': True}))
        if not admission():
            raise RuntimeError('HOST_RESOURCE_ADMISSION_REFUSED_AFTER_PAUSE')
        yield owner
    finally:
        try:
            if paused:
                pause_record['state'] = 'resume-requested'
                _atomic_json(PAUSE_OWNER, pause_record)
                resumed = supervisor('resume-model')
                health = {}
                for _ in range(60):
                    health = folio_health()
                    if health['model'].get('status') == 200:
                        break
                    time.sleep(5)
                model_ok = health.get('model', {}).get('status') == 200
                marker_after = _pause_marker()
                if resumed == 0 and model_ok and marker_after is None:
                    _archive_pause_owner(pause_record, disposition='resumed-by-live-owner')
                else:
                    log(json.dumps({'event': 'folio_resume_unverified', 'returncode': resumed,
                                    'model_ok': model_ok, 'marker_present': marker_after is not None,
                                    'owner_record_preserved': True}))
        finally:
            if held:
                release()
