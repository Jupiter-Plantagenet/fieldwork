"""Create a one-time Fieldwork Python handoff outside the caller's job object."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from .store import ROOT


def create_wmi_process(argv: list[str], *, cwd: Path) -> dict:
    """Invoke local Win32_Process.Create with a detached startup descriptor."""
    if (not isinstance(argv, list) or not argv
            or any(not isinstance(value, str) or any(c in value for c in '\x00\r\n') for value in argv)):
        raise ValueError('WMI_PROCESS_ARGUMENTS_INVALID')
    root = ROOT.resolve(strict=True)
    cwd = Path(cwd).resolve(strict=True)
    if cwd != root.parent:
        raise ValueError('WMI_PROCESS_CWD_INVALID')
    python = (root / '.venv/Scripts/python.exe').resolve(strict=True)
    if Path(argv[0]).resolve(strict=True) != python:
        raise ValueError('WMI_PROCESS_INTERPRETER_INVALID')
    if '-B' not in argv:
        raise ValueError('WMI_PROCESS_BYTECODE_FLAG_REQUIRED')
    powershell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    if not powershell.is_file():
        raise RuntimeError('WMI_POWERSHELL_MISSING')
    command_line = subprocess.list2cmdline(argv)
    ps_code = ("$ErrorActionPreference='Stop'; "
        "$r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
        "-Arguments @{CommandLine=$env:FW_WMI_COMMAND;CurrentDirectory=$env:FW_WMI_CWD}; "
        "[pscustomobject]@{return_value=[int]$r.ReturnValue;process_id=[int]$r.ProcessId} "
        "| ConvertTo-Json -Compress")
    env = dict(os.environ)
    env['FW_WMI_COMMAND'] = command_line
    env['FW_WMI_CWD'] = str(cwd)
    result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-Command', ps_code],
        cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=15, check=False)
    if result.returncode != 0:
        diagnostics = root / '.local/real-data/activation-diagnostics'
        diagnostics.mkdir(parents=True, exist_ok=True)
        from .scoped_authority import check_private
        check_private(diagnostics)
        path = diagnostics / ('wmi-create-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
                              + '-' + uuid.uuid4().hex + '.stderr.txt')
        with path.open('xb') as stream:
            stream.write(result.stderr[:16384]); stream.flush(); os.fsync(stream.fileno())
        check_private(path)
        raise RuntimeError('WMI_PROCESS_CREATE_FAILED')
    try:
        doc = json.loads(result.stdout.decode('ascii', 'strict'))
        return_code, pid = doc['return_value'], doc['process_id']
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise RuntimeError('WMI_PROCESS_CREATE_RECEIPT_INVALID')
    if type(return_code) is not int or return_code != 0:
        safe_code = str(return_code) if type(return_code) is int else 'INVALID'
        raise RuntimeError('WMI_PROCESS_CREATE_RETURN_' + safe_code)
    if type(pid) is not int or pid <= 0:
        raise RuntimeError('WMI_PROCESS_CREATE_RECEIPT_INVALID')
    try:
        import psutil
        process = psutil.Process(pid)
        created = process.create_time()
        cmdline = process.cmdline()
        actual_cwd = Path(process.cwd()).resolve()
    except Exception:
        raise RuntimeError('WMI_PROCESS_IDENTITY_UNAVAILABLE') from None
    if (abs(created - process.create_time()) >= .01 or actual_cwd != cwd
            or len(cmdline) != len(argv) or cmdline[1:] != argv[1:]
            or Path(cmdline[0]).resolve() != python):
        raise RuntimeError('WMI_PROCESS_IDENTITY_MISMATCH')
    return {'pid': pid, 'create_time': created, 'cwd': str(cwd),
            'command_sha256': hashlib.sha256(command_line.encode()).hexdigest()}
