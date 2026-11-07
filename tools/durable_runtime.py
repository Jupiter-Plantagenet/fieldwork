"""Small, fail-closed Task Scheduler supervisor for the local Fieldwork API.

Run ``python tools/durable_runtime.py --help`` for the operator actions.  The
scheduled process owns uvicorn in the foreground and honors a private stop file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

import psutil

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TASK_NAME = 'Fieldwork.DurableRuntime.v1'
TASK_MARKER = 'Fieldwork durable runtime v1; owned by tools/durable_runtime.py'
PURPOSE = 'fieldwork-durable-api-start'
POLL_SECONDS = 1.0
STOP_CAPTURE_GRACE_SECONDS = 2.0
GiB = 1024 ** 3
API_REAL_PIXEL_IMAGE_ID = 'sha256:b42e39dfea7adbace1be7766fc071e94ff3424ac175485c633986ac8ae883dcd'
API_REAL_MODEL_IMAGE_ID = 'sha256:41c680046133d0920a217adbfb951b8c77e4cec7e3ea7763646b19c5f4e7dfdc'


def _wrapper_path() -> Path:
    return (ROOT / 'tools/durable_runtime_task.ps1').resolve()


def _fixed_python_path() -> Path:
    return (ROOT / '.venv/Scripts/python.exe').resolve()


def _require_venv_python() -> None:
    if Path(sys.executable).resolve() != _fixed_python_path():
        raise RuntimeError('VENV_PYTHON_REQUIRED')


def _owner_user() -> str:
    return os.environ.get('USERDOMAIN', '') + '\\' + os.environ.get('USERNAME', '')


def _task_arguments() -> str:
    return ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'
            + str(_wrapper_path()) + '" -Action Run')


def _norm_windows(value: str) -> str:
    return str(value).replace('/', '\\').casefold()


SAFE_ERROR_CODES = frozenset({
    'TASK_SCHEDULER_REQUIRES_WINDOWS', 'TASK_WRAPPER_MISSING', 'TASK_EXISTS_BUT_IS_NOT_OWNED',
    'TASK_INSTALL_FAILED', 'TASK_UNINSTALL_FAILED', 'TASK_NOT_INSTALLED',
    'TASK_DID_NOT_STOP_CLEANLY', 'TASK_QUERY_FAILED', 'TASK_QUERY_RECEIPT_INVALID',
    'TASK_SOURCE_PIN_MISMATCH', 'TASK_DEFINITION_MISMATCH', 'TASK_REGISTRATION_INCOMPLETE',
    'TASK_ENABLE_FAILED', 'OWNER_MANIFEST_INVALID', 'OWNER_MANIFEST_WRITE_FAILED',
    'OWNER_MANIFEST_RECOVERY_FAILED', 'WINDOWS_RUNTIME_REQUIRED', 'PERFOS_COUNTER_UNAVAILABLE',
    'PERFOS_COUNTER_INVALID', 'HOST_RAM_GATE_REFUSED',
    'HOST_DISK_GATE_REFUSED', 'MIGRATION_017_SOURCE_MISSING', 'MIGRATION_017_SCHEMA_REQUIRED',
    'SHARED_PRODUCT_LOCK_PATH_OVERRIDDEN', 'SHARED_PRODUCT_LOCK_HELD_OR_CLEANUP_PENDING',
    'SHARED_PRODUCT_LOCK_OWNERSHIP_INVALID', 'SHARED_PRODUCT_LOCK_RELEASE_REFUSED',
    'PORT_8102_ALREADY_IN_USE', 'API_READINESS_PROBE_FAILED', 'API_START_FAILED',
    'PROCESS_IDENTITY_UNAVAILABLE', 'PROCESS_IDENTITY_MISMATCH',
    'HOST_COMMIT_GATE_REFUSED', 'PROCESS_TREE_IDENTITY_MISMATCH',
    'PRIVATE_FILE_ALREADY_EXISTS', 'PRIVATE_FILE_CONTENT_MISMATCH',
    'POWERSHELL_NOT_FOUND', 'UNEXPECTED_ERROR', 'VENV_PYTHON_REQUIRED',
    'POWERSHELL_TEMP_DIRECTORY_UNAVAILABLE', 'POWERSHELL_TEMP_FILE_CREATE_FAILED',
    'POWERSHELL_TEMP_FILE_CLEANUP_FAILED',
})


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _private(path: Path, *, allow_missing: bool = False) -> None:
    from fieldwork.privacy_lifecycle import _check_c_ancestry
    from fieldwork.scoped_authority import check_private
    _check_c_ancestry(path, allow_missing_leaf=allow_missing)
    if allow_missing and not path.exists():
        return
    check_private(path)


def _write_new_private_file(path: Path, raw: bytes) -> None:
    """Create a new private leaf without following or replacing an existing one."""
    _private(path, allow_missing=True)
    try:
        with path.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        # Exclusive creation does not follow a racing symlink/reparse point.
        raise RuntimeError('PRIVATE_FILE_ALREADY_EXISTS') from None
    _private(path)


def _paths() -> dict[str, Path]:
    return {
        'launcher': Path(__file__).resolve(),
        'task_wrapper': _wrapper_path(),
        'api': (ROOT / 'fieldwork/api.py').resolve(),
        'logging': (ROOT / 'fieldwork/privacy_logging.py').resolve(),
        'migration_017': (ROOT / 'migrations/017_privacy_lifecycle.sql').resolve(),
        'python': _fixed_python_path(),
    }


def _runtime_dir() -> Path:
    from fieldwork.privacy_lifecycle import _check_c_ancestry
    from fieldwork.scoped_authority import check_private
    var = ROOT / 'var'
    _check_c_ancestry(var)
    check_private(var)
    path = ROOT / 'var/durable-runtime'
    _check_c_ancestry(path, allow_missing_leaf=True)
    path.mkdir(parents=True, exist_ok=True)
    _private(path)
    return path


def _manifest_path() -> Path:
    return _runtime_dir() / 'owner-pins.json'


def _read_manifest() -> dict:
    path = _manifest_path()
    candidates = [path]
    candidates.extend(sorted(path.parent.glob('owner-pins.*.json'), key=lambda item: item.name, reverse=True))
    for candidate in candidates:
        try:
            _private(candidate)
            data = json.loads(candidate.read_text(encoding='utf-8'))
            _validate_manifest(data, require_task_fingerprint=(candidate != path))
        except (OSError, ValueError, RuntimeError, TypeError):
            continue
        if candidate != path:
            _publish_manifest(data)
        return data
    raise RuntimeError('OWNER_MANIFEST_INVALID')


def _validate_manifest(data: dict, *, require_task_fingerprint: bool = False) -> None:
    enabled_hash = data.get('task_xml_enabled_sha256') if isinstance(data, dict) else None
    disabled_hash = data.get('task_xml_disabled_sha256') if isinstance(data, dict) else None
    pending = data.get('registration_pending') if isinstance(data, dict) else None
    fingerprint_invalid = ((enabled_hash is None) != (disabled_hash is None)
        or (enabled_hash is not None and (not _valid_digest(enabled_hash) or not _valid_digest(disabled_hash)))
        or (pending is True and enabled_hash is not None)
        or (pending is False and enabled_hash is None)
        or type(pending) is not bool)
    if (not isinstance(data, dict)
            or data.get('schema') != 'fieldwork.durable-runtime-owner/v1'
            or data.get('task_name') != TASK_NAME
            or data.get('task_marker') != TASK_MARKER
            or data.get('root') != str(ROOT)
            or data.get('owner_user') != _owner_user()
            or not isinstance(data.get('pins'), dict)
            or fingerprint_invalid
            or (require_task_fingerprint and (not _valid_digest(enabled_hash)
                or not _valid_digest(disabled_hash)))):
        raise RuntimeError('OWNER_MANIFEST_INVALID')


def _valid_digest(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _manifest_bytes(data: dict) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')


def _write_exclusive_private(path: Path, raw: bytes) -> None:
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    _private(path)


def _publish_manifest(data: dict) -> bytes | None:
    """Atomically publish a complete owner receipt and keep a versioned copy."""
    _validate_manifest(data)
    path = _manifest_path()
    previous = path.read_bytes() if path.exists() else None
    raw = _manifest_bytes(data)
    stamp_value = time.time_ns()
    stamp = f'{stamp_value:020d}'
    if previous is not None:
        old_copy = path.with_name('owner-pins.' + stamp + '.previous.' + uuid.uuid4().hex + '.json')
        _write_exclusive_private(old_copy, previous)
    versioned = path.with_name('owner-pins.' + f'{stamp_value + 1:020d}' + '.' + uuid.uuid4().hex + '.json')
    temp = path.with_name('owner-pins.' + uuid.uuid4().hex + '.tmp')
    try:
        _write_exclusive_private(versioned, raw)
        check = json.loads(versioned.read_text(encoding='utf-8'))
        _validate_manifest(check)
        _write_exclusive_private(temp, raw)
        os.replace(temp, path)
        _private(path)
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise RuntimeError('OWNER_MANIFEST_WRITE_FAILED') from None
    return previous


def _restore_manifest(previous: bytes | None) -> None:
    path = _manifest_path()
    if previous is None:
        path.unlink(missing_ok=True)
        return
    tmp = path.with_name('owner-pins.' + uuid.uuid4().hex + '.rollback.tmp')
    _write_exclusive_private(tmp, previous)
    os.replace(tmp, path)
    _private(path)


def _confirm_pins() -> dict:
    manifest = _read_manifest()
    for key, path in _paths().items():
        expected = manifest.get('pins', {}).get(key)
        if not isinstance(expected, str) or _sha(path) != expected:
            raise RuntimeError('TASK_SOURCE_PIN_MISMATCH')
    return manifest


def _powershell(script: str, *args: str) -> subprocess.CompletedProcess:
    exe = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    if not exe.is_file():
        raise RuntimeError('POWERSHELL_NOT_FOUND')
    common = [str(exe), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass']
    if not args:
        return subprocess.run([*common, '-Command', script], cwd=ROOT, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    script_dir = ROOT / 'var/durable-runtime'
    if not script_dir.is_dir():
        raise RuntimeError('POWERSHELL_TEMP_DIRECTORY_UNAVAILABLE')
    from fieldwork.privacy_lifecycle import _check_c_ancestry
    temp_path = script_dir / ('powershell-' + uuid.uuid4().hex + '.ps1')
    _private(script_dir)
    _check_c_ancestry(temp_path, allow_missing_leaf=True)
    try:
        try:
            with temp_path.open('xb') as stream:
                stream.write(script.encode('utf-8-sig'))
                stream.flush()
                os.fsync(stream.fileno())
            _private(temp_path)
        except OSError:
            raise RuntimeError('POWERSHELL_TEMP_FILE_CREATE_FAILED') from None
        return subprocess.run([*common, '-File', str(temp_path), *args], cwd=ROOT,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=30, check=False)
    finally:
        try:
            if temp_path.exists():
                _check_c_ancestry(temp_path)
                temp_path.unlink()
        except OSError:
            raise RuntimeError('POWERSHELL_TEMP_FILE_CLEANUP_FAILED') from None


def _task_state() -> dict:
    script = r"""
$ErrorActionPreference='Stop'
$t=Get-ScheduledTask -TaskName $args[0] -ErrorAction SilentlyContinue
if ($null -eq $t) { '{"exists":false}'; exit 0 }
$principalUser=[string]$t.Principal.UserId
$principalSid=''
try {
 if ($principalUser -match '^S-1-') { $principalSid=$principalUser }
 else {
   if ($principalUser -notmatch '\\') { $principalUser=$env:USERDOMAIN + '\' + $principalUser }
   $principalSid=([Security.Principal.NTAccount]$principalUser).Translate([Security.Principal.SecurityIdentifier]).Value
 }
} catch { $principalSid='' }
$currentUserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$actions=@($t.Actions | ForEach-Object { [pscustomobject]@{
 type=[string]$_.CimClass.CimClassName;execute=[string]$_.Execute;arguments=[string]$_.Arguments;
 workingDirectory=[string]$_.WorkingDirectory;id=[string]$_.Id } })
$triggers=@($t.Triggers | ForEach-Object { [pscustomobject]@{
 type=[string]$_.CimClass.CimClassName;userId=[string]$_.UserId;enabled=[bool]$_.Enabled } })
$s=$t.Settings
$settings=[pscustomobject]@{
 hidden=[bool]$s.Hidden;multipleInstances=[string]$s.MultipleInstances;
 executionTimeLimitSeconds=[double]$s.ExecutionTimeLimit.TotalSeconds;
 startWhenAvailable=[bool]$s.StartWhenAvailable;
 disallowStartIfOnBatteries=[bool]$s.DisallowStartIfOnBatteries;
 stopIfGoingOnBatteries=[bool]$s.StopIfGoingOnBatteries;
 allowHardTerminate=[bool]$s.AllowHardTerminate;wakeToRun=[bool]$s.WakeToRun;
 runOnlyIfNetworkAvailable=[bool]$s.RunOnlyIfNetworkAvailable;priority=[int]$s.Priority }
$xml=Export-ScheduledTask -TaskName $args[0]
$sha=[Security.Cryptography.SHA256]::Create()
$xmlText=([string]$xml).Trim()
$settingsEnabled='(?s)(<Settings\b[^>]*>.*?<Enabled>)(?:true|false)(</Enabled>)'
$disabledText=[regex]::Replace($xmlText,$settingsEnabled,'${1}false${2}',1)
$enabledText=[regex]::Replace($xmlText,$settingsEnabled,'${1}true${2}',1)
$hashText={ param($text) $b=[Text.Encoding]::UTF8.GetBytes($text); ([BitConverter]::ToString($sha.ComputeHash($b))).Replace('-','').ToLowerInvariant() }
$xmlHash=& $hashText $xmlText
$xmlDisabledHash=& $hashText $disabledText
$xmlEnabledHash=& $hashText $enabledText
$p=[pscustomobject]@{exists=$true;taskPath=[string]$t.TaskPath;taskName=[string]$t.TaskName;
 author=[string]$t.Author;description=[string]$t.Description;actions=$actions;triggers=$triggers;
 settings=$settings;state=[string]$t.State;user=$principalUser;principalSid=$principalSid;currentUserSid=$currentUserSid;
 logonType=[string]$t.Principal.LogonType;runLevel=[string]$t.Principal.RunLevel;
 groupId=[string]$t.Principal.GroupId;xmlSha256=$xmlHash;
 xmlDisabledSha256=$xmlDisabledHash;xmlEnabledSha256=$xmlEnabledHash}
$p | ConvertTo-Json -Compress
"""
    result = _powershell(script, TASK_NAME)
    if result.returncode:
        raise RuntimeError('TASK_QUERY_FAILED')
    try:
        return json.loads(result.stdout.decode('utf-8-sig').strip())
    except (ValueError, UnicodeError):
        raise RuntimeError('TASK_QUERY_RECEIPT_INVALID') from None


def _owned_task_state() -> dict | None:
    state = _task_state()
    if not state.get('exists'):
        return None
    try:
        manifest = _read_manifest()
    except RuntimeError:
        raise RuntimeError('TASK_EXISTS_BUT_IS_NOT_OWNED') from None
    powershell = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) /
                     'System32/WindowsPowerShell/v1.0/powershell.exe')
    expected_action = {'type': 'MSFT_TaskExecAction', 'execute': powershell,
                       'arguments': _task_arguments(), 'workingDirectory': str(ROOT), 'id': ''}
    actions = state.get('actions')
    if isinstance(actions, dict):
        actions = [actions]
    expected_trigger = {'type': 'MSFT_TaskLogonTrigger', 'userId': _owner_user(), 'enabled': True}
    triggers = state.get('triggers')
    if isinstance(triggers, dict):
        triggers = [triggers]
    expected_settings = {
        'hidden': True, 'multipleInstances': 'IgnoreNew', 'executionTimeLimitSeconds': 0.0,
        'startWhenAvailable': True, 'disallowStartIfOnBatteries': False,
        'stopIfGoingOnBatteries': False, 'allowHardTerminate': True,
        'wakeToRun': False, 'runOnlyIfNetworkAvailable': False, 'priority': 7,
    }
    state_owner = {
        'taskPath': '\\', 'taskName': TASK_NAME, 'author': _owner_user(),
        'description': TASK_MARKER,
        'actions': [expected_action], 'triggers': [expected_trigger],
        'settings': expected_settings,
        'logonType': 'Interactive', 'runLevel': 'Limited', 'groupId': '',
    }
    structural_mismatch = any(state.get(key) != value for key, value in state_owner.items()
                              if key not in ('actions', 'triggers'))
    if (structural_mismatch or not state.get('currentUserSid')
            or state.get('principalSid') != state.get('currentUserSid')
            or not isinstance(actions, list) or len(actions) != 1
            or not isinstance(triggers, list) or len(triggers) != 1):
        raise RuntimeError('TASK_EXISTS_BUT_IS_NOT_OWNED')
    actual_action = actions[0]
    if (not isinstance(actual_action, dict)
            or actual_action.get('type') != expected_action['type']
            or _norm_windows(actual_action.get('execute', '')) != _norm_windows(expected_action['execute'])
            or _norm_windows(actual_action.get('workingDirectory', '')) != _norm_windows(expected_action['workingDirectory'])
            or _norm_windows(actual_action.get('arguments', '')) != _norm_windows(expected_action['arguments'])
            or actual_action.get('id') != expected_action['id']):
        raise RuntimeError('TASK_EXISTS_BUT_IS_NOT_OWNED')
    if triggers != [expected_trigger]:
        raise RuntimeError('TASK_EXISTS_BUT_IS_NOT_OWNED')
    fingerprint = state.get('xmlSha256')
    expected_fingerprint = (manifest.get('task_xml_disabled_sha256') if state.get('state') == 'Disabled'
                            else manifest.get('task_xml_enabled_sha256'))
    if expected_fingerprint is not None and fingerprint != expected_fingerprint:
        raise RuntimeError('TASK_EXISTS_BUT_IS_NOT_OWNED')
    if expected_fingerprint is None and (not manifest.get('registration_pending')
                                         or state.get('state') != 'Disabled'):
        raise RuntimeError('TASK_EXISTS_BUT_IS_NOT_OWNED')
    return state


def install() -> dict:
    if os.name != 'nt':
        raise RuntimeError('TASK_SCHEDULER_REQUIRES_WINDOWS')
    _require_venv_python()
    wrapper = _paths()['task_wrapper']
    if not wrapper.is_file():
        raise RuntimeError('TASK_WRAPPER_MISSING')
    runtime_dir = _runtime_dir()
    pins = {name: _sha(path) for name, path in _paths().items()}
    state = _task_state()
    existing = bool(state.get('exists'))
    old_state = _owned_task_state() if existing else None
    owner = {'schema': 'fieldwork.durable-runtime-owner/v1', 'task_name': TASK_NAME,
             'task_marker': TASK_MARKER, 'root': str(ROOT), 'pins': pins,
             'owner_user': _owner_user(), 'task_xml_enabled_sha256': None,
             'task_xml_disabled_sha256': None,
             'registration_pending': not existing}
    previous = None
    if existing:
        owner['task_xml_enabled_sha256'] = old_state['xmlEnabledSha256']
        owner['task_xml_disabled_sha256'] = old_state['xmlDisabledSha256']
        owner['registration_pending'] = False
        _publish_manifest(owner)
    else:
        previous = _publish_manifest(owner)
        script = r"""
$ErrorActionPreference='Stop'
$name=$args[0]; $marker=$args[1]; $wrapper=$args[2]; $root=$args[3]; $user=$args[4]
$old=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if ($null -ne $old) { throw 'TASK_EXISTS_BUT_IS_NOT_OWNED' }
$exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $wrapper + '" -Action Run'
$esc={ param($v) [System.Security.SecurityElement]::Escape([string]$v) }
$author=& $esc $user; $safeMarker=& $esc $marker; $safeUser=& $esc $user
$safeExe=& $esc $exe; $safeArguments=& $esc $arguments; $safeRoot=& $esc $root
$date=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
$xml=@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>$date</Date><Author>$author</Author><Description>$safeMarker</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>$safeUser</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>$safeUser</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><Enabled>false</Enabled><Hidden>true</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>$safeExe</Command><Arguments>$safeArguments</Arguments><WorkingDirectory>$safeRoot</WorkingDirectory></Exec></Actions>
</Task>
"@
Register-ScheduledTask -TaskName $name -Xml $xml -ErrorAction Stop | Out-Null
"installed"
"""
        result = _powershell(script, TASK_NAME, TASK_MARKER, str(wrapper), str(ROOT), owner['owner_user'])
        if result.returncode:
            if not _task_state().get('exists'):
                _restore_manifest(previous)
            raise RuntimeError('TASK_INSTALL_FAILED')
        try:
            registered = _owned_task_state()
            if registered is None or registered.get('state') != 'Disabled':
                raise RuntimeError('TASK_REGISTRATION_INCOMPLETE')
            owner['task_xml_enabled_sha256'] = registered['xmlEnabledSha256']
            owner['task_xml_disabled_sha256'] = registered['xmlDisabledSha256']
            owner['registration_pending'] = False
            _publish_manifest(owner)
        except Exception:
            # A newly registered task remains disabled unless every identity
            # check and the final owner receipt succeed.
            raise RuntimeError('TASK_REGISTRATION_INCOMPLETE') from None
    enable_script = r"""
$ErrorActionPreference='Stop'
$name=$args[0]; $expectedDisabled=$args[1]; $expectedEnabled=$args[2]
$xml=Export-ScheduledTask -TaskName $name -ErrorAction Stop
$sha=[Security.Cryptography.SHA256]::Create()
$xmlText=([string]$xml).Trim()
$settingsEnabled='(?s)(<Settings\b[^>]*>.*?<Enabled>)(?:true|false)(</Enabled>)'
$disabledText=[regex]::Replace($xmlText,$settingsEnabled,'${1}false${2}',1)
$enabledText=[regex]::Replace($xmlText,$settingsEnabled,'${1}true${2}',1)
$hashText={ param($text) $b=[Text.Encoding]::UTF8.GetBytes($text); ([BitConverter]::ToString($sha.ComputeHash($b))).Replace('-','').ToLowerInvariant() }
if ((& $hashText $xmlText) -ne $expectedDisabled) { throw 'TASK_DEFINITION_MISMATCH' }
Enable-ScheduledTask -TaskName $name -ErrorAction Stop | Out-Null
$after=Export-ScheduledTask -TaskName $name -ErrorAction Stop
$afterText=([string]$after).Trim()
if ((& $hashText $afterText) -ne $expectedEnabled) {
    Disable-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue | Out-Null
    throw 'TASK_DEFINITION_MISMATCH'
}
'enabled'
"""
    current_manifest = _read_manifest()
    result = _powershell(enable_script, TASK_NAME, current_manifest['task_xml_disabled_sha256'],
                         current_manifest['task_xml_enabled_sha256'])
    if result.returncode:
        raise RuntimeError('TASK_ENABLE_FAILED')
    _owned_task_state()
    # Clearing this private marker is an explicit install-time resume action.
    stop = runtime_dir / 'operator-stop'
    if stop.exists():
        _private(stop)
        stop.unlink()
    return {'status': 'installed', 'task_name': TASK_NAME, 'source_pins': pins}


def uninstall() -> dict:
    manifest = _read_manifest()
    state = _owned_task_state()
    if state is None:
        return {'status': 'not-installed', 'task_name': TASK_NAME}
    if not _valid_digest(manifest.get('task_xml_enabled_sha256')):
        raise RuntimeError('TASK_REGISTRATION_INCOMPLETE')
    _write_stop_marker()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        current = _owned_task_state()
        if current is None or current.get('state') in ('Ready', 'Disabled', 'Unknown'):
            break
        time.sleep(.5)
    else:
        raise RuntimeError('TASK_DID_NOT_STOP_CLEANLY')
    script = r"""
$ErrorActionPreference='Stop'
$name=$args[0]; $expected=$args[1]
$xml=Export-ScheduledTask -TaskName $name -ErrorAction Stop
$sha=[Security.Cryptography.SHA256]::Create()
$bytes=[Text.Encoding]::UTF8.GetBytes(([string]$xml).Trim())
$actual=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
if ($actual -ne $expected) { throw 'TASK_EXISTS_BUT_IS_NOT_OWNED' }
Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
'uninstalled'
"""
    if _powershell(script, TASK_NAME, state['xmlSha256']).returncode:
        raise RuntimeError('TASK_UNINSTALL_FAILED')
    return {'status': 'uninstalled', 'task_name': TASK_NAME}


def status() -> dict:
    manifest = _read_manifest()
    try:
        _confirm_pins()
        pins_valid = True
    except RuntimeError:
        pins_valid = False
    task = _owned_task_state()
    stop = _runtime_dir() / 'operator-stop'
    return {'task_name': TASK_NAME, 'task_state': task.get('state') if task else 'not-installed',
            'operator_stop_requested': stop.exists(), 'source_pins_valid': pins_valid,
            'source_pins': manifest['pins'],
            'api_runtime': _read_runtime_receipt()}


def _read_runtime_receipt() -> dict | None:
    path = _runtime_dir() / 'api-owner.json'
    if not path.exists():
        return None
    _private(path)
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, OSError):
        return {'state': 'unreadable'}


def _write_stop_marker() -> Path:
    path = _runtime_dir() / 'operator-stop'
    # An existing valid marker already requests a stop; never truncate it.
    _private(path, allow_missing=True)
    if path.exists():
        _private(path)
        return path
    _write_new_private_file(path, b'operator stop requested\n')
    return path


def operator_stop() -> dict:
    _read_manifest()
    if _owned_task_state() is None:
        raise RuntimeError('TASK_NOT_INSTALLED')
    _write_stop_marker()
    return {'status': 'stop-requested', 'task_name': TASK_NAME}


def _parse_commit_counters(counters: dict) -> tuple[float, float]:
    if not isinstance(counters, dict):
        raise RuntimeError('PERFOS_COUNTER_INVALID')
    values = (counters.get('CommittedBytes'), counters.get('CommitLimit'),
              counters.get('PercentCommittedBytesInUse'))
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in values):
        raise RuntimeError('PERFOS_COUNTER_INVALID')
    try:
        if any(not math.isfinite(value) for value in values):
            raise RuntimeError('PERFOS_COUNTER_INVALID')
    except (OverflowError, TypeError, ValueError):
        raise RuntimeError('PERFOS_COUNTER_INVALID') from None
    committed, limit, reported_percent = values
    if committed < 0 or limit <= 0 or committed > limit or not 0 <= reported_percent <= 100:
        raise RuntimeError('PERFOS_COUNTER_INVALID')
    return committed / limit, float(reported_percent)


def _perf_os_commit() -> tuple[float, float]:
    script = r"""
$ErrorActionPreference='Stop'
$v=Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory |
    Select-Object CommittedBytes,CommitLimit,PercentCommittedBytesInUse
if ($null -eq $v) { exit 3 }
$v | ConvertTo-Json -Compress
"""
    try:
        result = _powershell(script)
    except subprocess.TimeoutExpired:
        raise RuntimeError('PERFOS_COUNTER_UNAVAILABLE') from None
    if result.returncode:
        raise RuntimeError('PERFOS_COUNTER_UNAVAILABLE')
    try:
        counters = json.loads(result.stdout.decode('ascii').strip())
        return _parse_commit_counters(counters)
    except (ValueError, UnicodeError, TypeError):
        raise RuntimeError('PERFOS_COUNTER_INVALID') from None


def _host_gate() -> None:
    if os.name != 'nt':
        raise RuntimeError('WINDOWS_RUNTIME_REQUIRED')
    commit_ratio, reported_commit_percent = _perf_os_commit()
    if commit_ratio >= .85 or reported_commit_percent >= 85:
        raise RuntimeError('HOST_COMMIT_GATE_REFUSED')
    try:
        available = psutil.virtual_memory().available
    except (OSError, AttributeError):
        raise RuntimeError('HOST_RAM_GATE_REFUSED') from None
    if isinstance(available, bool) or not isinstance(available, (int, float)) \
            or not math.isfinite(available) or available < 6 * GiB:
        raise RuntimeError('HOST_RAM_GATE_REFUSED')
    if shutil.disk_usage('C:\\').free < 50_000_000_000:
        raise RuntimeError('HOST_DISK_GATE_REFUSED')


def _schema_017_gate() -> None:
    migration = _paths()['migration_017']
    if not migration.is_file():
        raise RuntimeError('MIGRATION_017_SOURCE_MISSING')
    # Store loads its existing local DSN without rendering it; this is a read-only
    # catalog check and intentionally does not apply or repair schema.
    from fieldwork.store import Store
    with Store().connect() as conn:
        present = conn.execute("SELECT to_regclass('public.fw_privacy_objects') IS NOT NULL").fetchone()[0]
    if not present:
        raise RuntimeError('MIGRATION_017_SCHEMA_REQUIRED')


def _acquire_start_lock():
    sys.path.insert(0, str(REPO / 'tools'))
    import product_lock
    shared_path = REPO / '.cache/product-build.lock'
    if Path(product_lock.DEFAULT).resolve() != shared_path.resolve():
        raise RuntimeError('SHARED_PRODUCT_LOCK_PATH_OVERRIDDEN')
    if not product_lock.acquire('fieldwork', PURPOSE, shared_path):
        raise RuntimeError('SHARED_PRODUCT_LOCK_HELD_OR_CLEANUP_PENDING')
    record = product_lock.read_owner(shared_path)
    if (not isinstance(record, dict) or not product_lock.is_mine(record) or record.get('product') != 'fieldwork'
            or record.get('purpose') != PURPOSE):
        product_lock.release(shared_path)
        raise RuntimeError('SHARED_PRODUCT_LOCK_OWNERSHIP_INVALID')
    return product_lock, shared_path


def _check_listener_absent() -> None:
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == 8102:
            raise RuntimeError('PORT_8102_ALREADY_IN_USE')


def _api_command(log_config: Path) -> list[str]:
    return [sys.executable, '-m', 'uvicorn', 'fieldwork.api:app', '--host', '127.0.0.1',
            '--port', '8102', '--no-access-log', '--log-config', str(log_config)]


def _api_environment() -> dict[str, str]:
    """Preserve the approved runtime pins across Task Scheduler's fresh environment."""
    env = dict(os.environ)
    env['FIELDWORK_REAL_PIXEL_IMAGE_ID'] = API_REAL_PIXEL_IMAGE_ID
    env['FIELDWORK_REAL_MODEL_IMAGE_ID'] = API_REAL_MODEL_IMAGE_ID
    env['FIELDWORK_QUALIFIED_MODEL_IMAGE_ID'] = API_REAL_MODEL_IMAGE_ID
    reviewers = ROOT / 'var/commons_r5/rights/reviewers.json'
    if 'FIELDWORK_RIGHTS_REVIEWERS_FILE' not in env and reviewers.is_file():
        env['FIELDWORK_RIGHTS_REVIEWERS_FILE'] = str(reviewers)
    return env


def _write_log_config() -> Path:
    var = ROOT / 'var'
    var.mkdir(exist_ok=True)
    _private(var)
    log_path = var / 'api-live.log'
    _private(log_path, allow_missing=True)
    config_path = _runtime_dir() / 'api-log-config.json'
    config = {'version': 1, 'disable_existing_loggers': False,
        'formatters': {'fieldwork': {'format': '%(asctime)s %(levelname)s %(name)s %(message)s'}},
        'handlers': {'fieldwork_file': {'class': 'fieldwork.privacy_logging.PrivateTimedRotatingFileHandler',
            'filename': str(log_path), 'when': 'midnight', 'interval': 1, 'backupCount': 0,
            'encoding': 'utf-8', 'delay': True, 'formatter': 'fieldwork'}},
        'loggers': {'uvicorn': {'handlers': ['fieldwork_file'], 'level': 'INFO', 'propagate': False},
            'uvicorn.error': {'handlers': ['fieldwork_file'], 'level': 'INFO', 'propagate': False},
            'uvicorn.access': {'handlers': ['fieldwork_file'], 'level': 'WARNING', 'propagate': False}},
        'root': {'handlers': ['fieldwork_file'], 'level': 'WARNING'}}
    raw = json.dumps(config, separators=(',', ':')).encode('utf-8')
    _private(config_path, allow_missing=True)
    if config_path.exists():
        _private(config_path)
        if config_path.read_bytes() != raw:
            raise RuntimeError('PRIVATE_FILE_CONTENT_MISMATCH')
    else:
        _write_new_private_file(config_path, raw)
    return config_path


def _atomic_receipt(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with tmp.open('x', encoding='utf-8') as f:
        json.dump(data, f, sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
    _private(tmp)
    os.replace(tmp, path)
    _private(path)


def _identity(pid: int, created: float, cwd: Path, command: list[str]) -> psutil.Process:
    try:
        proc = psutil.Process(pid)
        actual_created = proc.create_time()
        actual_cwd = Path(proc.cwd()).resolve()
        actual_cmd = proc.cmdline()
    except (psutil.Error, OSError):
        raise RuntimeError('PROCESS_IDENTITY_UNAVAILABLE') from None
    if abs(actual_created - created) >= .01 or actual_cwd != cwd.resolve() or actual_cmd != command:
        raise RuntimeError('PROCESS_IDENTITY_MISMATCH')
    return proc


def _process_record(proc: psutil.Process) -> dict:
    return {'pid': proc.pid, 'create_time': proc.create_time(), 'cwd': str(Path(proc.cwd()).resolve()),
            'command': proc.cmdline(), 'executable': str(Path(proc.exe()).resolve()), 'ppid': proc.ppid()}


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def _validate_record(record: dict, expected_parent: int | None = None) -> psutil.Process | None:
    """Return the exact recorded live process, or None if that PID has exited."""
    try:
        proc = psutil.Process(int(record['pid']))
        created = proc.create_time()
        cwd = str(Path(proc.cwd()).resolve())
        command = proc.cmdline()
        executable = str(Path(proc.exe()).resolve())
        ppid = proc.ppid()
    except psutil.NoSuchProcess:
        return None
    except (psutil.Error, OSError, KeyError, TypeError, ValueError):
        raise RuntimeError('PROCESS_TREE_IDENTITY_MISMATCH') from None
    if (abs(created - float(record['create_time'])) >= .01
            or not _same_path(cwd, str(record['cwd']))
            or command != record['command']
            or not _same_path(executable, str(record['executable']))
            or ppid != int(record['ppid'])
            or (expected_parent is not None and ppid != expected_parent)):
        raise RuntimeError('PROCESS_TREE_IDENTITY_MISMATCH')
    return proc


def _allowed_python_executables(command: list[str]) -> set[str]:
    allowed = {os.path.normcase(os.path.normpath(str(Path(command[0]).resolve())))}
    base_python = getattr(sys, '_base_executable', None)
    if isinstance(base_python, str) and base_python:
        allowed.add(os.path.normcase(os.path.normpath(str(Path(base_python).resolve()))))
    return allowed


def _tree_for_target(launcher: psutil.Process, target: psutil.Process, cwd: Path,
                     command: list[str], port: int | None) -> dict | None:
    launcher_record = _process_record(launcher)
    try:
        target_record = _process_record(target)
        allowed = _allowed_python_executables(command)
        if (target_record['command'][1:] != command[1:]
                or os.path.normcase(os.path.normpath(target_record['executable'])) not in allowed
                or not _same_path(target_record['cwd'], str(cwd.resolve()))):
            return None
        reverse_descendants = []
        current = target
        while current.pid != launcher.pid:
            reverse_descendants.append(_process_record(current))
            current = current.parent()
            if current is None:
                return None
        descendants = list(reversed(reverse_descendants))
        records = [launcher_record, *descendants]
        for index in range(1, len(records)):
            if records[index]['ppid'] != records[index - 1]['pid']:
                raise RuntimeError('PROCESS_TREE_IDENTITY_MISMATCH')
        if not descendants:
            records = [launcher_record]
        owner = records[-1]
        return {'launcher_pid': launcher.pid, 'owner_pid': owner['pid'],
                'owner_create_time': owner['create_time'], 'listener_pid': owner['pid'] if port else None,
                'listener_create_time': owner['create_time'] if port else None,
                'port': port, 'processes': records}
    except psutil.NoSuchProcess:
        return None
    except (psutil.Error, OSError):
        return None


def _owned_command_tree(launcher_pid: int, launcher_created: float, cwd: Path,
                        command: list[str]) -> dict | None:
    """Capture the exact API-command descendant before it binds a listener."""
    launcher = _identity(launcher_pid, launcher_created, cwd, command)
    try:
        children = launcher.children(recursive=True)
    except psutil.Error:
        return None
    for child in children:
        tree = _tree_for_target(launcher, child, cwd, command, None)
        if tree is not None:
            return tree
    return None


def _owned_listener_tree(launcher_pid: int, launcher_created: float, cwd: Path,
                         command: list[str], port: int) -> dict | None:
    """Find the exact-command listener and capture its ancestry to the launcher."""
    launcher = _identity(launcher_pid, launcher_created, cwd, command)
    listeners = {conn.pid for conn in psutil.net_connections(kind='tcp')
                 if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port and conn.pid is not None}
    for listener_pid in listeners:
        try:
            target = launcher if listener_pid == launcher_pid else psutil.Process(listener_pid)
            tree = _tree_for_target(launcher, target, cwd, command, port)
            if tree is not None and tree['owner_pid'] == listener_pid:
                return tree
        except psutil.NoSuchProcess:
            continue
        except (psutil.Error, OSError):
            continue
    return None


def _validate_owned_tree(tree: dict) -> list[psutil.Process | None]:
    records = tree.get('processes') if isinstance(tree, dict) else None
    if not isinstance(records, list) or not records:
        raise RuntimeError('PROCESS_TREE_IDENTITY_MISMATCH')
    current = []
    for index, record in enumerate(records):
        parent_pid = records[index - 1]['pid'] if index else None
        current.append(_validate_record(record, parent_pid))
    owner = records[-1]
    if (int(tree.get('owner_pid', -1)) != int(owner['pid'])
            or abs(float(tree.get('owner_create_time', -1)) - float(owner['create_time'])) >= .01
            or (tree.get('port') is not None and
                (int(tree.get('listener_pid', -1)) != int(owner['pid'])
                 or abs(float(tree.get('listener_create_time', -1)) - float(owner['create_time'])) >= .01))):
        raise RuntimeError('PROCESS_TREE_IDENTITY_MISMATCH')
    return current


def _listener_owned_by(tree: dict) -> bool:
    if not isinstance(tree, dict) or tree.get('port') is None:
        return False
    current = _validate_owned_tree(tree)
    if not current or current[-1] is None:
        return False
    return any(conn.status == psutil.CONN_LISTEN and conn.laddr.port == int(tree['port'])
               and conn.pid == int(tree['owner_pid']) for conn in psutil.net_connections(kind='tcp'))


def _capture_owned_api_tree(launcher_pid: int, created: float, command: list[str],
                            owner_tree: dict | None, stop_path: Path
                            ) -> tuple[dict | None, dict | None, bool]:
    """Refresh descendant identity before observing an operator stop request."""
    def refresh(current_tree):
        early_tree = _owned_command_tree(launcher_pid, created, ROOT, command)
        if early_tree is not None:
            current_tree = early_tree
        listener_tree = _owned_listener_tree(launcher_pid, created, ROOT, command, 8102)
        if listener_tree is not None:
            current_tree = listener_tree
        return current_tree, listener_tree

    owner_tree, listener_tree = refresh(owner_tree)
    stop_requested = stop_path.exists()
    if stop_requested and owner_tree is None:
        deadline = time.monotonic() + STOP_CAPTURE_GRACE_SECONDS
        while owner_tree is None and time.monotonic() < deadline:
            time.sleep(.05)
            owner_tree, listener_tree = refresh(owner_tree)
    return owner_tree, listener_tree, stop_requested


def _terminate_owned_tree(process: subprocess.Popen, launcher_record: dict,
                          tree: dict | None) -> None:
    if tree is None:
        proc = _validate_record(launcher_record)
        if proc is None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except psutil.TimeoutExpired:
            _validate_record(launcher_record).kill()
            proc.wait(timeout=5)
        return
    current = _validate_owned_tree(tree)
    records = tree['processes']
    for index in range(len(records) - 1, -1, -1):
        record, proc = records[index], current[index]
        if proc is None:
            continue
        # Revalidate identity and ancestry immediately before each signal.
        expected_parent = records[index - 1]['pid'] if index else None
        proc = _validate_record(record, expected_parent)
        if proc is None:
            continue
        proc.terminate()
        try:
            proc.wait(timeout=15 if record['pid'] == tree['owner_pid'] else 5)
        except psutil.TimeoutExpired:
            proc = _validate_record(record, expected_parent)
            if proc is None:
                continue
            proc.kill()
            proc.wait(timeout=5)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        # The launcher is part of the captured chain and was already identity-checked.
        pass


def run() -> int:
    _require_venv_python()
    manifest = _confirm_pins()
    task_state = _owned_task_state()
    if task_state is None:
        raise RuntimeError('TASK_NOT_INSTALLED')
    if task_state.get('state') == 'Disabled' or not _valid_digest(manifest.get('task_xml_enabled_sha256')):
        raise RuntimeError('TASK_DEFINITION_MISMATCH')
    runtime = _runtime_dir()
    stop = runtime / 'operator-stop'
    if stop.exists():
        return 0
    lock, lock_path = _acquire_start_lock()
    lock_held = True
    process = None
    created = None
    command = None
    launcher_record = None
    owner_tree = None
    try:
        _host_gate()
        _schema_017_gate()
        _check_listener_absent()
        # Recheck after admission: another product could have started during gates.
        _check_listener_absent()
        log_config = _write_log_config()
        env = _api_environment()
        command = _api_command(log_config)
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        created = psutil.Process(process.pid).create_time()
        launcher_record = _process_record(_identity(process.pid, created, ROOT, command))
        owner_tree = _owned_command_tree(process.pid, created, ROOT, command)
        receipt_path = runtime / 'api-owner.json'
        receipt = {'schema': 'fieldwork.durable-runtime-process/v1', 'pid': process.pid,
                   'create_time': created, 'cwd': str(ROOT), 'command': command,
                   'launcher': launcher_record, 'owned_process_tree': owner_tree,
                   'source_pins': manifest['pins'], 'state': 'starting', 'started_epoch': time.time()}
        _atomic_receipt(receipt_path, receipt)
        # PID is identity evidence only; never report readiness without the API probe.
        import httpx
        deadline = time.monotonic() + 30
        ready = False
        while time.monotonic() < deadline:
            # Capture a late-starting venv child before honoring an operator stop.
            owner_tree, listener_tree, stop_requested = _capture_owned_api_tree(
                process.pid, created, command, owner_tree, stop)
            if owner_tree is not None and receipt['owned_process_tree'] != owner_tree:
                receipt['owned_process_tree'] = owner_tree
                _atomic_receipt(receipt_path, receipt)
            if stop_requested:
                break
            try:
                response = httpx.get('http://127.0.0.1:8102/health/ready', timeout=1)
                ready = response.status_code == 200 and listener_tree is not None \
                    and _listener_owned_by(listener_tree)
            except httpx.HTTPError:
                pass
            if ready:
                receipt['owned_process_tree'] = owner_tree
                receipt['state'] = 'ready-probe-passed'
                _atomic_receipt(receipt_path, receipt)
                # Serialize admission and startup only; the running API must not
                # monopolize the shared portfolio build lock for its lifetime.
                if not lock.release(lock_path):
                    raise RuntimeError('SHARED_PRODUCT_LOCK_RELEASE_REFUSED')
                lock_held = False
                break
            time.sleep(.25)
        if not ready:
            if stop.exists():
                return 0
            raise RuntimeError('API_READINESS_PROBE_FAILED')
        # A venv redirector may own a base-Python descendant that owns the port.
        # Supervise that captured listener tree, not just the redirector PID.
        while not stop.exists():
            current = _validate_owned_tree(owner_tree)
            if not current or current[-1] is None:
                break
            time.sleep(POLL_SECONDS)
        _terminate_owned_tree(process, launcher_record, owner_tree)
        receipt['state'] = 'stopped' if stop.exists() else 'api-exited'
        receipt['stopped_epoch'] = time.time()
        _atomic_receipt(receipt_path, receipt)
        return 0
    finally:
        if process is not None and launcher_record is not None \
                and (owner_tree is not None or process.poll() is None):
            try:
                _terminate_owned_tree(process, launcher_record, owner_tree)
            except (RuntimeError, psutil.Error, subprocess.TimeoutExpired, OSError):
                # Never signal an unvalidated or reused process identity.
                pass
        if lock_held and not lock.release(lock_path):
            raise RuntimeError('SHARED_PRODUCT_LOCK_RELEASE_REFUSED')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'uninstall', 'status', 'run', 'operatorstop'))
    args = parser.parse_args(argv)
    try:
        result = {'install': install, 'uninstall': uninstall, 'status': status,
                  'run': run, 'operatorstop': operator_stop}[args.action]()
        if isinstance(result, dict):
            print(json.dumps(result, sort_keys=True))
        return int(result) if isinstance(result, int) else 0
    except Exception as exc:
        # Emit only a fixed code allowlist; arbitrary exception text may be private.
        raw = exc.args[0] if exc.args else ''
        code = raw if isinstance(raw, str) and raw in SAFE_ERROR_CODES else 'UNEXPECTED_ERROR'
        print(json.dumps({'status': 'refused', 'code': code}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
