"""Focused unit checks for the source-only durable runtime launcher."""
from __future__ import annotations

import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import unittest
from unittest.mock import Mock, patch

from tools import durable_runtime as runtime


class RuntimeSourceTests(unittest.TestCase):
    def _owned_state(self):
        powershell = str(Path(runtime.os.environ.get('SystemRoot', r'C:\Windows')) /
                         'System32/WindowsPowerShell/v1.0/powershell.exe')
        return {'exists': True, 'taskPath': '\\', 'taskName': runtime.TASK_NAME,
            'author': runtime._owner_user(), 'description': runtime.TASK_MARKER,
            'actions': [{'type': 'MSFT_TaskExecAction', 'execute': powershell,
                'arguments': runtime._task_arguments(), 'workingDirectory': str(runtime.ROOT), 'id': ''}],
            'triggers': [{'type': 'MSFT_TaskLogonTrigger', 'userId': runtime._owner_user(), 'enabled': True}],
            'settings': {'hidden': True, 'multipleInstances': 'IgnoreNew',
                'executionTimeLimitSeconds': 0.0, 'startWhenAvailable': True,
                'disallowStartIfOnBatteries': False, 'stopIfGoingOnBatteries': False,
                'allowHardTerminate': True, 'wakeToRun': False,
                'runOnlyIfNetworkAvailable': False, 'priority': 7},
            'state': 'Ready', 'user': runtime._owner_user(),
            'principalSid': 'S-1-5-21-111-222-333-1000',
            'currentUserSid': 'S-1-5-21-111-222-333-1000', 'logonType': 'Interactive',
            'runLevel': 'Limited', 'groupId': '', 'xmlSha256': 'a' * 64,
            'xmlDisabledSha256': 'b' * 64, 'xmlEnabledSha256': 'a' * 64}

    def test_owned_task_identity_is_strict(self):
        state = self._owned_state()
        with patch.object(runtime, '_task_state', return_value=state), \
             patch.object(runtime, '_read_manifest', return_value={
                 'task_xml_enabled_sha256': 'a' * 64, 'task_xml_disabled_sha256': 'b' * 64,
                 'registration_pending': False}):
            self.assertEqual(runtime._owned_task_state()['state'], 'Ready')
        state['actions'].append(dict(state['actions'][0]))
        with patch.object(runtime, '_task_state', return_value=state), \
             patch.object(runtime, '_read_manifest', return_value={
                 'task_xml_enabled_sha256': 'a' * 64, 'task_xml_disabled_sha256': 'b' * 64,
                 'registration_pending': False}):
            with self.assertRaisesRegex(RuntimeError, 'TASK_EXISTS_BUT_IS_NOT_OWNED'):
                runtime._owned_task_state()

    def test_owned_task_accepts_same_user_name_alias_but_rejects_foreign_sid(self):
        manifest = {'task_xml_enabled_sha256': 'a' * 64,
                    'task_xml_disabled_sha256': 'b' * 64, 'registration_pending': False}
        state = self._owned_state()
        state['user'] = 'user'
        with patch.object(runtime, '_task_state', return_value=state), \
             patch.object(runtime, '_read_manifest', return_value=manifest):
            self.assertEqual(runtime._owned_task_state()['state'], 'Ready')

        state['principalSid'] = 'S-1-5-21-111-222-333-1001'
        with patch.object(runtime, '_task_state', return_value=state), \
             patch.object(runtime, '_read_manifest', return_value=manifest):
            with self.assertRaisesRegex(RuntimeError, 'TASK_EXISTS_BUT_IS_NOT_OWNED'):
                runtime._owned_task_state()

    def test_owned_task_rejects_action_trigger_principal_runlevel_and_settings_changes(self):
        mutations = [
            lambda state: state['actions'][0].update(arguments=state['actions'][0]['arguments'] + ' -Extra'),
            lambda state: state['triggers'].append(dict(state['triggers'][0])),
            lambda state: state.update(runLevel='Highest'),
            lambda state: state['settings'].update(hidden=False),
        ]
        for mutate in mutations:
            state = self._owned_state()
            mutate(state)
            with self.subTest(state=state), \
                 patch.object(runtime, '_task_state', return_value=state), \
                 patch.object(runtime, '_read_manifest', return_value={
                     'task_xml_enabled_sha256': 'a' * 64, 'task_xml_disabled_sha256': 'b' * 64,
                     'registration_pending': False}):
                with self.assertRaisesRegex(RuntimeError, 'TASK_EXISTS_BUT_IS_NOT_OWNED'):
                    runtime._owned_task_state()

    def test_owner_manifest_publication_is_exclusive_and_preserves_prior_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'owner-pins.json'
            manifest = {'schema': 'fieldwork.durable-runtime-owner/v1',
                'task_name': runtime.TASK_NAME, 'task_marker': runtime.TASK_MARKER,
                'root': str(runtime.ROOT), 'pins': {'launcher': 'a' * 64},
                'owner_user': runtime._owner_user(), 'task_xml_enabled_sha256': None,
                'task_xml_disabled_sha256': None, 'registration_pending': True}
            with patch.object(runtime, '_manifest_path', return_value=path), \
                 patch.object(runtime, '_private', return_value=None):
                self.assertIsNone(runtime._publish_manifest(manifest))
                first = path.read_bytes()
                manifest['pins'] = {'launcher': 'b' * 64}
                self.assertEqual(runtime._publish_manifest(manifest), first)
                prior = list(Path(temp).glob('owner-pins.*.previous.*.json'))
                self.assertEqual(len(prior), 1)
                self.assertEqual(prior[0].read_bytes(), first)
                self.assertEqual(json.loads(path.read_text())['pins']['launcher'], 'b' * 64)

    def test_refusal_output_never_echoes_arbitrary_exception_arguments(self):
        stdout = io.StringIO()
        with patch.object(runtime, 'status', side_effect=RuntimeError('secret-token-123')), \
             contextlib.redirect_stdout(stdout):
            self.assertEqual(runtime.main(['status']), 2)
        self.assertEqual(json.loads(stdout.getvalue()), {'status': 'refused', 'code': 'UNEXPECTED_ERROR'})
        self.assertNotIn('secret-token', stdout.getvalue())

    def test_install_interpreter_must_be_the_fixed_venv(self):
        with patch.object(runtime, '_fixed_python_path', return_value=Path('C:/elsewhere/python.exe')):
            with self.assertRaisesRegex(RuntimeError, 'VENV_PYTHON_REQUIRED'):
                runtime._require_venv_python()

    @unittest.skipUnless(os.name == 'nt', 'the Task Scheduler status entrypoint is Windows-only')
    def test_direct_file_entrypoint_status_imports_repository_packages(self):
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        result = subprocess.run(
            [sys.executable, '-B', str(runtime.ROOT / 'tools/durable_runtime.py'), 'status'],
            cwd=runtime.ROOT, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
        self.assertIn(result.returncode, (0, 2), result.stderr.decode('utf-8', 'replace'))
        output = json.loads(result.stdout.decode('utf-8-sig').strip())
        if result.returncode == 0:
            self.assertEqual(output.get('task_name'), runtime.TASK_NAME)
        else:
            self.assertIn(output.get('code'), runtime.SAFE_ERROR_CODES - {'UNEXPECTED_ERROR'})

    @unittest.skipUnless(os.name == 'nt', 'requires Windows PowerShell 5.1')
    def test_powershell_file_argv_round_trip_preserves_spaces_and_quotes(self):
        runtime._runtime_dir()
        script_dir = runtime.ROOT / 'var/durable-runtime'
        before = {path.name for path in script_dir.glob('powershell-*.ps1')}
        script = r"""
if ($args.Count -ne 4 -or $args[0] -cne 'plain' -or $args[1] -cne 'two words' -or
    $args[2] -cne 'quote"inside' -or $args[3] -cne "apostrophe'inside") { exit 17 }
'PS_ARGUMENTS_OK'
"""
        result = runtime._powershell(script, 'plain', 'two words', 'quote"inside', "apostrophe'inside")
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace'))
        self.assertIn('PS_ARGUMENTS_OK', result.stdout.decode('utf-8-sig', 'replace'))
        after = {path.name for path in script_dir.glob('powershell-*.ps1')}
        self.assertEqual(after, before, 'owned temporary PowerShell script must be removed')

    @unittest.skipUnless(os.name == 'nt', 'requires the Windows Task Scheduler query module')
    def test_task_state_query_works_without_task_installation(self):
        state = runtime._task_state()
        self.assertIn('exists', state)
        if state['exists']:
            self.assertIn('principalSid', state)
            self.assertIn('currentUserSid', state)

    def test_commit_counter_sampler_uses_memory_class_and_validates_json(self):
        result = type('Result', (), {'returncode': 0,
            'stdout': b'{"CommittedBytes":800,"CommitLimit":1000,"PercentCommittedBytesInUse":80}'})()
        with patch.object(runtime, '_powershell', return_value=result) as powershell:
            self.assertEqual(runtime._perf_os_commit(), (.8, 80.0))
        script = powershell.call_args.args[0]
        self.assertIn('Win32_PerfFormattedData_PerfOS_Memory', script)
        self.assertIn('CommittedBytes,CommitLimit,PercentCommittedBytesInUse', script)
        self.assertNotIn('Processor', script)
        with patch.object(runtime, '_powershell', side_effect=runtime.subprocess.TimeoutExpired('powershell', 1)):
            with self.assertRaisesRegex(RuntimeError, 'PERFOS_COUNTER_UNAVAILABLE'):
                runtime._perf_os_commit()
        missing = type('Result', (), {'returncode': 3, 'stdout': b''})()
        with patch.object(runtime, '_powershell', return_value=missing):
            with self.assertRaisesRegex(RuntimeError, 'PERFOS_COUNTER_UNAVAILABLE'):
                runtime._perf_os_commit()
        for counters in (
            {'CommittedBytes': float('nan'), 'CommitLimit': 1000, 'PercentCommittedBytesInUse': 1},
            {'CommittedBytes': 10 ** 1000, 'CommitLimit': 10 ** 1001, 'PercentCommittedBytesInUse': 1},
            {'CommittedBytes': 1, 'CommitLimit': 0, 'PercentCommittedBytesInUse': 1},
            {'CommittedBytes': 1001, 'CommitLimit': 1000, 'PercentCommittedBytesInUse': 1},
        ):
            with self.subTest(counters=counters), self.assertRaisesRegex(RuntimeError, 'PERFOS_COUNTER_INVALID'):
                runtime._parse_commit_counters(counters)

    def test_commit_ratio_at_85_refuses_even_if_counter_rounds_to_84(self):
        counters = {'CommittedBytes': 850, 'CommitLimit': 1000,
                    'PercentCommittedBytesInUse': 84}
        self.assertFalse(hasattr(runtime, '_perf_os_cpu_percent'))
        with patch.object(runtime.os, 'name', 'nt'), \
             patch.object(runtime, '_perf_os_commit', return_value=runtime._parse_commit_counters(counters)):
            with self.assertRaisesRegex(RuntimeError, 'HOST_COMMIT_GATE_REFUSED'):
                runtime._host_gate()

    def test_reported_commit_counter_at_85_refuses(self):
        with patch.object(runtime.os, 'name', 'nt'), \
             patch.object(runtime, '_perf_os_commit', return_value=(.84, 85.0)):
            with self.assertRaisesRegex(RuntimeError, 'HOST_COMMIT_GATE_REFUSED'):
                runtime._host_gate()

    def test_available_ram_gate_uses_available_not_installed_total(self):
        memory = type('Memory', (), {'total': 32 * runtime.GiB, 'available': 5 * runtime.GiB})()
        with patch.object(runtime.os, 'name', 'nt'), \
             patch.object(runtime, '_perf_os_commit', return_value=(.5, 50)), \
             patch.object(runtime.psutil, 'virtual_memory', return_value=memory):
            with self.assertRaisesRegex(RuntimeError, 'HOST_RAM_GATE_REFUSED'):
                runtime._host_gate()

    def test_api_environment_pins_approved_image_ids(self):
        with patch.dict(runtime.os.environ, {
            'FIELDWORK_REAL_PIXEL_IMAGE_ID': 'sha256:wrong',
            'FIELDWORK_REAL_MODEL_IMAGE_ID': 'sha256:wrong',
            'FIELDWORK_QUALIFIED_MODEL_IMAGE_ID': 'sha256:wrong',
            'DURABLE_RUNTIME_TEST_ENV': 'preserved',
        }, clear=False):
            env = runtime._api_environment()
        self.assertEqual(env['FIELDWORK_REAL_PIXEL_IMAGE_ID'],
            'sha256:b42e39dfea7adbace1be7766fc071e94ff3424ac175485c633986ac8ae883dcd')
        self.assertEqual(env['FIELDWORK_REAL_MODEL_IMAGE_ID'],
            'sha256:41c680046133d0920a217adbfb951b8c77e4cec7e3ea7763646b19c5f4e7dfdc')
        self.assertEqual(env['FIELDWORK_QUALIFIED_MODEL_IMAGE_ID'],
            env['FIELDWORK_REAL_MODEL_IMAGE_ID'])
        self.assertEqual(env['DURABLE_RUNTIME_TEST_ENV'], 'preserved')

    @unittest.skipUnless(os.name == 'nt', 'requires the Windows venv Python redirector')
    def test_venv_redirector_child_listener_is_ready_and_owned_tree_stops(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        server_script = (
            'import http.server,sys; '
            'class_body=""; '
            'Handler=type("Handler",(http.server.BaseHTTPRequestHandler,),'
            '{"do_GET":lambda self:(self.send_response(200),self.end_headers(),self.wfile.write(b\"ok\")), '
            '"log_message":lambda *a:None}); '
            'http.server.HTTPServer(("127.0.0.1",int(sys.argv[1])),Handler).serve_forever()'
        )
        command = [sys.executable, '-c', server_script, str(port)]
        process = subprocess.Popen(command, cwd=runtime.ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        created = runtime.psutil.Process(process.pid).create_time()
        launcher_record = runtime._process_record(runtime._identity(process.pid, created,
            runtime.ROOT, command))
        tree = None
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                tree = runtime._owned_listener_tree(process.pid, created, runtime.ROOT, command, port)
                if tree is not None and runtime._listener_owned_by(tree):
                    break
                time.sleep(.1)
            self.assertIsNotNone(tree, 'the venv listener descendant was not discovered')
            self.assertNotEqual(tree['listener_pid'], process.pid,
                'fixture did not exercise a child listener owned by the venv redirector')
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=2) as response:
                self.assertEqual((response.status, response.read()), (200, b'ok'))
            runtime._terminate_owned_tree(process, launcher_record, tree)
            process.wait(timeout=5)
            self.assertFalse(runtime._listener_owned_by(tree))
        finally:
            if tree is not None and (process.poll() is None or runtime.psutil.pid_exists(tree['listener_pid'])):
                try:
                    runtime._terminate_owned_tree(process, launcher_record, tree)
                except (RuntimeError, runtime.psutil.Error, OSError):
                    pass
            elif process.poll() is None:
                runtime._terminate_owned_tree(process, launcher_record, None)

    @unittest.skipUnless(os.name == 'nt', 'requires the Windows venv Python redirector')
    def test_readiness_failure_before_listener_still_stops_captured_child(self):
        # Simulates a child that starts but fails readiness before it binds 8102.
        command = [sys.executable, '-c', 'import time; time.sleep(60)']
        process = subprocess.Popen(command, cwd=runtime.ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        created = runtime.psutil.Process(process.pid).create_time()
        launcher_record = runtime._process_record(runtime._identity(process.pid, created,
            runtime.ROOT, command))
        tree = None
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                tree = runtime._owned_command_tree(process.pid, created, runtime.ROOT, command)
                if tree is not None:
                    break
                time.sleep(.05)
            self.assertIsNotNone(tree, 'the pre-listener redirector child was not captured')
            self.assertNotEqual(tree['owner_pid'], process.pid)
            self.assertFalse(runtime._listener_owned_by(tree))
            runtime._terminate_owned_tree(process, launcher_record, tree)
            process.wait(timeout=5)
            self.assertIsNone(runtime._validate_record(tree['processes'][-1]))
        finally:
            if tree is not None and (process.poll() is None or runtime.psutil.pid_exists(tree['owner_pid'])):
                try:
                    runtime._terminate_owned_tree(process, launcher_record, tree)
                except (RuntimeError, runtime.psutil.Error, OSError):
                    pass
            elif process.poll() is None:
                runtime._terminate_owned_tree(process, launcher_record, None)

    @unittest.skipUnless(os.name == 'nt', 'requires the Windows venv Python redirector')
    def test_stop_before_first_readiness_capture_stops_late_venv_child(self):
        # Model the initial post-Popen snapshot missing the redirector child;
        # stop is already requested when the first readiness iteration runs.
        command = [sys.executable, '-c', 'import time; time.sleep(60)']
        process = subprocess.Popen(command, cwd=runtime.ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        created = runtime.psutil.Process(process.pid).create_time()
        launcher_record = runtime._process_record(runtime._identity(process.pid, created,
            runtime.ROOT, command))
        owner_tree = None
        with tempfile.TemporaryDirectory() as temp:
            stop_path = Path(temp) / 'operator-stop'
            stop_path.write_text('stop requested\n', encoding='utf-8')
            actual_capture = runtime._owned_command_tree
            captures = 0

            def miss_initial_snapshot(*args):
                nonlocal captures
                captures += 1
                if captures == 1:
                    return None
                return actual_capture(*args)

            try:
                with patch.object(runtime, '_owned_command_tree', side_effect=miss_initial_snapshot):
                    owner_tree, listener_tree, stop_requested = runtime._capture_owned_api_tree(
                        process.pid, created, command, owner_tree, stop_path)
                self.assertTrue(stop_requested)
                self.assertGreaterEqual(captures, 2,
                    'capture grace must retry after the initial post-Popen snapshot misses')
                self.assertIsNotNone(owner_tree,
                    'the late venv descendant must be captured before stop is honored')
                self.assertIsNone(listener_tree,
                    'the child should be captured before it binds a listener')
                self.assertNotEqual(owner_tree['owner_pid'], process.pid,
                    'fixture did not exercise a child process behind the venv redirector')
                runtime._terminate_owned_tree(process, launcher_record, owner_tree)
                process.wait(timeout=5)
                self.assertIsNone(runtime._validate_record(owner_tree['processes'][-1]))
            finally:
                if owner_tree is not None and (process.poll() is None
                                               or runtime.psutil.pid_exists(owner_tree['owner_pid'])):
                    try:
                        runtime._terminate_owned_tree(process, launcher_record, owner_tree)
                    except (RuntimeError, runtime.psutil.Error, OSError):
                        pass
                elif process.poll() is None:
                    runtime._terminate_owned_tree(process, launcher_record, None)

    def test_run_releases_start_lock_after_ready_receipt_before_supervision(self):
        class Lock:
            def __init__(self):
                self.releases = 0

            def release(self, path):
                self.releases += 1
                return True

        lock = Lock()
        owned_tree = {'owner_pid': 2002, 'processes': []}
        launcher_record = {'pid': 2001}
        api_process = Mock()
        api_process.pid = 2001
        api_process.poll.return_value = None
        ready_response = Mock(status_code=200)
        receipt_states = []

        def persist_receipt(path, receipt):
            receipt_states.append((receipt['state'], lock.releases))

        with tempfile.TemporaryDirectory() as temp:
            runtime_dir = Path(temp)
            stop = runtime_dir / 'operator-stop'
            command = ['python.exe', '-m', 'uvicorn', 'fieldwork.api:app']

            def validate_during_supervision(tree):
                self.assertEqual(lock.releases, 1,
                    'the shared startup lock must be free before lifetime supervision')
                stop.write_text('stop requested\n', encoding='utf-8')
                return [Mock()]

            patches = [
                patch.object(runtime, '_require_venv_python'),
                patch.object(runtime, '_confirm_pins', return_value={
                    'pins': {}, 'task_xml_enabled_sha256': 'a' * 64}),
                patch.object(runtime, '_owned_task_state', return_value={'state': 'Ready'}),
                patch.object(runtime, '_runtime_dir', return_value=runtime_dir),
                patch.object(runtime, '_acquire_start_lock', return_value=(lock, Path(temp) / 'lock')),
                patch.object(runtime, '_host_gate'),
                patch.object(runtime, '_schema_017_gate'),
                patch.object(runtime, '_check_listener_absent'),
                patch.object(runtime, '_write_log_config', return_value=runtime_dir / 'logging.json'),
                patch.object(runtime, '_api_environment', return_value={}),
                patch.object(runtime, '_api_command', return_value=command),
                patch.object(runtime.subprocess, 'Popen', return_value=api_process),
                patch.object(runtime.psutil, 'Process', return_value=Mock(create_time=Mock(return_value=1.0))),
                patch.object(runtime, '_identity', return_value=Mock()),
                patch.object(runtime, '_process_record', return_value=launcher_record),
                patch.object(runtime, '_owned_command_tree', return_value=None),
                patch.object(runtime, '_owned_listener_tree', return_value=None),
                patch.object(runtime, '_capture_owned_api_tree',
                             return_value=(owned_tree, owned_tree, False)),
                patch.object(runtime, '_listener_owned_by', return_value=True),
                patch.object(runtime, '_validate_owned_tree', side_effect=validate_during_supervision),
                patch.object(runtime, '_terminate_owned_tree'),
                patch.object(runtime, '_atomic_receipt', side_effect=persist_receipt),
                patch.object(runtime.time, 'sleep'),
                patch('httpx.get', return_value=ready_response),
            ]
            with contextlib.ExitStack() as stack:
                for active_patch in patches:
                    stack.enter_context(active_patch)
                self.assertEqual(runtime.run(), 0)

        self.assertEqual(receipt_states[0], ('starting', 0))
        self.assertIn(('ready-probe-passed', 0), receipt_states)
        self.assertEqual(receipt_states[-1], ('stopped', 1))
        self.assertEqual(lock.releases, 1,
            'readiness release should prevent a duplicate finally release')

    def test_stop_marker_is_idempotent_and_never_truncates_existing_leaf(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'operator-stop'
            original = b'existing trusted stop marker\n'
            path.write_bytes(original)
            with patch.object(runtime, '_runtime_dir', return_value=Path(temp)), \
                 patch.object(runtime, '_private', return_value=None), \
                 patch.object(Path, 'open', side_effect=AssertionError('existing leaf opened')):
                self.assertEqual(runtime._write_stop_marker(), path)
            self.assertEqual(path.read_bytes(), original)

    def test_private_leaf_is_validated_before_exclusive_open(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'leaf'
            with patch.object(runtime, '_private', side_effect=RuntimeError('unsafe leaf')) as check, \
                 patch.object(Path, 'open', side_effect=AssertionError('open before validation')) as open_leaf:
                with self.assertRaisesRegex(RuntimeError, 'unsafe leaf'):
                    runtime._write_new_private_file(path, b'content')
            check.assert_called_once_with(path, allow_missing=True)
            open_leaf.assert_not_called()

    def test_private_file_creation_does_not_clobber_existing_leaf(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'leaf'
            original = b'keep this leaf unchanged\n'
            path.write_bytes(original)
            with patch.object(runtime, '_private', return_value=None):
                with self.assertRaisesRegex(RuntimeError, 'PRIVATE_FILE_ALREADY_EXISTS'):
                    runtime._write_new_private_file(path, b'new data')
            self.assertEqual(path.read_bytes(), original)

    def test_process_identity_rejects_pid_reuse_or_command_change(self):
        fake = type('Process', (), {'create_time': lambda self: 12.0,
            'cwd': lambda self: str(runtime.ROOT), 'cmdline': lambda self: ['python', 'wrong']})()
        with patch.object(runtime.psutil, 'Process', return_value=fake):
            with self.assertRaisesRegex(RuntimeError, 'PROCESS_IDENTITY_MISMATCH'):
                runtime._identity(10, 12.0, runtime.ROOT, ['python', 'expected'])

    def test_owned_tree_identity_mismatch_prevents_any_signal(self):
        process = Mock()
        with patch.object(runtime, '_validate_owned_tree',
                          side_effect=RuntimeError('PROCESS_TREE_IDENTITY_MISMATCH')):
            with self.assertRaisesRegex(RuntimeError, 'PROCESS_TREE_IDENTITY_MISMATCH'):
                runtime._terminate_owned_tree(process, {}, {'processes': []})
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        process.wait.assert_not_called()

    def test_pin_digest_is_sha256_of_exact_bytes(self):
        path = Path(__file__)
        self.assertEqual(runtime._sha(path), hashlib.sha256(path.read_bytes()).hexdigest())

    def test_stop_marker_prevents_start_before_any_host_or_schema_probe(self):
        with patch.object(runtime, '_confirm_pins', return_value={'pins': {}, 'task_xml_enabled_sha256': 'a' * 64}), \
             patch.object(runtime, '_owned_task_state', return_value={'state': 'Running'}), \
             patch.object(runtime, '_runtime_dir', return_value=Path('C:/private-runtime')), \
             patch.object(Path, 'exists', return_value=True), \
             patch.object(runtime, '_host_gate', side_effect=AssertionError('host gate called')):
            self.assertEqual(runtime.run(), 0)


if __name__ == '__main__':
    unittest.main()
