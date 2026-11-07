"""Stdlib orchestration checks ONLY: not PostgreSQL, process or timing proof."""
import importlib.util
import unittest


class LeaseRecoveryPure(unittest.TestCase):
    def test_independent_controller_scans_without_worker_or_manual_expire(self):
        spec = importlib.util.find_spec('fieldwork.lease_recovery')
        self.assertIsNotNone(spec, 'No independent automatic training lease scanner exists')
        from fieldwork.lease_recovery import scan_once
        class Backend:
            def candidates(self, cursor, batch_size):
                return [{'id': 'a', 'fence': 2, 'revision': 4, 'state': 'running'}]
            def expire(self, candidate):
                return {'run': candidate['id'], 'state': 'interrupted'}
        receipt = scan_once(Backend())
        self.assertEqual(receipt['transitions'], [{'run': 'a', 'state': 'interrupted'}])
        self.assertEqual(receipt['cursor'], 'a')

    def test_poison_candidate_does_not_starve_next_and_empty_wraps(self):
        from fieldwork.lease_recovery import scan_once
        class Backend:
            def candidates(self, cursor, batch_size):
                return [] if cursor else [{'id': 'a'}, {'id': 'b'}]
            def expire(self, candidate):
                if candidate['id'] == 'a':
                    raise ValueError('secret must not enter diagnostics')
                return {'run': 'b'}
        receipt = scan_once(Backend())
        self.assertEqual(receipt['transitions'], [{'run': 'b'}])
        self.assertEqual(receipt['errors'], [{'run': 'a', 'code': 'ValueError'}])
        self.assertEqual(scan_once(Backend(), cursor='b')['cursor'], '')

    def test_sql_protocol_is_exact_scoped_atomic_and_never_touches_slot(self):
        from fieldwork import lease_recovery as recovery
        self.assertTrue(hasattr(recovery, 'PostgresBackend'), 'Missing DB-time transactional expiry backend')
        from unittest.mock import MagicMock
        candidate = {'id': 'a', 'fence': 3, 'revision': 5, 'state': 'cancel_requested'}
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.return_value.fetchone.return_value = {
            'id': 'a', 'workspace': 'tenant', 'state': 'cancelled', 'fence': 4, 'revision': 6}
        backend = recovery.PostgresBackend(lambda: connection, ['tenant'])
        result = backend.expire(candidate)
        self.assertEqual(result['state'], 'cancelled')
        calls = connection.execute.call_args_list
        sql = '\n'.join(call.args[0] for call in calls)
        for fragment in ['SKIP LOCKED', 'clock_timestamp()', 'revision=%s', 'fence=%s',
                         'workspace=ANY(%s)', 'INSERT INTO fw_events', 'object_revision']:
            self.assertIn(fragment, sql)
        self.assertNotIn('fw_slot', sql)
        self.assertNotIn('fw_attempts', sql)
        update = next(call for call in calls if 'UPDATE fw_runs' in call.args[0])
        self.assertEqual(update.args[1], ('a', ['tenant'], 3, 5, 'cancel_requested'))
        # No mutation -> no event; two contenders cannot both publish from this protocol.
        connection.reset_mock()
        connection.execute.return_value.fetchone.return_value = None
        self.assertIsNone(backend.expire(candidate))
        self.assertFalse(any('INSERT INTO fw_events' in call.args[0]
                             for call in connection.execute.call_args_list))

    def test_cli_requires_explicit_operator_authority_and_bounded_loop(self):
        from fieldwork import lease_recovery as recovery
        self.assertTrue(hasattr(recovery, 'parse_options'), 'Missing independent scanner CLI')
        options = recovery.parse_options(['--authority-file', 'isolated-only.json', '--once'])
        self.assertTrue(options.once)
        self.assertLessEqual(options.interval, 5)
        for args in [[], ['--authority-file', 'x', '--interval', '6'],
                     ['--authority-file', 'x', '--interval', 'nan'],
                     ['--authority-file', 'x', '--batch-size', '33']]:
            with self.assertRaises(ValueError):
                recovery.parse_options(args)
        authority = {'dsn': 'not printed', 'workspaces': ['fixture'],
                     'purpose': 'fieldwork-training-lease-controller',
                     'authority_mode': 'trusted-operator-not-least-privilege'}
        self.assertEqual(recovery.validate_authority(authority), authority)
        for patch in [{'workspaces': []}, {'purpose': 'browser'},
                      {'authority_mode': 'request'}, {'workspaces': ['*']}]:
            with self.assertRaises(ValueError):
                recovery.validate_authority({**authority, **patch})
        class Backend:
            def candidates(self, cursor, batch_size): return []
        import io
        from unittest.mock import patch
        output = io.StringIO()
        with patch('sys.stdout', output):
            self.assertEqual(recovery.run_controller(Backend(), options), 0)
        self.assertIn('RETAINED', output.getvalue())


if __name__ == '__main__':
    unittest.main()
