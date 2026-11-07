"""Deterministic orchestration only; no PostgreSQL/timing/process certification."""
import unittest
from unittest.mock import patch

from fieldwork.lease_recovery import scan_once


class DiscoveryBudgetProgress(unittest.TestCase):
    def test_successful_slow_discovery_attempts_first_only_and_resumes(self):
        for discovery_seconds in (1.0, 2.0):
            with self.subTest(discovery_seconds=discovery_seconds):
                clock = [0.0]
                attempted = []

                class Backend:
                    def candidates(self, cursor, batch_size):
                        clock[0] += discovery_seconds
                        return [row for row in [{'id': 'a'}, {'id': 'b'}]
                                if row['id'] > cursor][:batch_size]

                    def expire(self, candidate):
                        attempted.append(candidate['id'])
                        return {'run': candidate['id']}

                backend = Backend()
                with patch('fieldwork.lease_recovery.time.monotonic', side_effect=lambda: clock[0]):
                    first = scan_once(backend, budget_seconds=1.0)
                    self.assertEqual(attempted, ['a'])
                    self.assertEqual(first['cursor'], 'a')
                    self.assertEqual(first['transitions'], [{'run': 'a'}])
                    second = scan_once(backend, cursor=first['cursor'], budget_seconds=1.0)
                    self.assertEqual(attempted, ['a', 'b'])
                    self.assertEqual(second['cursor'], 'b')
                    self.assertEqual(scan_once(backend, cursor='b')['cursor'], '')

    def test_inflight_attempt_overrun_does_not_skip_unattempted_candidate(self):
        clock = [0.0]
        attempted = []

        class Backend:
            def candidates(self, cursor, batch_size):
                return [{'id': 'a'}, {'id': 'b'}]

            def expire(self, candidate):
                attempted.append(candidate['id'])
                clock[0] += 2.0
                raise ValueError('private driver detail')

        with patch('fieldwork.lease_recovery.time.monotonic', side_effect=lambda: clock[0]):
            receipt = scan_once(Backend(), budget_seconds=1.0)
        self.assertEqual(attempted, ['a'])
        self.assertEqual(receipt, {'cursor': 'a', 'transitions': [],
                                  'errors': [{'run': 'a', 'code': 'ValueError'}]})


if __name__ == '__main__':
    unittest.main()
