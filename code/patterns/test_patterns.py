"""Unit tests for Strategy and State. Run from code/patterns:  python -m unittest -v"""
import unittest

from command_state import Command, InvalidTransition
from detection_strategy import (CRIT, OK, WARN, ConsecutiveStrategy, DiagnosticService,
                                InMemoryRepository, SingleSampleStrategy, Threshold, ZScoreStrategy)

T = Threshold(warn=80, crit=95, consecutive=3)


class StrategyTests(unittest.TestCase):
    def test_single_spike_is_alert_for_old_strategy(self):
        self.assertEqual(SingleSampleStrategy().evaluate([99, 12, 18], T), CRIT)

    def test_single_spike_is_ignored_by_consecutive(self):
        self.assertEqual(ConsecutiveStrategy().evaluate([99, 12, 18], T), OK)

    def test_three_in_a_row_gives_lowest_level_in_window(self):
        self.assertEqual(ConsecutiveStrategy().evaluate([97, 96, 85], T), WARN)
        self.assertEqual(ConsecutiveStrategy().evaluate([97, 96, 95], T), CRIT)

    def test_not_enough_samples(self):
        self.assertEqual(ConsecutiveStrategy().evaluate([99, 99], T), OK)

    def test_zscore_detects_deviation_from_own_history(self):
        history = [70, 71, 69, 70, 72, 70, 71, 69, 70, 71]
        self.assertEqual(ZScoreStrategy(k=3).evaluate([71] + history, T), OK)
        self.assertNotEqual(ZScoreStrategy(k=3).evaluate([95] + history, T), OK)

    def test_service_switches_strategy_without_changes(self):
        repo = InMemoryRepository()
        repo.add("pc", "cpu", 10, 10, 99)
        service = DiagnosticService(repo, SingleSampleStrategy())
        self.assertIsNotNone(service.check("pc", "cpu", T))
        service.set_strategy(ConsecutiveStrategy())
        self.assertIsNone(service.check("pc", "cpu", T))

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            Threshold(warn=95, crit=80)


class StateTests(unittest.TestCase):
    def test_normal_flow(self):
        c = Command("uptime", created_at=0)
        c.deliver(1)
        c.complete("ok", 2)
        self.assertEqual(c.history, ["pending", "running", "done"])

    def test_expired_when_agent_offline(self):
        c = Command("uptime", created_at=0, ttl=300)
        c.tick(301)
        self.assertEqual(c.status, "expired")
        with self.assertRaises(InvalidTransition):
            c.deliver(302)

    def test_retry_then_failed(self):
        c = Command("disk_usage", created_at=0, timeout=60, max_attempts=2)
        c.deliver(1); c.tick(70)
        self.assertEqual(c.status, "pending")
        c.deliver(80); c.tick(150)
        self.assertEqual(c.status, "failed")
        self.assertEqual(c.attempts, 2)

    def test_late_result_rejected(self):
        c = Command("ping_test", created_at=0, max_attempts=1)
        c.deliver(1); c.tick(100)
        with self.assertRaises(InvalidTransition):
            c.complete("late", 101)

    def test_done_is_final(self):
        c = Command("uptime", created_at=0)
        c.deliver(1); c.complete("ok", 2); c.tick(10_000)
        self.assertEqual(c.status, "done")


if __name__ == "__main__":
    unittest.main()
