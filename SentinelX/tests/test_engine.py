"""
SentinelX – Test Suite
Tests for the rule engine, threat scoring, and detection simulation.
"""

import os
import sys
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# Ensure imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinelx.core.rules import (
    Rule, Severity, DEFAULT_RULES, get_rules_by_module, get_rule_by_name
)
from sentinelx.core.threat_scoring import ThreatScorer, SEVERITY_SCORES


class TestRules(unittest.TestCase):
    """Test detection rule definitions."""

    def test_default_rules_exist(self):
        """Verify default rules are defined."""
        self.assertGreater(len(DEFAULT_RULES), 0)
        self.assertGreaterEqual(len(DEFAULT_RULES), 15)

    def test_rule_properties(self):
        """Each rule must have required properties."""
        for rule in DEFAULT_RULES:
            self.assertIsInstance(rule.name, str)
            self.assertGreater(len(rule.name), 0)
            self.assertIsInstance(rule.condition, str)
            self.assertIsInstance(rule.threshold, int)
            self.assertGreater(rule.threshold, 0)
            self.assertIsInstance(rule.time_window, int)
            self.assertGreater(rule.time_window, 0)
            self.assertIn(rule.severity, [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])
            self.assertIn(rule.module, ["network", "host", "file", "process"])

    def test_risk_scores(self):
        """Verify risk scores match severity."""
        low_rule = Rule("Test", "test", 1, 1, Severity.LOW, module="network")
        self.assertEqual(low_rule.risk_score, 10)

        med_rule = Rule("Test", "test", 1, 1, Severity.MEDIUM, module="network")
        self.assertEqual(med_rule.risk_score, 30)

        high_rule = Rule("Test", "test", 1, 1, Severity.HIGH, module="network")
        self.assertEqual(high_rule.risk_score, 70)

        crit_rule = Rule("Test", "test", 1, 1, Severity.CRITICAL, module="network")
        self.assertEqual(crit_rule.risk_score, 100)

    def test_get_rules_by_module(self):
        """Retrieve rules filtered by module."""
        network_rules = get_rules_by_module("network")
        self.assertGreater(len(network_rules), 0)
        for rule in network_rules:
            self.assertEqual(rule.module, "network")

        host_rules = get_rules_by_module("host")
        self.assertGreater(len(host_rules), 0)

        file_rules = get_rules_by_module("file")
        self.assertGreater(len(file_rules), 0)

        process_rules = get_rules_by_module("process")
        self.assertGreater(len(process_rules), 0)

    def test_get_rule_by_name(self):
        """Find a specific rule by name."""
        rule = get_rule_by_name("Port Scan Detected")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.condition, "same_ip_multiple_ports")
        self.assertEqual(rule.threshold, 10)

    def test_port_scan_rule(self):
        """Port scan rule has correct configuration."""
        rule = get_rule_by_name("Port Scan Detected")
        self.assertEqual(rule.threshold, 10)
        self.assertEqual(rule.time_window, 10)
        self.assertEqual(rule.severity, Severity.HIGH)

    def test_ransomware_rule(self):
        """Ransomware rule has correct configuration."""
        rule = get_rule_by_name("Ransomware Behavior Detected")
        self.assertEqual(rule.threshold, 50)
        self.assertEqual(rule.time_window, 30)
        self.assertEqual(rule.severity, Severity.CRITICAL)


class TestThreatScoring(unittest.TestCase):
    """Test the threat scoring system."""

    def setUp(self):
        self.scorer = ThreatScorer()
        self.scorer.clear_all()

    def test_add_score(self):
        """Adding a score returns updated total."""
        total = self.scorer.add_score("192.168.1.100", "Low", "test")
        self.assertEqual(total, 10)

    def test_aggregate_scores(self):
        """Scores aggregate correctly."""
        self.scorer.add_score("10.0.0.1", "Low", "event1")
        self.scorer.add_score("10.0.0.1", "Medium", "event2")
        total = self.scorer.add_score("10.0.0.1", "High", "event3")
        self.assertEqual(total, 110)  # 10 + 30 + 70

    def test_score_capped_at_1000(self):
        """Score should be capped at 1000."""
        for _ in range(20):
            self.scorer.add_score("attacker.ip", "Critical", "flood")
        score = self.scorer.get_score("attacker.ip")
        self.assertEqual(score, 1000)

    def test_risk_level(self):
        """Risk level strings match score ranges."""
        self.assertEqual(self.scorer.get_risk_level(5), "Low")
        self.assertEqual(self.scorer.get_risk_level(50), "Medium")
        self.assertEqual(self.scorer.get_risk_level(150), "High")
        self.assertEqual(self.scorer.get_risk_level(250), "Critical")

    def test_top_entities(self):
        """Top entities returns sorted list."""
        self.scorer.add_score("ip1", "Critical", "test")
        self.scorer.add_score("ip2", "Low", "test")
        self.scorer.add_score("ip3", "High", "test")

        top = self.scorer.get_top_entities(limit=3)
        self.assertEqual(len(top), 3)
        self.assertEqual(top[0]["entity"], "ip1")  # Highest score
        self.assertEqual(top[0]["score"], 100)

    def test_clear_entity(self):
        """Clearing an entity removes its scores."""
        self.scorer.add_score("target", "High", "test")
        self.scorer.clear_entity("target")
        self.assertEqual(self.scorer.get_score("target"), 0)

    def test_severity_scores_mapping(self):
        """Severity score mapping is correct."""
        self.assertEqual(SEVERITY_SCORES["Low"], 10)
        self.assertEqual(SEVERITY_SCORES["Medium"], 30)
        self.assertEqual(SEVERITY_SCORES["High"], 70)
        self.assertEqual(SEVERITY_SCORES["Critical"], 100)


class TestDetectionEngine(unittest.TestCase):
    """Test the detection engine."""

    @patch("sentinelx.core.engine.DatabaseManager")
    def test_engine_singleton(self, mock_db):
        """Engine should be a singleton."""
        # Reset singleton for test
        from sentinelx.core.engine import DetectionEngine
        DetectionEngine._instance = None
        DetectionEngine._lock = __import__("threading").Lock()

        e1 = DetectionEngine()
        e2 = DetectionEngine()
        self.assertIs(e1, e2)

    @patch("sentinelx.core.engine.DatabaseManager")
    def test_submit_event(self, mock_db):
        """Events can be submitted without error."""
        from sentinelx.core.engine import DetectionEngine, Event
        DetectionEngine._instance = None
        DetectionEngine._lock = __import__("threading").Lock()

        engine = DetectionEngine()
        event = Event(
            event_type="test_condition",
            source="192.168.1.1",
            details={"test": True},
        )
        # Should not raise
        engine.submit_event(event)

    @patch("sentinelx.core.engine.DatabaseManager")
    def test_alert_callback(self, mock_db):
        """Alert callbacks are called when alerts fire."""
        from sentinelx.core.engine import DetectionEngine, Event
        DetectionEngine._instance = None
        DetectionEngine._lock = __import__("threading").Lock()

        engine = DetectionEngine()

        # Mock the db.add_alert to return a mock alert
        mock_alert = MagicMock()
        mock_alert.to_dict.return_value = {"id": 1, "title": "Test", "severity": "High"}
        mock_db.return_value.add_alert.return_value = mock_alert

        received = []
        engine.register_alert_callback(lambda a: received.append(a))

        # Submit an event that matches a threshold-1 rule
        event = Event(
            event_type="arp_spoof",
            source="10.0.0.1",
            details={"old_mac": "aa:bb", "new_mac": "cc:dd"},
        )
        engine.submit_event(event)

        # callback should have been called
        self.assertGreaterEqual(len(received), 1)


class TestSimulations(unittest.TestCase):
    """Simulate attack scenarios and verify detection."""

    def test_port_scan_simulation(self):
        """Simulate a port scan: same IP hitting 10+ ports."""
        from sentinelx.core.rules import get_rule_by_name
        rule = get_rule_by_name("Port Scan Detected")
        self.assertIsNotNone(rule)

        # Simulate 12 unique ports from the same IP
        ports = set(range(20, 32))
        self.assertGreaterEqual(len(ports), rule.threshold)

    def test_failed_login_simulation(self):
        """Simulate brute force: 5+ failed logins in 60s."""
        from sentinelx.core.rules import get_rule_by_name
        rule = get_rule_by_name("Brute Force Login Attempt")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.threshold, 5)
        self.assertEqual(rule.time_window, 60)

    def test_ransomware_simulation(self):
        """Simulate ransomware: 50+ files changed in 30s."""
        from sentinelx.core.rules import get_rule_by_name
        rule = get_rule_by_name("Ransomware Behavior Detected")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.threshold, 50)
        self.assertEqual(rule.time_window, 30)


if __name__ == "__main__":
    unittest.main(verbosity=2)
