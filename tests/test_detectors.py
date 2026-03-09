"""Tests for detection engines."""

from datetime import datetime, timedelta

import pytest

from sentinel_mcp.detectors.anomaly import AnomalyDetector
from sentinel_mcp.detectors.rules import RuleEngine


class TestRuleEngine:
    def setup_method(self):
        self.engine = RuleEngine()

    def test_list_rules(self):
        rules = self.engine.list_rules()
        assert len(rules) == 20
        assert all("rule_id" in r for r in rules)

    def test_ssh_brute_force(self):
        """5+ failed logins from same IP in 5 minutes should trigger."""
        base_time = datetime(2026, 3, 8, 2, 14, 0)
        events = [
            {
                "event_type": "failed_login",
                "source_ip": "198.51.100.23",
                "username": f"user{i}",
                "timestamp": base_time + timedelta(seconds=i * 10),
            }
            for i in range(8)
        ]
        detections = self.engine.evaluate_rule("RULE-001", events)
        assert len(detections) >= 1
        assert detections[0].rule_name == "SSH Brute Force"
        assert detections[0].severity == "high"
        assert detections[0].mitre_technique == "T1110.001"

    def test_successful_login_after_brute_force(self):
        """Login from IP with prior failures should trigger."""
        base_time = datetime(2026, 3, 8, 2, 14, 0)
        events = [
            {"event_type": "failed_login", "source_ip": "1.2.3.4",
             "username": "admin", "timestamp": base_time + timedelta(seconds=i)}
            for i in range(5)
        ] + [
            {"event_type": "successful_login", "source_ip": "1.2.3.4",
             "username": "admin", "timestamp": base_time + timedelta(minutes=3)},
        ]
        detections = self.engine.evaluate_rule("RULE-002", events)
        assert len(detections) == 1
        assert detections[0].severity == "critical"

    def test_privilege_escalation(self):
        events = [
            {
                "event_type": "sudo",
                "username": "deploy",
                "target_user": "root",
                "command": "/bin/bash",
                "timestamp": datetime(2026, 3, 8, 2, 18, 0),
                "hostname": "webserver01",
            }
        ]
        detections = self.engine.evaluate_rule("RULE-003", events)
        assert len(detections) == 1
        assert "deploy" in detections[0].description

    def test_new_user_creation(self):
        events = [
            {
                "event_type": "user_add",
                "username": "backdoor_user",
                "timestamp": datetime(2026, 3, 8, 2, 19, 0),
                "hostname": "webserver01",
            }
        ]
        detections = self.engine.evaluate_rule("RULE-005", events)
        assert len(detections) == 1
        assert detections[0].mitre_technique == "T1136"

    def test_port_scan(self):
        """20+ unique ports from same IP should trigger."""
        events = [
            {
                "source_ip": "198.51.100.23",
                "dest_port": port,
                "action": "blocked",
                "timestamp": datetime(2026, 3, 8, 1, 45, 0),
            }
            for port in range(1, 30)
        ]
        detections = self.engine.evaluate_rule("RULE-007", events)
        assert len(detections) == 1
        assert "198.51.100.23" in detections[0].description

    def test_credential_stuffing(self):
        """5+ unique usernames from same IP should trigger."""
        events = [
            {
                "event_type": "failed_login",
                "source_ip": "1.2.3.4",
                "username": f"user_{i}",
                "timestamp": datetime(2026, 3, 8, 2, 14, i),
            }
            for i in range(6)
        ]
        detections = self.engine.evaluate_rule("RULE-017", events)
        assert len(detections) == 1

    def test_impossible_travel(self):
        events = [
            {
                "event_type": "successful_login",
                "source_ip": "10.0.1.50",
                "username": "admin",
                "timestamp": datetime(2026, 3, 8, 10, 0, 0),
            },
            {
                "event_type": "successful_login",
                "source_ip": "198.51.100.23",
                "username": "admin",
                "timestamp": datetime(2026, 3, 8, 10, 2, 0),
            },
        ]
        detections = self.engine.evaluate_rule("RULE-018", events)
        assert len(detections) == 1
        assert detections[0].rule_name == "Impossible Travel"

    def test_cloudtrail_logging_disabled(self):
        events = [
            {
                "event_name": "StopLogging",
                "user_identity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/attacker"},
                "source_ip": "198.51.100.23",
                "timestamp": datetime(2026, 3, 8, 2, 33, 0),
            }
        ]
        detections = self.engine.evaluate_rule("RULE-013", events)
        assert len(detections) == 1
        assert detections[0].severity == "critical"

    def test_user_added_to_admin_group(self):
        events = [
            {
                "event_type": "user_modify",
                "username": "svc_backup",
                "extra": {"group": "sudo"},
                "timestamp": datetime(2026, 3, 8, 2, 19, 45),
            }
        ]
        detections = self.engine.evaluate_rule("RULE-006", events)
        assert len(detections) == 1
        assert detections[0].severity == "critical"

    def test_service_stopped(self):
        events = [
            {
                "event_type": "service_stop",
                "extra": {"unit": "Fail2Ban Service"},
                "hostname": "webserver01",
                "timestamp": datetime(2026, 3, 8, 2, 17, 30),
            }
        ]
        detections = self.engine.evaluate_rule("RULE-009", events)
        assert len(detections) == 1

    def test_evaluate_all(self):
        """Run all rules on a realistic event set."""
        base_time = datetime(2026, 3, 8, 2, 14, 0)
        events = [
            {"event_type": "failed_login", "source_ip": "1.2.3.4",
             "username": f"user{i}", "timestamp": base_time + timedelta(seconds=i * 5)}
            for i in range(10)
        ] + [
            {"event_type": "successful_login", "source_ip": "1.2.3.4",
             "username": "admin", "timestamp": base_time + timedelta(minutes=5)},
            {"event_type": "sudo", "username": "admin", "target_user": "root",
             "command": "/bin/bash", "timestamp": base_time + timedelta(minutes=6),
             "hostname": "srv1"},
        ]
        detections = self.engine.evaluate_all(events)
        assert len(detections) >= 3  # brute force + login after BF + sudo
        # Should be sorted by severity (critical first)
        if len(detections) >= 2:
            sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            assert sev_order[detections[0].severity] >= sev_order[detections[1].severity]

    def test_no_false_positives_on_clean_events(self):
        """Normal activity should not trigger high/critical rules."""
        events = [
            {"event_type": "session_open", "username": "admin",
             "timestamp": datetime(2026, 3, 7, 9, 0, 0)},
            {"event_type": "successful_login", "source_ip": "10.0.1.50",
             "username": "admin", "timestamp": datetime(2026, 3, 7, 9, 0, 0)},
            {"event_type": "session_close", "username": "admin",
             "timestamp": datetime(2026, 3, 7, 17, 0, 0)},
        ]
        detections = self.engine.evaluate_all(events)
        critical = [d for d in detections if d.severity == "critical"]
        assert len(critical) == 0


class TestAnomalyDetector:
    def test_detect_brute_force(self):
        detector = AnomalyDetector(sensitivity=0.5)
        base_time = datetime(2026, 3, 8, 2, 14, 0)
        events = [
            {
                "event_type": "failed_login",
                "source_ip": "198.51.100.23",
                "username": "root",
                "timestamp": base_time + timedelta(seconds=i * 2),
            }
            for i in range(20)
        ]
        anomalies = detector.detect(events)
        brute = [a for a in anomalies if a.anomaly_type == "brute_force"]
        assert len(brute) >= 1

    def test_detect_unusual_hours(self):
        detector = AnomalyDetector(sensitivity=0.7)
        events = [
            {
                "event_type": "successful_login",
                "source_ip": "10.0.1.50",
                "username": "admin",
                "timestamp": datetime(2026, 3, 8, 3, 0, 0),  # 3 AM
            }
        ]
        anomalies = detector.detect(events)
        unusual = [a for a in anomalies if a.anomaly_type == "unusual_hour"]
        assert len(unusual) == 1

    def test_no_anomalies_normal_traffic(self):
        """Normal business hours login should not flag unusual hours."""
        detector = AnomalyDetector(sensitivity=0.3)
        events = [
            {
                "event_type": "successful_login",
                "source_ip": "10.0.1.50",
                "username": "admin",
                "timestamp": datetime(2026, 3, 7, 10, 0, 0),  # 10 AM
            }
        ]
        anomalies = detector.detect(events)
        unusual = [a for a in anomalies if a.anomaly_type == "unusual_hour"]
        assert len(unusual) == 0

    def test_detect_volume_spike(self):
        detector = AnomalyDetector(sensitivity=0.5)
        base_time = datetime(2026, 3, 7, 8, 0, 0)
        # Normal: ~5 events per hour
        events = []
        for hour in range(12):
            for i in range(5):
                events.append({
                    "event_type": "session_open",
                    "timestamp": base_time + timedelta(hours=hour, minutes=i * 10),
                })
        # Spike: 50 events in one hour
        spike_time = base_time + timedelta(hours=13)
        for i in range(50):
            events.append({
                "event_type": "failed_login",
                "source_ip": f"10.0.{i}.1",
                "timestamp": spike_time + timedelta(seconds=i * 60),
            })

        anomalies = detector.detect(events)
        spikes = [a for a in anomalies if a.anomaly_type == "volume_spike"]
        assert len(spikes) >= 1

    def test_empty_events(self):
        detector = AnomalyDetector()
        assert detector.detect([]) == []

    def test_sensitivity_range(self):
        """Ensure sensitivity is clamped."""
        d1 = AnomalyDetector(sensitivity=-1.0)
        assert d1.sensitivity == 0.0
        d2 = AnomalyDetector(sensitivity=5.0)
        assert d2.sensitivity == 1.0

    def test_isolation_forest_runs(self):
        """Isolation Forest needs 20+ events to run."""
        detector = AnomalyDetector(sensitivity=0.8)
        base_time = datetime(2026, 3, 7, 10, 0, 0)
        events = [
            {
                "event_type": "session_open",
                "source_ip": "10.0.1.50",
                "timestamp": base_time + timedelta(minutes=i),
            }
            for i in range(25)
        ]
        # Add one outlier
        events.append({
            "event_type": "failed_login",
            "source_ip": "198.51.100.23",
            "timestamp": datetime(2026, 3, 8, 3, 0, 0),
        })
        anomalies = detector.detect(events)
        # Should have at least the behavioral anomalies from IF
        assert len(anomalies) >= 1
