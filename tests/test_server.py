"""Tests for the MCP server tools."""

import pytest

from sentinel_mcp.server import (
    analyze_logs,
    check_iocs,
    correlate_events,
    detect_anomalies,
    generate_report,
    hunt_threat,
    map_to_mitre,
)


class TestAnalyzeLogs:
    def test_analyze_auth_sample(self):
        result = analyze_logs("auth")
        assert "auth.log" in result
        assert "failed_login" in result
        assert "Total events:" in result

    def test_analyze_firewall_sample(self):
        result = analyze_logs("firewall")
        assert "firewall.log" in result
        assert "Total events:" in result

    def test_analyze_syslog_sample(self):
        result = analyze_logs("syslog")
        assert "syslog.log" in result

    def test_analyze_cloudtrail_sample(self):
        result = analyze_logs("cloudtrail")
        assert "cloudtrail.json" in result

    def test_analyze_nonexistent_file(self):
        result = analyze_logs("/nonexistent/file.log")
        assert "Error" in result

    def test_analyze_detects_rules(self):
        result = analyze_logs("auth")
        assert "Rule-Based Detections" in result
        # Should detect brute force in sample auth.log
        assert "Brute Force" in result or "brute" in result.lower()


class TestHuntThreat:
    def test_hunt_known_attacker_ip(self):
        result = hunt_threat("198.51.100.23", "ip")
        assert "198.51.100.23" in result
        assert int(result.split("Total matches:")[1].split("\n")[0].strip()) > 0

    def test_hunt_internal_ip(self):
        result = hunt_threat("10.0.1.50", "ip")
        assert "10.0.1.50" in result

    def test_hunt_username(self):
        result = hunt_threat("deploy", "username")
        assert "deploy" in result

    def test_hunt_nonexistent_indicator(self):
        result = hunt_threat("1.1.1.1", "ip")
        assert "Total matches: 0" in result or "No matches found" in result


class TestDetectAnomalies:
    def test_detect_auth_anomalies(self):
        result = detect_anomalies("auth", 0.5)
        assert "Anomaly Detection Results" in result
        assert "Events analyzed:" in result
        # Should find something in the attack-heavy auth.log
        assert "Anomalies found:" in result

    def test_detect_firewall_anomalies(self):
        result = detect_anomalies("firewall", 0.5)
        assert "Anomaly Detection Results" in result

    def test_detect_nonexistent(self):
        result = detect_anomalies("/nonexistent/file.log")
        assert "Error" in result

    def test_sensitivity_affects_results(self):
        result_low = detect_anomalies("auth", 0.1)
        result_high = detect_anomalies("auth", 0.9)
        # Higher sensitivity should generally find more anomalies
        low_count = int(result_low.split("Anomalies found:")[1].split("\n")[0].strip())
        high_count = int(result_high.split("Anomalies found:")[1].split("\n")[0].strip())
        assert high_count >= low_count


class TestCorrelateEvents:
    def test_correlate_default(self):
        result = correlate_events()
        assert "Event Correlation Report" in result
        assert "Sources parsed:" in result
        # Should find the attacker IP chain
        assert "198.51.100.23" in result

    def test_correlate_identifies_attack_chain(self):
        result = correlate_events(timeframe_hours=48, min_severity="medium")
        assert "ATTACK CHAIN" in result


class TestMapToMitre:
    def test_map_brute_force(self):
        result = map_to_mitre("Brute force attack with multiple failed login attempts and authentication failures")
        assert "T1110" in result
        assert "Brute Force" in result
        assert "Credential Access" in result

    def test_map_privilege_escalation(self):
        result = map_to_mitre("User escalated privileges using sudo to root")
        assert "T1548" in result or "Privilege Escalation" in result

    def test_map_exfiltration(self):
        result = map_to_mitre("Large data transfer to external server, possible exfiltration")
        assert "T1048" in result or "Exfiltration" in result

    def test_map_no_match(self):
        result = map_to_mitre("normal user logged in and checked email")
        # Should gracefully handle no matches
        assert "No MITRE" in result or "Mapping" in result

    def test_map_port_scan(self):
        result = map_to_mitre("Port scan detected from external IP, nmap fingerprinting")
        assert "T1046" in result


class TestGenerateReport:
    def test_generate_report(self):
        result = generate_report(timeframe_hours=48)
        assert "# Security Incident Report" in result
        assert "Executive Summary" in result
        assert "Timeline" in result
        assert "MITRE ATT&CK Mapping" in result
        assert "Recommended Actions" in result
        assert "Indicators of Compromise" in result

    def test_report_has_severity(self):
        result = generate_report()
        assert "CRITICAL" in result or "HIGH" in result

    def test_report_has_findings(self):
        result = generate_report()
        assert "Detailed Findings" in result


class TestCheckIOCs:
    def test_check_known_bad_ip(self):
        result = check_iocs("198.51.100.23")
        assert "MALICIOUS" in result
        assert "brute-force" in result.lower() or "brute force" in result.lower()

    def test_check_unknown_ip(self):
        result = check_iocs("8.8.8.8")
        assert "NOT FOUND" in result

    def test_check_multiple_iocs(self):
        result = check_iocs("198.51.100.23, 203.0.113.50, 8.8.8.8")
        assert "MALICIOUS" in result
        assert "NOT FOUND" in result

    def test_check_empty_list(self):
        result = check_iocs("")
        assert "No IOCs provided" in result
