"""Tests for log parsers."""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from sentinel_mcp.parsers.auth import AuthLogParser
from sentinel_mcp.parsers.cloudtrail import CloudTrailParser
from sentinel_mcp.parsers.firewall import FirewallLogParser
from sentinel_mcp.parsers.generic import GenericLogParser
from sentinel_mcp.parsers.syslog import SyslogParser

SAMPLE_DIR = Path(__file__).parent.parent / "data" / "sample_logs"


class TestAuthLogParser:
    def setup_method(self):
        self.parser = AuthLogParser(year=2026)

    def test_parse_failed_login(self):
        line = "Mar  8 02:14:34 webserver01 sshd[20100]: Failed password for invalid user test from 198.51.100.23 port 44120 ssh2"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "failed_login"
        assert event.username == "test"
        assert event.source_ip == "198.51.100.23"
        assert event.source_port == 44120
        assert event.severity == "medium"
        assert event.hostname == "webserver01"

    def test_parse_accepted_login(self):
        line = "Mar  7 08:30:22 webserver01 sshd[14201]: Accepted publickey for admin from 10.0.1.50 port 52341 ssh2"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "successful_login"
        assert event.username == "admin"
        assert event.source_ip == "10.0.1.50"

    def test_parse_sudo(self):
        line = "Mar  8 02:18:05 webserver01 sudo: deploy : TTY=pts/2 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "sudo"
        assert event.username == "deploy"
        assert event.target_user == "root"
        assert event.command == "/bin/bash"
        assert event.severity == "high"

    def test_parse_useradd(self):
        line = "Mar  8 02:19:30 webserver01 useradd[20300]: new user: name=svc_backup"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "user_add"
        assert event.username == "svc_backup"
        assert event.severity == "high"

    def test_parse_usermod(self):
        line = "Mar  8 02:19:45 webserver01 usermod[20301]: add 'svc_backup' to group 'sudo'"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "user_modify"
        assert event.username == "svc_backup"
        assert event.extra["group"] == "sudo"

    def test_parse_invalid_user(self):
        line = "Mar  8 02:14:33 webserver01 sshd[20100]: Invalid user test from 198.51.100.23 port 44120"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "invalid_user"
        assert event.username == "test"
        assert event.source_ip == "198.51.100.23"

    def test_parse_session(self):
        line = "Mar  7 08:30:22 webserver01 sshd[14201]: pam_unix(sshd:session): session opened for user admin"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "session_open"
        assert event.username == "admin"

    def test_parse_empty_line(self):
        assert self.parser.parse_line("") is None
        assert self.parser.parse_line("   ") is None

    def test_parse_malformed_line(self):
        assert self.parser.parse_line("this is not a valid log line") is None

    def test_parse_sample_file(self):
        if not SAMPLE_DIR.exists():
            pytest.skip("Sample data not found")
        events = self.parser.parse_file(str(SAMPLE_DIR / "auth.log"))
        assert len(events) > 20
        # Should find brute force attempts
        failed = [e for e in events if e.event_type == "failed_login"]
        assert len(failed) >= 5
        # Should find successful logins
        success = [e for e in events if e.event_type == "successful_login"]
        assert len(success) >= 1

    def test_parse_nonexistent_file(self):
        events = self.parser.parse_file("/nonexistent/path/auth.log")
        assert events == []


class TestFirewallLogParser:
    def setup_method(self):
        self.parser = FirewallLogParser(year=2026)

    def test_parse_ufw_block(self):
        line = "Mar  8 01:45:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=10.0.1.10 PROTO=TCP SPT=40001 DPT=21"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.action == "blocked"
        assert event.source_ip == "198.51.100.23"
        assert event.dest_ip == "10.0.1.10"
        assert event.dest_port == 21
        assert event.protocol == "TCP"

    def test_parse_ufw_allow(self):
        line = "Mar  7 08:00:01 fw01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.1.50 DST=10.0.1.10 PROTO=TCP SPT=52341 DPT=22"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.action == "allowed"
        assert event.source_ip == "10.0.1.50"

    def test_parse_sample_file(self):
        if not SAMPLE_DIR.exists():
            pytest.skip("Sample data not found")
        events = self.parser.parse_file(str(SAMPLE_DIR / "firewall.log"))
        assert len(events) > 10
        blocked = [e for e in events if e.action == "blocked"]
        assert len(blocked) >= 20  # Port scan events
        allowed = [e for e in events if e.action == "allowed"]
        assert len(allowed) >= 1


class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser(year=2026)

    def test_parse_service_start(self):
        line = "Mar  7 09:00:00 webserver01 systemd[1]: Started Nginx HTTP Server."
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "service_start"

    def test_parse_service_stop(self):
        line = "Mar  8 02:17:30 webserver01 systemd[1]: Stopped Fail2Ban Service."
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "service_stop"
        assert event.severity == "medium"

    def test_parse_cron_modification(self):
        line = "Mar  8 02:19:01 webserver01 crontab[20251]: (svc_backup) REPLACE (svc_backup)"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "cron_modified"

    def test_parse_suspicious_process(self):
        line = "Mar  8 02:24:06 webserver01 ncat[20600]: Connection from 198.51.100.23:4444"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "suspicious_process"
        assert event.severity == "high"

    def test_parse_sample_file(self):
        if not SAMPLE_DIR.exists():
            pytest.skip("Sample data not found")
        events = self.parser.parse_file(str(SAMPLE_DIR / "syslog.log"))
        assert len(events) > 5


class TestCloudTrailParser:
    def setup_method(self):
        self.parser = CloudTrailParser()

    def test_parse_console_login(self):
        record = {
            "eventTime": "2026-03-07T10:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "10.0.1.50",
            "userAgent": "Mozilla/5.0",
            "userIdentity": {"type": "IAMUser", "userName": "admin-jsmith"},
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success"},
        }
        event = self.parser.parse_event(record)
        assert event is not None
        assert event.event_name == "ConsoleLogin"
        assert event.source_ip == "10.0.1.50"
        assert event.severity == "medium"

    def test_parse_create_user(self):
        record = {
            "eventTime": "2026-03-08T02:30:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.23",
            "userAgent": "aws-cli/2.0",
            "userIdentity": {"type": "IAMUser", "userName": "deploy"},
            "requestParameters": {"userName": "svc-automation"},
            "responseElements": None,
        }
        event = self.parser.parse_event(record)
        assert event is not None
        assert event.event_name == "CreateUser"
        assert event.severity == "high"
        assert event.event_type == "iam_modification"

    def test_parse_stop_logging(self):
        record = {
            "eventTime": "2026-03-08T02:33:00Z",
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "StopLogging",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.23",
            "userAgent": "aws-cli/2.0",
            "userIdentity": {"type": "IAMUser", "userName": "svc-automation"},
            "requestParameters": {"name": "management-trail"},
            "responseElements": None,
        }
        event = self.parser.parse_event(record)
        assert event is not None
        assert event.severity == "high"
        assert event.event_type == "defense_evasion"

    def test_parse_sample_file(self):
        if not SAMPLE_DIR.exists():
            pytest.skip("Sample data not found")
        events = self.parser.parse_file(str(SAMPLE_DIR / "cloudtrail.json"))
        assert len(events) >= 10
        # Should have IAM changes
        iam_events = [e for e in events if "iam" in e.event_source.lower()]
        assert len(iam_events) >= 3

    def test_parse_malformed_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            f.flush()
            events = self.parser.parse_file(f.name)
            assert events == []
        os.unlink(f.name)


class TestGenericLogParser:
    def setup_method(self):
        self.parser = GenericLogParser(source_name="test")

    def test_detect_sql_injection(self):
        line = '2026-03-08 10:00:00 GET /search?q=1 UNION SELECT * FROM users'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "sql_injection"
        assert event.severity == "critical"

    def test_detect_xss(self):
        line = '2026-03-08 10:00:00 POST /comment body=<script>alert(1)</script>'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "xss_attempt"
        assert event.severity == "high"

    def test_detect_path_traversal(self):
        line = '2026-03-08 10:00:00 GET /files/../../etc/passwd'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "path_traversal"

    def test_timestamp_extraction_iso(self):
        line = "2026-03-08T14:23:01 some event"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.timestamp is not None
        assert event.timestamp.hour == 14

    def test_normal_line(self):
        line = "2026-03-08 10:00:00 INFO Application started successfully"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "info"
        assert event.severity == "info"
