"""Sigma-like rule engine with built-in detection rules."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional


@dataclass
class Detection:
    """A rule-based detection finding."""

    rule_id: str
    rule_name: str
    description: str
    severity: str  # low, medium, high, critical
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    evidence: dict = field(default_factory=dict)
    affected_events: list[dict] = field(default_factory=list)


@dataclass
class Rule:
    """A detection rule definition."""

    rule_id: str
    name: str
    description: str
    severity: str
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    evaluate: Callable[[list[dict[str, Any]]], list[Detection]] = lambda _: []


class RuleEngine:
    """Sigma-inspired rule engine with built-in security detection rules.

    Each rule operates on a list of normalized event dicts and produces
    Detection objects when triggered.
    """

    def __init__(self) -> None:
        self.rules: list[Rule] = self._build_rules()

    def evaluate_all(self, events: list[dict[str, Any]]) -> list[Detection]:
        """Run all rules against the event set."""
        detections: list[Detection] = []
        for rule in self.rules:
            try:
                results = rule.evaluate(events)
                detections.extend(results)
            except Exception:
                continue
        detections.sort(
            key=lambda d: ["info", "low", "medium", "high", "critical"].index(d.severity),
            reverse=True,
        )
        return detections

    def evaluate_rule(self, rule_id: str, events: list[dict[str, Any]]) -> list[Detection]:
        """Run a specific rule by ID."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule.evaluate(events)
        return []

    def list_rules(self) -> list[dict[str, str]]:
        """Return metadata about all rules."""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "mitre_technique": r.mitre_technique or "N/A",
                "mitre_tactic": r.mitre_tactic or "N/A",
            }
            for r in self.rules
        ]

    def _build_rules(self) -> list[Rule]:
        """Construct all built-in detection rules."""
        return [
            self._rule_ssh_brute_force(),
            self._rule_successful_login_after_brute_force(),
            self._rule_privilege_escalation(),
            self._rule_unauthorized_sudo(),
            self._rule_new_user_creation(),
            self._rule_user_added_to_admin_group(),
            self._rule_port_scan(),
            self._rule_large_outbound_transfer(),
            self._rule_service_stopped(),
            self._rule_crontab_modification(),
            self._rule_suspicious_process(),
            self._rule_iam_policy_change(),
            self._rule_cloudtrail_logging_disabled(),
            self._rule_s3_bucket_public(),
            self._rule_root_account_usage(),
            self._rule_security_group_opened(),
            self._rule_credential_stuffing(),
            self._rule_impossible_travel(),
            self._rule_password_spray(),
            self._rule_reverse_shell_indicator(),
        ]

    # --- Rule Definitions ---

    def _rule_ssh_brute_force(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            failed_by_ip: defaultdict[str, list] = defaultdict(list)
            for e in events:
                if e.get("event_type") in ("failed_login", "invalid_user"):
                    ip = e.get("source_ip")
                    if ip:
                        failed_by_ip[ip].append(e)

            for ip, fails in failed_by_ip.items():
                if len(fails) < 5:
                    continue
                fails.sort(key=lambda x: x.get("timestamp", datetime.min))
                # Check 5-minute windows
                for i in range(len(fails) - 4):
                    t0 = fails[i].get("timestamp")
                    t4 = fails[i + 4].get("timestamp")
                    if t0 and t4 and (t4 - t0) <= timedelta(minutes=5):
                        detections.append(Detection(
                            rule_id="RULE-001",
                            rule_name="SSH Brute Force",
                            description=f"{len(fails)} failed login attempts from {ip}",
                            severity="high",
                            mitre_technique="T1110.001",
                            mitre_tactic="Credential Access",
                            timestamp=t0,
                            source_ip=ip,
                            evidence={"total_failures": len(fails), "window": "5 minutes"},
                            affected_events=fails[:10],
                        ))
                        break
            return detections

        return Rule(
            rule_id="RULE-001",
            name="SSH Brute Force",
            description="5+ failed SSH logins from same IP within 5 minutes",
            severity="high",
            mitre_technique="T1110.001",
            mitre_tactic="Credential Access",
            evaluate=evaluate,
        )

    def _rule_successful_login_after_brute_force(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            failed_by_ip: defaultdict[str, list] = defaultdict(list)
            success_by_ip: defaultdict[str, list] = defaultdict(list)

            for e in events:
                ip = e.get("source_ip")
                if not ip:
                    continue
                if e.get("event_type") in ("failed_login", "invalid_user"):
                    failed_by_ip[ip].append(e)
                elif e.get("event_type") == "successful_login":
                    success_by_ip[ip].append(e)

            for ip in failed_by_ip:
                if len(failed_by_ip[ip]) >= 3 and ip in success_by_ip:
                    detections.append(Detection(
                        rule_id="RULE-002",
                        rule_name="Successful Login After Brute Force",
                        description=f"Successful login from {ip} after {len(failed_by_ip[ip])} failed attempts",
                        severity="critical",
                        mitre_technique="T1110",
                        mitre_tactic="Credential Access",
                        timestamp=success_by_ip[ip][0].get("timestamp"),
                        source_ip=ip,
                        username=success_by_ip[ip][0].get("username"),
                        evidence={
                            "failed_attempts": len(failed_by_ip[ip]),
                            "successful_user": success_by_ip[ip][0].get("username"),
                        },
                    ))
            return detections

        return Rule(
            rule_id="RULE-002",
            name="Successful Login After Brute Force",
            description="Successful login from IP with prior failed attempts (compromised credential)",
            severity="critical",
            mitre_technique="T1110",
            mitre_tactic="Credential Access",
            evaluate=evaluate,
        )

    def _rule_privilege_escalation(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                if e.get("event_type") == "sudo" and e.get("target_user") == "root":
                    detections.append(Detection(
                        rule_id="RULE-003",
                        rule_name="Privilege Escalation to Root",
                        description=f"User '{e.get('username')}' escalated to root via sudo",
                        severity="high",
                        mitre_technique="T1548.003",
                        mitre_tactic="Privilege Escalation",
                        timestamp=e.get("timestamp"),
                        username=e.get("username"),
                        hostname=e.get("hostname"),
                        evidence={"command": e.get("command", "unknown")},
                    ))
            return detections

        return Rule(
            rule_id="RULE-003",
            name="Privilege Escalation to Root",
            description="User sudo to root (potential privilege escalation)",
            severity="high",
            mitre_technique="T1548.003",
            mitre_tactic="Privilege Escalation",
            evaluate=evaluate,
        )

    def _rule_unauthorized_sudo(self) -> Rule:
        _allowed_sudo_users = {"root", "admin", "sysadmin", "ubuntu", "ec2-user"}

        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                if e.get("event_type") == "sudo":
                    user = e.get("username", "")
                    if user and user not in _allowed_sudo_users:
                        detections.append(Detection(
                            rule_id="RULE-004",
                            rule_name="Unauthorized Sudo Usage",
                            description=f"Non-admin user '{user}' used sudo: {e.get('command', 'unknown')}",
                            severity="high",
                            mitre_technique="T1548.003",
                            mitre_tactic="Privilege Escalation",
                            timestamp=e.get("timestamp"),
                            username=user,
                            evidence={"command": e.get("command", "unknown")},
                        ))
            return detections

        return Rule(
            rule_id="RULE-004",
            name="Unauthorized Sudo Usage",
            description="Sudo usage by non-admin user",
            severity="high",
            mitre_technique="T1548.003",
            mitre_tactic="Privilege Escalation",
            evaluate=evaluate,
        )

    def _rule_new_user_creation(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                if e.get("event_type") in ("user_add", "iam_modification"):
                    event_name = e.get("event_name", "")
                    if e.get("event_type") == "iam_modification" and "CreateUser" not in event_name:
                        continue
                    detections.append(Detection(
                        rule_id="RULE-005",
                        rule_name="New User Account Created",
                        description=f"New user account created: '{e.get('username', 'unknown')}'",
                        severity="high",
                        mitre_technique="T1136",
                        mitre_tactic="Persistence",
                        timestamp=e.get("timestamp"),
                        username=e.get("username"),
                        hostname=e.get("hostname"),
                    ))
            return detections

        return Rule(
            rule_id="RULE-005",
            name="New User Account Created",
            description="Detection of new local or cloud user account creation",
            severity="high",
            mitre_technique="T1136",
            mitre_tactic="Persistence",
            evaluate=evaluate,
        )

    def _rule_user_added_to_admin_group(self) -> Rule:
        _admin_groups = {"sudo", "wheel", "admin", "root", "administrators"}

        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                if e.get("event_type") == "user_modify":
                    group = (e.get("extra") or {}).get("group", "").lower()
                    if group in _admin_groups:
                        detections.append(Detection(
                            rule_id="RULE-006",
                            rule_name="User Added to Admin Group",
                            description=f"User '{e.get('username')}' added to admin group '{group}'",
                            severity="critical",
                            mitre_technique="T1098",
                            mitre_tactic="Persistence",
                            timestamp=e.get("timestamp"),
                            username=e.get("username"),
                            evidence={"group": group},
                        ))
            return detections

        return Rule(
            rule_id="RULE-006",
            name="User Added to Admin Group",
            description="User added to privileged group (sudo, wheel, admin)",
            severity="critical",
            mitre_technique="T1098",
            mitre_tactic="Persistence",
            evaluate=evaluate,
        )

    def _rule_port_scan(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            ports_by_ip: defaultdict[str, set] = defaultdict(set)
            events_by_ip: defaultdict[str, list] = defaultdict(list)

            for e in events:
                ip = e.get("source_ip")
                port = e.get("dest_port")
                if ip and port and e.get("action") == "blocked":
                    ports_by_ip[ip].add(port)
                    events_by_ip[ip].append(e)

            for ip, ports in ports_by_ip.items():
                if len(ports) >= 20:
                    first = events_by_ip[ip][0]
                    detections.append(Detection(
                        rule_id="RULE-007",
                        rule_name="Port Scan Detected",
                        description=f"Port scan from {ip}: {len(ports)} unique ports targeted",
                        severity="high",
                        mitre_technique="T1046",
                        mitre_tactic="Discovery",
                        timestamp=first.get("timestamp"),
                        source_ip=ip,
                        evidence={
                            "unique_ports": len(ports),
                            "sample_ports": sorted(list(ports))[:20],
                        },
                    ))
            return detections

        return Rule(
            rule_id="RULE-007",
            name="Port Scan Detected",
            description="20+ unique destination ports blocked from single source IP",
            severity="high",
            mitre_technique="T1046",
            mitre_tactic="Discovery",
            evaluate=evaluate,
        )

    def _rule_large_outbound_transfer(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                bytes_out = (e.get("extra") or {}).get("bytes_out", 0)
                if bytes_out and int(bytes_out) > 100_000_000:  # 100MB
                    detections.append(Detection(
                        rule_id="RULE-008",
                        rule_name="Large Outbound Data Transfer",
                        description=f"Large outbound transfer: {int(bytes_out) / 1_000_000:.1f}MB "
                                    f"to {e.get('dest_ip', 'unknown')}",
                        severity="high",
                        mitre_technique="T1048",
                        mitre_tactic="Exfiltration",
                        timestamp=e.get("timestamp"),
                        source_ip=e.get("source_ip"),
                        evidence={"bytes": int(bytes_out)},
                    ))
            return detections

        return Rule(
            rule_id="RULE-008",
            name="Large Outbound Data Transfer",
            description="Outbound transfer exceeding 100MB (potential data exfiltration)",
            severity="high",
            mitre_technique="T1048",
            mitre_tactic="Exfiltration",
            evaluate=evaluate,
        )

    def _rule_service_stopped(self) -> Rule:
        _critical_services = {
            "sshd", "auditd", "rsyslog", "syslog-ng", "firewalld",
            "iptables", "ufw", "fail2ban", "ossec", "clamd", "aide",
        }

        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                if e.get("event_type") == "service_stop":
                    svc = (e.get("extra") or {}).get("target_service", "")
                    unit = (e.get("extra") or {}).get("unit", "")
                    name = svc or unit
                    if any(cs in name.lower() for cs in _critical_services):
                        detections.append(Detection(
                            rule_id="RULE-009",
                            rule_name="Critical Service Stopped",
                            description=f"Critical security service stopped: {name}",
                            severity="high",
                            mitre_technique="T1562.001",
                            mitre_tactic="Defense Evasion",
                            timestamp=e.get("timestamp"),
                            hostname=e.get("hostname"),
                            evidence={"service": name},
                        ))
            return detections

        return Rule(
            rule_id="RULE-009",
            name="Critical Service Stopped",
            description="Security-critical service (auditd, syslog, firewall, etc.) was stopped",
            severity="high",
            mitre_technique="T1562.001",
            mitre_tactic="Defense Evasion",
            evaluate=evaluate,
        )

    def _rule_crontab_modification(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                if e.get("event_type") == "cron_modified":
                    user = (e.get("extra") or {}).get("cron_user", "unknown")
                    detections.append(Detection(
                        rule_id="RULE-010",
                        rule_name="Crontab Modification",
                        description=f"Crontab modified for user '{user}'",
                        severity="high",
                        mitre_technique="T1053.003",
                        mitre_tactic="Persistence",
                        timestamp=e.get("timestamp"),
                        username=user,
                        hostname=e.get("hostname"),
                    ))
            return detections

        return Rule(
            rule_id="RULE-010",
            name="Crontab Modification",
            description="Crontab edited (potential scheduled persistence mechanism)",
            severity="high",
            mitre_technique="T1053.003",
            mitre_tactic="Persistence",
            evaluate=evaluate,
        )

    def _rule_suspicious_process(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                if e.get("event_type") == "suspicious_process":
                    binary = (e.get("extra") or {}).get("suspicious_binary", "unknown")
                    detections.append(Detection(
                        rule_id="RULE-011",
                        rule_name="Suspicious Process Execution",
                        description=f"Suspicious binary executed: {binary}",
                        severity="critical",
                        mitre_technique="T1059",
                        mitre_tactic="Execution",
                        timestamp=e.get("timestamp"),
                        hostname=e.get("hostname"),
                        evidence={"binary": binary},
                    ))
            return detections

        return Rule(
            rule_id="RULE-011",
            name="Suspicious Process Execution",
            description="Known offensive tool or suspicious binary executed (nc, nmap, etc.)",
            severity="critical",
            mitre_technique="T1059",
            mitre_tactic="Execution",
            evaluate=evaluate,
        )

    def _rule_iam_policy_change(self) -> Rule:
        _iam_write_events = {
            "AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy",
            "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy",
            "DetachUserPolicy", "DetachGroupPolicy", "DetachRolePolicy",
            "CreatePolicy", "DeletePolicy", "CreatePolicyVersion",
        }

        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                event_name = e.get("event_name", "")
                if event_name in _iam_write_events:
                    user_id = e.get("user_identity", {})
                    principal = user_id.get("arn", user_id.get("userName", "unknown"))
                    detections.append(Detection(
                        rule_id="RULE-012",
                        rule_name="IAM Policy Modification",
                        description=f"IAM policy changed: {event_name} by {principal}",
                        severity="high",
                        mitre_technique="T1098",
                        mitre_tactic="Persistence",
                        timestamp=e.get("timestamp"),
                        source_ip=e.get("source_ip"),
                        username=str(principal),
                        evidence={
                            "event_name": event_name,
                            "request_params": e.get("request_params"),
                        },
                    ))
            return detections

        return Rule(
            rule_id="RULE-012",
            name="IAM Policy Modification",
            description="AWS IAM policy attached, modified, or deleted",
            severity="high",
            mitre_technique="T1098",
            mitre_tactic="Persistence",
            evaluate=evaluate,
        )

    def _rule_cloudtrail_logging_disabled(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                event_name = e.get("event_name", "")
                if event_name in ("StopLogging", "DeleteTrail", "UpdateTrail"):
                    user_id = e.get("user_identity", {})
                    principal = user_id.get("arn", "unknown")
                    detections.append(Detection(
                        rule_id="RULE-013",
                        rule_name="CloudTrail Logging Disabled",
                        description=f"CloudTrail logging modified: {event_name} by {principal}",
                        severity="critical",
                        mitre_technique="T1562.008",
                        mitre_tactic="Defense Evasion",
                        timestamp=e.get("timestamp"),
                        source_ip=e.get("source_ip"),
                        evidence={"event_name": event_name, "principal": str(principal)},
                    ))
            return detections

        return Rule(
            rule_id="RULE-013",
            name="CloudTrail Logging Disabled",
            description="CloudTrail logging stopped or trail deleted (anti-forensics)",
            severity="critical",
            mitre_technique="T1562.008",
            mitre_tactic="Defense Evasion",
            evaluate=evaluate,
        )

    def _rule_s3_bucket_public(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                event_name = e.get("event_name", "")
                if event_name in ("PutBucketPolicy", "PutBucketAcl"):
                    params = e.get("request_params") or {}
                    policy_str = str(params).lower()
                    if '"principal":"*"' in policy_str or "*" in policy_str:
                        detections.append(Detection(
                            rule_id="RULE-014",
                            rule_name="S3 Bucket Made Public",
                            description=f"S3 bucket policy/ACL changed to allow public access",
                            severity="critical",
                            mitre_technique="T1530",
                            mitre_tactic="Collection",
                            timestamp=e.get("timestamp"),
                            source_ip=e.get("source_ip"),
                            evidence={
                                "event_name": event_name,
                                "bucket": params.get("bucketName", "unknown"),
                            },
                        ))
            return detections

        return Rule(
            rule_id="RULE-014",
            name="S3 Bucket Made Public",
            description="S3 bucket policy or ACL changed to allow public access",
            severity="critical",
            mitre_technique="T1530",
            mitre_tactic="Collection",
            evaluate=evaluate,
        )

    def _rule_root_account_usage(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                user_id = e.get("user_identity", {})
                if user_id.get("type") == "Root":
                    event_name = e.get("event_name", "")
                    detections.append(Detection(
                        rule_id="RULE-015",
                        rule_name="AWS Root Account Usage",
                        description=f"Root account used for: {event_name}",
                        severity="critical",
                        mitre_technique="T1078.004",
                        mitre_tactic="Privilege Escalation",
                        timestamp=e.get("timestamp"),
                        source_ip=e.get("source_ip"),
                        evidence={"event_name": event_name},
                    ))
            return detections

        return Rule(
            rule_id="RULE-015",
            name="AWS Root Account Usage",
            description="AWS root account used (should use IAM users instead)",
            severity="critical",
            mitre_technique="T1078.004",
            mitre_tactic="Privilege Escalation",
            evaluate=evaluate,
        )

    def _rule_security_group_opened(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                if e.get("event_name") == "AuthorizeSecurityGroupIngress":
                    params = e.get("request_params") or {}
                    params_str = str(params)
                    if "0.0.0.0/0" in params_str or "::/0" in params_str:
                        detections.append(Detection(
                            rule_id="RULE-016",
                            rule_name="Security Group Opened to World",
                            description="Security group ingress rule allows 0.0.0.0/0",
                            severity="critical",
                            mitre_technique="T1562.007",
                            mitre_tactic="Defense Evasion",
                            timestamp=e.get("timestamp"),
                            source_ip=e.get("source_ip"),
                            evidence={"request_params": params},
                        ))
            return detections

        return Rule(
            rule_id="RULE-016",
            name="Security Group Opened to World",
            description="AWS security group opened to 0.0.0.0/0 (all internet traffic)",
            severity="critical",
            mitre_technique="T1562.007",
            mitre_tactic="Defense Evasion",
            evaluate=evaluate,
        )

    def _rule_credential_stuffing(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            # Many different usernames from same IP
            users_by_ip: defaultdict[str, set] = defaultdict(set)
            events_by_ip: defaultdict[str, list] = defaultdict(list)

            for e in events:
                if e.get("event_type") in ("failed_login", "invalid_user"):
                    ip = e.get("source_ip")
                    user = e.get("username")
                    if ip and user:
                        users_by_ip[ip].add(user)
                        events_by_ip[ip].append(e)

            for ip, users in users_by_ip.items():
                if len(users) >= 5:
                    first = events_by_ip[ip][0]
                    detections.append(Detection(
                        rule_id="RULE-017",
                        rule_name="Credential Stuffing",
                        description=f"Credential stuffing from {ip}: {len(users)} unique usernames attempted",
                        severity="high",
                        mitre_technique="T1110.004",
                        mitre_tactic="Credential Access",
                        timestamp=first.get("timestamp"),
                        source_ip=ip,
                        evidence={
                            "unique_usernames": len(users),
                            "sample_users": sorted(list(users))[:10],
                        },
                    ))
            return detections

        return Rule(
            rule_id="RULE-017",
            name="Credential Stuffing",
            description="5+ unique usernames attempted from single IP (credential stuffing)",
            severity="high",
            mitre_technique="T1110.004",
            mitre_tactic="Credential Access",
            evaluate=evaluate,
        )

    def _rule_impossible_travel(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            logins_by_user: defaultdict[str, list] = defaultdict(list)

            for e in events:
                if e.get("event_type") == "successful_login":
                    user = e.get("username")
                    ip = e.get("source_ip")
                    ts = e.get("timestamp")
                    if user and ip and ts:
                        logins_by_user[user].append(e)

            for user, logins in logins_by_user.items():
                logins.sort(key=lambda x: x["timestamp"])
                for i in range(1, len(logins)):
                    prev_ip = logins[i - 1].get("source_ip")
                    curr_ip = logins[i].get("source_ip")
                    time_diff = (logins[i]["timestamp"] - logins[i - 1]["timestamp"]).total_seconds()

                    # Different IPs within 5 minutes
                    if prev_ip != curr_ip and 0 < time_diff < 300:
                        detections.append(Detection(
                            rule_id="RULE-018",
                            rule_name="Impossible Travel",
                            description=f"User '{user}' logged in from {prev_ip} and {curr_ip} "
                                        f"within {int(time_diff)}s",
                            severity="high",
                            mitre_technique="T1078",
                            mitre_tactic="Initial Access",
                            timestamp=logins[i]["timestamp"],
                            source_ip=curr_ip,
                            username=user,
                            evidence={
                                "previous_ip": prev_ip,
                                "current_ip": curr_ip,
                                "time_diff_seconds": int(time_diff),
                            },
                        ))
            return detections

        return Rule(
            rule_id="RULE-018",
            name="Impossible Travel",
            description="Login from different IPs within 5 minutes (compromised credentials)",
            severity="high",
            mitre_technique="T1078",
            mitre_tactic="Initial Access",
            evaluate=evaluate,
        )

    def _rule_password_spray(self) -> Rule:
        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            # Same username attempted from many IPs
            ips_by_user: defaultdict[str, set] = defaultdict(set)

            for e in events:
                if e.get("event_type") in ("failed_login",):
                    user = e.get("username")
                    ip = e.get("source_ip")
                    if user and ip:
                        ips_by_user[user].add(ip)

            for user, ips in ips_by_user.items():
                if len(ips) >= 3:
                    detections.append(Detection(
                        rule_id="RULE-019",
                        rule_name="Password Spray",
                        description=f"Password spray against '{user}': "
                                    f"failed logins from {len(ips)} different IPs",
                        severity="high",
                        mitre_technique="T1110.003",
                        mitre_tactic="Credential Access",
                        timestamp=None,
                        username=user,
                        evidence={
                            "source_ips": sorted(list(ips))[:10],
                            "unique_sources": len(ips),
                        },
                    ))
            return detections

        return Rule(
            rule_id="RULE-019",
            name="Password Spray",
            description="Failed logins for same username from 3+ different IPs",
            severity="high",
            mitre_technique="T1110.003",
            mitre_tactic="Credential Access",
            evaluate=evaluate,
        )

    def _rule_reverse_shell_indicator(self) -> Rule:
        _indicators = {"nc -e", "ncat -e", "bash -i", "/dev/tcp/", "/dev/udp/",
                        "mkfifo", "mknod", "reverse_shell", "bind_shell",
                        "meterpreter", "powershell -enc", "IEX("}

        def evaluate(events: list[dict]) -> list[Detection]:
            detections = []
            for e in events:
                cmd = e.get("command", "") or e.get("message", "") or ""
                raw = e.get("raw_line", "")
                text = f"{cmd} {raw}".lower()
                for indicator in _indicators:
                    if indicator.lower() in text:
                        detections.append(Detection(
                            rule_id="RULE-020",
                            rule_name="Reverse Shell Indicator",
                            description=f"Reverse shell indicator detected: '{indicator}'",
                            severity="critical",
                            mitre_technique="T1059",
                            mitre_tactic="Execution",
                            timestamp=e.get("timestamp"),
                            hostname=e.get("hostname"),
                            evidence={"indicator": indicator, "context": text[:200]},
                        ))
                        break
            return detections

        return Rule(
            rule_id="RULE-020",
            name="Reverse Shell Indicator",
            description="Command patterns indicating reverse shell (nc -e, bash -i, /dev/tcp, etc.)",
            severity="critical",
            mitre_technique="T1059",
            mitre_tactic="Execution",
            evaluate=evaluate,
        )
