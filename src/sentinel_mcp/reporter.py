"""Incident report generator producing structured Markdown reports."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Optional


class ReportGenerator:
    """Generate comprehensive incident reports from detection findings."""

    def generate(
        self,
        detections: list[dict[str, Any]],
        anomalies: list[dict[str, Any]],
        timeframe_hours: int = 24,
        title: Optional[str] = None,
    ) -> str:
        """Generate a full Markdown incident report.

        Args:
            detections: List of Detection-like dicts from the rule engine.
            anomalies: List of Anomaly-like dicts from the anomaly detector.
            timeframe_hours: Reporting window in hours.
            title: Optional report title override.

        Returns:
            Markdown-formatted incident report string.
        """
        now = datetime.now()
        all_findings = self._merge_findings(detections, anomalies)
        severity = self._assess_overall_severity(all_findings)
        affected_hosts = self._extract_hosts(all_findings)
        affected_accounts = self._extract_accounts(all_findings)
        iocs = self._extract_iocs(all_findings)
        mitre_mappings = self._extract_mitre(detections)
        timeline = self._build_timeline(all_findings)

        report_title = title or f"Security Incident Report - {now.strftime('%Y-%m-%d %H:%M')}"

        sections = [
            f"# {report_title}\n",
            f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Timeframe:** Last {timeframe_hours} hours  ",
            f"**Overall Severity:** {severity.upper()}  ",
            f"**Total Findings:** {len(all_findings)}  \n",
            "---\n",
            self._section_executive_summary(all_findings, severity, affected_hosts, iocs),
            self._section_severity_breakdown(all_findings),
            self._section_timeline(timeline),
            self._section_affected_assets(affected_hosts, affected_accounts),
            self._section_iocs(iocs),
            self._section_mitre_mapping(mitre_mappings),
            self._section_detailed_findings(all_findings),
            self._section_recommendations(all_findings, severity),
        ]

        return "\n".join(sections)

    def _merge_findings(
        self,
        detections: list[dict],
        anomalies: list[dict],
    ) -> list[dict]:
        """Merge detections and anomalies into a unified finding list."""
        findings = []

        for d in detections:
            findings.append({
                "type": "detection",
                "id": d.get("rule_id", "N/A"),
                "name": d.get("rule_name", d.get("anomaly_type", "Unknown")),
                "description": d.get("description", ""),
                "severity": d.get("severity", "info"),
                "timestamp": d.get("timestamp"),
                "source_ip": d.get("source_ip"),
                "username": d.get("username"),
                "hostname": d.get("hostname"),
                "mitre_technique": d.get("mitre_technique"),
                "mitre_tactic": d.get("mitre_tactic"),
                "evidence": d.get("evidence", {}),
            })

        for a in anomalies:
            findings.append({
                "type": "anomaly",
                "id": a.get("anomaly_type", "N/A"),
                "name": a.get("anomaly_type", "Unknown Anomaly"),
                "description": a.get("description", ""),
                "severity": a.get("severity", "info"),
                "timestamp": a.get("timestamp"),
                "source_ip": a.get("source_ip"),
                "username": a.get("username"),
                "hostname": None,
                "mitre_technique": None,
                "mitre_tactic": None,
                "evidence": a.get("evidence", {}),
                "score": a.get("score", 0.0),
            })

        return findings

    def _assess_overall_severity(self, findings: list[dict]) -> str:
        """Determine overall severity from findings."""
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        max_sev = 0
        for f in findings:
            sev = severity_order.get(f.get("severity", "info"), 0)
            max_sev = max(max_sev, sev)

        # Also escalate if there are many high findings
        high_count = sum(1 for f in findings if f.get("severity") in ("high", "critical"))
        if high_count >= 3 and max_sev < 4:
            max_sev = min(max_sev + 1, 4)

        reverse_map = {v: k for k, v in severity_order.items()}
        return reverse_map.get(max_sev, "info")

    def _extract_hosts(self, findings: list[dict]) -> list[str]:
        """Extract unique affected hostnames."""
        hosts = set()
        for f in findings:
            if f.get("hostname"):
                hosts.add(f["hostname"])
        return sorted(hosts) if hosts else ["(none identified)"]

    def _extract_accounts(self, findings: list[dict]) -> list[str]:
        """Extract unique affected user accounts."""
        accounts = set()
        for f in findings:
            if f.get("username"):
                accounts.add(f["username"])
        return sorted(accounts) if accounts else ["(none identified)"]

    def _extract_iocs(self, findings: list[dict]) -> dict[str, set[str]]:
        """Extract IOCs (IPs, usernames, etc.) from findings."""
        iocs: dict[str, set[str]] = {
            "ip_addresses": set(),
            "usernames": set(),
        }
        for f in findings:
            if f.get("source_ip") and f.get("severity") in ("medium", "high", "critical"):
                iocs["ip_addresses"].add(f["source_ip"])
            if f.get("username") and f.get("severity") in ("high", "critical"):
                iocs["usernames"].add(f["username"])
            evidence = f.get("evidence", {})
            if isinstance(evidence, dict):
                prev_ip = evidence.get("previous_ip")
                if prev_ip:
                    iocs["ip_addresses"].add(prev_ip)
        return iocs

    def _extract_mitre(self, detections: list[dict]) -> list[dict]:
        """Extract unique MITRE mappings from detections."""
        seen = set()
        mappings = []
        for d in detections:
            tid = d.get("mitre_technique")
            if tid and tid not in seen:
                seen.add(tid)
                mappings.append({
                    "technique_id": tid,
                    "tactic": d.get("mitre_tactic", "Unknown"),
                    "rule": d.get("rule_name", "N/A"),
                })
        return mappings

    def _build_timeline(self, findings: list[dict]) -> list[dict]:
        """Build a chronological timeline from findings."""
        timed = [f for f in findings if f.get("timestamp")]
        timed.sort(key=lambda f: f["timestamp"])
        return timed

    # -- Report Sections --

    def _section_executive_summary(
        self,
        findings: list[dict],
        severity: str,
        hosts: list[str],
        iocs: dict[str, set[str]],
    ) -> str:
        """Generate the executive summary section."""
        severity_counts = Counter(f.get("severity", "info") for f in findings)
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)

        ip_count = len(iocs.get("ip_addresses", set()))

        summary_parts = []
        if critical > 0:
            summary_parts.append(f"{critical} critical-severity finding(s)")
        if high > 0:
            summary_parts.append(f"{high} high-severity finding(s)")

        summary_text = " and ".join(summary_parts) if summary_parts else "No critical or high-severity findings"

        return (
            "## Executive Summary\n\n"
            f"Analysis identified **{len(findings)} security findings** across the monitored infrastructure, "
            f"including {summary_text}. "
            f"**{ip_count} suspicious IP address(es)** were identified as indicators of compromise. "
            f"The overall severity assessment is **{severity.upper()}**. "
            "Immediate investigation and response actions are recommended for critical and high-severity findings.\n\n"
        )

    def _section_severity_breakdown(self, findings: list[dict]) -> str:
        """Generate severity breakdown table."""
        counts = Counter(f.get("severity", "info") for f in findings)
        lines = [
            "## Severity Breakdown\n",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            marker = " **<--**" if sev in ("critical", "high") and c > 0 else ""
            lines.append(f"| {sev.upper()} | {c}{marker} |")
        lines.append("")
        return "\n".join(lines) + "\n"

    def _section_timeline(self, timeline: list[dict]) -> str:
        """Generate chronological timeline."""
        if not timeline:
            return "## Timeline\n\nNo timestamped events available.\n\n"

        lines = [
            "## Timeline of Events\n",
            "| Time | Severity | Finding | Source IP | Details |",
            "|------|----------|---------|-----------|---------|",
        ]
        for f in timeline[:50]:  # Limit to 50 entries
            ts = f["timestamp"]
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)
            lines.append(
                f"| {ts_str} "
                f"| {f.get('severity', 'info').upper()} "
                f"| {f.get('name', 'Unknown')} "
                f"| {f.get('source_ip', 'N/A')} "
                f"| {f.get('description', '')[:80]} |"
            )
        lines.append("")
        return "\n".join(lines) + "\n"

    def _section_affected_assets(
        self, hosts: list[str], accounts: list[str]
    ) -> str:
        """Generate affected assets section."""
        lines = ["## Affected Assets\n", "### Hosts"]
        for h in hosts:
            lines.append(f"- {h}")
        lines.append("\n### User Accounts")
        for a in accounts:
            lines.append(f"- `{a}`")
        lines.append("")
        return "\n".join(lines) + "\n"

    def _section_iocs(self, iocs: dict[str, set[str]]) -> str:
        """Generate IOC section."""
        lines = ["## Indicators of Compromise (IOCs)\n"]

        ips = iocs.get("ip_addresses", set())
        if ips:
            lines.append("### Suspicious IP Addresses")
            for ip in sorted(ips):
                lines.append(f"- `{ip}`")
            lines.append("")

        users = iocs.get("usernames", set())
        if users:
            lines.append("### Compromised/Targeted Accounts")
            for u in sorted(users):
                lines.append(f"- `{u}`")
            lines.append("")

        if not ips and not users:
            lines.append("No IOCs extracted from current findings.\n")

        return "\n".join(lines) + "\n"

    def _section_mitre_mapping(self, mappings: list[dict]) -> str:
        """Generate MITRE ATT&CK mapping table."""
        if not mappings:
            return "## MITRE ATT&CK Mapping\n\nNo techniques mapped for current findings.\n\n"

        lines = [
            "## MITRE ATT&CK Mapping\n",
            "| Technique ID | Tactic | Triggered By |",
            "|-------------|--------|-------------|",
        ]
        for m in mappings:
            lines.append(
                f"| [{m['technique_id']}](https://attack.mitre.org/techniques/{m['technique_id'].replace('.', '/')}) "
                f"| {m['tactic']} "
                f"| {m['rule']} |"
            )
        lines.append("")
        return "\n".join(lines) + "\n"

    def _section_detailed_findings(self, findings: list[dict]) -> str:
        """Generate detailed findings section."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5)
        )

        lines = ["## Detailed Findings\n"]
        for i, f in enumerate(sorted_findings[:30], 1):
            sev = f.get("severity", "info").upper()
            lines.append(f"### {i}. [{sev}] {f.get('name', 'Unknown')}\n")
            lines.append(f"- **Description:** {f.get('description', 'N/A')}")
            if f.get("timestamp"):
                ts = f["timestamp"]
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)
                lines.append(f"- **Time:** {ts_str}")
            if f.get("source_ip"):
                lines.append(f"- **Source IP:** `{f['source_ip']}`")
            if f.get("username"):
                lines.append(f"- **User:** `{f['username']}`")
            if f.get("hostname"):
                lines.append(f"- **Host:** `{f['hostname']}`")
            if f.get("mitre_technique"):
                lines.append(f"- **MITRE:** {f['mitre_technique']} ({f.get('mitre_tactic', 'N/A')})")
            evidence = f.get("evidence")
            if evidence and isinstance(evidence, dict):
                lines.append(f"- **Evidence:** {_format_evidence(evidence)}")
            lines.append("")
        return "\n".join(lines) + "\n"

    def _section_recommendations(self, findings: list[dict], severity: str) -> str:
        """Generate actionable recommendations based on findings."""
        lines = ["## Recommended Actions\n"]

        recs: list[str] = []
        finding_types = {f.get("name", "").lower() for f in findings}
        mitre_techniques = {f.get("mitre_technique", "") for f in findings if f.get("mitre_technique")}

        if severity in ("critical", "high"):
            recs.append("**IMMEDIATE:** Activate incident response procedures and notify the security team.")

        if any("brute force" in t for t in finding_types):
            recs.extend([
                "Block attacker IP addresses at the perimeter firewall.",
                "Enforce account lockout policies after 5 failed attempts.",
                "Implement multi-factor authentication for all remote access.",
                "Review and rotate credentials for any compromised accounts.",
            ])

        if any("privilege" in t or "sudo" in t for t in finding_types):
            recs.extend([
                "Audit all sudo configurations and remove unnecessary privileges.",
                "Review recent privilege escalation events for unauthorized access.",
                "Implement least-privilege access controls.",
            ])

        if any("user" in t and ("creat" in t or "add" in t) for t in finding_types):
            recs.extend([
                "Verify all recently created accounts are authorized.",
                "Disable any unauthorized accounts immediately.",
                "Review group memberships for privilege creep.",
            ])

        if any("port scan" in t for t in finding_types):
            recs.extend([
                "Block scanning IP addresses at the firewall.",
                "Verify no unauthorized services are exposed.",
                "Review firewall rules for overly permissive configurations.",
            ])

        if "T1562" in mitre_techniques or "T1562.008" in mitre_techniques:
            recs.extend([
                "Verify all security monitoring and logging services are operational.",
                "Restore any disabled logging immediately.",
                "Investigate the actor who disabled defenses.",
            ])

        if any("cloudtrail" in t or "iam" in t for t in finding_types):
            recs.extend([
                "Review all IAM changes in the affected AWS account.",
                "Enable CloudTrail logging in all regions if not already active.",
                "Review S3 bucket policies for public exposure.",
            ])

        if any("cron" in t for t in finding_types):
            recs.append("Audit all crontab entries across affected hosts for malicious persistence.")

        if any("reverse shell" in t or "suspicious process" in t for t in finding_types):
            recs.extend([
                "Isolate affected host(s) from the network immediately.",
                "Perform forensic analysis of the compromised system.",
                "Scan for additional indicators of compromise.",
            ])

        if not recs:
            recs.append("Continue monitoring. No immediate action required based on current findings.")

        # General recommendations always included
        recs.extend([
            "Preserve all relevant log files for forensic analysis.",
            "Document all response actions taken with timestamps.",
        ])

        # Deduplicate while preserving order
        seen: set[str] = set()
        for r in recs:
            if r not in seen:
                seen.add(r)
                lines.append(f"1. {r}")

        lines.append("")
        return "\n".join(lines) + "\n"


def _format_evidence(evidence: dict) -> str:
    """Format evidence dict as a readable string."""
    parts = []
    for k, v in evidence.items():
        if isinstance(v, (list, set)):
            v_str = ", ".join(str(x) for x in list(v)[:5])
            if len(list(v)) > 5:
                v_str += f" ... ({len(v)} total)"
            parts.append(f"{k}=[{v_str}]")
        elif isinstance(v, dict):
            parts.append(f"{k}={{...}}")
        else:
            parts.append(f"{k}={v}")
    return "; ".join(parts)
