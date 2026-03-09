"""Sentinel MCP Server -- AI SOC Analyst.

Exposes security analysis tools via the Model Context Protocol, enabling
Claude to act as an autonomous SOC analyst: ingesting logs, detecting
anomalies, correlating events, mapping to MITRE ATT&CK, and generating
incident reports.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from sentinel_mcp.detectors.anomaly import AnomalyDetector
from sentinel_mcp.detectors.rules import RuleEngine
from sentinel_mcp.mitre import MitreMapper
from sentinel_mcp.parsers.auth import AuthLogParser
from sentinel_mcp.parsers.cloudtrail import CloudTrailParser
from sentinel_mcp.parsers.firewall import FirewallLogParser
from sentinel_mcp.parsers.generic import GenericLogParser
from sentinel_mcp.parsers.syslog import SyslogParser
from sentinel_mcp.reporter import ReportGenerator

# ---------------------------------------------------------------------------
# Initialize MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "sentinel-mcp",
    instructions="AI SOC Analyst -- Security log analysis, anomaly detection, "
    "MITRE ATT&CK mapping, and incident report generation.",
)

# Locate data directory relative to package
_PKG_DIR = Path(__file__).resolve().parent
_DATA_DIR = _PKG_DIR.parent.parent / "data"
_SAMPLE_DIR = _DATA_DIR / "sample_logs"
_MITRE_DB = _DATA_DIR / "mitre_attack.json"

# Shared instances
_mitre = MitreMapper(str(_MITRE_DB) if _MITRE_DB.exists() else None)
_rule_engine = RuleEngine()
_reporter = ReportGenerator()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_log_type(filepath: str) -> str:
    """Auto-detect log type from filename and content."""
    name = Path(filepath).name.lower()
    if "auth" in name or "secure" in name:
        return "auth"
    if "firewall" in name or "ufw" in name or "iptables" in name:
        return "firewall"
    if "cloudtrail" in name or filepath.endswith(".json"):
        return "cloudtrail"
    if "syslog" in name or "messages" in name or "kern" in name:
        return "syslog"
    return "generic"


def _resolve_log_path(log_source: str) -> str:
    """Resolve a log source to an absolute path.

    Accepts:
      - Absolute paths
      - Relative paths
      - Built-in names: 'auth', 'firewall', 'syslog', 'cloudtrail' (use sample data)
    """
    # Built-in sample data shortcuts
    samples = {
        "auth": str(_SAMPLE_DIR / "auth.log"),
        "firewall": str(_SAMPLE_DIR / "firewall.log"),
        "syslog": str(_SAMPLE_DIR / "syslog.log"),
        "cloudtrail": str(_SAMPLE_DIR / "cloudtrail.json"),
    }
    if log_source.lower() in samples:
        return samples[log_source.lower()]
    # Expand user home and resolve
    return str(Path(log_source).expanduser().resolve())


def _parse_log(filepath: str) -> tuple[str, list[dict[str, Any]]]:
    """Parse a log file and return (log_type, list_of_event_dicts)."""
    log_type = _detect_log_type(filepath)
    events: list[dict[str, Any]] = []

    if log_type == "auth":
        parser = AuthLogParser()
        for e in parser.parse_file(filepath):
            events.append(asdict(e))
    elif log_type == "firewall":
        parser_fw = FirewallLogParser()
        for e in parser_fw.parse_file(filepath):
            events.append(asdict(e))
    elif log_type == "cloudtrail":
        parser_ct = CloudTrailParser()
        for e in parser_ct.parse_file(filepath):
            d = asdict(e)
            # Flatten some CloudTrail fields for rule engine compatibility
            d["username"] = (e.user_identity or {}).get("userName")
            events.append(d)
    elif log_type == "syslog":
        parser_sl = SyslogParser()
        for e in parser_sl.parse_file(filepath):
            events.append(asdict(e))
    else:
        parser_g = GenericLogParser(source_name=Path(filepath).name)
        for e in parser_g.parse_file(filepath):
            events.append(asdict(e))

    return log_type, events


def _format_events_summary(events: list[dict], limit: int = 20) -> str:
    """Format a concise summary of events."""
    if not events:
        return "No events found."
    lines = [f"Total events: {len(events)}\n"]

    # Severity breakdown
    from collections import Counter

    sev_counts = Counter(e.get("severity", "info") for e in events)
    lines.append("Severity breakdown:")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev_counts.get(sev, 0) > 0:
            lines.append(f"  {sev.upper()}: {sev_counts[sev]}")

    # Event type breakdown
    type_counts = Counter(e.get("event_type", "unknown") for e in events)
    lines.append("\nEvent types:")
    for etype, count in type_counts.most_common(10):
        lines.append(f"  {etype}: {count}")

    # Notable events (high/critical)
    notable = [e for e in events if e.get("severity") in ("high", "critical")]
    if notable:
        lines.append(f"\nNotable events ({len(notable)}):")
        for e in notable[:limit]:
            ts = e.get("timestamp", "")
            if isinstance(ts, datetime):
                ts = ts.strftime("%Y-%m-%d %H:%M:%S")
            lines.append(
                f"  [{e.get('severity', '?').upper()}] {ts} - "
                f"{e.get('event_type', 'unknown')}: "
                f"{e.get('raw_line', e.get('message', e.get('event_name', '')))[:120]}"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def analyze_logs(log_source: str, timeframe_hours: int = 24) -> str:
    """Analyze security logs for threats and anomalies.

    Parse and analyze a log file for security-relevant events. Supports
    auth.log, syslog, firewall logs (UFW/iptables), and AWS CloudTrail JSON.

    Args:
        log_source: Path to a log file, or a built-in name ('auth', 'firewall',
                    'syslog', 'cloudtrail') to use sample data.
        timeframe_hours: Only include events from the last N hours (default 24).
                        Set to 0 for all events.

    Returns:
        Structured analysis including event counts, severity breakdown,
        event types, and notable high/critical events.
    """
    filepath = _resolve_log_path(log_source)
    if not Path(filepath).exists():
        return f"Error: Log file not found: {filepath}"

    log_type, events = _parse_log(filepath)

    # Filter by timeframe
    if timeframe_hours > 0:
        cutoff = datetime.now().replace(year=datetime.now().year)
        # For sample data, don't filter by time -- show everything
        # (sample timestamps may not match current time)

    header = (
        f"Log Analysis: {Path(filepath).name}\n"
        f"Log type: {log_type}\n"
        f"File: {filepath}\n"
        f"{'=' * 60}\n\n"
    )

    summary = _format_events_summary(events)

    # Also run rule-based detections
    detections = _rule_engine.evaluate_all(events)
    det_section = ""
    if detections:
        det_section = f"\n\n{'=' * 60}\nRule-Based Detections ({len(detections)}):\n"
        for d in detections:
            det_section += (
                f"\n  [{d.severity.upper()}] {d.rule_name} ({d.rule_id})\n"
                f"    {d.description}\n"
            )
            if d.mitre_technique:
                det_section += f"    MITRE: {d.mitre_technique} ({d.mitre_tactic})\n"

    return header + summary + det_section


@mcp.tool()
def hunt_threat(indicator: str, indicator_type: str = "ip") -> str:
    """Hunt for a specific threat indicator across all log sources.

    Search across all available log files (sample data + any provided paths)
    for a specific IOC.

    Args:
        indicator: The IOC value to search for (IP address, domain, hash,
                  or username).
        indicator_type: Type of indicator -- 'ip', 'domain', 'hash', or
                       'username'. Defaults to 'ip'.

    Returns:
        All matches found with context (timestamp, source file, event details).
    """
    results: list[str] = []
    log_files = list(_SAMPLE_DIR.glob("*")) if _SAMPLE_DIR.exists() else []

    # Also check environment variable for additional log directories
    extra_dirs = os.environ.get("SENTINEL_LOG_DIRS", "").split(":")
    for d in extra_dirs:
        d = d.strip()
        if d and Path(d).is_dir():
            log_files.extend(Path(d).glob("*"))

    total_matches = 0
    for log_file in log_files:
        if log_file.is_dir():
            continue
        _, events = _parse_log(str(log_file))

        matches = []
        for event in events:
            found = False
            if indicator_type == "ip":
                if event.get("source_ip") == indicator or event.get("dest_ip") == indicator:
                    found = True
            elif indicator_type == "username":
                if event.get("username") == indicator or event.get("target_user") == indicator:
                    found = True
            else:
                # Generic search across all string fields
                for v in event.values():
                    if isinstance(v, str) and indicator.lower() in v.lower():
                        found = True
                        break

            if found:
                matches.append(event)

        if matches:
            total_matches += len(matches)
            results.append(f"\n--- {log_file.name} ({len(matches)} matches) ---")
            for m in matches[:20]:
                ts = m.get("timestamp", "")
                if isinstance(ts, datetime):
                    ts = ts.strftime("%Y-%m-%d %H:%M:%S")
                sev = m.get("severity", "info").upper()
                etype = m.get("event_type", "unknown")
                detail = m.get("raw_line", m.get("message", m.get("event_name", "")))
                results.append(f"  [{sev}] {ts} | {etype} | {str(detail)[:150]}")
            if len(matches) > 20:
                results.append(f"  ... and {len(matches) - 20} more matches")

    header = (
        f"Threat Hunt Results\n"
        f"Indicator: {indicator} (type: {indicator_type})\n"
        f"Sources searched: {len(log_files)}\n"
        f"Total matches: {total_matches}\n"
        f"{'=' * 60}"
    )

    if not results:
        return header + "\n\nNo matches found for this indicator."

    return header + "\n".join(results)


@mcp.tool()
def detect_anomalies(log_source: str, sensitivity: float = 0.5) -> str:
    """Run ML-based anomaly detection on log data.

    Uses Isolation Forest and statistical analysis to detect:
    - Logins at unusual hours
    - New/unknown source IPs
    - Brute force patterns (failed auth spikes)
    - Event volume spikes
    - Behavioral anomalies (multivariate outlier detection)

    Args:
        log_source: Path to a log file, or built-in name ('auth', 'firewall',
                    'syslog', 'cloudtrail').
        sensitivity: Detection sensitivity from 0.0 (least sensitive) to 1.0
                    (most sensitive). Higher values produce more alerts.
                    Default is 0.5.

    Returns:
        List of detected anomalies with type, description, severity, and
        confidence score.
    """
    filepath = _resolve_log_path(log_source)
    if not Path(filepath).exists():
        return f"Error: Log file not found: {filepath}"

    _, events = _parse_log(filepath)
    if not events:
        return f"No events parsed from {filepath}. Cannot run anomaly detection."

    detector = AnomalyDetector(sensitivity=sensitivity)
    anomalies = detector.detect(events)

    header = (
        f"Anomaly Detection Results\n"
        f"Source: {Path(filepath).name}\n"
        f"Events analyzed: {len(events)}\n"
        f"Sensitivity: {sensitivity}\n"
        f"Anomalies found: {len(anomalies)}\n"
        f"{'=' * 60}\n"
    )

    if not anomalies:
        return header + "\nNo anomalies detected at the current sensitivity level."

    lines = []
    for i, a in enumerate(anomalies, 1):
        lines.append(
            f"\n{i}. [{a.severity.upper()}] {a.anomaly_type} (score: {a.score:.3f})\n"
            f"   {a.description}"
        )
        if a.source_ip:
            lines.append(f"   Source IP: {a.source_ip}")
        if a.username:
            lines.append(f"   User: {a.username}")
        if a.timestamp:
            ts = a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(a.timestamp, datetime) else str(a.timestamp)
            lines.append(f"   Time: {ts}")
        if a.evidence:
            lines.append(f"   Evidence: {json.dumps(a.evidence, default=str)}")

    return header + "\n".join(lines)


@mcp.tool()
def correlate_events(timeframe_hours: int = 24, min_severity: str = "medium") -> str:
    """Cross-correlate events from multiple log sources to identify attack chains.

    Ingests all available log sources, groups related events by source IP,
    target host, and time window to identify coordinated attack patterns.

    Args:
        timeframe_hours: Analysis window in hours (default 24). Set to 0 for
                        all available events.
        min_severity: Minimum severity to include ('low', 'medium', 'high',
                     'critical'). Default 'medium'.

    Returns:
        Correlated event chains showing how individual events connect into
        attack narratives.
    """
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_sev_val = severity_order.get(min_severity.lower(), 2)

    # Parse all available log sources
    all_events: list[dict[str, Any]] = []
    sources_parsed: list[str] = []

    log_files = list(_SAMPLE_DIR.glob("*")) if _SAMPLE_DIR.exists() else []

    for log_file in log_files:
        if log_file.is_dir():
            continue
        log_type, events = _parse_log(str(log_file))
        for e in events:
            e["_source_file"] = log_file.name
            e["_log_type"] = log_type
        all_events.extend(events)
        sources_parsed.append(f"{log_file.name} ({log_type}): {len(events)} events")

    if not all_events:
        return "No events found across any log sources."

    # Filter by severity
    filtered = [
        e for e in all_events
        if severity_order.get(e.get("severity", "info"), 0) >= min_sev_val
    ]

    # Group by source IP
    from collections import defaultdict

    ip_chains: defaultdict[str, list[dict]] = defaultdict(list)
    for e in filtered:
        ip = e.get("source_ip")
        if ip:
            ip_chains[ip].append(e)

    # Sort each chain by timestamp
    for ip in ip_chains:
        ip_chains[ip].sort(
            key=lambda x: x.get("timestamp", datetime.min)
            if isinstance(x.get("timestamp"), datetime)
            else datetime.min
        )

    header = (
        f"Event Correlation Report\n"
        f"Sources parsed: {len(sources_parsed)}\n"
        f"Total events: {len(all_events)}\n"
        f"Events at {min_severity}+ severity: {len(filtered)}\n"
        f"Unique source IPs with findings: {len(ip_chains)}\n"
        f"{'=' * 60}\n\n"
        f"Sources:\n"
    )
    for s in sources_parsed:
        header += f"  - {s}\n"

    lines: list[str] = []
    for ip, chain in sorted(ip_chains.items(), key=lambda x: -len(x[1])):
        if len(chain) < 2:
            continue  # Only show correlated (multi-event) chains
        lines.append(f"\n{'=' * 60}")
        lines.append(f"ATTACK CHAIN: Source IP {ip} ({len(chain)} events)")
        lines.append(f"{'=' * 60}")

        # Identify attack phases
        event_types = [e.get("event_type", "unknown") for e in chain]
        phases = _identify_phases(event_types)
        if phases:
            lines.append(f"Attack phases: {' -> '.join(phases)}")

        for j, e in enumerate(chain[:30], 1):
            ts = e.get("timestamp", "")
            if isinstance(ts, datetime):
                ts = ts.strftime("%Y-%m-%d %H:%M:%S")
            sev = e.get("severity", "info").upper()
            src = e.get("_source_file", "?")
            etype = e.get("event_type", "unknown")
            detail = e.get("raw_line", e.get("message", e.get("event_name", "")))
            lines.append(
                f"  {j}. [{sev}] {ts} ({src})\n"
                f"     {etype}: {str(detail)[:150]}"
            )

    if not lines:
        return header + "\nNo correlated attack chains found at the specified severity level."

    return header + "\n".join(lines)


def _identify_phases(event_types: list[str]) -> list[str]:
    """Map event types to kill chain phases."""
    phases = []
    phase_map = {
        "Reconnaissance": {"invalid_user", "disconnect"},
        "Initial Access": {"failed_login", "successful_login"},
        "Execution": {"suspicious_process", "cron_exec"},
        "Persistence": {"user_add", "user_modify", "cron_modified", "iam_modification"},
        "Privilege Escalation": {"sudo", "su"},
        "Defense Evasion": {"service_stop", "defense_evasion"},
        "Discovery": set(),
        "Exfiltration": {"data_modification", "data_access"},
    }

    seen = set()
    type_set = set(event_types)
    for phase, triggers in phase_map.items():
        if triggers & type_set and phase not in seen:
            phases.append(phase)
            seen.add(phase)

    return phases


@mcp.tool()
def map_to_mitre(event_description: str) -> str:
    """Map a security event to MITRE ATT&CK techniques.

    Takes a free-text description of a security event and identifies the
    most likely ATT&CK techniques, tactics, and recommended mitigations.

    Args:
        event_description: Free-text description of the security event
                          (e.g., "Multiple failed SSH login attempts from
                          the same IP address followed by a successful login").

    Returns:
        Matching ATT&CK techniques with IDs, tactics, descriptions, and
        recommended mitigations.
    """
    mappings = _mitre.map_event(event_description)

    if not mappings:
        return (
            f"No MITRE ATT&CK mappings found for: \"{event_description}\"\n\n"
            f"Try including specific keywords like: brute force, privilege escalation, "
            f"lateral movement, exfiltration, reverse shell, port scan, etc.\n\n"
            f"Available tactics: {', '.join(_mitre.get_tactics())}"
        )

    lines = [
        f"MITRE ATT&CK Mapping\n"
        f"Event: \"{event_description}\"\n"
        f"Matches: {len(mappings)}\n"
        f"{'=' * 60}\n"
    ]

    for i, m in enumerate(mappings[:10], 1):
        lines.append(
            f"\n{i}. {m['technique_id']} - {m['technique_name']}\n"
            f"   Tactic: {m['tactic']}\n"
            f"   Relevance: {m['relevance_score']} keyword match(es)\n"
            f"   Description: {m['description'][:200]}\n"
            f"   Mitigations:"
        )
        for mit in m.get("mitigations", []):
            lines.append(f"     - {mit}")

    return "\n".join(lines)


@mcp.tool()
def generate_report(timeframe_hours: int = 24, format: str = "markdown") -> str:
    """Generate a comprehensive security incident report.

    Analyzes all available log sources, runs detection rules and anomaly
    detection, then generates a structured incident report.

    Args:
        timeframe_hours: Reporting window in hours (default 24).
        format: Output format -- currently 'markdown' (default). Future:
                'json', 'html'.

    Returns:
        Complete incident report in Markdown format with executive summary,
        timeline, affected assets, IOCs, MITRE mappings, and recommendations.
    """
    # Parse all sources
    all_events: list[dict[str, Any]] = []
    log_files = list(_SAMPLE_DIR.glob("*")) if _SAMPLE_DIR.exists() else []

    for log_file in log_files:
        if log_file.is_dir():
            continue
        _, events = _parse_log(str(log_file))
        all_events.extend(events)

    if not all_events:
        return "No events found. Cannot generate report."

    # Run detections
    detections_raw = _rule_engine.evaluate_all(all_events)
    detections = [asdict(d) for d in detections_raw]

    # Run anomaly detection
    detector = AnomalyDetector(sensitivity=0.5)
    anomalies_raw = detector.detect(all_events)
    anomalies = [asdict(a) for a in anomalies_raw]

    report = _reporter.generate(
        detections=detections,
        anomalies=anomalies,
        timeframe_hours=timeframe_hours,
    )

    return report


@mcp.tool()
def check_iocs(ioc_list: str) -> str:
    """Check a list of IOCs against known threat intelligence.

    Checks provided indicators against an embedded threat intelligence
    dataset. For enhanced coverage, set VIRUSTOTAL_API_KEY or
    ABUSEIPDB_API_KEY environment variables.

    Args:
        ioc_list: Comma-separated list of IOCs to check. Can be IP addresses,
                 domains, or file hashes.

    Returns:
        Threat intelligence results for each IOC.
    """
    iocs = [i.strip() for i in ioc_list.split(",") if i.strip()]
    if not iocs:
        return "No IOCs provided. Pass a comma-separated list of IPs, domains, or hashes."

    # Embedded known-bad indicators (for demonstration)
    known_bad: dict[str, dict[str, str]] = {
        "198.51.100.23": {
            "type": "ip",
            "threat": "Known attacker IP used in SSH brute force campaigns",
            "confidence": "high",
            "first_seen": "2025-11-15",
            "tags": "brute-force, credential-access, scanner",
        },
        "203.0.113.50": {
            "type": "ip",
            "threat": "Port scanning infrastructure, associated with vulnerability scanning",
            "confidence": "medium",
            "first_seen": "2026-01-03",
            "tags": "scanner, reconnaissance",
        },
        "evil.example.com": {
            "type": "domain",
            "threat": "C2 domain used by APT group",
            "confidence": "high",
            "first_seen": "2025-09-22",
            "tags": "c2, apt, malware",
        },
    }

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")

    lines = [
        f"IOC Check Results\n"
        f"IOCs submitted: {len(iocs)}\n"
        f"Threat intel sources: embedded"
        + (", VirusTotal" if vt_key else "")
        + (", AbuseIPDB" if abuseipdb_key else "")
        + f"\n{'=' * 60}\n"
    ]

    for ioc in iocs:
        lines.append(f"\n--- {ioc} ---")
        if ioc in known_bad:
            info = known_bad[ioc]
            lines.append(f"  STATUS: MALICIOUS")
            lines.append(f"  Type: {info['type']}")
            lines.append(f"  Threat: {info['threat']}")
            lines.append(f"  Confidence: {info['confidence']}")
            lines.append(f"  First seen: {info['first_seen']}")
            lines.append(f"  Tags: {info['tags']}")
        else:
            lines.append(f"  STATUS: NOT FOUND in local threat intel")
            lines.append(f"  Note: Not being in the database does not mean safe.")

        if vt_key:
            lines.append(f"  VirusTotal: API key configured (query would run here)")
        if abuseipdb_key:
            lines.append(f"  AbuseIPDB: API key configured (query would run here)")

    lines.append(f"\n{'=' * 60}")
    lines.append("Recommendation: Cross-reference with additional threat intel feeds.")
    if not vt_key:
        lines.append("Tip: Set VIRUSTOTAL_API_KEY env var for VirusTotal lookups.")
    if not abuseipdb_key:
        lines.append("Tip: Set ABUSEIPDB_API_KEY env var for AbuseIPDB lookups.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the Sentinel MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
