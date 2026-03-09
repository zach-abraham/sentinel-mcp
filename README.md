# sentinel-mcp

![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![MCP Compatible](https://img.shields.io/badge/MCP-compatible-purple.svg)

**Turn Claude into an autonomous SOC analyst.**

An MCP (Model Context Protocol) server that gives Claude the ability to ingest security logs, detect anomalies using machine learning, correlate events across sources, map findings to MITRE ATT&CK, and generate incident reports -- all without leaving the chat.

---

## Tools

| Tool | Description |
|------|-------------|
| `analyze_logs` | Parse and analyze a log file for security events. Supports auth.log, syslog, firewall (UFW/iptables), and AWS CloudTrail JSON. Returns severity breakdown, event classification, and rule-based detections. |
| `hunt_threat` | Search across all ingested log sources for a specific IOC (IP, domain, hash, username). Returns every match with timestamp and context. |
| `detect_anomalies` | Run Isolation Forest and statistical anomaly detection. Finds unusual login hours, new IPs, brute force spikes, volume anomalies, and multivariate behavioral outliers. |
| `correlate_events` | Cross-correlate events from multiple log sources by source IP, target host, and time window. Identifies attack chains and maps them to kill chain phases. |
| `map_to_mitre` | Map a free-text security event description to MITRE ATT&CK techniques. Returns technique IDs, tactics, descriptions, and recommended mitigations. |
| `generate_report` | Produce a full Markdown incident report: executive summary, severity assessment, timeline, affected assets, IOCs, MITRE mapping table, and recommended response actions. |
| `check_iocs` | Check a list of IOCs against embedded threat intelligence. Optionally integrates with VirusTotal and AbuseIPDB when API keys are set. |

---

## Quick Start

### Install

```bash
git clone https://github.com/yourusername/sentinel-mcp.git
cd sentinel-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Configure in Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sentinel-mcp": {
      "command": "/path/to/sentinel-mcp/.venv/bin/sentinel-mcp"
    }
  }
}
```

### Configure in Claude Code

```bash
claude mcp add sentinel-mcp /path/to/sentinel-mcp/.venv/bin/sentinel-mcp
```

### Run Standalone

```bash
sentinel-mcp
```

---

## Example Usage

Once configured, Claude can act as your SOC analyst:

**Analyze authentication logs for threats:**
> "Analyze the auth logs from the last 24 hours. Are there any brute force attempts?"

**Hunt for a suspicious IP across all sources:**
> "Hunt for IP 198.51.100.23 across all available logs."

**Run anomaly detection with high sensitivity:**
> "Run anomaly detection on the auth logs with sensitivity 0.8."

**Correlate events into attack chains:**
> "Correlate all events from the last 48 hours. Show me any attack chains."

**Map an event to MITRE ATT&CK:**
> "Map this to MITRE: Multiple failed SSH logins followed by a successful login and immediate sudo to root."

**Generate an incident report:**
> "Generate a full incident report for the last 24 hours."

**Check indicators of compromise:**
> "Check these IOCs: 198.51.100.23, 203.0.113.50, evil.example.com"

---

## Architecture

```
                          Claude (LLM)
                               |
                          MCP Protocol
                               |
                    +----------+-----------+
                    |   sentinel-mcp       |
                    |   (FastMCP Server)   |
                    +----------+-----------+
                               |
          +--------------------+--------------------+
          |                    |                    |
    +-----+------+     +------+------+     +-------+------+
    |  Parsers   |     |  Detectors  |     |   Analysis   |
    +-----+------+     +------+------+     +-------+------+
    | auth.py    |     | anomaly.py  |     | mitre.py     |
    | syslog.py  |     |  (Isolation |     |  (ATT&CK     |
    | firewall.py|     |   Forest)   |     |   mapping)   |
    | cloudtrail |     | rules.py    |     | reporter.py  |
    | generic.py |     |  (20 rules) |     |  (Markdown   |
    +------------+     +-------------+     |   reports)   |
                                           +--------------+
          |
    +-----+------+
    | Log Sources |
    +-----+------+
    | auth.log   |     Syslog, firewall, CloudTrail,
    | syslog.log |     or any text-based log format
    | *.json     |
    +------------+
```

### Data Flow

1. **Ingestion** -- Parsers normalize raw logs into structured event objects with typed fields (timestamp, source IP, event type, severity).
2. **Detection** -- The rule engine (20 Sigma-inspired rules) and Isolation Forest anomaly detector independently evaluate the event stream.
3. **Correlation** -- Events are grouped by source IP and time window to reconstruct attack chains and map them to kill chain phases.
4. **Mapping** -- Findings are mapped to MITRE ATT&CK techniques via keyword-indexed lookup across 20+ techniques and 10 tactics.
5. **Reporting** -- All findings are synthesized into a structured incident report with executive summary, timeline, IOCs, MITRE table, and response recommendations.

---

## Detection Capabilities

### Rule Engine (20 Built-in Rules)

| ID | Rule | Severity | MITRE Technique |
|----|------|----------|-----------------|
| RULE-001 | SSH Brute Force (5+ failures in 5 min) | HIGH | T1110.001 |
| RULE-002 | Successful Login After Brute Force | CRITICAL | T1110 |
| RULE-003 | Privilege Escalation to Root | HIGH | T1548.003 |
| RULE-004 | Unauthorized Sudo Usage | HIGH | T1548.003 |
| RULE-005 | New User Account Created | HIGH | T1136 |
| RULE-006 | User Added to Admin Group | CRITICAL | T1098 |
| RULE-007 | Port Scan (20+ unique ports) | HIGH | T1046 |
| RULE-008 | Large Outbound Transfer (>100MB) | HIGH | T1048 |
| RULE-009 | Critical Service Stopped | HIGH | T1562.001 |
| RULE-010 | Crontab Modification | HIGH | T1053.003 |
| RULE-011 | Suspicious Process Execution | CRITICAL | T1059 |
| RULE-012 | IAM Policy Modification | HIGH | T1098 |
| RULE-013 | CloudTrail Logging Disabled | CRITICAL | T1562.008 |
| RULE-014 | S3 Bucket Made Public | CRITICAL | T1530 |
| RULE-015 | AWS Root Account Usage | CRITICAL | T1078.004 |
| RULE-016 | Security Group Opened to 0.0.0.0/0 | CRITICAL | T1562.007 |
| RULE-017 | Credential Stuffing (5+ usernames) | HIGH | T1110.004 |
| RULE-018 | Impossible Travel | HIGH | T1078 |
| RULE-019 | Password Spray | HIGH | T1110.003 |
| RULE-020 | Reverse Shell Indicator | CRITICAL | T1059 |

### Anomaly Detection (ML-Based)

| Method | What It Finds |
|--------|--------------|
| Unusual Hour Detection | Logins outside business hours (configurable by sensitivity) |
| New IP Detection | Source IPs appearing only in the latter half of logs |
| Brute Force Detection | Failed authentication rate spikes within sliding time windows |
| Volume Spike Detection | Hourly event counts exceeding statistical thresholds (z-score) |
| Isolation Forest | Multivariate behavioral anomalies across hour, event type, IP frequency, and failure indicators |

---

## MITRE ATT&CK Coverage

The embedded technique database covers 20+ techniques across these tactics:

| Tactic | Example Techniques |
|--------|--------------------|
| Initial Access | T1078 Valid Accounts, T1190 Exploit Public-Facing App, T1133 External Remote Services |
| Execution | T1059 Command and Scripting Interpreter |
| Persistence | T1136 Create Account, T1098 Account Manipulation, T1053 Scheduled Task, T1505 Server Software Component |
| Privilege Escalation | T1548 Abuse Elevation Control, T1078.004 Cloud Accounts |
| Defense Evasion | T1562 Impair Defenses, T1027 Obfuscated Files, T1070 Indicator Removal |
| Credential Access | T1110 Brute Force, T1003 OS Credential Dumping |
| Discovery | T1046 Network Service Discovery |
| Lateral Movement | T1021 Remote Services |
| Collection | T1530 Data from Cloud Storage |
| Exfiltration | T1048 Exfiltration Over Alternative Protocol |
| Command and Control | T1071 Application Layer Protocol, T1105 Ingress Tool Transfer |

---

## Sample Attack Scenario

The included sample data (`data/sample_logs/`) contains a realistic multi-stage attack:

1. **Reconnaissance** (firewall.log) -- Port scan of 25 common service ports from 198.51.100.23
2. **Initial Access** (auth.log) -- SSH brute force with 12+ failed attempts across 8 usernames
3. **Credential Access** (auth.log) -- Successful login with compromised `deploy` credentials
4. **Privilege Escalation** (auth.log) -- `sudo /bin/bash` to root
5. **Persistence** (auth.log, syslog) -- New user `svc_backup` created, added to sudo group, crontab modified
6. **Defense Evasion** (syslog, cloudtrail.json) -- Fail2Ban stopped, rsyslog stopped, CloudTrail logging disabled
7. **Cloud Exploitation** (cloudtrail.json) -- IAM user created with AdministratorAccess, S3 bucket made public, security group opened to 0.0.0.0/0
8. **Execution** (auth.log, syslog) -- Reverse shell via netcat to attacker C2

Running `generate_report` against this sample data produces a comprehensive incident report identifying all eight phases.

---

## Configuration

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `SENTINEL_LOG_DIRS` | Colon-separated list of additional log directories to search during threat hunts |
| `VIRUSTOTAL_API_KEY` | Enable VirusTotal lookups in `check_iocs` |
| `ABUSEIPDB_API_KEY` | Enable AbuseIPDB lookups in `check_iocs` |

### Extending

**Custom log parsers:** Subclass the generic parser or add new parsers to `src/sentinel_mcp/parsers/`.

**Custom detection rules:** Add rules to the `_build_rules()` method in `src/sentinel_mcp/detectors/rules.py`. Each rule is a function that takes a list of event dicts and returns Detection objects.

**Additional MITRE techniques:** Add entries to `data/mitre_attack.json` following the existing schema. The mapper loads external JSON and merges it with the built-in database.

---

## Testing

```bash
python -m pytest tests/ -v
```

77 tests covering parsers, detectors, MITRE mapping, report generation, and all MCP tool functions.

---

## Why This Matters

This project demonstrates practical application of several security engineering disciplines:

| Skill | Implementation |
|-------|----------------|
| **Log Analysis & SIEM Engineering** | Five format-specific parsers handling auth.log, syslog, iptables/UFW, CloudTrail JSON, and generic text logs. Regex-based extraction with graceful handling of malformed input. |
| **Threat Detection Engineering** | 20 detection rules modeled after Sigma rule format, covering credential attacks, privilege escalation, persistence, defense evasion, and cloud security misconfigurations. |
| **Machine Learning for Security** | Isolation Forest anomaly detection with configurable sensitivity, combined with statistical methods (z-score volume analysis, sliding window brute force detection). |
| **MITRE ATT&CK Framework** | Keyword-indexed technique database covering 20+ techniques across 11 tactics. Automated mapping from raw events to technique IDs with mitigation recommendations. |
| **Incident Response** | Automated report generation following IR best practices: executive summary, timeline reconstruction, IOC extraction, affected asset enumeration, and prioritized response actions. |
| **Attack Chain Correlation** | Cross-source event correlation that groups events by source IP and time window, then maps event sequences to kill chain phases (reconnaissance through exfiltration). |
| **Cloud Security** | CloudTrail log analysis detecting IAM abuse, S3 exposure, security group misconfigurations, logging tampering, and root account usage. |
| **MCP/Tool-Use Integration** | Clean implementation of the Model Context Protocol, enabling an LLM to autonomously investigate security incidents using structured tools. |

---

## License

MIT
