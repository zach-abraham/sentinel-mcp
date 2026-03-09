"""MITRE ATT&CK technique mapping and lookup."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

# Embedded ATT&CK techniques database -- loaded from JSON file if available,
# otherwise uses this built-in subset covering the most common SOC detections.
_BUILTIN_TECHNIQUES: list[dict] = [
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "sub_techniques": [
            {"id": "T1110.001", "name": "Password Guessing"},
            {"id": "T1110.002", "name": "Password Cracking"},
            {"id": "T1110.003", "name": "Password Spraying"},
            {"id": "T1110.004", "name": "Credential Stuffing"},
        ],
        "mitigations": [
            "Account lockout policies",
            "Multi-factor authentication",
            "Password complexity requirements",
            "Rate limiting on authentication endpoints",
        ],
        "detection_keywords": ["brute force", "failed login", "authentication failure", "invalid password", "credential stuffing"],
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "sub_techniques": [
            {"id": "T1078.001", "name": "Default Accounts"},
            {"id": "T1078.002", "name": "Domain Accounts"},
            {"id": "T1078.003", "name": "Local Accounts"},
            {"id": "T1078.004", "name": "Cloud Accounts"},
        ],
        "mitigations": [
            "Application developer guidance",
            "Password policies",
            "Privileged account management",
            "User training",
        ],
        "detection_keywords": ["valid account", "compromised credential", "account login", "impossible travel", "unusual login"],
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "sub_techniques": [
            {"id": "T1059.001", "name": "PowerShell"},
            {"id": "T1059.003", "name": "Windows Command Shell"},
            {"id": "T1059.004", "name": "Unix Shell"},
            {"id": "T1059.006", "name": "Python"},
        ],
        "mitigations": [
            "Code signing",
            "Disable or remove feature or program",
            "Execution prevention",
            "Antivirus/Antimalware",
        ],
        "detection_keywords": ["reverse shell", "command execution", "script execution", "bash -i", "nc -e", "suspicious process"],
    },
    {
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic": "Persistence",
        "description": "Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access.",
        "sub_techniques": [
            {"id": "T1136.001", "name": "Local Account"},
            {"id": "T1136.002", "name": "Domain Account"},
            {"id": "T1136.003", "name": "Cloud Account"},
        ],
        "mitigations": [
            "Multi-factor authentication",
            "Network segmentation",
            "Privileged account management",
            "Operating system configuration",
        ],
        "detection_keywords": ["user create", "new user", "useradd", "adduser", "CreateUser", "account creation"],
    },
    {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account.",
        "sub_techniques": [
            {"id": "T1098.001", "name": "Additional Cloud Credentials"},
            {"id": "T1098.003", "name": "Additional Cloud Roles"},
        ],
        "mitigations": [
            "Multi-factor authentication",
            "Network segmentation",
            "Privileged account management",
        ],
        "detection_keywords": ["account manipulation", "group add", "policy attach", "IAM change", "permission change", "admin group"],
    },
    {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions.",
        "sub_techniques": [
            {"id": "T1548.001", "name": "Setuid and Setgid"},
            {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
        ],
        "mitigations": [
            "Audit",
            "Execution prevention",
            "Operating system configuration",
            "Privileged account management",
            "Restrict file and directory permissions",
        ],
        "detection_keywords": ["privilege escalation", "sudo", "su root", "setuid", "elevation"],
    },
    {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.",
        "sub_techniques": [],
        "mitigations": [
            "Disable or remove feature or program",
            "Network intrusion prevention",
            "Network segmentation",
        ],
        "detection_keywords": ["port scan", "network scan", "service discovery", "nmap", "reconnaissance"],
    },
    {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.",
        "sub_techniques": [
            {"id": "T1048.001", "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol"},
            {"id": "T1048.002", "name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"},
            {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2 Protocol"},
        ],
        "mitigations": [
            "Data loss prevention",
            "Filter network traffic",
            "Network segmentation",
        ],
        "detection_keywords": ["exfiltration", "data transfer", "large upload", "outbound transfer", "data theft"],
    },
    {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        "sub_techniques": [
            {"id": "T1053.003", "name": "Cron"},
            {"id": "T1053.005", "name": "Scheduled Task"},
        ],
        "mitigations": [
            "Audit",
            "Operating system configuration",
            "Privileged account management",
            "User account management",
        ],
        "detection_keywords": ["crontab", "cron job", "scheduled task", "at job", "persistence mechanism"],
    },
    {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms.",
        "sub_techniques": [
            {"id": "T1562.001", "name": "Disable or Modify Tools"},
            {"id": "T1562.002", "name": "Disable Windows Event Logging"},
            {"id": "T1562.004", "name": "Disable or Modify System Firewall"},
            {"id": "T1562.007", "name": "Disable or Modify Cloud Firewall"},
            {"id": "T1562.008", "name": "Disable Cloud Logs"},
        ],
        "mitigations": [
            "Restrict file and directory permissions",
            "Restrict registry permissions",
            "User account management",
        ],
        "detection_keywords": ["disable logging", "stop service", "kill process", "impair defense", "CloudTrail stop", "firewall disable"],
    },
    {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": "Adversaries may access data from improperly secured cloud storage. Many cloud storage services allow for the storage of data in configurations that are accessible to external parties.",
        "sub_techniques": [],
        "mitigations": [
            "Audit",
            "Encrypt sensitive information",
            "Filter network traffic",
            "Multi-factor authentication",
            "Restrict file and directory permissions",
            "User account management",
        ],
        "detection_keywords": ["S3 public", "bucket policy", "cloud storage", "public access", "S3 ACL"],
    },
    {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as SSH, RDP, or VNC.",
        "sub_techniques": [
            {"id": "T1021.001", "name": "Remote Desktop Protocol"},
            {"id": "T1021.004", "name": "SSH"},
        ],
        "mitigations": [
            "Disable or remove feature or program",
            "Limit access to resource over network",
            "Multi-factor authentication",
            "Network segmentation",
        ],
        "detection_keywords": ["lateral movement", "SSH login", "RDP", "remote service", "remote access"],
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
        "sub_techniques": [],
        "mitigations": [
            "Application isolation and sandboxing",
            "Exploit protection",
            "Network segmentation",
            "Privileged account management",
            "Update software",
            "Vulnerability scanning",
        ],
        "detection_keywords": ["exploit", "SQL injection", "XSS", "command injection", "path traversal", "web attack"],
    },
    {
        "technique_id": "T1133",
        "technique_name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network.",
        "sub_techniques": [],
        "mitigations": [
            "Disable or remove feature or program",
            "Limit access to resource over network",
            "Multi-factor authentication",
            "Network segmentation",
        ],
        "detection_keywords": ["external remote", "VPN", "remote service", "external access"],
    },
    {
        "technique_id": "T1505",
        "technique_name": "Server Software Component",
        "tactic": "Persistence",
        "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems.",
        "sub_techniques": [
            {"id": "T1505.003", "name": "Web Shell"},
        ],
        "mitigations": [
            "Audit",
            "Code signing",
            "Disable or remove feature or program",
            "Privileged account management",
        ],
        "detection_keywords": ["web shell", "webshell", "backdoor", "persistent access"],
    },
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
        "sub_techniques": [
            {"id": "T1071.001", "name": "Web Protocols"},
            {"id": "T1071.004", "name": "DNS"},
        ],
        "mitigations": [
            "Filter network traffic",
            "Network intrusion prevention",
        ],
        "detection_keywords": ["C2", "command and control", "beaconing", "DNS tunnel", "covert channel"],
    },
    {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.",
        "sub_techniques": [
            {"id": "T1027.001", "name": "Binary Padding"},
            {"id": "T1027.005", "name": "Indicator Removal from Tools"},
        ],
        "mitigations": [
            "Antivirus/Antimalware",
            "Behavior prevention on endpoint",
        ],
        "detection_keywords": ["obfuscated", "encoded", "base64", "encrypted payload"],
    },
    {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.",
        "sub_techniques": [
            {"id": "T1003.001", "name": "LSASS Memory"},
            {"id": "T1003.008", "name": "/etc/passwd and /etc/shadow"},
        ],
        "mitigations": [
            "Active directory configuration",
            "Credential access protection",
            "Operating system configuration",
            "Password policies",
            "Privileged account management",
            "Privileged process integrity",
            "User training",
        ],
        "detection_keywords": ["credential dump", "mimikatz", "hashdump", "shadow file", "password dump"],
    },
    {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses.",
        "sub_techniques": [
            {"id": "T1070.001", "name": "Clear Windows Event Logs"},
            {"id": "T1070.002", "name": "Clear Linux or Mac System Logs"},
            {"id": "T1070.003", "name": "Clear Command History"},
            {"id": "T1070.004", "name": "File Deletion"},
        ],
        "mitigations": [
            "Encrypt sensitive information",
            "Remote data storage",
            "Restrict file and directory permissions",
        ],
        "detection_keywords": ["log clear", "log delete", "history clear", "evidence removal", "indicator removal"],
    },
    {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
        "sub_techniques": [],
        "mitigations": [
            "Network intrusion prevention",
        ],
        "detection_keywords": ["wget", "curl download", "tool transfer", "file download", "ingress"],
    },
]


class MitreMapper:
    """Map security events to MITRE ATT&CK techniques."""

    def __init__(self, database_path: Optional[str] = None) -> None:
        """Initialize with optional external JSON database."""
        self.techniques: dict[str, dict] = {}
        self._keyword_index: dict[str, list[str]] = {}

        # Try loading external database
        if database_path and os.path.exists(database_path):
            try:
                with open(database_path) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for t in data:
                        self.techniques[t["technique_id"]] = t
                elif isinstance(data, dict) and "techniques" in data:
                    for t in data["techniques"]:
                        self.techniques[t["technique_id"]] = t
            except (json.JSONDecodeError, KeyError, TypeError):
                pass

        # Fall back to / supplement with built-in techniques
        for t in _BUILTIN_TECHNIQUES:
            if t["technique_id"] not in self.techniques:
                self.techniques[t["technique_id"]] = t

        # Build keyword index
        self._build_keyword_index()

    def _build_keyword_index(self) -> None:
        """Build reverse index from keywords to technique IDs."""
        for tid, tech in self.techniques.items():
            for kw in tech.get("detection_keywords", []):
                kw_lower = kw.lower()
                if kw_lower not in self._keyword_index:
                    self._keyword_index[kw_lower] = []
                self._keyword_index[kw_lower].append(tid)

    def lookup(self, technique_id: str) -> Optional[dict]:
        """Look up a technique by its ID (e.g., T1110, T1110.001)."""
        # Try exact match
        if technique_id in self.techniques:
            return self.techniques[technique_id]
        # Try parent technique for sub-techniques
        parent = technique_id.split(".")[0]
        return self.techniques.get(parent)

    def map_event(self, event_description: str) -> list[dict]:
        """Map a free-text event description to matching ATT&CK techniques.

        Returns a list of technique dicts sorted by relevance (keyword match count).
        """
        desc_lower = event_description.lower()
        scores: dict[str, int] = {}

        for keyword, tech_ids in self._keyword_index.items():
            if keyword in desc_lower:
                for tid in tech_ids:
                    scores[tid] = scores.get(tid, 0) + 1

        # Sort by match score descending
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        results = []
        for tid, score in ranked:
            tech = self.techniques[tid]
            results.append({
                "technique_id": tid,
                "technique_name": tech["technique_name"],
                "tactic": tech["tactic"],
                "description": tech["description"],
                "mitigations": tech.get("mitigations", []),
                "relevance_score": score,
            })
        return results

    def get_all_techniques(self) -> list[dict]:
        """Return all techniques in the database."""
        return [
            {
                "technique_id": t["technique_id"],
                "technique_name": t["technique_name"],
                "tactic": t["tactic"],
                "description": t["description"][:100] + "..." if len(t["description"]) > 100 else t["description"],
            }
            for t in self.techniques.values()
        ]

    def get_tactics(self) -> list[str]:
        """Return all unique tactics covered."""
        return sorted({t["tactic"] for t in self.techniques.values()})
