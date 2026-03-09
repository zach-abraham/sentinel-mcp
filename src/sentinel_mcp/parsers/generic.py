"""Generic log parser with configurable regex-based pattern matching."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class GenericLogEvent:
    """A parsed generic log event."""

    timestamp: Optional[datetime]
    message: str
    source: str
    event_type: str = "unknown"
    severity: str = "info"
    raw_line: str = ""
    matched_pattern: Optional[str] = None
    extra: dict = field(default_factory=dict)


# Common timestamp formats
_TIMESTAMP_PATTERNS = [
    # ISO 8601: 2026-03-09T14:23:01Z or 2026-03-09T14:23:01+00:00
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"), "%Y-%m-%dT%H:%M:%S"),
    # Syslog: Mar  9 14:23:01
    (re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    # Common log format: 09/Mar/2026:14:23:01
    (re.compile(r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"), "%d/%b/%Y:%H:%M:%S"),
    # YYYY-MM-DD HH:MM:SS
    (re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S"),
]

# Security-relevant patterns (name, regex, severity)
_SECURITY_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("sql_injection", re.compile(
        r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE|;\s*DELETE|--\s*$|'\s*OR\s+')",
        re.IGNORECASE,
    ), "critical"),
    ("xss_attempt", re.compile(
        r"<script[^>]*>|javascript:|onerror\s*=|onload\s*=",
        re.IGNORECASE,
    ), "high"),
    ("path_traversal", re.compile(r"\.\./\.\./|%2e%2e%2f|\.\.\\", re.IGNORECASE), "high"),
    ("command_injection", re.compile(
        r";\s*(?:cat|ls|whoami|id|uname|wget|curl|nc|bash|sh|python)\s",
        re.IGNORECASE,
    ), "critical"),
    ("failed_auth", re.compile(
        r"(?:authentication fail|login fail|invalid password|access denied|unauthorized)",
        re.IGNORECASE,
    ), "medium"),
    ("brute_force", re.compile(
        r"(?:too many|rate limit|blocked|banned|locked out|max.* attempt)",
        re.IGNORECASE,
    ), "high"),
    ("privilege_escalation", re.compile(
        r"(?:sudo|su\s|privilege|escalat|root access|admin access)",
        re.IGNORECASE,
    ), "high"),
    ("data_exfiltration", re.compile(
        r"(?:large transfer|bulk download|export.*data|dump.*database)",
        re.IGNORECASE,
    ), "high"),
    ("malware_indicator", re.compile(
        r"(?:malware|trojan|ransomware|cryptominer|backdoor|rootkit|c2|command.and.control)",
        re.IGNORECASE,
    ), "critical"),
    ("error", re.compile(r"(?:ERROR|FATAL|CRITICAL|PANIC)", re.IGNORECASE), "medium"),
    ("warning", re.compile(r"(?:WARNING|WARN)", re.IGNORECASE), "low"),
]


class GenericLogParser:
    """Generic regex-based log parser that works with any text log format.

    Extracts timestamps (multiple formats), classifies events by pattern
    matching, and flags security-relevant entries.
    """

    def __init__(
        self,
        source_name: str = "generic",
        custom_patterns: Optional[list[tuple[str, str, str]]] = None,
        year: Optional[int] = None,
    ) -> None:
        self.source_name = source_name
        self.year = year or datetime.now().year
        self.patterns = list(_SECURITY_PATTERNS)

        if custom_patterns:
            for name, regex_str, severity in custom_patterns:
                self.patterns.append((name, re.compile(regex_str, re.IGNORECASE), severity))

    def parse_line(self, line: str) -> Optional[GenericLogEvent]:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None

        ts = self._extract_timestamp(line)
        event_type, severity, matched = self._classify(line)

        return GenericLogEvent(
            timestamp=ts,
            message=line,
            source=self.source_name,
            event_type=event_type,
            severity=severity,
            raw_line=line,
            matched_pattern=matched,
        )

    def parse_file(self, filepath: str) -> list[GenericLogEvent]:
        """Parse an entire log file."""
        events: list[GenericLogEvent] = []
        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    event = self.parse_line(line)
                    if event is not None:
                        events.append(event)
        except (OSError, IOError):
            pass
        return events

    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        """Try to extract a timestamp from the line using known formats."""
        for pattern, fmt in _TIMESTAMP_PATTERNS:
            m = pattern.search(line)
            if m:
                ts_str = m.group(1)
                try:
                    ts = datetime.strptime(ts_str, fmt)
                    # If format lacks year, add current year
                    if ts.year == 1900:
                        ts = ts.replace(year=self.year)
                    return ts
                except ValueError:
                    continue
        return None

    def _classify(self, line: str) -> tuple[str, str, Optional[str]]:
        """Classify line by matching against security patterns.

        Returns (event_type, severity, matched_pattern_name).
        """
        # Check patterns in order (most severe first by construction)
        for name, pattern, severity in self.patterns:
            if pattern.search(line):
                return name, severity, name
        return "info", "info", None
