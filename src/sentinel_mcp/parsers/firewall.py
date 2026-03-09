"""Parser for firewall logs (iptables, UFW, pf)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class FirewallEvent:
    """A parsed firewall log event."""

    timestamp: datetime
    hostname: str
    action: str  # blocked, allowed, dropped, rejected
    protocol: str  # TCP, UDP, ICMP
    source_ip: str
    source_port: Optional[int]
    dest_ip: str
    dest_port: Optional[int]
    interface_in: Optional[str] = None
    interface_out: Optional[str] = None
    raw_line: str = ""
    severity: str = "info"
    extra: dict = field(default_factory=dict)


_TIMESTAMP_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
)

# iptables / netfilter kernel log
_IPTABLES = re.compile(
    r"(?:IN=(\S*)\s+OUT=(\S*)\s+)?.*?"
    r"SRC=([\d.]+)\s+DST=([\d.]+)\s+.*?"
    r"PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?"
)

# UFW log format
_UFW = re.compile(
    r"\[UFW\s+(BLOCK|ALLOW|AUDIT)\]\s+"
    r"IN=(\S*)\s+OUT=(\S*)\s+.*?"
    r"SRC=([\d.]+)\s+DST=([\d.]+)\s+.*?"
    r"PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?"
)

# Generic blocked/allowed pattern
_GENERIC_FW = re.compile(
    r"(BLOCK|DROP|REJECT|ALLOW|ACCEPT|DENIED)\s+.*?"
    r"(?:src|from|SRC)[=:\s]*([\d.]+).*?"
    r"(?:dst|to|DST)[=:\s]*([\d.]+).*?"
    r"(?:proto|PROTO)[=:\s]*(\S+)",
    re.IGNORECASE,
)


class FirewallLogParser:
    """Parse firewall logs (iptables, UFW, pf, generic)."""

    def __init__(self, year: Optional[int] = None) -> None:
        self.year = year or datetime.now().year

    def parse_line(self, line: str) -> Optional[FirewallEvent]:
        """Parse a single firewall log line."""
        line = line.strip()
        if not line:
            return None

        # Extract timestamp and hostname
        ts_match = _TIMESTAMP_RE.match(line)
        if not ts_match:
            return None

        ts_str, hostname = ts_match.groups()
        try:
            ts = datetime.strptime(f"{self.year} {ts_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None

        # Try UFW format first (more specific)
        event = self._try_ufw(line, ts, hostname)
        if event:
            return event

        # Try iptables format
        event = self._try_iptables(line, ts, hostname)
        if event:
            return event

        # Try generic format
        event = self._try_generic(line, ts, hostname)
        return event

    def parse_file(self, filepath: str) -> list[FirewallEvent]:
        """Parse an entire firewall log file."""
        events: list[FirewallEvent] = []
        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    event = self.parse_line(line)
                    if event is not None:
                        events.append(event)
        except (OSError, IOError):
            pass
        return events

    def _try_ufw(
        self, line: str, ts: datetime, hostname: str
    ) -> Optional[FirewallEvent]:
        m = _UFW.search(line)
        if not m:
            return None
        action_raw = m.group(1).lower()
        action = "blocked" if action_raw == "block" else "allowed"
        severity = "medium" if action == "blocked" else "low"
        return FirewallEvent(
            timestamp=ts,
            hostname=hostname,
            action=action,
            protocol=m.group(6).upper(),
            source_ip=m.group(4),
            source_port=int(m.group(7)) if m.group(7) else None,
            dest_ip=m.group(5),
            dest_port=int(m.group(8)) if m.group(8) else None,
            interface_in=m.group(2) or None,
            interface_out=m.group(3) or None,
            raw_line=line,
            severity=severity,
        )

    def _try_iptables(
        self, line: str, ts: datetime, hostname: str
    ) -> Optional[FirewallEvent]:
        m = _IPTABLES.search(line)
        if not m:
            return None
        # Determine action from keywords in line
        lower = line.lower()
        if any(w in lower for w in ("drop", "block", "denied", "reject")):
            action = "blocked"
            severity = "medium"
        elif any(w in lower for w in ("accept", "allow")):
            action = "allowed"
            severity = "low"
        else:
            action = "blocked"
            severity = "medium"

        return FirewallEvent(
            timestamp=ts,
            hostname=hostname,
            action=action,
            protocol=m.group(5).upper(),
            source_ip=m.group(3),
            source_port=int(m.group(6)) if m.group(6) else None,
            dest_ip=m.group(4),
            dest_port=int(m.group(7)) if m.group(7) else None,
            interface_in=m.group(1) or None,
            interface_out=m.group(2) or None,
            raw_line=line,
            severity=severity,
        )

    def _try_generic(
        self, line: str, ts: datetime, hostname: str
    ) -> Optional[FirewallEvent]:
        m = _GENERIC_FW.search(line)
        if not m:
            return None
        action_raw = m.group(1).upper()
        if action_raw in ("BLOCK", "DROP", "REJECT", "DENIED"):
            action = "blocked"
            severity = "medium"
        else:
            action = "allowed"
            severity = "low"

        return FirewallEvent(
            timestamp=ts,
            hostname=hostname,
            action=action,
            protocol=m.group(4).upper(),
            source_ip=m.group(2),
            source_port=None,
            dest_ip=m.group(3),
            dest_port=None,
            raw_line=line,
            severity=severity,
        )
