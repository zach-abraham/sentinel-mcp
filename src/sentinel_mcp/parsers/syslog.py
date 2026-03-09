"""Parser for syslog entries."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class SyslogEvent:
    """A parsed syslog event."""

    timestamp: datetime
    hostname: str
    service: str
    pid: Optional[int]
    message: str
    event_type: str  # service_start, service_stop, kernel, cron, process, error, warning, info
    severity: str = "info"
    raw_line: str = ""
    extra: dict = field(default_factory=dict)


_TIMESTAMP_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)"
)

# Suspicious patterns
_CRON_EDIT = re.compile(r"(?:REPLACE|EDIT)\s+\((\S+)\)", re.IGNORECASE)
_SERVICE_ACTION = re.compile(
    r"(?:start|stop|restart|reload)(?:ed|ing)?\s+(\S+)", re.IGNORECASE
)
_KERNEL_SEGFAULT = re.compile(r"segfault at", re.IGNORECASE)
_OOM_KILLER = re.compile(r"Out of memory|oom-killer|oom_kill", re.IGNORECASE)
_SUSPICIOUS_PROC = re.compile(
    r"(?:nc|ncat|netcat|nmap|tcpdump|wireshark|ettercap|hydra|john|hashcat"
    r"|mimikatz|meterpreter|reverse_shell|bind_shell|/tmp/\S+|/dev/shm/\S+)",
    re.IGNORECASE,
)
_SYSTEMD_UNIT = re.compile(r"(Started|Stopped|Stopping|Starting)\s+(.+)\.")


class SyslogParser:
    """Parse syslog files for security-relevant events."""

    def __init__(self, year: Optional[int] = None) -> None:
        self.year = year or datetime.now().year

    def parse_line(self, line: str) -> Optional[SyslogEvent]:
        """Parse a single syslog line."""
        line = line.strip()
        if not line:
            return None

        m = _TIMESTAMP_RE.match(line)
        if not m:
            return None

        ts_str, hostname, service, pid_str, message = m.groups()
        try:
            ts = datetime.strptime(f"{self.year} {ts_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None

        pid = int(pid_str) if pid_str else None
        event_type, severity, extra = self._classify(service, message)

        return SyslogEvent(
            timestamp=ts,
            hostname=hostname,
            service=service.split("/")[0],
            pid=pid,
            message=message,
            event_type=event_type,
            severity=severity,
            raw_line=line,
            extra=extra,
        )

    def parse_file(self, filepath: str) -> list[SyslogEvent]:
        """Parse an entire syslog file."""
        events: list[SyslogEvent] = []
        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    event = self.parse_line(line)
                    if event is not None:
                        events.append(event)
        except (OSError, IOError):
            pass
        return events

    def _classify(
        self, service: str, message: str
    ) -> tuple[str, str, dict]:
        """Classify the event type, severity, and extract metadata."""
        extra: dict = {}

        # Suspicious process execution (check both service name and message)
        m = _SUSPICIOUS_PROC.search(service) or _SUSPICIOUS_PROC.search(message)
        if m:
            extra["suspicious_binary"] = m.group(0)
            return "suspicious_process", "high", extra

        # Crontab modification
        m = _CRON_EDIT.search(message)
        if m:
            extra["cron_user"] = m.group(1)
            return "cron_modified", "high", extra

        # Systemd unit state changes
        m = _SYSTEMD_UNIT.search(message)
        if m:
            action = m.group(1).lower()
            unit_name = m.group(2)
            extra["unit"] = unit_name
            if action in ("stopped", "stopping"):
                return "service_stop", "medium", extra
            return "service_start", "info", extra

        # Service start/stop
        m = _SERVICE_ACTION.search(message)
        if m:
            extra["target_service"] = m.group(1)
            if "stop" in message.lower():
                return "service_stop", "medium", extra
            return "service_start", "info", extra

        # OOM killer
        if _OOM_KILLER.search(message):
            return "oom_kill", "high", extra

        # Kernel segfault
        if _KERNEL_SEGFAULT.search(message):
            return "segfault", "medium", extra

        # Kernel messages
        if service.startswith("kernel"):
            return "kernel", "info", extra

        # CRON execution
        if service.upper() == "CRON" or "cron" in service.lower():
            return "cron_exec", "info", extra

        # Error / warning keywords
        lower_msg = message.lower()
        if "error" in lower_msg or "fail" in lower_msg:
            return "error", "medium", extra
        if "warning" in lower_msg or "warn" in lower_msg:
            return "warning", "low", extra

        return "info", "info", extra
