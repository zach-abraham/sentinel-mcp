"""Parser for authentication logs (auth.log, secure)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AuthEvent:
    """A single parsed authentication event."""

    timestamp: datetime
    hostname: str
    service: str
    pid: Optional[int]
    event_type: str  # failed_login, successful_login, sudo, user_add, session_open, session_close, invalid_user
    username: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    target_user: Optional[str] = None
    command: Optional[str] = None
    raw_line: str = ""
    severity: str = "info"  # info, low, medium, high, critical
    extra: dict = field(default_factory=dict)


# Patterns for common auth.log entries
_SSHD_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
)
_SSHD_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)"
)
_SSHD_INVALID_USER = re.compile(
    r"Invalid user (\S+) from ([\d.]+)(?: port (\d+))?"
)
_SSHD_DISCONNECT = re.compile(
    r"Disconnected from(?: authenticating)?(?: invalid)?(?: user (\S+))? ([\d.]+) port (\d+)"
)
_SUDO = re.compile(
    r"(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)"
)
_USERADD = re.compile(r"new user: name=(\S+)")
_USERMOD = re.compile(r"add '(\S+)' to group '(\S+)'")
_SESSION_OPEN = re.compile(r"pam_unix\(\S+:session\): session opened for user (\S+)")
_SESSION_CLOSE = re.compile(r"pam_unix\(\S+:session\): session closed for user (\S+)")
_SU = re.compile(r"Successful su for (\S+) by (\S+)")
_PASSWD_CHANGE = re.compile(r"password changed for (\S+)")

# Timestamp format: "Mar  5 14:23:01" (no year -- assume current year)
_TIMESTAMP_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)"
)


class AuthLogParser:
    """Parse auth.log / secure log files for security-relevant events."""

    def __init__(self, year: Optional[int] = None) -> None:
        self.year = year or datetime.now().year

    def parse_line(self, line: str) -> Optional[AuthEvent]:
        """Parse a single auth.log line into an AuthEvent."""
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
        base = dict(
            timestamp=ts,
            hostname=hostname,
            service=service.split("/")[0],
            pid=pid,
            raw_line=line,
        )

        # Try each pattern in order of specificity
        event = (
            self._try_failed_login(message, base)
            or self._try_accepted_login(message, base)
            or self._try_invalid_user(message, base)
            or self._try_sudo(message, base)
            or self._try_useradd(message, base)
            or self._try_usermod(message, base)
            or self._try_su(message, base)
            or self._try_passwd_change(message, base)
            or self._try_session(message, base)
            or self._try_disconnect(message, base)
        )

        return event

    def parse_file(self, filepath: str) -> list[AuthEvent]:
        """Parse an entire auth.log file."""
        events: list[AuthEvent] = []
        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    event = self.parse_line(line)
                    if event is not None:
                        events.append(event)
        except (OSError, IOError):
            pass
        return events

    # -- Pattern matchers --

    def _try_failed_login(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _SSHD_FAILED.search(msg)
        if not m:
            return None
        return AuthEvent(
            **base,
            event_type="failed_login",
            username=m.group(1),
            source_ip=m.group(2),
            source_port=int(m.group(3)),
            severity="medium",
        )

    def _try_accepted_login(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _SSHD_ACCEPTED.search(msg)
        if not m:
            return None
        return AuthEvent(
            **base,
            event_type="successful_login",
            username=m.group(1),
            source_ip=m.group(2),
            source_port=int(m.group(3)),
            severity="info",
        )

    def _try_invalid_user(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _SSHD_INVALID_USER.search(msg)
        if not m:
            return None
        port = int(m.group(3)) if m.group(3) else None
        return AuthEvent(
            **base,
            event_type="invalid_user",
            username=m.group(1),
            source_ip=m.group(2),
            source_port=port,
            severity="medium",
        )

    def _try_sudo(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _SUDO.search(msg)
        if not m:
            return None
        severity = "high" if m.group(2) == "root" else "medium"
        return AuthEvent(
            **base,
            event_type="sudo",
            username=m.group(1),
            target_user=m.group(2),
            command=m.group(3).strip(),
            severity=severity,
        )

    def _try_useradd(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _USERADD.search(msg)
        if not m:
            return None
        return AuthEvent(
            **base,
            event_type="user_add",
            username=m.group(1),
            severity="high",
        )

    def _try_usermod(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _USERMOD.search(msg)
        if not m:
            return None
        return AuthEvent(
            **base,
            event_type="user_modify",
            username=m.group(1),
            severity="high",
            extra={"group": m.group(2)},
        )

    def _try_su(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _SU.search(msg)
        if not m:
            return None
        return AuthEvent(
            **base,
            event_type="su",
            username=m.group(2),
            target_user=m.group(1),
            severity="high",
        )

    def _try_passwd_change(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _PASSWD_CHANGE.search(msg)
        if not m:
            return None
        return AuthEvent(
            **base,
            event_type="password_change",
            username=m.group(1),
            severity="medium",
        )

    def _try_session(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _SESSION_OPEN.search(msg)
        if m:
            return AuthEvent(
                **base,
                event_type="session_open",
                username=m.group(1),
                severity="info",
            )
        m = _SESSION_CLOSE.search(msg)
        if m:
            return AuthEvent(
                **base,
                event_type="session_close",
                username=m.group(1),
                severity="info",
            )
        return None

    def _try_disconnect(self, msg: str, base: dict) -> Optional[AuthEvent]:
        m = _SSHD_DISCONNECT.search(msg)
        if not m:
            return None
        return AuthEvent(
            **base,
            event_type="disconnect",
            username=m.group(1),
            source_ip=m.group(2),
            source_port=int(m.group(3)),
            severity="info",
        )
