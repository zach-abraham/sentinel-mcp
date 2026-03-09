"""Parser for AWS CloudTrail JSON logs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class CloudTrailEvent:
    """A parsed CloudTrail event."""

    timestamp: datetime
    event_name: str
    event_source: str  # e.g., iam.amazonaws.com, s3.amazonaws.com
    aws_region: str
    source_ip: str
    user_agent: Optional[str]
    user_identity: dict
    request_params: Optional[dict]
    response_elements: Optional[dict]
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    event_type: str = "api_call"
    severity: str = "info"
    raw_event: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)


# High-severity event patterns
_HIGH_SEVERITY_EVENTS = {
    "CreateUser",
    "CreateLoginProfile",
    "CreateAccessKey",
    "AttachUserPolicy",
    "AttachGroupPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutGroupPolicy",
    "PutRolePolicy",
    "CreateRole",
    "UpdateAssumeRolePolicy",
    "DeleteTrail",
    "StopLogging",
    "PutBucketPolicy",
    "PutBucketAcl",
    "DeleteBucketPolicy",
    "AuthorizeSecurityGroupIngress",
    "CreateSecurityGroup",
    "ModifyInstanceAttribute",
    "RunInstances",
    "CreateKeyPair",
    "DisableKey",
    "ScheduleKeyDeletion",
}

_MEDIUM_SEVERITY_EVENTS = {
    "ConsoleLogin",
    "AssumeRole",
    "GetSecretValue",
    "Decrypt",
    "PutObject",
    "GetObject",
    "DeleteObject",
    "CreateBucket",
    "DeleteBucket",
    "DescribeInstances",
    "DescribeSecurityGroups",
    "ListBuckets",
    "ListUsers",
    "ListRoles",
    "ListAccessKeys",
    "GetCallerIdentity",
}


class CloudTrailParser:
    """Parse AWS CloudTrail JSON log files."""

    def parse_event(self, record: dict[str, Any]) -> Optional[CloudTrailEvent]:
        """Parse a single CloudTrail record dict."""
        try:
            event_name = record.get("eventName", "Unknown")
            event_source = record.get("eventSource", "unknown")

            # Parse timestamp
            event_time = record.get("eventTime", "")
            try:
                ts = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                # Strip tzinfo for consistency
                ts = ts.replace(tzinfo=None)
            except (ValueError, AttributeError):
                ts = datetime.now()

            # Determine severity
            severity = "info"
            if event_name in _HIGH_SEVERITY_EVENTS:
                severity = "high"
            elif event_name in _MEDIUM_SEVERITY_EVENTS:
                severity = "medium"

            # Check for errors (often indicate unauthorized access attempts)
            error_code = record.get("errorCode")
            error_message = record.get("errorMessage")
            if error_code in ("AccessDenied", "UnauthorizedAccess", "Client.UnauthorizedAccess"):
                severity = "high"
            elif error_code:
                severity = max(severity, "medium", key=lambda s: ["info", "low", "medium", "high", "critical"].index(s))

            # Classify event type
            event_type = self._classify_event(event_name, event_source)

            # Check for root usage
            user_identity = record.get("userIdentity", {})
            if user_identity.get("type") == "Root":
                severity = "critical" if event_name not in ("ConsoleLogin",) else "high"

            source_ip = record.get("sourceIPAddress", "unknown")

            return CloudTrailEvent(
                timestamp=ts,
                event_name=event_name,
                event_source=event_source,
                aws_region=record.get("awsRegion", "unknown"),
                source_ip=source_ip,
                user_agent=record.get("userAgent"),
                user_identity=user_identity,
                request_params=record.get("requestParameters"),
                response_elements=record.get("responseElements"),
                error_code=error_code,
                error_message=error_message,
                event_type=event_type,
                severity=severity,
                raw_event=record,
            )
        except Exception:
            return None

    def parse_file(self, filepath: str) -> list[CloudTrailEvent]:
        """Parse a CloudTrail JSON log file.

        Handles both single-record and multi-record (Records array) formats.
        """
        events: list[CloudTrailEvent] = []
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return events

        records: list[dict]
        if isinstance(data, dict) and "Records" in data:
            records = data["Records"]
        elif isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            records = [data]
        else:
            return events

        for record in records:
            event = self.parse_event(record)
            if event is not None:
                events.append(event)

        return events

    def parse_directory(self, dirpath: str) -> list[CloudTrailEvent]:
        """Parse all JSON files in a directory."""
        events: list[CloudTrailEvent] = []
        p = Path(dirpath)
        if not p.is_dir():
            return events
        for json_file in sorted(p.glob("**/*.json")):
            events.extend(self.parse_file(str(json_file)))
        return events

    def _classify_event(self, event_name: str, event_source: str) -> str:
        """Classify the event into a category."""
        source = event_source.lower()
        name = event_name.lower()

        if "iam" in source:
            if "create" in name or "attach" in name or "put" in name:
                return "iam_modification"
            return "iam_read"
        if "s3" in source:
            if "put" in name or "delete" in name:
                return "data_modification"
            return "data_access"
        if "ec2" in source:
            if "run" in name or "create" in name or "modify" in name:
                return "infrastructure_change"
            return "infrastructure_read"
        if "cloudtrail" in source:
            if "stop" in name or "delete" in name:
                return "defense_evasion"
            return "audit_config"
        if "kms" in source:
            return "encryption_operation"
        if "sts" in source:
            return "credential_use"
        if "signin" in source:
            return "authentication"
        return "api_call"
