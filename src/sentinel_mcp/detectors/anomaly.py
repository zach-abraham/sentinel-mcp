"""Anomaly detection using Isolation Forest and statistical methods."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest


@dataclass
class Anomaly:
    """A detected anomaly."""

    anomaly_type: str  # unusual_hour, new_ip, brute_force, volume_spike, behavioral
    description: str
    severity: str  # low, medium, high, critical
    score: float  # 0.0 (normal) to 1.0 (highly anomalous)
    timestamp: datetime | None = None
    source_ip: str | None = None
    username: str | None = None
    evidence: dict | None = None


class AnomalyDetector:
    """ML-based anomaly detection for security log events.

    Uses Isolation Forest for multivariate anomaly detection and statistical
    thresholds for specific attack pattern identification (brute force,
    volume spikes, unusual login hours, new IPs).
    """

    def __init__(self, sensitivity: float = 0.5) -> None:
        """Initialize detector.

        Args:
            sensitivity: 0.0 (least sensitive) to 1.0 (most sensitive).
                Controls contamination parameter and statistical thresholds.
        """
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        # Map sensitivity to contamination: 0.5 -> 0.1, 1.0 -> 0.3, 0.0 -> 0.01
        self.contamination = 0.01 + (self.sensitivity * 0.29)

    def detect(self, events: list[dict[str, Any]]) -> list[Anomaly]:
        """Run full anomaly detection suite on a list of event dicts.

        Each event dict should have at minimum:
            - timestamp (datetime)
            - event_type (str)
        And optionally:
            - source_ip (str)
            - username (str)
            - severity (str)
        """
        if not events:
            return []

        anomalies: list[Anomaly] = []

        anomalies.extend(self._detect_unusual_hours(events))
        anomalies.extend(self._detect_new_ips(events))
        anomalies.extend(self._detect_brute_force(events))
        anomalies.extend(self._detect_volume_spikes(events))
        anomalies.extend(self._detect_isolation_forest(events))

        # Deduplicate and sort by score
        anomalies.sort(key=lambda a: a.score, reverse=True)
        return anomalies

    def _detect_unusual_hours(self, events: list[dict]) -> list[Anomaly]:
        """Flag logins outside normal business hours (configurable by sensitivity)."""
        anomalies: list[Anomaly] = []
        # Define "unusual" hours based on sensitivity
        # High sensitivity: anything outside 8-18 is unusual
        # Low sensitivity: only 0-5 is unusual
        if self.sensitivity >= 0.7:
            unusual_hours = set(range(0, 7)) | set(range(20, 24))
        elif self.sensitivity >= 0.4:
            unusual_hours = set(range(0, 6)) | set(range(22, 24))
        else:
            unusual_hours = set(range(0, 5))

        login_types = {"successful_login", "failed_login", "session_open", "authentication"}

        for event in events:
            ts = event.get("timestamp")
            etype = event.get("event_type", "")
            if not ts or etype not in login_types:
                continue

            hour = ts.hour if isinstance(ts, datetime) else None
            if hour is not None and hour in unusual_hours:
                anomalies.append(Anomaly(
                    anomaly_type="unusual_hour",
                    description=f"Login activity at unusual hour ({hour:02d}:00) "
                                f"for user '{event.get('username', 'unknown')}' "
                                f"from {event.get('source_ip', 'unknown')}",
                    severity="medium",
                    score=0.6 + (0.2 if hour < 4 else 0.0),
                    timestamp=ts,
                    source_ip=event.get("source_ip"),
                    username=event.get("username"),
                    evidence={"hour": hour, "event_type": etype},
                ))
        return anomalies

    def _detect_new_ips(self, events: list[dict]) -> list[Anomaly]:
        """Detect IPs that appear only in the latter portion of the log (new arrivals)."""
        anomalies: list[Anomaly] = []

        timed_events = [e for e in events if e.get("timestamp") and e.get("source_ip")]
        if len(timed_events) < 10:
            return anomalies

        timed_events.sort(key=lambda e: e["timestamp"])
        midpoint = len(timed_events) // 2

        early_ips = {e["source_ip"] for e in timed_events[:midpoint]}
        late_events = timed_events[midpoint:]

        for event in late_events:
            ip = event["source_ip"]
            if ip not in early_ips and ip not in ("127.0.0.1", "::1"):
                # Only flag once per IP
                early_ips.add(ip)
                anomalies.append(Anomaly(
                    anomaly_type="new_ip",
                    description=f"New source IP {ip} appeared in latter half of logs, "
                                f"associated with user '{event.get('username', 'unknown')}'",
                    severity="medium",
                    score=0.55,
                    timestamp=event.get("timestamp"),
                    source_ip=ip,
                    username=event.get("username"),
                    evidence={"first_seen_position": "late"},
                ))
        return anomalies

    def _detect_brute_force(self, events: list[dict]) -> list[Anomaly]:
        """Detect brute force patterns: many failed logins from same IP in short window."""
        anomalies: list[Anomaly] = []
        # Threshold scales with sensitivity
        threshold = max(3, int(10 - (self.sensitivity * 7)))  # 3-10 attempts
        window_minutes = 5

        failed_by_ip: defaultdict[str, list[datetime]] = defaultdict(list)
        for event in events:
            if event.get("event_type") in ("failed_login", "invalid_user"):
                ip = event.get("source_ip")
                ts = event.get("timestamp")
                if ip and ts:
                    failed_by_ip[ip].append(ts)

        for ip, timestamps in failed_by_ip.items():
            timestamps.sort()
            # Sliding window
            for i, ts in enumerate(timestamps):
                window_end = ts + timedelta(minutes=window_minutes)
                count = sum(1 for t in timestamps[i:] if t <= window_end)
                if count >= threshold:
                    anomalies.append(Anomaly(
                        anomaly_type="brute_force",
                        description=f"Potential brute force: {count} failed login attempts "
                                    f"from {ip} within {window_minutes} minutes",
                        severity="high" if count >= threshold * 2 else "medium",
                        score=min(1.0, 0.5 + (count / (threshold * 4))),
                        timestamp=ts,
                        source_ip=ip,
                        evidence={
                            "failed_count": count,
                            "window_minutes": window_minutes,
                            "threshold": threshold,
                        },
                    ))
                    break  # One alert per IP

        return anomalies

    def _detect_volume_spikes(self, events: list[dict]) -> list[Anomaly]:
        """Detect sudden spikes in event volume using hourly bucketing."""
        anomalies: list[Anomaly] = []

        hourly_counts: Counter[str] = Counter()
        for event in events:
            ts = event.get("timestamp")
            if ts and isinstance(ts, datetime):
                bucket = ts.strftime("%Y-%m-%d %H:00")
                hourly_counts[bucket] += 1

        if len(hourly_counts) < 3:
            return anomalies

        counts = np.array(list(hourly_counts.values()), dtype=float)
        mean = np.mean(counts)
        std = np.std(counts)

        if std == 0:
            return anomalies

        # Threshold: z-score based on sensitivity
        z_threshold = 3.0 - (self.sensitivity * 1.5)  # 1.5 to 3.0

        for bucket, count in hourly_counts.items():
            z = (count - mean) / std
            if z > z_threshold:
                anomalies.append(Anomaly(
                    anomaly_type="volume_spike",
                    description=f"Volume spike detected at {bucket}: {count} events "
                                f"(mean={mean:.1f}, z-score={z:.2f})",
                    severity="high" if z > z_threshold + 1.5 else "medium",
                    score=min(1.0, 0.5 + (z / 10.0)),
                    evidence={
                        "hour": bucket,
                        "count": int(count),
                        "mean": round(float(mean), 2),
                        "z_score": round(float(z), 2),
                    },
                ))
        return anomalies

    def _detect_isolation_forest(self, events: list[dict]) -> list[Anomaly]:
        """Use Isolation Forest on feature vectors extracted from events."""
        anomalies: list[Anomaly] = []

        # Build feature matrix: [hour, event_type_encoded, ip_frequency, is_failure]
        if len(events) < 20:
            return anomalies

        ip_counts = Counter(e.get("source_ip", "none") for e in events)
        type_map: dict[str, int] = {}
        type_counter = 0

        features = []
        valid_events = []

        for event in events:
            ts = event.get("timestamp")
            if not ts or not isinstance(ts, datetime):
                continue

            etype = event.get("event_type", "unknown")
            if etype not in type_map:
                type_map[etype] = type_counter
                type_counter += 1

            ip = event.get("source_ip", "none")
            is_failure = 1.0 if etype in ("failed_login", "invalid_user", "error") else 0.0

            features.append([
                float(ts.hour),
                float(type_map[etype]),
                float(ip_counts.get(ip, 0)),
                is_failure,
            ])
            valid_events.append(event)

        if len(features) < 20:
            return anomalies

        X = np.array(features)

        try:
            model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            predictions = model.fit_predict(X)
            scores = model.decision_function(X)
        except Exception:
            return anomalies

        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1:  # Anomaly
                event = valid_events[i]
                norm_score = max(0.0, min(1.0, 0.5 - float(score)))
                anomalies.append(Anomaly(
                    anomaly_type="behavioral",
                    description=f"Isolation Forest anomaly: event '{event.get('event_type')}' "
                                f"from {event.get('source_ip', 'unknown')} at "
                                f"{event.get('timestamp', 'unknown')} "
                                f"(anomaly score={norm_score:.3f})",
                    severity="medium" if norm_score < 0.7 else "high",
                    score=norm_score,
                    timestamp=event.get("timestamp"),
                    source_ip=event.get("source_ip"),
                    username=event.get("username"),
                    evidence={
                        "isolation_score": round(float(score), 4),
                        "normalized_score": round(norm_score, 4),
                        "features": {
                            "hour": features[i][0],
                            "event_type_id": features[i][1],
                            "ip_frequency": features[i][2],
                            "is_failure": features[i][3],
                        },
                    },
                ))

        return anomalies
