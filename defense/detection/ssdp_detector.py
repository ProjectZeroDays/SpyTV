"""SSDP/UPnP anomaly detection: discovery sweeps and fan-out scans.

Normal SSDP traffic is low-rate periodic NOTIFY advertisements and occasional
M-SEARCHes from media clients. A source emitting high-rate or high-fan-out
SSDP in a short window is doing a discovery sweep — the reconnaissance step
of TV-targeting tooling (and of many IoT worms).
"""
from __future__ import annotations

from .events import Alert, BaseDetector, Event


class SsdpAnomalyDetector(BaseDetector):
    """Alert when one source exceeds rate or distinct-destination thresholds in a window."""

    name = "ssdp_anomaly"

    def __init__(self, rate_threshold: int = 50, window: float = 10.0,
                 distinct_dst_threshold: int = 25, cooldown: float = 120.0):
        self.rate_threshold = rate_threshold
        self.window = window
        self.distinct_dst_threshold = distinct_dst_threshold
        self.cooldown = cooldown
        self._events: dict[str, list[tuple[float, str | None]]] = {}
        self._last_alert: dict[str, float] = {}

    def observe(self, event: Event) -> list[Alert]:
        if event.kind != "ssdp" or not event.src:
            return []
        now = event.ts
        bucket = self._events.setdefault(event.src, [])
        bucket.append((now, event.dst))
        cutoff = now - self.window
        bucket = [x for x in bucket if x[0] >= cutoff]
        self._events[event.src] = bucket

        reasons: list[str] = []
        if len(bucket) >= self.rate_threshold:
            reasons.append(f"{len(bucket)} SSDP messages within {self.window:.0f}s (threshold {self.rate_threshold})")
        distinct_dst = {d for _, d in bucket if d}
        if len(distinct_dst) >= self.distinct_dst_threshold:
            reasons.append(f"{len(distinct_dst)} distinct destinations within {self.window:.0f}s "
                           f"(threshold {self.distinct_dst_threshold})")
        if not reasons:
            return []
        if now - self._last_alert.get(event.src, float("-inf")) < self.cooldown:
            return []
        self._last_alert[event.src] = now

        method = str(event.detail.get("method", "?")).upper()
        return [
            Alert(
                ts=now,
                detector=self.name,
                severity="MEDIUM" if method == "NOTIFY" else "HIGH",
                title=f"SSDP sweep/anomaly from {event.src}",
                description=(
                    "; ".join(reasons)
                    + ". High-rate or fan-out SSDP from one source is consistent with a "
                      "network discovery sweep (typical first stage of smart-TV targeting) "
                      "or SSDP reflection abuse. Identify the host and verify the activity."
                ),
                evidence={"src": event.src, "messages": len(bucket),
                          "distinct_dst": len(distinct_dst), "method": method},
            )
        ]
