"""SSH brute-force detection from sshd authentication logs.

`parse_sshd_line` recognizes the common OpenSSH failure formats written to
/var/log/auth.log (Linux), /var/log/secure (RHEL), and the OpenSSH
operational log on Windows. Feed lines through the adapter in
`defense.detection.adapters` or parse directly when integrating elsewhere.
"""
from __future__ import annotations

import re
import time

from .events import Alert, BaseDetector, Event

_FAIL_PATTERNS = [
    re.compile(
        r"Failed (?:password|publickey|none) for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<ip>\S+) port (?P<port>\d+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
    re.compile(r"Connection closed by authenticating user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"),
    re.compile(r"error: maximum authentication attempts exceeded .* from (?P<ip>\S+)(?: port (?P<port>\d+))?.*ruser=(?P<user>\S*)"),
]


def parse_sshd_line(line: str, ts: float | None = None) -> Event | None:
    """Return an ssh_auth_failure Event for a failed-auth log line, else None."""
    for pattern in _FAIL_PATTERNS:
        match = pattern.search(line)
        if match:
            data = match.groupdict()
            return Event(
                ts=ts if ts is not None else time.time(),
                kind="ssh_auth_failure",
                src=data.get("ip"),
                detail={
                    "user": data.get("user") or "?",
                    "port": data.get("port"),
                    "raw": line.strip()[:300],
                },
            )
    return None


class SshBruteForceDetector(BaseDetector):
    """Alert when one source IP accumulates `threshold` auth failures inside `window`.

    A per-source cooldown prevents alert storms from a single ongoing attack;
    windowing is driven entirely by Event.ts.
    """

    name = "ssh_bruteforce"

    def __init__(self, threshold: int = 5, window: float = 60.0, cooldown: float = 300.0):
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self._hits: dict[str, list[tuple[float, str]]] = {}
        self._last_alert: dict[str, float] = {}

    def observe(self, event: Event) -> list[Alert]:
        if event.kind != "ssh_auth_failure" or not event.src:
            return []
        now = event.ts
        bucket = self._hits.setdefault(event.src, [])
        bucket.append((now, str(event.detail.get("user", "?"))))
        cutoff = now - self.window
        bucket = [(t, u) for t, u in bucket if t >= cutoff]
        self._hits[event.src] = bucket

        if len(bucket) < self.threshold:
            return []
        if now - self._last_alert.get(event.src, float("-inf")) < self.cooldown:
            return []
        self._last_alert[event.src] = now
        users = sorted({u for _, u in bucket})
        return [
            Alert(
                ts=now,
                detector=self.name,
                severity="HIGH",
                title=f"SSH brute force from {event.src}",
                description=(
                    f"{len(bucket)} failed sshd authentications from {event.src} within "
                    f"{self.window:.0f}s (threshold {self.threshold}). "
                    f"Usernames tried: {', '.join(users[:10])}."
                ),
                evidence={"src": event.src, "count": len(bucket), "users": users,
                          "window_s": self.window, "last_raw": event.detail.get("raw")},
            )
        ]
