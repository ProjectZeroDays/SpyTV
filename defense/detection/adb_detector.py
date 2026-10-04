"""Rogue ADB detection: unapproved connections to ADB ports and `adb connect` usage.

Network ADB (TCP/5555) grants a shell on Android-based TVs without any
on-device prompt — any connection that isn't from an approved debugging host
deserves an alert. TCP/5037 is the local adb server port; unexpected remote
peers hitting it indicate something else driving ADB on this machine.
"""
from __future__ import annotations

from .events import Alert, BaseDetector, Event

ADB_PORTS = {5555, 5037}
ADB_PROCESS_NAMES = {"adb", "adb.exe"}


class RogueAdbDetector(BaseDetector):
    """Consumes tcp / process / adb_device Events; peers in the allowlist are ignored."""

    name = "rogue_adb"

    def __init__(self, allowed_peers: set[str] | None = None):
        self.allowed = set(allowed_peers or ())
        self._seen_conns: set[tuple[str, str, int]] = set()

    def _peer_allowed(self, *candidates: str | None) -> bool:
        return any(c in self.allowed for c in candidates if c)

    def observe(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []

        if event.kind == "tcp" and event.dport in ADB_PORTS:
            state = str(event.detail.get("state", "")).upper()
            if state and state != "ESTABLISHED":
                return alerts
            local = event.src or "?"
            peer = event.dst or "?"
            key = (local, peer, event.dport)
            if key in self._seen_conns or self._peer_allowed(peer, local):
                return alerts
            self._seen_conns.add(key)
            alerts.append(
                Alert(
                    ts=event.ts,
                    detector=self.name,
                    severity="HIGH",
                    title=f"Connection to ADB port {event.dport}: {local} -> {peer}",
                    description=(
                        f"A host initiated a connection to ADB port {event.dport} "
                        f"({local} -> {peer}) and neither endpoint is in the approved "
                        "list. If this is not an authorized debugging session, disable "
                        "network debugging on the device (defense.hardening.adb_disable) "
                        "and investigate the source host."
                    ),
                    evidence={"local": local, "peer": peer, "port": event.dport},
                )
            )

        elif event.kind == "process":
            name = str(event.detail.get("name", "")).lower()
            cmdline = str(event.detail.get("cmdline", ""))
            if name in ADB_PROCESS_NAMES and " connect " in f" {cmdline} ":
                alerts.append(
                    Alert(
                        ts=event.ts,
                        detector=self.name,
                        severity="HIGH",
                        title="adb network connect initiated",
                        description=(
                            "The ADB client was used to connect to a network target. "
                            "If this host is not a development machine, treat as "
                            "suspicious: 'adb connect' to a TV is the first step of "
                            "network-ADB takeover."
                        ),
                        evidence={"cmdline": cmdline, "pid": event.detail.get("pid")},
                    )
                )

        elif event.kind == "adb_device":
            status = str(event.detail.get("status", ""))
            serial = str(event.detail.get("serial", "?"))
            if status in ("device", "offline", "unauthorized"):
                host = serial.split(":", 1)[0]
                if not self._peer_allowed(host):
                    alerts.append(
                        Alert(
                            ts=event.ts,
                            detector=self.name,
                            severity="MEDIUM",
                            title=f"ADB device attached: {serial} ({status})",
                            description=(
                                "A device appeared in 'adb devices'. Confirm it is an "
                                "approved debugging target; 'unauthorized' status means "
                                "the TV is prompting (good) — repeated entries mean "
                                "someone keeps trying (investigate)."
                            ),
                            evidence={"serial": serial, "status": status},
                        )
                    )

        return alerts
