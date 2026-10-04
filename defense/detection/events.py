"""Event and alert model shared by all detectors.

Events are normalized records fed in by adapters (sshd logs, the live TCP
table, or a SOC pipeline via JSONL). Detectors consume Events and emit Alerts.
`Event.ts` is authoritative for all windowing so behavior is deterministic and
testable regardless of wall-clock time.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field


@dataclass
class Event:
    ts: float
    kind: str  # ssh_auth_failure | tcp | process | adb_device | ssdp
    src: str | None = None
    dst: str | None = None
    dport: int | None = None
    detail: dict = field(default_factory=dict)

    @classmethod
    def from_json(cls, raw: dict) -> "Event":
        known = set(cls.__dataclass_fields__)
        return Event(**{k: v for k, v in raw.items() if k in known})


@dataclass
class Alert:
    ts: float
    detector: str
    severity: str  # HIGH | MEDIUM | LOW
    title: str
    description: str
    evidence: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))


class BaseDetector:
    """Base class: observe() consumes one Event and returns zero or more Alerts."""

    name: str = "base"

    def observe(self, event: Event) -> list[Alert]:
        raise NotImplementedError

    def flush(self) -> list[Alert]:
        """Emit any pending windowed alerts at shutdown."""
        return []
