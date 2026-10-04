"""Event sources feeding the detectors: sshd logs, live TCP table, JSONL pipelines.

All adapters expose `events()` which returns whatever new Events are available
and returns quickly (non-blocking), so the monitor loop can poll several
sources. `start_at_end=True` skips existing log content and only reports new
lines — useful on a large historical auth.log.
"""
from __future__ import annotations

import platform
import re
import subprocess
import time
from pathlib import Path

from ..common import LOG
from .events import Event
from .ssh_detector import parse_sshd_line


class SshdLogAdapter:
    """Tail an sshd auth log and emit ssh_auth_failure Events."""

    def __init__(self, path: str | Path, start_at_end: bool = False):
        self.path = Path(path)
        self._pos = self.path.stat().st_size if (start_at_end and self.path.exists()) else 0

    def events(self) -> list[Event]:
        if not self.path.exists():
            return []
        size = self.path.stat().st_size
        if size < self._pos:  # rotated or truncated
            self._pos = 0
        if size == self._pos:
            return []
        out: list[Event] = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self._pos)
            for line in fh:
                event = parse_sshd_line(line)
                if event:
                    out.append(event)
            self._pos = fh.tell()
        return out


def _split_addr(addr: str) -> tuple[str, int]:
    """Split 'host:port' / '[v6]:port' / '*:port' into (host, port)."""
    if addr.startswith("["):
        host, _, port = addr[1:].partition("]:")
        return host, int(port) if port.isdigit() else 0
    host, sep, port = addr.rpartition(":")
    if not sep:
        return addr, 0
    return host, int(port) if port.isdigit() else 0


class NetstatAdapter:
    """Poll the live TCP table for connections involving ADB ports.

    Emits one tcp Event per newly-seen (local, remote) pair so detectors don't
    re-alert on long-lived sessions. Windows uses `netstat -ano -p tcp`; Linux
    uses `ss -tn state established`.
    """

    def __init__(self, ports: tuple[int, ...] = (5555, 5037)):
        self.ports = set(ports)
        self._seen: set[tuple[str, str]] = set()

    def _snapshot(self) -> list[tuple[str, str, int, str]]:
        rows: list[tuple[str, str, int, str]] = []
        if platform.system() == "Windows":
            proc = subprocess.run(["netstat", "-ano", "-p", "tcp"],
                                  capture_output=True, text=True, timeout=20)
            for line in proc.stdout.splitlines():
                match = re.match(r"\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)", line)
                if not match:
                    continue
                local, remote, state = match.groups()
                if "ESTABLISHED" not in state.upper():
                    continue
                _lip, lport = _split_addr(local)
                rip, rport = _split_addr(remote)
                if lport in self.ports or rport in self.ports:
                    rows.append((local, remote, rport, "ESTABLISHED"))
        else:
            proc = subprocess.run(["ss", "-Htn", "state", "established"],
                                  capture_output=True, text=True, timeout=20)
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                local, remote = parts[-2], parts[-1]
                _lip, lport = _split_addr(local)
                rip, rport = _split_addr(remote)
                if lport in self.ports or rport in self.ports:
                    rows.append((local, remote, rport, "ESTABLISHED"))
        return rows

    def events(self) -> list[Event]:
        try:
            rows = self._snapshot()
        except (OSError, subprocess.SubprocessError) as exc:
            LOG.error("TCP table poll failed: %s", exc)
            return []
        now = time.time()
        out: list[Event] = []
        for local, remote, rport, state in rows:
            key = (local, remote)
            if key in self._seen:
                continue
            self._seen.add(key)
            out.append(Event(
                ts=now,
                kind="tcp",
                src=local.rsplit(":", 1)[0].strip("[]"),
                dst=remote.rsplit(":", 1)[0].strip("[]"),
                dport=rport,
                detail={"state": state, "local": local, "remote": remote},
            ))
        return out


class JsonlAdapter:
    """Tail a JSONL file of normalized events (SOC pipeline ingestion).

    Expected record shape matches the Event dataclass fields; unknown keys are
    ignored so pipelines can carry extra context in `detail`.
    """

    def __init__(self, path: str | Path, start_at_end: bool = True):
        self.path = Path(path)
        self._pos = self.path.stat().st_size if (start_at_end and self.path.exists()) else 0

    def events(self) -> list[Event]:
        import json

        if not self.path.exists():
            return []
        size = self.path.stat().st_size
        if size < self._pos:
            self._pos = 0
        if size == self._pos:
            return []
        out: list[Event] = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self._pos)
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(Event.from_json(json.loads(line)))
                except ValueError as exc:
                    LOG.warning("Skipping malformed JSONL event: %s", exc)
            self._pos = fh.tell()
        return out
