"""Unified detection monitor: wire event sources to detectors and emit alerts.

Examples:
    # Watch a Linux sshd auth log and the local TCP table for ADB connections:
    python -m defense.detection.monitor --sshd-log /var/log/auth.log --netstat

    # Only new log lines (skip history), allowlist your own dev TV:
    python -m defense.detection.monitor --sshd-log /var/log/auth.log --tail-only \
        --netstat --allowlist config/known_hosts.json

    # Ingest a SOC pipeline's normalized events instead:
    python -m defense.detection.monitor --jsonl events.jsonl

Alerts print to the console and append as JSONL to --alert-file
(output/alerts.jsonl by default), one JSON object per alert.
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from ..common import load_json, setup_logging
from .adapters import JsonlAdapter, NetstatAdapter, SshdLogAdapter
from .adb_detector import RogueAdbDetector
from .events import Alert
from .ssh_detector import SshBruteForceDetector
from .ssdp_detector import SsdpAnomalyDetector


def emit(alert: Alert, alert_path: Path) -> None:
    line = f"[{alert.severity}] {alert.title} — {alert.description}"
    print(line, flush=True)
    with open(alert_path, "a", encoding="utf-8") as fh:
        fh.write(alert.to_json() + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sshd-log", help="sshd auth log to tail (e.g. /var/log/auth.log)")
    ap.add_argument("--tail-only", action="store_true", help="Don't replay existing log content")
    ap.add_argument("--netstat", action="store_true", help="Poll the live TCP table for ADB-port connections")
    ap.add_argument("--jsonl", help="Tail a JSONL file of normalized events")
    ap.add_argument("--allowlist", help="JSON list of approved ADB peer IPs (see config/known_hosts.example.json)")
    ap.add_argument("--alert-file", default="output/alerts.jsonl")
    ap.add_argument("--ssh-threshold", type=int, default=5, help="Failed auths per window to alert (default 5)")
    ap.add_argument("--ssh-window", type=int, default=60, help="Brute-force window in seconds (default 60)")
    ap.add_argument("--ssdp-rate", type=int, default=50, help="SSDP msgs per 10s to alert (default 50)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    setup_logging(verbose=args.verbose)

    if not (args.sshd_log or args.netstat or args.jsonl):
        ap.error("specify at least one source: --sshd-log, --netstat, and/or --jsonl")

    adapters = []
    if args.sshd_log:
        adapters.append(SshdLogAdapter(args.sshd_log, start_at_end=args.tail_only))
    if args.netstat:
        adapters.append(NetstatAdapter())
    if args.jsonl:
        adapters.append(JsonlAdapter(args.jsonl))

    allowed: set[str] = set()
    if args.allowlist:
        loaded = load_json(Path(args.allowlist))
        if isinstance(loaded, list):
            allowed = {str(x) for x in loaded}

    detectors = [
        SshBruteForceDetector(threshold=args.ssh_threshold, window=args.ssh_window),
        RogueAdbDetector(allowed_peers=allowed),
        SsdpAnomalyDetector(rate_threshold=args.ssdp_rate),
    ]

    alert_path = Path(args.alert_file)
    alert_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Monitoring {len(adapters)} source(s); alerts -> {alert_path}", flush=True)

    try:
        while True:
            for adapter in adapters:
                for event in adapter.events():
                    for detector in detectors:
                        for alert in detector.observe(event):
                            emit(alert, alert_path)
            time.sleep(1.0)
    except KeyboardInterrupt:
        for detector in detectors:
            for alert in detector.flush():
                emit(alert, alert_path)
        print("Stopped.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
