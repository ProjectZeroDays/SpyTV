"""Detection drill — fire synthetic attack-shaped events at your own detection stack.

Emits realistic but entirely synthetic Events (SSH brute-force bursts, rogue
ADB connections, an SSDP sweep, benign noise) and runs them through the *real*
detectors so operators can watch alerts fire, validate tuning, and demo the
stack — without touching any real host. Every scenario has a known expected
alert count, so the drill is self-scoring: PASS means the detection stack
behaves as designed, FAIL means something was tuned wrong.

Usage:
    python -m defense.detection.drill                          # all scenarios, instant
    python -m defense.detection.drill --live --interval 0.3    # paced, for demos
    python -m defense.detection.drill --scenario ssdp_sweep
    python -m defense.detection.drill --alert-file output/drill_alerts.jsonl
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from ..common import setup_logging
from .adb_detector import RogueAdbDetector
from .events import Alert, Event
from .ssh_detector import SshBruteForceDetector
from .ssdp_detector import SsdpAnomalyDetector

BASE_TS = 1_000_000.0
BENIGN_ALLOWED_PEER = "192.168.1.42"


def _fresh_detectors() -> list:
    return [
        SshBruteForceDetector(threshold=5, window=60.0, cooldown=300.0),
        RogueAdbDetector(allowed_peers={BENIGN_ALLOWED_PEER}),
        SsdpAnomalyDetector(rate_threshold=50, window=10.0, distinct_dst_threshold=25, cooldown=120.0),
    ]


def _ssh_fail(ts: float, src: str, user: str) -> Event:
    return Event(ts=ts, kind="ssh_auth_failure", src=src,
                 detail={"user": user, "raw": f"<drill> Failed password for {user} from {src} port 40000 ssh2"})


def scenario_ssh_bruteforce(ts: float) -> list[Event]:
    """8 password failures from one source inside the 60s window -> 1 HIGH alert."""
    events = []
    for i, user in enumerate(["admin", "root", "oracle", "pi", "test", "ubuntu", "guest", "admin"]):
        events.append(_ssh_fail(ts + i * 5.0, "198.51.100.77", user))
    return events


def scenario_adb_takeover(ts: float) -> list[Event]:
    """Two rogue TV connections + adb connect usage + device attach -> 3 HIGH + 1 MEDIUM."""
    events = [
        Event(ts=ts, kind="tcp", src="192.168.1.23", dst="192.168.1.64", dport=5555,
              detail={"state": "ESTABLISHED"}),
        Event(ts=ts + 1.0, kind="tcp", src="192.168.1.23", dst="192.168.1.64", dport=5555,
              detail={"state": "ESTABLISHED"}),   # duplicate pair: must not double-alert
        Event(ts=ts + 2.0, kind="tcp", src="192.168.1.23", dst="192.168.1.65", dport=5555,
              detail={"state": "ESTABLISHED"}),
        Event(ts=ts + 3.0, kind="process",
              detail={"name": "adb.exe", "cmdline": "adb connect 192.168.1.64:5555", "pid": 4242}),
        Event(ts=ts + 4.0, kind="adb_device",
              detail={"serial": "192.168.1.64:5555", "status": "unauthorized"}),
    ]
    return events


def scenario_ssdp_sweep(ts: float) -> list[Event]:
    """60-address M-SEARCH fan-out in ~6s -> 1 HIGH sweep alert (cooldown holds the rest)."""
    return [
        Event(ts=ts + i * 0.1, kind="ssdp", src="203.0.113.200",
              dst=f"239.255.255.{(i % 250) + 1}", detail={"method": "M-SEARCH"})
        for i in range(60)
    ]


def scenario_benign(ts: float) -> list[Event]:
    """Normal-day traffic -> zero alerts (negative control, incl. allowlisted ADB peer)."""
    events = []
    for i, (src, user) in enumerate([("203.0.113.10", "sam"), ("203.0.113.11", "alex"), ("203.0.113.12", "kim")]):
        events.append(_ssh_fail(ts + i * 40.0, src, user))  # one failure each: below threshold
    events.append(Event(ts=ts + 1.0, kind="tcp", src="192.168.1.50", dst="93.184.216.34", dport=443,
                        detail={"state": "ESTABLISHED"}))
    events.append(Event(ts=ts + 2.0, kind="tcp", src="192.168.1.50", dst=BENIGN_ALLOWED_PEER, dport=5555,
                        detail={"state": "ESTABLISHED"}))  # approved peer: ignored
    for i in range(3):
        events.append(Event(ts=ts + i * 30.0, kind="ssdp", src="192.168.1.61",
                            dst="239.255.255.250", detail={"method": "NOTIFY"}))
    return events


SCENARIOS: dict[str, tuple] = {
    "ssh_bruteforce": (scenario_ssh_bruteforce, 1,
                       "8 auth failures from one source in 40s -> exactly one HIGH brute-force alert"),
    "adb_takeover": (scenario_adb_takeover, 4,
                     "2 rogue port-5555 connections + 'adb connect' + device attach -> 3 HIGH + 1 MEDIUM"),
    "ssdp_sweep": (scenario_ssdp_sweep, 1,
                   "60-address M-SEARCH fan-out -> exactly one HIGH sweep alert"),
    "benign": (scenario_benign, 0,
               "normal logins, HTTPS, periodic NOTIFY, allowlisted ADB peer -> zero alerts"),
}


def run_drill(selected: list[str] | None = None, live: bool = False, interval: float = 0.3,
              alert_file: Path | None = None) -> tuple[int, list[dict]]:
    """Run scenarios through fresh detectors; returns (failures, result rows)."""
    names = selected or list(SCENARIOS)
    failures = 0
    rows: list[dict] = []
    all_alerts: list[Alert] = []

    print(f"{'Scenario':<16} {'Expected':>8} {'Fired':>6}  Result   Description")
    print("-" * 96, flush=True)
    for name in names:
        builder, expected, description = SCENARIOS[name]
        events = sorted(builder(time.time()), key=lambda e: e.ts)
        detectors = _fresh_detectors()
        fired: list[Alert] = []
        for event in events:
            emitted = event
            if live:
                emitted = Event(ts=time.time(), kind=event.kind, src=event.src, dst=event.dst,
                                dport=event.dport, detail=dict(event.detail))
                time.sleep(interval)
            for detector in detectors:
                fired.extend(detector.observe(emitted))
        ok = len(fired) == expected
        if not ok:
            failures += 1
        rows.append({"scenario": name, "expected": expected, "fired": len(fired),
                     "passed": ok, "description": description})
        all_alerts.extend(fired)
        print(f"{name:<16} {expected:>8} {len(fired):>6}  {'PASS' if ok else 'FAIL':<7} {description}",
              flush=True)
        for alert in fired:
            print(f"    -> [{alert.severity}] {alert.title}", flush=True)

    if alert_file is not None:
        alert_file.parent.mkdir(parents=True, exist_ok=True)
        with open(alert_file, "a", encoding="utf-8") as fh:
            for alert in all_alerts:
                fh.write(alert.to_json() + "\n")
        print(f"\nAlerts appended: {alert_file}", flush=True)
    print(f"\n{'ALL SCENARIOS PASS' if failures == 0 else str(failures) + ' SCENARIO(S) FAILED'}",
          flush=True)
    return failures, rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", action="append", choices=sorted(SCENARIOS),
                    help="Run only this scenario (repeatable; default all)")
    ap.add_argument("--live", action="store_true", help="Pace events in real time (demo mode)")
    ap.add_argument("--interval", type=float, default=0.3, help="Seconds between events in --live mode")
    ap.add_argument("--alert-file", type=Path, default=None,
                    help="Append drill alerts to this JSONL (e.g. to demo the report tool)")
    args = ap.parse_args(argv)
    setup_logging()
    failures, _ = run_drill(selected=args.scenario, live=args.live, interval=args.interval,
                            alert_file=args.alert_file)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
