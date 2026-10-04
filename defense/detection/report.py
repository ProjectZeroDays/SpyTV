"""Incident summary report — aggregate alert JSONL files into a markdown brief.

Reads the JSONL written by the monitor or a drill (one Alert object per line)
and produces an executive-friendly markdown summary: counts by severity and
detector, top source hosts, and a timeline.

Usage:
    python -m defense.detection.report --alerts output/alerts.jsonl
    python -m defense.detection.report --alerts output/drill_alerts.jsonl --out output/drill_summary.md
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..common import OUTPUT_DIR, write_markdown

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _source_of(alert: dict) -> str:
    evidence = alert.get("evidence") or {}
    for key in ("src", "peer", "local", "serial"):
        if evidence.get(key):
            return str(evidence[key])
    return "(unknown)"


def load_alerts(path: Path) -> list[dict]:
    alerts: list[dict] = []
    if not path.exists():
        return alerts
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                alerts.append(json.loads(line))
            except ValueError:
                continue
    return alerts


def build_summary(alerts: list[dict]) -> str:
    if not alerts:
        return "No alerts found in the input file — either the period was quiet or the file is empty."
    by_sev = Counter(a.get("severity", "?") for a in alerts)
    by_det = Counter(a.get("detector", "?") for a in alerts)
    by_src = Counter(_source_of(a) for a in alerts)
    ordered = sorted(alerts, key=lambda a: a.get("ts", 0))
    first, last = _iso(ordered[0]["ts"]), _iso(ordered[-1]["ts"])

    parts = [
        f"- **Total alerts:** {len(alerts)}",
        f"- **Window (UTC):** {first} → {last}",
        "- **By severity:** " + ", ".join(f"{k} {v}" for k, v in sorted(by_sev.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))),
        "- **By detector:** " + ", ".join(f"{k} {v}" for k, v in by_det.most_common()),
        "- **Top sources:** " + ", ".join(f"{k} ({v})" for k, v in by_src.most_common(10)),
    ]
    return "\n".join(parts)


def build_timeline(alerts: list[dict], cap: int = 200) -> str:
    if not alerts:
        return ""
    ordered = sorted(alerts, key=lambda a: a.get("ts", 0))[:cap]
    rows = ["| Time (UTC) | Severity | Detector | Alert |", "|---|---|---|---|"]
    for a in ordered:
        rows.append(f"| {_iso(a.get('ts', 0))} | {a.get('severity', '?')} "
                    f"| {a.get('detector', '?')} | {a.get('title', '?')} |")
    if len(alerts) > cap:
        rows.append(f"| ... | | | {len(alerts) - cap} more alert(s) not shown |")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--alerts", type=Path, default=OUTPUT_DIR / "alerts.jsonl")
    ap.add_argument("--out", type=Path, default=OUTPUT_DIR / "incident_summary.md")
    args = ap.parse_args(argv)

    alerts = load_alerts(args.alerts)
    write_markdown(
        args.out,
        "Detection Alert Summary",
        [
            ("Overview", build_summary(alerts)),
            ("Timeline", build_timeline(alerts) or "_No alerts._"),
            ("Notes", "_Auto-generated from alert JSONL. Cross-reference the Detection Guide wiki page for "
                      "each detector's recommended triage actions._"),
        ],
    )
    print(build_summary(alerts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
