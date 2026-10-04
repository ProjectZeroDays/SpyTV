"""CVE whitepaper generator — a defensive markdown brief built live from NVD.

Pulls smart-TV platform CVEs from the NVD 2.0 API (same keyword set as the
monitor) over a lookback window and renders a client-ready whitepaper:
executive summary, severity breakdown, and per-CVE entries with defensive
recommended actions mapped to this toolkit's hardening modules. Purely
informational — references are listed as published by NVD, and no exploit
detail is included or fetched.

Usage:
    python -m defense.cve_monitor.whitepaper                     # 90 days, default keywords
    python -m defense.cve_monitor.whitepaper --days 180 --out output/wp.md
"""
from __future__ import annotations

import argparse
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..common import LOG, REPO_ROOT, setup_logging, write_markdown
from .monitor import DEFAULT_KEYWORDS_FILE, collect

PLATFORM_NAMES = {
    "smart tv": "Smart TVs (generic)",
    "smart television": "Smart TVs (generic)",
    "android tv": "Android TV / Google TV devices",
    "google tv": "Android TV / Google TV devices",
    "tizen": "Samsung Tizen TVs",
    "webos": "LG webOS TVs",
    "roku": "Roku TV / streaming devices",
    "fire tv": "Amazon Fire TV devices",
    "smartcast": "Vizio SmartCast TVs",
    "hbbtv": "HbbTV-capable TVs (EU models)",
    "chromecast": "Chromecast / cast-enabled devices",
    "vidaa": "Hisense VIDAA TVs",
}

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNRATED": 4, None: 5}


def recommended_actions(item: dict) -> list[str]:
    actions: list[str] = []
    if item.get("public_exploit_ref"):
        actions.append("**Priority patch** — NVD references point at public exploit material; "
                       "treat as actively exploitable and patch at the next window, not the next cycle.")
    if item.get("severity") == "CRITICAL":
        actions.append("Critical severity: schedule an emergency firmware update window.")
    actions += [
        "Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).",
        "Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug "
        "cannot pivot to trusted hosts.",
        "Close unused management surfaces on the device — network ADB, dev mode, UPnP AV "
        "(adb_disable, upnp_close).",
        "Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the "
        "entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.",
    ]
    return actions


def _platforms_for(item: dict) -> str:
    names = sorted({PLATFORM_NAMES.get(kw, kw) for kw in item.get("matched_keywords", [])})
    return "; ".join(names) if names else "unspecified"


def build_sections(merged: dict[str, dict], keywords: list[str], days: int,
                   max_cves: int) -> list[tuple[str, str]]:
    items = sorted(
        merged.values(),
        key=lambda i: (SEV_RANK.get(i.get("severity"), 9), i.get("published") or ""),
    )

    sev_counts: dict[str, int] = {}
    for item in items:
        sev_counts[item.get("severity") or "UNRATED"] = sev_counts.get(item.get("severity") or "UNRATED", 0) + 1
    exploit_count = sum(1 for i in items if i.get("public_exploit_ref"))

    scope = (f"- **Lookback window:** {days} days\n"
             f"- **Keyword scope:** {', '.join(keywords)}\n"
             f"- **CVEs found:** {len(items)}\n"
             f"- **Severity split:** " + ", ".join(
                 f"{k} {v}" for k, v in sorted(sev_counts.items(), key=lambda kv: SEV_RANK.get(kv[0], 9)))
             + f"\n- **With public exploit references:** {exploit_count}")

    exec_summary = (
        f"Over the last {days} days, NVD published {len(items)} vulnerability records matching the "
        f"smart TV platform keywords tracked by this toolkit"
        + (f", of which **{exploit_count} reference public exploit material** — these should be "
           f"treated as exploitable today" if exploit_count else "")
        + ". Smart TVs sit on living-room and boardroom networks with microphones, cameras, and a "
        "path onto the LAN; their patch cadence is slower than phones or laptops by design. The "
        "recommended posture is unchanged regardless of CVE count: automatic updates on, the TV on "
        "a segmented VLAN, management surfaces closed, and the detection stack watching the entry "
        "paths. Each entry below maps to those controls."
    )

    rows = ["| CVE | Severity | Score | Published | Platforms | Public exploit ref |",
            "|---|---|---|---|---|---|"]
    for item in items[:max_cves]:
        rows.append(
            f"| {item['id']} | {item.get('severity') or 'UNRATED'} | {item.get('score') if item.get('score') is not None else '—'} "
            f"| {(item.get('published') or '?')[:10]} | {_platforms_for(item)} | {'Yes' if item.get('public_exploit_ref') else 'No'} |"
        )
    if len(items) > max_cves:
        rows.append(f"| | | | | _{len(items) - max_cves} more entries below threshold of {max_cves}_ | |")

    sections = [
        ("Scope", scope),
        ("Executive summary", exec_summary),
        ("Vulnerability index", "\n".join(rows)),
    ]
    for item in items[:max_cves]:
        body = [
            f"- **Severity:** {item.get('severity') or 'UNRATED'}"
            + (f" (CVSS {item.get('score')})" if item.get('score') is not None else ""),
            f"- **Published:** {item.get('published') or '?'}",
            f"- **Platforms:** {_platforms_for(item)}",
            f"- **Matched keywords:** {', '.join(item.get('matched_keywords', []))}",
            f"- **Public exploit reference:** {'Yes — prioritize patching' if item.get('public_exploit_ref') else 'No'}",
            "",
            (item.get("description") or "_No description published._"),
            "",
            "**Recommended actions:**",
        ]
        body += [f"{i}. {a}" for i, a in enumerate(recommended_actions(item), start=1)]
        if item.get("references"):
            body += ["", "**References (as listed by NVD):**"] + [f"- {r}" for r in item["references"][:6]]
        sections.append((str(item["id"]), "\n".join(body)))
    return sections


def main(argv: list[str] | None = None) -> int:
    import json

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--keywords", type=Path, default=DEFAULT_KEYWORDS_FILE)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "output" / "cve_whitepaper.md")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--max-pages", type=int, default=1)
    ap.add_argument("--max-cves", type=int, default=40, help="Per-CVE sections to include (index table too)")
    args = ap.parse_args(argv)

    setup_logging()
    keywords = json.loads(args.keywords.read_text(encoding="utf-8"))
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    LOG.info("Collecting CVEs for whitepaper (%d days, %d keywords) ...", args.days, len(keywords))
    merged = collect(keywords, start, end, api_key=args.api_key, max_pages=args.max_pages)
    if not merged:
        LOG.warning("No CVEs matched in the window — the paper will be a stub. "
                    "Try a longer --days window or different keywords.")

    sections = build_sections(merged, keywords, args.days, args.max_cves)
    write_markdown(args.out, f"Smart TV Vulnerability Whitepaper — {args.days}-day lookback", sections)
    print(f"Whitepaper written: {args.out} ({len(merged)} CVEs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
