"""Smart TV CVE monitor — watches the NVD feed and alerts on relevant new CVEs.

This is the defensive counterpart of an "update mechanism": it watches the
National Vulnerability Database for newly published CVEs matching smart TV
platform keywords, deduplicates across runs with a local state file, and
alerts (console + JSONL file + optional webhook). It deliberately does
nothing beyond alerting — no exploit fetching, downloading, or configuration.

API notes: uses the NVD 2.0 REST API. Without an API key NVD asks for ~1
request per 6 seconds; with a key (https://nvd.nist.gov/developers/request-an-api-key)
the delay drops. Set the key via --api-key or the NVD_API_KEY environment
variable. First run covers the configured lookback window (default 7 days) and
can be chatty; subsequent runs only surface new IDs.

Usage:
    python -m defense.cve_monitor.monitor --once
    python -m defense.cve_monitor.monitor --watch --interval 21600
    python -m defense.cve_monitor.monitor --once --days 30 --webhook https://hooks.example.com/xyz
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..common import LOG, REPO_ROOT, setup_logging

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_KEYWORDS_FILE = Path(__file__).resolve().parent / "keywords.json"
DEFAULT_STATE_FILE = Path(__file__).resolve().parent / "state.json"
SEEN_LIMIT = 3000  # cap on remembered CVE IDs, pruned oldest-first

EXPLOIT_REFERENCE_MARKERS = ("exploit-db.com", "packetstormsecurity.com", "seclists.org")


def _fmt_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _default_get(url: str, headers: dict[str, str], timeout: float = 30.0) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "spydefense-cve-monitor/1.0", **headers})
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 500, 503) and attempt < 2:
                wait = 10 * (attempt + 1)
                LOG.warning("NVD returned %s; retrying in %ss", exc.code, wait)
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(5)
                continue
            raise
    raise RuntimeError(f"NVD fetch failed after retries: {last_error}")


def fetch_keyword(keyword: str, start: datetime, end: datetime, api_key: str | None = None,
                  fetch_fn=None, max_pages: int = 1, page_delay: float = 6.0) -> list[dict]:
    """Fetch one keyword's CVEs (raw NVD 'cve' objects) inside the time window."""
    fetch = fetch_fn or _default_get
    headers = {"apiKey": api_key} if api_key else {}
    results: list[dict] = []
    start_index = 0
    for _ in range(max_pages):
        params = {
            "keywordSearch": keyword,
            "pubStartDate": _fmt_time(start),
            "pubEndDate": _fmt_time(end),
            "resultsPerPage": 2000,
            "startIndex": start_index,
        }
        url = NVD_BASE + "?" + urllib.parse.urlencode(params)
        data = fetch(url, headers)
        vulns = data.get("vulnerabilities", [])
        results.extend(v.get("cve", {}) for v in vulns)
        total = data.get("totalResults", len(results))
        start_index += len(vulns)
        if not vulns or start_index >= total:
            break
        time.sleep(page_delay)
    return results


def summarize(cve: dict) -> dict:
    """Extract the fields we alert on from an NVD cve object."""
    description = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    severity: str | None = None
    score = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            entry = metrics[key][0]
            data = entry.get("cvssData", {})
            severity = (str(data.get("baseSeverity") or entry.get("baseSeverity") or "")).upper() or None
            score = data.get("baseScore", entry.get("baseScore"))
            break
    references = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
    public_exploit = any(marker in ref.lower() for ref in references for marker in EXPLOIT_REFERENCE_MARKERS)
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "severity": severity,
        "score": score,
        "description": description[:400],
        "references": references,
        "public_exploit_ref": public_exploit,
    }


def collect(keywords: list[str], start: datetime, end: datetime, api_key: str | None = None,
            fetch_fn=None, max_pages: int = 1, inter_query_delay: float = 6.0) -> dict[str, dict]:
    """Query every keyword and merge into {cve_id: summary + matched keywords}."""
    merged: dict[str, dict] = {}
    for i, keyword in enumerate(keywords):
        LOG.info("Querying NVD keyword %d/%d: %r", i + 1, len(keywords), keyword)
        try:
            raw = fetch_keyword(keyword, start, end, api_key=api_key, fetch_fn=fetch_fn,
                                max_pages=max_pages, page_delay=inter_query_delay)
        except Exception as exc:  # keep other keywords running; surface at end
            LOG.error("Keyword %r failed: %s", keyword, exc)
            continue
        for cve in raw:
            summary = summarize(cve)
            cve_id = summary["id"]
            if not cve_id:
                continue
            if cve_id in merged:
                merged[cve_id]["matched_keywords"].append(keyword)
            else:
                summary["matched_keywords"] = [keyword]
                merged[cve_id] = summary
        if i < len(keywords) - 1 and fetch_fn is None:
            time.sleep(inter_query_delay)
    return merged


def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            LOG.warning("State file %s unreadable; starting fresh", path)
    return {"last_run": None, "seen": {}}


def save_state(path: Path, state: dict) -> None:
    seen = state.get("seen", {})
    if len(seen) > SEEN_LIMIT:
        newest = sorted(seen.items(), key=lambda kv: kv[1], reverse=True)[:SEEN_LIMIT]
        state["seen"] = dict(newest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def format_alert(item: dict) -> str:
    sev = item.get("severity") or "UNRATED"
    head = f"{item['id']} [{sev}"
    if item.get("score") is not None:
        head += f" {item['score']}"
    head += f"] matched: {', '.join(item['matched_keywords'])}"
    if item.get("public_exploit_ref"):
        head += "  ** public exploit reference **"
    published = item.get("published") or "?"
    return f"{head}\n    published: {published}\n    {(item.get('description') or '')[:300]}"


def post_webhook(url: str, payload: dict, timeout: float = 10.0) -> bool:
    try:
        request = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError) as exc:
        LOG.error("Webhook POST failed: %s", exc)
        return False


def run_cycle(keywords_file: Path, days: int, state_file: Path, alert_file: Path | None,
              webhook: str | None, api_key: str | None, fetch_fn=None,
              max_pages: int = 1, inter_query_delay: float = 6.0) -> int:
    """One monitoring pass; returns the number of new CVEs alerted."""
    keywords = json.loads(keywords_file.read_text(encoding="utf-8"))
    if not isinstance(keywords, list) or not keywords:
        raise SystemExit(f"keywords file {keywords_file} must contain a non-empty JSON list")

    state = load_state(state_file)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    merged = collect(keywords, start, end, api_key=api_key, fetch_fn=fetch_fn,
                     max_pages=max_pages, inter_query_delay=inter_query_delay)

    seen: dict = state.setdefault("seen", {})
    fresh = [item for cve_id, item in merged.items() if cve_id not in seen]
    fresh.sort(key=lambda i: (i.get("published") or ""))

    for item in fresh:
        line = format_alert(item)
        print(line, flush=True)
        if alert_file is not None:
            alert_file.parent.mkdir(parents=True, exist_ok=True)
            with open(alert_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(item) + "\n")
        if webhook:
            post_webhook(webhook, {"text": line, "cve": item})
    for cve_id, item in merged.items():
        seen[cve_id] = item.get("published") or ""
    state["last_run"] = end.isoformat(timespec="seconds")
    save_state(state_file, state)

    LOG.info("Cycle complete: %d CVE(s) in window, %d new.", len(merged), len(fresh))
    return len(fresh)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true", help="Run a single cycle (default behavior if --watch not given)")
    ap.add_argument("--watch", action="store_true", help="Keep running every --interval seconds")
    ap.add_argument("--interval", type=int, default=21600, help="Watch interval seconds (default 6h)")
    ap.add_argument("--days", type=int, default=7, help="Lookback window in days (default 7)")
    ap.add_argument("--keywords", type=Path, default=DEFAULT_KEYWORDS_FILE)
    ap.add_argument("--state-file", type=Path, default=DEFAULT_STATE_FILE)
    ap.add_argument("--alert-file", type=Path, default=REPO_ROOT / "output" / "cve_alerts.jsonl")
    ap.add_argument("--webhook", help="Optional URL to POST each alert as JSON")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--max-pages", type=int, default=1, help="NVD pages per keyword (2000 CVEs/page)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    setup_logging(verbose=args.verbose)
    if args.days > 120:
        LOG.warning("Windows >120 days with --max-pages 1 may truncate; increase --max-pages.")
    delay = 0.75 if args.api_key else 6.0

    run_cycle(args.keywords, args.days, args.state_file, args.alert_file, args.webhook,
              args.api_key, max_pages=args.max_pages, inter_query_delay=delay)
    while args.watch:
        LOG.info("Sleeping %ss until next cycle ...", args.interval)
        time.sleep(args.interval)
        run_cycle(args.keywords, args.days, args.state_file, args.alert_file, args.webhook,
                  args.api_key, max_pages=args.max_pages, inter_query_delay=delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
