# CVE Monitoring Guide

The CVE monitor is the defensive counterpart of an "auto-update exploit"
mechanism: it watches NVD for newly published smart TV CVEs and **alerts
only** — it never downloads, evaluates, or configures exploits.

## Operation

```bash
# One pass over the last 7 days (first run can be chatty; start with --days 1-3)
python -m defense.cve_monitor.monitor --once --days 7

# Continuous: check every 6 hours
python -m defense.cve_monitor.monitor --watch --interval 21600

# Alerts to a webhook as well (JSON POST per alert)
python -m defense.cve_monitor.monitor --once --webhook https://hooks.example.com/abc
```

Schedule `--once --days 1` from Task Scheduler / cron for steady-state use.

## Keywords

`defense/cve_monitor/keywords.json` holds the search terms (smart tv, android
tv, tizen, webos, roku, fire tv, smartcast, hbbtv, chromecast, vidaa, ...).
Edit freely — each keyword is a separate NVD query, so more keywords means a
longer cycle. Keep terms platform-specific; a bare vendor name ("samsung")
matches phones and SSDs and buries you in noise.

## API key and rate limits

NVD allows ~1 request per 6 seconds anonymously (the monitor's default
delay) and much more with a free API key:
[request one here](https://nvd.nist.gov/developers/request-an-api-key), then
either `set NVD_API_KEY=...` or pass `--api-key`. The monitor retries
403/429/5xx responses with backoff and continues past per-keyword failures.

## State and dedupe

`defense/cve_monitor/state.json` remembers every alerted CVE ID (capped at
3,000, pruned oldest-first). Delete the file to force a full re-alert of the
lookback window. Outputs: console, `output/cve_alerts.jsonl` (one summary
object per new CVE), and optional webhook.

## Priority signal — public exploit references

Alerts and whitepaper entries where an NVD reference points at a public
exploit corpus (exploit-db, PacketStorm, Seclists) are flagged
`public exploit reference`. Treat those as patch-now regardless of CVSS.

## Whitepapers

```bash
python -m defense.cve_monitor.whitepaper --days 90
```

Builds `output/cve_whitepaper.md` — a client-ready defensive brief generated
live from NVD: scope, executive summary, severity index table, and per-CVE
entries (severity/score, platforms, description as published, references,
and recommended actions mapped to this toolkit's hardening modules). No
exploit detail is included or fetched; regenerate per client or per quarter.

## Suggested cadence

| Frequency | Action |
|---|---|
| Daily | `monitor --once --days 1` |
| Weekly | skim `cve_alerts.jsonl`; patch HIGH/CRITICAL or public-exploit items |
| Quarterly | `whitepaper --days 90` for stakeholders; re-run `attack_surface` and diff |
