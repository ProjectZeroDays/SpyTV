# SpyTV — Wiki

Welcome to the documentation home for SpyTV: an authorization-first smart
TV security assessment platform — C2 dashboard, e-signed audit and
patch-all engagements, an AI CVE artifact pipeline — plus the defensive
toolkit and the defect review of the framework that motivated it
(`CODE_REVIEW.md`).

## Pages

| Page | What it covers |
|---|---|
| [Getting Started](GETTING_STARTED.md) | Install (spoiler: almost nothing to install), the 15-minute first run, C2 quickstart, platform notes |
| [Architecture](ARCHITECTURE.md) | Full platform architecture: dashboard → C2 → engagement/ops layers → CVE pipeline → implant/collection → defense toolkit |
| [C2 Dashboard](C2_DASHBOARD.md) | Every API endpoint, dashboard features, the Audit / Patch All engagement flows, artifact pipeline |
| [Threat Model](THREAT_MODEL.md) | The smart TV attack classes this toolkit defends against, stage by stage, and the control that answers each |
| [Hardening Guide](HARDENING_GUIDE.md) | Playbooks: attack-surface audit, ADB disable, UPnP close-down, VLAN segmentation, firmware hygiene |
| [Detection Guide](DETECTION_GUIDE.md) | Event model, detectors and tuning, the monitor, drills, alert schema, Sigma/SIEM integration |
| [CVE Monitoring Guide](CVE_MONITORING_GUIDE.md) | Operating the NVD watcher (defensive + C2 pipelines), keywords, API keys, whitepaper generation |
| [Troubleshooting](TROUBLESHOOTING.md) | C2 startup, CVE feed, AI generation, engagements, patches, clips, SSL, performance |
| [Changes](CHANGES.md) | Release-by-release change log (current: v1.0.2) |
| [Segmentation Guide](SEGMENTATION_GUIDE.md) | IoT/VLAN segmentation playbooks |
| [Code Review](CODE_REVIEW.md) | 57-finding defect review of the reviewed framework |

## Component map

```
C2 platform (authorization-first)
├── c2_server.py       HTTP server (port 8443) — device/clip/scan/CVE/audit/patch APIs
├── c2_ops.py          Shared ops: scan, read-only check, exploit (dry-run-first), patch, teardown
├── c2_audit.py        AuditEngagement / PatchEngagement state machines + reportlab PDFs
│                      (industry-standard authorization instrument with e-sign + SHA-256 record)
├── c2_cve_feed.py     NVD fetch + AI exploit and artifact pipeline
│                      (whitepapers, pytest tests, signature + patch-check proposals, enrichment)
├── c2_dashboard.html  Single-page dashboard (responsive, equal-width viewer panel)
├── electron/          Desktop wrapper → SpyTV-C2-<ver>-portable.exe
└── tvreaper.js        Implant payload (C2 polling)

defense/
├── hardening/         attack_surface · adb_disable · upnp_close · vlan_segmentation · firmware_audit
├── detection/         ssh/adb/ssdp detectors · adapters · monitor · drill · report · rules/ (Sigma)
└── cve_monitor/       monitor (NVD watcher) · whitepaper (defensive brief generator)
```

## Operating principles

1. **Authorization first.** Every module is for networks and devices you own
   or are explicitly authorized to assess. Engagement paperwork belongs in
   the plan before the first scan — the C2's Audit flow enforces it: an
   industry-standard authorization form must be **e-signed by both the
   provider (Authenticated, Inc.) and the client** before any scanning runs.
2. **Read-only by default.** Audits never change state. Exploit checks are
   dry-run-first and transmit no payloads; hardening actions sit behind
   explicit `--apply` flags and are printed as a dry-run preview first.
3. **Minimal dependencies.** Defense toolkit: Python 3.10+ standard library.
   C2: `colorama`, `pyyaml`, `requests`, `reportlab` (PDF reports) — see
   `requirements.txt`. Works on Windows and Linux out of the box.
4. **Prove it.** Generated exploit tests must pass pytest before an exploit
   is marked generated (failing exploits are quarantined), and every CVE
   artifact status is logged to root `CVE_UPDATES.log`.

## Verification

```bash
python -m pytest -q                 # 82 tests (C2, engagements, CVE pipeline, defense)
python -m defense.detection.drill   # self-scoring detection drill (expect ALL PASS)
```
