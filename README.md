# SpyTV — TV Security Assessment Platform

The working repository of the SpyTV engagement for **Authenticated, Inc.**: an
authorization-first platform for assessing smart TVs on client networks,
plus the defensive toolkit and defect review produced alongside it.

1. **C2 dashboard** (`c2_server.py` + `c2_dashboard.html`) — scan networks,
   verify targets read-only, deploy exploit modules with dry-run-first
   behavior, patch devices, and manage engagements from a responsive web UI
   (also shipped as a desktop `.exe` via `electron/` and as a standalone APK
   with embedded C2 server on Android).
2. **Audit & Patch-all engagements (T-03)** — `c2_audit.py` drives the full
   engagement flow: client details → **industry-standard authorization form
   e-signed by both parties** → scan → verify → exploit → kill connections →
   **reportlab PDF report**. The Patch All flow proves every device
   vulnerability is remediated (or documents what is not, and why).
3. **CVE feed & AI artifact pipeline (T-01/T-02)** — `c2_cve_feed.py` pulls
   smart-TV CVEs from NVD and, per new CVE, generates the full artifact set:
   exploit module, whitepaper, a pytest test that must pass, detection
   signature proposal, patch check, and feed enrichment.
4. **`defense/`** — a production-quality toolkit covering the four defensive
   pillars: attack-surface assessment, hardening (ADB, UPnP, VLAN
   segmentation, firmware), detection engineering (SOC/home-lab), and CVE
   monitoring.
5. **`CODE_REVIEW.md`** — a defect review of the offensive framework code
   (57 findings: fatal defects, self-inflicted vulnerabilities,
   misconfigurations, portability gaps, and documentation-integrity
   problems).
6. **`docs/`** — the wiki: [home](docs/WIKI.md) ·
   [getting started](docs/GETTING_STARTED.md) ·
   [architecture](docs/ARCHITECTURE.md) ·
   [C2 dashboard](docs/C2_DASHBOARD.md) ·
   [threat model](docs/THREAT_MODEL.md) ·
   [hardening](docs/HARDENING_GUIDE.md) ·
   [detection](docs/DETECTION_GUIDE.md) ·
   [CVE monitoring](docs/CVE_MONITORING_GUIDE.md) ·
   [troubleshooting](docs/TROUBLESHOOTING.md) ·
   [changes](docs/CHANGES.md)

## Authorization

Use these tools **only on networks and devices you own or are explicitly
authorized to assess**. The C2 enforces this in flow: the **Audit** button
does not run until an *Authorization to Perform a Security Assessment and
Rules of Engagement* document has been **e-signed by both parties** — the
provider block is pre-signed by Authenticated, Inc., the client draws their
signature and confirms their company in the dashboard. The signed
instrument (with a SHA-256 record hash and audit trail) is archived under
`c2_data/audits/<auth_id>/`. The hardening modules are read-only by
default; every state-changing command is printed as a dry-run preview until
you pass `--apply`.

## Releases

GitHub releases ship three assets — **each capable of running the full C2**:

| Asset | What it is | C2 mode |
|---|---|---|
| `SpyTV.apk` | Android APK with dual-mode: Console (connects to remote C2) or Standalone (runs full C2 locally on-device) | Standalone ✓ + Console ✓ |
| `SpyTV-C2-standalone.exe` | Standalone Windows EXE with bundled Python — runs the full C2 server offline | Full C2 ✓ |
| `SHA256SUMS.txt` | SHA-256 checksum manifest for the attached assets | — |

## Screenshots

Screenshots of the web dashboard (`docs/screenshots/dashboard-web.png`), standalone EXE (`docs/screenshots/exe-running.png`), and native APK (`docs/screenshots/apk-running.png`) are included in `docs/screenshots/`.

### APK Modes

The SpyTV APK supports two modes:

1. **Console Mode** (default): The APK acts as a remote console — it loads the web
   dashboard from an external C2 server (the APK itself is not the C2). Use this
   when the C2 runs on a laptop/server and you operate from the phone.

2. **Standalone Mode** (new): The APK runs a full C2 server locally on the Android
   device, serving the complete dashboard and all API endpoints (`/api/devices`,
   `/api/scan`, `/api/command`, `/api/poll`, `/api/cves`, etc.). The server binds
   to port 8443 and is reachable from other devices on the same network. Use this
   when you need the C2 on-device without an external laptop.

   To toggle: launch SpyTV → tap the ⚙ settings button → select "Standalone Mode".

### EXE Mode

The standalone EXE bundles the Python C2 server + dashboard into a single
executable. It runs without Python installed and serves the full web dashboard at
`http://<machine-ip>:8443/`.

Latest: [v1.0.9](https://github.com/ProjectZeroDays/SpyTV/releases/tag/v1.0.9).

## Repository layout

```
SpyTV/
├── README.md
├── CODE_REVIEW.md                  # Defect review of the reviewed framework
├── requirements.txt                # colorama, pyyaml, requests, reportlab (C2 PDFs)
├── run_c2.bat                      # Launcher: AI-key prompt, starts the C2
├── create_apk.py                   # Builds SpyTV.apk for releases
│
├── c2_server.py                    # C2 HTTP server (port 8443) — all API endpoints
├── c2_ops.py                       # Shared scan/check/exploit/patch/teardown ops
├── c2_audit.py                     # Engagement state machines + reportlab PDF builders
├── c2_cve_feed.py                  # CVE feed manager: NVD fetch, AI exploit + artifact gen
├── c2_dashboard.html               # Web dashboard (served at /)
├── tvreaper.js                     # Implant payload (C2 polling)
├── CVE_UPDATES.log                 # Root JSONL CVE update log (replayed into the feed)
│
├── electron/                       # Desktop wrapper → SpyTV-C2-<ver>-portable.exe
├── core/                           # Core logic (discovery, dispatcher, receiver, config)
├── families/                       # Family-specific exploits (tizen/webos/android/dlna/hbbtv)
├── data/
│   └── exploits/generated/         # AI-generated exploit modules (CVE-*.py; quarantined on failing tests)
├── docs/                           # The wiki (see links above)
│   ├── whitepapers/                # Generated per-CVE whitepapers (T-01)
│   ├── C2_DASHBOARD.md             # Endpoints, dashboard features, engagement flows
│   └── CHANGES.md                  # Release-by-release change log
├── defense/                        # Defensive toolkit (hardening, detection, CVE monitor)
├── c2_data/                        # Runtime state (git-ignored): audits/, clips/, registries
│   └── audits/<auth_id>/           # Authorization PDFs (unsigned/signed) + reports
├── data/signatures/                # Detection-signature proposals (assessor-validated)
├── data/patch_checks/              # Patch verification checks
└── tests/                          # pytest suite — 114 tests (generated: tests/generated/)
```

## Quickstart — C2 dashboard

```bash
cd C:\Projects\SpyTV
pip install -r requirements.txt      # colorama, pyyaml, requests, reportlab
run_c2.bat                           # prompts for AI provider keys (or skip), starts C2
# …or run directly:
python c2_server.py

# Dashboard:  http://127.0.0.1:8443/   (desktop: electron\dist\SpyTV-C2-1.0.7-portable.exe)
# 1. Network Discovery → Scan → Check / Patch / Exploit per device
# 2. Audit  → client details → e-sign authorization → scan/check/exploit/kill → PDF report
# 3. Patch All → patches everything → client details → remediation proof PDF
# 4. CVE Monitor → Update CVEs → full artifact set per new CVE (see docs/C2_DASHBOARD.md)
```

## Quickstart — defensive toolkit

```bash
# 1. Audit your network's TV attack surface (read-only)
python -m defense.hardening.attack_surface --network 192.168.1.0/24

# 2. Hunt for exposed ADB and get per-vendor disable steps
python -m defense.hardening.adb_disable --network 192.168.1.0/24
python -m defense.hardening.adb_disable --local --apply   # admin shell; dry-run without --apply

# 3. Enumerate UPnP devices and shut unnecessary exposure
python -m defense.hardening.upnp_close
python -m defense.hardening.upnp_close --apply --block-inbound --stop-service

# 4. Generate an IoT VLAN ruleset + platform guide
python -m defense.hardening.vlan_segmentation            # writes output/vlan/

# 5. Audit firmware-update hygiene
copy config\devices.example.json config\devices.json     # edit to match your devices
python -m defense.hardening.firmware_audit

# 6. Detection (SOC or home lab)
python -m defense.detection.monitor --sshd-log /var/log/auth.log --netstat
python -m defense.detection.monitor --sshd-log C:\logs\auth.log --tail-only \
    --allowlist config/known_hosts.json --alert-file output/alerts.jsonl

# 7. Prove the detection stack works — self-scoring drill (great for demos)
python -m defense.detection.drill
python -m defense.detection.drill --live --interval 0.3

# 8. Turn alert logs into an incident summary
python -m defense.detection.report --alerts output/alerts.jsonl

# 9. CVE monitoring (alerting only — never downloads exploits)
python -m defense.cve_monitor.monitor --once --days 7
python -m defense.cve_monitor.monitor --watch --interval 21600 --webhook <url>

# 10. Client-ready vulnerability whitepaper, generated live from NVD
python -m defense.cve_monitor.whitepaper --days 90
```

## Detection model

- **Sources**: sshd auth logs (Linux `auth.log`/`secure`, Windows OpenSSH logs),
  the live TCP table (`netstat`/`ss`), or any pipeline via JSONL events.
- **Detectors**: SSH brute force (per-source sliding window), rogue ADB
  (TCP 5555/5037 connections not in the allowlist, `adb connect` process use,
  device attach), SSDP sweeps (rate + distinct-destination fan-out).
- **Drill**: four synthetic scenarios with known expected alert counts —
  including a negative control — so the stack proves itself without touching
  a single real host.
- **Output**: console + one JSON object per alert in `output/alerts.jsonl`;
  `report.py` turns any alert file into an executive markdown summary.
- **Determinism**: all windowing uses event timestamps, so behavior is fully
  covered by the unit tests.

## CVE monitor & whitepaper behavior

Two independent pipelines watch smart-TV CVEs:

- **Defensive watcher** (`defense/cve_monitor/`): queries the NVD 2.0 API per
  keyword, deduplicates against `defense/cve_monitor/state.json`, flags CVEs
  whose references point at public exploit corpora as **public exploit
  reference**, and alerts via console, JSONL, and optional webhook.
  `whitepaper.py` renders a defensive client brief — scope, executive
  summary, severity index, per-CVE entries with recommended actions mapped to
  the hardening modules. Without an API key it rate-limits to one request per
  6 seconds per NVD guidance.
- **C2 feed pipeline** (`c2_cve_feed.py`): runs at every C2 start and via
  *Update CVEs*. Each new CVE gets the full artifact set — exploit module
  (AI provider required), whitepaper (`docs/whitepapers/`), a
  pytest-validated generated test (`tests/generated/`, exploit quarantined on
  failure), detection-signature and patch-check proposals, and NVD
  enrichment (CWE / affected CPEs / fixed version / attack vector). Every
  status lands as JSONL `artifacts` events in root `CVE_UPDATES.log` and on
  the feed entry flags (`whitepaper_generated`, `tests_generated`,
  `signature_generated`, `patch_check_generated`).

## Tests

```bash
python -m pytest -q                 # 82 tests (everything, incl. generated-artifact suites)
python -m defense.detection.drill   # expect: ALL SCENARIOS PASS
```

The suite covers the C2 endpoints, audit/patch engagement state machines,
authorization PDF structure, signature validation, the CVE artifact
pipeline, and the defense toolkit — all offline (network operations are
stubbed).

## Scope note

Per the engagement terms, this repository exists for **authorized security
assessment of client-owned smart TVs**: scan, verify (read-only), deploy
dry-run-first exploit modules, patch, and produce signed reports — plus the
defensive counterparts (assess, harden, detect, monitor) and the defect
review. Exploit modules default to dry-run and transmit no payloads until an
engagement explicitly runs them against authorized targets. No guidance for
unauthorized use is provided or implied.
