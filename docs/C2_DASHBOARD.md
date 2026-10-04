# SpyTV C2 Dashboard

## Overview

The SpyTV C2 (Command & Control) server provides a web-based dashboard for
**authorized smart TV assessments**: network discovery and read-only target
verification, exploit deployment (dry-run-first), device patching,
audio/video capture from implanted devices — plus the **Audit** and
**Patch All** engagement flows (client details → e-signed authorization →
phases → PDF reports) and the CVE feed + AI artifact pipeline behind the
CVE Monitor tab. It ships as a desktop app via the Electron wrapper.

## Architecture

```
[TV Implant] <--HTTP--> [C2 Server :8443] <--HTTP--> [Web Dashboard / Electron app]
                                |
              +-----------------+------------------+
              |                                    |
      [c2_audit.py]                    [c2_cve_feed.py]
      engagements + PDFs               NVD feed + artifact pipeline
      (authorization e-sign)           (exploit/whitepaper/test/signature)
```

- **C2 Server** (`c2_server.py`): Python HTTP server on port 8443 — all API endpoints
- **Shared ops** (`c2_ops.py`): scan, read-only check, exploit (dry-run-first), patch, connection teardown
- **Engagements** (`c2_audit.py`): audit/patch state machines + reportlab PDFs (authorization instrument, reports)
- **CVE pipeline** (`c2_cve_feed.py`): NVD fetch, AI exploit + full artifact set per new CVE
- **Dashboard** (`c2_dashboard.html`): responsive single-page JS app served by C2
- **Implant** (`tvreaper.js`): Polls C2 every 5 seconds for commands
- **Desktop** (`electron/`): wrapper → `SpyTV-C2-<ver>-portable.exe`
- **Storage** (`c2_data/`): clips, device registry, command queue, engagement archives (`audits/<auth_id>/`)

## Starting the C2

```bash
# Recommended: checks .env for AI keys (prompts to add/skip if none), then starts
run_c2.bat          # Windows
python c2_server.py # direct
```

The dashboard is available at `http://localhost:8443/`

## API Endpoints

### Device Management
- `POST /api/register` — Implant registers with C2
- `GET /api/devices` — List all connected devices

### Clip Exfiltration
- `POST /api/exfil` — Upload audio/video clip (headers: `X-Device-ID`, `X-Clip-Kind`)
- `GET /api/clips` — List all clips
- `GET /api/clip/<id>` — Download a specific clip

### Command Dispatch
- `POST /api/command` — Send command to device
- `POST /api/poll` — Implant polls for pending commands

### CVE Feed & Patching
- `GET /api/cve/feed` — Feed payload (entries, counts, last update, masked AI key status, `updating` flag)
- `POST /api/cve/update` — Fetch new CVEs from NVD in a background thread (also runs automatically at every C2 start); auto-generates an exploit per new CVE when an AI key is configured
- `GET /api/cves` — Static family → CVE database (8 TV families, 28 CVEs)
- `POST /api/cve/patch` — Execute a device family's remediation commands against `{ip, tv_type, family}`; returns per-command output + `cves_fixed`
- `POST /api/cve/generate` — Generate + save an exploit for `{cve_id}` via the configured provider
- `GET /api/cve/whitepaper/<id>` — Per-CVE whitepaper (HTML full page; prefers the generated markdown document in `docs/whitepapers/`)
- `GET /api/cve/whitepaper_doc/<id>` — Per-CVE whitepaper as `{markdown, source, generated}` for the dashboard Output panel (falls back to the template so the viewer always renders)
- `GET /api/cve/artifacts/<id>` — Per-CVE artifact inventory: the four T-02 flags (`whitepaper_generated`, `tests_generated`, `signature_generated`, `patch_check_generated`), file paths + existence, exploit status, and enrichment fields (CWE / affected / fixed-in / attack vector)
- `GET /api/ai-keys` — Masked AI provider key status
- `POST /api/ai-keys` — Save keys to `c2_data/ai_keys.json`
- `GET /docs/<name>.md` — Any repo doc rendered as HTML (e.g. `/docs/TROUBLESHOOTING.md`)

### Scanning
- `POST /api/scan` — Port-scan a CIDR; merges CVE-database signature ports (Samsung 26101, LG 30000, Chromecast 8009, Hisense 56789, …) and attaches matched CVEs, severity, MAC, Bluetooth, SSH flags per host
- `GET /api/scans` — Recent scan history
- `POST /api/check` — **Read-only** verification of one target (ports, family, CVE match, exploit availability + dry-run) — transmits no payloads

### Audit & Patch-all (T-03 engagements)
- `POST /api/audit/authorize` — Validate the 6 client fields (`company`, `name`, `address`, `phone`, `email`, `website`) and stage the unsigned **Authorization & Rules of Engagement** PDF under `c2_data/audits/<auth_id>/`; returns `auth_id`, `pdf_url`, `record_hash`
- `POST /api/audit/sign` — `{auth_id, signature (base64 PNG dataURL), signer_company}` — validates the signature, archives `authorization-signed.pdf` + `authorization.json` (SHA-256 record hash, signer IP, UTC timestamps), then **starts the audit**
- `GET /api/audit/status` — Engagement snapshot (`phase`, `progress`, `log`, `report_ready`, `report_url`) — server-owned, survives page reloads
- `GET /api/audit/report.pdf` — Final audit report (attachment)
- `GET /api/audit/authorization.pdf?auth_id=…[&state=unsigned|signed]` — The authorization instrument (inline)
- `POST /api/patch/start` — Begin patch-all: fresh discovery ∪ registered devices, patches everything, then waits at `awaiting_client`
- `POST /api/patch/report` — Client details → renders the remediation proof report
- `GET /api/patch/status` — Patch engagement snapshot
- `GET /api/patch/report.pdf` — Remediation report (attachment)
- `GET /api/host_info` — Real host facts for the Server tab (IPv4/IPv6, MAC, hostname, OS, Python, C2 port, uptime)
- `POST /api/connections/kill` — Real teardown: close tracked sockets, terminate exploit child tools, verify remaining connections

## Dashboard Features

### CVE Feed (right sidebar)
- Refreshes at C2 startup, on "Update CVEs", and every 60s
- Each entry: CVE ID (links to NVD), severity badge, description, **NVD Advisory** + **Whitepaper** links, "exploit ready" marker when AI generation succeeded, plus **View Whitepaper** / **View Vulnerability Info** buttons
- The feed sits in the right column beside the main card — the two columns are equal width (`minmax(0,1fr) minmax(0,1fr)`) and stack under 1280px
- Update log: `CVE_UPDATES.log` in the repository root (also replayed into the feed if the state file is cleared)

### Output Panel — Whitepaper & Vulnerability Info (T-01)
- Card above the CVE Feed in the right column; a **single replaceable output area** — every button press fully replaces the previous content (`setOutput()`), and a **Clear** button resets it
- The panel resets to its empty state on every C2/dashboard start
- **View Whitepaper** fetches `GET /api/cve/whitepaper_doc/<id>` and renders the markdown (safe client-side renderer: HTML-escaped first, so AI/template content can never inject markup); shows whether the content came from the generated file or the on-demand template, with an "Open full page" link
- **View Vulnerability Info** renders severity, CVSS, CWE, component, fixed version, attack vector, exploit status, affected products (CPE), and then loads the T-02 artifact status via `GET /api/cve/artifacts/<id>` (flags + file paths)
- Fully responsive: columns stack and the panel scrolls internally at any width

### AI Provider Keys (CVE Monitor tab)
Keys for automatic exploit generation on each newly published CVE:

| Provider | Models |
|----------|--------|
| OpenRouter | Uncensored |
| Venice AI | Uncensored V 1.2, Qwen 3.6 Plus Uncensored, GLM 4.7 Flash Heretic |
| Abliteration.ai | Abliterated Large v2 |

Resolution order: dashboard-saved `c2_data/ai_keys.json` → `.env` (written by `run_c2.bat`) → process env. Keys display masked after saving.

### CVE Artifact Pipeline (T-02)
Every **new** CVE gets the full artifact set during `update_cve_database()`, one artifact and one CVE at a time (a partial failure never aborts the run):

| Artifact | Location | Notes |
|----------|----------|-------|
| Whitepaper (T-01) | `docs/whitepapers/CVE-*.md` | AI draft when a provider key is configured, deterministic template fallback — the file always exists |
| Pytest test | `tests/generated/test_CVE-*.py` | **Must pass pytest** before `tests_generated` is set; an AI draft that fails falls back to the template; if the test still fails the exploit module is quarantined (`.quarantined`) and `exploit_generated` is cleared |
| Detection signature | `data/signatures/CVE-*.md` | Proposal only — validated by an assessor, **never auto-merged** into `core/cve_scanner.py` |
| Patch check | `data/patch_checks/CVE-*.md` | Remediation verification steps for the Patch / Patch All flow |
| Feed enrichment | feed entry fields | CWE list, affected CPEs, fixed version, attack vector + exploitability note — parsed from NVD |
| Log records | `CVE_UPDATES.log` | One `artifacts` event per CVE with every flag + errors, plus `quarantined` in `update_summary` |

Flags on each feed entry: `whitepaper_generated`, `tests_generated`, `signature_generated`, `patch_check_generated` (visible in the Output panel via `GET /api/cve/artifacts/<id>`).

### Network Scan
- Scans generic ports **plus** every CVE-database family signature port
- Results show CVE chips (severity-colored), Check / Exploit / **Patch** buttons per device

### Audit & Patch All (T-03)
Toolbar buttons in Network Discovery (after Scan | Save | Clear), with a shared `#engagement-status` banner under the navigation:

1. **Audit** — ① client info modal (company, name, address, phone, email, website; pre-filled from `localStorage`) → ② **authorization & rules-of-engagement** PDF generated and saved locally under `c2_data/audits/<auth_id>/authorization.pdf` → ③ e-sign modal (rendered PDF + signature pad; provider block pre-signed by Authenticated, Inc. as `/s/ Ian`, Assessment Lead; client draws a signature + enters their company) → ④ `POST /api/audit/sign` validates the PNG, archives the signed instrument with a SHA-256 record hash and audit trail, and **starts the engagement** → ⑤ phases run (discover → verify → exploit → teardown) with the banner polling `/api/audit/status` → ⑥ the PDF report renders automatically in the Output area with download links (client info is already known — no second prompt)
2. **Patch All** — patches every discovered/registered device first, then asks for client info and renders the remediation proof report (which vulns are fixed, which are not and why)
3. Banner buttons: **Report** / **Authorization** downloads + **Dismiss**; server owns engagement state, so a page reload re-attaches via `restoreEngagement()`

### Device Grid (2x2)
Shows up to 4 connected devices with:
- IP address, family, entry method
- Online/offline status
- Video thumbnail grid (2x2, latest 4 frames)
- Audio player (latest clip)
- **CVE chips for the device's family** (marked "Patched" after remediation)

### Per-Device Controls
| Button | Command | Description |
|--------|---------|-------------|
| Record Audio | `record_audio` | Record audio for 1-20 minutes |
| Record Video | `record_video` | Record video for 1-20 minutes |
| Listen | `listen` | Stream live audio for 60 seconds |
| Watch | `watch` | Stream live video for 60 seconds |
| Remove | `remove` | Wipe implant and all traces |
| Patch | `patch` + `POST /api/cve/patch` | Executes the family's CVE remediation commands against the TV (per-command output shown in the Activity Log), marks its CVEs fixed, and disables the implant capture path |

### Duration Selection
Choose recording duration: 1, 2, 5, 10, 15, or 20 minutes.

### Activity Log
Shows timestamped command history with "Clear Logs" button.

## File Structure

```
c2_server.py          — C2 HTTP server
c2_ops.py             — Shared scan/check/patch/teardown operations (stateless)
c2_audit.py           — Audit & patch engagement state machines + reportlab PDFs
c2_cve_feed.py        — CVE feed manager (NVD fetch, root update log, AI exploit + artifact gen)
c2_dashboard.html     — Web dashboard (served at /)
run_c2.bat            — Launcher: checks .env for AI keys (prompt/skip), starts C2
.env.example          — Template for AI provider keys + NVD key
logo.png              — C2 logo (served at /logo.png)
tvreaper.js           — Updated implant with C2 polling
CVE_UPDATES.log       — Root-level CVE update log (JSONL; replayed into the feed;
                        one "artifacts" event per new CVE with every T-02 flag)
c2_data/
  cve_state.json      — Known-CVE state (feed source of truth)
  ai_keys.json        — Saved AI provider keys (git-ignored)
  devices.json        — Device registry
  commands.json       — Command queue
  audits/<auth_id>/   — authorization.pdf (+ signed copy, JSON record, reports)
  clips/
    audio/            — Audio clips (.wav)
    video/            — Video clips (.jpeg)
data/exploits/generated/
  CVE-*.py            — AI-generated exploit modules, one per new CVE
  CVE-*.quarantined   — Exploit moved aside when its generated test failed
data/signatures/
  CVE-*.md            — Detection-signature proposals (assessor-validated, not auto-merged)
data/patch_checks/
  CVE-*.md            — Patch verification checks for the Patch / Patch All flow
docs/whitepapers/
  CVE-*.md            — Generated per-CVE whitepapers (T-01)
tests/generated/
  test_CVE-*.py       — Generated exploit tests (T-02); must pass pytest
electron/             — Desktop wrapper around the C2 dashboard (portable .exe)
```

## Documentation from the C2

- Header **Wiki** and **Troubleshooting** links open repo docs rendered by the
  C2 itself (`/docs/WIKI.md`, `/docs/TROUBLESHOOTING.md`) — no file:// paths,
  works from any machine that can reach the dashboard.
- Any `docs/*.md` is reachable at `/docs/<name>.md`.

## Security Notes

- The C2 binds to `0.0.0.0:8443` by default. For operational use, restrict to localhost or use a reverse proxy with authentication.
- Clips are stored unencrypted on disk.
- No authentication on the dashboard — add auth before operational deployment.
- The implant polls over HTTPS in production (update `c2Base` in `CONFIG`).
