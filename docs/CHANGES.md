# SpyTV Code Changes Log

## [2026-10-04] — /Push Release Pipeline: error-correct, refactor, tests, debug

### New command
- **`/Push`** (`.opencode/commands/push.md`) — full release pipeline: error-correct
  & refactor → test all code → debug → generate release assets → push → merge into
  `main` (fixing merge blockers) → delete superseded branches → tag + GitHub release
  with all assets

### Error correction / refactoring
- **`core/implant.py`** — was a stale markdown-wrapped JS snippet (invalid Python,
  broke `compileall`, port drift vs. live implant). Refactored into a valid module
  that exposes the canonical implant source from `tvreaper.js` (single source of
  truth): `get_implant_js()` / `implant_path()`
- **`c2_server.py` `/api/scan` deadlock fixed** — `save_scans()` (which acquires the
  non-reentrant `scans_lock`) was called *while holding the lock*, hanging the scan
  handler. Extracted into `record_scan_results()` which releases the lock before
  persisting
- `file_structure.txt` description updated for `implant.py`

### Tests (39 → 42)
- `tests/test_c2_server.py` — regression tests: scan persistence never deadlocks on
  `scans_lock`, history caps at 100 entries, implant module exposes `tvreaper.js`
- Full verification: `pytest` 42/42, `py_compile` over all tracked `.py`, dashboard
  `<script>` block + `tvreaper.js` pass `node --check`, all YAML parses

### Release
- Release APK asset standardized as **`SpyTV.apk`** (builder `create_apk.py`
  updated) with `SHA256SUMS.txt` checksum manifest attached to releases
- Repo default branch: **`main`** (superseded `master` deleted after merge)

## [2026-10-04] — CVE Feed Pipeline, AI Auto-Exploit Generation, Live Patching

### Vulnerability updater run
- Ran the NVD updater against the smart-TV keyword set — **2 new CVEs ingested**:
  - **CVE-2026-87588** (HIGH 8.8) — Chromecast/Chrome use-after-free, fixed in Chrome 153.0.8010.36
  - **CVE-2026-95372** (HIGH 8.3) — Chromecast/Chrome sandbox escape, fixed in Chrome 154.0.8037.57
- Updates log to **`CVE_UPDATES.log` in the repo root** (JSONL: id, severity, score, description, NVD + whitepaper links, exploit status). The feed replays this file if `c2_data/cve_state.json` is cleared, so root-log entries are always addable to the C2.

### New files
- `c2_cve_feed.py` — feed manager: NVD 2.0 fetch (rate-limit aware), root update log, `.env`/JSON key resolution, AI exploit generation, per-CVE whitepaper rendering
- `core/cve_scanner.py` — 8-family TV CVE database (adds **chromecast** family, 28 CVEs total), family detection, patch command sets
- `data/exploits/cve_exploits.py` — working exploit modules per family incl. new **ChromecastExploit** (CVE-2026-87588 / CVE-2026-95372 staged via cast setup endpoint)
- `run_c2.bat` — launcher that **checks `.env` for AI keys first**; if none are present it prompts to add OpenRouter / Venice AI / Abliteration.ai keys or skip, then starts the C2
- `.env.example` — key template (`.env` is git-ignored)

### CVE Monitor tab (C2 dashboard)
- **Update CVEs** button → background NVD fetch; status banner + feed polling until complete
- **AI Provider Keys** panel: OpenRouter (Uncensored), Venice AI (Uncensored V 1.2 / Qwen 3.6 Plus Uncensored / GLM 4.7 Flash Heretic), Abliteration.ai (Abliterated Large v2); masked status, Save Keys, **Test Generate**
- Auto-generation: every newly ingested CVE gets an exploit module written to `data/exploits/generated/CVE-*.py` when any provider key is configured

### CVE Feed sidebar (right side of every tab)
- Entry list with severity badge, description, **NVD Advisory** link and **Whitepaper** link (`/api/cve/whitepaper/<id>`), "⚡ exploit ready" marker
- Header shows total count + last-update time (and "Updating…" during refresh)
- Loads at page start, on demand, and every 60 s; responsive layout (moves below content under 1280 px)

### Patch logic (live execution)
- `POST /api/cve/patch` now **executes** the family's remediation commands (shlex-split, 45 s timeout, per-command status/output), marks matching devices `patched` + `patched_cves`
- **Patch button under each device card** → runs CVE remediation first, then sends the implant `patch` command; activity log shows per-command results
- **Patch button on each scan row** → same execution path
- CVE table Patch button now targets the newest scanned device of that family (prompt fallback)
- Fixed non-reentrant `devices_lock` deadlock in patch/exfil/poll handlers (server hang)

### Scanning logic
- `/api/scan` merges CVE-database signature ports (26101 Tizen, 30000 webOS, 8009 Cast, 56789 Hisense, …) and attaches matched `cves`, severity, MAC, Bluetooth, SSH per host
- Device cards show family-specific **CVE chips** (severity-colored, fixed-in tooltip) with "Patched" state
- Chromecast/Google TV family added end-to-end (scan → exploit → patch → controls)

### Docs & help
- TROUBLESHOOTING + Wiki header links now served **from the C2** at `/docs/*.md` (rendered HTML, works remotely)
- `docs/TROUBLESHOOTING.md`: new sections for CVE feed, AI exploit generation, patch failures; corrected log-file list
- `docs/C2_DASHBOARD.md`: feed, AI keys, new endpoints, file structure
- Help icons ( ? ) and tooltips updated for Network Scan, CVE Monitor, feed sidebar, patch buttons

### Fixes
- `datetime.utcnow()` deprecation → timezone-aware `utc_now_iso()` (Python 3.14)
- `handle_scan` local-shadowing bug on `scans` (results never persisted)
- `.gitignore`: track `CVE_UPDATES.log` + generated exploits; ignore `.env` and `ai_keys.json`

### Testing
- 39/39 pytest pass; dashboard JS syntax-checked with `node --check`
- End-to-end verified: feed update, patch execution (3/3 chromecast commands, `cves_fixed` returned), AI key save/status, register/poll implant flow, `/docs/*` rendering

## [2026-10-03] — Code Review Fixes + C2 Dashboard

### Code Review Fixes (CR-01 through CR-56)

#### Core Framework
- **CR-04**: `core/__init__.py` — `__all__` now uses strings instead of class objects
- **CR-05/06/07/08/09/10**: `core/scanner.py` — Fixed integer port keys, vuln matching, scan flags, port table overlap, ANSI alignment, failure detection
- **CR-11–19**: `core/stealth.py` — Platform guard for Windows imports, proper CONTEXT struct, CREATE_SUSPENDED flag, WinAPI argtypes/restype, Poisson timing fix, proxy chain config, network discovery fix
- **CR-20–24**: `core/stream_manager.py` — Fixed VLC --sout syntax, recording options, timeout return, input MRL, mic mode stub
- **CR-01/25–33**: `core/exploit_engine.py` — Fixed adb_port config path, class discovery in loader, run() signatures, menu key mapping, shell injection, params handling, brute-force branch
- **CR-34**: `core/session_manager.py` — Load existing sessions, timestamps, proper status
- **CR-41/52**: `core/exploit_dispatcher.py` — Fixed inverted which checks, added missing imports
- **CR-02**: `core/config.py` — Returns sensible defaults instead of empty dict
- **CR-38/39**: `core/discovery.py` — OUI lookup used, SSDP multicast join
- **CR-42**: `core/receiver.py` — ssl.SSLContext instead of removed ssl.wrap_socket
- **CR-50**: `core/builder.py` — Fixed ares-package args, gradlew existence check

#### Main & Config
- **CR-02/35/36**: `main.py` — Default config fallback, selected_target persisted, exception handling
- **CR-01/03**: `config.yaml` — Fixed key mismatches, removed duplicate ports

#### Exploit Modules
- **CR-26**: All exploit `run()` methods now accept `params` argument
- **CR-28/30**: `ssh_brute.py` — Shell injection fix, brute-force branch fix
- **CR-32**: `vendor_specific.py` — Proper success criteria

#### TVREAPER / SpyTV
- **CR-40/41/43/44**: `tv_install.py` — Fixed syntax error, inverted which checks, Tizen PUT body, Vizio DIAL ports
- **CR-45–48**: `tvreaper.js` — Real activity tracking for fake-off, mic capture cleanup, WAV sample rate, DNS label splitting
- **CR-42**: `tv_flow_receiver.py` — ssl.SSLContext, path traversal protection
- **CR-38/39**: `tv_fingerprint.py` — OUI lookup used, SSDP multicast join
- **CR-51**: `spytv_tagger.py` — Defined missing functions, fixed deprecated utcfromtimestamp
- **CR-49**: `build_widget.py` — Fixed malformed config.xml, added privilege declarations

#### Family Installers
- **CR-41**: `families/tizen/install.py` + `families/webos/install.py` — Fixed inverted which checks

#### Infrastructure
- **CR-37**: `setup.sh` + `setup.py` — proxychains4 consistency, venv for PEP 668
- **CR-53**: `tools/banner.py` — Removed corrupted glyphs; `requirements.txt` — Removed unused deps

### New: C2 Web Dashboard

#### Files Added
- `c2_server.py` — C2 HTTP server (port 8443)
- `c2_dashboard.html` — Web-based dashboard
- `logo.png` — C2 logo (64x64)

#### Dashboard Features
- **Device Grid**: 2x2 grid showing connected TVs with status
- **Video Thumbnails**: 2x2 thumbnail grid per device (latest 4 frames)
- **Audio Controls**: Built-in audio player for latest clip
- **Per-Device Controls**:
  - Record Audio (1-20 min)
  - Record Video (1-20 min)
  - Listen (live audio stream)
  - Watch (live video stream)
  - Remove (wipe implant + logs)
  - Patch (disable capture)
- **Activity Log**: Timestamped command history
- **Duration Selector**: 1, 2, 5, 10, 15, 20 minutes

#### Implant Updates
- Polls C2 every 5 seconds for commands
- Registers with C2 on boot
- Exfiltrates clips via `/api/exfil`
- Supports remote commands: record_audio, record_video, listen, watch, remove, patch

### Testing
- All 39 existing tests pass
- All modules import cleanly
- `tvreaper.js` passes Node.js syntax check
- C2 server starts and serves dashboard
