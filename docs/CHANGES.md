# SpyTV Code Changes Log

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
