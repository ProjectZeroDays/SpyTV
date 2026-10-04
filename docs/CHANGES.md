# SpyTV Code Changes Log

## [2026-10-04] — Scan froze at 5% for 37 minutes: parallel discovery, live progress, non-blocking C2 · brand artwork becomes every app icon (v1.0.5)

### Why the engagement sat on 5%
- The engagement reported **once** before discovery and once after:
  `set_phase("scanning", 5)` → `perform_scan()` → `set_phase("checking", 25)`.
  Nothing moved the bar in between. Read off the live C2's
  `/api/audit/status`: `"[scanning] 5%"` at `13:16:04`, next log line
  `"Scan complete: 2 host(s)"` at `13:53:04` — **37 minutes pinned at 5%**.
- The scan was the cause. Two *sequential* passes over every host in the CIDR
  (`c2_ops.scan_network`, 12 ports, then `cve_scanner.scan_network`, 16 ports)
  each probe with `settimeout(0.3)`. A host that doesn't exist never sends a
  reset, so **every** probe pays the full 0.3s — measured on the local `/24`,
  pass 1 alone took **942.1s** (~15.7 min), pass 2 ~20 min more.
- Nothing in the repo restarts the C2 (neither `.bat` has a loop, Electron
  only *views* the dashboard and never spawns Python, teardown only kills
  child tool processes, and Windows has no crash record for `python.exe`):
  the "restart with a new terminal window" was the symptom of an operator
  restarting an app that had gone unresponsive, not a watchdog.

### Discovery is parallel and reports as it runs
- `probe_many()` / `probe_port()` (`core/cve_scanner.py`) probe
  `(host, port)` jobs through a bounded pool of 64 workers, keeping the old
  socket semantics exactly (never raises; a failed probe reads as closed).
  `MAX_SCAN_HOSTS`, the port lists and the family/CVE matching are unchanged.
- Measured on the same `/24`: pass 1 **942.1s → 15.1s (62×)**, pass 2
  **22.7s**, the whole `perform_scan()` **37.7s** — same hosts found (no
  findings dropped; checked against `127.0.0.1/32`).
- `perform_scan(cidr, scanner, progress_cb=None)` and
  `CVEScanner.scan_network(cidr, progress_cb=None)` emit a **monotonic
  0.0 → 1.0** across their three stages (0.55 generic / 0.15 extra CVE ports /
  0.30 CVE sweep). `Engagement.set_progress()` maps that onto the scanning
  phase's 5% → 25% slice, logging every 5 points. Callables wired the old
  way (`lambda cidr: …`) still work — the arity is sniffed, not caught.

### The C2 keeps answering while a scan runs
- `POST /api/scan` ran the entire discovery **inline** on a single-threaded
  `HTTPServer`, so device polling, engagement status and the desktop client's
  2s health check all stalled until it finished — the client fell back to its
  offline page and the C2 *read* as dead.
- `main()` now binds `ThreadingHTTPServer` (`daemon_threads` is already True);
  every shared structure (`devices` / `commands` / `scans` / `engagements` /
  `authorizations`) is guarded by its own lock.

### Every app icon now comes from the brand artwork
- Source of truth: `resources/logo_source.jpg` (1408×768). It is a JPEG, so
  the "transparent" backdrop is a baked grey/white checkerboard. `tools/make_icon.py`
  measures the disc's bounding box by luminance (disc ≈ `#141E27`, checkerboard
  ≥ `#CCC`), crops the largest square around it and paints everything outside
  the disc with the disc's own sampled fill — verified seamless (outside fill
  `[20,30,39]`, std **0**, no discontinuity at the rim).
- Outputs: `electron/icon.png` 1024² → desktop exe (embedded icon re-extracted
  and verified: corner `#141E27`, centre = the artwork), root `icon.png` 192² →
  widget builders, and Android `drawable-*/ic_launcher_{,round_}foreground.png`
  (108dp at every density bucket).
- The Android launcher used to be a **solid blue square** on v26 and a navy
  square with a plain blue circle on the legacy path. All four launcher XMLs
  now reference the artwork; the legacy round icon uses a pre-clipped circular
  PNG so it can't show square corners on a round launcher.

### Tests — 104 passed (+5)
- `test_scan_progress_advances_across_the_scanning_slice` — 5→10→15→20→25, never backwards.
- `test_run_scan_forwards_progress_when_scan_fn_accepts_it` and
  `test_run_scan_still_calls_single_argument_scan_fn` — new contract plus the old wiring.
- `test_other_requests_answer_while_a_scan_runs` — a 2s `/api/scan` must not
  stall `/api/scans` for more than 1s (fails on the old single-threaded server).
- `test_scan_pipeline_reports_monotonic_progress` — real sockets, 0.0 → 1.0.

## [2026-10-04] — Android console hit the wrong service: configurable C2 endpoint, probe-before-render, port diagnostics (v1.0.4)

### Why the console showed a JSON blob instead of the dashboard
- `MainActivity` loaded `http://localhost:8443/` unconditionally. On a device
  `localhost` **is the device**, so the WebView reached whatever else owned port
  8443 there and rendered that program's raw JSON
  (`…"version":"3.1.0","dashboard":"/dash","endpoints":[…]`) as if it were
  SpyTV. The C2 in this repo serves `text/html` at `/` and has no such endpoint.

### Android console
- **Configurable, persisted endpoint** — first-launch dialog, plus a **⚙**
  button / **C2 address** at any time. Accepts `host:port`, forces a scheme,
  requires a host, stores in `SharedPreferences`.
- **Probe before render** — unreachable, non-2xx, or a body without the
  dashboard marker (`TV Security Assessment Platform`) now shows an explicit
  error screen with the URL tried, the failure and the **raw response**, so the
  operator sees exactly what answered. Retry / change address from there.

### C2 server
- `SPYTV_C2_PORT` moves the whole platform (console, dashboard, generated
  implant payloads) without code edits; default stays 8443.
- Startup **diagnoses a squatted port** — which port, how to find the owner
  (`netstat` / `lsof`), how to move — instead of a bare `OSError` traceback, and
  prints the LAN URL to enter in the console.

### Tests
- `GET /` must serve the SpyTV dashboard HTML, never a JSON envelope (the
  contract the console checks), and `SPYTV_C2_PORT` must be honoured with the
  8443 default preserved.

## [2026-10-04] — Security sweep: real APK pipeline, dependency remediation, local-model provider, scan fixes (v1.0.3)

### Vulnerabilities fixed
- **electron ^33 → 44.5.1 / electron-builder 25.1.8 → 26.15.3** (`electron/`): clears all
  54 Dependabot alerts (electron CVEs, `tar`, `app-builder-lib`, `builder-util-runtime`);
  `npm audit` → **0 vulnerabilities**; `pip-audit -r requirements.txt` → clean.
- `extract-zip@2.0.1`: dev-only dependency with no patched release — accepted residual
  (not present in shipped artifacts).

### Android APK (the 1 KB placeholder is gone)
- `create_apk.py` now drives a **real Gradle build** (`android/`, `assembleDebug`) and
  verifies the artifact (zip integrity, `apksigner verify`, `aapt dump badging`, ≥1 MB)
  before writing `SpyTV.apk`; any failure exits non-zero and writes nothing.
- Restored `android/gradle/wrapper/gradle-wrapper.jar`; removed the AGP 8-blocking
  `package=` attribute from `AndroidManifest.xml`.

### Bug fixes found in the sweep
- `c2_ops.scan_network` + `core/cve_scanner.scan_network`: CIDR handling silently assumed
  `/24` (`base_ip + .1-.254`) — now enumerates real hosts via `ipaddress`, capped at 1024.
- `setup.sh`: dead `github.com/anonymous/spytv` URL → `ProjectZeroDays/SpyTV`; archive
  directory corrected to `SpyTV-main` (the old `mv spytv-main/*` failed silently).
- `core/builder.py`: restored the CR-49 Tizen privileges dropped during refactoring (with a
  declared `xmlns:tizen`), made `ares-package` optional (webOS CLI), and pointed `build_apk()`
  at the verified `create_apk.py` pipeline instead of the nonexistent `resources/apk/`.
- `build_widget.py`: declared `xmlns:tizen` (undeclared XML prefix), schema-correct
  `<tizen:privilege name=…/>` + `<feature>` elements, guarded `ares-package`.
- Added the missing `icon.png` (referenced by both widget builders — previously a hard
  crash); removed the dead duplicate `resources/tvreaper.js` (canonical implant is root
  `tvreaper.js`).

### Local model provider (GGUF / MLX)
- New keyless **`local`** provider in `AI_PROVIDERS`: point `LOCAL_LLM_ENDPOINT`
  (default `http://127.0.0.1:8080/v1/chat/completions`) at `llama-server` (GGUF) or
  `mlx_lm.server` (MLX) running on the C2 host. Auto-selection probes the endpoint
  (20 s cache) and only picks it while a server answers; the dashboard shows the endpoint
  instead of a masked key, and the saved "key" value doubles as an endpoint override.

### Repo hygiene / `/Push`
- Untracked agent-state junk (`.mimosa/`, `.v2c/`, `.video_agent/`, `.zcodeignore`) and
  hardened `.gitignore`; regenerated `file_structure.txt`.
- `/Push` extended with cleanup, `file_structure.txt` regeneration, and
  vulnerability-sweep phases.
- `SpyTV.apk` is no longer tracked — it is a **generated release asset** built on
  demand by `create_apk.py` (build outputs stay out of git).

### Release assets (v1.0.3)
- Desktop asset rebuilt on the new toolchain as `SpyTV-C2-1.0.3-portable.exe`
  (electron-builder 26.15.3, signtool-signed); `electron/package.json` +
  lockfile bumped to 1.0.3.
- **Branded desktop icon** — new `electron/icon.png` (1024×1024, dark `#0B0E14`
  tile, blue `#3B82F6` TV + eye) wired to `build.win.icon`, replacing the stock
  Electron icon. `tools/make_icon.py` regenerates it (drawn at 4096px and
  downsampled). The icon is a build-time input and is not packed into the asar.
- `SHA256SUMS.txt` regenerated for the attached asset set.

## [2026-10-04] — T-03 Audit + Patch-all with e-signed authorization, CVE whitepaper viewer & artifact pipeline (T-01/T-02), GUI overhaul, Electron wrapper (v1.0.2)

### Audit button (T-03, full flow)
- **`c2_ops.py` (new)** — stateless shared operations: network scan +
  family/CVE enrichment (`perform_scan`), read-only target verification
  (`check_target`), exploit registry loader + dry-run/live execution,
  patch execution (`execute_patches`), connection teardown
  (`kill_all_connections`). Imported by both the HTTP handlers and the
  engagement runners (injected via lambdas) so neither side imports the
  other — no circular imports.
- **`c2_audit.py` (new)** — engagement state machines + reportlab PDF
  builders:
  - `AuditEngagement`: scan → dry-run checks (no payloads) → send
    exploits → kill/verify connections → **auto-render report** (client
    captured up-front — no second prompt).
  - `PatchEngagement`: discover + patch every device first, then
    `awaiting_client` → remediation proof report (patched per device/CVE,
    or not-patched with the reason).
  - Industry-standard PDF machinery: branded cover, TOC (multiBuild),
    exec summary, scope & methodology, inventory, findings, risk matrix,
    remediation/attestation, recommendations, appendices, sign-off;
    severity colour-coding, header/footer, page numbers.
  - **Authorization instrument builder** — *Authorization to Perform a
    Security Assessment and Rules of Engagement*: 10 numbered clauses
    (parties, authorization statement, scope, out-of-scope, rules of
    engagement, confidentiality, liability, ESIGN Act 15 U.S.C. §7001 /
    UETA electronic-signature clause, term, execution), provider block
    **pre-signed by Authenticated, Inc.** ("/s/ Ian, Assessment Lead"),
    client signature image with `/s/` fallback, document-control table,
    SHA-256 record hash and an execution audit trail (doc ID, UTC
    timestamps, signer IP). Valid for 30 days (`AUTH_VALID_DAYS`).
- **New endpoints** (wired via dependency injection in `c2_server.py`):
  | Method | Path | Purpose |
  |---|---|---|
  | POST | `/api/audit/authorize` | validate 6 client fields → unsigned auth PDF |
  | POST | `/api/audit/sign` | validate drawn PNG signature → archive signed PDF → **start audit** |
  | GET | `/api/audit/status` | phase/progress/log/report_ready (survives reloads) |
  | GET | `/api/audit/report.pdf` | final audit report |
  | GET | `/api/audit/authorization.pdf` | `?auth_id=…[&state=unsigned\|signed]` |
  | POST | `/api/patch/start` | begin patch-all (discovery + registry) |
  | POST | `/api/patch/report` | client details → remediation PDF |
  | GET | `/api/patch/status` / `/api/patch/report.pdf` | progress / download |
  | POST | `/api/check` | read-only target verification (no payloads) |
  | GET | `/api/host_info` | real host facts (replaces simulated Server tab) |
  | POST | `/api/connections/kill` | teardown + verification |
- Archives under `c2_data/audits/<auth_id>/` (`authorization.pdf`,
  `authorization-signed.pdf`, `authorization.json` sidecar with record
  hash, `report.pdf`, `engagement.json`).
- Refactors: `handle_scan` → `c2_ops.perform_scan`, `serve_cve_patch` →
  `c2_ops.execute_patches` (removes duplicated inline logic), local
  `scan_network`/`utc_now_iso` deleted from `c2_server.py`.
- New `tests/test_audit_flow.py` (**19 tests**): client validation,
  authorization PDF structure (content extracted from compressed
  streams), record-hash determinism, signature decode + size cap, path
  traversal guard, both engagement machines end-to-end, every HTTP
  endpoint, dashboard static contract.

### Dashboard — GUI best practices + responsive pass
- **Audit** (amber) and **Patch All** (green) buttons in the Network
  Scan toolbar; shared `#engagement-status` banner under the nav with
  live phase, progress bar, last message and contextual actions
  (Report / Authorization / Dismiss).
- **Client details modal** (6 fields, labelled inputs, server-side error
  display, prefilled from `localStorage`) used by both flows.
- **Authorization e-sign modal**: inline PDF preview (iframe) + canvas
  signature pad (pointer events, devicePixelRatio-aware, `touch-action:
  none`), company confirmation, ESIGN notice, Clear/Cancel/Sign.
- Keyboard support: Escape closes dialogs, nav tabs keyboard-activatable
  (`role="tab"`, `tabindex`, `aria-selected`), backdrop click dismisses;
  `aria-live` banner, `:focus-visible` outlines, `prefers-reduced-motion`
  support, 44px touch targets on coarse pointers.
- Accessibility: AA-contrast fixes (button variants rebuilt against
  verified text colours, `--text-muted` raised to 5.4:1), labelled form
  fields, dialogs with `role="dialog"`/`aria-modal`.
- Responsive: `.table-scroll` wrappers for wide tables, form/auth grids
  collapse to one column, modals fit 96vw/92vh on phones, toolbar wraps,
  banner stacks on narrow screens.
- **Simulated data removed** (real data only): `loadServerInfo()` now
  reads `/api/host_info` (hostname, OS, Python, MAC, uptime — no more
  `AA:BB:CC:DD:EE:FF`/fake proxy/VPN/Tor rows); `checkTarget()` calls the
  real `/api/check`; `saveScanResults()` downloads the actual scan JSON;
  fake proxy/VPN/Tor/Tailscale identity buttons replaced by a real
  **Kill All Connections** (`/api/connections/kill`).
- **Payload tab deploy flow made real**: the Exploit button used to queue
  a `deploy` command under the target's bare IP — implant IDs are sha1
  hashes and the implant has no `deploy` handler, so nothing ever consumed
  it while the log claimed "Exploit deployed". New `POST /api/exploit`
  executes the actual family exploit module (`c2_ops.run_exploit`) and the
  activity log reports the module's genuine outcome (attempted / success /
  failure / timeout with duration and error detail). Families without a
  registered module (e.g. generic DLNA) get an honest 404 without running
  anything; a new `chromecast-cast` family option routes Chromecast scan
  targets to the real Chromecast module. Contract tests cover the endpoint
  (module execution, no-module refusal, IP validation) and the dashboard
  (phantom `deploy` flow must never return).

### Electron wrapper
- New `electron/` app (main.js, preload.js, offline.html) loading
  `http://127.0.0.1:8443/` with a reachability check and offline
  fallback page; built with electron-builder (portable target) →
  `dist/SpyTV-C2-1.0.2-portable.exe` (attached to this release).
  `electron/node_modules/` and `electron/dist/` are gitignored.

### Whitepaper viewer + CVE artifact pipeline (T-01 / T-02)
- **`build_artifact_set()` in `c2_cve_feed.py`** — full artifact pass per
  new CVE inside `update_cve_database()` (after exploit generation), one
  artifact and one CVE at a time; a partial failure never aborts the run:
  | Artifact | Location | Behaviour |
  |---|---|---|
  | Whitepaper | `docs/whitepapers/CVE-*.md` | AI draft when a provider key is configured, deterministic template fallback — file always exists |
  | Pytest test | `tests/generated/test_CVE-*.py` | must **pass a real pytest run** before `tests_generated` is set; failing AI draft → offline-safe template; still failing → exploit renamed `.quarantined`, `exploit_generated` cleared, failure logged |
  | Detection signature | `data/signatures/CVE-*.md` | proposal for `core/cve_scanner.py` family matching — assessor-validated, **never auto-merged** |
  | Patch check | `data/patch_checks/CVE-*.md` | remediation verification steps for Patch / Patch All |
  | Feed enrichment | feed entry | CWE list, affected CPEs, fixed version, attack vector + exploitability note (from NVD `weaknesses`/`configurations`/CVSS) |
  | Log records | `CVE_UPDATES.log` | one `artifacts` JSONL event per CVE with every flag + errors, `quarantined` in `update_summary` |
- Feed flags per entry: `whitepaper_generated`, `tests_generated`,
  `signature_generated`, `patch_check_generated`; AI failure on any draft
  falls back to the deterministic template (offline-complete pipeline).
- **New endpoints**: `GET /api/cve/whitepaper_doc/<id>` (markdown +
  `source: file|template` for the viewer) and `GET /api/cve/artifacts/<id>`
  (flags, file inventory, enrichment). `render_cve_whitepaper()` now embeds
  the generated markdown document when present.
- **Dashboard (T-01)**: right column is now equal width to the main card
  (`minmax(0,1fr) × 2`, stacking under 1280px) and holds a new **Output**
  panel — a single replaceable output area (`setOutput()` replaces prior
  content; `resetOutput()` on every C2 start) — plus the CVE feed. Every
  feed entry gained **View Whitepaper** (safe client-side markdown render:
  HTML-escaped before formatting, so AI content can't inject markup) and
  **View Vulnerability Info** (severity/CVSS/CWE/component/fixed-in/
  attack-vector/exploit status table, affected CPEs, then live artifact
  status from `/api/cve/artifacts/<id>`). Help tooltips + `docs/C2_DASHBOARD.md`
  document the viewer, the artifact set and the new endpoints.
- `tests/generated/.gitignore` — mirrors the `data/exploits/generated/`
  tracking exception (generated tests tracked, pytest scratch not).
- New `tests/test_cve_artifacts.py` (**21 tests**): template structure +
  XSS-safe markdown rendering, whitepaper file generation and source
  fallback, HTML page preferring the generated document, generated test
  passing a real pytest run, full artifact set + flags, AI-failure and
  single-artifact-failure isolation, test-failure quarantine, NVD
  enrichment, `update_cve_database` end-to-end (statuses logged, partial
  failure doesn't abort), both new HTTP endpoints, dashboard/docs contract.

### Housekeeping
- `requirements.txt`: `reportlab>=5.0.0`.
- Tests **42 → 82** (all green).

---

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
