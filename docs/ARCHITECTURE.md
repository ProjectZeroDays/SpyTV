# SpyTV — Architecture

**Core philosophy:** authorization-gated, modular, and layered. Network
discovery drills down into family-specific exploits through a centralized
dispatcher; every engagement runs through a state machine that requires a
**dual-signed authorization instrument** before a single packet is sent;
every new CVE produces a complete, tested artifact set instead of a lone
exploit file.

## Platform overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│ PRESENTATION                                                             │
│   c2_dashboard.html   responsive SPA (equal-width viewer panel,          │
│                       Audit/Patch All modals, e-sign pad, live banner)   │
│   electron/           desktop wrapper → SpyTV-C2-<ver>-portable.exe      │
├──────────────────────────────────────────────────────────────────────────┤
│ C2 SERVER — c2_server.py (HTTP + TLS, port 8443)                         │
│   routing · device/clip/command registries · scan history · feed thread  │
│   /api/devices /api/clips /api/commands /api/scans /api/check            │
│   /api/cve/* /api/audit/* /api/patch/* /api/host_info /api/connections/* │
│   /api/exploit /api/local_ip /api/ai-keys /api/register /api/poll        │
├────────────────────────────────┬─────────────────────────────────────────┤
│ ENGAGEMENT LAYER — c2_audit.py │ CVE FEED + ARTIFACT PIPELINE            │
│   AuditEngagement              │   c2_cve_feed.py                        │
│     discover → verify (RO) →   │   NVD 2.0 → c2_data/cve_state.json      │
│     exploit → kill → report    │   AI exploit + artifact set per new CVE: │
│   PatchEngagement              │     whitepaper  docs/whitepapers/       │
│     patch-all → client →       │     test        tests/generated/        │
│     remediation proof report   │       (must pass pytest or the exploit   │
│   Authorization instrument     │        is quarantined)                  │
│     10 clauses, ESIGN/UETA,    │     signature   data/signatures/        │
│     provider pre-signature,    │     patch check data/patch_checks/      │
│     client e-sign, SHA-256     │     enrichment  CWE/CPE/fixed-in/AV     │
│     record hash + audit trail  │   JSONL status → CVE_UPDATES.log        │
├────────────────────────────────┴─────────────────────────────────────────┤
│ SHARED OPS — c2_ops.py (stateless, dependency-injected into both sides)  │
│   perform_scan · check_target (read-only) · run_exploit (dry-run-first)  │
│   execute_patches · kill_all_connections · probe_ports                   │
├──────────────────────────────────────────────────────────────────────────┤
│ ASSESSMENT FRAMEWORK                                                     │
│   core/        discovery · exploit dispatcher · receiver · withdrawal    │
│                implant accessor (tvreaper.js) · config                   │
│   families/    tizen · webos · android · dlna · hbbtv (per-family mods)  │
│   tvreaper.js  implant (C2 polling, capture, exfil)                      │
├──────────────────────────────────────────────────────────────────────────┤
│ STORAGE                                                                  │
│   c2_data/                 audits/<auth_id>/ · clips/ · registries (git- │
│                            ignored) · ai_keys.json · cve_state.json      │
│   data/exploits/generated/  CVE-*.py (CVE-*.quarantined on test failure) │
│   docs/whitepapers/ · data/signatures/ · data/patch_checks/ (tracked)    │
│   CVE_UPDATES.log           root JSONL — replayed into the feed          │
├──────────────────────────────────────────────────────────────────────────┤
│ DEFENSE TOOLKIT — defense/ (stdlib only)                                 │
│   hardening/ (attack-surface · ADB · UPnP · VLAN · firmware)             │
│   detection/ (ssh/adb/ssdp detectors · monitor · drill · Sigma rules)    │
│   cve_monitor/ (NVD watcher · defensive whitepaper generator)            │
└──────────────────────────────────────────────────────────────────────────┘
```

## Engagement request flow (Audit button)

```
operator clicks Audit
   └─ POST /api/audit/authorize   (6 client fields validated)
        └─ unsigned authorization PDF written → c2_data/audits/<auth_id>/
   └─ e-sign modal: PDF preview + signature pad
        └─ POST /api/audit/sign   (base64 PNG validated: magic bytes, 400 KB cap)
             ├─ provider block: pre-signed "/s/ Ian", Assessment Lead (Authenticated, Inc.)
             ├─ client signature + company embedded
             ├─ SHA-256 record hash + audit trail (doc id, UTC times, signer IP)
             └─ AuditEngagement starts  (server-owned state — survives reloads)
                  discover → read-only verify → exploit → kill + verify → report
   └─ GET /api/audit/status  (banner polls every 2 s)
   └─ GET /api/audit/report.pdf   (auto-rendered — client info captured up front)
```

Patch All inverts the order: **patch everything first**, then collect client
details and render the remediation proof report (patched — or not, with the
reason per device/CVE).

## CVE artifact pipeline (per new CVE)

```
NVD fetch (background thread at C2 start / Update CVEs)
   └─ new CVE → update_cve_database()
        ├─ exploit generation (AI provider; skipped without a key)
        └─ build_artifact_set()   ← one artifact at a time, failures isolated
             ├─ whitepaper  → docs/whitepapers/CVE-*.md   (AI draft | template)
             ├─ test        → tests/generated/test_CVE-*.py
             │                 real pytest run → pass: flag set
             │                                → fail: template → still fail:
             │                                  exploit → .quarantined
             ├─ signature   → data/signatures/CVE-*.md     (proposal — never auto-merged)
             ├─ patch check → data/patch_checks/CVE-*.md
             ├─ enrichment  → feed entry (CWE, affected CPEs, fixed-in, attack vector)
             └─ log         → JSONL "artifacts" event per CVE in CVE_UPDATES.log
```

Feed entries carry `whitepaper_generated`, `tests_generated`,
`signature_generated`, `patch_check_generated`; the dashboard's Output panel
reads them via `GET /api/cve/artifacts/<id>`.

## Assessment framework stack (subsystem)

The core framework the C2 drives:

```
CLIENT (RUNNER)   discovery.py → install.py (dispatcher) → withdraw.py
       ↓
DEPLOYMENT        setup.sh · build.py · config.yaml
       ↓
EXPLORATION       SSDP/port fingerprint · port scanner · OUI lookup
       ↓
ENTRY SURFACE     pluggable per-family modules
                  Tizen Dev · WebOS Dev · HbbTV AIT · DLNA inject · ADB net
       ↓
IMPLANT           tvreaper.js — power-key liveness, A/V capture, dual exfil
       ↓
COLLECTION        C2 receiver (HTTP/HTTPS) → clip storage + capture table
```

## Design decisions

- **Dependency injection, no cycles** — `c2_server.py` imports operations
  from `c2_ops.py` and machines from `c2_audit.py`, passing lambdas into the
  engagement runners so the audit module never imports the server.
- **Stateless ops, stateful engagements** — ops functions take explicit
  inputs; engagement state lives server-side and is re-attached on reload.
- **Dry-run first** — exploit checks transmit no payloads; live execution is
  an explicit engagement step against authorized targets.
- **Server-owned flow** — engagement phase/progress live in the server, not
  the browser, so reloads, second tabs, and the desktop app stay consistent.
- **Prove generated code** — every generated exploit test runs in a
  sandboxed pytest subprocess before `tests_generated` is granted.
