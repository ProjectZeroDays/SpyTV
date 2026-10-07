# SpyTV — TODO / Backlog

> Living task list. Move completed items to `docs/CHANGES.md` when shipped.

---

## T-01: AI-generated whitepapers for every exploited CVE + in-dashboard viewer panel

**Status:** ✅ Complete — 2026-10-04 (ships with v1.0.2)
**Requested:** 2026-10-04
**Area:** `c2_cve_feed.py`, `c2_server.py`, `c2_dashboard.html`

### Requirements

1. **Auto-generate whitepapers alongside exploits**
   - When the AI provider generates an exploit module for a new CVE
     (`data/exploits/generated/CVE-*.py`), it must **also** create/add a
     whitepaper document for that same CVE.
   - Applies to all new CVEs where an exploit was created — the whitepaper
     generation is chained to the exploit-generation step in
     `update_cve_database()` / `generate_exploit_with_ai()`.
   - Store per-CVE whitepapers (e.g. `docs/whitepapers/CVE-*.md` and/or in
     `c2_data/`), linked to the feed entry (`whitepaper_generated: true`).

2. **Two new buttons in the C2**
   - **"View Whitepaper"** — opens/renders the AI whitepaper for the exploit's CVE.
   - **"View Vulnerability Info"** — opens/renders vulnerability details
     (description, severity/CVSS, affected component/family, fixed version,
     references, exploit status).

3. **Right-side vertical output panel (replace-in-place view)**
   - Information populates in a **vertical web card on the right side**,
     **the same width as the card on the left** (the current 340px feed
     sidebar / main-content column — make the two columns equal width).
   - The panel is a **single replaceable output area**: pressing any of the
     buttons above (or other buttons designated to display output there)
     **replaces whatever was previously displayed** — no stacking/append.
   - The panel **refreshes at C2 start** (initial load resets it to its
     default/empty state alongside the feed reload).

### Notes / constraints

- Reuse the existing whitepaper renderer (`render_cve_whitepaper()`) or
  extend it to prefer the AI-generated document when present.
- Keep the current NVD + whitepaper links in the feed sidebar working.
- Responsive: under the current 1280px breakpoint the right panel should
  stack below the main content like the feed panel does.
- Update help icon/tooltip text and `docs/C2_DASHBOARD.md` when implemented.

### Acceptance checklist

- [x] New CVE with an exploit generated also has a whitepaper file
- [x] "View Whitepaper" button renders it in the right panel
- [x] "View Vulnerability Info" button renders vuln details in the right panel
- [x] Right panel is equal width to the left card
- [x] Each button press replaces the previous panel content
- [x] Panel resets on C2/dashboard start
- [x] Tests pass; docs + tooltips updated

**Shipped (2026-10-04):** whitepapers land in `docs/whitepapers/CVE-*.md`
(AI draft via `build_artifact_set()` when a provider key is configured,
deterministic template fallback otherwise — the file always exists) with
`whitepaper_generated` on every feed entry. New `GET /api/cve/whitepaper_doc/<id>`
serves the markdown (file → template fallback) to the new **Output** panel —
a right-column card equal width to the main card (`minmax(0,1fr) × 2`,
stacking under 1280px) that is fully replaced on every press (`setOutput()`)
and reset by `resetOutput()` in `init()`. `render_cve_whitepaper()` now
embeds the generated document when present. Both viewer buttons render on
every feed entry; help tooltips + `docs/C2_DASHBOARD.md` updated.
Covered by `tests/test_cve_artifacts.py` (21 tests; suite 61 → 82 green).

---

## T-02: AI-generated tests + all relevant artifacts for every new exploit

**Status:** ✅ Complete — 2026-10-04 (ships with v1.0.2)
**Requested:** 2026-10-04
**Area:** `c2_cve_feed.py`, `tests/`, `c2_server.py`

### Requirements

1. **AI generates a test for every new exploit module**
   - When `generate_exploit_with_ai()` writes
     `data/exploits/generated/CVE-*.py`, the same AI call (or a follow-up
     call) must also produce a pytest file, e.g.
     `tests/generated/test_CVE-*.py`.
   - Generated tests must be **safe by default**: import/structure checks,
     constructor/config validation, and dry-run or mocked-transport
     execution — **no live network traffic** to real devices.
   - Tests must validate the exploit's public surface (class exists,
     `run()`/family interface matches `core/cve_scanner.py` contract,
     family/CVE ID metadata correct) and exercise error paths.
   - Generated tests must actually pass in `pytest` before the exploit is
     marked `exploit_generated` (quarantine on failure, flag the feed entry
     `tests_generated: false` + log the failure).

2. **Everything else relevant gets generated too** — the CVE-update AI
   pass should emit the full artifact set per new exploited CVE, not just
   the exploit:
   - **Whitepaper** (see T-01).
   - **Detection signature** — scanner/port fingerprint additions or a
     snippet for `core/cve_scanner.py` family matching (validated, not
     auto-merged blindly).
   - **Patch/remediation check** — verification command(s) for the
     existing Patch button's family remediation list, if the CVE needs one.
   - **Feed enrichment** — CWE, affected versions/products, fixed version,
     exploitability notes (EPSS/attack vector) for the dashboard card.
   - **Docs blurb** — short entry for `docs/CHANGES.md` /
     `CVE_UPDATES.log` describing what was generated.
   - Each artifact gets its own status flag on the feed entry
     (`whitepaper_generated`, `tests_generated`, `signature_generated`,
     `patch_check_generated`) and each lands in the JSONL root log.

3. **Pipeline wiring**
   - All generation happens inside `update_cve_database()`'s background
     thread at C2 start (and via the "Update CVEs" button) so the server
     still boots immediately.
   - Failures are per-artifact: a failed test generation must not roll
     back the exploit or block the feed; record the error on the entry.

### Notes / constraints

- Reuse one prompt/config per CVE where possible to limit token spend;
  sequential provider calls with backoff like the current exploit call.
- Generated tests live in `tests/generated/` with its own `.gitignore`
  exception (mirroring `data/exploits/generated/`).
- Keep the 39 existing tests green — never overwrite hand-written tests.
- Add a `/api/cve/artifacts/<cve_id>` status endpoint if the dashboard
  needs to show which artifacts exist (pairs with T-01's viewer panel).

### Acceptance checklist

- [x] New exploit CVE also has `tests/generated/test_CVE-*.py`
- [x] Generated tests pass under `pytest` (or entry flagged as failed)
- [x] Tests are offline/mocked — no live device calls
- [x] Whitepaper, detection signature, patch check, feed enrichment,
      docs blurb each generated where applicable and flagged per-entry
- [x] All artifact statuses logged to root `CVE_UPDATES.log`
- [x] Partial failures don't abort the CVE update run
- [x] `docs/C2_DASHBOARD.md` + tooltips document the artifact set

**Shipped (2026-10-04):** `build_artifact_set()` runs per new CVE inside
`update_cve_database()` — whitepaper (`docs/whitepapers/`), pytest test
(`tests/generated/test_CVE-*.py`, **validated with a real pytest run**;
AI draft falls back to the offline-safe template when it fails; if the
test still can't pass the exploit is renamed `.quarantined`,
`exploit_generated` cleared and the failure logged), detection-signature
proposal (`data/signatures/`, assessor-validated — never auto-merged),
patch check (`data/patch_checks/`), NVD enrichment (CWE / affected CPEs /
fixed-in / attack vector + exploitability note) and a docs blurb per CVE.
Flags `whitepaper_generated` / `tests_generated` / `signature_generated` /
`patch_check_generated` on every feed entry; one JSONL `artifacts` event
per CVE in root `CVE_UPDATES.log` (+ `quarantined` in `update_summary`);
per-artifact and per-CVE isolation keeps partial failures from aborting
the run. `GET /api/cve/artifacts/<id>` exposes the inventory; the Output
panel's "View Vulnerability Info" renders it. `tests/generated/.gitignore`
mirrors the `data/exploits/generated/` tracking exception.
Covered by `tests/test_cve_artifacts.py` (suite 61 → 82 green).

---

## T-03: One-click "Audit" — full network audit → connection teardown → PDF Red Team report

**Status:** ✅ Complete (2026-10-04) — shipped with v1.0.2, incl. authorization
e-sign gate and the companion **Patch-all** engagement
**Requested:** 2026-10-04
**Area:** `c2_server.py`, `c2_dashboard.html`, new `c2_audit.py` (PDF
builders), new `c2_ops.py` (shared ops), `tests/test_audit_flow.py`

### Overview

A single **"Audit"** button that runs the complete engagement end-to-end.
As amended on delivery, the flow is gated by a signed authorization:

1. **Client details first** — modal form: **company, name (authorized rep),
   address, phone, email, website** (validated before anything runs).
2. **Authorization instrument** — an industry-standard *Authorization to
   Perform a Security Assessment and Rules of Engagement* PDF (numbered
   clauses 1–10: parties, authorization statement, scope, out of scope,
   rules of engagement, confidentiality, disclaimer/liability, ESIGN/UETA
   electronic-signature clause, term, execution) is generated and saved
   locally under `c2_data/audits/<auth_id>/authorization.pdf`, pre-signed
   by Authenticated, Inc. ("/s/ Ian, Assessment Lead") and shown in an
   iframe for the client to countersign on a signature pad.
3. **E-sign** — the client's drawn signature (PNG dataURL, validated) +
   client company name execute the instrument: signed PDF archived as
   `authorization-signed.pdf` with a SHA-256 record hash and audit trail
   (doc ID, UTC timestamps, signer IP) in `authorization.json` sidecar.
   **Only then does the audit start** — no signature, no test.
4. **Phases** — scan → check (dry-run, no payloads) → send exploits →
   kill all connections (verified) → report auto-renders (client info
   already known; **no second prompt**).
5. **Report** — industry-standard PDF (cover, contents, exec summary,
   scope & methodology, inventory, findings, risk, remediation,
   recommendations, appendix, sign-off) branded **Authenticated, Inc.**

The companion **Patch All** button patches every discovered/registered
device first, *then* collects the same client details and renders a
remediation report PDF proving what was patched — or which devices
could not be patched and why.

### Workflow (audit phases, with live progress in the dashboard)

After the authorization gate above, `AuditEngagement` runs:

1. **Scan** — scan the network for vulnerable TVs (shared
   `c2_ops.perform_scan` family/CVE matching); record every finding.
2. **Check (no send)** — for each discovered vuln TV, validate all
   applicable exploits **without sending them** (dry-run: signature match,
   target reachable, exploit module loads, preconditions OK).
3. **Send** — execute the exploits that passed the check; capture
   per-attempt result (success/fail, evidence).
4. **Kill all connections** — terminate every session/socket opened during
   the audit and verify nothing is left connected.
5. **PDF report** — generated automatically at the end of phase 4 (client
   details were captured up-front), downloadable from the status banner:
   - Cover page: **Authenticated, Inc.** as delivering company, client
     info block, engagement type ("Red Team / Vulnerability Audit"),
     date, report reference/ID.
   - Industry-standard structure: executive summary, scope & methodology,
     network/device inventory, findings per device (CVE, severity/CVSS,
     exploit check + execution results), risk ratings matrix,
     remediation/patch recommendations, conclusion, appendix
     (CVE feed references, tooling).
   - Professional layout: branded header/footer, page numbers,
     severity color-coding, tables.

### Technical notes

- New modules: `c2_audit.py` (`AuditEngagement` / `PatchEngagement` state
  machines + reportlab PDF builders) and `c2_ops.py` (stateless shared
  scan/check/patch/exploit/teardown ops injected by the server — no
  circular imports). Server-side engagement state guarded by
  `engagements_lock`; status survives page reloads (server owns it).
- Endpoints: `POST /api/audit/authorize` (client → unsigned auth PDF),
  `POST /api/audit/sign` (e-sign → starts audit), `GET /api/audit/status`,
  `GET /api/audit/report.pdf`, `GET /api/audit/authorization.pdf
  ?auth_id=…[&state=unsigned|signed]`; `POST /api/patch/start`,
  `POST /api/patch/report`, `GET /api/patch/status`,
  `GET /api/patch/report.pdf`; plus `POST /api/check` (read-only
  verification), `GET /api/host_info`, `POST /api/connections/kill`.
- PDF via `reportlab>=5.0.0` (in `requirements.txt`) — pure server-side
  generation, no browser print-to-PDF.
- Audit runs in a background thread; the shared status banner shows
  phase + progress + last message and polls every 2s.
- Archives under `c2_data/audits/<id>/` (report.pdf, engagement.json,
  authorization.pdf, authorization-signed.pdf, authorization.json).
- Signature: base64 PNG dataURL validated (magic bytes, size cap) before
  embedding; record hash = SHA-256 over client+signature+timestamp.
- Audit type field ("Red Team Vulnerability Audit") included so future
  variants (compliance, black-box) can reuse the same template.

### Acceptance checklist

- [x] "Audit" button runs all phases in order with visible progress
- [x] Authorization gate: client details → industry-standard form (10
      numbered clauses, ESIGN/UETA, provider pre-signed) → e-signature
      pad → audit starts only when executed
- [x] Signed instrument saved locally with SHA-256 record hash + audit
      trail (doc ID, UTC timestamps, signer IP)
- [x] Check phase verifies exploits without transmitting payloads
- [x] All connections/sessions killed and verified before report phase
- [x] Client form (company, name, address, phone, email, website)
      validated; no second prompt — report renders automatically
- [x] PDF renders with Authenticated, Inc. branding, client block, audit
      type, findings, risk ratings, recommendations
- [x] Report structure matches industry pentest-report conventions
- [x] Audit JSON + PDF archived under `c2_data/audits/`
- [x] Companion **Patch All**: patch every device first → client details →
      remediation proof report (patched / not-patched + why)
- [x] Docs/tooltips (`docs/C2_DASHBOARD.md`, help icons) updated

---

## v1.0.9 — Default to Self-Hosted C2 + Mode Selection Dialog

**Status:** ✅ Complete
**Area:** APK (`MainActivity.kt`, layout), `c2_server.py`, `run_c2.bat`, all platforms

### Requirements

1. **Default mode is Self-Hosted C2** on all platforms (APK, EXE, Web)
   - APK defaults to standalone mode (isStandaloneMode = true)
   - `run_c2.bat` defaults to self-hosted when run
   - `c2_server.py` runs self-hosted by default (interactive prompt for new users)

2. **Setup C2 Server dialog on app open** — two buttons:
   - **Self-Hosted**: Run the full C2 server on this device
   - **Connect-Remote**: Connect to an external C2 server

3. **Mode toggle in settings** (⚙ button) allows switching between modes

### Acceptance checklist

- [x] APK defaults to Self-Hosted mode on first run
- [x] APK shows "Setup C2 Server" dialog with two buttons: "Self-Hosted" / "Connect-Remote"
- [x] Mode toggle (top-right Switch) switches between Self-Hosted and Connect-Remote
- [x] Self-Hosted mode runs C2Server.kt on port 8443 with all API endpoints
- [x] Connect-Remote mode connects to external C2 URL (with address prompt)
- [x] EXE/standalone shows mode selection prompt on startup
- [x] run_c2.bat shows mode selection menu
- [x] All MD files updated with v1.0.9 release notes
- [x] SHA256SUMS.txt updated with new APK + EXE hashes
- [x] urllib3 pinned to >=2.8.0 (fixed moderate vulnerability)
