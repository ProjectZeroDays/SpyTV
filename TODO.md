# SpyTV — TODO / Backlog

> Living task list. Move completed items to `docs/CHANGES.md` when shipped.

---

## T-01: AI-generated whitepapers for every exploited CVE + in-dashboard viewer panel

**Status:** Not started
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

- [ ] New CVE with an exploit generated also has a whitepaper file
- [ ] "View Whitepaper" button renders it in the right panel
- [ ] "View Vulnerability Info" button renders vuln details in the right panel
- [ ] Right panel is equal width to the left card
- [ ] Each button press replaces the previous panel content
- [ ] Panel resets on C2/dashboard start
- [ ] Tests pass; docs + tooltips updated

---

## T-02: AI-generated tests + all relevant artifacts for every new exploit

**Status:** Not started
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

- [ ] New exploit CVE also has `tests/generated/test_CVE-*.py`
- [ ] Generated tests pass under `pytest` (or entry flagged as failed)
- [ ] Tests are offline/mocked — no live device calls
- [ ] Whitepaper, detection signature, patch check, feed enrichment,
      docs blurb each generated where applicable and flagged per-entry
- [ ] All artifact statuses logged to root `CVE_UPDATES.log`
- [ ] Partial failures don't abort the CVE update run
- [ ] `docs/C2_DASHBOARD.md` + tooltips document the artifact set
