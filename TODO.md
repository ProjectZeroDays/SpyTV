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
