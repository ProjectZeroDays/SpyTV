---
description: Universal release pipeline — repo cleanup, vulnerability sweep, error-correct, test, debug, build assets, push, merge, tag + release for any git-tracked repo
---

Run the complete release pipeline for the current repository (any project, not
project-specific). Work through every phase in order, fix anything that
fails, and report the result of each phase at the end.

The repo root is auto-detected (`git rev-parse --show-toplevel`). The GitHub
owner/repo is auto-detected from `git remote -v`.

Optional argument: $ARGUMENTS — a target tag like `v2.1.0`.
If empty, use the next semantic version after the latest GitHub release
(next patch if the latest tag is `vX.Y.Z`).

Each phase that depends on project-specific tooling (APK build, Electron audit,
YAML configs, etc.) is **skipped** with a note if the relevant file/dir is not
present, so the command works on any repo.

## Phase 1 — Error-correct & refactor
- `git status` / `git diff` review of all pending and recent changes.
- Fix obvious errors: broken imports, dead code, deprecated API usage,
  duplicated logic, inconsistent naming.
- Keep refactors behavior-preserving; do not redesign features.

## Phase 2 — Repo cleanup
- Untrack and remove junk that must not be in the repo: agent/tool state
  (`.mimosa/`, `.v2c/`, `.video_agent/`, `.zcode/`, `.zcodeignore`),
  `__pycache__`, build outputs (`node_modules/`, `dist/`, `build/`,
  `android/**/build`, `electron/dist`), stale logs — `git rm -r --cached`
  where tracked, delete from disk where untracked and stale.
- Extend `.gitignore` so every removed pattern stays out (verify by re-running
  `git status --ignored` afterwards — nothing new should appear).
- Confirm no secrets are tracked (`git ls-files` vs `*.key`, `*.pem`, `.env`,
  `ai_keys.json`); ignored-only is the rule.
- Delete dead/duplicate files ONLY after grepping that nothing references them.

## Phase 3 — Regenerate file_structure.txt
- If a `file_structure.txt` is tracked in the repo, rebuild it from
  `git ls-files` as an indented tree with one-line comments on root folders.
  It must reflect the tree AFTER Phase 2. Skip if the file is not present
  or not version-controlled.

## Phase 4 — Vulnerability sweep
- **Python**: If `requirements.txt` exists, run
  `python -m pip_audit -r requirements.txt` (install `pip-audit` if missing).
  Upgrade vulnerable pins to the minimum fixed versions; re-run Phase 5.
- **Node**: If `electron/` (or `package.json` at repo root) exists, run
  `npm audit` and resolve with `npm audit fix`, dependency bumps, and
  `overrides` for transitive packages (e.g. `tar`); never downgrade or ignore.
  Smoke `npx electron --version` after changes.
- **GitHub**: `gh api --paginate repos/<OWNER>/<REPO>/dependabot/alerts` (auto-
  detected from `git remote`). The open count must drop; any alert that remains
  needs an explicit "accepted" rationale in the report (e.g. dev-only package
  with no patched release published).
- Grep the tree for hardcoded credentials, embedded tokens, and dead URLs.
- Record fixed-vs-accepted in the final phase report.

## Phase 5 — Test all code
- If a `tests/` directory exists, run `python -m pytest -q` — every test must
  pass. Skip if no test suite is present.
- `python -m compileall -q` (or `py_compile` over all `.py` files).
- Syntax-check JS assets: if `c2_dashboard.html` or `tvreaper.js` exists,
  `node --check` on extracted script blocks.
- Parse all YAML configs if present (`*.yaml`, `*.yml`); verify
  `.env.example`/`.gitignore` consistency.

## Phase 6 — Debug
- Any failure from Phases 1–5 must be fixed and re-run until green.
- Watch for known traps: non-reentrant `threading.Lock` re-acquisition
  (deadlocks), stale processes holding port 8443, Windows PowerShell `;`
  vs `&&`, and concurrent Gradle builds racing on `android/app/build`
  (check for other Gradle processes before a build; wipe `app/build` after
  an interrupted run).

## Phase 7 — Generate release assets
- If `create_apk.py` exists, run `python create_apk.py` — builds the REAL
  Android APK from the Gradle project (`android/`, `assembleDebug`) and verifies
  it before writing the APK: zip integrity, `apksigner verify`,
  `aapt dump badging` (package + launchable activity), sane size (>1 MB).
- If `build_standalone_exe.py` exists, run it to produce the standalone EXE.
- If `electron/` exists, run `npm run build` or `npm run package`.
- Generate `SHA256SUMS.txt` covering every asset to be attached.

## Phase 8 — Push everything
- Commit all Phase 1–7 work with a clear message and `git push`.

## Phase 9 — Merge with main
- Ensure a `main` branch exists containing all current work (create it from
  the working branch if missing).
- If the merge is blocked by conflicts/issues, fix them, re-run Phase 5
  tests, then complete the merge.
- Make `main` the default branch on GitHub (`gh repo edit --default-branch
  main`), then delete superseded branches (local and remote, e.g. `master`).

## Phase 10 — Tag & release
- Create the next tag (default: bump patch from the latest release) on `main`
  and push it. The tag name is auto-derived: if the latest GitHub release is
  `vX.Y.Z`, the next tag is `vX.Y.(Z+1)`.
- `gh release create <tag>` titled `<REPO_NAME> <tag> — release` (auto-
  detected repo name from `git remote`), with release notes summarizing the
  changes, and attach **all** generated assets from Phase 7.
- Verify with `gh release view <tag>`.

Finish with a concise phase-by-phase report (cleanup removed, vulnerabilities
fixed/accepted, tests run, fixes made, assets, branches merged/deleted,
tag + release URL).
