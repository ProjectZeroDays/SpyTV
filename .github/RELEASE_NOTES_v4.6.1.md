## SpyTV v4.6.1

Patch release over v4.6.0.

### What's new
- **NSIS Windows installer** - `SpyTV-C2-Setup.exe` now ships as a first-class asset. Includes a license page, component picker, an optional "Python dependencies" section (venv + `pip install -r requirements.txt`) for running the C2 from source, and proper Add/Remove Programs registration with an uninstaller.
- **Dashboard update banner** - the web UI polls `/api/update/check` on load and shows a banner when a newer release is available, with a direct download link. Wired through `core/auto_update.py` against the GitHub Releases API.
- **Auto-update wiring fixes** - version bump endpoint and update-state plumbing completed.

### Assets
| File | Purpose |
|------|---------|
| `SpyTV-C2-Setup.exe` | Windows NSIS installer (recommended for Windows) |
| `SpyTV-C2-standalone.exe` | Frozen single-file C2 server, no install needed |
| `SpyTV.apk` | Android application with embedded C2 + dashboard |
| `SHA256SUMS.txt` | Checksums for all binaries |

### Verify
Each release asset's SHA256 is listed in `SHA256SUMS.txt`.
