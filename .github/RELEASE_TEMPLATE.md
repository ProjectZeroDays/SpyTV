# SpyTV v{{VERSION}} Release

## Overview
SpyTV is an authorization-first platform for assessing smart TVs on client networks, plus the defensive toolkit and defect review produced alongside it.

## New in this version
- **Standalone APK mode**: The APK can now run as a full local C2 server on Android devices
- **Console mode**: The APK can still connect to an external C2 server as a remote console
- **Mode toggle**: Switch between modes from the settings menu

## Release Assets

### SpyTV.apk (Android)
- APK with embedded standalone C2 server mode
- Run C2 operations directly on an Android device
- Compatible with Android 7.0+ (API 24+)
- Install via: `adb install SpyTV.apk`

### SpyTV-C2-standalone.exe (Windows)  
- Bundled Python C2 server with dashboard
- Runs without installing Python separately
- Includes offline dashboard fallback

### SHA256SUMS.txt
- SHA-256 checksum manifest for all release assets

## Usage

### APK Standalone Mode
1. Install the APK on an Android device
2. Launch SpyTV
3. Tap the ⚙ settings button
4. Select "Standalone Mode" to run a local C2 server
5. The server starts on port 8443

### APK Console Mode
1. Install the APK on an Android device  
2. Ensure the C2 server is running on another device
3. Launch SpyTV
4. Enter the C2 server's LAN IP address
5. The dashboard loads in the WebView

### Web/EXE Mode
```bash
python c2_server.py
# or
SpyTV-C2-standalone.exe
# Then open http://<ip>:8443/ in a browser
```

## Security
- Authorization required for all audits (e-signature flow)
- All exploit modules are dry-run by default
- No unauthorized use is permitted

---
© 2026 Authenticated, Inc. All rights reserved.
