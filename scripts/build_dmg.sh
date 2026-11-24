#!/bin/bash
# Build .dmg for the SpyTV C2 desktop client.
# Requires a macOS host (electron-builder can only build dmg on macOS).
# CI builds this on a macos-latest runner — see .github/workflows/build-desktop.yml.
set -euo pipefail
cd "$(dirname "$0")/../electron"
npx electron-builder --mac dmg
echo ".dmg written to electron/dist/"
