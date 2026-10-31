#!/bin/bash
# Build .dmg for macOS (run on macOS VM or with electron-builder --mac dmg)
VERSION=${VERSION:-4.5.2}
echo "Building macOS .dmg..."
# Uses electron-builder with mac target or create-dmg
if command -v electron-builder &>/dev/null; then
  electron-builder --mac dmg --dir
  echo ".dmg written to electron/dist/SpyTV-C2-${VERSION}.dmg"
else
  echo "electron-builder not found — install: npm install -g electron-builder"
  echo "Alternative: use create-dmg (brew install create-dmg) manually"
fi
