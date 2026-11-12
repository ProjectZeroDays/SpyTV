#!/bin/bash
# Build .ipa for iOS / iPad (requires macOS + Xcode in VM)
VERSION=${VERSION:-4.5.2}
echo "Building .ipa requires Xcode command-line tools (xcrun, xcodebuild)"
echo "Run on macOS VM with Apple Developer account configured"
# Electron does not support .ipa directly — wrap electron output or use Capacitor/Cordova
# For SpyTV (Electron desktop), .ipa is produced via:
# 1. Convert electron app to Cordova project
# 2. Build with xcodebuild
# 3. Sign + archive
if command -v xcodebuild &>/dev/null; then
  echo "xcodebuild available — attempting archive"
  # Placeholder: real .ipa build needs Cordova/iOS project setup
  echo "Placeholder .ipa build — full iOS build requires Cordova wrapper"
fi
