#!/bin/bash
# Build .deb package for SpyTV C2 (Linux/VM)
# Requires: dpkg-deb, fakeroot, electron-builder or manual packaging
set -euo pipefail
VERSION=${VERSION:-4.5.2}
PKGDIR="build/deb/packages/SpyTV-c2_${VERSION}_amd64"
mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/usr/share/SpyTV-c2" "$PKGDIR/usr/bin"
cp -r electron/dist/win-unpacked/* "$PKGDIR/usr/share/SpyTV-c2/" 2>/dev/null || cp -r electron/dist/SpyTV\ C2\ 4.5.2.exe "$PKGDIR/usr/share/SpyTV-c2/" 2>/dev/null || echo "No electron dist; package Python C2 instead"
# Fallback: package Python server as deb
cp c2_server.py c2_dashboard.html run_c2.bat requirements.txt "$PKGDIR/usr/share/SpyTV-c2/" 2>/dev/null || true
cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: spytv-c2
Version: ${VERSION}
Section: net
Priority: optional
Architecture: amd64
Depends: python3, python3-yaml, python3-requests, python3-colorama
Maintainer: Authenticated, Inc.
Description: SpyTV C2 — TV Security Assessment Platform
 The full C2 server, dashboard, and defensive toolkit for
 smart-TV security assessment.
EOF
echo "Built .deb in $PKGDIR (run dpkg-deb --build $PKGDIR)"
