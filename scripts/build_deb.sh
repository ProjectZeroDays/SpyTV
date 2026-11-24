#!/bin/bash
# Build .deb package for the SpyTV C2 desktop client.
# Preferred: electron-builder (fpm). On hosts where fpm is broken
# (electron-builder's fpm crashes on Windows with 0xC0000005), fall back to
# the pure-Python packager, which consumes the linux-unpacked tree that
# electron-builder produces before the packaging step fails.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${VERSION:-4.6.1}

cd electron
if npx electron-builder --linux deb; then
  echo ".deb written to electron/dist/"
  exit 0
fi
cd ..
echo "electron-builder fpm step failed; using Python packager" >&2
if [ ! -f electron/dist/linux-unpacked/resources/py/c2_server.py ]; then
  echo "electron/dist/linux-unpacked is missing — run 'npx electron-builder --linux deb' once first" >&2
  exit 1
fi
python scripts/build_deb_py.py --root electron/dist/linux-unpacked \
  --out "electron/dist/spytv-c2_${VERSION}_amd64.deb" --version "$VERSION"
