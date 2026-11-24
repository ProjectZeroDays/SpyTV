#!/bin/bash
# All package formats — run inside VM with required tools
VERSION=${VERSION:-4.6.1}
echo "=== SpyTV Package Build Matrix ==="
echo "  .deb     -> scripts/build_deb.sh (electron-builder; any host)"
echo "  .snap    -> scripts/build_snap.sh (needs snapcraft)"
echo "  .flatpak -> scripts/build_flatpak.sh (needs flatpak-builder)"
echo "  .dmg     -> scripts/build_dmg.sh (needs macOS)"
echo "  .ipa     -> scripts/build_ipa.sh (needs Xcode / macOS VM)"
echo ""
echo "Run individually per VM environment. All outputs go to build/packages/"
