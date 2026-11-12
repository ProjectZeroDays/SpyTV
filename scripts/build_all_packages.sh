#!/bin/bash
# All package formats — run inside VM with required tools
VERSION=${VERSION:-4.5.2}
echo "=== SpyTV Package Build Matrix ==="
echo "  .deb     -> scripts/build_deb.sh (needs dpkg-deb)"
echo "  .snap    -> scripts/build_snap.sh (needs snapcraft)"
echo "  .flatpak -> scripts/build_flatpak.sh (needs flatpak-builder)"
echo "  .dmg     -> scripts/build_dmg.sh (needs electron-builder / macOS)"
echo "  .ipa     -> scripts/build_ipa.sh (needs Xcode / macOS VM)"
echo ""
echo "Run individually per VM environment. All outputs go to build/packages/"
