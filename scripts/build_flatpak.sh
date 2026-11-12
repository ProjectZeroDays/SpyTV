#!/bin/bash
# Build Flatpak for SpyTV C2
# Requires: flatpak-builder (run in Linux VM)
VERSION=${VERSION:-4.5.2}
mkdir -p flatpak
cat > flatpak/com.authenticated.spytv-c2.json <<EOF
{
  "app-id": "com.authenticated.spytv-c2",
  "runtime": "org.freedesktop.Platform//22.08",
  "sdk": "org.freedesktop.Sdk//22.08",
  "command": "run_c2.sh",
  "modules": [{
    "name": "spytv-c2",
    "buildsystem": "simple",
    "build-commands": [
      "install -D c2_server.py /app/bin/c2_server.py",
      "install -D c2_dashboard.html /app/share/spytv-c2/dashboard.html"
    ],
    "sources": [{"type":"dir","path":".."}]
  }],
  "finish-args": [
    "--share=network",
    "--device=dri"
  ]
}
EOF
echo "Flatpak manifest at flatpak/com.authenticated.spytv-c2.json (build: flatpak-builder --force-clean flatpak/com.authenticated.spytv-c2.json)"
