#!/bin/bash
# Build Snap for SpyTV C2
# Requires: snapcraft (run inside Ubuntu VM or snapcraft container)
VERSION=${VERSION:-4.5.2}
mkdir -p snap/meta
cat > snap/snapcraft.yaml <<EOF
name: spytv-c2
version: '${VERSION}'
summary: SpyTV C2 Security Assessment Platform
description: |
  Full C2 server, web dashboard, audit pipeline,
  and defensive toolkit for smart-TV networks.
base: core22
confinement: strict
grade: stable
parts:
  c2:
    plugin: dump
    source: .
    organize:
      c2_server.py: usr/share/spytv-c2/
      c2_dashboard.html: usr/share/spytv-c2/
      requirements.txt: usr/share/spytv-c2/
    stage-packages: [python3, python3-yaml, python3-requests, python3-colorama]
apps:
  c2:
    command: python3 /usr/share/spytv-c2/c2_server.py
EOF
echo "Snap config created in snap/snapcraft.yaml (build: snapcraft)"
