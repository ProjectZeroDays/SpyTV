#!/usr/bin/env python3
"""Verify a .deb package: structure, control metadata, path sanity, md5sums.

Usage: python scripts/verify_deb.py <file.deb>
"""
from __future__ import annotations

import hashlib
import io
import sys
import tarfile


def read_ar(path: str) -> dict[str, bytes]:
    data = open(path, "rb").read()
    if data[:8] != b"!<arch>\n":
        raise SystemExit("not an ar archive (bad magic)")
    members, off = {}, 8
    while off < len(data):
        hdr = data[off:off + 60]
        if len(hdr) < 60 or hdr[58:60] != b"`\n":
            raise SystemExit("corrupt ar member header")
        name = hdr[0:16].decode().strip()
        size = int(hdr[48:58].decode().strip())
        members[name] = data[off + 60:off + 60 + size]
        off += 60 + size + (size % 2)
    return members


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    members = read_ar(sys.argv[1])

    assert members["debian-binary"] == b"2.0\n", "bad debian-binary"
    ctrl = tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]),
                        mode="r:gz")
    control = ctrl.extractfile("./control").read().decode()
    print("--- control ---")
    print(control)

    md5s = {}
    for line in ctrl.extractfile("./md5sums").read().decode().splitlines():
        digest, _, p = line.partition("  ")
        md5s[p] = digest

    bad = 0
    entries = 0
    with tarfile.open(fileobj=io.BytesIO(members["data.tar.xz"]),
                      mode="r|xz") as tar:
        for m in tar:
            entries += 1
            name = m.name.lstrip("./")
            if "\\" in m.name:
                print(f"BAD backslash in path: {m.name}")
                bad += 1
            if not m.name.startswith("./"):
                print(f"BAD relative path (needs ./): {m.name}")
                bad += 1
            if m.isfile() and name in md5s:
                digest = hashlib.md5(tar.extractfile(m).read()).hexdigest()
                if digest != md5s[name]:
                    print(f"MD5 MISMATCH: {name}")
                    bad += 1
                del md5s[name]
    if md5s:
        print(f"MISSING from data.tar: {list(md5s)[:5]}")
        bad += len(md5s)
    print(f"entries={entries} problems={bad}")
    if bad:
        raise SystemExit("FAILED")
    print("OK")


if __name__ == "__main__":
    main()
