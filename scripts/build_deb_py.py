#!/usr/bin/env python3
"""Build a .deb from an electron-builder linux-unpacked tree.

Pure-stdlib replacement for `dpkg-deb`/`fpm` so a valid .deb can be produced
on hosts without dpkg tooling (e.g. Windows). Mirrors what electron-builder's
fpm target generates: payload under /opt, .desktop entry, hicolor icon,
/usr/bin symlink, and a postinst that sets chrome-sandbox permissions.

Usage:
    python scripts/build_deb_py.py \
        --root electron/dist/linux-unpacked \
        --out electron/dist/spytv-c2_4.6.1_amd64.deb \
        --version 4.6.1
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import tarfile

APP_ID = "spytv-c2"
PRODUCT_NAME = "SpyTV C2"  # must match electron-builder productName
MAINTAINER = "Authenticated, Inc."
HOMEPAGE = "https://github.com/ProjectZeroDays/SpyTV"
ICON_SOURCE = "electron/icon.png"
DESKTOP_TEMPLATE = """[Desktop Entry]
Name={product}
Comment={product} desktop client
Exec="/opt/{product}/{app_id}" %U
Terminal=false
Type=Application
Icon={app_id}
StartupWMClass={product}
Categories=Network;Security;
"""
DEPENDS = [
    "libgtk-3-0", "libnotify4", "libnss3", "libxss1", "libxtst6",
    "xdg-utils", "libatspi2.0-0", "libuuid1", "libsecret-1-0",
]
RECOMMENDS = ["libappindicator3-1"]
POSTINST = """#!/bin/sh
set -e
# Electron's setuid sandbox helper needs root ownership + setuid bit.
SANDBOX="/opt/%s/chrome-sandbox"
if [ -f "$SANDBOX" ]; then
  chmod 4755 "$SANDBOX" || true
fi
""" % PRODUCT_NAME

EXEC_NAMES = {"spytv-c2", "chrome-sandbox", "chrome_crashpad_handler"}
EXEC_SUFFIXES = (".so", ".so.1")


def is_executable(rel: str) -> bool:
    name = os.path.basename(rel)
    return name in EXEC_NAMES or name.endswith(EXEC_SUFFIXES)


def iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        rel_dir = os.path.relpath(dirpath, root)
        for d in dirnames:
            rel = os.path.normpath(os.path.join(rel_dir, d))
            yield os.path.join(dirpath, d), rel.replace(os.sep, "/"), "dir"
        for f in sorted(filenames):
            if f.endswith((".pyc", ".pyo")):
                continue
            rel = os.path.normpath(os.path.join(rel_dir, f))
            yield os.path.join(dirpath, f), rel.replace(os.sep, "/"), "file"


def build_data_tar(root: str, mtime: int) -> tuple[bytes, list[tuple[str, str]]]:
    """Return (data.tar.xz bytes, [(path, md5)]) for the payload."""
    buf = io.BytesIO()
    md5s: list[tuple[str, str]] = []
    with tarfile.open(fileobj=buf, mode="w:xz",
                      format=tarfile.PAX_FORMAT) as tar:
        # Symlink for PATH lookup.
        link = tarfile.TarInfo(f"./usr/bin/{APP_ID}")
        link.type = tarfile.SYMTYPE
        link.linkname = f"/opt/{PRODUCT_NAME}/{APP_ID}"
        link.mode = 0o777
        link.mtime = mtime
        tar.addfile(link)

        for abs_path, rel, kind in iter_files(root):
            arc = f"./opt/{PRODUCT_NAME}/{rel}"
            st = os.lstat(abs_path)
            ti = tarfile.TarInfo(arc)
            ti.mtime = mtime
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tar.addfile(ti)
            else:
                ti.mode = 0o755 if is_executable(rel) else 0o644
                with open(abs_path, "rb") as fh:
                    data = fh.read()
                ti.size = len(data)
                md5s.append((hashlib.md5(data).hexdigest(), arc[2:]))
                tar.addfile(ti, io.BytesIO(data))

        # .desktop entry and icon.
        for arc, data, mode in (
            (f"./usr/share/applications/{APP_ID}.desktop",
             DESKTOP_TEMPLATE.format(product=PRODUCT_NAME, app_id=APP_ID)
             .encode(), 0o644),
            (f"./usr/share/icons/hicolor/432x432/apps/{APP_ID}.png",
             open(ICON_SOURCE, "rb").read(), 0o644),
        ):
            ti = tarfile.TarInfo(arc)
            ti.size = len(data)
            ti.mode = mode
            ti.mtime = mtime
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            md5s.append((hashlib.md5(data).hexdigest(), arc[2:]))
            tar.addfile(ti, io.BytesIO(data))

    return buf.getvalue(), md5s


def ar_member(name: str, data: bytes) -> bytes:
    header = (f"{name:<16}"
              f"{0:<12}{0:<6}{0:<6}{0o644:<8o}{len(data):<10}`\n")
    out = header.encode("ascii") + data
    if len(data) % 2:
        out += b"\n"
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True,
                    help="electron-builder linux-unpacked directory")
    ap.add_argument("--out", required=True, help="output .deb path")
    ap.add_argument("--version", required=True)
    args = ap.parse_args()

    mtime = 0  # reproducible build
    data_tar, md5s = build_data_tar(args.root, mtime)
    installed_kb = len(data_tar) // 1024  # approximation (compressed)

    control_buf = io.BytesIO()
    with tarfile.open(fileobj=control_buf, mode="w:gz",
                      format=tarfile.PAX_FORMAT) as tar:
        control_text = (
            f"Package: {APP_ID}\n"
            f"Version: {args.version}\n"
            f"Architecture: amd64\n"
            f"Maintainer: {MAINTAINER}\n"
            f"Vendor: {MAINTAINER}\n"
            f"Homepage: {HOMEPAGE}\n"
            f"Section: net\n"
            f"Priority: optional\n"
            f"Installed-Size: {installed_kb}\n"
            f"Depends: {', '.join(DEPENDS)}\n"
            f"Recommends: {', '.join(RECOMMENDS)}\n"
            f"Description: {PRODUCT_NAME} desktop client\n"
            f" The full C2 server, dashboard, and defensive toolkit for\n"
            f" smart-TV security assessment.\n"
        ).encode()
        md5_text = "".join(f"{h}  {p}\n" for h, p in md5s).encode()
        for arc, data, mode in (
            ("./control", control_text, 0o644),
            ("./md5sums", md5_text, 0o644),
            ("./postinst", POSTINST.encode(), 0o755),
        ):
            ti = tarfile.TarInfo(arc)
            ti.size = len(data)
            ti.mode = mode
            ti.mtime = mtime
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            tar.addfile(ti, io.BytesIO(data))

    deb = b"!<arch>\n"
    deb += ar_member("debian-binary", b"2.0\n")
    deb += ar_member("control.tar.gz", control_buf.getvalue())
    deb += ar_member("data.tar.xz", data_tar)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "wb") as fh:
        fh.write(deb)
    print(f"Built {args.out} ({len(deb) / 1024 / 1024:.1f} MiB, "
          f"{len(md5s)} files)")


if __name__ == "__main__":
    main()
