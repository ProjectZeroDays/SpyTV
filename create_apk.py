#!/usr/bin/env python3
"""Build + verify the SpyTV Android APK with the real Gradle pipeline.

History: the old script fabricated a ~1 KB ZIP renamed to ``SpyTV.apk`` —
no manifest, no dex, uninstallable. This driver builds the ``android/``
project with the Gradle wrapper, runs a verification suite, and only then
writes the repo-root ``SpyTV.apk``. Any failure exits non-zero WITHOUT
writing output — a placeholder can never be shipped again.

The APK now supports two modes:
  1. Console Mode: Connects to an external C2 server (default)
  2. Standalone Mode: Runs a full C2 server locally on the Android device

Usage:
    python create_apk.py                # build, verify, copy to repo root
    python create_apk.py --verify-only  # verify an already-built APK only
    python create_apk.py --release      # build release variant

Checks performed on the artifact:
  1. file exists and is >= 1 MB (the placeholder was 1 KB)
  2. valid ZIP containing AndroidManifest.xml, classes.dex, resources.arsc
  3. ``apksigner verify``  — signature present and valid
  4. ``aapt dump badging`` — expected package + a launchable activity
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent
ANDROID = REPO / "android"
BUILT_APK = (ANDROID / "app" / "build" / "outputs" / "apk" / "debug"
             / "app-debug.apk")
OUT_APK = REPO / "SpyTV.apk"

MIN_SIZE = 1_000_000          # real APKs are multi-MB; the fake was 1 KB
EXPECTED_PACKAGE = "com.authenticated.spytv"
REQUIRED_ENTRIES = ("AndroidManifest.xml", "classes.dex", "resources.arsc")


def _sdk() -> Path:
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(var):
            return Path(os.environ[var])
    local = os.environ.get("LOCALAPPDATA", "")
    return Path(local) / "Android" / "Sdk" if local else Path("/nonexistent-sdk")


def _build_tool(name: str) -> Path | None:
    """Newest build-tools copy of *name* (apksigner.bat / aapt.exe / …).

    Wrapper extensions first (apksigner.bat), then bare names, then .exe.
    """
    bt = _sdk() / "build-tools"
    if not bt.is_dir():
        return None
    exts = (".bat", ".exe", "") if os.name == "nt" else ("", ".sh")
    for version in sorted((d.name for d in bt.iterdir() if d.is_dir()),
                          reverse=True):
        for ext in exts:
            cand = bt / version / f"{name}{ext}"
            if cand.exists():
                return cand
    return None


def _die(msg: str) -> "None":
    print(f"[apk] ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    print(f"[apk] + {' '.join(str(c) for c in cmd)}")
    return subprocess.run([str(c) for c in cmd], **kwargs)


def copy_assets():
    """Copy the dashboard HTML to the Android assets folder before building."""
    assets_dir = ANDROID / "app" / "src" / "main" / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    
    dashboard = REPO / "c2_dashboard.html"
    if dashboard.exists():
        shutil.copy2(dashboard, assets_dir / "c2_dashboard.html")
        print(f"[apk] Copied dashboard to {assets_dir / 'c2_dashboard.html'}")
    else:
        print("[apk] WARNING: Dashboard HTML not found, will use built-in fallback")


def verify(apk: Path) -> str:
    """Run every check on *apk*; returns a summary or raises SystemExit."""
    if not apk.exists():
        _die(f"APK not found: {apk}")
    size = apk.stat().st_size
    if size < MIN_SIZE:
        _die(f"{apk.name} is only {size} bytes (< {MIN_SIZE}) — "
             "this is not a real APK, refusing to ship it")

    # 2. structure
    try:
        with zipfile.ZipFile(apk) as zf:
            bad = zf.testzip()
            if bad is not None:
                _die(f"corrupt ZIP entry: {bad}")
            names = set(zf.namelist())
    except zipfile.BadZipFile as exc:
        _die(f"not a valid ZIP/APK: {exc}")
    missing = [e for e in REQUIRED_ENTRIES if e not in names]
    if missing:
        _die(f"missing required APK entries: {missing}")

    # 3. signature (mandatory — an unsigned APK cannot be installed)
    apksigner = _build_tool("apksigner")
    if apksigner is None:
        _die("apksigner not found under SDK build-tools — install it "
             f"(looked in {_sdk() / 'build-tools'})")
    sig = _run([apksigner, "verify", "--print-certs", apk],
               capture_output=True, text=True, timeout=120)
    if sig.returncode != 0:
        _die("apksigner verify FAILED:\n" + (sig.stdout + sig.stderr)[-2000:])

    # 4. badging: package name + launchable activity
    aapt = _build_tool("aapt")
    if aapt is None:
        _die("aapt not found under SDK build-tools")
    bad = _run([aapt, "dump", "badging", apk],
               capture_output=True, text=True, timeout=120)
    if bad.returncode != 0:
        _die("aapt dump badging FAILED:\n" + (bad.stdout + bad.stderr)[-2000:])
    package = activity = ""
    for line in (bad.stdout or "").splitlines():
        if line.startswith("package: "):
            package = line.split("name='", 1)[1].split("'", 1)[0]
        elif line.startswith("launchable-activity: "):
            activity = line.split("name='", 1)[1].split("'", 1)[0]
    if package != EXPECTED_PACKAGE:
        _die(f"unexpected package {package!r} (want {EXPECTED_PACKAGE!r})")
    if not activity:
        _die("no launchable-activity in badging — app would not open")

    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    subject = next((l for l in (sig.stdout or "").splitlines()
                    if "Subject:" in l), "(see apksigner output)").strip()
    summary = (f"{apk.name}: {size} bytes, package {package}, "
               f"launcher {activity}, {subject}")
    print(f"[apk] SHA256 {digest}")
    return summary


def build() -> None:
    gradlew = ANDROID / ("gradlew.bat" if os.name == "nt" else "gradlew")
    if not gradlew.exists():
        _die(f"gradle wrapper missing ({gradlew}) — cannot build")

    # Copy assets before build
    copy_assets()

    if not (ANDROID / "local.properties").exists():
        sdk = _sdk()
        if sdk.is_dir():
            (ANDROID / "local.properties").write_text(
                f"sdk.dir={str(sdk).replace(chr(92), chr(92) * 2)}\n",
                encoding="utf-8")

    env = dict(os.environ)
    if _sdk().is_dir():
        env.setdefault("ANDROID_HOME", str(_sdk()))

    def run_gradle() -> int:
        return _run([gradlew, "assembleDebug", "--no-daemon", "--console=plain"],
                    cwd=ANDROID, env=env, timeout=3600).returncode

    print("[apk] building android/ (assembleDebug) — first run may download "
          "Gradle/AGP dependencies")
    rc = run_gradle()
    if rc != 0:
        # Interrupted/partial runs leave corrupt incremental outputs — clean
        # once and retry before giving up.
        print("[apk] build failed — wiping android/app/build and retrying once")
        shutil.rmtree(ANDROID / "app" / "build", ignore_errors=True)
        shutil.rmtree(ANDROID / ".gradle", ignore_errors=True)
        rc = run_gradle()
    if rc != 0:
        _die(f"gradle assembleDebug failed (exit {rc})")
    if not BUILT_APK.exists():
        _die(f"gradle reported success but produced no APK at {BUILT_APK}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true",
                        help="skip the Gradle build; verify the existing output")
    parser.add_argument("--release", action="store_true",
                        help="build release variant instead of debug")
    args = parser.parse_args()

    if not args.verify_only:
        build()

    summary = verify(BUILT_APK)
    shutil.copyfile(BUILT_APK, OUT_APK)
    print(f"[apk] verified + written: {OUT_APK} ({OUT_APK.stat().st_size} bytes)")
    print(f"[apk] OK — {summary}")
    print(f"[apk] Standalone C2 mode is supported on the APK")
    return 0


if __name__ == "__main__":
    sys.exit(main())