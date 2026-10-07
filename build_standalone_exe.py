#!/usr/bin/env python3
"""Build a standalone SpyTV C2 executable (Windows .exe).

Uses PyInstaller to bundle the Python C2 server + dashboard into a single
executable. The resulting EXE runs without Python installed on the target
machine.

Usage:
    python build_standalone_exe.py [--output-dir dist/]

The EXE operates as a full C2 server (same as `python c2_server.py`):
    - Serves the web dashboard at http://localhost:8443/
    - All API endpoints work (scan, exploit, patch, CVE feed, audit reports)
    - Offline fallback page included if the C2 backend is unreachable
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent


def build_exe(output_dir: str = "dist") -> Path:
    """Build the standalone EXE using PyInstaller."""
    
    # Check PyInstaller is installed
    try:
        subprocess.run([sys.executable, "-m", "pip", "show", "pyinstaller"],
                       capture_output=True, check=True)
    except subprocess.CalledProcessError:
        print("[exe] Installing PyInstaller...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"],
                       check=True)

    exe_name = "SpyTV-C2-standalone"
    
    # PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--name", exe_name,
        "--add-data", f"{REPO / 'c2_dashboard.html'};.",
        "--add-data", f"{REPO / 'logo.png'};.",
        "--add-data", f"{REPO / 'c2_data'};c2_data",
        "--hidden-import", "reportlab",
        "--hidden-import", "yaml",
        "--hidden-import", "requests",
        "--hidden-import", "colorama",
        "--clean",
        "--distpath", output_dir,
        "--workpath", "build/tmp",
        "--specpath", "build/tmp",
        str(REPO / "c2_server.py"),
    ]
    
    print(f"[exe] Building standalone EXE: {exe_name}.exe")
    print(f"[exe] Using Python: {sys.executable}")
    
    subprocess.run(cmd, check=True, cwd=str(REPO))
    
    exe_path = REPO / output_dir / f"{exe_name}.exe"
    
    if not exe_path.exists():
        print(f"[exe] ERROR: EXE not found at {exe_path}")
        sys.exit(1)
    
    # Verify the EXE
    size = exe_path.stat().st_size
    print(f"[exe] Built successfully: {exe_path} ({size:,} bytes)")
    
    return exe_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="dist",
                        help="Output directory for the EXE")
    args = parser.parse_args()
    
    exe_path = build_exe(args.output_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())