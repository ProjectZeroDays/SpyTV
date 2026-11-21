"""SpyTV C2 auto-update checker.

Queries the GitHub Releases API for the latest release tag and compares it
against the running version. Exposes a simple API used by the C2 server
(`/api/update/check`, `/api/update/download`) and by the dashboard banner.

Design:
  - No background daemon. The check runs on server startup and on demand.
  - Network failures are non-fatal: the checker returns the cached/unknown
    state and the server continues normally.
  - The download URL is the asset matching the current platform (Windows
    standalone EXE or Android APK).
"""
from __future__ import annotations

import json
import os
import platform
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

# Single source of truth for the running version. Update this string (and the
# matching tag) when cutting a release.
APP_VERSION = "4.6.1"
REPO = "ProjectZeroDays/SpyTV"
RELEASES_API = f"https://api.github.com/repos/{REPO}/releases/latest"
CHECK_INTERVAL_SECONDS = 6 * 60 * 60  # 6 hours between background re-checks

_state = {
    "checked_at": 0.0,
    "latest_version": None,
    "latest_tag": None,
    "release_url": None,
    "download_url": None,
    "asset_name": None,
    "update_available": False,
    "error": None,
}
_lock = threading.Lock()


def _platform_asset_suffix() -> str:
    system = platform.system().lower()
    if system == "windows":
        return ".exe"
    if system == "linux":
        return ".apk"
    if system == "darwin":
        return ".dmg"
    return ""


def _parse_version(tag: str) -> tuple:
    """Parse a tag like 'v4.6.0' into a comparable tuple of ints."""
    tag = (tag or "").strip().lstrip("vV")
    parts = []
    for chunk in tag.split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _fetch_latest() -> dict:
    """Hit the GitHub API and return a normalized dict. Never raises."""
    result = {
        "latest_version": None,
        "latest_tag": None,
        "release_url": None,
        "download_url": None,
        "asset_name": None,
        "update_available": False,
        "error": None,
    }
    try:
        req = urllib.request.Request(
            RELEASES_API,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"SpyTV-C2/{APP_VERSION}",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        result["latest_tag"] = data.get("tag_name")
        result["latest_version"] = (data.get("tag_name") or "").lstrip("vV")
        result["release_url"] = data.get("html_url")
        suffix = _platform_asset_suffix()
        for asset in data.get("assets", []) or []:
            name = asset.get("name", "")
            if suffix and name.lower().endswith(suffix):
                result["download_url"] = asset.get("browser_download_url")
                result["asset_name"] = name
                break
        if result["latest_tag"]:
            result["update_available"] = (
                _parse_version(result["latest_tag"]) > _parse_version(APP_VERSION)
            )
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, Exception) as exc:
        result["error"] = str(exc)
    return result


def check(force: bool = False) -> dict:
    """Return the current update state, refreshing if stale or forced."""
    with _lock:
        now = time.time()
        if force or (now - _state["checked_at"]) > CHECK_INTERVAL_SECONDS:
            fresh = _fetch_latest()
            _state.update(fresh)
            _state["checked_at"] = now
        return dict(_state)


def check_async(force: bool = False) -> None:
    """Kick off a background check (non-blocking)."""
    def _run():
        check(force=force)
    threading.Thread(target=_run, daemon=True).start()


def status() -> dict:
    """Return a JSON-serializable status dict for the API."""
    s = check()
    return {
        "current_version": APP_VERSION,
        "latest_version": s.get("latest_version"),
        "latest_tag": s.get("latest_tag"),
        "update_available": s.get("update_available", False),
        "release_url": s.get("release_url"),
        "download_url": s.get("download_url"),
        "asset_name": s.get("asset_name"),
        "checked_at": s.get("checked_at"),
        "error": s.get("error"),
    }
