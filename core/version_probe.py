"""Firmware version probes for the TV families that expose one unauthenticated.

Version-aware CVE filtering is only as good as the version string it starts
from. Each family has one canonical unauthenticated endpoint; the fetchers
below pull the version with a short timeout and forgiving parsing — a TV
that doesn't answer simply yields None, and filtering stays off (fail-closed
in ``core.fingerprint.filter_cves_for_version`` keeps every CVE).
"""
import http.client
import re

FAMILY_VERSION_ENDPOINTS = {
    "roku": (8060, "/query/device-info"),
    "lg-webos": (3000, "/api/system"),
    "samsung-tizen": (8001, "/api/v2/"),
}

_TIMEOUT = 1.5
_READ_LIMIT = 8192

# (<osversion>12.5.0</osversion>, "osVersion": "23.1.0",
#  "firmwareVersion":"4.2.1", software-version XML...). We take the first
# dotted token tied to a version-ish key, then any dotted token as fallback.
_KEYED_RE = re.compile(
    r'"?[a-z]*[Vv]ersion"?\s*[:>]\s*"?([0-9]+(?:\.[0-9A-Za-z]+)+)"?',
    re.IGNORECASE)
_FALLBACK_RE = re.compile(r"\d+(?:\.\d+)+")


def fetch_device_version(ip, tv_type, timeout=_TIMEOUT):
    """Firmware/OS version string for the family, or None.

    Never raises — an unreachable endpoint or unparseable body reads as
    "version unknown", which disables (not weakens) version filtering.
    """
    target = FAMILY_VERSION_ENDPOINTS.get(tv_type or "")
    if not target:
        return None
    port, path = target
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "SpyTV/1.0"})
            resp = conn.getresponse()
            if resp.status >= 400:
                return None
            body = resp.read(_READ_LIMIT).decode("utf-8", "ignore")
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 — no version is a normal scan outcome
        return None

    m = _KEYED_RE.search(body)
    if m:
        return m.group(1)
    m = _FALLBACK_RE.search(body)
    return m.group(0) if m else None
