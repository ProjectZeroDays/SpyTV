"""Firmware-update hygiene audit for a smart TV / IoT device inventory.

Reads a device inventory JSON (see config/devices.example.json), flags devices
with automatic updates disabled, unknown firmware, or stale check-in dates,
and produces a markdown report with per-vendor update paths and a signed-
update safety checklist.

Usage:
    python -m defense.hardening.firmware_audit --inventory config/devices.json
"""
from __future__ import annotations

import argparse
from datetime import date, datetime
from pathlib import Path

from ..common import CONFIG_DIR, LOG, load_json, write_markdown, OUTPUT_DIR

CHECK_INTERVAL_DAYS = 90

# vendor key -> where updates live / how to enable automatic updates
VENDOR_GUIDANCE: dict[str, str] = {
    "samsung": "Settings -> Support -> Software Update -> enable **Auto Update**; also apply 'Security policy updates'.",
    "lg": "Settings -> Support -> Software Update -> **Allow Automatic Updates**; webOS also checks on standby.",
    "sony": "Settings -> Device Preferences -> About -> System software update -> **Automatic updates** on.",
    "google": "Settings (System) -> System -> About -> System update; Google TVs update automatically when idle — confirm the TV sleeps properly.",
    "android": "Settings -> Device Preferences -> About -> System software update -> automatic updates on.",
    "vizio": "Settings -> System -> **Check for Updates**; keep SmartCast connected so automatic updates apply.",
    "roku": "Settings -> System -> System update -> **Check now**; Roku auto-updates nightly by default — don't disable via hotel/retail modes.",
    "tcl": "Roku models: Settings -> System -> System update. Google models follow the Android/Google TV path.",
    "hisense": "VIDAA: Settings -> Support -> System Update. Android models follow the Android TV path.",
    "panasonic": "Settings -> Setup -> **System Update** / Network Update.",
    "philips": "Settings -> **Update software**; Android models follow the Android TV path.",
    "amazon": "Settings -> My Fire TV -> About -> **Check for Updates**; automatic updates on by default — verify 'Install Updates Automatically'.",
    "toshiba": "Fire TV models follow the Amazon path.",
    "insignia": "Fire TV models follow the Amazon path.",
    "sharp": "Android/Google models follow the Android path; others: Settings -> Support -> System Update.",
}

SIGNED_UPDATE_CHECKLIST = """\
1. Apply updates only through the TV's built-in update mechanism or the
   vendor's official site — never a USB image or APK from a forum.
2. Vendor firmwares are signed; sideloaded "updates" are the classic
   implant-delivery path for TVs. If a device has had sideloaded content,
   factory-reset it and re-apply stock firmware.
3. Note each applied version in this inventory (the `firmware` field) so
   regressions and skipped devices are visible in the next audit.
4. Devices past vendor end-of-life (no updates for >18 months on a
   network-connected model) belong on an isolated IoT VLAN at minimum —
   see defense.hardening.vlan_segmentation.
"""


def _parse_day(value: str) -> date | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def audit_devices(devices: list[dict], today: date | None = None) -> list[dict]:
    """Return a list of findings: {device, check, severity, message}."""
    today = today or date.today()
    findings: list[dict] = []
    for dev in devices:
        name = dev.get("name") or dev.get("model") or "<unnamed>"
        vendor = str(dev.get("vendor", "")).lower().strip()

        if not vendor or not dev.get("model"):
            findings.append({"device": name, "check": "inventory", "severity": "MEDIUM",
                             "message": "Missing vendor/model — complete the inventory entry so CVE matching and update paths are actionable."})
        if dev.get("auto_update") is False:
            findings.append({"device": name, "check": "auto_update", "severity": "HIGH",
                             "message": "Automatic updates are disabled. Re-enable via: " + VENDOR_GUIDANCE.get(vendor, "the vendor's settings under Support/System -> Software Update.")})
        if not dev.get("firmware"):
            findings.append({"device": name, "check": "firmware", "severity": "LOW",
                             "message": "Firmware version unknown. Record it (Settings -> Support/About -> Software Info) to make CVE alerts actionable."})
        last = _parse_day(str(dev.get("last_checked", "")))
        if last is None:
            findings.append({"device": name, "check": "last_checked", "severity": "LOW",
                             "message": "last_checked missing/unparseable (expected YYYY-MM-DD)."})
        elif (today - last).days > CHECK_INTERVAL_DAYS:
            findings.append({"device": name, "check": "last_checked", "severity": "MEDIUM",
                             "message": f"Last checked {last.isoformat()} ({(today - last).days} days ago, threshold {CHECK_INTERVAL_DAYS}). "
                                        "Run a manual check now: " + VENDOR_GUIDANCE.get(vendor, "vendor update menu.")})
        if vendor and vendor not in VENDOR_GUIDANCE:
            findings.append({"device": name, "check": "vendor", "severity": "LOW",
                             "message": f"Vendor '{vendor}' has no canned guidance; use the vendor's own update menu and note it here."})
    return findings


SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def findings_markdown(findings: list[dict]) -> str:
    if not findings:
        return "All devices pass: auto-update on, firmware recorded, checked recently."
    rows = ["| Device | Check | Severity | Action |", "|---|---|---|---|"]
    for f in sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["device"])):
        rows.append(f"| {f['device']} | {f['check']} | {f['severity']} | {f['message']} |")
    return "\n".join(rows)


def guidance_markdown(devices: list[dict]) -> str:
    lines = []
    for dev in devices:
        vendor = str(dev.get("vendor", "")).lower().strip()
        if vendor in VENDOR_GUIDANCE:
            lines.append(f"- **{dev.get('name', dev.get('model'))} ({vendor})**: {VENDOR_GUIDANCE[vendor]}")
    return "\n".join(lines) if lines else "No recognized vendors in inventory."


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inventory", type=Path, default=CONFIG_DIR / "devices.json")
    ap.add_argument("--out", default=str(OUTPUT_DIR / "firmware_audit.md"))
    args = ap.parse_args(argv)

    devices = load_json(args.inventory)  # type: ignore[assignment]
    if not isinstance(devices, list):
        LOG.error("Inventory must be a JSON list of device objects (see config/devices.example.json)")
        return 2
    findings = audit_devices(devices)
    write_markdown(
        Path(args.out),
        "Firmware Update Hygiene Audit",
        [
            ("Findings", findings_markdown(findings)),
            ("Vendor update paths", guidance_markdown(devices)),
            ("Signed-update safety checklist", SIGNED_UPDATE_CHECKLIST),
        ],
    )
    print(findings_markdown(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
