# Firmware Update Hygiene Audit

_Generated 2026-10-03T07:40:56+00:00 by the SpyTV defensive toolkit._

## Findings

| Device | Check | Severity | Action |
|---|---|---|---|
| Bedroom TV | auto_update | HIGH | Automatic updates are disabled. Re-enable via: Settings -> My Fire TV -> About -> **Check for Updates**; automatic updates on by default — verify 'Install Updates Automatically'. |
| Bedroom TV | last_checked | MEDIUM | Last checked 2026-01-02 (274 days ago, threshold 90). Run a manual check now: Settings -> My Fire TV -> About -> **Check for Updates**; automatic updates on by default — verify 'Install Updates Automatically'. |

## Vendor update paths

- **Living room TV (samsung)**: Settings -> Support -> Software Update -> enable **Auto Update**; also apply 'Security policy updates'.
- **Bedroom TV (amazon)**: Settings -> My Fire TV -> About -> **Check for Updates**; automatic updates on by default — verify 'Install Updates Automatically'.
- **Den cast dongle (google)**: Settings (System) -> System -> About -> System update; Google TVs update automatically when idle — confirm the TV sleeps properly.

## Signed-update safety checklist

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
