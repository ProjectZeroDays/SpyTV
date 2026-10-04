# Detection Alert Summary

_Generated 2026-10-03T20:25:00+00:00 by the SpyTV defensive toolkit._

## Overview

- **Total alerts:** 6
- **Window (UTC):** 2026-10-03T20:24:59+00:00 → 2026-10-03T20:25:19+00:00
- **By severity:** HIGH 5, MEDIUM 1
- **By detector:** rogue_adb 4, ssh_bruteforce 1, ssdp_anomaly 1
- **Top sources:** 198.51.100.77 (1), 192.168.1.64 (1), 192.168.1.65 (1), (unknown) (1), 192.168.1.64:5555 (1), 203.0.113.200 (1)

## Timeline

| Time (UTC) | Severity | Detector | Alert |
|---|---|---|---|
| 2026-10-03T20:24:59+00:00 | HIGH | rogue_adb | Connection to ADB port 5555: 192.168.1.23 -> 192.168.1.64 |
| 2026-10-03T20:25:01+00:00 | HIGH | rogue_adb | Connection to ADB port 5555: 192.168.1.23 -> 192.168.1.65 |
| 2026-10-03T20:25:01+00:00 | HIGH | ssdp_anomaly | SSDP sweep/anomaly from 203.0.113.200 |
| 2026-10-03T20:25:02+00:00 | HIGH | rogue_adb | adb network connect initiated |
| 2026-10-03T20:25:03+00:00 | MEDIUM | rogue_adb | ADB device attached: 192.168.1.64:5555 (unauthorized) |
| 2026-10-03T20:25:19+00:00 | HIGH | ssh_bruteforce | SSH brute force from 198.51.100.77 |

## Notes

_Auto-generated from alert JSONL. Cross-reference the Detection Guide wiki page for each detector's recommended triage actions._
