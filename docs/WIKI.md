# SpyTV Defensive Toolkit — Wiki

Welcome to the documentation home for the SpyTV defensive toolkit: an
authorization-first, stdlib-only toolkit for auditing, hardening, and
monitoring smart TV / IoT environments — plus a full defect review of the
offensive framework that motivated it (`CODE_REVIEW.md`).

## Pages

| Page | What it covers |
|---|---|
| [Getting Started](Getting-Started.md) | Install (spoiler: nothing to install), the 15-minute first run, platform notes |
| [Threat Model](Threat-Model.md) | The smart TV attack classes this toolkit defends against, stage by stage, and the control that answers each |
| [Hardening Guide](Hardening-Guide.md) | Playbooks: attack-surface audit, ADB disable, UPnP close-down, VLAN segmentation, firmware hygiene |
| [Detection Guide](Detection-Guide.md) | Event model, detectors and tuning, the monitor, drills, alert schema, Sigma/SIEM integration |
| [CVE Monitoring Guide](CVE-Monitoring-Guide.md) | Operating the NVD watcher, keywords, API keys, whitepaper generation |

## Component map

```
defense/
├── hardening/      attack_surface · adb_disable · upnp_close · vlan_segmentation · firmware_audit
├── detection/      ssh/adb/ssdp detectors · adapters · monitor · drill · report · rules/ (Sigma)
└── cve_monitor/    monitor (NVD watcher) · whitepaper (defensive brief generator)
```

## Operating principles

1. **Authorization first.** Every module is for networks and devices you own
   or are explicitly authorized to assess. Engagement paperwork belongs in the
   plan before the first scan.
2. **Read-only by default.** Audits never change state. The only state-changing
   actions are behind explicit `--apply` flags, and every command is printed
   as a dry-run preview first.
3. **No dependencies.** Python 3.10+ standard library only; works on Windows
   and Linux out of the box.
4. **Defensive only.** This repository deliberately contains no offensive
   capability. See `CODE_REVIEW.md` §7 for the scope statement.

## Verification

```bash
python -m unittest discover -s tests -v   # 39 tests
python -m defense.detection.drill         # self-scoring detection drill (expect ALL PASS)
```
