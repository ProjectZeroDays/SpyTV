# SpyTV — Defensive Toolkit & Framework Review

This repository contains the **defensive** work product of the SpyTV engagement:

1. **`CODE_REVIEW.md`** — a defect review of the offensive SpyTV / SpyTV / TVREAPER
   code (57 findings: fatal defects, self-inflicted vulnerabilities,
   misconfigurations, portability gaps, and documentation-integrity problems).
   The review documents what is broken; it deliberately provides no corrected
   exploit, targeting, implant, or evasion logic.
2. **`defense/`** — a stdlib-only, production-quality toolkit covering the four
   defensive pillars: attack-surface assessment, hardening (ADB, UPnP, VLAN
   segmentation, firmware), detection engineering (SOC/home-lab), and CVE
   monitoring.
3. **`docs/`** — the wiki: [home](docs/WIKI.md) · [getting started](docs/Getting-Started.md) ·
   [threat model](docs/Threat-Model.md) · [hardening](docs/Hardening-Guide.md) ·
   [detection](docs/Detection-Guide.md) · [CVE monitoring](docs/CVE-Monitoring-Guide.md)

## Authorization

Use these tools **only on networks and devices you own or are explicitly
authorized to assess**. The hardening modules are read-only by default; every
state-changing command is printed as a dry-run preview until you pass
`--apply`.

## Repository layout

```
SpyTV/
├── CODE_REVIEW.md                  # Defect review of the reviewed framework
├── README.md
├── requirements.txt                # empty — stdlib only
├── defense/
│   ├── common.py                   # shared helpers (report writing, dry-run exec)
│   ├── hardening/
│   │   ├── attack_surface.py       # TV port/attack-surface auditor (read-only)
│   │   ├── adb_disable.py          # find TCP/5555, vendor disable steps, local blocks
│   │   ├── upnp_close.py           # SSDP/UPnP enumeration + close-down guidance
│   │   ├── vlan_segmentation.py    # nftables/iptables/guide generator for IoT VLAN
│   │   └── firmware_audit.py       # inventory hygiene audit + vendor update paths
│   ├── detection/
│   │   ├── events.py               # Event/Alert model
│   │   ├── ssh_detector.py         # sshd brute-force detector + log line parser
│   │   ├── adb_detector.py         # rogue ADB connections / adb connect / device attach
│   │   ├── ssdp_detector.py        # SSDP sweep / fan-out anomaly detector
│   │   ├── adapters.py             # sshd log tail, netstat/ss poller, JSONL pipeline
│   │   ├── monitor.py              # unified monitor CLI
│   │   ├── drill.py                # self-scoring detection drill (synthetic events)
│   │   ├── report.py               # alert JSONL -> incident summary markdown
│   │   └── rules/                  # Sigma rules for SIEM import
│   └── cve_monitor/
│       ├── monitor.py              # NVD 2.0 watcher, dedupe, alerting
│       ├── whitepaper.py           # client-ready defensive CVE brief generator
│       └── keywords.json           # smart TV platform keywords
├── config/                         # example configs (copy, remove .example)
├── docs/                           # the wiki (see links above)
└── tests/                          # unittest suite (39 tests)
```

## Quickstart

```bash
cd C:\Projects\SpyTV

# 1. Audit your network's TV attack surface (read-only)
python -m defense.hardening.attack_surface --network 192.168.1.0/24

# 2. Hunt for exposed ADB and get per-vendor disable steps
python -m defense.hardening.adb_disable --network 192.168.1.0/24
python -m defense.hardening.adb_disable --local --apply   # admin shell; dry-run without --apply

# 3. Enumerate UPnP devices and shut unnecessary exposure
python -m defense.hardening.upnp_close
python -m defense.hardening.upnp_close --apply --block-inbound --stop-service

# 4. Generate an IoT VLAN ruleset + platform guide
python -m defense.hardening.vlan_segmentation            # writes output/vlan/

# 5. Audit firmware-update hygiene
copy config\devices.example.json config\devices.json     # edit to match your devices
python -m defense.hardening.firmware_audit

# 6. Detection (SOC or home lab)
python -m defense.detection.monitor --sshd-log /var/log/auth.log --netstat
python -m defense.detection.monitor --sshd-log C:\logs\auth.log --tail-only \
    --allowlist config/known_hosts.json --alert-file output/alerts.jsonl

# 7. Prove the detection stack works — self-scoring drill (great for demos)
python -m defense.detection.drill
python -m defense.detection.drill --live --interval 0.3

# 8. Turn alert logs into an incident summary
python -m defense.detection.report --alerts output/alerts.jsonl

# 9. CVE monitoring (alerting only — never downloads exploits)
python -m defense.cve_monitor.monitor --once --days 7
python -m defense.cve_monitor.monitor --watch --interval 21600 --webhook <url>

# 10. Client-ready vulnerability whitepaper, generated live from NVD
python -m defense.cve_monitor.whitepaper --days 90
```

## Detection model

- **Sources**: sshd auth logs (Linux `auth.log`/`secure`, Windows OpenSSH logs),
  the live TCP table (`netstat`/`ss`), or any pipeline via JSONL events.
- **Detectors**: SSH brute force (per-source sliding window), rogue ADB
  (TCP 5555/5037 connections not in the allowlist, `adb connect` process use,
  device attach), SSDP sweeps (rate + distinct-destination fan-out).
- **Drill**: four synthetic scenarios with known expected alert counts —
  including a negative control — so the stack proves itself without touching
  a single real host.
- **Output**: console + one JSON object per alert in `output/alerts.jsonl`;
  `report.py` turns any alert file into an executive markdown summary.
- **Determinism**: all windowing uses event timestamps, so behavior is fully
  covered by the unit tests.

## CVE monitor & whitepaper behavior

Queries the NVD 2.0 API per keyword (default set covers smart TV platforms),
deduplicates against `defense/cve_monitor/state.json`, flags CVEs whose
references point at public exploit corpora as **public exploit reference**,
and alerts via console, JSONL, and optional webhook. `whitepaper.py` renders
the same data as a defensive client brief — scope, executive summary,
severity index, per-CVE entries with recommended actions mapped to the
hardening modules. Without an API key it rate-limits to one request per 6
seconds per NVD guidance.

## Tests

```bash
python -m unittest discover -s tests -v   # 39 tests
python -m defense.detection.drill         # expect: ALL SCENARIOS PASS
```

## Scope note

Per the engagement terms, this repo intentionally contains **no** offensive
capability: no exploit code, no scanner/exploit fixes, no implant logic, no
evasion tooling, and no autonomous exploit acquisition. Everything here is
defensive: assess, harden, detect, monitor.
