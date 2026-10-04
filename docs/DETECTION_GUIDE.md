# Detection Guide

## Architecture

```
sources (adapters)                detectors                     outputs
───────────────────               ─────────────────────         ─────────────
SshdLogAdapter   ─┐               SshBruteForceDetector   ─┐    console
NetstatAdapter   ─┼─ Event ─────▶ RogueAdbDetector        ─┼──▶ alerts.jsonl
JsonlAdapter     ─┘               SsdpAnomalyDetector     ─┘    report.py → markdown
```

Every event carries an authoritative `ts`; all detector windows key off it,
which is why the suite is fully unit-testable and the drill is deterministic.

## Event model

| Field | Meaning |
|---|---|
| `ts` | Epoch seconds; drives all windowing |
| `kind` | `ssh_auth_failure` · `tcp` · `process` · `adb_device` · `ssdp` |
| `src` / `dst` / `dport` | Endpoints where applicable |
| `detail` | Free-form context (`user`, `state`, `method`, `serial`, ...) |

Feed your own pipeline by appending JSON objects with these fields to a file
and pointing the monitor at it with `--jsonl`.

## Detectors and tuning

| Detector | Fires when | Defaults | Tune via |
|---|---|---|---|
| `SshBruteForceDetector` | ≥N failed auths from one source in the window | N=5 / 60s, cooldown 300s | `--ssh-threshold`, `--ssh-window` |
| `RogueAdbDetector` | Connection to 5555/5037 not in the allowlist; `adb connect` process use; device attach | allowlist from `--allowlist` | `config/known_hosts.json` |
| `SsdpAnomalyDetector` | ≥N SSDP msgs in window **or** ≥D distinct destinations | N=50/10s, D=25, cooldown 120s | `--ssdp-rate` |

Tuning advice: on a network with automated asset scanners, allowlist them in
the ADB detector and raise the SSDP rate before lowering anything else; a
noisy detector gets ignored faster than a quiet one.

## Running the monitor

```bash
python -m defense.detection.monitor --sshd-log /var/log/auth.log --netstat
python -m defense.detection.monitor --sshd-log C:\logs\auth.log --tail-only \
    --allowlist config/known_hosts.json --alert-file output/alerts.jsonl
```

`--tail-only` skips existing log content. Alerts print and append to the
JSONL file — one object per alert:

```json
{"ts": 1791013298.2, "detector": "ssh_bruteforce", "severity": "HIGH",
 "title": "SSH brute force from 203.0.113.9", "description": "5 failed ...",
 "evidence": {"src": "203.0.113.9", "count": 5, "users": ["admin", ...]}}
```

## Drills — prove it works, on the record

```bash
python -m defense.detection.drill                     # instant, self-scoring
python -m defense.detection.drill --live --interval 0.3   # paced, for demos
python -m defense.detection.drill --alert-file output/drill_alerts.jsonl
```

Four scenarios with known expected alert counts: `ssh_bruteforce` (1 HIGH),
`adb_takeover` (3 HIGH + 1 MEDIUM), `ssdp_sweep` (1 HIGH), and `benign` —
the negative control that must produce **zero** alerts, including an
allowlisted ADB peer. PASS on all four means the stack is wired and tuned
correctly. Run a drill after any config change, and in front of clients:
synthetic events, real detections, nothing touched.

## Incident summaries

```bash
python -m defense.detection.report --alerts output/alerts.jsonl
```

Aggregates any alert JSONL into `output/incident_summary.md`: counts by
severity/detector, top source hosts, and a capped timeline — the page you
attach to a ticket or a client update.

## SIEM / SOC integration

`defense/detection/rules/` contains five Sigma rules covering `adb connect`
process creation, connections to ADB ports, sshd brute force (windowed
count), SSDP sweeps, and DLNA AVTransport control. Import them into any
Sigma-compatible backend (Splunk/Elastic/Sentinel via converters). For
SOAR-style automation, consume `output/alerts.jsonl` directly — the schema
above is stable and each alert is self-contained.
