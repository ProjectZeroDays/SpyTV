# Getting Started

## Requirements

- Python 3.10 or newer (3.14 verified). No third-party packages.
- Windows or Linux. Some actions (`--apply` firewall rules, service control)
  need an elevated shell.
- Network scans should be run from a host on the segment you are auditing.

## The 15-minute first run

Run these in order; each writes a markdown report under `output/`.

```bash
cd <repo root>

# 1. What is exposed on your network? (read-only, ~30-60s for a /24)
python -m defense.hardening.attack_surface --network 192.168.1.0/24

# 2. Any TVs with network ADB open? Get vendor-specific disable steps.
python -m defense.hardening.adb_disable --network 192.168.1.0/24

# 3. What UPnP devices answered discovery? What should be closed?
python -m defense.hardening.upnp_close

# 4. Generate an IoT VLAN ruleset + platform-specific guide.
python -m defense.hardening.vlan_segmentation

# 5. Audit firmware hygiene (edit the inventory first).
copy config\devices.example.json config\devices.json   # Windows
cp    config/devices.example.json config/devices.json   # Linux
python -m defense.hardening.firmware_audit

# 6. Prove the detection stack works — self-scoring drill.
python -m defense.detection.drill

# 7. What's newly published that affects your TVs?
python -m defense.cve_monitor.monitor --once --days 30
```

## Going steady-state

- Keep a monitor running where logs exist:
  `python -m defense.detection.monitor --sshd-log /var/log/auth.log --netstat`
- Schedule the CVE watcher (Task Scheduler / cron):
  `python -m defense.cve_monitor.monitor --once --days 1`
- Re-run `attack_surface` after every network change; diff the reports.
- Generate a client-ready vulnerability brief any time:
  `python -m defense.cve_monitor.whitepaper --days 90`

## Platform notes

| Concern | Windows | Linux |
|---|---|---|
| TCP table source for the monitor | `netstat -ano -p tcp` | `ss -Htn state established` |
| `--apply` firewall actions | `netsh advfirewall` (admin) | `ufw` (root) |
| sshd log to tail | OpenSSH for Windows operational log exported to a file | `/var/log/auth.log`, `/var/log/secure` |
| UPnP service control | `SSDPSRV`, `upnphost` | `miniupnpd` via systemd |

## Where things land

- `output/` — all generated reports, rulesets, alert files, whitepapers.
- `defense/cve_monitor/state.json` — CVE dedupe state (delete to force a full re-alert).
- `config/` — your copies of the `.example.json` files.
