# Hardening Guide

Every module is read-only by default; anything that changes state requires
`--apply` and prints the exact command first. Reports land in `output/`.

## 1. Attack-surface audit — `defense.hardening.attack_surface`

```bash
python -m defense.hardening.attack_surface --network 192.168.1.0/24
python -m defense.hardening.attack_surface --hosts 10.0.0.5,10.0.0.9 --json out.json
```

Connect-checks a registry of TV-relevant ports (Telnet, ADB 5555, SSH, vendor
control surfaces, DLNA, DIAL, RTSP) and writes a risk-ranked report:
CRITICAL (23/5555), HIGH (SSH, dev-mode APIs, DLNA), MEDIUM (ECP/DIAL/RTSP),
LOW (generic HTTP). Reading the report:

- **Every CRITICAL is same-day work.** Telnet means disable-in-firmware;
  ADB means the TV's developer settings have network debugging on.
- **HIGH entries are reachability problems** — the surface exists, so make
  sure only the media VLAN can touch it (step 4).
- Re-run after remediation and compare reports; the delta is your evidence.

## 2. ADB hardening — `defense.hardening.adb_disable`

```bash
python -m defense.hardening.adb_disable --network 192.168.1.0/24   # find + vendor steps
python -m defense.hardening.adb_disable --local                    # preview local actions
python -m defense.hardening.adb_disable --local --apply            # execute (admin)
```

Per-vendor disable paths for Android/Google TV, Fire TV, Samsung dev mode,
and LG webOS dev mode are printed for every exposed host. `--local` stops
the ADB server and adds inbound blocks for 5037/5555 (netsh on Windows, ufw
on Linux).

## 3. UPnP/SSDP close-down — `defense.hardening.upnp_close`

```bash
python -m defense.hardening.upnp_close                       # enumerate + report
python -m defense.hardening.upnp_close --apply --block-inbound --stop-service
```

M-SEARCH discovery shows exactly what any LAN sweep sees: every responding
device with its USN, SERVER header, and LOCATION URL. The report's router
guidance covers pfSense/OPNsense, UniFi, and consumer firmware; the
fundamentals: UPnP/IGD off at the router, SSDP blocked inbound at the WAN
edge, DLNA renderers off on TVs unless actively used (then media-VLAN only).

## 4. IoT VLAN segmentation — `defense.hardening.vlan_segmentation`

```bash
copy config\vlan_policy.example.json config\vlan_policy.json   # edit subnets/DNS
python -m defense.hardening.vlan_segmentation
```

Generates `output/vlan/nftables.rules`, `iptables.rules`, and a
`SEGMENTATION_GUIDE.md` covering pfSense/OPNsense, UniFi, Omada, and mDNS
reflection for casting. Policy schema:

| Key | Meaning |
|---|---|
| `trusted_subnet` / `iot_subnet` | The two segments; IoT may not initiate to trusted |
| `allow.dns_servers` | Resolvers IoT may reach (include your gateway DNS if IoT uses it) |
| `allow.ntp_udp` | Allow UDP/123 (TVs need time for TLS) |
| `allow.outbound_tcp` | Vendor-cloud ports, normally `[80, 443]` |
| `block_iot_to_rfc1918` | Optionally drop all other private-space destinations too |

Apply the ruleset on the gateway (not a TV), then verify from the IoT side
that trusted hosts are unreachable.

## 5. Firmware hygiene — `defense.hardening.firmware_audit`

Maintain `config/devices.json` (schema in `devices.example.json`):
`name, vendor, model, firmware, auto_update, last_checked (YYYY-MM-DD)`.
The audit flags: auto-update disabled (HIGH), check-in older than 90 days
(MEDIUM), missing firmware/model (inventory debt), unknown vendor (LOW) —
each with the vendor's own update-path text. The signed-update checklist is
the rule that matters most: **updates only via the TV's built-in mechanism
or the vendor's official source; any device with a sideload history gets a
factory reset.**

## Sequencing for an engagement

1. `attack_surface` (evidence) → 2. `adb_disable` + `upnp_close` (close
CRITICALs) → 3. `vlan_segmentation` (contain what remains) →
4. `firmware_audit` (keep patched) → 5. `attack_surface` again (prove the
delta) → 6. hand the client the reports plus the whitepaper.
