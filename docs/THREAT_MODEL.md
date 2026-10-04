# Threat Model

The classes below describe how smart TV compromise actually happens in
practice — recon, entry, persistence, capture, exfil — and the control in
this toolkit that answers each stage. `CODE_REVIEW.md` documents a real
offensive framework attempt covering these same classes; this page is its
defensive mirror.

## Stage 1 — Reconnaissance

**What the adversary does.** Discovery sweeps to inventory TVs: SSDP
M-SEARCH fan-out, banner probes against known vendor ports (Samsung 8001/7676,
LG 3000/3001, Roku 8060, Philips 9197, HiSense 56789, DLNA 49152+), and
port scans for SSH/ADB.

**Signature.** One source generating high-rate or high-fan-out SSDP, or
probing many vendor ports in sequence.

**Controls.** `SsdpAnomalyDetector` (rate + distinct-destination windows);
Sigma rule `net_ssdp_sweep.yml`; reduce the attack surface itself with
`attack_surface.py` so recon finds less.

## Stage 2 — Entry

**What the adversary does.**

| Vector | Why it works |
|---|---|
| Network ADB (TCP/5555) | Grants a shell on Android-based TVs with no on-device prompt in most configurations |
| SSH default credentials | TV/IoT images ship with root/admin-class defaults and no lockout |
| Developer-mode surfaces | Tizen dev mode, webOS dev mode, Philips Jointspace — pairing-free control APIs when enabled |
| DLNA/UPnP AVTransport | SOAP media-control endpoints; a known command-injection class on several stacks |
| Sideloading | "Updates" and apps from outside the vendor store are the classic implant-delivery path |

**Controls.** `SshBruteForceDetector` (sliding-window credential attack
detection); `RogueAdbDetector` (connections to 5555/5037 outside the
allowlist, `adb connect` process usage, device attach); Sigma rules
`win_adb_network_connect.yml`, `net_adb_ports.yml`, `lnx_sshd_bruteforce.yml`,
`net_upnp_avtransport.yml`; hardening closes the doors (`adb_disable`,
`upnp_close`, `attack_surface` findings).

## Stage 3 — Persistence

**What the adversary does.** Installs an app/widget (dev mode, sideload) so
access survives reboots; the goal is a payload that lives on the TV's own app
surface.

**Controls.** Prevent installation: disable dev mode (see Hardening Guide),
never sideload, vendor-store apps only. Detect staging: the installation
paths traverse Stage-2 vectors the detectors already watch. Post-incident:
the firmware checklist's rule — a TV that has ever run sideloaded content
gets factory-reset and reimaged.

## Stage 4 — Covert capture

**What the adversary does.** With code running on the TV: microphone/camera
access via platform media APIs, and "fake-off" tricks (screen dark, SoC and
network alive) so the owner believes the device is off.

**Controls.** This stage is reached only through Stages 2–3, so the front
doors are the primary control. Physical tell: a "powered off" TV that still
answers on the network (ping/port) is suspicious — `attack_surface.py` on a
schedule makes that check routine. Microphone-equipped TVs should have
voice-recognition agreements and storage handled per policy; where secrecy
matters, unplug — the only undefeated control.

## Stage 5 — Exfiltration

**What the adversary does.** Ships captured data out over the LAN to a
collector host, sometimes via fallback channels (DNS, covert HTTP).

**Controls.** Segmentation is the structural answer: an IoT VLAN whose
devices may only reach DNS/NTP/vendor-HTTPS cannot exfiltrate to your file
servers or pivot (`vlan_segmentation`). On-host egress anomalies and
unexpected listener ports on the segment show up in recurring
`attack_surface.py` diffs.

## Residual risk (be honest with clients)

A bespoke, zero-click, supply-chain-grade implant does not traverse these
paths; commodity tooling overwhelmingly does. Detection here catches the
attack classes that actually hit real networks; nation-state phantoms are a
leak-and-researcher problem, not a dashboard problem.
