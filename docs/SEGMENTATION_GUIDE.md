# IoT VLAN Segmentation

_Generated 2026-10-03T07:40:57+00:00 by the SpyTV defensive toolkit._

## Policy

- Trusted subnet: `192.168.10.0/24`
- IoT/TV subnet: `192.168.20.0/24`
- Approved DNS: 192.168.10.1, 1.1.1.1
- Outbound TCP: [80, 443]
- Block IoT to all RFC1918: False

## How to apply

### Goal
Put TVs and other IoT devices on their own VLAN/subnet, and make that segment
**initiate nothing toward the trusted LAN** while still reaching DNS, NTP, and
vendor cloud (TCP 80/443).

### Router / switch platforms
- **pfSense / OPNsense**: Interfaces -> assign the IoT VLAN; Firewall -> Rules
  on the IoT interface: pass DNS/NTP/HTTP(S) out, then a block rule
  IoT net -> LAN net (log enabled). Leave the default allow-to-WAN last.
- **UniFi**: Settings -> Networks -> create "IoT" VLAN network; Security ->
  Traffic & Firewall Rules: block IoT -> Local Networks, allow IoT -> Internet.
- **Omada (TpLink)**: create the VLAN in Settings -> Network; Firewall/ACL:
  deny IoT -> LAN subnet, permit IoT -> any on 80/443/53/123.
- **Plain Linux gateway**: review and apply the generated `nftables.rules`
  (or `iptables.rules`).

### Casting across VLANs (mDNS reflection)
Chromecast/SmartCast discovery uses multicast DNS (5353). If phones live on the
trusted VLAN and TVs on the IoT VLAN, run an **Avahi reflector** on the gateway
scoped to only those two interfaces — or keep the casting phone on the IoT SSID.
Do NOT solve this by merging the VLANs; reflection is the controlled exception.

### Wi-Fi
Give the IoT VLAN its own SSID (2.4 GHz usually enough for TVs), WPA2/WPA3, and
disable any "guest isolation OFF" convenience that places TVs on the LAN.

### Verification
After applying, from the IoT side try to reach a trusted host on any port
(should fail), and run `python -m defense.hardening.attack_surface --hosts <tv-ip>`
from the trusted side: management surfaces should still answer, but nothing new
should be reachable from guest networks.
