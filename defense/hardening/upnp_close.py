"""Enumerate UPnP/SSDP devices on your network and close unnecessary exposure.

What it does:
  1. Sends an SSDP M-SEARCH and lists responding UPnP devices (USN, SERVER,
     LOCATION) — this is what any LAN discovery sweep sees from your network.
  2. Checks the local host's SSDP/UPnP helper services.
  3. Emits router guidance for disabling UPnP, and with --apply can stop the
     local SSDP service and block inbound UDP/1900 at the host firewall.

State-changing actions are dry-run by default.

Usage:
    python -m defense.hardening.upnp_close
    python -m defense.hardening.upnp_close --timeout 8
    python -m defense.hardening.upnp_close --apply --block-inbound --stop-service
"""
from __future__ import annotations

import argparse
import socket
import platform
import subprocess
from pathlib import Path

from ..common import LOG, run_or_preview, write_markdown, OUTPUT_DIR

SSDP_ADDR = ("239.255.255.250", 1900)
MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode("utf-8")


def ssdp_discover(timeout: float = 5.0) -> dict[str, dict[str, str]]:
    """Return devices keyed by USN with SERVER/LOCATION/ST headers."""
    found: dict[str, dict[str, str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    try:
        sock.sendto(MSEARCH, SSDP_ADDR)
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            text = data.decode("utf-8", errors="replace")
            headers = {}
            for line in text.split("\r\n")[1:]:
                if ":" in line:
                    key, _, value = line.partition(":")
                    headers[key.strip().upper()] = value.strip()
            usn = headers.get("USN") or f"{addr[0]}:{headers.get('ST', '?')}"
            entry = found.setdefault(usn, {"ip": addr[0]})
            for want in ("SERVER", "LOCATION", "ST"):
                if headers.get(want) and want not in entry:
                    entry[want] = headers[want]
    finally:
        sock.close()
    return found


def devices_markdown(devices: dict[str, dict[str, str]]) -> str:
    if not devices:
        return "No UPnP devices responded. Either UPnP is already disabled network-wide, or discovery is blocked."
    lines = ["| IP | USN | Type (ST) | SERVER | LOCATION |", "|---|---|---|---|---|"]
    for usn, info in sorted(devices.items(), key=lambda kv: kv[1].get("ip", "")):
        lines.append(
            f"| {info.get('ip', '?')} | {usn[:60]} | {info.get('ST', '?')[:40]} "
            f"| {info.get('SERVER', '?')[:40]} | {info.get('LOCATION', '?')[:60]} |"
        )
    return "\n".join(lines)


def local_service_status() -> list[str]:
    status: list[str] = []
    if platform.system() == "Windows":
        for svc in ("SSDPSRV", "upnphost"):
            try:
                out = subprocess.run(["sc", "query", svc], capture_output=True, text=True, timeout=15).stdout
            except (OSError, subprocess.SubprocessError):
                continue
            running = "RUNNING" in out
            status.append(f"{svc}: {'RUNNING' if running else 'stopped'}")
    else:
        for svc in ("miniupnpd", "upnpd"):
            try:
                out = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                continue
            state = out.stdout.strip()
            if state and state != "inactive":
                status.append(f"{svc}: {state}")
    return status or ["No local UPnP/SSDP services detected (or systemctl unavailable)."]


ROUTER_GUIDANCE = """\
Router / network guidance (do these in the router admin UI):

1. **Disable UPnP (IGD) entirely** on the router. Manual port forwards take a
   minute to create and are auditable; UPnP lets any LAN device open inbound
   holes silently. Typical locations:
   - pfSense/OPNsense: Services -> UPnP & NAT-PMP -> disable.
   - UniFi: Settings -> Network -> (per network) -> no "UPnP" enable; global under Settings.
   - Asus/TpLink/Netlink consumer firmware: Advanced -> WAN -> "Enable UPnP" off.
2. **Block inbound UDP/1900 at the WAN edge** (anti-SSDP-reflection) if the
   router exposes a firewall ruleset.
3. **Disable UPnP AV / DLNA renderers on TVs** (Settings usually under Network
   or AllShare/DLNA) so their AVTransport SOAP endpoints (49152+) close; verify
   with `python -m defense.hardening.attack_surface`.
4. If casting must keep working across segments, prefer controlled mDNS
   reflection (see vlan_segmentation guide) over flat UPnP.
"""


def local_actions(apply: bool, block_inbound: bool, stop_service: bool) -> None:
    is_windows = platform.system() == "Windows"
    if block_inbound:
        if is_windows:
            run_or_preview(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 'name="Block inbound SSDP (UDP 1900)"', "dir=in", "action=block",
                 "protocol=UDP", "localport=1900"],
                apply=apply, note="block inbound SSDP")
        else:
            run_or_preview(["ufw", "deny", "in", "1900/udp"], apply=apply, note="block inbound SSDP")
    if stop_service:
        if is_windows:
            run_or_preview(["sc", "stop", "SSDPSRV"], apply=apply, note="stop SSDP discovery service")
            run_or_preview(["sc", "config", "SSDPSRV", "start=", "disabled"], apply=apply,
                           note="disable SSDP discovery service at boot")
        else:
            run_or_preview(["systemctl", "disable", "--now", "miniupnpd"], apply=apply,
                           note="disable miniupnpd")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--timeout", type=float, default=5.0, help="SSDP collection window in seconds")
    ap.add_argument("--apply", action="store_true", help="Execute local actions (default: dry-run)")
    ap.add_argument("--block-inbound", action="store_true", help="Block inbound UDP/1900 at the host firewall")
    ap.add_argument("--stop-service", action="store_true", help="Stop/disable the local SSDP/UPnP service")
    ap.add_argument("--out", default=str(OUTPUT_DIR / "upnp_audit.md"))
    args = ap.parse_args(argv)

    LOG.info("Discovering UPnP devices for %.0fs ...", args.timeout)
    devices = ssdp_discover(args.timeout)
    status = local_service_status()
    write_markdown(
        Path(args.out),
        "UPnP / SSDP Exposure Audit",
        [
            ("Discovered UPnP devices", devices_markdown(devices)),
            ("Local host services", "\n".join(f"- {s}" for s in status)),
            ("How to close it down", ROUTER_GUIDANCE),
        ],
    )
    print(devices_markdown(devices))
    print()
    for line in status:
        print(f"- {line}")
    if args.block_inbound or args.stop_service:
        local_actions(apply=args.apply, block_inbound=args.block_inbound, stop_service=args.stop_service)
    else:
        LOG.info("No local actions requested. Re-run with --block-inbound / --stop-service (and --apply) as needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
