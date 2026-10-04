"""Smart TV attack-surface auditor for networks you own or are authorized to assess.

Performs read-only TCP connect checks against ports associated with smart TV
management, debugging, and media surfaces, then produces a risk-ranked
markdown report. It never changes device or host state.

Usage:
    python -m defense.hardening.attack_surface --network 192.168.1.0/24
    python -m defense.hardening.attack_surface --network 192.168.1.0/24 --json out.json
    python -m defense.hardening.attack_surface --hosts 192.168.1.42,192.168.1.55
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import socket
from dataclasses import asdict, dataclass
from pathlib import Path

from ..common import LOG, OUTPUT_DIR, write_markdown

# port: (surface name, risk, finding guidance)
PORT_REGISTRY: dict[int, tuple[str, str, str]] = {
    23: ("Telnet", "CRITICAL", "Clear-text management console. Disable in firmware; block at the firewall immediately."),
    5555: ("ADB over network", "CRITICAL", "Full device control with no console prompt on most TVs. Disable 'Network/ADB debugging' in developer settings (see defense.hardening.adb_disable)."),
    22: ("SSH", "HIGH", "Management shell exposed on a TV/IoT segment. Default credentials are common; restrict to an admin subnet or disable."),
    3000: ("LG webOS first-screen service", "HIGH", "webOS TV control surface; should only be reachable from the media VLAN (see defense.hardening.vlan_segmentation)."),
    3001: ("LG webOS legacy ROAP", "HIGH", "Legacy pairing-free control API; restrict reachability."),
    8001: ("Samsung dev/API", "HIGH", "Samsung SmartThings/developer surface; disable Developer Mode on the TV."),
    8002: ("Samsung dev/API (alt)", "HIGH", "As above."),
    9197: ("Philips Jointspace", "HIGH", "Legacy unauthenticated control API on many Philips models; restrict or update firmware."),
    56789: ("HiSense local service", "HIGH", "Vendor local channel historically used for sideload-class tooling; restrict to media VLAN."),
    49152: ("UPnP/DLNA AVTransport", "HIGH", "SOAP control of media functions and a known command-injection class; disable UPnP AV on the device (see defense.hardening.upnp_close)."),
    49153: ("UPnP/DLNA (alt)", "HIGH", "As above."),
    554: ("RTSP", "MEDIUM", "Stream control; keep inside the media VLAN only."),
    8554: ("RTSP (alt)", "MEDIUM", "As above."),
    7676: ("Samsung DMP websocket", "MEDIUM", "Samsung app-layer surface; restrict reachability."),
    8060: ("Roku ECP", "MEDIUM", "External Control Protocol allows local control of the TV; acceptable on a media VLAN, not reachable from guest/other VLANs."),
    8008: ("DIAL/Chromecast", "MEDIUM", "Cast discovery and app launch; media VLAN only."),
    8009: ("Chromecast (alt)", "MEDIUM", "As above."),
    36669: ("Vizio SmartCast", "MEDIUM", "SmartCast local API; media VLAN only."),
    7345: ("DIAL (alt)", "MEDIUM", "As above."),
    9999: ("Vendor web service", "MEDIUM", "Uncommon service on a TV; identify the owner and restrict."),
    80: ("HTTP", "LOW", "Vendor web UI/API; confirm it belongs to an expected device."),
    443: ("HTTPS", "LOW", "As above."),
    8080: ("HTTP (alt)", "LOW", "As above."),
    1900: ("SSDP/UPnP (UDP)", "INFO", "Audited separately by defense.hardening.upnp_close."),
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    host: str
    port: int
    surface: str
    risk: str
    guidance: str


def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolve_hosts(network: str | None, hosts: str | None) -> list[str]:
    if hosts:
        return [h.strip() for h in hosts.split(",") if h.strip()]
    if not network:
        raise ValueError("provide --network or --hosts")
    if "/" not in network:
        network += "/32"
    return [str(h) for h in ipaddress.ip_network(network, strict=False).hosts()]


def audit_network(hosts: list[str], ports: list[int] | None = None,
                  timeout: float = 0.8, workers: int = 64) -> list[Finding]:
    ports = ports or sorted(PORT_REGISTRY)
    targets = [(h, p) for h in hosts for p in ports]
    LOG.info("Auditing %d host(s) x %d port(s) = %d probes ...", len(hosts), len(ports), len(targets))
    findings: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fut_map = {ex.submit(tcp_open, h, p, timeout): (h, p) for h, p in targets}
        for fut in concurrent.futures.as_completed(fut_map):
            host, port = fut_map[fut]
            if fut.result():
                surface, risk, guidance = PORT_REGISTRY[port]
                findings.append(Finding(host, port, surface, risk, guidance))
    findings.sort(key=lambda f: (RISK_ORDER[f.risk], f.host, f.port))
    LOG.info("Found %d open service endpoint(s) across %d host(s).",
             len(findings), len({f.host for f in findings}))
    return findings


def findings_markdown(findings: list[Finding]) -> str:
    if not findings:
        return "No TV-relevant services found open. Nothing to act on from this audit."
    lines = [
        "| Host | Port | Surface | Risk | Action |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.host} | {f.port} | {f.surface} | {f.risk} | {f.guidance} |")
    return "\n".join(lines)


def summary_markdown(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.risk] = counts.get(f.risk, 0) + 1
    if not counts:
        return "No findings."
    parts = [f"{risk}: {counts[risk]}" for risk in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if risk in counts]
    return "Open endpoints by risk — " + ", ".join(parts) + "."


NEXT_STEPS = """\
1. **CRITICAL findings first** — Telnet (23) and ADB (5555) mean the device is
   remotely controllable from the LAN. Run `python -m defense.hardening.adb_disable`
   for per-vendor disable steps and local blocking.
2. **UPnP/DLNA (49152+)** — run `python -m defense.hardening.upnp_close` to enumerate
   UPnP devices and shut unnecessary exposure.
3. **Everything HIGH/MEDIUM** — these surfaces should not be reachable from trusted or
   guest networks. Run `python -m defense.hardening.vlan_segmentation` to generate an
   IoT VLAN isolation ruleset.
4. **Keep current** — run `python -m defense.hardening.firmware_audit` against your
   device inventory and `python -m defense.cve_monitor.monitor --once` for new CVEs.
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--network", help="CIDR to audit, e.g. 192.168.1.0/24")
    ap.add_argument("--hosts", help="Comma-separated explicit host list (alternative to --network)")
    ap.add_argument("--ports", help="Comma-separated port subset of the registry")
    ap.add_argument("--timeout", type=float, default=0.8)
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--out", default=str(OUTPUT_DIR / "attack_surface_report.md"))
    ap.add_argument("--json", dest="json_out", help="Also write findings as JSON to this path")
    args = ap.parse_args(argv)

    try:
        hosts = resolve_hosts(args.network, args.hosts)
    except ValueError as exc:
        ap.error(str(exc))
    ports = [int(p) for p in args.ports.split(",")] if args.ports else None

    findings = audit_network(hosts, ports, args.timeout, args.workers)
    write_markdown(
        Path(args.out),
        "Smart TV Attack-Surface Audit",
        [("Summary", summary_markdown(findings)), ("Findings", findings_markdown(findings)), ("Next steps", NEXT_STEPS)],
    )
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")
        LOG.info("JSON findings written: %s", args.json_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
