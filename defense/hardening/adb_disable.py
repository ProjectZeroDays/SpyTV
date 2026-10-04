"""Find and shut down ADB-over-network exposure on networks you administer.

What it does:
  1. Scans your subnet for TCP/5555 (network ADB) and TCP/5037 (adb server).
  2. Prints per-vendor instructions for disabling network debugging on the TVs.
  3. Hardens the local machine: stops the ADB server and (with --apply, admin
     shell) adds host-firewall rules blocking inbound 5037/5555.

All state-changing actions are dry-run by default; pass --apply to execute.

Usage:
    python -m defense.hardening.adb_disable --network 192.168.1.0/24
    python -m defense.hardening.adb_disable --local
    python -m defense.hardening.adb_disable --local --apply
"""
from __future__ import annotations

import argparse
import platform
import shutil

from ..common import LOG, run_or_preview
from .attack_surface import resolve_hosts, tcp_open

ADB_PORTS = (5555, 5037)

VENDOR_DISABLE_STEPS = """\
### Android TV / Google TV (Sony, TCL, Hisense, Philips, Toshiba ...)
Settings -> Device Preferences -> About -> click "Build" 7 times to enable
Developer options -> back -> Developer options -> set **USB debugging** and
**Network debugging** to off. On newer Google TV: Settings -> System ->
Developer options.

### Amazon Fire TV / Fire TV Edition TVs
Settings -> My Fire TV (or Device & Software) -> Developer Options ->
**ADB Debugging** off (and "Apps from Unknown Sources" off).

### Samsung (Tizen)
Developer Mode is enabled via the SmartThings/TV Developer Mode app; open the
Dev Mode app on the TV and turn Developer Mode **off**, then power-cycle.
Samsung TVs have no port-5555 ADB; an open 5555 here usually means an attached
Android device/dongle — identify it.

### LG (webOS)
webOS Dev Mode expires by design; open the Developer Mode app on the TV and
**Delete** the dev mode session (also revokes the dev-mode certificate), or
Settings -> General -> Devices -> External Devices and remove paired dev tools.

### Roku
Roku has no ADB. Port 5555 open on something claiming to be a Roku means the
host is misidentified — re-check with `python -m defense.hardening.attack_surface`.
"""

LOCAL_STEPS_WINDOWS = """\
Windows local hardening:
  - Stop any running ADB server:            adb kill-server
  - Block inbound ADB server/debug ports:
      netsh advfirewall firewall add rule name="Block inbound adb server (5037)" dir=in action=block protocol=TCP localport=5037
      netsh advfirewall firewall add rule name="Block inbound network ADB (5555)" dir=in action=block protocol=TCP localport=5555
"""

LOCAL_STEPS_LINUX = """\
Linux local hardening:
  - Stop any running ADB server:            adb kill-server
  - Block the ports (ufw):
      ufw deny in 5037/tcp
      ufw deny in 5555/tcp
    (iptables equivalent: iptables -A INPUT -p tcp --dport 5555 -j DROP ; ... 5037)
"""


def find_adb_exposures(hosts: list[str], timeout: float = 0.8) -> dict[int, list[str]]:
    found: dict[int, list[str]] = {p: [] for p in ADB_PORTS}
    for host in hosts:
        for port in ADB_PORTS:
            if tcp_open(host, port, timeout):
                found[port].append(host)
    return found


def report_network(findings: dict[int, list[str]]) -> str:
    lines = []
    for port, hosts in findings.items():
        if not hosts:
            lines.append(f"- TCP/{port}: no hosts exposed.")
        else:
            label = "network ADB (full device control)" if port == 5555 else "adb server"
            lines.append(f"- **TCP/{port} ({label}) exposed on: {', '.join(hosts)}**")
    if findings.get(5555):
        lines.append("")
        lines.append("Port 5555 exposure is CRITICAL: on most TVs, network ADB grants a "
                     "shell with no on-screen confirmation. Disable it using the vendor "
                     "steps below, then re-scan.")
    return "\n".join(lines)


def harden_local(apply: bool) -> list[list[str]]:
    """Preview/execute local hardening commands; returns commands regardless."""
    is_windows = platform.system() == "Windows"
    cmds: list[list[str]] = []
    if shutil.which("adb"):
        cmds.append(["adb", "kill-server"])
    if is_windows:
        cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                     'name="Block inbound adb server (5037)"', "dir=in", "action=block",
                     "protocol=TCP", "localport=5037"])
        cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                     'name="Block inbound network ADB (5555)"', "dir=in", "action=block",
                     "protocol=TCP", "localport=5555"])
    else:
        cmds.append(["ufw", "deny", "in", "5037/tcp"])
        cmds.append(["ufw", "deny", "in", "5555/tcp"])
    for cmd in cmds:
        run_or_preview(cmd, apply=apply, note="local ADB hardening")
    LOG.info("Local steps reference:\n%s", LOCAL_STEPS_WINDOWS if is_windows else LOCAL_STEPS_LINUX)
    return cmds


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--network", help="CIDR to scan for exposed ADB ports, e.g. 192.168.1.0/24")
    ap.add_argument("--hosts", help="Comma-separated host list (alternative to --network)")
    ap.add_argument("--local", action="store_true", help="Harden this machine (dry-run unless --apply)")
    ap.add_argument("--apply", action="store_true", help="Actually execute local state-changing commands")
    args = ap.parse_args(argv)

    if not args.network and not args.hosts and not args.local:
        ap.error("nothing to do: pass --network/--hosts and/or --local")

    if args.network or args.hosts:
        hosts = resolve_hosts(args.network, args.hosts)
        LOG.info("Scanning %d host(s) for ADB exposure ...", len(hosts))
        findings = find_adb_exposures(hosts)
        print(report_network(findings))
        if findings[5555]:
            print()
            print(VENDOR_DISABLE_STEPS)

    if args.local:
        harden_local(apply=args.apply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
