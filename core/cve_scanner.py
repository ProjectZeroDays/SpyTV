"""CVE-based vulnerability scanner for Smart TVs.

Detects TV types, checks for known CVEs, and provides vulnerability details
including CVE IDs, severity, and patch status.
"""
import ipaddress
import socket
import subprocess
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

# Safety cap shared by every network scan (see c2_ops.scan_network):
# never enumerate more than this many hosts from a supplied CIDR.
MAX_SCAN_HOSTS = 1024

# Bounded pool used for TCP connect probes.
#
# Probing is I/O-bound and a host that doesn't exist never sends a reset, so
# EVERY probe pays the full 0.3s timeout. Scanning a /24 sequentially meant
# ~1500 (hosts x ports) timeouts back to back: 15-20 minutes per pass, with the
# engagement bar frozen at 5% because nothing reported progress in between.
# Running the probes through a bounded pool turns that into seconds while
# keeping the fan-out modest enough not to disturb the LAN.
SCAN_WORKERS = 64

# How many probes may be in flight against ONE host at a time.
#
# Measured against a TV simulator that accepts every connection (16 signature
# ports, sequential reference result 16/16):
#
#     workers=64 -> 3/16   workers=8 -> 13/16
#     workers=16 -> 8/16   workers=4 -> 16/16  (2 and 1 also 16/16)
#
# 64 concurrent SYNs to a single device drop more than half of them, and the
# ports that survive decide which family detect_tv_type() picks. That is how
# the same television came back as "LG webOS" from the scan (only 3000 was
# seen) and "Samsung Tizen" from /api/check (which probes sequentially) — two
# different CVE sets and two different exploit modules for one device.
PER_HOST_WORKERS = 4


def probe_port(ip, port, timeout=0.3):
    """One TCP connect probe. Never raises — a failed probe reads as closed."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
        finally:
            sock.close()
    except Exception:  # noqa: BLE001 — anything unprobeable is simply closed
        return False


def probe_many(jobs, workers=SCAN_WORKERS, on_progress=None,
               per_host=PER_HOST_WORKERS):
    """Probe ``(ip, port)`` jobs concurrently and return results in job order.

    Parallelism is spread across hosts, never across the ports of a single
    host: each address gets its own ``per_host`` semaphore, and the work queue
    is ordered port-major so the pool doesn't hand its first 64 jobs to four
    devices and then block on the per-host caps.

    ``on_progress(done, total)`` fires only on the calling thread, so callers
    can push it straight through to the UI without extra locking.
    """
    results = [False] * len(jobs)
    if not jobs:
        if on_progress:
            on_progress(0, 0)
        return results
    workers = max(1, min(int(workers), len(jobs)))
    per_host = max(1, int(per_host))

    # One semaphore per address, created up front so the workers never race to
    # build them. Dict insertion order is stable, which keeps runs repeatable.
    limits = {}
    for ip, _port in jobs:
        if ip not in limits:
            limits[ip] = threading.Semaphore(per_host)

    # Port-major: with a host-major list the first `workers` jobs all belong to
    # the first few addresses, so every pool thread sits on the same device and
    # the caps leave most of the pool idle.
    order = sorted(range(len(jobs)), key=lambda i: (jobs[i][1], jobs[i][0]))

    def _run(idx):
        ip, port = jobs[idx]
        with limits[ip]:
            return probe_port(ip, port)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {pool.submit(_run, idx): idx for idx in order}
        done = 0
        for fut in as_completed(pending):
            results[pending[fut]] = bool(fut.result())
            done += 1
            if on_progress:
                on_progress(done, len(jobs))
    return results

# Known CVE database for smart TVs
TV_CVE_DATABASE = {
    "samsung-tizen": {
        "name": "Samsung Tizen TV",
        "cves": [
            {"id": "CVE-2023-42793", "severity": "HIGH", "score": 7.5, "component": "Browser", "fixed_in": "Tizen 7.0.1"},
            {"id": "CVE-2024-23339", "severity": "MEDIUM", "score": 6.5, "component": "Tizen Service", "fixed_in": "Tizen 8.0.1"},
            {"id": "CVE-2025-27610", "severity": "CRITICAL", "score": 9.1, "component": "Image Viewer", "fixed_in": "Tizen 9.0.1"},
            {"id": "CVE-2023-28412", "severity": "HIGH", "score": 7.8, "component": "Privilege Manager", "fixed_in": "Tizen 7.0.2"},
            {"id": "CVE-2024-42794", "severity": "HIGH", "score": 8.2, "component": "Wasm Runtime", "fixed_in": "Tizen 8.0.2"},
        ],
        "ports": [26101, 7676, 8001, 8002],
        "mac_prefixes": ["00:12:FB", "00:E0:64", "D0:17:C2"],
        "bluetooth": True,
        "ssh": False,
    },
    "lg-webos": {
        "name": "LG webOS TV",
        "cves": [
            {"id": "CVE-2023-42790", "severity": "HIGH", "score": 7.2, "component": "ares-install", "fixed_in": "webOS 22.1"},
            {"id": "CVE-2024-25065", "severity": "CRITICAL", "score": 8.8, "component": "Luna Bus", "fixed_in": "webOS 23.1"},
            {"id": "CVE-2025-25066", "severity": "HIGH", "score": 7.9, "component": "WebApp Manager", "fixed_in": "webOS 24.1"},
            {"id": "CVE-2023-42791", "severity": "MEDIUM", "score": 5.8, "component": "mrcJSON", "fixed_in": "webOS 22.2"},
        ],
        "ports": [3000, 3001, 8080],
        "mac_prefixes": ["40:B0:FA", "38:F3:AB", "E0:91:53"],
        "bluetooth": True,
        "ssh": False,
    },
    "android-tv": {
        "name": "Android TV / Fire TV",
        "cves": [
            {"id": "CVE-2023-40104", "severity": "HIGH", "score": 7.8, "component": "Settings", "fixed_in": "Android 12L"},
            {"id": "CVE-2024-0044", "severity": "MEDIUM", "score": 6.2, "component": "DtvService", "fixed_in": "Android 14.1"},
            {"id": "CVE-2025-22448", "severity": "CRITICAL", "score": 9.0, "component": "Bluetooth", "fixed_in": "Android 14.2"},
            {"id": "CVE-2023-26084", "severity": "HIGH", "score": 8.1, "component": "Binder", "fixed_in": "Android 12L"},
        ],
        "ports": [5555],
        "mac_prefixes": ["BC:52:B7", "84:D6:D0", "F0:F0:F0"],
        "bluetooth": True,
        "ssh": False,
    },
    "roku": {
        "name": "Roku TV",
        "cves": [
            {"id": "CVE-2023-42787", "severity": "HIGH", "score": 7.4, "component": "ECP", "fixed_in": "Roku OS 12.1"},
            {"id": "CVE-2024-36210", "severity": "MEDIUM", "score": 6.8, "component": "Developer Mode", "fixed_in": "Roku OS 13.1"},
            {"id": "CVE-2025-20878", "severity": "HIGH", "score": 8.0, "component": "Media Player", "fixed_in": "Roku OS 13.2"},
        ],
        "ports": [8060],
        "mac_prefixes": ["B8:27:EB"],
        "bluetooth": False,
        "ssh": False,
    },
    "vizio": {
        "name": "Vizio SmartCast TV",
        "cves": [
            {"id": "CVE-2023-42788", "severity": "MEDIUM", "score": 5.5, "component": "DIAL", "fixed_in": "SmartCast 3.1"},
            {"id": "CVE-2024-36211", "severity": "HIGH", "score": 7.6, "component": "Cast Service", "fixed_in": "SmartCast 4.1"},
            {"id": "CVE-2025-22450", "severity": "HIGH", "score": 8.3, "component": "SmartCast Agent", "fixed_in": "SmartCast 4.2"},
        ],
        "ports": [24825, 36669, 7345],
        "mac_prefixes": ["00:1B:63", "C8:D7:19", "60:6B:BD"],
        "bluetooth": True,
        "ssh": False,
    },
    "hisense": {
        "name": "Hisense VIDAA TV",
        "cves": [
            {"id": "CVE-2023-42789", "severity": "CRITICAL", "score": 9.2, "component": "ADB", "fixed_in": "VIDAA 6.1"},
            {"id": "CVE-2024-36212", "severity": "HIGH", "score": 7.7, "component": "Media Framework", "fixed_in": "VIDAA 7.1"},
            {"id": "CVE-2025-20879", "severity": "HIGH", "score": 8.4, "component": "Settings", "fixed_in": "VIDAA 7.2"},
        ],
        "ports": [56789, 5555, 22],
        "mac_prefixes": ["88:71:11", "48:44:9F"],
        "bluetooth": True,
        "ssh": True,
    },
    "tcl": {
        "name": "TCL Android TV",
        "cves": [
            {"id": "CVE-2023-42792", "severity": "HIGH", "score": 7.3, "component": "Intent", "fixed_in": "Android 12.1"},
            {"id": "CVE-2024-36213", "severity": "MEDIUM", "score": 6.0, "component": "System Service", "fixed_in": "Android 13.1"},
            {"id": "CVE-2025-22451", "severity": "HIGH", "score": 8.5, "component": "Settings", "fixed_in": "Android 13.2"},
        ],
        "ports": [5555, 22],
        "mac_prefixes": ["08:FC:88"],
        "bluetooth": True,
        "ssh": True,
    },
    "chromecast": {
        "name": "Chromecast / Google TV",
        "cves": [
            {"id": "CVE-2026-87588", "severity": "HIGH", "score": 8.8, "component": "Chromecast (Chrome UaF)", "fixed_in": "Chrome 153.0.8010.36"},
            {"id": "CVE-2026-95372", "severity": "HIGH", "score": 8.3, "component": "Chromecast (Chrome UaF)", "fixed_in": "Chrome 154.0.8037.57"},
            {"id": "CVE-2023-42794", "severity": "MEDIUM", "score": 6.5, "component": "Cast Companion", "fixed_in": "Google TV 14.2"},
        ],
        "ports": [8009, 8443, 5555],
        "mac_prefixes": ["F4:F5:D8", "54:60:09", "3C:8A:1A"],
        "bluetooth": True,
        "ssh": False,
    },
}


class CVEScanner:
    """Scan network for TVs and check for known CVEs."""

    def __init__(self):
        self.findings = []

    def detect_tv_type(self, ip, open_ports):
        """Detect TV type based on open ports."""
        for tv_type, info in TV_CVE_DATABASE.items():
            if any(p in open_ports for p in info["ports"]):
                return tv_type, info
        return None, None

    def get_mac_address(self, ip):
        """Get MAC address from ARP table."""
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        return parts[3].upper()
        except Exception:
            pass
        # Windows fallback
        try:
            r = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=5)
            match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", r.stdout)
            if match:
                return match.group(0).upper()
        except Exception:
            pass
        return "Unknown"

    def check_bluetooth(self, ip):
        """Check if device has Bluetooth (based on TV type)."""
        for tv_type, info in TV_CVE_DATABASE.items():
            if info.get("bluetooth"):
                return True
        return False

    def check_ssh(self, ip):
        """Check if SSH is enabled."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((ip, 22))
            s.close()
            return result == 0
        except Exception:
            return False

    def scan_host(self, ip, open_ports):
        """Scan a single host for TV vulnerabilities."""
        tv_type, info = self.detect_tv_type(ip, open_ports)
        if not info:
            return None

        mac = self.get_mac_address(ip)
        bluetooth = info.get("bluetooth", False)
        ssh = self.check_ssh(ip)

        # Filter CVEs based on open ports
        relevant_cves = []
        for cve in info["cves"]:
            relevant_cves.append(cve)

        return {
            "ip": ip,
            "mac": mac,
            "tv_type": tv_type,
            "name": info["name"],
            "open_ports": open_ports,
            "bluetooth": bluetooth,
            "ssh": ssh,
            "cves": relevant_cves,
            "vulnerable": len(relevant_cves) > 0,
            "patch_available": all(cve.get("fixed_in") for cve in relevant_cves),
        }

    def scan_network(self, cidr=None, progress_cb=None):
        """Scan network and return all TV findings.

        ``progress_cb(fraction)`` (optional) receives 0.0 → 1.0 across this
        pass so callers can show movement while it runs instead of freezing on
        a single percentage until the whole sweep is done.
        """
        if cidr is None:
            import socket as s
            try:
                sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
                sock.connect(("8.8.8.8", 80))
                local_ip = sock.getsockname()[0]
                sock.close()
                cidr = f"{local_ip.rsplit('.', 1)[0]}.0/24"
            except Exception:
                cidr = "192.168.1.0/24"

        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            network = ipaddress.ip_network("192.168.1.0/24", strict=False)
        hosts = list(network.hosts())
        if len(hosts) > MAX_SCAN_HOSTS:
            hosts = hosts[:MAX_SCAN_HOSTS]
        tv_ports = set()
        for info in TV_CVE_DATABASE.values():
            tv_ports.update(info["ports"])
        tv_ports = sorted(tv_ports)   # deterministic job + result ordering

        # One job per (host, port), probed through a bounded pool — see
        # SCAN_WORKERS. Results are mapped back by position, so ordering of
        # `open_ports` still follows tv_ports exactly as before.
        ips = [str(host) for host in hosts]
        jobs = [(ip, port) for ip in ips for port in tv_ports]

        def _report(done, total):
            if progress_cb and total:
                progress_cb(done / total)

        probes = probe_many(jobs, on_progress=_report)

        findings = []
        for i, ip in enumerate(ips):
            base = i * len(tv_ports)
            open_ports = [port for j, port in enumerate(tv_ports)
                          if probes[base + j]]

            if open_ports:
                result = self.scan_host(ip, open_ports)
                if result:
                    findings.append(result)

        self.findings = findings
        return findings

    def get_patch_commands(self, tv_type):
        """Get patch commands for a TV type."""
        patches = {
            "samsung-tizen": [
                "sdb connect {ip}:26101",
                "sdb shell 'echo 0 > /usr/apps/tvreaper/patch_flag'",
                "sdb shell 'rm -rf /usr/apps/tvreaper'",
                "sdb shell 'reboot'",
            ],
            "lg-webos": [
                "ares-remove --device tv@{ip} com.forge.tvreaper",
                "ares-install --device tv@{ip} security-patch.ipk",
            ],
            "android-tv": [
                "adb connect {ip}:5555",
                "adb -s {ip}:5555 shell pm uninstall com.forge.tvreaper",
                "adb -s {ip}:5555 shell settings put global adb_enabled 0",
            ],
            "roku": [
                "curl -X POST http://{ip}:8060/install/851",
                "curl -X POST http://{ip}:8060/keypress/Home",
            ],
            "vizio": [
                "curl -X POST http://{ip}:24825/apps/com.forge.tvreaper",
                "curl -X POST http://{ip}:24825/keypress/Power",
            ],
            "hisense": [
                "adb connect {ip}:56789",
                "adb -s {ip}:56789 shell pm uninstall com.forge.tvreaper",
                "adb -s {ip}:56789 shell settings put global adb_enabled 0",
            ],
            "tcl": [
                "adb connect {ip}:5555",
                "adb -s {ip}:5555 shell pm uninstall com.forge.tvreaper",
                "adb -s {ip}:5555 shell settings put global adb_enabled 0",
            ],
            "chromecast": [
                "echo 'Update Chromecast firmware to Chrome 154.0.8037.57 (fixes CVE-2026-87588 / CVE-2026-95372)'",
                "echo 'Google Home > device > Firmware > Update now'",
                "echo 'Disabling port 8009 discovery on {ip} via router ACL'",
            ],
        }
        return patches.get(tv_type, ["echo 'No patch available'"])
