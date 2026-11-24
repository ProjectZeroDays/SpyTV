"""Live-host pre-seed: find the hosts that answer before TCP-probing everything.

A /24 TCP sweep probes hundreds of silent addresses at ~0.3s each even with
a bounded pool. Most of that work is wasted: the hosts were never there.
This module finds the live ones cheaply —

1. parallel ICMP echo sweep (short deadline, one packet per host), then
2. the OS ARP table, which the sweep itself just populated (devices that
   drop ICMP still answer ARP on their own subnet).

and the scanners only TCP-probe the union. Any failure — no ping binary,
ARP parse error, empty result — returns None and the caller probes the full
range, so pre-seeding can never make a scan see *less* than it used to.

Results are cached briefly (one TTL per network string) because a single
audit runs the generic pass and the CVE sweep back to back and shouldn't
ping the network twice.
"""
import ipaddress
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

_TIMEOUT_MS = 250
_WORKERS = 128
_TTL_SECONDS = 60
_MAX_HOSTS = 4096

_cache = {}
_cache_lock = threading.Lock()


def read_arp_table_map():
    """``{ip: mac}`` from the OS ARP cache (MACs uppercased, as listed).

    One batch read replaces a per-IP subprocess round-trip in finalize, and
    sees everything the ping sweep just populated — even entries that have
    since aged out of a per-IP lookup's view.
    """
    table = {}
    if os.name == "nt":
        try:
            out = subprocess.run(["arp", "-a"], capture_output=True,
                                 text=True, timeout=10).stdout
            for line in out.splitlines():
                m = re.match(
                    r"\s*(\d+\.\d+\.\d+\.\d+)\s+"
                    r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", line)
                if m:
                    table[m.group(1)] = m.group(2).upper()
        except Exception:  # noqa: BLE001 — no ARP data is not fatal
            pass
        return table
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3].upper()
    except OSError:
        pass
    return table


def read_arp_table():
    """IPv4 addresses visible in the OS ARP cache, as a set of strings."""
    return set(read_arp_table_map().keys())


def _ping_cmd(ip, timeout_ms):
    if os.name == "nt":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    # -W is whole-second deadline on GNU ping; ceil the millisecond budget.
    return ["ping", "-c", "1", "-W", str(max(1, (timeout_ms + 999) // 1000)),
            ip]


def _ping_host(ip, timeout_ms):
    try:
        return subprocess.run(_ping_cmd(ip, timeout_ms),
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              timeout=(timeout_ms / 1000.0) + 1.0
                              ).returncode == 0
    except Exception:  # noqa: BLE001 — treat ping failure as "no answer"
        return False


def _sweep(network):
    hosts = [str(h) for h in network.hosts()][: _MAX_HOSTS]
    if not hosts:
        return None
    try:
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            flags = list(pool.map(lambda ip: _ping_host(ip, _TIMEOUT_MS),
                                  hosts))
    except Exception:  # noqa: BLE001
        return None
    answered = {ip for ip, ok in zip(hosts, flags) if ok}
    try:
        arp = read_arp_table()
        answered |= arp.intersection(hosts)
    except Exception:  # noqa: BLE001
        pass
    return answered or None


def live_hosts(network):
    """Live IPs in ``network`` (an IPv4Network), or None to mean "unknown".

    None/empty always falls back to a full TCP probe by the caller, so this
    function failing safe looks exactly like the old behavior.
    """
    if isinstance(network, str):
        try:
            network = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return None
    if network.version != 4:
        return None
    key = str(network)
    now = time.monotonic()
    with _cache_lock:
        stamp, cached = _cache.get(key, (0.0, None))
        if cached is not None and now - stamp < _TTL_SECONDS:
            return cached
    live = _sweep(network)
    # An empty answer means "couldn't tell", which callers treat as
    # probe-everything — same as a failure. The full-scan fallback lives in
    # the scanners, not here.
    if not live:
        live = None
    with _cache_lock:
        _cache[key] = (now, live)
    return live


def clear_cache():
    """Forget cached liveness (tests, and scans forced to re-discover)."""
    with _cache_lock:
        _cache.clear()
