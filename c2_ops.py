"""Shared operational routines for the SpyTV C2.

Imported by the HTTP handlers in ``c2_server.py`` and (via injection) by the
engagement runners in ``c2_audit.py``. The module deliberately holds no
server state so both sides can use it without circular imports.
"""
import datetime
import importlib.util
import ipaddress
import os
import socket
import shlex
import subprocess
import threading
import time

from core.cve_scanner import MAX_SCAN_HOSTS, TV_CVE_DATABASE

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
GENERATED_EXPLOITS_DIR = os.path.join(REPO_ROOT, "data", "exploits", "generated")

# Ports probed during generic discovery (kept for continuity with older scans).
GENERIC_TV_PORTS = [5555, 22, 80, 554, 8080, 1900, 7676, 3000, 8060, 36669,
                    8009, 49152]

# Child tools the exploit modules spawn — terminated during connection teardown.
EXPLOIT_TOOL_PROCS = {
    "sdb", "adb", "ares-install", "ares-novacom", "ares-package",
    "curl", "nmap", "ssh", "proxychains4",
}

_open_sockets = []
_sockets_lock = threading.Lock()
_REGISTRY_CACHE = None


def utc_now_iso():
    """Timezone-aware UTC timestamp in the legacy '...Z' string format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "")


def track_socket(sock):
    """Register a long-lived socket so kill_all_connections() can close it."""
    with _sockets_lock:
        _open_sockets.append(sock)


def signature_ports():
    """Generic TV ports + every CVE-family signature port."""
    ports = set(GENERIC_TV_PORTS)
    for info in TV_CVE_DATABASE.values():
        ports.update(info.get("ports", []))
    return sorted(ports)


def probe_ports(ip, ports=None, timeout=0.3):
    """TCP connect probe. Returns the list of open ports (read-only)."""
    open_ports = []
    for port in (ports if ports is not None else signature_ports()):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
    return open_ports


def scan_network(cidr=None):
    """Scan local network for vulnerable TVs using port scanning."""
    if cidr is None:
        cidr = _default_cidr()

    results = []
    try:
        network = ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        network = ipaddress.ip_network(_default_cidr(), strict=False)
    hosts = list(network.hosts())
    if len(hosts) > MAX_SCAN_HOSTS:
        print(f"[scan] {cidr} covers {len(hosts)} hosts — capping at "
              f"{MAX_SCAN_HOSTS} (MAX_SCAN_HOSTS)")
        hosts = hosts[:MAX_SCAN_HOSTS]
    tv_ports = [5555, 22, 80, 554, 8080, 1900, 7676, 3000, 8060, 36669, 8009, 49152]

    for host in hosts:
        ip = str(host)
        open_ports = []
        for port in tv_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    open_ports.append(port)
            except Exception:
                pass

        if open_ports:
            device_type = "Unknown"
            if 5555 in open_ports:
                device_type = "Android TV/Fire TV"
            elif 7676 in open_ports:
                device_type = "Samsung Tizen"
            elif 3000 in open_ports:
                device_type = "LG webOS"
            elif 8060 in open_ports:
                device_type = "Roku"
            elif 36669 in open_ports:
                device_type = "Vizio"
            elif 8009 in open_ports:
                device_type = "Chromecast"

            results.append({
                "ip": ip,
                "open_ports": open_ports,
                "device_type": device_type,
                "vulnerable": len(open_ports) > 0,
                "scanned_at": utc_now_iso()
            })

    return results


def _default_cidr():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return f"{local_ip.rsplit('.', 1)[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def perform_scan(cidr, scanner):
    """Full discovery pass: generic scan + CVE signature ports + family/CVE
    matching. Returns enriched findings (same shape /api/scan returns)."""
    results = scan_network(cidr)

    # Enrich with CVE-database matching: add the vulnerability signature
    # ports for every known TV family so those TVs are discovered too, then
    # attach the CVE list per finding.
    cve_ports = sorted({p for info in TV_CVE_DATABASE.values()
                        for p in info["ports"]})
    scanned_ips = {r["ip"] for r in results}
    extra_ports = [p for p in cve_ports
                   if p not in (5555, 22, 80, 8080, 8060, 36669)]
    for r in results:
        for port in extra_ports:
            if port in r["open_ports"]:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((r["ip"], port)) == 0:
                    r["open_ports"].append(port)
                s.close()
            except Exception:
                pass

    # CVE-scan pass over the whole range (picks up families the generic
    # pass missed, e.g. Samsung 26101 / LG 30000 / Hisense 56789).
    try:
        cve_findings = scanner.scan_network(cidr)
    except Exception:
        cve_findings = []
    by_ip = {r["ip"]: r for r in results}
    for f in cve_findings:
        if f["ip"] in by_ip:
            tgt = by_ip[f["ip"]]
            tgt["tv_type"] = f["tv_type"]
            tgt["device_type"] = f["name"]
            tgt["cves"] = f["cves"]
            tgt["mac"] = f.get("mac", "Unknown")
            tgt["bluetooth"] = f.get("bluetooth", False)
            tgt["ssh"] = f.get("ssh", False)
            tgt["patch_available"] = f.get("patch_available", False)
            for port in f["open_ports"]:
                if port not in tgt["open_ports"]:
                    tgt["open_ports"].append(port)
        elif f["ip"] not in scanned_ips:
            results.append(f)
            by_ip[f["ip"]] = f
            scanned_ips.add(f["ip"])

    # Attach CVE details to every finding that matched a family.
    for r in results:
        if r.get("cves"):
            r["vulnerable"] = True
            r["cve_ids"] = [c["id"] for c in r["cves"]]
            r["severity"] = max(
                (c.get("severity") or "LOW" for c in r["cves"]),
                key=lambda s: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s)
                if s in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else 0)
        else:
            tv_type, info = scanner.detect_tv_type(r["ip"], r.get("open_ports", []))
            if info:
                r["tv_type"] = tv_type
                r["name"] = info["name"]
                r["cves"] = info["cves"]
                r["cve_ids"] = [c["id"] for c in info["cves"]]
                r["vulnerable"] = True

    return results


def _load_cve_exploit_registry():
    """Lazy-load CVE_EXPLOITS {tv_type: exploit class} from data/exploits."""
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is None:
        path = os.path.join(REPO_ROOT, "data", "exploits", "cve_exploits.py")
        try:
            spec = importlib.util.spec_from_file_location("spytv_cve_exploits", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _REGISTRY_CACHE = dict(getattr(module, "CVE_EXPLOITS", {}))
        except Exception:
            _REGISTRY_CACHE = {}
    return _REGISTRY_CACHE


def exploit_availability(tv_type, cve_ids=()):
    """Built-in family module + any AI-generated per-CVE modules."""
    registry = _load_cve_exploit_registry()
    built_in = bool(tv_type) and tv_type in registry
    generated = [cid for cid in (cve_ids or [])
                 if cid and os.path.exists(os.path.join(GENERATED_EXPLOITS_DIR, f"{cid}.py"))]
    return {"built_in": built_in, "generated": generated,
            "ready": built_in or bool(generated)}


def _call_with_timeout(fn, args=(), timeout=20):
    """Run fn(*args) in a daemon thread. Returns (value, error, timed_out)."""
    out = {}

    def target():
        try:
            out["value"] = fn(*args)
        except Exception as e:  # noqa: BLE001 — surface anything the module raises
            out["error"] = str(e)

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None, None, True
    return out.get("value"), out.get("error"), False


def check_target(ip, scanner):
    """Read-only verification of one target — probe ports, match family/CVEs,
    confirm exploit availability, and run the family's dry-run version check.

    No exploit payloads are transmitted.
    """
    open_ports = probe_ports(ip, signature_ports())
    checked_at = utc_now_iso()
    if not open_ports:
        return {"ip": ip, "reachable": False, "open_ports": [], "checked_at": checked_at,
                "message": "No open ports — host is down or filtered."}

    finding = scanner.scan_host(ip, open_ports)
    tv_type = finding.get("tv_type") if finding else None
    cves = (finding or {}).get("cves", [])
    cve_ids = [c.get("id") for c in cves]
    avail = exploit_availability(tv_type, cve_ids)
    dry = dry_run_exploit(tv_type, ip) if tv_type else None

    return {
        "ip": ip,
        "reachable": True,
        "open_ports": open_ports,
        "tv_type": tv_type,
        "name": (finding or {}).get("name", "Unknown device"),
        "mac": (finding or {}).get("mac"),
        "vulnerable": bool(finding) and bool(cves),
        "cves": [{"id": c.get("id"), "severity": c.get("severity"),
                  "score": c.get("score"), "component": c.get("component"),
                  "fixed_in": c.get("fixed_in")} for c in cves],
        "exploit_ready": avail["ready"],
        "exploit_sources": {"built_in": avail["built_in"], "generated": avail["generated"]},
        "dry_run": dry,
        "checked_at": checked_at,
        "message": "Checked (read-only probe — no payloads sent).",
    }


def dry_run_exploit(tv_type, ip, timeout=25):
    """Run the family exploit's vulnerability check only (no exploitation)."""
    cls = _load_cve_exploit_registry().get(tv_type)
    if not cls:
        return {"available": False, "reason": f"no exploit module for family '{tv_type}'"}
    checker = getattr(cls, "check_vulnerable", None)
    if checker is None:
        return {"available": False, "reason": "module has no dry-run check"}
    value, error, timed_out = _call_with_timeout(lambda: cls().check_vulnerable(ip),
                                                 timeout=timeout)
    if timed_out:
        return {"available": True, "timeout": True,
                "error": f"version check exceeded {timeout}s"}
    if error:
        return {"available": True, "error": error}
    result = {"available": True}
    result.update(value or {})
    return result


def run_exploit(tv_type, ip, timeout=90):
    """Execute the family exploit module against the target (audit send phase)."""
    cls = _load_cve_exploit_registry().get(tv_type)
    if not cls:
        return {"attempted": False, "success": False,
                "error": f"no exploit module for family '{tv_type}'"}
    started = time.time()
    value, error, timed_out = _call_with_timeout(lambda: cls().run(ip),
                                                 timeout=timeout)
    duration = round(time.time() - started, 1)
    if timed_out:
        return {"attempted": True, "success": False, "timed_out": True,
                "duration_s": duration, "error": f"attempt exceeded {timeout}s"}
    if error:
        return {"attempted": True, "success": False, "duration_s": duration,
                "error": error}
    return {"attempted": True, "success": bool(value), "duration_s": duration}


def execute_patches(ip, tv_type, scanner, timeout_per_cmd=45):
    """Execute a family's remediation commands against one device.

    Returns per-command status/output so callers (Patch button, patch-all
    engagement, reports) can prove exactly what ran and what failed.
    """
    patches = scanner.get_patch_commands(tv_type)
    patch_results = []
    for cmd in patches:
        cmd_formatted = cmd.replace("{ip}", ip)
        entry = {"command": cmd_formatted, "status": "executed",
                 "output": "", "returncode": 0}
        if cmd_formatted.startswith("echo "):
            entry["output"] = cmd_formatted[5:].strip("'\"")
        else:
            try:
                proc = subprocess.run(
                    shlex.split(cmd_formatted),
                    capture_output=True, text=True, timeout=timeout_per_cmd)
                entry["returncode"] = proc.returncode
                entry["status"] = "ok" if proc.returncode == 0 else "failed"
                entry["output"] = (proc.stdout or proc.stderr or "")[:500]
            except FileNotFoundError:
                entry["status"] = "skipped"
                entry["output"] = "tool not installed on operator host"
            except subprocess.TimeoutExpired:
                entry["status"] = "timeout"
                entry["output"] = f"command timed out after {timeout_per_cmd}s"
            except Exception as e:  # noqa: BLE001
                entry["status"] = "error"
                entry["output"] = str(e)
        patch_results.append(entry)

    cves_fixed = [c["id"] for c in TV_CVE_DATABASE.get(tv_type, {}).get("cves", [])]
    ok = sum(1 for p in patch_results if p["status"] in ("ok", "executed"))
    return {"ip": ip, "tv_type": tv_type, "patches": patch_results,
            "ok": ok, "total": len(patch_results), "cves_fixed": cves_fixed}


def kill_all_connections(target_ips=None):
    """Teardown: close tracked sockets, terminate exploit child tools, and
    verify no established connections to the engagement targets remain."""
    closed = 0
    with _sockets_lock:
        for sock in list(_open_sockets):
            try:
                sock.close()
                closed += 1
            except Exception:
                pass
        _open_sockets.clear()

    terminated = []
    remaining = -1
    detail = []
    try:
        import psutil
        me = psutil.Process()
        wanted = {t if t.endswith(".exe") else f"{t}.exe" for t in EXPLOIT_TOOL_PROCS}
        wanted |= EXPLOIT_TOOL_PROCS
        for child in me.children(recursive=True):
            try:
                name = (child.name() or "").lower()
                if name in wanted:
                    child.terminate()
                    _, alive = psutil.wait_procs([child], timeout=3)
                    if alive:
                        child.kill()
                    terminated.append(name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        try:
            targets = set(target_ips or [])
            remaining = 0
            for conn in me.net_connections(kind="inet"):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    remote = getattr(conn.raddr, "ip", "")
                    if not targets or remote in targets:
                        remaining += 1
        except Exception as e:  # noqa: BLE001
            remaining = -1
            detail.append(f"connection verification failed: {e}")
    except ImportError:
        detail.append("psutil unavailable — verification limited to tracked sockets")

    verified = remaining == 0
    if remaining > 0:
        detail.append(f"{remaining} established connection(s) remain")
    elif remaining == -1:
        detail.append("could not verify connection table")
    else:
        detail.append("no established connections to engagement targets remain")

    return {"sockets_closed": closed, "tools_terminated": terminated,
            "remaining_established": remaining, "verified": verified,
            "detail": "; ".join(detail), "verified_at": utc_now_iso()}
