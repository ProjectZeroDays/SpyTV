#!/usr/bin/env python3
import socket
import concurrent.futures
import re
import json
import time
import logging
from core.utils import logger

# CR-38 fix: OUI table is now actually used for MAC-based vendor lookup
OUI = {
    "00:12:fb":"Samsung","00:e0:64":"Samsung","d0:17:c2":"Samsung",
    "40:b0:fa":"LG","38:f3:ab":"LG","e0:91:53":"LG",
    "08:fc:88":"Sony","b8:27:eb":"Roku","00:1b:63":"Vizio",
    "c8:d7:19":"Vizio","60:6b:bd":"Vizio","88:87:17":"Chromecast",
    "54:60:09":"Chromecast","88:71:11":"HiSense","48:44:9f":"HiSense",
    "00:09:6b":"Sharp","00:1a:79":"Philips","49:90:07":"Philips",
    "bc:52:b7":"Amazon/FireTV","84:d6:d0":"Amazon/FireTV",
    "fc:a1:3e":"Panasonic","a4:77:33":"Panasonic","f0:f0:f0":"Amazon/FireTV",
}

SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()

PROBES = [
    (7676, b"GET /ws/apps/ HTTP/1.0\r\n\r\n", "Tizen/DMP"),
    (3000, b"GET /hdmi/input/list HTTP/1.0\r\n\r\n", "webOS"),
    (8060, b"GET /query/device-info HTTP/1.0\r\n\r\n", "Roku/ECP"),
    (5555, b"GET / HTTP/1.0\r\n\r\n", "AndroidTV/ADB"),
    (36669, b"GET / HTTP/1.0\r\n\r\n", "Vizio SmartCast"),
    (8009, b"GET / HTTP/1.0\r\n\r\n", "Chromecast/DIAL"),
]

def ssdp_sweep():
    # CR-39 fix: Join multicast group for proper SSDP discovery
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        mreq = socket.inet_aton("239.255.255.250") + socket.inet_aton("0.0.0.0")
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except Exception:
        pass
    s.sendto(SSDP_MSEARCH, ("239.255.255.250", 1900))
    found = {}
    try:
        while True:
            data, addr = s.recvfrom(4096)
            d = data.decode(errors="replace")
            # CR-39 fix: More precise cue matching
            cues = ["samsung","lgtv","webos","tizen","roku","vizio",
                    "hisense","philips","nettv","bravia","firetv",
                    "chromecast","panasonic"]
            for cue in cues:
                if cue in d.lower():
                    # CR-39 fix: Don't overwrite existing entries
                    if addr[0] not in found:
                        found[addr[0]] = {"cue": cue}
                    break
    except socket.timeout:
        pass
    finally:
        s.close()
    return found

def probe_ip(ip, port, payload, label):
    try:
        s = socket.create_connection((ip, port), timeout=2)
        s.send(payload)
        data = s.recv(256).decode(errors="replace")
        s.close()
        return {"ip": ip, "port": port, "label": label, "banner": data[:128]}
    except Exception:
        return None

def oui_lookup(ip):
    """CR-38 fix: Actually perform OUI lookup via ARP table."""
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3].lower()
                    prefix = mac[:8]
                    return OUI.get(prefix, None)
    except Exception:
        pass
    return None

def classify_target(ip, probe_results):
    family = "UNKNOWN"
    entry_method = "unknown"

    for r in probe_results:
        if r and "Tizen" in r.get("label", ""):
            family = "Samsung(Tizen)"
            entry_method = "tizen-dev"
        elif r and "webOS" in r.get("label", ""):
            family = "LG(webOS)"
            entry_method = "webos-dev"
        elif r and "Roku" in r.get("label", ""):
            family = "RokuTV"
            entry_method = "roku-ecp"
        elif r and "Android" in r.get("label", ""):
            family = "AndroidTV"
            entry_method = "adb-net"
        elif r and "Vizio" in r.get("label", ""):
            family = "Vizio(SmartCast)"
            entry_method = "vizio-dial"
        elif r and "Cast" in r.get("label", ""):
            family = "Chromecast(dongle)"
            entry_method = "cast-dial"

    # CR-38 fix: Fallback to OUI lookup
    if family == "UNKNOWN":
        oui_vendor = oui_lookup(ip)
        if oui_vendor:
            family = oui_vendor
            entry_method = "unknown"

    return {"ip": ip, "family": family, "entry": entry_method}

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--network", type=str, default="192.168.1.0/24")
    a = p.parse_args()
    targets = ssdp_sweep()
    print(f"Discovered {len(targets)} devices via SSDP.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = []
        for ip in targets:
            for port, pay, lbl in PROBES:
                futs.append(ex.submit(probe_ip, ip, port, pay, lbl))
        results = {}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                results.setdefault(r["ip"], []).append(r)

    for ip, res in results.items():
        info = classify_target(ip, res)
        print(json.dumps(info, indent=2))
