#!/usr/bin/env python3
"""TVREAPER v2 family fingerprinter. SSDP + port + OUI + capability probes.
NEW in v2: HiSense, Philips NetTV, Sony BRAVIA/Android-TV, Fire TV Edition,
Vizio SmartCast, hotel-mode flags, and DLNA service discovery.
Usage: tv_fingerprint.py --network 192.168.1.0/24 [--deep]"""
import socket, concurrent.futures, re, json, argparse, sys, logging
logging.basicConfig(filename='spytv_fingerprint.log', level=logging.INFO,
    format='%(asctime)s UTC %(message)s')

# CR-38 fix: OUI table is now actually used for MAC-based vendor lookup
OUI = {
    "00:12:fb":"Samsung","00:e0:64":"Samsung","d0:17:c2":"Samsung",
    "40:b0:fa":"LG","38:f3:ab":"LG","e0:91:53":"LG",
    "08:fc:88":"Sony","b8:27:eb":"Roku","00:1b:63":"Vizio",
    "c8:d7:19":"Vizio","60:6b:bd":"Vizio","88:87:17":"Chromecast",
    "54:60:09":"Chromecast",
    "88:71:11":"HiSense","48:44:9f":"HiSense","00:09:6b":"Sharp",
    "00:1a:79":"Philips","49:90:07":"Philips","88:d0:39":"Toshiba",
    "fc:a1:3e":"Panasonic","a4:77:33":"Panasonic","bc:52:b7":"Amazon/FireTV",
    "84:d6:d0":"Amazon/FireTV","f0:f0:f0":"Amazon/FireTV",
}

SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n"
).encode()

PROBES = [
    (7676,  b"GET /ws/apps/ HTTP/1.0\r\n\r\n",
             "Tizen/DMP-svc",          {"entry":"tizen-dev","mic":True,"cam":True}),
    (3000,  b"GET /hdmi/input/list HTTP/1.0\r\n\r\n",
             "webOS",                  {"entry":"webos-dev","mic":True,"cam":True}),
    (3001,  b"GET /roap/api/adapters HTTP/1.0\r\n\r\n",
             "webOS-legacy",           {"entry":"webos-dev","mic":True,"cam":False}),
    (8060,  b"GET /query/device-info HTTP/1.0\r\n\r\n",
             "Roku/ECP",              {"entry":"roku-ecp","mic":False,"cam":False}),
    (56789, b"GET /clientlist.html HTTP/1.0\r\n\r\n",
             "HiSense-local",         {"entry":"hisense-adb","mic":"model","cam":"model"}),
    (9197,  b"GET /remote/ctrl HTTP/1.0\r\n\r\n",
             "Sharp/NetTV",           {"entry":"nettv-web","mic":"model","cam":False}),
    (49152, b"POST /upnp/control/AVTransport HTTP/1.0\r\n"
            b"CONTENT-TYPE: text/xml\r\nSOAPACTION: \"urn:schemas-upnp-org:"
            b"service:AVTransport:1#Play\"\r\n\r\n",
             "DLNA-AVTransport",      {"entry":"dlna","mic":False,"cam":False}),
    (9999,  b"GET /ws/doctor HTTP/1.0\r\n\r\n",
             "Philips/NetTV",         {"entry":"nettv-web","mic":"model","cam":False}),
    (5555,  b"GET / HTTP/1.0\r\n\r\n",
             "AndroidTV/ADB (Sony/FireTV/Toshiba/etc.)",
             {"entry":"adb-net","mic":True,"cam":True}),
    (36669, b"POST /adhoc/start HTTP/1.0\r\n\r\n",
             "Vizio",                 {"entry":"vizio-dial","mic":"model","cam":False}),
    (8009,  b"GET /ssdp/device-desc.xml HTTP/1.0\r\n\r\n",
             "Chromecast/DIAL",       {"entry":"cast-dial","mic":"dongle","cam":"dongle"}),
]

def ssdp_sweep(timeout=5):
    # CR-39 fix: Join multicast group for proper SSDP discovery
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(timeout)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Join the SSDP multicast group
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
            # CR-39 fix: More precise cue matching - avoid substring false positives
            # e.g., "cast" matching "Chromecast" is fine, but be more specific
            cues = ["samsung","lgtv","webos","tizen","roku","vizio",
                    "hisense","philips","nettv","bravia","firetv",
                    "chromecast","panasonic"]
            for cue in cues:
                if cue in d.lower():
                    loc = re.search(r"LOCATION:\s*(\S+)", d, re.I)
                    srv = re.search(r"SERVER:\s*(\S+[^>]*)", d, re.I)
                    # CR-39 fix: Don't overwrite existing entries
                    if addr[0] not in found:
                        found[addr[0]] = {"cue": cue,
                            "location": loc.group(1) if loc else None,
                            "server": srv.group(1) if srv else None}
                    break
    except socket.timeout:
        pass
    finally:
        s.close()
    return found

def probe(ip, port, payload, label, caps):
    try:
        s = socket.create_connection((ip, port), timeout=2)
        s.send(payload)
        data = s.recv(256); s.close()
        if data:
            return {"ip": ip, "port": port, "label": label,
                    "caps": caps,
                    "banner": data[:128].decode(errors="replace")}
    except Exception:
        return None
    return None

def dlna_discover(ip):
    """DLNA AVTransport reaches most smart TVs."""
    try:
        s = socket.create_connection((ip, 49152), timeout=2)
        s.send(b"GET /description.xml HTTP/1.0\r\n\r\n")
        d = s.recv(2048).decode(errors="replace"); s.close()
        if "AVTransport" in d or "MediaRenderer" in d:
            return True
    except Exception:
        pass
    return False

def hotel_mode_probe(ip):
    """Hotel Samsung TVs expose hospitality panels."""
    try:
        s = socket.create_connection((ip, 7676), timeout=2)
        s.send(b"GET /ws/apps/ HTTP/1.0\r\n\r\n")
        d = s.recv(1024).decode(errors="replace"); s.close()
        return "hotel" in d.lower() or "hospitality" in d.lower()
    except Exception:
        return False

def oui_lookup(ip):
    """CR-38 fix: Actually perform OUI lookup via ARP table."""
    try:
        # Try to read ARP table
        with open("/proc/net/arp", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3].lower()
                    prefix = mac[:8]  # First 3 octets
                    return OUI.get(prefix, None)
    except Exception:
        pass
    return None

def classify(ip, results):
    """Rank entry surfaces by probe responses."""
    family, entry = "UNKNOWN", None
    for r in results:
        if r and "Tizen/DMP" in r["label"]:
            family, entry = "Samsung(Tizen)", "tizen-dev"
            if hotel_mode_probe(ip): entry = "tizen-hotel"
        elif r and "webOS" in r["label"]:
            family, entry = "LG(webOS)", "webos-dev"
        elif r and "Roku" in r["label"]:
            family, entry = "RokuTV", "roku-ecp"
        elif r and "HiSense" in r["label"]:
            family, entry = "HiSense/Sharp", "hisense-adb"
        elif r and "NetTV" in r["label"]:
            family, entry = "Philips(NetTV)", "nettv-web"
        elif r and "ADB" in r["label"]:
            family, entry = "AndroidTV(Sony/Fire/Toshiba)", "adb-net"
        elif r and "Vizio" in r["label"]:
            family, entry = "Vizio(SmartCast)", "vizio-dial"
        elif r and "Cast" in r["label"]:
            family, entry = "Chromecast(dongle)", "cast-dial"
    if not entry and dlna_discover(ip):
        family, entry = "AnyTV(DLNA)", "dlna"
    # CR-38 fix: Fallback to OUI lookup
    if not entry:
        oui_vendor = oui_lookup(ip)
        if oui_vendor:
            family = oui_vendor
            entry = "unknown"
    return {"ip": ip, "family": family, "entry": entry,
            "probes": [r for r in results if r]}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--network", default="192.168.1.0/24")
    p.add_argument("--deep", action="store_true")
    a = p.parse_args()
    seeds = ssdp_sweep()
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = []
        for ip in seeds:
            for port, pay, label, caps in PROBES:
                futs.append(ex.submit(probe, ip, port, pay, label, caps))
        results_by_ip = {}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                results_by_ip.setdefault(r["ip"], []).append(r)
    for ip, results in results_by_ip.items():
        out = classify(ip, results)
        print(json.dumps(out, indent=2))
        logging.info(f"discovered {ip} family={out['family']} entry={out['entry']}")
