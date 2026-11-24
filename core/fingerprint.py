"""Fingerprinting helpers: scored port matching, OUI corroboration, HTTP fallback.

Three independent identity signals, weakest to strongest:

- **Port scoring** — signature ports weighted by distinctiveness (a port
  shared by N families scores 1/N, a unique port scores 1.0), plus a full
  point when a family's *primary* port is open. Replaces the old
  ``any(port in open_ports)`` dict-order first match, which let one generic
  port (e.g. 8443, 22) claim a host for whichever family listed it first.
- **OUI corroboration** — the ``mac_prefixes`` already present in
  ``TV_CVE_DATABASE`` are matched against the ARP-derived MAC. Used to
  classify hosts ports couldn't, and to flag when the two signals disagree.
- **HTTP fallback** — hosts still unidentified get one small GET per open
  HTTP-ish port, matched against per-family response signatures (Roku ECP,
  webOS /api/system, Tizen /api/v2, Server-header tokens).

Everything here is side-effect free except ``http_fingerprint``, which only
ever opens short-timeout connections to the target it is asked about.
"""
import http.client
import json
import os
import re

# Per-family ports that must be open for the family to count as a candidate
# even with no other hits, and per-family fixed_in keywords for version
# filtering. ``ports``/``mac_prefixes``/``cves`` live in TV_CVE_DATABASE;
# this table only holds what the database schema has no room for.
FAMILY_PRIMARY_PORTS = {
    "samsung-tizen": [8001, 8002],
    "lg-webos": [3000],
    "android-tv": [5555],
    "roku": [8060],
    "vizio": [24825, 36669, 7345],
    "hisense": [56789],
    "tcl": [5555],
    "chromecast": [8009],
}

# Keywords that must appear in a CVE's fixed_in before a device version is
# allowed to prove the CVE patched. Guards against comparing a TV firmware
# version ("23.1") against an unrelated component version ("Samba 4.6.4",
# "OpenSSH 9.8p1") — without it, fail-closed filtering silently passes
# every Linux-kernel CVE the moment the firmware string sorts higher.
FAMILY_FIXED_IN_KEYWORDS = {
    "samsung-tizen": ["tizen"],
    "lg-webos": ["webos"],
    "android-tv": ["android"],
    "roku": ["roku"],
    "vizio": ["smartcast"],
    "hisense": ["vidaa"],
    "tcl": ["android"],
    "chromecast": ["google tv", "chrome"],
}

HTTP_TIMEOUT = 1.5
HTTP_READ_LIMIT = 8192

# Ordered, most-specific-first HTTP probes per family.
HTTP_SIGNATURES = [
    {"family": "roku", "ports": [8060], "path": "/query/device-info",
     "tokens": ["<vendor-name>Roku</vendor-name>", "roku"]},
    {"family": "lg-webos", "ports": [3000], "path": "/api/system",
     "tokens": ["modelname", "webos"]},
    {"family": "samsung-tizen", "ports": [8001, 8002], "path": "/api/v2/",
     "tokens": ["tizen"]},
]

# Last-resort root-document tokens, checked on the first open of these ports.
HTTP_ROOT_PORTS = [80, 8080, 8443]
HTTP_ROOT_TOKENS = {
    "roku": ["roku"],
    "lg-webos": ["webos"],
    "samsung-tizen": ["tizen"],
    "hisense": ["vidaa", "hisense"],
    "vizio": ["viziocast", "vizio"],
}


def port_usage_counts(db):
    """How many families list each signature port (for IDF-style weights)."""
    usage = {}
    for info in db.values():
        for p in info.get("ports", []):
            usage[p] = usage.get(p, 0) + 1
    return usage


def best_family_match(open_ports, db, usage):
    """Best-scoring family for a port set, or (None, None).

    Score = sum(1/usage[p]) over open signature ports, +1.0 when a primary
    port is open. A candidate needs score >= 1.0: one fully-distinctive
    port, or a primary port, or several shared ports together. Ties break
    toward more matching ports, then database order (stable, deterministic).
    """
    open_set = set(open_ports or [])
    best = None
    for tv_type, info in db.items():
        sig = [p for p in info.get("ports", []) if p in open_set]
        if not sig:
            continue
        score = sum(1.0 / usage.get(p, 1) for p in sig)
        primary = FAMILY_PRIMARY_PORTS.get(tv_type, [])
        if any(p in open_set for p in primary):
            score += 1.0
        candidate = (round(score, 6), len(sig))
        if candidate[0] >= 1.0 and (best is None
                                    or candidate > best[0]):
            best = (candidate, tv_type, info)
    if best is None:
        return None, None
    return best[1], best[2]


def _load_oui_table():
    """Family -> prefix set, from data/oui_prefixes.json (IEEE assignments).

    Loaded once, tolerantly: a missing or malformed table just means OUI
    corroboration falls back to the inline mac_prefixes in the CVE database.
    """
    global _OUI_TABLE
    if _OUI_TABLE is not None:
        return _OUI_TABLE
    table = {}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "data", "oui_prefixes.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        for family, prefixes in raw.get("families", {}).items():
            cleaned = set()
            for p in prefixes:
                normalized = re.sub(r"[^0-9A-Fa-f]", "", str(p)).upper()
                if len(normalized) >= 6:
                    cleaned.add(normalized[:6])
            if cleaned:
                table[family] = cleaned
    except (OSError, ValueError, AttributeError):
        table = {}
    _OUI_TABLE = table
    return table


_OUI_TABLE = None


def classify_by_oui(mac, db):
    """Family whose OUI prefix matches the MAC, else None.

    Prefixes compare on separator-free uppercase hex (6 chars), so
    "C0-74-AD-BF-F8-E0", "c0:74:ad:bf:f8:e0" and "C074ADBF F8E0" all match
    the same database prefix regardless of OS formatting. Consults the
    full IEEE-derived ``data/oui_prefixes.json`` plus the inline
    ``mac_prefixes`` shipped in the CVE database.
    """
    if not mac or mac == "Unknown":
        return None
    normalized = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    if len(normalized) < 6:
        return None
    prefix = normalized[:6]
    candidates = []
    table = _load_oui_table()
    if prefix and table:
        for family, prefixes in table.items():
            if prefix in prefixes:
                candidates.append(family)
    if not candidates:
        for tv_type, info in db.items():
            for p in info.get("mac_prefixes", []):
                candidate = re.sub(r"[^0-9A-Fa-f]", "", str(p)).upper()
                if prefix == candidate[:6]:
                    candidates.append(tv_type)
                    break
    if not candidates:
        return None
    # A prefix can serve several families (e.g. Sony makes Android TVs and
    # game consoles); prefer one the CVE database actually knows.
    for fam in candidates:
        if fam in db:
            return fam
    return candidates[0]


def _http_get(ip, port, path, timeout):
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "SpyTV/1.0"})
            resp = conn.getresponse()
            body = resp.read(HTTP_READ_LIMIT)
            server = resp.getheader("Server") or ""
            return resp.status, body.decode("utf-8", "ignore"), server
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 — any failure reads as "no fingerprint"
        return None, "", ""


def http_fingerprint(ip, open_ports, timeout=HTTP_TIMEOUT):
    """Identify a host from its HTTP responses, or None.

    Returns {"family", "source", "evidence"} on the first confident match.
    Only probes ports the host already showed open, one GET each, so it
    costs nothing against hosts with no HTTP surface.
    """
    open_set = set(open_ports or [])

    for sig in HTTP_SIGNATURES:
        for port in sig["ports"]:
            if port not in open_set:
                continue
            status, body, server = _http_get(ip, port, sig["path"], timeout)
            if status is None:
                continue
            haystack = (body + "\n" + server).lower()
            for token in sig["tokens"]:
                if token.lower() in haystack:
                    return {"family": sig["family"],
                            "source": "http:%d%s" % (port, sig["path"]),
                            "evidence": token}
            break  # one attempt per family signature

    for port in HTTP_ROOT_PORTS:
        if port not in open_set:
            continue
        status, body, server = _http_get(ip, port, "/", timeout)
        if status is None:
            continue
        haystack = (body + "\n" + server).lower()
        for family, tokens in HTTP_ROOT_TOKENS.items():
            for token in tokens:
                if token in haystack:
                    return {"family": family,
                            "source": "http:%d/" % port,
                            "evidence": token}
        break  # one root GET against the first open HTTP port

    return None


_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)+")


def parse_version_tuple(text):
    """(major, minor, ...) for a dotted version string, or None."""
    if not text:
        return None
    m = _VERSION_TOKEN_RE.search(str(text))
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(0).split("."))
    except ValueError:
        return None


def filter_cves_for_version(cves, device_version, tv_type):
    """Split CVEs into (still_affected, proven_patched).

    Fail-closed: a CVE is dropped ONLY when its fixed_in (1) names the same
    vendor/OS family as the device, (2) contains exactly one parseable
    version, and (3) the device version sorts at or above it. Anything
    ambiguous — unparsable device version, branch lists like
    "4.6.4 / 4.5.10", unrelated components like "Samba 4.6.4" — keeps the
    CVE on the list, because an audit must never claim safety it didn't
    prove.
    """
    kept, patched = [], []
    if not device_version:
        return list(cves), patched
    dev = parse_version_tuple(device_version)
    if dev is None:
        return list(cves), patched
    keywords = FAMILY_FIXED_IN_KEYWORDS.get(tv_type or "", [])
    for cve in cves or []:
        fixed_in = str(cve.get("fixed_in") or "")
        fixed_lower = fixed_in.lower()
        tokens = _VERSION_TOKEN_RE.findall(fixed_in)
        drop = False
        if (len(tokens) == 1
                and any(k in fixed_lower for k in keywords)):
            fix = parse_version_tuple(tokens[0])
            if fix is not None:
                width = max(len(dev), len(fix))
                d = dev + (0,) * (width - len(dev))
                f = fix + (0,) * (width - len(fix))
                drop = d >= f
        if drop:
            patched.append(cve)
        else:
            kept.append(cve)
    return kept, patched
