"""Autonomous mode + full-database exploits/patches listing.

Covers: list_exploits() (built-in per-CVE + generated), list_patches(),
c2_ops.run_autonomous() (scan -> check -> exploit -> register), and the
live /api/patches + /api/autonomous endpoints.
"""
import json
import pathlib
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import c2_cve_feed
import c2_ops
import c2_server
from core.cve_scanner import TV_CVE_DATABASE


def _db_cve_ids():
    return sorted(c["id"] for info in TV_CVE_DATABASE.values()
                  for c in info["cves"])


def test_list_exploits_covers_entire_database():
    exploits = c2_cve_feed.list_exploits()
    built_in = [e for e in exploits if e["source"] == "built-in"]
    assert sorted(e["cve_id"] for e in built_in) == _db_cve_ids()
    assert all(e["exploit_ready"] for e in built_in)
    assert all(e["tv_type"] and e["severity"] for e in built_in)
    generated = [e for e in exploits if e["source"] == "generated"]
    assert all(e["exploit_ready"] for e in generated)


def test_list_patches_covers_entire_database():
    patches = c2_cve_feed.list_patches()
    assert sorted(p["cve_id"] for p in patches) == _db_cve_ids()
    assert all(p["patch_ready"] and p["commands"] for p in patches)
    assert all(p["tv_type"] and p["fixed_in"] for p in patches)


class _StubScanner:
    pass


def _fake_ops(monkeypatch):
    monkeypatch.setattr(
        c2_ops, "perform_scan",
        lambda cidr, scanner: [
            {"ip": "10.9.0.11", "tv_type": "android-tv",
             "cves": [{"id": "CVE-2023-40104", "severity": "HIGH",
                       "component": "Settings", "fixed_in": "Android 12L"}]},
            {"ip": "10.9.0.12", "tv_type": "roku", "cves": []},
            {"ip": "10.9.0.13", "tv_type": "roku",
             "cves": [{"id": "CVE-2023-42787", "severity": "HIGH",
                       "component": "ECP", "fixed_in": "Roku OS 12.1"}]},
        ])
    monkeypatch.setattr(
        c2_ops, "check_target",
        lambda ip, scanner: {"ip": ip, "vulnerable": ip != "10.9.0.13"})
    def _run(tv_type, ip, timeout=90):
        return {"attempted": True, "success": True, "duration_s": 0.1}
    monkeypatch.setattr(c2_ops, "run_exploit", _run)


def test_run_autonomous_exploits_and_registers(monkeypatch):
    _fake_ops(monkeypatch)
    registered = {}
    summary = c2_ops.run_autonomous(
        "10.9.0.0/24", _StubScanner(),
        lambda ip, tv, cves, run: registered.setdefault(ip, (tv, cves, run)))
    assert summary["scanned"] == 3
    assert [v["ip"] for v in summary["vulnerable"]] == ["10.9.0.11"]
    assert [v["ip"] for v in summary["exploited"]] == ["10.9.0.11"]
    assert list(registered) == ["10.9.0.11"]
    assert summary["errors"] == []


def test_run_autonomous_collects_errors(monkeypatch):
    monkeypatch.setattr(
        c2_ops, "perform_scan",
        lambda cidr, scanner: (_ for _ in ()).throw(IOError("net down")))
    summary = c2_ops.run_autonomous("10.9.0.0/24", _StubScanner(),
                                    lambda *a: "x")
    assert summary["scanned"] == 0
    assert summary["errors"] and "net down" in summary["errors"][0]


def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), c2_server.C2Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=15) as r:
        return json.loads(r.read().decode())


def _post(base, path, payload):
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def test_api_patches_lists_database():
    server, base = _serve()
    try:
        patches = _get(base, "/api/patches")
        assert len(patches) == len(_db_cve_ids())
        assert all(p["commands"] for p in patches)
    finally:
        server.shutdown()


def test_api_exploits_lists_database():
    server, base = _serve()
    try:
        exploits = _get(base, "/api/exploits")
        built_in = [e for e in exploits if e.get("source") == "built-in"]
        assert sorted(e["cve_id"] for e in built_in) == _db_cve_ids()
        assert all(e.get("exploit_ready") for e in built_in)
    finally:
        server.shutdown()


def test_dashboard_contract_exploits_patches_autonomous():
    """Static contract of the new dashboard surfaces (web == Android asset)."""
    html = pathlib.Path("c2_dashboard.html").read_text(encoding="utf-8")
    android = pathlib.Path(
        "android/app/src/main/assets/c2_dashboard.html").read_text(encoding="utf-8")
    assert html == android, "dashboard asset out of sync with web dashboard"

    # Patches dashboard: nav entry, tab, renderer, switchTab hook.
    assert "switchTab('patches')" in html
    assert 'id="tab-patches"' in html
    assert "async function loadPatches()" in html
    assert "tab === 'patches'" in html
    assert 'api(\'/api/patches\')' in html

    # Exploits dashboard shows the whole database, not just generated files.
    assert "async function runExploitRow(" in html
    assert "source === 'generated'" in html

    # Autonomous mode button -> /api/autonomous, refreshes devices.
    assert 'id="autonomous-btn"' in html
    assert "async function startAutonomous()" in html
    assert "'/api/autonomous'" in html

    # Per-device whitepaper button + worst-CVE picker.
    assert "function viewDeviceWhitepaper(" in html
    assert "function deviceWorstCve(" in html
    assert "Whitepaper" in html.split("confirmPatch", 1)[1][:800]


def test_api_autonomous_registers_device(monkeypatch, tmp_path):
    _fake_ops(monkeypatch)
    monkeypatch.setattr(c2_server, "DEVICE_FILE", str(tmp_path / "dev.json"))
    monkeypatch.setattr(c2_server, "SCAN_FILE", str(tmp_path / "sc.json"))
    with c2_server.devices_lock:
        c2_server.devices.clear()
    with c2_server.scans_lock:
        c2_server.scans.clear()
    server, base = _serve()
    try:
        res = _post(base, "/api/autonomous", {"cidr": "10.9.0.0/24"})
        assert res["status"] == "ok"
        assert [r["ip"] for r in res["registered"]] == ["10.9.0.11"]
        with c2_server.devices_lock:
            devs = list(c2_server.devices.values())
        assert len(devs) == 1
        dev = devs[0]
        assert dev["ip"] == "10.9.0.11"
        assert dev["entry"] == "autonomous"
        assert dev["cves"] and dev["cves"][0]["id"] == "CVE-2023-40104"
        assert dev["exploit"]["success"] is True
    finally:
        server.shutdown()
        with c2_server.devices_lock:
            c2_server.devices.clear()
