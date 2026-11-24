"""Integration tests over REAL sockets on loopback, plus diff/export tests.

These exist because every bug the 10.1.10.0/24 live run exposed passed the
fully-mocked suite: probe -> match -> classify -> verdict only proves itself
against real listeners. Everything here binds 127.0.0.1 on high ports and
skips gracefully if the port is taken.
"""
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import c2_ops
import core.fingerprint as fp
import core.liveness as liveness
from core.cve_scanner import CVEScanner, probe_many
from core.scan_export import export_findings_json


class _FakeRokuHandler(BaseHTTPRequestHandler):
    """Answers Roku ECP device-info like a real Roku on /query/device-info."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/query/device-info"):
            body = (b"<?xml version='1.0'?><device-info>"
                    b"<vendor-name>Roku</vendor-name>"
                    b"<model-name>Roku Ultra</model-name>"
                    b"<software-version>13.1.4</software-version>"
                    b"</device-info>")
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)


@pytest.fixture()
def roku_server(monkeypatch):
    """A real HTTP listener on 127.0.0.1:18080 that looks like a Roku ECP
    endpoint, plus the fingerprint table repointed at that port."""
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 18080), _FakeRokuHandler)
    except OSError as e:
        pytest.skip("port 18080 unavailable: %s" % e)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    sigs = [dict(s) for s in fp.HTTP_SIGNATURES]
    for s in sigs:
        if s["family"] == "roku":
            s["ports"] = [18080]
    monkeypatch.setattr(fp, "HTTP_SIGNATURES", sigs)

    yield server
    server.shutdown()
    server.server_close()
    t.join(timeout=5)


def test_perform_scan_identifies_fake_roku_over_real_sockets(roku_server,
                                                             monkeypatch):
    """The full pipeline against a real listener: ports place nothing (18080
    is no signature port), OUI knows nothing about loopback, and the HTTP
    fallback names the device from its ECP device-info."""
    monkeypatch.setattr(liveness, "_cache", {})  # no stale pre-seed between runs
    # 18080 is not a real signature port; make the generic pass look at it
    # so the host is discovered at all.
    monkeypatch.setattr(c2_ops, "GENERIC_TV_PORTS",
                        c2_ops.GENERIC_TV_PORTS + [18080])

    seen = []
    results = c2_ops.perform_scan(
        "127.0.0.1/32", CVEScanner(),
        progress_cb=lambda f: seen.append(f))

    assert seen and seen[-1] == 1.0, seen[-1:]
    assert all(b >= a for a, b in zip(seen, seen[1:])), seen
    roku = [r for r in results if r.get("tv_type") == "roku"]
    assert len(roku) == 1, results
    r = roku[0]
    assert r["ip"] == "127.0.0.1"
    assert r["device_type"] == "Roku TV"
    assert r["vulnerable"] is True
    assert r["fingerprint_source"] == "http"
    assert "roku" in r["fingerprint_evidence"].lower()
    assert r["severity"] == "HIGH"          # roku CVE bundle tops out at HIGH
    assert any(c["id"] == "CVE-2023-42787" for c in r["cves"])
    assert 18080 in r["open_ports"]


def test_probe_cache_skips_reprobes(monkeypatch):
    """A warm (ip, port) entry is served from the cache and never re-probed;
    fresh results are stored for the next pass."""
    def _boom(ip, port, timeout=0.3):
        raise AssertionError("cached probe must not re-connect")

    monkeypatch.setattr("core.cve_scanner.probe_port", _boom)
    cache = {("10.9.9.9", 8060): True, ("10.9.9.9", 8009): False}
    results = probe_many([("10.9.9.9", 8060), ("10.9.9.9", 8009)],
                         cache=cache)
    assert results == [True, False]
    assert cache[("10.9.9.9", 8060)] is True

    # New probes store into the cache (restore a real probe for this half).
    monkeypatch.undo()
    seen = []

    def _record(ip, port, timeout=0.3):
        seen.append((ip, port))
        return True

    monkeypatch.setattr("core.cve_scanner.probe_port", _record)
    results = probe_many([("127.0.0.1", 1)], cache=cache)
    assert results == [True]
    assert cache[("127.0.0.1", 1)] is True
    assert ("127.0.0.1", 1) in seen


def test_live_hosts_falls_back_when_discovery_fails(monkeypatch):
    """Pre-seed failure or an empty answer must mean 'probe everything',
    never 'scan nothing'."""
    monkeypatch.setattr(liveness, "_sweep", lambda network: None)
    assert liveness.live_hosts("10.9.9.0/30") is None
    monkeypatch.setattr(liveness, "_sweep", lambda network: set())
    assert liveness.live_hosts("10.9.9.0/30") is None

    # A real answer is honored and cached until clear_cache().
    monkeypatch.setattr(liveness, "_sweep",
                        lambda network: {"10.9.9.1", "10.9.9.2"})
    monkeypatch.setattr(liveness, "_cache", {})
    assert liveness.live_hosts("10.9.9.0/30") == {"10.9.9.1", "10.9.9.2"}
    monkeypatch.setattr(liveness, "_sweep",
                        lambda network: (_ for _ in ()).throw(AssertionError))
    assert liveness.live_hosts("10.9.9.0/30") == {"10.9.9.1", "10.9.9.2"}
    liveness.clear_cache()


def test_diff_findings_tracks_fleet_changes():
    prev = [
        {"ip": "10.1.10.8", "device_type": "LG webOS TV", "vulnerable": True,
         "severity": "CRITICAL", "open_ports": [22, 80, 8080]},
        {"ip": "10.1.10.15", "device_type": "Roku TV", "vulnerable": True,
         "severity": "HIGH", "open_ports": [8060]},
        {"ip": "10.1.10.68", "device_type": "Unknown", "vulnerable": False,
         "open_ports": [49152]},
    ]
    curr = [
        # .8 got patched: severity collapsed
        {"ip": "10.1.10.8", "device_type": "LG webOS TV", "vulnerable": True,
         "severity": "HIGH", "open_ports": [22, 80, 8080]},
        # .15 is gone (offline / removed from VLAN)
        # .68 unchanged
        {"ip": "10.1.10.68", "device_type": "Unknown", "vulnerable": False,
         "open_ports": [49152]},
        # .142 new Hisense
        {"ip": "10.1.10.142", "device_type": "Hisense VIDAA TV",
         "vulnerable": True, "severity": "CRITICAL",
         "open_ports": [8009, 56789]},
    ]
    d = c2_ops.diff_findings(prev, curr)
    assert [r["ip"] for r in d["new"]] == ["10.1.10.142"]
    assert [r["ip"] for r in d["removed"]] == ["10.1.10.15"]
    assert [c["ip"] for c in d["changed"]] == ["10.1.10.8"]
    assert d["changed"][0]["changes"]["severity"] == {
        "from": "CRITICAL", "to": "HIGH"}
    assert d["unchanged"] == 1


def test_export_findings_json_is_deterministic():
    findings = [
        {"ip": "10.1.10.9", "mac": "aa:bb:cc:dd:ee:ff", "b": 2, "a": 1},
        {"ip": "10.1.10.8", "mac": "AA:BB:CC:00:00:00", "c": 3},
    ]
    one = export_findings_json(findings, generated_at="2026-11-21T00:00:00")
    two = export_findings_json(list(reversed(findings)),
                               generated_at="2026-11-21T00:00:00")
    assert one == two
    payload = json.loads(one)
    assert [f["ip"] for f in payload["findings"]] == ["10.1.10.8",
                                                      "10.1.10.9"]
    assert payload["findings"][1]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert payload["finding_count"] == 2


def _http(port, method, path, body=None):
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port, path),
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"}, method=method)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode())


def test_scans_diff_endpoint_groups_runs(monkeypatch, tmp_path):
    import c2_server
    from http.server import ThreadingHTTPServer

    monkeypatch.setattr(c2_server, "SCAN_FILE", str(tmp_path / "scans.json"))
    with c2_server.scans_lock:
        c2_server.scans[:] = [
            {"ip": "10.1.10.15", "device_type": "Roku TV",
             "vulnerable": True, "scan_id": "run-1"},
            {"ip": "10.1.10.68", "device_type": "Unknown",
             "vulnerable": False, "scan_id": "run-1"},
            {"ip": "10.1.10.142", "device_type": "Hisense VIDAA TV",
             "vulnerable": True, "scan_id": "run-2"},
            {"ip": "10.1.10.68", "device_type": "Unknown",
             "vulnerable": False, "scan_id": "run-2"},
        ]
    server = ThreadingHTTPServer(("127.0.0.1", 0), c2_server.C2Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        code, body = _http(port, "GET", "/api/scans/diff")
        assert code == 200
        assert [r["scan_id"] for r in body["runs"]] == ["run-1", "run-2"]
        diff = body["diff"]
        assert [r["ip"] for r in diff["new"]] == ["10.1.10.142"]
        assert [r["ip"] for r in diff["removed"]] == ["10.1.10.15"]
        assert diff["unchanged"] == 1
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=5)
        with c2_server.scans_lock:
            c2_server.scans[:] = []


def test_finalize_oui_only_labels_probable_never_verdict():
    """An OUI match names the vendor, not the model or firmware — it must
    identify the device as 'probable' and must NOT attach a CVE bundle (a
    Samsung laptop carries Samsung's prefixes too)."""

    class _OuiScanner:
        def detect_tv_type(self, ip, open_ports):
            return None, None

        def classify_by_oui(self, mac):
            if mac and mac.startswith("60:92"):
                return "roku"
            return None

        def get_mac_address(self, ip):
            return "60:92:C8:00:00:01"   # real Roku prefix

    results = c2_ops.finalize_findings(
        [{"ip": "10.1.10.99", "open_ports": [515]}], _OuiScanner())

    r = results[0]
    assert r["device_type"] == "Roku TV (probable, OUI)", r
    assert r["vulnerable"] is False, r
    assert not r.get("cves"), r
    assert r["oui_family"] == "roku", r
    assert r["fingerprint_source"] == "oui", r
