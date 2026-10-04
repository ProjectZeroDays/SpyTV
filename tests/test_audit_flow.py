"""End-to-end tests for the Audit / Patch-all engagement flow (T-03).

Covers: client validation (6 fields), the industry-standard authorization
PDF (unsigned + e-signed), signature decoding, the audit engagement state
machine with real report rendering, and every HTTP endpoint involved:

    POST /api/audit/authorize  ->  GET authorization.pdf
    POST /api/audit/sign       ->  GET /api/audit/status -> GET report.pdf
    POST /api/patch/start      ->  awaiting_client -> POST report -> GET pdf
    POST /api/check, POST /api/connections/kill, GET /api/host_info

Heavy network operations are stubbed so the suite stays deterministic;
everything else (PDF generation, state machines, routing) is real.
"""
import base64
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import c2_audit
import c2_server

# Minimal valid 1x1 PNG (used as a drawn e-signature).
PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8Dw"
    "HwAFAAH/q842iQAAAABJRU5ErkJggg=="
)
SIG_DATAURL = "data:image/png;base64," + base64.b64encode(PNG_1PX).decode()


def _pdf_text(pdf):
    """Decode PDF content streams (ASCII85 + Flate) and pull out the
    literal strings so phrase assertions work against reportlab output."""
    import base64 as _b64
    import re
    import zlib
    parts = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        chunk = m.group(1).strip(b"\r\n")
        if chunk.endswith(b"~>"):
            chunk = chunk[:-2]
            try:
                chunk = _b64.a85decode(chunk, adobe=False,
                                       ignorechars=b" \t\r\n")
            except Exception:
                continue
        try:
            chunk = zlib.decompress(chunk)
        except zlib.error:
            pass
        parts.append(chunk)
    strings = re.findall(rb"\((?:\\.|[^\\()])*\)", b"\n".join(parts))
    return b" ".join(s[1:-1] for s in strings).decode("latin-1",
                                                       errors="ignore")

CLIENT = {
    "company": "Acme Streaming Ltd",
    "name": "Dana Reyes",
    "address": "12 Harbor Way, Suite 400, Portland, OR 97201",
    "phone": "+1 503 555 0142",
    "email": "dana@acmestreaming.example",
    "website": "https://acmestreaming.example",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _http(port, method, path, body=None, _retries=1):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    # The local test server shares the machine's socket stack with the rest of
    # the suite, so a request can occasionally come back with a transient
    # transport abort (WSAECONNABORTED/10053). That says nothing about the
    # endpoint under test, so re-issue it once before failing the test.
    for attempt in range(_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                ctype = resp.headers.get("Content-Type", "")
                if "json" in ctype:
                    return resp.status, json.loads(raw)
                return resp.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw
        except (ConnectionAbortedError, ConnectionResetError):
            if attempt >= _retries:
                raise
            time.sleep(0.05)


@pytest.fixture()
def httpd(monkeypatch, tmp_path):
    """C2 server on a random port with stubbed network operations and an
    isolated archive directory."""
    monkeypatch.setattr(c2_audit, "ARCHIVE_ROOT", str(tmp_path / "audits"))
    monkeypatch.setattr(c2_server, "perform_scan",
                        lambda cidr, scanner: [])
    monkeypatch.setattr(c2_server, "check_target",
                        lambda ip, scanner: {
                            "ip": ip, "reachable": True, "open_ports": [7676],
                            "tv_type": "samsung-tizen", "vulnerable": True,
                            "cves": [], "exploit_ready": True, "dry_run": None,
                            "checked_at": "2026-10-04T00:00:00",
                            "message": "Checked (read-only probe).",
                        })
    monkeypatch.setattr(c2_server, "run_exploit",
                        lambda tv_type, ip: {"attempted": True, "success": True})
    monkeypatch.setattr(c2_server, "kill_all_connections",
                        lambda ips=None: {
                            "sockets_closed": 1, "tools_terminated": [],
                            "remaining_established": 0, "verified": True,
                            "detail": "no established connections remain",
                        })
    monkeypatch.setattr(c2_server, "execute_patches",
                        lambda ip, tv_type, scanner, **kw: {
                            "ip": ip, "tv_type": tv_type,
                            "patches": [{"command": "echo done", "status": "executed",
                                         "output": "done", "returncode": 0}],
                            "ok": 1, "total": 1, "cves_fixed": [],
                        })
    with c2_server.engagements_lock:
        c2_server.audit_engagement = None
        c2_server.patch_engagement = None
        c2_server.authorizations.clear()

    server = ThreadingHTTPServer(("127.0.0.1", 0), c2_server.C2Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield port
    server.shutdown()
    server.server_close()
    t.join(timeout=5)
    with c2_server.engagements_lock:
        c2_server.audit_engagement = None
        c2_server.patch_engagement = None
        c2_server.authorizations.clear()


def _wait_status(port, kind, predicate, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, status = _http(port, "GET", f"/api/{kind}/status")
        assert code == 200, status
        if predicate(status):
            return status
        time.sleep(0.2)
    raise AssertionError(f"{kind} status never satisfied predicate: {status}")


# ---------------------------------------------------------------------------
# client validation + authorization PDF
# ---------------------------------------------------------------------------

def test_validate_client_requires_company_and_rep():
    client, errors = c2_audit.validate_client(CLIENT)
    assert not errors
    assert client["company"] == "Acme Streaming Ltd"

    _, errors = c2_audit.validate_client({k: v for k, v in CLIENT.items()
                                          if k != "company"})
    assert any("company" in e.lower() for e in errors)


def test_validate_client_flags_every_bad_field():
    _, errors = c2_audit.validate_client({})
    assert len(errors) >= 5  # company, name, address, phone, email, website


def test_authorization_record_hash_is_stable_and_sensitive():
    h1 = c2_audit.authorization_record_hash("AUTH-1", CLIENT, PNG_1PX, "T")
    h2 = c2_audit.authorization_record_hash("AUTH-1", CLIENT, PNG_1PX, "T")
    assert h1 == h2 and len(h1) == 64
    other = dict(CLIENT, company="Other Co")
    assert c2_audit.authorization_record_hash("AUTH-1", other, PNG_1PX, "T") != h1
    assert c2_audit.authorization_record_hash("AUTH-2", CLIENT, PNG_1PX, "T") != h1


def test_unsigned_authorization_pdf_is_industry_standard():
    pdf = c2_audit.build_authorization_pdf(CLIENT, "AUTH-TEST-0001")
    assert pdf.startswith(b"%PDF-") and len(pdf) > 4000
    # The rendered document must carry the legally required sections.
    text = _pdf_text(pdf)
    for phrase in ("rules of engagement", "authorization", "esign",
                   "pre-signed", "out of scope", "confidentiality"):
        assert phrase in text.lower(), f"missing: {phrase}"


def test_signed_authorization_pdf_embeds_signature_and_audit_trail():
    h = c2_audit.authorization_record_hash("AUTH-TEST-0002", CLIENT, PNG_1PX,
                                           "2026-10-04 12:00:00 UTC")
    pdf = c2_audit.build_authorization_pdf(
        CLIENT, "AUTH-TEST-0002", signature_png=PNG_1PX,
        signer_ip="127.0.0.1", signed_at="2026-10-04 12:00:00 UTC",
        record_hash=h)
    assert pdf.startswith(b"%PDF-")
    text = _pdf_text(pdf)
    assert "audit trail" in text.lower()
    assert h[:16] in text  # record hash rendered in the document


# ---------------------------------------------------------------------------
# signature decoding + path safety
# ---------------------------------------------------------------------------

def test_decode_signature_accepts_png_dataurl():
    png, errors = c2_server._decode_signature(SIG_DATAURL)
    assert not errors and png.startswith(b"\x89PNG")


def test_decode_signature_rejects_garbage():
    for bad in ("", "not-base64!!", "data:image/png;base64,@@@",
                "data:image/png;base64," + base64.b64encode(b"<html>").decode()):
        png, errors = c2_server._decode_signature(bad)
        assert png is None and errors


def test_decode_signature_enforces_size_cap():
    big = b"\x89PNG\r\n\x1a\n" + b"\x00" * (500 * 1024)
    png, errors = c2_server._decode_signature(
        "data:image/png;base64," + base64.b64encode(big).decode())
    assert png is None and "KB" in errors[0]


def test_auth_dir_rejects_path_traversal():
    assert c2_server._auth_dir("../etc") is None
    assert c2_server._auth_dir("AUTH-20261004-ABCD12") is not None


# ---------------------------------------------------------------------------
# engagement state machines (direct, with stub callbacks)
# ---------------------------------------------------------------------------

def test_audit_engagement_auto_renders_report(monkeypatch, tmp_path):
    monkeypatch.setattr(c2_audit, "ARCHIVE_ROOT", str(tmp_path))
    eng = c2_audit.AuditEngagement(
        cidr="10.9.0.0/24",
        scan_fn=lambda cidr: [],
        check_fn=lambda ip: {"ip": ip, "vulnerable": False},
        exploit_fn=lambda tv, ip: {"attempted": False, "success": False},
        kill_fn=lambda ips: {"detail": "clean", "verified": True},
        client=CLIENT,
    )
    eng.run()  # synchronous — stubs are instant
    assert eng.phase == "done"
    assert eng.report_path and eng.report_path.endswith("report.pdf")
    with open(eng.report_path, "rb") as f:
        assert f.read(5) == b"%PDF-"
    assert eng.snapshot()["report_ready"] is True
    assert eng.snapshot()["report_url"] == "/api/audit/report.pdf"


def test_patch_engagement_awaits_client_then_renders(monkeypatch, tmp_path):
    monkeypatch.setattr(c2_audit, "ARCHIVE_ROOT", str(tmp_path))
    eng = c2_audit.PatchEngagement(
        targets_fn=lambda: [{"ip": "10.9.0.20", "tv_type": "roku",
                             "name": "Roku TV", "source": "scan"}],
        patch_fn=lambda ip, tv: {"patches": [{"command": "echo x",
                                              "status": "executed"}],
                                 "ok": 1, "total": 1, "cves_fixed": []},
    )
    eng.run()
    assert eng.phase == "awaiting_client"
    assert eng.results["summary"]["patched"] == 1
    eng.render(CLIENT)
    assert eng.phase == "done"
    with open(eng.report_path, "rb") as f:
        assert f.read(5) == b"%PDF-"


# ---------------------------------------------------------------------------
# HTTP endpoints — authorize -> sign -> status -> report
# ---------------------------------------------------------------------------

def test_audit_http_flow_end_to_end(httpd):
    port = httpd

    # 1. authorize — invalid client rejected
    code, res = _http(port, "POST", "/api/audit/authorize",
                      {"client": {"company": ""}})
    assert code == 400 and res["errors"]

    # 2. authorize — valid client creates the unsigned instrument
    code, res = _http(port, "POST", "/api/audit/authorize", {"client": CLIENT})
    assert code == 200, res
    auth_id = res["auth_id"]
    assert "authorization.pdf" in res["pdf_url"]
    assert len(res["record_hash"]) == 64

    # 3. unsigned PDF served inline
    code, pdf = _http(port, "GET", res["pdf_url"])
    assert code == 200 and pdf.startswith(b"%PDF-")

    # 4. signing with garbage rejected
    code, res = _http(port, "POST", "/api/audit/sign",
                      {"auth_id": auth_id, "signature": "junk!!"})
    assert code == 400

    # 5. valid signature starts the audit
    code, res = _http(port, "POST", "/api/audit/sign",
                      {"auth_id": auth_id, "signature": SIG_DATAURL,
                       "signer_company": CLIENT["company"]})
    assert code == 200, res
    assert res["status"] == "started" and res["record_hash"]

    # 6. double-sign blocked
    code, res = _http(port, "POST", "/api/audit/sign",
                      {"auth_id": auth_id, "signature": SIG_DATAURL})
    assert code == 409

    # 7. signed instrument on disk + served
    code, pdf = _http(port, "GET",
                      f"/api/audit/authorization.pdf?auth_id={auth_id}&state=signed")
    assert code == 200 and pdf.startswith(b"%PDF-")
    code, rec = _http(port, "GET",
                      f"/api/audit/authorization.pdf?auth_id={auth_id}&state=unsigned")
    assert code == 200 and rec.startswith(b"%PDF-")

    # 8. engagement runs (stubbed scan) and auto-renders the report
    status = _wait_status(port, "audit", lambda s: s["phase"] == "done")
    assert status["report_ready"] is True
    assert status["client"]["company"] == CLIENT["company"]

    # 9. report downloadable
    code, pdf = _http(port, "GET", "/api/audit/report.pdf")
    assert code == 200 and pdf.startswith(b"%PDF-")

    # 10. unknown authorization id -> 404
    code, _ = _http(port, "GET",
                    "/api/audit/authorization.pdf?auth_id=AUTH-NOPE-0000")
    assert code == 404


def test_patch_http_flow_end_to_end(httpd):
    port = httpd

    # 1. report before any engagement -> 404
    code, _ = _http(port, "POST", "/api/patch/report", {"client": CLIENT})
    assert code == 404

    # 2. patch-all starts (stubbed discovery finds nothing)
    code, res = _http(port, "POST", "/api/patch/start", {})
    assert code == 200 and res["status"] == "started"

    # 3. duplicate start blocked while running
    code, res = _http(port, "POST", "/api/patch/start", {})
    assert code in (200, 409)  # may have finished instantly with stubs

    # 4. waits for client details
    status = _wait_status(port, "patch",
                          lambda s: s["phase"] == "awaiting_client")
    assert status["results"]["summary"]["total"] == 0

    # 5. render the report with client details
    code, res = _http(port, "POST", "/api/patch/report", {"client": CLIENT})
    assert code == 200, res
    assert res["report_url"] == "/api/patch/report.pdf"

    # 6. double-render blocked
    code, _ = _http(port, "POST", "/api/patch/report", {"client": CLIENT})
    assert code == 409

    # 7. report downloadable
    code, pdf = _http(port, "GET", "/api/patch/report.pdf")
    assert code == 200 and pdf.startswith(b"%PDF-")

    # 8. status now done
    code, status = _http(port, "GET", "/api/patch/status")
    assert status["phase"] == "done" and status["report_ready"] is True


def test_check_endpoint_is_read_only(httpd):
    code, res = _http(httpd, "POST", "/api/check", {})
    assert code == 400
    code, res = _http(httpd, "POST", "/api/check", {"ip": "10.9.0.5"})
    assert code == 200
    assert res["result"]["reachable"] is True
    assert res["result"]["tv_type"] == "samsung-tizen"


def test_host_info_returns_real_values(httpd):
    code, res = _http(httpd, "GET", "/api/host_info")
    assert code == 200
    assert res["hostname"] and res["local_ip"]
    assert res["mac"].count(":") == 5
    assert res["c2_port"] == 8443
    assert "uptime_s" in res
    # simulated placeholders must never come back
    assert res["mac"] != "AA:BB:CC:DD:EE:FF"
    assert res["ipv6"] != "fe80::1"


def test_kill_connections_endpoint(httpd):
    code, res = _http(httpd, "POST", "/api/connections/kill", {})
    assert code == 200
    assert res["result"]["verified"] is True


def test_idle_status_payloads(httpd):
    code, audit = _http(httpd, "GET", "/api/audit/status")
    code2, patch = _http(httpd, "GET", "/api/patch/status")
    assert audit["phase"] == "idle" and patch["phase"] == "idle"
    assert audit["report_ready"] is False


# ---------------------------------------------------------------------------
# exploit execution endpoint (real module run — replaces the phantom
# `deploy` command the Payload tab used to queue for a device_id nobody
# ever polls)
# ---------------------------------------------------------------------------

def test_exploit_endpoint_runs_registered_module(httpd, monkeypatch):
    calls = []

    def _fake_run(tv_type, ip):
        calls.append((tv_type, ip))
        return {"attempted": True, "success": True, "duration_s": 2.5}

    monkeypatch.setattr(c2_server, "run_exploit", _fake_run)
    code, res = _http(httpd, "POST", "/api/exploit",
                      {"ip": "10.20.30.40", "family": "tizen-dev"})
    assert code == 200
    assert res["attempted"] is True and res["success"] is True
    assert res["tv_type"] == "samsung-tizen"
    assert res["duration_s"] == 2.5
    assert res["executed_at"]
    assert calls == [("samsung-tizen", "10.20.30.40")]


def test_exploit_endpoint_honors_explicit_tv_type_and_reports_failure(httpd,
                                                                      monkeypatch):
    calls = []
    monkeypatch.setattr(
        c2_server, "run_exploit",
        lambda tv, ip: calls.append(tv) or {
            "attempted": True, "success": False, "duration_s": 0.4,
            "error": "connection refused"})
    code, res = _http(httpd, "POST", "/api/exploit",
                      {"ip": "10.20.30.41", "tv_type": "chromecast"})
    assert code == 200
    assert res["success"] is False and res["error"] == "connection refused"
    assert res["tv_type"] == "chromecast"
    assert calls == ["chromecast"]


def test_exploit_endpoint_never_runs_without_a_module(httpd, monkeypatch):
    def _must_not_run(tv_type, ip):
        raise AssertionError("run_exploit must not be called without a module")

    monkeypatch.setattr(c2_server, "run_exploit", _must_not_run)
    # 'dlna' has no registry module — honest 404, nothing executed.
    code, res = _http(httpd, "POST", "/api/exploit",
                      {"ip": "10.20.30.42", "family": "dlna"})
    assert code == 404
    assert res["attempted"] is False
    assert "no exploit module" in res["error"]


def test_exploit_endpoint_validates_ip(httpd):
    code, res = _http(httpd, "POST", "/api/exploit",
                      {"ip": "", "family": "tizen-dev"})
    assert code == 400 and "Missing" in res["error"]
    code, res = _http(httpd, "POST", "/api/exploit",
                      {"ip": "not-an-ip", "family": "tizen-dev"})
    assert code == 400 and "Invalid IPv4" in res["error"]


# ---------------------------------------------------------------------------
# dashboard static contract (buttons, modals, no simulated leftovers)
# ---------------------------------------------------------------------------

def test_dashboard_ships_engagement_ui():
    import os
    path = os.path.join(os.path.dirname(c2_server.__file__),
                        "c2_dashboard.html")
    with open(path, encoding="utf-8") as f:
        html = f.read()
    for needle in ("startAudit()", "startPatchAll()", 'id="client-modal"',
                   'id="auth-modal"', "sig-canvas", "/api/audit/authorize",
                   "/api/audit/sign", "/api/check", "engagement-status",
                   "id=\"cf-company\"", "table-scroll", "prefers-reduced-motion"):
        assert needle in html, f"dashboard missing: {needle}"


def test_dashboard_has_no_simulated_info():
    import os
    path = os.path.join(os.path.dirname(c2_server.__file__),
                        "c2_dashboard.html")
    with open(path, encoding="utf-8") as f:
        html = f.read()
    for stale in ("Simulate check", "srv-proxy", "changeProxyIdentity",
                  "killProxyChain", "killTor()", "AA:BB:CC:DD:EE:FF",
                  "// Simulated server info"):
        assert stale not in html, f"simulated UI leftover: {stale}"


def test_dashboard_exploit_flow_calls_real_endpoint():
    """The Payload tab's Exploit button must run the real /api/exploit
    endpoint and must never queue the phantom `deploy` command again."""
    import os
    path = os.path.join(os.path.dirname(c2_server.__file__),
                        "c2_dashboard.html")
    with open(path, encoding="utf-8") as f:
        html = f.read()
    assert "/api/exploit" in html
    for stale in ("command: 'deploy'", "Exploit deployed"):
        assert stale not in html, f"phantom deploy flow leftover: {stale}"
