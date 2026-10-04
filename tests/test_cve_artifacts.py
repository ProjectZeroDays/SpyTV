"""Tests for the CVE artifact pipeline (T-02) and the dashboard viewer (T-01).

Covers:
  * Whitepaper generation — deterministic template always produces a file
    in docs/whitepapers/ (AI draft when configured), safe markdown→HTML
    rendering (XSS escape), the HTML page preferring the generated file
  * Generated pytest tests — must pass before ``tests_generated`` is set;
    failure quarantines the exploit module
  * Signature / patch-check proposals (validated, never auto-merged)
  * Feed enrichment from NVD (CWE, affected CPEs, fixed-in, attack vector)
  * Per-artifact + per-CVE failure isolation (the update run never aborts)
  * All artifact statuses logged to the root CVE_UPDATES.log (JSONL)
  * HTTP: GET /api/cve/whitepaper_doc/<id>, GET /api/cve/artifacts/<id>
  * Dashboard contract: viewer buttons, single replaceable output panel,
    equal-width columns, reset on start, tooltips + docs

Everything runs offline: AI paths are exercised through monkeypatched
drafts, state/log/artifact directories live in tmp_path.
"""
import json
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest

import c2_cve_feed as f
import c2_server

REPO_ROOT = f.REPO_ROOT
DASHBOARD = REPO_ROOT / "c2_dashboard.html"
DOCS = REPO_ROOT / "docs" / "C2_DASHBOARD.md"

SAMPLE_CVE = {
    "id": "CVE-2099-0001",
    "description": "A smart TV web UI bug fixed in 4.2.1 allows RCE.",
    "severity": "HIGH",
    "score": 8.1,
    "published": "2026-01-01T00:00:00.000",
    "references": ["https://example.com/adv"],
    "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
    "whitepaper_url": "/api/cve/whitepaper/CVE-2099-0001",
    "ports": [8080],
    "component": "Web UI",
    "device_name": "TestOS TV",
    "cwe": ["CWE-79"],
    "affected": ["cpe:2.3:a:testos:tv:4.0"],
    "fixed_in": "4.2.1",
    "attack_vector": "NETWORK",
    "exploitability": "Network-reachable",
    "exploit_generated": False,
    # Post-pipeline state (as stored after build_artifact_set ran)
    "whitepaper_generated": True,
    "tests_generated": True,
    "signature_generated": True,
    "patch_check_generated": True,
}


@pytest.fixture()
def feed_env(monkeypatch, tmp_path):
    """Isolated state/log/artifact directories + no AI provider."""
    monkeypatch.setattr(f, "CVE_STATE_FILE", tmp_path / "cve_state.json")
    monkeypatch.setattr(f, "CVE_LOG_FILE", tmp_path / "CVE_UPDATES.log")
    monkeypatch.setattr(f, "WHITEPAPER_DIR", tmp_path / "whitepapers")
    monkeypatch.setattr(f, "GENERATED_TESTS_DIR", tmp_path / "tests_gen")
    monkeypatch.setattr(f, "SIGNATURE_DIR", tmp_path / "signatures")
    monkeypatch.setattr(f, "PATCH_CHECK_DIR", tmp_path / "patch_checks")
    monkeypatch.setattr(f, "GENERATED_DIR", tmp_path / "exploits")
    monkeypatch.setattr(f, "first_configured_provider", lambda: None)
    # Most tests don't need a real pytest subprocess — one dedicated test
    # below resets this to prove the generated test actually passes.
    monkeypatch.setattr(f, "_template_test_proven", True)
    monkeypatch.delenv("CVE_OFFLINE", raising=False)
    return tmp_path


def _seed_root_log(path, ids):
    with open(path, "a", encoding="utf-8") as fh:
        for cid in ids:
            fh.write(json.dumps({
                "ts": "2026-10-01T00:00:00+00:00",
                "event": "new_cve",
                "id": cid,
                "severity": "HIGH",
                "score": 7.5,
                "description": "desc " + cid,
                "exploit_generated": False,
            }) + "\n")


def _log_events(path):
    return [json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


# ---------------------------------------------------------------------------
# T-01: whitepapers
# ---------------------------------------------------------------------------
def test_template_whitepaper_has_required_sections():
    wp = f.template_whitepaper(SAMPLE_CVE)
    for section in ("# CVE-2099-0001", "## Summary", "## Affected products",
                    "## Detection (SpyTV)", "## Remediation", "## References",
                    "## Document control", "4.2.1", "CWE-79"):
        assert section in wp, section


def test_markdown_to_html_renders_and_escapes():
    md = f.template_whitepaper(SAMPLE_CVE)
    html = f.markdown_to_html(md)
    assert "<h1>" in html and "<h2>" in html and "<ul>" in html
    assert "A smart TV web UI bug" in html

    xss = f.markdown_to_html("<script>alert(1)</script>")
    assert "<script>" not in xss
    assert "&lt;script&gt;" in xss

    inline = f.markdown_to_html("hi **b** `c` [t](https://e.com)")
    assert "<strong>b</strong>" in inline
    assert "<code>c</code>" in inline
    assert '<a href="https://e.com"' in inline


def test_build_artifact_set_writes_whitepaper_file(feed_env):
    cve = dict(SAMPLE_CVE)
    report = f.build_artifact_set(cve, provider=None)
    assert report["whitepaper_generated"] is True
    assert cve["whitepaper_generated"] is True
    wp = feed_env / "whitepapers" / "CVE-2099-0001.md"
    assert wp.exists()
    assert "## Summary" in wp.read_text(encoding="utf-8")


def test_get_whitepaper_markdown_falls_back_to_template(feed_env):
    f.CVE_STATE_FILE.write_text(
        json.dumps({"known_cves": {SAMPLE_CVE["id"]: dict(SAMPLE_CVE)},
                    "last_update": None, "new_count": 1}),
        encoding="utf-8")
    md, source = f.get_whitepaper_markdown(SAMPLE_CVE["id"])
    assert source == "template"
    assert "## Summary" in md

    f.build_artifact_set(dict(SAMPLE_CVE), provider=None)
    md, source = f.get_whitepaper_markdown(SAMPLE_CVE["id"])
    assert source == "file"
    assert "## Summary" in md


def test_render_page_prefers_generated_file(feed_env, monkeypatch):
    f.CVE_STATE_FILE.write_text(
        json.dumps({"known_cves": {SAMPLE_CVE["id"]: SAMPLE_CVE},
                    "last_update": None, "new_count": 1}),
        encoding="utf-8")

    html = f.render_cve_whitepaper(SAMPLE_CVE["id"])
    assert "Description" in html          # template-body fallback path

    wp = feed_env / "whitepapers" / "CVE-2099-0001.md"
    wp.parent.mkdir(parents=True, exist_ok=True)
    wp.write_text("# TITLE-MARKER-9000\n\n## Summary\n\nBody text.",
                  encoding="utf-8")
    html = f.render_cve_whitepaper(SAMPLE_CVE["id"])
    assert "TITLE-MARKER-9000" in html
    assert "Generated whitepaper" in html
    assert "whitepaper: &#10003;" in html          # artifact flags rendered

    assert f.render_cve_whitepaper("CVE-0000-0000") is None


# ---------------------------------------------------------------------------
# T-02: tests / signatures / patch checks / enrichment
# ---------------------------------------------------------------------------
def test_generated_test_template_actually_passes_pytest(feed_env, monkeypatch):
    """A freshly written template test must pass under real pytest."""
    monkeypatch.setattr(f, "_template_test_proven", False)
    cve = dict(SAMPLE_CVE)
    report = f.build_artifact_set(cve, provider=None)
    test_path = feed_env / "tests_gen" / "test_CVE-2099-0001.py"
    assert test_path.exists()
    assert report["tests_generated"] is True
    passed, out = f._pytest_passes(test_path)
    assert passed, out


def test_build_artifact_set_full_set_and_flags(feed_env):
    cve = dict(SAMPLE_CVE)
    report = f.build_artifact_set(cve, provider=None)
    for flag in f.ARTIFACT_FLAGS:
        assert report[flag] is True, (flag, report)
        assert cve[flag] is True
    assert (feed_env / "tests_gen" / "test_CVE-2099-0001.py").exists()
    assert (feed_env / "signatures" / "CVE-2099-0001.md").exists()
    assert (feed_env / "patch_checks" / "CVE-2099-0001.md").exists()
    # Signature is a proposal, never source edits.
    sig = (feed_env / "signatures" / "CVE-2099-0001.md").read_text(encoding="utf-8")
    assert "not merged" in sig and "CVE-2099-0001" in sig
    pch = (feed_env / "patch_checks" / "CVE-2099-0001.md").read_text(encoding="utf-8")
    assert "Patch verification check" in pch and "4.2.1" in pch


def test_ai_failure_falls_back_to_templates_without_aborting(feed_env, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("provider down")

    monkeypatch.setattr(f, "_ai_artifact", boom)
    cve = dict(SAMPLE_CVE)
    report = f.build_artifact_set(cve, provider="openrouter")
    for flag in f.ARTIFACT_FLAGS:
        assert report[flag] is True, (flag, report)
    assert report["errors"]                      # failures recorded…
    assert "whitepaper_ai" in report["errors"]
    assert (feed_env / "whitepapers" / "CVE-2099-0001.md").exists()  # …templates saved


def test_single_artifact_failure_does_not_block_others(feed_env):
    blocker = feed_env / "not_a_dir"
    blocker.write_text("x", encoding="utf-8")    # mkdir() on this will fail
    monkey_target = f.WHITEPAPER_DIR
    import c2_cve_feed
    c2_cve_feed.WHITEPAPER_DIR = blocker
    try:
        cve = dict(SAMPLE_CVE)
        report = c2_cve_feed.build_artifact_set(cve, provider=None)
    finally:
        c2_cve_feed.WHITEPAPER_DIR = monkey_target
    assert report["whitepaper_generated"] is False
    assert report["tests_generated"] is True
    assert report["signature_generated"] is True
    assert report["patch_check_generated"] is True
    assert "whitepaper" in report["errors"]


def test_failing_test_quarantines_exploit(feed_env, monkeypatch):
    """If the generated test cannot pass, the exploit is quarantined and
    the entry is flagged tests_generated=False."""
    exploit = feed_env / "exploits"
    exploit.mkdir(parents=True, exist_ok=True)
    (exploit / "CVE-2099-0001.py").write_text("CHECK = 1\n",
                                               encoding="utf-8")
    monkeypatch.setattr(f, "_pytest_passes", lambda p: (False, "boom"))
    cve = dict(SAMPLE_CVE)
    cve["exploit_generated"] = True
    report = f.build_artifact_set(cve, provider=None)
    assert report["tests_generated"] is False
    assert report["quarantined"] is True
    assert cve["exploit_generated"] is False
    assert not (exploit / "CVE-2099-0001.py").exists()
    assert (exploit / "CVE-2099-0001.quarantined").exists()
    # Other artifacts still generated.
    assert report["whitepaper_generated"] is True
    assert report["signature_generated"] is True
    assert report["patch_check_generated"] is True


def test_test_dir_failure_sets_only_tests_flag_false(feed_env):
    blocker = feed_env / "tests_blocked"
    blocker.write_text("x", encoding="utf-8")
    import c2_cve_feed
    saved = c2_cve_feed.GENERATED_TESTS_DIR
    c2_cve_feed.GENERATED_TESTS_DIR = blocker
    try:
        cve = dict(SAMPLE_CVE)
        report = c2_cve_feed.build_artifact_set(cve, provider=None)
    finally:
        c2_cve_feed.GENERATED_TESTS_DIR = saved
    assert report["tests_generated"] is False
    assert "test" in report["errors"]
    assert report["whitepaper_generated"] is True
    assert report["signature_generated"] is True
    assert report["patch_check_generated"] is True


def test_parse_nvd_enrichment_fields():
    nvd = {
        "id": "CVE-2026-55555",
        "published": "2026-09-15T00:00:00.000",
        "descriptions": [{"lang": "en",
                          "value": "A flaw in the media renderer. Fixed in "
                                   "version 4.2.1 to address the issue."}],
        "metrics": {"cvssMetricV31": [{
            "cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.8,
                         "attackVector": "NETWORK", "userInteraction": "NONE"}}]},
        "references": [{"url": "https://example.com/adv"}],
        "weaknesses": [{"description": [{"value": "CWE-787"},
                                         {"value": "CWE-20"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [{"criteria":
            "cpe:2.3:a:example:tv:*:*:*:*:*:*:*:*"}]}]}],
    }
    entry = f.parse_nvd_cve(nvd)
    assert entry["cwe"] == ["CWE-787", "CWE-20"]
    assert entry["affected"] == ["cpe:2.3:a:example:tv:*:*:*:*:*:*:*:*"]
    assert entry["fixed_in"] == "4.2.1"
    assert entry["attack_vector"] == "NETWORK"
    assert "Network-reachable" in entry["exploitability"]
    assert "no user interaction required" in entry["exploitability"]
    for flag in f.ARTIFACT_FLAGS:
        assert entry[flag] is False      # defaults until the pipeline runs


# ---------------------------------------------------------------------------
# update_cve_database integration (offline, isolated)
# ---------------------------------------------------------------------------
def test_update_runs_artifacts_and_logs_every_status(feed_env, monkeypatch):
    monkeypatch.setenv("CVE_OFFLINE", "1")
    _seed_root_log(f.CVE_LOG_FILE, ["CVE-2099-0001", "CVE-2099-0002"])

    result = f.update_cve_database(auto_generate=False)
    ids = {c["id"] for c in result}
    assert ids == {"CVE-2099-0001", "CVE-2099-0002"}

    state = json.loads(f.CVE_STATE_FILE.read_text(encoding="utf-8"))
    for cid in ids:
        for flag in f.ARTIFACT_FLAGS:
            assert state["known_cves"][cid][flag] is True, (cid, flag)

    events = _log_events(f.CVE_LOG_FILE)
    art = {e["id"]: e for e in events if e["event"] == "artifacts"}
    assert set(art) == ids
    for cid in ids:
        for flag in f.ARTIFACT_FLAGS:
            assert art[cid][flag] is True, (cid, flag)
    summary = [e for e in events if e["event"] == "update_summary"][-1]
    assert summary["new"] == 2
    assert summary["artifacts"] == 2
    assert summary["quarantined"] is None


def test_partial_artifact_failure_does_not_abort_update(feed_env, monkeypatch):
    monkeypatch.setenv("CVE_OFFLINE", "1")
    _seed_root_log(f.CVE_LOG_FILE, ["CVE-2099-0001", "CVE-2099-0002"])
    real = f.build_artifact_set

    def flaky(cve, provider=None):
        if cve.get("id") == "CVE-2099-0002":
            raise RuntimeError("simulated pipeline crash")
        return real(cve, provider)

    monkeypatch.setattr(f, "build_artifact_set", flaky)
    result = f.update_cve_database(auto_generate=False)

    # The run completed and both CVEs were still logged/returned.
    assert {c["id"] for c in result} == {"CVE-2099-0001", "CVE-2099-0002"}
    state = json.loads(f.CVE_STATE_FILE.read_text(encoding="utf-8"))
    assert state["known_cves"]["CVE-2099-0001"]["whitepaper_generated"] is True
    assert state["known_cves"]["CVE-2099-0002"]["whitepaper_generated"] is False

    events = _log_events(f.CVE_LOG_FILE)
    art = {e["id"]: e for e in events if e["event"] == "artifacts"}
    assert art["CVE-2099-0001"]["whitepaper_generated"] is True
    assert art["CVE-2099-0002"]["errors"]["pipeline"].startswith("simulated")
    assert any(e["event"] == "update_summary" for e in events)   # run finished


def test_log_cve_update_writes_artifact_events(feed_env):
    cve = dict(SAMPLE_CVE)
    report = f.build_artifact_set(cve, provider=None)
    f.log_cve_update([cve], [], {cve["id"]: report})
    events = _log_events(f.CVE_LOG_FILE)
    kinds = [e["event"] for e in events]
    assert kinds == ["new_cve", "artifacts", "update_summary"]
    art = events[1]
    for flag in f.ARTIFACT_FLAGS:
        assert art[flag] is True
    assert art["quarantined"] is False
    assert art["errors"] is None


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------
def _http(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            if "json" in resp.headers.get("Content-Type", ""):
                return resp.status, json.loads(raw)
            return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


@pytest.fixture()
def httpd(feed_env, monkeypatch):
    f.CVE_STATE_FILE.write_text(
        json.dumps({"known_cves": {SAMPLE_CVE["id"]: dict(SAMPLE_CVE)},
                    "last_update": "2026-10-04T00:00:00+00:00",
                    "new_count": 1}),
        encoding="utf-8")
    (feed_env / "whitepapers").mkdir(exist_ok=True)
    (feed_env / "whitepapers" / "CVE-2099-0001.md").write_text(
        "# Generated WP\n\n## Summary\n\nFrom file.", encoding="utf-8")
    server = HTTPServer(("127.0.0.1", 0), c2_server.C2Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield port
    server.shutdown()
    server.server_close()
    t.join(timeout=5)


def test_whitepaper_doc_endpoint(httpd):
    status, doc = _http(httpd, "/api/cve/whitepaper_doc/CVE-2099-0001")
    assert status == 200
    assert doc["id"] == "CVE-2099-0001"
    assert doc["source"] == "file"
    assert doc["generated"] is True
    assert "From file." in doc["markdown"]

    status, err = _http(httpd, "/api/cve/whitepaper_doc/CVE-0000-0000")
    assert status == 404
    assert "error" in err


def test_artifacts_endpoint(httpd):
    status, art = _http(httpd, "/api/cve/artifacts/CVE-2099-0001")
    assert status == 200
    for flag in f.ARTIFACT_FLAGS:
        assert art["flags"][flag] is True
    assert art["files"]["whitepaper"]["exists"] is True
    assert art["files"]["test"]["exists"] is False
    assert art["files"]["whitepaper"]["path"].endswith("CVE-2099-0001.md")
    assert art["enrichment"]["fixed_in"] == "4.2.1"

    status, err = _http(httpd, "/api/cve/artifacts/CVE-0000-0000")
    assert status == 404


def test_whitepaper_html_endpoint_still_serves(httpd):
    status, html = _http(httpd, "/api/cve/whitepaper/CVE-2099-0001")
    assert status == 200
    assert b"Generated whitepaper" in html
    assert b"CVE-2099-0001" in html


# ---------------------------------------------------------------------------
# Dashboard + docs contract (T-01/T-02 UI + T-03 feature docs)
# ---------------------------------------------------------------------------
def test_dashboard_viewer_buttons_and_panel():
    html = DASHBOARD.read_text(encoding="utf-8")
    # Buttons on every feed entry
    assert "onclick=\"viewWhitepaper('" in html
    assert "onclick=\"viewVulnInfo('" in html
    assert ">View Whitepaper</button>" in html
    assert ">View Vulnerability Info</button>" in html
    # Single replaceable output panel
    assert 'id="output-panel"' in html
    assert 'id="output-body"' in html
    assert "function setOutput" in html
    # Equal-width columns (T-01: right column == left card)
    assert "grid-template-columns: minmax(0, 1fr) minmax(0, 1fr)" in html
    # Reset on C2/dashboard start
    assert "resetOutput();" in html
    # Viewers + safe renderer + artifact status loader
    for fn in ("async function viewWhitepaper", "function viewVulnInfo",
               "function mdToHtml", "function escapeHtml",
               "async function loadArtifactStatus", "function resetOutput"):
        assert fn in html, fn


def test_dashboard_tooltips_document_artifact_set():
    html = DASHBOARD.read_text(encoding="utf-8")
    assert "View Whitepaper" in html          # feed tooltip
    assert "detection-signature proposal" in html
    assert "patch-check proposal" in html


def test_docs_document_endpoints_features_and_artifacts():
    doc = DOCS.read_text(encoding="utf-8")
    # T-01/T-02 endpoints + feature sections
    assert "/api/cve/whitepaper_doc/<id>" in doc
    assert "/api/cve/artifacts/<id>" in doc
    assert "### Output Panel — Whitepaper & Vulnerability Info (T-01)" in doc
    assert "### CVE Artifact Pipeline (T-02)" in doc
    # T-03 feature section + artifact locations
    assert "### Audit & Patch All (T-03)" in doc
    assert "docs/whitepapers/" in doc
    assert "tests/generated/" in doc
    assert "data/signatures/" in doc
    assert "data/patch_checks/" in doc
