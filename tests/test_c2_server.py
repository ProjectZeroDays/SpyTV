"""Regression tests for c2_server persistence paths.

guards against the non-reentrant `scans_lock` deadlock: `save_scans()`
acquires the lock itself, so it must never run while the caller still
holds it (previously hung the /api/scan handler).
"""
import json
import threading

import c2_server


def test_record_scan_results_does_not_deadlock(monkeypatch, tmp_path):
    monkeypatch.setattr(c2_server, "SCAN_FILE", str(tmp_path / "scans.json"))
    with c2_server.scans_lock:
        c2_server.scans.clear()

    t = threading.Thread(
        target=c2_server.record_scan_results, args=([{"ip": "10.0.0.9"}],)
    )
    t.start()
    t.join(timeout=5)
    assert not t.is_alive(), "record_scan_results deadlocked on scans_lock"

    with c2_server.scans_lock:
        assert any(s.get("ip") == "10.0.0.9" for s in c2_server.scans)
    data = json.loads((tmp_path / "scans.json").read_text())
    assert data, "scan results were not persisted to SCAN_FILE"


def test_record_scan_results_caps_history(monkeypatch, tmp_path):
    monkeypatch.setattr(c2_server, "SCAN_FILE", str(tmp_path / "scans.json"))
    with c2_server.scans_lock:
        c2_server.scans.clear()

    c2_server.record_scan_results([{"ip": f"10.0.1.{i}"} for i in range(150)])

    with c2_server.scans_lock:
        assert len(c2_server.scans) == 100


def test_implant_module_exposes_js():
    from core.implant import get_implant_js, implant_path

    src = get_implant_js()
    assert "function" in src and "CONFIG" in src
    assert implant_path().endswith("tvreaper.js")
