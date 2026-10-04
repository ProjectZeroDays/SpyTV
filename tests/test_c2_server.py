"""Regression tests for c2_server persistence paths.

guards against the non-reentrant `scans_lock` deadlock: `save_scans()`
acquires the lock itself, so it must never run while the caller still
holds it (previously hung the /api/scan handler).
"""
import json
import os
import pathlib
import queue
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

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


# ---------------------------------------------------------------------------
# Android console contract: the app's WebView loads "/" and decides from that
# response whether it reached SpyTV, so the root document must be our dashboard
# — never a bare JSON status blob from whatever else happens to own the port.
# ---------------------------------------------------------------------------

def _serve_root():
    server = ThreadingHTTPServer(("127.0.0.1", 0), c2_server.C2Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, t, f"http://127.0.0.1:{server.server_address[1]}"


def test_root_serves_the_spytv_dashboard_html():
    server, t, base = _serve_root()
    try:
        with urllib.request.urlopen(f"{base}/", timeout=10) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8", "replace")
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=5)

    assert status == 200
    assert "text/html" in ctype
    assert "TV Security Assessment Platform" in body
    # The symptom seen when another service owns the port: a JSON envelope with
    # an "endpoints" list rendered raw by the WebView.
    assert '"endpoints"' not in body
    assert '"dashboard"' not in body


def test_c2_port_env_override_moves_the_whole_platform():
    """SPYTV_C2_PORT must relocate the whole platform (console, dashboard and
    generated implant payloads) without code edits. Run in a subprocess so the
    imported c2_server module isn't reloaded underneath the other tests."""
    script = "import c2_server; print(c2_server.C2_PORT)"
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=120,
        env={**os.environ, "SPYTV_C2_PORT": "9443"},
        cwd=str(pathlib.Path(__file__).resolve().parents[1]),
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "9443"

    # default is unchanged when the variable isn't set
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=120,
        env={k: v for k, v in os.environ.items() if k != "SPYTV_C2_PORT"},
        cwd=str(pathlib.Path(__file__).resolve().parents[1]),
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "8443"


def test_server_boots_when_stdout_is_not_utf8():
    """Regression: the startup banner's '⚙' has no representation in cp1252,
    which is the code page a piped or redirected stdout gets on Windows. The
    print ran AFTER the port was already bound but BEFORE serve_forever(), so
    UnicodeEncodeError killed the process during startup — the dashboard then
    answered nothing at all, and the C2 read as "keeps restarting, opening a
    terminal window again".

    Run in a real subprocess (a pipe is what forces the ANSI code page) with
    SPYTV_C2_PORT=0 so the ephemeral port can never collide with a live C2.
    """
    env = {k: v for k, v in os.environ.items() if k != "SPYTV_C2_PORT"}
    env["SPYTV_C2_PORT"] = "0"
    # A pipe would otherwise block-buffer stdout: a healthy server would never
    # flush the banner and the test could not tell "running" from "stuck".
    # PYTHONUNBUFFERED only changes buffering, never the ANSI code page.
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "c2_server.py"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=env, cwd=str(pathlib.Path(__file__).resolve().parents[1]),
        text=True, errors="replace",   # match the child's own code page
    )
    lines: "queue.Queue[str]" = queue.Queue()

    def _pump():
        for line in proc.stdout:
            lines.put(line)

    threading.Thread(target=_pump, daemon=True).start()

    seen, booted, deadline = [], False, time.time() + 60
    try:
        while time.time() < deadline:
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                if proc.poll() is not None:
                    break
                continue
            seen.append(line)
            if "C2 Server running" not in line:
                continue
            booted = True
            # The bind happens first, so the banner appears BEFORE the '⚙'
            # print that used to kill the process. Keep draining afterwards,
            # otherwise a startup death hides behind the banner line.
            settle = time.time() + 3
            while time.time() < settle:
                try:
                    seen.append(lines.get(timeout=0.2))
                except queue.Empty:
                    if proc.poll() is not None:
                        break
            break

        blob = "".join(seen)
        assert booted, f"server never reported it was running:\n{blob}"
        assert "UnicodeEncodeError" not in blob, blob
        assert "Traceback" not in blob, blob
        assert proc.poll() is None, f"server exited during startup:\n{blob}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:              # noqa: BLE001 — never leak the process
            proc.kill()
