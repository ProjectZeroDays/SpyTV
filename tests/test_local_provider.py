"""Local OpenAI-compatible model provider (GGUF via llama.cpp / Apple MLX).

The C2 can generate CVE artifacts with a model running ON the operator
machine: `llama-server` (GGUF) or `mlx_lm.server` (MLX). The provider is
keyless — auto-selection probes the endpoint and only picks it when a
server actually answers, so an absent local server never displaces
configured cloud providers.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import c2_cve_feed as f


class _StubHandler(BaseHTTPRequestHandler):
    """Minimal OpenAI-compatible server: GET /models + POST /chat/completions."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output quiet
        pass

    def _drain_body(self):
        """Read and discard the whole request body before answering."""
        try:
            remaining = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            return
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                return
            remaining -= len(chunk)

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # client vanished mid-response — harmless for a stub
        finally:
            self.close_connection = True

    def do_GET(self):
        try:
            if self.path.rstrip("/").endswith("/models"):
                self._json(200, {"data": [{"id": "stub-model"}]})
            else:
                self._json(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_POST(self):
        # Answer only after the body has been fully read. Replying first and
        # closing left the client mid-write, and Windows reports that as
        # [WinError 10053] "An established connection was aborted" *in the
        # client* — which is why test_generate_exploit_without_key failed only
        # some of the time, depending on how fast the response won the race.
        self._drain_body()
        try:
            if self.path.rstrip("/").endswith("/chat/completions"):
                self._json(200, {
                    "choices": [{"message": {"role": "assistant",
                                             "content": "STUB-CONTENT"}}],
                })
            else:
                self._json(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


@pytest.fixture()
def local_server():
    """A real OpenAI-compatible stub on an ephemeral localhost port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """No machine state: empty key files, no env keys, cold probe cache."""
    monkeypatch.setattr(f, "AI_KEYS_FILE", tmp_path / "no_keys.json")
    monkeypatch.setattr(f, "ENV_FILE", tmp_path / "no_env")
    monkeypatch.setattr(f, "_PROBE_CACHE", {})
    for prov in f.AI_PROVIDERS.values():
        monkeypatch.delenv(prov["key_env"], raising=False)
    monkeypatch.delenv("LOCAL_LLM_ENDPOINT", raising=False)
    monkeypatch.delenv("LOCAL_LLM_MODEL", raising=False)


# A guaranteed-dead endpoint (port 9 = discard, connection refused instantly).
DEAD = "http://127.0.0.1:9/v1/chat/completions"


def test_local_provider_is_keyless():
    prov = f.AI_PROVIDERS["local"]
    assert prov["requires_key"] is False
    assert prov["default_model"] == "local"
    assert prov["endpoint"].startswith("http://")
    assert prov["key_env"] == "LOCAL_LLM_API_KEY"


def test_cloud_provider_order_unchanged():
    # Local must come LAST so configured cloud providers keep precedence.
    assert list(f.AI_PROVIDERS)[:3] == ["openrouter", "venice", "abliteration"]
    assert list(f.AI_PROVIDERS)[-1] == "local"


def test_auto_select_none_when_local_down(monkeypatch):
    monkeypatch.setitem(f.AI_PROVIDERS["local"], "endpoint", DEAD)
    assert f.first_configured_provider({}) is None


def test_auto_selects_local_when_server_up(monkeypatch, local_server):
    monkeypatch.setitem(f.AI_PROVIDERS["local"], "endpoint", local_server)
    assert f.first_configured_provider({}) == "local"


def test_saved_url_becomes_endpoint():
    prov = f.AI_PROVIDERS["local"]
    override = "http://10.0.0.5:9999/v1/chat/completions"
    assert f._provider_endpoint("local", prov, {"local": override}) == override
    assert f._provider_endpoint("local", prov, {"local": ""}) == prov["endpoint"]
    # Cloud providers never treat their key as an endpoint.
    assert f._provider_endpoint("venice", f.AI_PROVIDERS["venice"],
                                {"venice": "http://x/y"}) == f.AI_PROVIDERS["venice"]["endpoint"]


def test_ai_complete_without_key(monkeypatch, local_server):
    monkeypatch.setitem(f.AI_PROVIDERS["local"], "endpoint", local_server)
    text, err = f._ai_complete("hi", "local")
    assert err is None, err
    assert text == "STUB-CONTENT"


def test_ai_complete_keyed_provider_still_requires_key(monkeypatch, local_server):
    # A cloud provider with no key must fail exactly as before.
    text, err = f._ai_complete("hi", "openrouter")
    assert text is None
    assert err == "No AI provider API key configured"


def test_generate_exploit_without_key(monkeypatch, local_server, tmp_path):
    monkeypatch.setitem(f.AI_PROVIDERS["local"], "endpoint", local_server)
    monkeypatch.setattr(f, "GENERATED_DIR", tmp_path)
    cve = {"id": "CVE-2099-0001", "description": "stub", "severity": "LOW",
           "score": 1.0, "device_name": "StubTV", "component": "stub",
           "fixed_in": "none", "ports": [1234]}
    code, err = f.generate_exploit_with_ai(cve, "local")
    assert err is None, err
    assert code == "STUB-CONTENT"
    assert (tmp_path / "CVE-2099-0001.py").exists()


def test_status_reports_local_endpoint(monkeypatch, local_server):
    monkeypatch.setitem(f.AI_PROVIDERS["local"], "endpoint", local_server)
    status = f.ai_key_status()
    assert status["local"]["configured"] is True
    assert status["local"]["masked"] == local_server
    # Cloud providers stay unconfigured with an empty key file.
    assert status["openrouter"]["configured"] is False
    assert status["venice"]["masked"] == ""


def test_status_local_not_configured_when_down(monkeypatch):
    monkeypatch.setitem(f.AI_PROVIDERS["local"], "endpoint", DEAD)
    status = f.ai_key_status()
    assert status["local"]["configured"] is False
