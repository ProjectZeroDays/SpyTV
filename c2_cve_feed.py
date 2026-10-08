#!/usr/bin/env python3
"""CVE Feed Manager — Fetches, stores, and serves CVE data for Smart TVs.

Responsibilities:
  * Fetch new smart-TV CVEs from the NVD 2.0 API (rate-limit aware).
  * Persist known CVEs in ``c2_data/cve_state.json``.
  * Append every update to ``CVE_UPDATES.log`` in the repository ROOT so the
    entries can be replayed into the C2 feed.
  * Auto-generate an exploit module for each NEW CVE when an AI provider
    is configured (OpenRouter / Venice AI / Abliteration.ai, or a keyless
    local GGUF/MLX server running on this machine).
  * Provide NVD + whitepaper links for every feed entry.

AI keys are resolved in this order:
  1. ``c2_data/ai_keys.json`` (written by the dashboard "Save Keys" button)
  2. ``.env`` in the repository root (written by ``run_c2.bat``)
  3. process environment variables

Usage:
    python -c "from c2_cve_feed import update_cve_database; print(len(update_cve_database()))"
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Repository root (this file lives at the repo root)
REPO_ROOT = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# AI provider configuration
# ---------------------------------------------------------------------------
AI_PROVIDERS = {
    "openrouter": {
        "name": "OpenRouter (Uncensored)",
        "endpoint": os.environ.get(
            "OPENROUTER_ENDPOINT", "https://openrouter.ai/api/v1/chat/completions"
        ),
        "key_env": "OPENROUTER_API_KEY",
        "models": {
            "uncensored": os.environ.get(
                "OPENROUTER_MODEL", "sao10k/l3-70b-euryale-v2.1"
            ),
            # Free models available on OpenRouter (zero prompt pricing)
            "nemotron_3_ultra": os.environ.get(
                "OPENROUTER_MODEL_NEMOTRON_3_ULTRA", "nvidia/nemotron-3-ultra-550b-a55b:free"
            ),
            "nemotron_3_5_lightning": os.environ.get(
                "OPENROUTER_MODEL_NEMOTRON_3_5_LIGHTNING", "nvidia/nemotron-3.5-lightning:free"
            ),
            "nemotron_3_super": os.environ.get(
                "OPENROUTER_MODEL_NEMOTRON_3_SUPER", "nvidia/nemotron-3-super-120b-a12b:free"
            ),
            "nemotron_3_nano": os.environ.get(
                "OPENROUTER_MODEL_NEMOTRON_3_NANO", "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free"
            ),
            "nemotron_3_5_content_safety": os.environ.get(
                "OPENROUTER_MODEL_NEMOTRON_3_5_CS", "nvidia/nemotron-3.5-content-safety:free"
            ),
            "laguna_s_2_1": os.environ.get(
                "OPENROUTER_MODEL_LAGUNA_S", "poolside/laguna-s-2.1:free"
            ),
            "laguna_xs_2_1": os.environ.get(
                "OPENROUTER_MODEL_LAGUNA_XS", "poolside/laguna-xs-2.1:free"
            ),
            "inkling_small": os.environ.get(
                "OPENROUTER_MODEL_INKING_SMALL", "thinkingmachines/inkling-small:free"
            ),
            "inkling": os.environ.get(
                "OPENROUTER_MODEL_INKING", "thinkingmachines/inkling:free"
            ),
            "dots3_note_preview": os.environ.get(
                "OPENROUTER_MODEL_DOTS3", "dots-studio/dots-3-note-preview:free"
            ),
            "ling_3_0_flash_sante": os.environ.get(
                "OPENROUTER_MODEL_LING_3_0", "inclusionai/ling-3.0-flash-sante:free"
            ),
            "ling_3_1_flash": os.environ.get(
                "OPENROUTER_MODEL_LING_3_1", "inclusionai/ling-3.1-flash"
            ),
            "gemma_4_26b": os.environ.get(
                "OPENROUTER_MODEL_GEMMA_4_26B", "google/gemma-4-26b-a4b-it:free"
            ),
            "gemma_4_31b": os.environ.get(
                "OPENROUTER_MODEL_GEMMA_4_31B", "google/gemma-4-31b-it:free"
            ),
            "lyria_3_pro_preview": os.environ.get(
                "OPENROUTER_MODEL_LYRIA_3_PRO", "google/lyria-3-pro-preview"
            ),
            "lyria_3_clip_preview": os.environ.get(
                "OPENROUTER_MODEL_LYRIA_3_CLIP", "google/lyria-3-clip-preview"
            ),
            "lfm_2_5_2_6b": os.environ.get(
                "OPENROUTER_MODEL_LFM_2_5", "liquid/lfm-2.5-2.6b:free"
            ),
            "north_mini_code": os.environ.get(
                "OPENROUTER_MODEL_NORTH_MINI", "cohere/north-mini-code:free"
            ),
            "apodex_1_1_mini": os.environ.get(
                "OPENROUTER_MODEL_APEDEX", "apodex/apodex-1.1-mini:free"
            ),
            "openrouter_free_router": os.environ.get(
                "OPENROUTER_MODEL_FREE_ROUTER", "openrouter/free"
            ),
        },
        "model_labels": {
            "uncensored": "Uncensored",
            "nemotron_3_ultra": "Nemotron 3 Ultra 550B (free)",
            "nemotron_3_5_lightning": "Nemotron 3.5 Lightning (free)",
            "nemotron_3_super": "Nemotron 3 Super 120B (free)",
            "nemotron_3_nano": "Nemotron 3 Nano Omni 30B (free)",
            "nemotron_3_5_content_safety": "Nemotron 3.5 Content Safety (free)",
            "laguna_s_2_1": "Laguna S 2.1 (free)",
            "laguna_xs_2_1": "Laguna XS 2.1 (free)",
            "inkling_small": "Inkling Small (free)",
            "inkling": "Inkling (free)",
            "dots3_note_preview": "Dots3-Note Preview (free)",
            "ling_3_0_flash_sante": "Ling 3.0 Flash Sante (free)",
            "ling_3_1_flash": "Ling 3.1 Flash (free)",
            "gemma_4_26b": "Gemma 4 26B (free)",
            "gemma_4_31b": "Gemma 4 31B (free)",
            "lyria_3_pro_preview": "Lyria 3 Pro Preview (free)",
            "lyria_3_clip_preview": "Lyria 3 Clip Preview (free)",
            "lfm_2_5_2_6b": "LFM2.5 2.6B (free)",
            "north_mini_code": "North Mini Code (free)",
            "apodex_1_1_mini": "Apodex 1.1 Mini (free)",
            "openrouter_free_router": "Auto Router (free)",
        },
        "default_model": "uncensored",
    },
    "venice": {
        "name": "Venice AI",
        "endpoint": os.environ.get(
            "VENICE_ENDPOINT", "https://api.venice.ai/api/v1/chat/completions"
        ),
        "key_env": "VENICE_API_KEY",
        "models": {
            "uncensored_v1_2": os.environ.get(
                "VENICE_MODEL_UNCENSORED", "venice-uncensored"
            ),
            "qwen_3_6_plus_uncensored": os.environ.get(
                "VENICE_MODEL_QWEN", "qwen3.6-plus-uncensored"
            ),
            "glm_4_7_flash_heretic": os.environ.get(
                "VENICE_MODEL_GLM", "glm-4.7-flash-heretic"
            ),
        },
        "model_labels": {
            "uncensored_v1_2": "Uncensored V 1.2",
            "qwen_3_6_plus_uncensored": "Qwen 3.6 Plus Uncensored",
            "glm_4_7_flash_heretic": "GLM 4.7 Flash Heretic",
        },
        "default_model": "uncensored_v1_2",
    },
    "abliteration": {
        "name": "Abliteration.ai",
        "endpoint": os.environ.get(
            "ABLITERATION_ENDPOINT", "https://api.abliteration.ai/v1/chat/completions"
        ),
        "key_env": "ABLITERATION_API_KEY",
        "models": {
            "abliterated_large_v2": os.environ.get(
                "ABLITERATION_MODEL", "abliterated-large-v2"
            ),
        },
        "model_labels": {
            "abliterated_large_v2": "Abliterated Large v2",
        },
        "default_model": "abliterated_large_v2",
    },
    # Local OpenAI-compatible server — llama.cpp `llama-server` (GGUF) or
    # `mlx_lm.server` (Apple MLX) running beside the C2. Keyless: the saved
    # "key" value may hold the endpoint URL; auto-selection probes the
    # endpoint and only picks this provider when a server actually answers.
    "local": {
        "name": "Local Model (GGUF / MLX)",
        "endpoint": os.environ.get(
            "LOCAL_LLM_ENDPOINT", "http://127.0.0.1:8080/v1/chat/completions"
        ),
        "key_env": "LOCAL_LLM_API_KEY",
        "requires_key": False,
        "models": {
            "local": os.environ.get("LOCAL_LLM_MODEL", "local-model"),
        },
        "model_labels": {
            "local": "Local (llama.cpp GGUF / Apple MLX)",
        },
        "default_model": "local",
    },
}

# ---------------------------------------------------------------------------
# Storage paths
# ---------------------------------------------------------------------------
CVE_STATE_FILE = REPO_ROOT / "c2_data" / "cve_state.json"
# Update log lives in the repo ROOT (per operator requirement) so its entries
# can be added to the C2 feed from the repository checkout.
CVE_LOG_FILE = REPO_ROOT / "CVE_UPDATES.log"
AI_KEYS_FILE = REPO_ROOT / "c2_data" / "ai_keys.json"
ENV_FILE = REPO_ROOT / ".env"
GENERATED_DIR = REPO_ROOT / "data" / "exploits" / "generated"
# T-01/T-02 artifact locations (all tracked in the repo).
WHITEPAPER_DIR = REPO_ROOT / "docs" / "whitepapers"
GENERATED_TESTS_DIR = REPO_ROOT / "tests" / "generated"
SIGNATURE_DIR = REPO_ROOT / "data" / "signatures"
PATCH_CHECK_DIR = REPO_ROOT / "data" / "patch_checks"
# Per-entry artifact flags — mirrored onto every feed entry (T-02).
ARTIFACT_FLAGS = ("whitepaper_generated", "tests_generated",
                  "signature_generated", "patch_check_generated")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_KEYWORDS = [
    "smart tv", "android tv", "tizen", "webos", "roku",
    "fire tv", "smartcast", "hbbtv", "chromecast",
]


# ---------------------------------------------------------------------------
# .env / key handling
# ---------------------------------------------------------------------------
def load_env_file(path: Path = ENV_FILE) -> dict:
    """Parse a simple KEY=VALUE .env file (no external dependency)."""
    values = {}
    if not path.exists():
        return values
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


# The .env file is the operator's config home — honour LOCAL_LLM_* there even
# though no API key is involved (the local GGUF/MLX provider is keyless).
_env_at_import = load_env_file()
AI_PROVIDERS["local"]["endpoint"] = (
    os.environ.get("LOCAL_LLM_ENDPOINT")
    or _env_at_import.get("LOCAL_LLM_ENDPOINT")
    or AI_PROVIDERS["local"]["endpoint"]
).strip()
if _env_at_import.get("LOCAL_LLM_MODEL", "").strip():
    AI_PROVIDERS["local"]["models"]["local"] = _env_at_import["LOCAL_LLM_MODEL"].strip()


def load_ai_keys() -> dict:
    """Resolve AI provider keys: ai_keys.json -> .env -> process env."""
    file_keys = {}
    if AI_KEYS_FILE.exists():
        try:
            file_keys = json.loads(AI_KEYS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            file_keys = {}
    env_file = load_env_file()
    resolved = {}
    for pid, prov in AI_PROVIDERS.items():
        key = (
            str(file_keys.get(pid, "") or "")
            or env_file.get(prov["key_env"], "")
            or os.environ.get(prov["key_env"], "")
        )
        resolved[pid] = key.strip()
    return resolved


def save_ai_keys(keys: dict):
    """Persist provider keys written from the dashboard."""
    AI_KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    current = {}
    if AI_KEYS_FILE.exists():
        try:
            current = json.loads(AI_KEYS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            current = {}
    for pid in AI_PROVIDERS:
        if pid in keys and isinstance(keys[pid], str):
            current[pid] = keys[pid].strip()
    AI_KEYS_FILE.write_text(json.dumps(current, indent=2), encoding="utf-8")


# Reachability cache for keyless providers: endpoint -> (timestamp, ok).
_PROBE_TTL = 20.0
_PROBE_CACHE: dict = {}


def _provider_endpoint(pid: str, prov: dict, keys: dict) -> str:
    """Resolve a provider's endpoint.

    Keyless providers (the `local` GGUF/MLX server) may store their server
    URL in place of a key — the dashboard "key" field doubles as an
    endpoint override when its value looks like a URL.
    """
    value = (keys.get(pid) or "").strip()
    if not prov.get("requires_key", True) and value.startswith(("http://", "https://")):
        return value
    return prov["endpoint"]


def _endpoint_reachable(endpoint: str) -> bool:
    """True when an OpenAI-compatible server answers at *endpoint*.

    Any HTTP reply (even 4xx/5xx) proves a live server; connection refused
    or timeout means nothing is listening. Cached for _PROBE_TTL seconds so
    feed updates and dashboard polls never hammer the endpoint.
    """
    now = time.time()
    cached = _PROBE_CACHE.get(endpoint)
    if cached and now - cached[0] < _PROBE_TTL:
        return cached[1]
    base = endpoint.rsplit("/chat/completions", 1)[0]
    ok = False
    try:
        with urllib.request.urlopen(base + "/models", timeout=0.6):
            ok = True
    except Exception as exc:  # noqa: BLE001 — HTTPError still proves a server
        ok = type(exc).__name__ == "HTTPError"
    _PROBE_CACHE[endpoint] = (now, ok)
    return ok


def _provider_configured(pid: str, keys: dict) -> bool:
    """A provider counts as configured when it has a key — or, for a keyless
    one, when its endpoint answers (a local GGUF/MLX server is auto-detected)."""
    prov = AI_PROVIDERS[pid]
    if keys.get(pid):
        return True
    if prov.get("requires_key", True):
        return False
    return _endpoint_reachable(_provider_endpoint(pid, prov, keys))


def ai_key_status() -> dict:
    """Masked status of each provider (for the dashboard)."""
    keys = load_ai_keys()
    status = {}
    for pid, prov in AI_PROVIDERS.items():
        key = keys.get(pid, "")
        if prov.get("requires_key", True):
            masked = (key[:4] + "…" + key[-4:]) if len(key) > 8 else ("••••" if key else "")
        else:
            # Keyless providers show where they point instead of a mask.
            masked = _provider_endpoint(pid, prov, keys)
        status[pid] = {
            "name": prov["name"],
            "configured": _provider_configured(pid, keys),
            "masked": masked,
            "models": [
                {"id": mid, "label": prov["model_labels"].get(mid, mid)}
                for mid in prov["models"]
            ],
            "default_model": prov["default_model"],
        }
    return status


def first_configured_provider(keys: dict | None = None) -> str | None:
    keys = keys if keys is not None else load_ai_keys()
    for pid in AI_PROVIDERS:
        if _provider_configured(pid, keys):
            return pid
    return None


# ---------------------------------------------------------------------------
# AI exploit generation
# ---------------------------------------------------------------------------
def generate_exploit_with_ai(cve_info: dict, provider: str | None = None,
                             model: str | None = None):
    """Ask the configured AI provider to write an exploit module for a CVE.

    Returns (code, error). The generated code is saved under
    ``data/exploits/generated/<CVE-ID>.py`` on success.
    """
    keys = load_ai_keys()
    provider = provider or first_configured_provider(keys)
    prov = AI_PROVIDERS.get(provider) if provider else None
    if (not provider or not prov
            or (prov.get("requires_key", True) and not keys.get(provider))):
        return None, "No AI provider API key configured (see AI Provider Keys)"
    model = model or prov["default_model"]
    model_id = prov["models"].get(model, model)

    prompt = f"""You are writing an authorized security-testing exploit module for a
smart TV vulnerability assessment (lab / client-owned devices only).

CVE: {cve_info.get('id')}
Description: {cve_info.get('description')}
Severity: {cve_info.get('severity')} (CVSS {cve_info.get('score')})
Target platform: {cve_info.get('device_name', 'Smart TV')}
Component: {cve_info.get('component', 'unknown')}
Fixed version: {cve_info.get('fixed_in', 'unknown')}
Service ports: {cve_info.get('ports', [])}

Requirements:
1. Python 3 stdlib only, class with NAME/CVES/PORTS attributes.
2. check(ip) -> bool: detect vulnerability safely (read-only probe).
3. run(ip, params=None) -> bool: perform the authorized exploit, printing steps.
4. Reference the CVE in a module docstring; no destructive payloads.

Output ONLY raw Python source, no markdown fences, no commentary."""

    payload = {
        "model": model_id,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.4,
        "max_tokens": 2500,
    }
    headers = {
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/authenticated-inc/spytv",
        "X-Title": "SpyTV CVE Exploit Generator",
    }
    auth = (keys.get(provider) or "").strip()
    if auth and (prov.get("requires_key", True)
                 or not auth.startswith(("http://", "https://"))):
        headers["Authorization"] = f"Bearer {auth}"
    endpoint = _provider_endpoint(provider, prov, keys)
    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode())
        code = data["choices"][0]["message"]["content"]
        # Strip markdown fences if the model added them anyway.
        code = re.sub(r"^```(?:python)?\s*|\s*```$", "", code.strip(),
                      flags=re.MULTILINE).strip()
        cve_id = cve_info.get("id", "CVE-UNKNOWN")
        GENERATED_DIR.mkdir(parents=True, exist_ok=True)
        out = GENERATED_DIR / f"{cve_id}.py"
        header = (
            f'"""Auto-generated exploit for {cve_id} '
            f'({prov["name"]} / {model_id}).\n'
            f'Authorized security testing only.\n"""\n'
        )
        out.write_text(header + code + "\n", encoding="utf-8")
        return code, None
    except Exception as exc:  # noqa: BLE001 — surface any provider failure
        return None, str(exc)


def generate_exploit_for_cve(cve_id: str, provider: str | None = None,
                             model: str | None = None):
    """Generate + save an exploit for a CVE already in the state database.

    Provider/model resolution: when ``provider`` is falsy, the first
    *configured* provider is auto-selected so the dashboard can send
    ``provider=None`` and still get a result. ``model`` is only honoured
    when it belongs to the resolved provider — a Venice model name sent
    for the OpenRouter provider is silently dropped to the provider default,
    which is what caused the original 400 "Bad Request" from the upstream API.
    """
    state = load_state()
    cve = state.get("known_cves", {}).get(cve_id)
    if not cve:
        return None, "CVE not found in database"
    # If provider is not explicitly chosen, auto-select first configured.
    if not provider:
        keys = load_ai_keys()
        provider = first_configured_provider(keys)
    # Validate model belongs to the chosen provider; fall back to default.
    if provider and provider in AI_PROVIDERS:
        prov = AI_PROVIDERS[provider]
        if model and model not in prov.get("models", {}):
            model = prov.get("default_model")
    return generate_exploit_with_ai(cve, provider, model)


def generate_patch_for_cve(cve_id: str, provider: str | None = None,
                           model: str | None = None):
    """Generate + save a remediation patch for a CVE.

    Returns (code, error). The generated patch is saved under
    ``data/patches/generated/<CVE-ID>.patch`` on success.
    """
    state = load_state()
    cve = state.get("known_cves", {}).get(cve_id)
    if not cve:
        return None, "CVE not found in database"
    if not provider:
        keys = load_ai_keys()
        provider = first_configured_provider(keys)
    if provider and provider in AI_PROVIDERS:
        prov = AI_PROVIDERS[provider]
        if model and model not in prov.get("models", {}):
            model = prov.get("default_model")
    return _generate_patch_with_ai(cve, provider, model)


def _generate_patch_with_ai(cve_info: dict, provider: str | None = None,
                            model: str | None = None):
    """Ask AI for a patch script for a CVE. Returns (code, error)."""
    keys = load_ai_keys()
    provider = provider or first_configured_provider(keys)
    prov = AI_PROVIDERS.get(provider) if provider else None
    if (not provider or not prov
            or (prov.get("requires_key", True) and not keys.get(provider))):
        return None, "No AI provider API key configured (see AI Provider Keys)"
    model = model or prov["default_model"]
    model_id = prov["models"].get(model, model)

    prompt = f"""You are writing an authorized security-remediation patch script for a
smart TV vulnerability. The patch should safely apply a firmware/config fix or
workaround (lab / client-owned devices only).

CVE: {cve_info.get('id')}
Description: {cve_info.get('description')}
Severity: {cve_info.get('severity')} (CVSS {cve_info.get('score')})
Target platform: {cve_info.get('device_name', 'Smart TV')}
Component: {cve_info.get('component', 'unknown')}
Fixed version: {cve_info.get('fixed_in', 'unknown')}
Service ports: {cve_info.get('ports', [])}

Requirements:
1. Output the remediation commands or script (bash, curl, or config change).
2. No destructive payloads — only safe remediation steps.
3. Reference the CVE in a comment header.

Output ONLY the patch script, no markdown fences, no commentary."""

    payload = {
        "model": model_id,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 2000,
    }
    headers = {
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/authenticated-inc/spytv",
        "X-Title": "SpyTV CVE Patch Generator",
    }
    auth = (keys.get(provider) or "").strip()
    if auth and (prov.get("requires_key", True)
                 or not auth.startswith(("http://", "https://"))):
        headers["Authorization"] = f"Bearer {auth}"
    endpoint = _provider_endpoint(provider, prov, keys)
    try:
        import urllib.request as ulreq
        req = ulreq.Request(
            endpoint,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        with ulreq.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode())
        code = data["choices"][0]["message"]["content"].strip()
        import re
        code = re.sub(r"^```(?:bash|sh)?\s*|\s*```$", "", code,
                      flags=re.MULTILINE).strip()
        cve_id = cve_info.get("id", "CVE-UNKNOWN")
        import pathlib
        patches_dir = pathlib.Path(GENERATED_DIR).parent / "patches" / "generated"
        patches_dir.mkdir(parents=True, exist_ok=True)
        out = patches_dir / f"{cve_id}.patch"
        header = f'#!/bin/bash\n# Remediation patch for {cve_id} ({prov["name"]} / {model_id}).\n# Authorized security testing only.\n'
        out.write_text(header + code + "\n", encoding="utf-8")
        # Mark the patch_check_generated flag in state
        _mark_artifact_flag(cve_id, "patch_check_generated")
        return code, None
    except Exception as exc:
        return None, str(exc)


def list_exploits():
    """List all generated exploits with their success rate / status."""
    import pathlib
    state = load_state()
    results = []
    if GENERATED_DIR.exists():
        for f in sorted(GENERATED_DIR.glob("CVE-*.py")):
            cid = f.stem
            cve = state.get("known_cves", {}).get(cid, {})
            results.append({
                "cve_id": cid,
                "tv_type": cve.get("tv_type", "smart-tv"),
                "device_name": cve.get("device_name", "Unknown"),
                "severity": cve.get("severity", "UNKNOWN"),
                "file": str(f.relative_to(REPO_ROOT)),
                "exploit_status": "generated",
                "success_rate": cve.get("success_rate", 0),
                "attempts": cve.get("attempts", 0),
                "last_run": cve.get("last_run"),
                "exploit_ready": True,
            })
    return results


def _mark_artifact_flag(cve_id: str, flag: str):
    """Set an artifact flag on a CVE in state and persist."""
    try:
        state = load_state()
        if cve_id in state.get("known_cves", {}):
            state["known_cves"][cve_id][flag] = True
            save_state(state)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Artifact generation — T-01 whitepaper + T-02 test/signature/patch/enrich
# ---------------------------------------------------------------------------
def _ai_complete(prompt: str, provider: str, model: str | None = None,
                 max_tokens: int = 2000, temperature: float = 0.4):
    """Single chat-completion call against a configured provider.

    Returns ``(text, error)`` — never raises.
    """
    keys = load_ai_keys()
    prov = AI_PROVIDERS.get(provider)
    if (not provider or not prov
            or (prov.get("requires_key", True) and not keys.get(provider))):
        return None, "No AI provider API key configured"
    model = model or prov["default_model"]
    model_id = prov["models"].get(model, model)
    payload = {
        "model": model_id,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/authenticated-inc/spytv",
        "X-Title": "SpyTV CVE Artifact Generator",
    }
    auth = (keys.get(provider) or "").strip()
    if auth and (prov.get("requires_key", True)
                 or not auth.startswith(("http://", "https://"))):
        headers["Authorization"] = f"Bearer {auth}"
    endpoint = _provider_endpoint(provider, prov, keys)
    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"].strip(), None
    except Exception as exc:  # noqa: BLE001 — surface any provider failure
        return None, str(exc)


def _ai_artifact(cve: dict, provider: str, kind: str):
    """Prompt the provider for one artifact of a CVE. Returns (text, error)."""
    cid = cve.get("id")
    base = (f"CVE: {cid}\nSeverity: {cve.get('severity')} "
            f"(CVSS {cve.get('score')})\n"
            f"Component: {cve.get('component', 'unknown')}\n"
            f"Device family: {cve.get('device_name', 'Smart TV')}\n"
            f"Fixed in: {cve.get('fixed_in', 'unknown')}\n"
            f"Ports: {cve.get('ports', [])}\n"
            f"Description: {cve.get('description', '')}")
    if kind == "whitepaper":
        prompt = (f"Write an authorized security-assessment whitepaper in markdown "
                  f"for this smart-TV vulnerability (lab / client-owned devices "
                  f"only, no exploit code):\n{base}\n\n"
                  f"Use exactly these ## sections: Summary, Affected products, "
                  f"Detection (SpyTV), Remediation, References. Output ONLY "
                  f"markdown.")
        max_tokens = 1400
    elif kind == "test":
        prompt = (f"Write a pytest test file for the exploit module "
                  f"data/exploits/generated/{cid}.py (class exposing check(ip) "
                  f"and run(ip, params=None)):\n{base}\n\n"
                  f"Constraints: load it with importlib.util.spec_from_file_"
                  f"location using pathlib Path(__file__).resolve().parents[2] / "
                  f"'data' / 'exploits' / 'generated' / '{cid}.py'; pytest.skip "
                  f"if the file is missing; structure/metadata assertions only; "
                  f"NO sockets or network; stdlib + pytest only. Output ONLY raw "
                  f"Python.")
        max_tokens = 1400
    elif kind == "signature":
        prompt = (f"Propose a detection-signature addition for "
                  f"core/cve_scanner.py family matching for this CVE (a markdown "
                  f"proposal — do NOT edit any source file):\n{base}\n\n"
                  f"Include matching ports/service fingerprints, family/device "
                  f"indicators, a suggested Python snippet, and validation "
                  f"notes. Output ONLY markdown.")
        max_tokens = 900
    else:  # patch_check
        prompt = (f"Write a remediation/patch verification check in markdown for "
                  f"this CVE's device family (commands an assessor runs to "
                  f"confirm the fix):\n{base}\n\n"
                  f"Include vendor firmware update steps, a verification "
                  f"command, and what 'patched' looks like. Output ONLY markdown.")
        max_tokens = 900
    text, err = _ai_complete(prompt, provider, max_tokens=max_tokens)
    if text:
        text = re.sub(r"^```(?:markdown|python)?\s*|\s*```$", "", text.strip(),
                      flags=re.MULTILINE).strip()
    return text, err


def _inline_md(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
                  r'<a href="\2" target="_blank" rel="noopener">\1</a>', text)
    return text


def markdown_to_html(md: str) -> str:
    """Minimal, safe markdown renderer for generated whitepapers.

    Input is HTML-escaped before inline formatting is applied, so AI (or
    template) content can never inject markup.
    """
    def esc(s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    out, buf, in_list, in_code = [], [], False, False

    def flush():
        if buf:
            # buf holds raw lines — escape exactly once here.
            out.append("<p>" + _inline_md(esc(" ".join(buf))) + "</p>")
            buf.clear()

    for raw in (md or "").splitlines():
        line = raw.rstrip()
        if in_code:
            if line.startswith("```"):
                out.append("</code></pre>")
                in_code = False
            else:
                out.append(esc(raw))
            continue
        if line.startswith("```"):
            flush()
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("<pre><code>")
            in_code = True
            continue
        m = re.match(r"^\s*[-*]\s+(.*)$", line)
        if m:
            flush()
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append("<li>" + _inline_md(esc(m.group(1))) + "</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            flush()
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>" + _inline_md(esc(m.group(2))) + f"</h{lvl}>")
            continue
        if not line.strip():
            flush()
        else:
            buf.append(line)
    flush()
    if in_list:
        out.append("</ul>")
    if in_code:
        out.append("</code></pre>")
    return "\n".join(out)


def template_whitepaper(cve: dict) -> str:
    """Deterministic per-CVE whitepaper (offline base / fallback document)."""
    cid = cve.get("id", "CVE-UNKNOWN")
    sev = (cve.get("severity") or "UNKNOWN").upper()
    refs = cve.get("references") or []
    affected = cve.get("affected") or []
    ref_lines = "\n".join(f"- [{u}]({u})" for u in refs) or "- No references recorded."
    aff_lines = "\n".join(f"- {a}" for a in affected) or (
        "- As reported by NVD for the affected smart-TV family — see the NVD "
        "advisory for the authoritative CPE list.")
    return f"""# {cid} — Smart TV vulnerability brief

**Severity:** {sev} · **CVSS:** {cve.get('score') or 'n/a'} · **Published:** {cve.get('published') or 'unknown'}
**Component:** {cve.get('component') or 'unknown'} · **Fixed in:** {cve.get('fixed_in') or 'see vendor advisory'}
**Attack vector:** {cve.get('exploitability') or cve.get('attack_vector') or 'unknown'} · **CWE:** {', '.join(cve.get('cwe') or []) or 'n/a'}

## Summary

{cve.get('description') or 'No description recorded.'}

## Affected products

{aff_lines}

## Detection (SpyTV)

- Matched during network scans (`/api/scan`) and read-only checks (`/api/check`) for the affected family.
- Signature ports: {', '.join(str(p) for p in (cve.get('ports') or [])) or 'see NVD / vendor advisory'}.
- Dry-run verification confirms exploitability **without transmitting payloads**.

## Remediation

- Upgrade the TV to the vendor-fixed firmware ({cve.get('fixed_in') or 'version per vendor advisory'}).
- Disable unused remote services (ADB/SSH/vendor dev ports) on the management VLAN.
- Use the C2 **Patch** (single device) or **Patch All** (network) button to run the family remediation commands, then re-scan to confirm the signature no longer matches.

## References

{ref_lines}
- [{cve.get('nvd_url')}]({cve.get('nvd_url')})

## Document control

Generated by the SpyTV CVE pipeline for {cid} on {datetime.now(timezone.utc).date().isoformat()} · Authenticated, Inc. · Authorized security assessments only.
"""


def template_signature(cve: dict) -> str:
    """Detection-signature proposal — validated by an assessor, never auto-merged."""
    cid = cve.get("id", "CVE-UNKNOWN")
    ports = ", ".join(str(p) for p in (cve.get("ports") or [])) or "see NVD / vendor advisory"
    ports_repr = repr(cve.get("ports") or [])
    family = cve.get("device_name") or cve.get("component") or "smart TV family"
    return f"""# Detection signature proposal — {cid}

> Proposal only — **not merged** into `core/cve_scanner.py`. An assessor
> reviews and applies validated changes.

## Indicators

- **Family / component:** {family} ({cid})
- **Service ports:** {ports}
- **Attack vector:** {cve.get('attack_vector') or 'unknown'}
- **CWE:** {', '.join(cve.get('cwe') or []) or 'n/a'}

## Suggested family-matching snippet (validate before merging)

```python
# core/cve_scanner.py — candidate match for {cid}
# ("{cid}", {ports_repr}, "{family}"),
```

## Validation checklist

- Confirm the port/fingerprint against a lab device running vulnerable firmware.
- Confirm no false positives against patched firmware of the same family.
- Keep existing family entries and CVE lists stable — additive changes only.
"""


def template_patch_check(cve: dict) -> str:
    """Patch/remediation verification check for the Patch / Patch All flow."""
    cid = cve.get("id", "CVE-UNKNOWN")
    cmds = cve.get("patch_commands") or []
    cmd_lines = "\n".join(f"- `{c}`" for c in cmds) or (
        "- No family commands recorded — vendor firmware update required.")
    return f"""# Patch verification check — {cid}

> Artifact for the C2 **Patch** / **Patch All** flow — review before use.

## Preconditions

- Device reachable on the local network; engagement authorized (signed authorization on file).

## Verification steps

- Apply the family remediation commands (the Patch button runs these):
{cmd_lines}
- Re-run `/api/scan` + `/api/check` for the device IP: the target must **no longer match** {cid}.
- Confirm firmware version is at or above {cve.get('fixed_in') or 'the vendor-fixed release'}.

## Patched looks like

- CVE no longer matched, the exploit dry-run reports not vulnerable, and the device card shows **Patched**.
"""


def template_generated_test(cve_id: str) -> str:
    """Deterministic, offline-safe pytest file for a generated exploit."""
    var = re.sub(r"[^0-9A-Za-z]", "_", cve_id)
    return f'''"""Auto-generated offline test for {cve_id} (T-02 artifact pipeline).

Safe by default: import/structure checks only — no network, no live devices.
"""
import importlib.util
import pathlib

import pytest

MOD_PATH = (pathlib.Path(__file__).resolve().parents[2]
            / "data" / "exploits" / "generated" / "{cve_id}.py")


def _load():
    if not MOD_PATH.exists():
        pytest.skip("exploit module not generated yet")
    spec = importlib.util.spec_from_file_location("exploit_{var}", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_module_imports():
    _load()


def test_public_interface_matches_contract():
    mod = _load()
    assert callable(getattr(mod, "check", None)), "check(ip) is missing"
    assert callable(getattr(mod, "run", None)), "run(ip, params=None) is missing"


def test_metadata_references_the_cve():
    mod = _load()
    cves = getattr(mod, "CVES", None)
    if cves is not None:
        assert "{cve_id}" in cves
    name = getattr(mod, "NAME", None)
    if name is not None:
        assert isinstance(name, str) and name.strip()
'''


def _with_test_header(source: str, cve_id: str) -> str:
    return (f'"""Auto-generated test for {cve_id} '
            f'(AI-assisted, validated by pytest)."""\n') + source.lstrip("\n")


def _pytest_passes(path: Path) -> tuple:
    """Run pytest on a generated test file (offline, sandboxed subprocess).

    Returns ``(passed, tail_of_output)``.
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(path), "-q", "--no-header",
             "-p", "no:cacheprovider"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )
        out = ((proc.stdout or "") + (proc.stderr or ""))[-800:]
        return proc.returncode == 0, out
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _quarantine_exploit(cve_id: str) -> bool:
    """Move an untested exploit module out of the import path (.quarantined)."""
    src = GENERATED_DIR / f"{cve_id}.py"
    if not src.exists():
        return False
    dst = GENERATED_DIR / f"{cve_id}.quarantined"
    try:
        if dst.exists():
            dst.unlink()
        src.rename(dst)
        return True
    except OSError:
        return False


# Proven once per process: the deterministic test template passes without an
# exploit module present (it pytest.skip()s) — avoids a pytest subprocess per
# CVE during large updates.
_template_test_proven = False


def build_artifact_set(cve: dict, provider: str | None = None) -> dict:
    """Generate the full T-02 artifact set for a CVE (T-01 whitepaper first).

    Each artifact is attempted independently — one failure never blocks
    another or the surrounding CVE update. AI drafts are used when a
    provider is configured; deterministic templates are the fallback so
    the artifact set is complete even offline. The generated test must
    **pass pytest** before ``tests_generated`` is set; if it cannot be
    made to pass, the exploit module is quarantined.

    The four ``*_generated`` flags are mirrored onto ``cve`` (the feed
    entry object stored in state).
    """
    global _template_test_proven
    cid = cve.get("id", "CVE-UNKNOWN")
    report = {flag: False for flag in ARTIFACT_FLAGS}
    errors = {}

    def _draft(kind):
        """AI draft when configured, else (None, None) → template path."""
        if not provider:
            return None, None
        try:
            text, err = _ai_artifact(cve, provider, kind)
            return (text, None) if text else (None, err or "empty AI response")
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)

    # 1. Whitepaper (T-01) ---------------------------------------------------
    try:
        text, err = _draft("whitepaper")
        if err:
            errors["whitepaper_ai"] = err
        text = text or template_whitepaper(cve)
        WHITEPAPER_DIR.mkdir(parents=True, exist_ok=True)
        (WHITEPAPER_DIR / f"{cid}.md").write_text(text, encoding="utf-8")
        report["whitepaper_generated"] = True
    except Exception as exc:  # noqa: BLE001
        errors["whitepaper"] = str(exc)

    # 2. Generated pytest test — must PASS before the flag is set ------------
    try:
        GENERATED_TESTS_DIR.mkdir(parents=True, exist_ok=True)
        test_path = GENERATED_TESTS_DIR / f"test_{cid}.py"
        source, ai_err = _draft("test")
        if ai_err:
            errors["test_ai"] = ai_err
        passed, log = False, ""
        if source:
            test_path.write_text(_with_test_header(source, cid),
                                 encoding="utf-8")
            passed, log = _pytest_passes(test_path)
            if not passed:
                errors["test_ai"] = "AI test failed pytest — using template"
        if not passed:
            test_path.write_text(template_generated_test(cid), encoding="utf-8")
            exploit_file = GENERATED_DIR / f"{cid}.py"
            # Template needs a real run when an exploit exists (import is the
            # actual check); without one it is proven once per process.
            if exploit_file.exists() or not _template_test_proven:
                passed, log = _pytest_passes(test_path)
                if passed and not exploit_file.exists():
                    _template_test_proven = True
            else:
                passed = True
        if passed:
            report["tests_generated"] = True
        else:
            errors["test"] = (log or "")[-400:]
            if _quarantine_exploit(cid):
                report["quarantined"] = True
                cve["exploit_generated"] = False
    except Exception as exc:  # noqa: BLE001
        errors["test"] = str(exc)
        if _quarantine_exploit(cid):
            report["quarantined"] = True
            cve["exploit_generated"] = False

    # 3. Detection-signature proposal (validated, never auto-merged) --------
    try:
        text, err = _draft("signature")
        if err:
            errors["signature_ai"] = err
        text = text or template_signature(cve)
        if len(text.strip()) < 80:
            raise ValueError("signature proposal too short")
        SIGNATURE_DIR.mkdir(parents=True, exist_ok=True)
        (SIGNATURE_DIR / f"{cid}.md").write_text(text, encoding="utf-8")
        report["signature_generated"] = True
    except Exception as exc:  # noqa: BLE001
        errors["signature"] = str(exc)

    # 4. Patch/remediation check proposal ------------------------------------
    try:
        text, err = _draft("patch_check")
        if err:
            errors["patch_check_ai"] = err
        text = text or template_patch_check(cve)
        if len(text.strip()) < 60:
            raise ValueError("patch check too short")
        PATCH_CHECK_DIR.mkdir(parents=True, exist_ok=True)
        (PATCH_CHECK_DIR / f"{cid}.md").write_text(text, encoding="utf-8")
        report["patch_check_generated"] = True
    except Exception as exc:  # noqa: BLE001
        errors["patch_check"] = str(exc)

    if errors:
        report["errors"] = errors
    for flag in ARTIFACT_FLAGS:
        cve[flag] = bool(report[flag])
    return report


def artifact_status(cve_id: str) -> dict | None:
    """Artifact inventory for one CVE (files on disk + per-entry flags)."""
    cve = get_cve(cve_id)
    if not cve:
        return None
    files = {
        "whitepaper": WHITEPAPER_DIR / f"{cve_id}.md",
        "test": GENERATED_TESTS_DIR / f"test_{cve_id}.py",
        "signature": SIGNATURE_DIR / f"{cve_id}.md",
        "patch_check": PATCH_CHECK_DIR / f"{cve_id}.md",
        "exploit": GENERATED_DIR / f"{cve_id}.py",
    }

    def _rel(p: Path):
        try:
            return str(p.relative_to(REPO_ROOT))
        except ValueError:
            return str(p)

    return {
        "id": cve_id,
        "flags": {f: bool(cve.get(f)) for f in ARTIFACT_FLAGS},
        "exploit_generated": bool(cve.get("exploit_generated")),
        "files": {name: {"path": _rel(p), "exists": p.exists()}
                  for name, p in files.items()},
        "enrichment": {k: cve.get(k)
                       for k in ("cwe", "affected", "fixed_in", "attack_vector",
                                 "exploitability")},
    }


def get_whitepaper_markdown(cve_id: str):
    """``(markdown, source)`` — generated file when present, template otherwise."""
    cve = get_cve(cve_id)
    if not cve:
        return None
    path = WHITEPAPER_DIR / f"{cve_id}.md"
    if path.exists():
        try:
            return path.read_text(encoding="utf-8"), "file"
        except OSError:
            pass
    return template_whitepaper(cve), "template"


# ---------------------------------------------------------------------------
# NVD fetching / parsing
# ---------------------------------------------------------------------------
def fetch_nvd_cves(days: int = 30, api_key: str | None = None):
    """Fetch recent smart-TV CVEs from the NVD 2.0 API."""
    start = datetime.now(timezone.utc) - timedelta(days=days)
    end = datetime.now(timezone.utc)
    results = []
    delay = 6 if not api_key else 1  # NVD anonymous rate limit
    for i, keyword in enumerate(NVD_KEYWORDS):
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 2000,
        }
        url = NVD_API_URL + "?" + urllib.parse.urlencode(params)
        headers = {"User-Agent": "SpyTV-CVE-Monitor/1.0"}
        if api_key:
            headers["apiKey"] = api_key
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                if cve.get("id"):
                    results.append(cve)
        except Exception as exc:  # noqa: BLE001
            print(f"[CVE] error fetching '{keyword}': {exc}")
        if i < len(NVD_KEYWORDS) - 1:
            time.sleep(delay)
    return results


def parse_nvd_cve(nvd_cve: dict) -> dict:
    """Normalize an NVD CVE document into a feed entry (with T-02
    enrichment: CWE, affected products, fixed version, attack vector)."""
    cve_id = nvd_cve.get("id", "")
    description = ""
    for desc in nvd_cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    severity, score, cvss_data = None, None, {}
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = nvd_cve.get("metrics", {}).get(metric_key, [])
        if metrics:
            data = metrics[0].get("cvssData", {})
            severity = data.get("baseSeverity") or metrics[0].get("baseSeverity")
            score = data.get("baseScore")
            cvss_data = data
            break

    references = [r.get("url", "") for r in nvd_cve.get("references", [])
                  if r.get("url")]

    # Enrichment — CWE ids from the weaknesses array.
    cwes, seen = [], set()
    for weak in nvd_cve.get("weaknesses", []):
        for entry in weak.get("description", []):
            value = entry.get("value")
            if value and value.startswith("CWE-") and value not in seen:
                seen.add(value)
                cwes.append(value)

    # Enrichment — affected products from the CPE configurations.
    affected = []
    for cfg in nvd_cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                crit = match.get("criteria") or match.get("cpe23Uri")
                if crit and crit not in affected:
                    affected.append(crit)

    # Enrichment — fixed version from the description ("fixed in 4.2.1").
    fixed_in = None
    m = re.search(r"fixed in(?: version)? ([0-9][0-9A-Za-z._+-]*)",
                  description, re.IGNORECASE)
    if m:
        fixed_in = m.group(1)

    # Enrichment — exploitability note for the dashboard card.
    attack_vector = cvss_data.get("attackVector")
    av_label = {"NETWORK": "Network-reachable",
                "ADJACENT_NETWORK": "Adjacent-network",
                "LOCAL": "Local", "PHYSICAL": "Physical"}.get(attack_vector)
    exploitability = av_label or "Unknown"
    if cvss_data.get("userInteraction") == "NONE":
        exploitability += " · no user interaction required"

    return {
        "id": cve_id,
        "description": description[:600],
        "severity": severity or "UNKNOWN",
        "score": score,
        "published": nvd_cve.get("published"),
        "references": references[:8],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        # Per-CVE whitepaper served by the C2 (rendered brief).
        "whitepaper_url": f"/api/cve/whitepaper/{cve_id}",
        "exploit_generated": False,
        # T-02 enrichment
        "cwe": cwes[:5],
        "affected": affected[:8],
        "fixed_in": fixed_in,
        "attack_vector": attack_vector,
        "exploitability": exploitability,
        # T-02 artifact flags (set by build_artifact_set)
        "whitepaper_generated": False,
        "tests_generated": False,
        "signature_generated": False,
        "patch_check_generated": False,
        "source": "nvd",
    }


# ---------------------------------------------------------------------------
# State / logging
# ---------------------------------------------------------------------------
def load_state() -> dict:
    if CVE_STATE_FILE.exists():
        try:
            state = json.loads(CVE_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(state.get("known_cves"), dict):
                return state
        except (json.JSONDecodeError, OSError):
            pass
    return {"known_cves": {}, "last_update": None, "new_count": 0}


def save_state(state: dict):
    CVE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state["last_update"] = datetime.now(timezone.utc).isoformat()
    CVE_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def log_cve_update(new_cves: list, generated: list | None = None,
                   artifacts: dict | None = None):
    """Append new-CVE entries to CVE_UPDATES.log in the repository root.

    ``artifacts`` maps CVE id → the report returned by
    :func:`build_artifact_set`; one ``artifacts`` event per CVE records
    every per-artifact status (T-02: all statuses land in the root log).
    """
    generated = generated or []
    artifacts = artifacts or {}
    quarantined = [cid for cid, r in artifacts.items() if r.get("quarantined")]
    try:
        CVE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CVE_LOG_FILE, "a", encoding="utf-8") as fh:
            for cve in new_cves:
                entry = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "event": "new_cve",
                    "id": cve["id"],
                    "severity": cve.get("severity"),
                    "score": cve.get("score"),
                    "description": (cve.get("description") or "")[:200],
                    "nvd_url": cve.get("nvd_url"),
                    "whitepaper": cve.get("whitepaper_url"),
                    "exploit_generated": cve["id"] in generated,
                }
                fh.write(json.dumps(entry) + "\n")
            for cid, report in artifacts.items():
                fh.write(json.dumps({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "event": "artifacts",
                    "id": cid,
                    "whitepaper_generated": bool(report.get("whitepaper_generated")),
                    "tests_generated": bool(report.get("tests_generated")),
                    "signature_generated": bool(report.get("signature_generated")),
                    "patch_check_generated": bool(report.get("patch_check_generated")),
                    "quarantined": bool(report.get("quarantined")),
                    "errors": report.get("errors") or None,
                }) + "\n")
            if new_cves:
                fh.write(json.dumps({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "event": "update_summary",
                    "new": len(new_cves),
                    "generated": len(generated),
                    "artifacts": len(artifacts),
                    "quarantined": quarantined or None,
                }) + "\n")
    except OSError as exc:
        print(f"[CVE] could not write update log: {exc}")


def import_root_log(state: dict) -> list:
    """Replay root CVE_UPDATES.log entries that are missing from state.

    This is how log lines recorded outside the C2 get added to the feed.
    """
    imported = []
    if not CVE_LOG_FILE.exists():
        return imported
    try:
        for line in CVE_LOG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("event") != "new_cve":
                continue
            cid = entry.get("id")
            if not cid or cid in state["known_cves"]:
                continue
            state["known_cves"][cid] = {
                "id": cid,
                "description": entry.get("description", ""),
                "severity": entry.get("severity") or "UNKNOWN",
                "score": entry.get("score"),
                "published": entry.get("ts"),
                "references": [],
                "nvd_url": entry.get("nvd_url")
                           or f"https://nvd.nist.gov/vuln/detail/{cid}",
                "whitepaper_url": entry.get("whitepaper")
                                  or f"/api/cve/whitepaper/{cid}",
                "exploit_generated": bool(entry.get("exploit_generated")),
                "source": "log",
            }
            imported.append(cid)
    except OSError:
        pass
    return imported


# ---------------------------------------------------------------------------
# Public update API
# ---------------------------------------------------------------------------
def update_cve_database(api_key: str | None = None, days: int = 30,
                        auto_generate: bool = True) -> list:
    """Fetch new CVEs, log them to the root file, auto-generate exploits.

    Returns the list of NEW feed entries (empty if nothing new).
    """
    state = load_state()
    new_cves = []

    # 1. Replay anything already logged at the repo root.
    imported_ids = set(import_root_log(state))
    for cid in imported_ids:
        new_cves.append(state["known_cves"][cid])

    # 2. Fetch from NVD (unless offline / disabled).
    if os.environ.get("CVE_OFFLINE", "").lower() not in ("1", "true", "yes"):
        api_key = api_key or load_env_file().get("NVD_API_KEY") \
            or os.environ.get("NVD_API_KEY")
        try:
            nvd_cves = fetch_nvd_cves(days, api_key)
        except Exception as exc:  # noqa: BLE001
            print(f"[CVE] NVD fetch failed: {exc}")
            nvd_cves = []
        for nvd_cve in nvd_cves:
            cve = parse_nvd_cve(nvd_cve)
            if cve["id"] and cve["id"] not in state["known_cves"]:
                new_cves.append(cve)
                state["known_cves"][cve["id"]] = cve

    # 3. Auto-generate an exploit for each new CVE when a key is configured.
    generated = []
    provider = first_configured_provider()
    if auto_generate and new_cves and provider:
        for cve in new_cves:
            code, err = generate_exploit_with_ai(cve, provider)
            if code:
                cve["exploit_generated"] = True
                state["known_cves"][cve["id"]]["exploit_generated"] = True
                generated.append(cve["id"])
                print(f"[CVE] generated exploit for {cve['id']} "
                      f"via {provider}")
            else:
                print(f"[CVE] exploit generation failed for "
                      f"{cve['id']}: {err}")
    elif auto_generate and new_cves:
        print("[CVE] no AI provider key configured — skipping auto "
              "exploit generation (add keys via run_c2.bat or the dashboard)")

    # 3b. Full artifact set per new CVE (T-01 whitepaper + T-02 test/
    #     signature/patch-check/enrichment). Each artifact and each CVE is
    #     isolated: a partial failure never aborts the update run.
    artifacts = {}
    for cve in new_cves:
        try:
            report = build_artifact_set(cve, provider if auto_generate else None)
        except Exception as exc:  # noqa: BLE001 — keep the run alive
            report = {flag: False for flag in ARTIFACT_FLAGS}
            report["errors"] = {"pipeline": str(exc)}
            for flag in ARTIFACT_FLAGS:
                cve[flag] = False
            print(f"[CVE] artifact pipeline failed for {cve.get('id')}: {exc}")
        artifacts[cve.get("id", "CVE-UNKNOWN")] = report
        if report.get("quarantined"):
            cve["exploit_generated"] = False
            if cve["id"] in generated:
                generated.remove(cve["id"])
            print(f"[CVE] quarantined exploit for {cve['id']} "
                  f"(generated test did not pass)")
        # new_cves entries are the same objects stored in known_cves —
        # mirror flags anyway in case a caller passed a detached dict.
        entry = state["known_cves"].get(cve.get("id"))
        if entry is not None and entry is not cve:
            for flag in ARTIFACT_FLAGS:
                entry[flag] = cve.get(flag, False)
            entry["exploit_generated"] = bool(cve.get("exploit_generated"))

    state["new_count"] = len(new_cves)
    save_state(state)
    log_cve_update(new_cves, generated, artifacts)
    return new_cves


def get_feed(limit: int = 0) -> dict:
    """Full feed payload for the dashboard sidebar."""
    state = load_state()
    entries = sorted(
        state.get("known_cves", {}).values(),
        key=lambda e: e.get("published") or e.get("ts") or "",
        reverse=True,
    )
    if limit:
        entries = entries[:limit]
    return {
        "cves": entries,
        "count": len(state.get("known_cves", {})),
        "new_count": state.get("new_count", 0),
        "last_update": state.get("last_update"),
        "log_file": str(CVE_LOG_FILE.name),
        "ai": ai_key_status(),
    }


def get_all_cves() -> list:
    """All known CVE feed entries (newest first)."""
    return get_feed()["cves"]


def get_cve(cve_id: str) -> dict | None:
    return load_state().get("known_cves", {}).get(cve_id)


def render_cve_whitepaper(cve_id: str) -> str | None:
    """Render a per-CVE whitepaper (HTML) from stored feed data.

    Prefers the generated markdown document in ``docs/whitepapers/`` when
    one exists (T-01); falls back to the structured feed-data brief.
    """
    cve = get_cve(cve_id)
    if not cve:
        return None
    refs = "".join(
        f'<li><a href="{u}" target="_blank" rel="noopener">{u}</a></li>'
        for u in cve.get("references", [])
    ) or "<li>No references recorded.</li>"
    score = cve.get("score")
    sev = (cve.get("severity") or "UNKNOWN").upper()
    sev_color = {"CRITICAL": "#EF4444", "HIGH": "#F59E0B",
                 "MEDIUM": "#3B82F6", "LOW": "#10B981"}.get(sev, "#6B7280")
    esc = lambda s: (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # T-01: prefer the generated document (AI-assisted or template) when it
    # is on disk; it carries the full section structure.
    doc_path = WHITEPAPER_DIR / f"{cve_id}.md"
    if doc_path.exists():
        try:
            body = (f'<div class="card"><h2 style="margin-top:0">'
                    f'Generated whitepaper</h2>'
                    f'{markdown_to_html(doc_path.read_text(encoding="utf-8"))}</div>')
        except OSError:
            body = None
    else:
        body = None
    if body is None:
        body = f"""<div class="card"><h2 style="margin-top:0">Description</h2>
<p>{esc(cve.get('description'))}</p></div>
<div class="card"><h2 style="margin-top:0">References</h2><ul>{refs}</ul></div>
<div class="card"><h2 style="margin-top:0">Remediation</h2>
<p>Patch the affected TV to the vendor-fixed firmware, disable unused remote
services (ADB/SSH/dev ports), and re-run the SpyTV network scan to confirm the
device no longer matches the vulnerable signature. The C2 <b>Patch</b> button
applies the remediation commands for the matched device family.</p></div>"""
    artifacts = artifact_status(cve_id) or {}
    flags = artifacts.get("flags", {})
    flag_line = " · ".join(
        f"{k.replace('_generated', '')}: "
        f"{'&#10003;' if flags.get(k) else '&#8212;'}"
        for k in ARTIFACT_FLAGS
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(cve_id)} — SpyTV Whitepaper</title>
<style>
 body {{ background:#0B0E14; color:#F3F4F6; font-family:-apple-system,'Segoe UI',Roboto,sans-serif;
        max-width:860px; margin:0 auto; padding:32px; line-height:1.6; }}
 h1 {{ font-size:22px; }} h2 {{ font-size:15px; color:#9CA3AF; margin-top:28px; }}
 h3 {{ font-size:14px; color:#D1D5DB; margin-top:20px; }}
 a {{ color:#3B82F6; }} .badge {{ display:inline-block; padding:3px 10px; border-radius:12px;
        font-size:12px; font-weight:700; background:{sev_color}22; color:{sev_color};
        border:1px solid {sev_color}; }}
 .meta {{ color:#9CA3AF; font-size:13px; }}
 .card {{ background:#151B27; border:1px solid #1F2937; border-radius:12px; padding:20px; margin:16px 0; }}
 ul {{ padding-left:20px; }} .back {{ font-size:13px; }}
 pre {{ background:#0B0E14; border:1px solid #1F2937; border-radius:8px; padding:12px;
        overflow-x:auto; font-size:12px; }}
 code {{ color:#93C5FD; }}
</style></head><body>
<p class="back"><a href="/">&#8592; Back to C2 Dashboard</a></p>
<h1>{esc(cve_id)} <span class="badge">{esc(sev)}{f" · {score}" if score else ""}</span></h1>
<p class="meta">Published: {esc(cve.get('published') or 'unknown')} &middot;
Fixed in: {esc(cve.get('fixed_in') or 'see vendor advisory')} &middot;
CWE: {esc(', '.join(cve.get('cwe') or []) or 'n/a')} &middot;
Source: <a href="{esc(cve.get('nvd_url'))}" target="_blank">NVD entry</a></p>
{body}
<div class="card"><h2 style="margin-top:0">References</h2><ul>{refs}</ul></div>
<div class="card"><h2 style="margin-top:0">Assessment status</h2>
<p>Exploit module generated: {"yes" if cve.get("exploit_generated") else "no"}</p>
<p>Artifacts — {flag_line}</p></div>
</body></html>"""
