#!/usr/bin/env python3
"""CVE Feed Manager — Fetches, stores, and serves CVE data for Smart TVs.

Responsibilities:
  * Fetch new smart-TV CVEs from the NVD 2.0 API (rate-limit aware).
  * Persist known CVEs in ``c2_data/cve_state.json``.
  * Append every update to ``CVE_UPDATES.log`` in the repository ROOT so the
    entries can be replayed into the C2 feed.
  * Auto-generate an exploit module for each NEW CVE when an AI provider
    key is configured (OpenRouter / Venice AI / Abliteration.ai).
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
import time
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
        },
        "model_labels": {
            "uncensored": "Uncensored",
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


def ai_key_status() -> dict:
    """Masked status of each provider (for the dashboard)."""
    keys = load_ai_keys()
    status = {}
    for pid, prov in AI_PROVIDERS.items():
        key = keys.get(pid, "")
        status[pid] = {
            "name": prov["name"],
            "configured": bool(key),
            "masked": (key[:4] + "…" + key[-4:]) if len(key) > 8 else ("••••" if key else ""),
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
        if keys.get(pid):
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
    if not provider or not keys.get(provider):
        return None, "No AI provider API key configured (see AI Provider Keys)"
    prov = AI_PROVIDERS.get(provider)
    if not prov:
        return None, f"Unknown provider: {provider}"
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
        "Authorization": f"Bearer {keys[provider]}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/authenticated-inc/spytv",
        "X-Title": "SpyTV CVE Exploit Generator",
    }
    try:
        req = urllib.request.Request(
            prov["endpoint"],
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
    """Generate + save an exploit for a CVE already in the state database."""
    state = load_state()
    cve = state.get("known_cves", {}).get(cve_id)
    if not cve:
        return None, "CVE not found in database"
    return generate_exploit_with_ai(cve, provider, model)


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
    """Normalize an NVD CVE document into a feed entry."""
    cve_id = nvd_cve.get("id", "")
    description = ""
    for desc in nvd_cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    severity, score = None, None
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = nvd_cve.get("metrics", {}).get(metric_key, [])
        if metrics:
            data = metrics[0].get("cvssData", {})
            severity = data.get("baseSeverity")
            score = data.get("baseScore")
            break

    references = [r.get("url", "") for r in nvd_cve.get("references", [])
                  if r.get("url")]
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


def log_cve_update(new_cves: list, generated: list | None = None):
    """Append new-CVE entries to CVE_UPDATES.log in the repository root."""
    generated = generated or []
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
            if new_cves:
                fh.write(json.dumps({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "event": "update_summary",
                    "new": len(new_cves),
                    "generated": len(generated),
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

    state["new_count"] = len(new_cves)
    save_state(state)
    log_cve_update(new_cves, generated)
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
    """Render a per-CVE whitepaper (HTML) from stored feed data."""
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
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(cve_id)} — SpyTV Whitepaper</title>
<style>
 body {{ background:#0B0E14; color:#F3F4F6; font-family:-apple-system,'Segoe UI',Roboto,sans-serif;
        max-width:860px; margin:0 auto; padding:32px; line-height:1.6; }}
 h1 {{ font-size:22px; }} h2 {{ font-size:15px; color:#9CA3AF; margin-top:28px; }}
 a {{ color:#3B82F6; }} .badge {{ display:inline-block; padding:3px 10px; border-radius:12px;
        font-size:12px; font-weight:700; background:{sev_color}22; color:{sev_color};
        border:1px solid {sev_color}; }}
 .meta {{ color:#9CA3AF; font-size:13px; }}
 .card {{ background:#151B27; border:1px solid #1F2937; border-radius:12px; padding:20px; margin:16px 0; }}
 ul {{ padding-left:20px; }} .back {{ font-size:13px; }}
</style></head><body>
<p class="back"><a href="/">&#8592; Back to C2 Dashboard</a></p>
<h1>{esc(cve_id)} <span class="badge">{esc(sev)}{f" · {score}" if score else ""}</span></h1>
<p class="meta">Published: {esc(cve.get('published') or 'unknown')} &middot;
Source: <a href="{esc(cve.get('nvd_url'))}" target="_blank">NVD entry</a></p>
<div class="card"><h2 style="margin-top:0">Description</h2>
<p>{esc(cve.get('description'))}</p></div>
<div class="card"><h2 style="margin-top:0">References</h2><ul>{refs}</ul></div>
<div class="card"><h2 style="margin-top:0">Remediation</h2>
<p>Patch the affected TV to the vendor-fixed firmware, disable unused remote
services (ADB/SSH/dev ports), and re-run the SpyTV network scan to confirm the
device no longer matches the vulnerable signature. The C2 <b>Patch</b> button
applies the remediation commands for the matched device family.</p></div>
<div class="card"><h2 style="margin-top:0">Assessment status</h2>
<p>Exploit module generated: {"yes" if cve.get("exploit_generated") else "no"}</p></div>
</body></html>"""
