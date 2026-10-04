"""SpyTV universal JavaScript implant — Python accessor for ``tvreaper.js``.

This module previously held a stale markdown-wrapped copy of an older
implant snippet (invalid Python, port drift vs. the live implant). The
canonical implant source now lives in one place only: ``tvreaper.js`` in
the repository root (TVREAPER v2 — Tizen, WebOS, Android TV, HbbTV,
Philips NetTV). This module exposes that file to Python tooling so the
payload can be embedded or served without duplicating the source.
"""
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPLANT_JS_PATH = os.path.join(_REPO_ROOT, "tvreaper.js")


def get_implant_js():
    """Return the full source of the universal TV implant (tvreaper.js)."""
    with open(IMPLANT_JS_PATH, "r", encoding="utf-8") as f:
        return f.read()


def implant_path():
    """Return the absolute path to the implant source file."""
    return IMPLANT_JS_PATH


if __name__ == "__main__":
    src = get_implant_js()
    print(f"SpyTV implant: {IMPLANT_JS_PATH} ({len(src)} bytes)")
