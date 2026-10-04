"""Shared helpers for the SpyTV defensive toolkit (stdlib only, no dependencies)."""
from __future__ import annotations

import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "output"
CONFIG_DIR = REPO_ROOT / "config"

LOG = logging.getLogger("spydefense")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def setup_logging(verbose: bool = False, log_file: Path | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        handlers=handlers,
    )


def load_json(path: Path) -> object:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        LOG.error("Config file not found: %s (copy the matching .example file from config/)", path)
        raise


def write_markdown(path: Path, title: str, sections: list[tuple[str, str]]) -> Path:
    """Write a titled markdown report made of (heading, body) sections."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# {title}",
        "",
        f"_Generated {utc_now_iso()} by the SpyTV defensive toolkit._",
        "",
    ]
    for heading, body in sections:
        lines += [f"## {heading}", "", body.rstrip(), ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    LOG.info("Report written: %s", path)
    return path


def run_or_preview(cmd: list[str], apply: bool, note: str = "") -> bool:
    """Preview a state-changing shell command; execute it only when apply=True.

    Every state-changing helper in this toolkit routes through here so that a
    default run can never alter the host.
    """
    printable = " ".join(cmd)
    if note:
        LOG.info("[%s] %s", "APPLY" if apply else "DRY-RUN", note)
    if not apply:
        LOG.info("[DRY-RUN] %s", printable)
        return True
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        LOG.error("Command failed to run: %s (%s)", printable, exc)
        return False
    if proc.stdout.strip():
        LOG.info("[stdout] %s", proc.stdout.strip()[:400])
    if proc.returncode != 0:
        LOG.error("Command failed (rc=%d): %s\n%s", proc.returncode, printable, proc.stderr.strip()[:400])
        return False
    LOG.info("[APPLIED] %s", printable)
    return True
