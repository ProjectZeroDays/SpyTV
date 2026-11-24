"""Deterministic JSON export for scan findings.

Same input → same bytes: findings are normalized (MACs uppercased, keys
sorted, addresses in numeric order) and no wall-clock time is embedded
unless the caller passes one. That makes exports diffable across runs and
safe to commit as scan artifacts.
"""
import json


def export_findings_json(findings, generated_at=None):
    """Canonical JSON string for a list of findings (or scan-history items)."""
    normalized = []
    for f in findings or []:
        item = dict(f)
        mac = item.get("mac")
        if isinstance(mac, str):
            item["mac"] = mac.upper()
        normalized.append(item)

    def _key(r):
        try:
            return tuple(int(p) for p in str(r.get("ip", "")).split("."))
        except (AttributeError, ValueError):
            return ()

    normalized.sort(key=_key)
    payload = {
        "generator": "SpyTV-C2 scan export",
        "format_version": 1,
        "generated_at": generated_at,
        "finding_count": len(normalized),
        "findings": normalized,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
