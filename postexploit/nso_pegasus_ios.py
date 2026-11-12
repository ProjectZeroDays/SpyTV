"""NSO Pegasus / iOS Forced Entry — real capability references only (authorized).
Functional names: forced_entry, ios_zero_click, pegasus_ref.
References real NSO Pegasus capabilities (zero-click, Trident, forced entry via link) without simulating exploits."""
from __future__ import annotations
from datetime import datetime

IOS_EXPLOIT_REFS = {
    "pegasus": {"name":"NSO Pegasus Reference","desc":"Real zero-click mobile exploit framework reference","url":"https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/","category":"zero_click"},
    "trident": {"name":"Trident (iOS zero-day chain)","desc":"Real iOS exploit chain reference (CVE-2016-4657 / etc.)","url":"https://googleprojectzero.blogspot.com/2016/08/three-months-to-go.html","category":"zero_day"},
    "forced_entry": {"name":"Forced Entry Reference","desc":"Real forced-entry / jailbreak capability reference","url":"https://github.com/projectzero/iOS-security-research","category":"forced_entry"},
    "new_ios": {"name":"Recent iOS Exploit References","desc":"Latest iOS vulnerability research references","url":"https://support.apple.com/en-us/security-updates","category":"reference"},
}

def nso_pegasus_dashboard_state():
    return {
        "function_name": "nso_pegasus_ios",
        "compatible_target": "Compromised iOS device / target for authorized security assessment",
        "hardware_connected": False,
        "status_note": "Real capability references only; actual zero-click/forced entry requires real exploits and authorization",
        "capabilities": IOS_EXPLOIT_REFS,
        "updated": datetime.now().isoformat(),
    }

def forced_entry_config(device_type="ios", method="zero_click"):
    return {"action":"forced_entry_config","device_type":device_type,"method":method,"note":"Real reference only — requires authorization and real exploit","updated":datetime.now().isoformat()}
