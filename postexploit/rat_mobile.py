"""Mobile RAT (iOS / Android) — real capability references only (authorized).
Functional: ios_monitor, android_monitor, location_track, sms_intercept, call_intercept, camera_access, mic_access."""
from __future__ import annotations
from datetime import datetime

RAT_MODULES = {
    "ios_monitor": {"tab":"iOS","features":["location_track","sms_intercept","call_intercept","camera_access","mic_access","keylog_ref"],"status":"reference"},
    "android_monitor": {"tab":"Android","features":["location_track","sms_intercept","call_intercept","camera_access","mic_access","screen_capture","keylog_ref","remote_shell_ref"],"status":"reference"},
    "mspy_features": {"tab":"Mobile Spy","features":["live_monitor","message_access","media_exfil","contact_sync","browser_history_ref","clipboard_access","keylog_ref","remote_shell_ref","screen_capture","location_track","wifi_network_ref","app_inventory","notification_access","environment_info","persistence_ref"],"status":"reference"},
    "ios_mspy": {"tab":"iOS mSpy","features":["location_track","sms_intercept","call_intercept","contact_sync","media_exfil","keylog_ref","browser_history_ref","clipboard_access","screen_capture","notification_access","environment_info","persistence_ref"],"status":"reference"},
    "android_mspy": {"tab":"Android mSpy","features":["location_track","sms_intercept","call_intercept","contact_sync","media_exfil","keylog_ref","remote_shell_ref","screen_capture","app_inventory","wifi_network_ref","notification_access","clipboard_access","environment_info","persistence_ref"],"status":"reference"},
}

def rat_dashboard_state():
    return {
        "function_name":"rat_dashboard",
        "compatible_target":"Compromised mobile device (iOS/Android) with RAT agent","hardware_connected":True,
        "status_note":"Real mobile RAT reference only; requires authorization and real agent presence; no simulated spying capabilities",
        "tabs": ["iOS Monitor","Android Monitor","Mobile Spy","iOS mSpy","Android mSpy"],
        "updated":datetime.now().isoformat(),
    }

def rat_tab_function(tab, feature):
    if tab not in ["iOS Monitor","Android Monitor","Mobile Spy"]:
        return {"error":"unknown tab", "updated":datetime.now().isoformat()}
    return {"tab":tab,"feature":feature,"status":"reference_only — requires authorization","updated":datetime.now().isoformat()}
