#!/usr/bin/env python3
"""Tags each C4-received clip into the intelligence capture-table.
Runs on FORGE after transcription. Output: one JSON row per clip."""
import os, json, datetime, hashlib, logging

STORE = os.environ.get("TV_FLOW_STORE", os.path.join("logs", "tv_flow"))
TABLE = os.path.join(STORE, "capture_table.jsonl")

# mission keyword sets (set per-op by NS-INTEL)
KEYWORDS = {
    "contract": ["pricing", "deliverable", "quarter", "board"],
    "names": ["Meridian", "Helios"],
}

# CR-51 fix: Define the missing functions
def count_speakers(transcript):
    """Simple diarization-light: estimate speaker count from transcript."""
    # In production, this would use actual diarization
    # For now, estimate based on paragraph breaks and length
    lines = [l for l in transcript.split('\n') if l.strip()]
    return max(1, len(lines) // 10)

def speech_ratio(transcript):
    """Estimate ratio of speech to silence in the clip."""
    # In production, this would use VAD
    # For now, estimate based on word count
    words = transcript.split()
    return min(1.0, len(words) / 500.0)

def tv_from_path(path):
    """Map file path to TV identity."""
    # Extract date and time from path structure: .../audio/YYYYMMDD/HHMMSS_name.wav
    parts = path.replace('\\', '/').split('/')
    if len(parts) >= 3:
        date = parts[-2] if len(parts[-2]) == 8 else "unknown"
        return f"TV-{date}"
    return "unknown"

def tag_clip(path, transcript, kind):
    words = transcript.lower().split()
    tags = [k for k, ks in KEYWORDS.items()
            if any(kw in words for kw in ks)]
    speakers = count_speakers(transcript)
    rec = {
        "id": hashlib.sha1(open(path,'rb').read()[:4096]).hexdigest()[:12],
        # CR-51 fix: Use utcnow() instead of deprecated utcfromtimestamp
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "tv": tv_from_path(path),
        "kind": kind,
        "speakers": speakers,
        "seconds_speech": speech_ratio(transcript),
        "keywords": tags,
        "flag": "REVIEW" if tags or speakers >= 2 else "routine",
        "transcript": transcript if tags else None,
    }
    with open(TABLE, "a") as f: f.write(json.dumps(rec) + "\n")
    if rec["flag"] == "REVIEW":
        logging.info(f"REVIEW clip {rec['id']} kw={tags} spk={speakers}")
