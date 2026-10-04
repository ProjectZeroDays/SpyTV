#!/usr/bin/env python3
import json
import base64
import logging
import os

# Logging Config
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join("logs", "spytv.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def b32encode(data_bytes):
    """Base32 encode for DNS exfil."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    bits = 0
    value = 0
    output = ""

    for b in data_bytes:
        value = (value << 8) | b
        bits += 8
        while bits >= 5:
            output += alphabet[(value >> (bits - 5)) & 31]
            bits -= 5
    if bits > 0:
        output += alphabet[(value << (5 - bits)) & 31]
    return output

def log_json(data):
    logger.info(json.dumps(data, indent=2))

# CR-52 fix: Define print_banner here so it can be imported
def print_banner():
    print("""
    ================================================
                  SpyTV: THE TELEVISION OMNI-EXPLOIT FRAMEWORK
                (Fused Solution: Your Setup + TVREAPER Capability)
    ================================================
    """)
