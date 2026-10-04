#!/usr/bin/env python3
import subprocess
import sys
import os
import argparse
from core.utils import logger

def tizen_clean(ip):
    logger.info(f"Cleaning Tizen implant on {ip}...")
    subprocess.run(["sdb", "-s", f"{ip}:26101", "uninstall", "tvinfo"], capture_output=True)

def webos_clean(ip):
    logger.info(f"Cleaning WebOS implant on {ip}...")
    subprocess.run(["ares-remove", "--device", f"tv@{ip}", "com.forge.tvreaper"], capture_output=True)

def android_clean(ip):
    logger.info(f"Cleaning Android implant on {ip}...")
    subprocess.run(["adb", "-s", f"{ip}:5555", "uninstall", "com.forge.tvreaper"], capture_output=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--family", required=True, choices=["tizen","webos","android"])
    parser.add_argument("--ip", required=True)
    args = parser.parse_args()

    if args.family == "tizen": tizen_clean(args.ip)
    elif args.family == "webos": webos_clean(args.ip)
    elif args.family == "android": android_clean(args.ip)
