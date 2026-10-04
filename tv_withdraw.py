#!/usr/bin/env python3
"""TVREAPER v2 withdrawal: uninstall per family."""
import subprocess, sys, argparse

def tizen_clean(ip):
    subprocess.run(["sdb","-s",f"{ip}:26101","uninstall","tvinfo"],
                   capture_output=True, timeout=60); print("tizen_clean",ip)

def webos_clean(ip):
    subprocess.run(["ares-remove","--device",f"tv@{ip}",
                    "com.forge.tvreaper"],capture_output=True,timeout=60)
    print("webos_clean",ip)

def orsay_clean(ip):
    print("Reverse-sync removal at next maintenance-window USB visit.")

def hisense_clean(ip):
    subprocess.run(["adb","-s",f"{ip}:56789","uninstall","com.forge.tvreaper"],
                   capture_output=True, timeout=60); print("hisense_clean",ip)

def androidtv_clean(ip):
    subprocess.run(["adb","-s",f"{ip}:5555","uninstall","com.forge.tvreaper"],
                   capture_output=True, timeout=60); print("androidtv_clean",ip)

def nettv_clean(ip):
    print("Philips NetTV cleaning = remove the history from stored-page "
          "registry via Jointspace API.")

def vizio_clean(ip):
    print("Vizio cleaning: cast-registry self-purges; no on-disk artifact.")

def hbbtv_clean(ip):
    print("HbbTV payload purges on tune-out; no on-disk artifact.")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--family",required=True,
        choices=["tizen","webos","orsay","hisense","androidtv",
                 "nettv","vizio","hbbtv"])
    p.add_argument("--ip",required=True)
    a=p.parse_args()
    {"tizen":lambda:tizen_clean(a.ip),"webos":lambda:webos_clean(a.ip),
     "orsay":lambda:orsay_clean(a.ip),"hisense":lambda:hisense_clean(a.ip),
     "androidtv":lambda:androidtv_clean(a.ip),"nettv":lambda:nettv_clean(a.ip),
     "vizio":lambda:vizio_clean(a.ip),"hbbtv":lambda:hbbtv_clean(a.ip)}[a.family]()
