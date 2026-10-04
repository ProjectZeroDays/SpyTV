#!/usr/bin/env python3
import os, json, shutil, subprocess, argparse, sys, zipfile

TVREAPER_JS = "tvreaper.js"

WGT = {
 "config.xml": """<?xml version="1.0" encoding="UTF-8"?>
<widget xmlns="http://www.samsungdforum.com/Banner/widget"
        xmlns:tizen="http://tizen.org/ns/widgets">
 <cpname>FORGE</cpname>
 <type>user</type>
 <category>video</category>
 <fullwidget>y</fullwidget>
 <srcctl enabled="no"/>
 <ThumbIcon>icon.png</ThumbIcon>
 <name>tvinfo</name>
 <author>Forge Labs</author>
 <tizen:privilege name="http://tizen.org/privilege/internet"/>
 <tizen:privilege name="http://tizen.org/privilege/mediacapture"/>
 <feature name="http://tizen.org/feature/microphone"/>
 <feature name="http://tizen.org/feature/camera"/>
</widget>""",
 "index.html": f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<script src="{TVREAPER_JS}"></script></head>
<body style="background:transparent"></body></html>"""
}

IPK = {
 "appinfo.json": json.dumps({"id":"com.forge.tvreaper","version":"2.0.0",
  "type":"web","main":"index.html","title":"TV Info","icon":"icon.png"}),
 "index.html": WGT["index.html"]
}

APK = {
 "AndroidManifest.xml": """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.forge.tvreaper" versionCode="2" versionName="2.0">
 <uses-permission android:name="android.permission.INTERNET"/>
 <uses-permission android:name="android.permission.RECORD_AUDIO"/>
 <uses-permission android:name="android.permission.CAMERA"/>
 <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
 <application android:label="TV Info" android:icon="@drawable/icon">
  <activity android:name=".Main" android:exported="true">
   <intent-filter><action android:name="android.intent.action.MAIN"/>
   <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
  </activity>
  <service android:name=".Capture" android:exported="false"/>
 </application></manifest>"""
}

def build_wgt():
    print("Building Tizen/Orsay Widget (.wgt)...")
    tmp="wgt";shutil.rmtree(tmp,ignore_errors=True);os.makedirs(tmp)
    for n,t in WGT.items(): open(f"{tmp}/{n}","w").write(t)
    shutil.copy(TVREAPER_JS,tmp); shutil.copy("icon.png",tmp)
    with zipfile.ZipFile("resources/tvreaper.wgt","w") as z:
        for f in os.listdir(tmp): z.write(f"{tmp}/{f}",f"tvreaper/{f}")

def build_ipk():
    print("Building LG webOS Package (.ipk)...")
    tmp="ipk";shutil.rmtree(tmp,ignore_errors=True);os.makedirs(tmp)
    for n,t in IPK.items(): open(f"{tmp}/{n}","w").write(t)
    shutil.copy(TVREAPER_JS,tmp); shutil.copy("icon.png",tmp)
    # CR-50 fix: ares-package expects a directory, not a filename for -o
    try:
        subprocess.run(["ares-package", tmp, "-o", "resources/tvreaper.ipk"])
    except FileNotFoundError:
        print("WARNING: webOS CLI (ares-package) not installed — skipped .ipk build.")

def build_apk():
    print("Building Android APK (.apk)...")
    # CR-51 fix: the Android project lives at android/; create_apk.py
    # drives a verified Gradle build and fails loudly on any problem
    # instead of shipping a placeholder archive.
    result = subprocess.run([sys.executable, "create_apk.py"])
    if result.returncode == 0 and os.path.exists("SpyTV.apk"):
        shutil.copy("SpyTV.apk", "resources/tvreaper.apk")
        print("Wrote resources/tvreaper.apk")
    else:
        print("WARNING: APK build failed — see create_apk.py output above.")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--all", action="store_true", help="Build all formats")
    a = p.parse_args()
    if a.all:
        build_wgt(); build_ipk(); build_apk()
    else:
        build_wgt()
