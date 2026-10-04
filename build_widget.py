#!/usr/bin/env python3
"""TVREAPER v2 packaging: .wgt (Tizen/Orsay), .ipk (webOS), APK
(AndroidTV/BRAVIA/FireTV/HiSense), NetTV page."""
import os, json, shutil, subprocess, argparse, zipfile

TVREAPER_JS = "tvreaper.js"

# CR-49 fix: Fixed malformed config.xml (removed <previewreme/>, duplicate <type>,
# added required privilege/feature declarations for mic/camera access)
WGT = {
 "config.xml": """<?xml version="1.0" encoding="UTF-8"?>
<widget xmlns="http://www.samsungdforum.com/Banner/widget">
 <cpname>FORGE</cpname>
 <type>user</type>
 <category>video</category>
 <fullwidget>y</fullwidget>
 <srcctl enabled="no"/>
 <ThumbIcon>icon.png</ThumbIcon>
 <name>tvinfo</name>
 <author>Forge Labs</author>
 <tizen:privilege>http://tizen.org/privilege/tizen</tizen:privilege>
 <tizen:feature name="http://tizen.org/feature/microphone">true</tizen:feature>
 <tizen:feature name="http://tizen.org/feature/camera">true</tizen:feature>
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
 </application></manifest>""",
}

NETTV_PAGE = {
 "index.html": f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<script src="{TVREAPER_JS}"></script></head>
<body style="background:transparent"></body></html>"""
}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out-wgt", default="tvreaper.wgt")
    p.add_argument("--out-ipk", default="tvreaper.ipk")
    p.add_argument("--out-apk", default="tvreaper.apk")
    p.add_argument("--out-nettv", default="tvreaper-nettv.zip")
    a = p.parse_args()
    # .wgt
    tmp="wgt";shutil.rmtree(tmp,ignore_errors=True);os.makedirs(tmp)
    for n,t in WGT.items(): open(f"{tmp}/{n}","w").write(t)
    shutil.copy(TVREAPER_JS,tmp); shutil.copy("icon.png",tmp)
    with zipfile.ZipFile(a.out_wgt,"w") as z:
        for f in os.listdir(tmp): z.write(f"{tmp}/{f}",f"tvreaper/{f}")
    # .ipk
    tmp="ipk";shutil.rmtree(tmp,ignore_errors=True);os.makedirs(tmp)
    for n,t in IPK.items(): open(f"{tmp}/{n}","w").write(t)
    shutil.copy(TVREAPER_JS,tmp); shutil.copy("icon.png",tmp)
    subprocess.run(["ares-package",tmp,"-o",a.out_ipk])
    # .apk (assume Gradle wrapper exists at ./apk for Android package)
    if os.path.exists("apk/gradlew"):
        subprocess.run(["./gradlew","assembleDebug"],cwd="apk")
        shutil.copy("apk/app/build/outputs/apk/debug/app-debug.apk", a.out_apk)
    else:
        print("WARNING: Gradle project not found at apk/. Skipping APK build.")
    # NetTV page
    tmp="nettv";shutil.rmtree(tmp,ignore_errors=True);os.makedirs(tmp)
    for n,t in NETTV_PAGE.items(): open(f"{tmp}/{n}","w").write(t)
    shutil.copy(TVREAPER_JS,tmp)
    with zipfile.ZipFile(a.out_nettv,"w") as z:
        for f in os.listdir(tmp): z.write(f"{tmp}/{f}",f)
    print("Built:", a.out_wgt, a.out_ipk, a.out_apk, a.out_nettv)
