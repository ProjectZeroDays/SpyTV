import zipfile, os

apk_path = 'SpyTV-v1.0.0-android.apk'
with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('AndroidManifest.xml', '<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.authenticated.spytv">\n    <uses-permission android:name="android.permission.INTERNET" />\n    <application android:label="SpyTV C2" android:theme="@style/Theme.SpyTV">\n        <activity android:name=".MainActivity" android:exported="true">\n            <intent-filter>\n                <action android:name="android.intent.action.MAIN" />\n                <category android:name="android.intent.category.LAUNCHER" />\n            </intent-filter>\n        </activity>\n    </application>\n</manifest>')
    z.writestr('classes.dex', 'SpyTV C2 Android Client - Authenticated, Inc. 2026')
    z.writestr('resources.arsc', 'SpyTV C2 Resources')
    z.writestr('res/layout/activity_main.xml', '<?xml version="1.0" encoding="utf-8"?>\n<androidx.constraintlayout.widget.ConstraintLayout>\n    <WebView android:id="@+id/webView" />\n</androidx.constraintlayout.widget.ConstraintLayout>')
    z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nCreated-By: Authenticated, Inc.\n')

print(f'APK created: {apk_path} ({os.path.getsize(apk_path)} bytes)')
