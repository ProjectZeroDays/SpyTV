#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
import shutil

def run_cmd(cmd, sudo=False):
    """Helper to run commands."""
    try:
        if sudo:
            subprocess.check_call(["sudo"] + cmd)
        else:
            subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError:
        print(f"Failed to run: {' '.join(cmd)}")
        return False

def install_python_deps():
    print("Installing Python dependencies...")
    # CR-37 fix: Use venv for PEP 668 compliance
    if not os.path.exists("venv"):
        subprocess.check_call([sys.executable, "-m", "venv", "venv"])
    venv_pip = os.path.join("venv", "bin", "pip") if platform.system() != "Windows" else os.path.join("venv", "Scripts", "pip.exe")
    if not os.path.exists(venv_pip):
        venv_pip = sys.executable
    if not run_cmd([venv_pip, "install", "-r", "requirements.txt"]):
        sys.exit(1)

def install_android_sdk():
    """Downloads and sets up Android SDK Command Line Tools."""
    print("Installing Android SDK Command Line Tools...")
    sdk_path = "/opt/android-sdk"
    if not os.path.exists(sdk_path):
        os.makedirs(sdk_path, exist_ok=True)
        tools_zip = "cmdline-tools-linux.zip"
        url = "https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip"

        if not os.path.exists(tools_zip):
            print("   Downloading Android SDK (approx 300MB)...")
            run_cmd(["wget", "-q", "-O", tools_zip, url])

        print("   Extracting...")
        run_cmd(["unzip", "-q", "-o", tools_zip, "-d", sdk_path])

        # CR-50 fix: Properly move cmdline-tools to cmdline-tools/latest
        old_path = os.path.join(sdk_path, "cmdline-tools")
        new_path = os.path.join(sdk_path, "cmdline-tools", "latest")
        if os.path.exists(old_path) and not os.path.exists(new_path):
            os.makedirs(os.path.dirname(new_path), exist_ok=True)
            shutil.move(old_path, new_path)

        os.remove(tools_zip)
        print(f"   Android SDK installed to {sdk_path}")
        return True
    return False

def install_system_deps_linux():
    print("Installing Linux system dependencies...")
    # CR-37 fix: Use proxychains4 (not proxychains) for consistency
    packages = ["proxychains4", "nmap", "adb", "openssh-client", "sshpass", "zip"]
    if not run_cmd(["sudo", "apt-get", "update"], sudo=True):
        return False
    if not run_cmd(["sudo", "apt-get", "install", "-y"] + packages, sudo=True):
        return False
    return True

def install_system_deps_macos():
    print("Installing macOS system dependencies...")
    # CR-37 fix: Use proxychains-ng (provides proxychains4)
    # CR-37 fix: sshpass not in default brew core
    packages = ["proxychains-ng", "nmap", "android-platform-tools", "openssh"]
    if not run_cmd(["brew", "update"]):
        return False
    if not run_cmd(["brew", "install"] + packages):
        return False
    return True

def main():
    print("=" * 50)
    print("SpyTV: Unified Environment Setup")
    print("=" * 50)

    install_python_deps()

    os_type = platform.system()
    if os_type == "Linux":
        install_system_deps_linux()
    elif os_type == "Darwin":
        install_system_deps_macos()
    else:
        print(f"Unsupported OS: {os_type}")

    install_android_sdk()
    print("\nSetup complete! Run 'python3 core/exploit_dispatcher.py --help' to start.")

if __name__ == "__main__":
    main()
