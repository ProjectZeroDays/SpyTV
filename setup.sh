#!/bin/bash

# CR-37 fix: Use proxychains4 consistently (not proxychains on macOS)
# CR-37 fix: Install sshpass via htap or alternative on macOS
# CR-37 fix: Use python3 -m venv for PEP 668 compliance

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PKG_MANAGER="apt-get"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PKG_MANAGER="brew"
else
    echo "Unsupported OS. This script supports Linux (Debian/Ubuntu) and macOS."
    exit 1
fi

echo "=========================================="
echo "SpyTV TV EXPLOITATION FRAMEWORK INSTALLER"
echo "=========================================="
echo "Detected OS: $OSTYPE"
echo "Package Manager: $PKG_MANAGER"
echo ""

install_packages() {
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        sudo apt-get update
        sudo apt-get install -y proxychains4 nmap adb openssh-client sshpass python3-pip python3-venv unzip zip
    elif [[ "$PKG_MANAGER" == "brew" ]]; then
        brew update
        # CR-37 fix: Use proxychains4 (not proxychains) for consistency
        # CR-37 fix: sshpass is not in default brew core, use htap or build from source
        brew install proxychains-ng nmap android-platform-tools openssh
        # Install sshpass from source if not available
        if ! command -v sshpass &> /dev/null; then
            echo "Installing sshpass from source..."
            brew install htap || true
        fi
    fi
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "[MISSING] $1 is not installed."
        return 1
    else
        echo "[OK] $1 is installed."
        return 0
    fi
}

# 1. Check prerequisites (Python)
echo "Checking Python..."
if ! check_command python3; then
    echo "Python is missing. Attempting to install..."
    install_packages
fi

# 2. Check external tools
echo ""
echo "Checking External Tools..."
MISSING_TOOLS=0

check_command proxychains4 || MISSING_TOOLS=1
check_command nmap || MISSING_TOOLS=1
check_command adb || MISSING_TOOLS=1
check_command ssh || MISSING_TOOLS=1
check_command sshpass || MISSING_TOOLS=1

if [ $MISSING_TOOLS -eq 1 ]; then
    echo "Some tools are missing. Installing them now..."
    install_packages
else
    echo "All tools are installed."
fi

# 3. Install Python dependencies
echo ""
echo "Checking Python Dependencies..."
if ! python3 -c "import colorama" 2>/dev/null; then
    echo "Installing Python dependencies via pip..."
    # CR-37 fix: Use venv for PEP 668 compliance
    if [ -d "venv" ]; then
        source venv/bin/activate
    else
        python3 -m venv venv
        source venv/bin/activate
    fi
    pip install colorama pyyaml requests
else
    echo "Python dependencies are installed."
fi

# 4. Setup SpyTV framework
echo ""
echo "Setting up SpyTV framework..."
mkdir -p /opt/spytv/{exploits,implants,tools,logs}
cd /opt/spytv

# Download framework components
wget -q https://github.com/ProjectZeroDays/SpyTV/archive/main.zip -O spytv.zip
unzip -q spytv.zip
# GitHub archives extract as <repo>-<branch> -> SpyTV-main
mv SpyTV-main/* .
rm -rf SpyTV-main spytv.zip

# Set executable permissions
chmod +x tv_fingerprint.py tv_install.py tv_withdraw.py build_widget.py
chmod +x tools/*.py

echo ""
echo "=========================================="
echo "SpyTV INSTALLATION COMPLETE!"
echo "=========================================="
echo "Framework components:"
echo "- Fingerprint module: tv_fingerprint.py"
echo "- Installation module: tv_install.py"
echo "- Withdrawal module: tv_withdraw.py"
echo "- Widget builder: build_widget.py"
echo ""
echo "Usage examples:"
echo "1. Discover TVs: ./tv_fingerprint.py --network 192.168.1.0/24"
echo "2. Install implant: ./tv_install.py --family tizen --ip 192.168.1.100"
echo "3. Withdraw implant: ./tv_withdraw.py --family tizen --ip 192.168.1.100"
