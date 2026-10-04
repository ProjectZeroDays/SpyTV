#!/bin/bash
# SpyTV C2 Server - Linux/macOS Installation and Launch Script
# Authenticated, Inc. - 2026

echo "=========================================="
echo " SpyTV C2 Server - Linux/macOS Setup"
echo " Authenticated, Inc."
echo "=========================================="
echo ""

# Check Python installation
echo "[1/5] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed."
    echo "Please install Python 3.8+ using your package manager:"
    echo "  Ubuntu/Debian: sudo apt-get install python3 python3-venv python3-pip"
    echo "  macOS: brew install python3"
    echo "  Fedora: sudo dnf install python3 python3-virtualenv"
    exit 1
fi
echo "[OK] Python found."
echo ""

# Create virtual environment
echo "[2/5] Setting up virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment."
        exit 1
    fi
fi
echo "[OK] Virtual environment ready."
echo ""

# Install dependencies
echo "[3/5] Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install pyyaml requests colorama
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install dependencies."
    exit 1
fi
echo "[OK] Dependencies installed."
echo ""

# Configure repository
echo "[4/5] Configuring repository..."
mkdir -p c2_data/clips/audio
mkdir -p c2_data/clips/video
mkdir -p logs
mkdir -p certs
echo "[OK] Repository configured."
echo ""

# Launch C2 server
echo "[5/5] Launching C2 Server..."
echo ""
echo "=========================================="
echo " C2 Server starting on http://localhost:8443"
echo " Dashboard: http://localhost:8443/"
echo ""
echo " Press Ctrl+C to stop the server."
echo "=========================================="
echo ""

python3 c2_server.py
