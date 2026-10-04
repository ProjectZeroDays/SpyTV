@echo off
REM SpyTV C2 Server - Windows Installation and Launch Script
REM Authenticated, Inc. - 2026

echo ==========================================
echo  SpyTV C2 Server - Windows Setup
echo  Authenticated, Inc.
echo ==========================================
echo.

REM Check Python installation
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed.
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
echo [OK] Python found.
echo.

REM Create virtual environment
echo [2/5] Setting up virtual environment...
if not exist "venv" (
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)
echo [OK] Virtual environment ready.
echo.

REM Install dependencies
echo [3/5] Installing dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip >nul 2>&1
pip install pyyaml requests colorama
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo [OK] Dependencies installed.
echo.

REM Configure repository
echo [4/5] Configuring repository...
if not exist "c2_data" mkdir c2_data
if not exist "c2_data\clips" mkdir c2_data\clips
if not exist "c2_data\clips\audio" mkdir c2_data\clips\audio
if not exist "c2_data\clips\video" mkdir c2_data\clips\video
if not exist "logs" mkdir logs
if not exist "certs" mkdir certs
echo [OK] Repository configured.
echo.

REM Launch C2 server
echo [5/5] Launching C2 Server...
echo.
echo ==========================================
echo  C2 Server starting on http://localhost:8443
echo  Dashboard: http://localhost:8443/
echo.
echo  Press Ctrl+C to stop the server.
echo ==========================================
echo.

python c2_server.py

pause
