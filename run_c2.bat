@echo off
REM ============================================================
REM  SpyTV C2 Launcher - Authenticated, Inc.
REM  Mode selection: Self-Hosted C2 Server | Connect-Remote
REM  1) Prompts for mode selection
REM  2) Checks .env for AI provider API keys
REM  3) Launches the appropriate mode
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

:MENU
echo ==========================================
echo  SpyTV C2 Launcher
echo  Authenticated, Inc.
echo ==========================================
echo.
echo  Select C2 mode:
echo    1 = Self-Hosted C2 Server (run C2 locally, serves dashboard at :8443)
echo    2 = Connect-Remote (connect to an external C2 server)
echo    Q = Quit
echo.
set /p "CHOICE=Your choice: "

if /i "!CHOICE!"=="1" goto :self_hosted
if /i "!CHOICE!"=="2" goto :connect_remote
if /i "!CHOICE!"=="Q" goto :eof
if /i "!CHOICE!"=="q" goto :eof
echo Invalid choice.
goto :MENU

:self_hosted
echo.
echo Starting Self-Hosted C2 Server...
goto :check_keys

:connect_remote
echo.
set /p "REMOTE_URL=Enter C2 server URL (e.g. http://192.168.1.10:8443/): "
if "!REMOTE_URL!"=="" set "REMOTE_URL=http://localhost:8443/"
echo.
echo Opening Connect-Remote dashboard at !REMOTE_URL!
echo.
echo The C2 server must be running at that address.
echo.
REM Launch default browser to the remote C2
start "" "!REMOTE_URL!"
echo.
echo SpyTV C2 Console mode. Press any key to exit.
pause
goto :eof

:check_keys
REM ---------- Step 1: check .env for keys ----------
set "HAVE_KEYS=0"
if exist ".env" (
    findstr /b /c:"OPENROUTER_API_KEY=" ".env" >nul 2>&1 && findstr /v /r /c:"OPENROUTER_API_KEY=$" /c:"OPENROUTER_API_KEY= *$" ".env" >nul 2>&1 && set "HAVE_KEYS=1"
    findstr /b /c:"VENICE_API_KEY=" ".env" >nul 2>&1 && findstr /v /r /c:"VENICE_API_KEY=$" /c:"VENICE_API_KEY= *$" ".env" >nul 2>&1 && set "HAVE_KEYS=1"
    findstr /b /c:"ABLITERATION_API_KEY=" ".env" >nul 2>&1 && findstr /v /r /c:"ABLITERATION_API_KEY=$" /c:"ABLITERATION_API_KEY= *$" ".env" >nul 2>&1 && set "HAVE_KEYS=1"
)

REM More reliable check: count non-empty key assignments
set "KEY_COUNT=0"
if exist ".env" (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        set "kname=%%A"
        set "kval=%%B"
        if not "!kval!"=="" (
            if "!kname!"=="OPENROUTER_API_KEY" set /a KEY_COUNT+=1
            if "!kname!"=="VENICE_API_KEY" set /a KEY_COUNT+=1
            if "!kname!"=="ABLITERATION_API_KEY" set /a KEY_COUNT+=1
        )
    )
)

if !KEY_COUNT! GEQ 1 (
    echo [OK] !KEY_COUNT! AI provider key^(s^) found in .env - skipping prompt.
    echo.
    goto :launch
)

REM ---------- Step 2: no keys in .env - ask the user ----------
echo No AI provider API keys found in .env.
echo.
echo Add API keys for automatic exploit generation on new CVEs?
echo Select providers to configure (enter numbers, space-separated, or S to skip):
echo.
echo   1 = OpenRouter        (Uncensored model)
echo   2 = Venice AI         (Uncensored V 1.2 / Qwen 3.6 Plus Uncensored / GLM 4.7 Flash Heretic)
echo   3 = Abliteration.ai   (Abliterated Large v2)
echo   S = Skip (run C2 without AI exploit generation)
echo.
set "SELECTION="
set /p "SELECTION=Your choice: "

if /i "!SELECTION!"=="S" goto :launch
if "!SELECTION!"=="" goto :launch

echo set "DONE=0"> "%temp%\spytv_sel.bat"

for %%N in (!SELECTION!) do (
    if "%%N"=="1" call :askkey OPENROUTER_API_KEY "OpenRouter key (sk-or-...)"
    if "%%N"=="2" call :askkey VENICE_API_KEY "Venice AI key"
    if "%%N"=="3" call :askkey ABLITERATION_API_KEY "Abliteration.ai key"
)

echo.
echo [OK] Keys written to .env (git-ignored).
echo.

:launch
REM ---------- Step 3: launch the C2 ----------
if not exist ".env" (
    echo # SpyTV C2 local secrets - do not commit> .env
    echo OPENROUTER_API_KEY=>> .env
    echo VENICE_API_KEY=>> .env
    echo ABLITERATION_API_KEY=>> .env
    echo NVD_API_KEY=>> .env
)

if not exist "c2_data" mkdir c2_data
if not exist "data\exploits\generated" mkdir data\exploits\generated

echo ==========================================
echo  Starting C2 Server (Self-Hosted)
echo  Dashboard: http://localhost:8443/
echo.
echo  CVE feed auto-updates on start and logs
echo  new entries to CVE_UPDATES.log
echo  Press Ctrl+C to stop.
echo ==========================================
echo.

if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" c2_server.py
) else (
    python c2_server.py
)

pause
exit /b 0

:askkey
set "ENVNAME=%~1"
set "ENVDESC=%~2"
set "NEWKEY="
set /p "NEWKEY=Enter %ENVDESC% (blank to skip): "
if "!NEWKEY!"=="" goto :eof
REM Remove any existing definition, then append the new one
if exist ".env" (
    findstr /v /b /c:"%ENVNAME%=" ".env" > ".env.tmp" 2>nul
    move /y ".env.tmp" ".env" >nul
)
echo %ENVNAME%=!NEWKEY!>> .env
echo   [added] %ENVNAME%
goto :eof
