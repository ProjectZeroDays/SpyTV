; SpyTV C2 — Windows Installer (NSIS)
; Builds a native installer that installs the standalone C2 EXE,
; creates desktop + Start Menu shortcuts, and registers an uninstaller.
;
; Optional section: installs Python dependencies (venv + pip install -r
; requirements.txt) for users who want to run the C2 from source instead of
; the frozen EXE. Requires Python already on PATH (3.9+).
;
; Build:  makensis SpyTV.nsi
;   (run from the installer\ directory with SpyTV-C2-standalone.exe and
;    LICENSE.txt alongside this script — see .github/workflows for CI)

!include "MUI2.nsh"
!include "LogicLib.nsh"

; --- Basic info ---
Name "SpyTV C2"
OutFile "SpyTV-C2-Setup.exe"
InstallDir "$PROGRAMFILES64\SpyTV"
InstallDirRegKey HKLM "Software\SpyTV" "InstallDir"
RequestExecutionLevel admin

; --- Version ---
!define APP_VERSION "4.6.1"
!define APP_NAME "SpyTV C2"
!define APP_PUBLISHER "ProjectZeroDays"
!define APP_URL "https://github.com/ProjectZeroDays/SpyTV"
!define APP_EXE "SpyTV-C2-standalone.exe"

; --- MUI settings ---
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; --- Installer sections ---
Section "SpyTV C2 (required)" SecMain
    SectionIn RO
    SetOutPath "$INSTDIR"

    ; Copy the standalone EXE (built by PyInstaller)
    File "SpyTV-C2-standalone.exe"

    ; Copy source-of-truth files needed for the optional source-run section
    ; (requirements.txt drives `pip install -r` below)
    File "..\requirements.txt"

    ; Create data directories
    CreateDirectory "$INSTDIR\c2_data"
    CreateDirectory "$INSTDIR\c2_data\clips"
    CreateDirectory "$INSTDIR\c2_data\clips\audio"
    CreateDirectory "$INSTDIR\c2_data\clips\video"
    CreateDirectory "$INSTDIR\logs"
    CreateDirectory "$INSTDIR\certs"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Registry entries for Add/Remove Programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV" "DisplayName" "${APP_NAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV" "DisplayIcon" "$INSTDIR\${APP_EXE}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV" "Publisher" "${APP_PUBLISHER}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV" "URLInfoAbout" "${APP_URL}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV" "DisplayVersion" "${APP_VERSION}"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV" "NoRepair" 1

    ; Store install dir
    WriteRegStr HKLM "Software\SpyTV" "InstallDir" "$INSTDIR"
SectionEnd

Section "Python dependencies (run from source)" SecPythonDeps
    ; Optional: only useful if the user plans to run c2_server.py from source
    ; instead of the frozen EXE. Requires Python 3.9+ already installed and
    ; on PATH. Uses the repo's venv + requirements.txt flow.
    ;
    ; We detect python via `py -3 --version` (Windows py launcher) first,
    ; then fall back to `python --version`.

    DetailPrint "Checking for Python 3.9+..."
    nsExec::ExecToStack 'py -3 --version'
    Pop $0  ; exit code
    Pop $1  ; output
    ${If} $0 != 0
        nsExec::ExecToStack 'python --version'
        Pop $0
        Pop $1
    ${EndIf}
    ${If} $0 != 0
        MessageBox MB_ICONEXCLAMATION|MB_OK \
            "Python 3.9+ was not found on PATH.$\r$\n$\r$\n\
            The SpyTV C2 EXE does not need Python; this section only matters$\r$\n\
            if you plan to run c2_server.py from source.$\r$\n$\r$\n\
            Install Python from https://www.python.org/downloads/ (check$\r$\n\
            'Add Python to PATH') and re-run this installer, or skip."
        DetailPrint "Skipping Python deps: Python not found."
        Goto PyDepsDone
    ${EndIf}
    DetailPrint "Found Python: $1"

    ; Create venv inside the install dir and install pinned deps
    DetailPrint "Creating virtual environment..."
    nsExec::ExecToLog 'py -3 -m venv "$INSTDIR\venv"'
    Pop $0
    ${If} $0 != 0
        nsExec::ExecToLog 'python -m venv "$INSTDIR\venv"'
        Pop $0
    ${EndIf}
    ${If} $0 != 0
        MessageBox MB_ICONEXCLAMATION|MB_OK "Failed to create venv (exit $0). Skipping dependency installation."
        Goto PyDepsDone
    ${EndIf}

    DetailPrint "Installing requirements.txt into venv..."
    nsExec::ExecToLog '"$INSTDIR\venv\Scripts\python.exe" -m pip install --upgrade pip'
    nsExec::ExecToLog '"$INSTDIR\venv\Scripts\python.exe" -m pip install -r "$INSTDIR\requirements.txt"'
    Pop $0
    ${If} $0 != 0
        MessageBox MB_ICONEXCLAMATION|MB_OK "pip install finished with exit code $0. Check the install log."
    ${Else}
        DetailPrint "Python dependencies installed into $INSTDIR\venv"
    ${EndIf}
PyDepsDone:
SectionEnd

Section "Desktop Shortcut" SecDesktop
    CreateShortCut "$DESKTOP\SpyTV C2.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
SectionEnd

Section "Start Menu" SecStartMenu
    CreateDirectory "$SMPROGRAMS\SpyTV"
    CreateShortCut "$SMPROGRAMS\SpyTV\SpyTV C2.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
    CreateShortCut "$SMPROGRAMS\SpyTV\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

; --- Section descriptions ---
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} \
        "The SpyTV C2 server as a standalone executable. No Python required."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecPythonDeps} \
        "OPTIONAL: Install Python packages (venv + requirements.txt) so c2_server.py can run from source. Requires Python 3.9+ on PATH. Skip this if you will only use the frozen EXE."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Create a SpyTV C2 shortcut on the desktop."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} "Create Start Menu shortcuts for SpyTV C2 and the uninstaller."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; --- Uninstaller ---
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\requirements.txt"
    Delete "$INSTDIR\Uninstall.exe"

    ; Remove shortcuts
    Delete "$DESKTOP\SpyTV C2.lnk"
    Delete "$SMPROGRAMS\SpyTV\SpyTV C2.lnk"
    Delete "$SMPROGRAMS\SpyTV\Uninstall.lnk"
    RMDir "$SMPROGRAMS\SpyTV"

    ; Remove registry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV"
    DeleteRegKey HKLM "Software\SpyTV"

    ; Remove venv if we created one (user data we explicitly installed)
    RMDir /r "$INSTDIR\venv"

    ; Remove directories (only if empty — c2_data/logs/certs may hold user data)
    RMDir "$INSTDIR\c2_data\clips\audio"
    RMDir "$INSTDIR\c2_data\clips\video"
    RMDir "$INSTDIR\c2_data\clips"
    RMDir "$INSTDIR\c2_data"
    RMDir "$INSTDIR\logs"
    RMDir "$INSTDIR\certs"
    RMDir "$INSTDIR"
SectionEnd
