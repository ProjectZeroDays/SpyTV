; SpyTV C2 — Windows Installer (NSIS)
; Builds a native installer that installs the standalone C2 EXE,
; creates desktop + Start Menu shortcuts, and registers an uninstaller.

!include "MUI2.nsh"

; --- Basic info ---
Name "SpyTV C2"
OutFile "SpyTV-C2-Setup.exe"
InstallDir "$PROGRAMFILES64\SpyTV"
InstallDirRegKey HKLM "Software\SpyTV" "InstallDir"
RequestExecutionLevel admin

; --- Version ---
!define APP_VERSION "4.6.0"
!define APP_NAME "SpyTV C2"
!define APP_PUBLISHER "ProjectZeroDays"
!define APP_URL "https://github.com/ProjectZeroDays/SpyTV"
!define APP_EXE "SpyTV-C2-standalone.exe"

; --- MUI settings ---
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
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

Section "Desktop Shortcut" SecDesktop
    CreateShortCut "$DESKTOP\SpyTV C2.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
SectionEnd

Section "Start Menu" SecStartMenu
    CreateDirectory "$SMPROGRAMS\SpyTV"
    CreateShortCut "$SMPROGRAMS\SpyTV\SpyTV C2.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
    CreateShortCut "$SMPROGRAMS\SpyTV\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

; --- Uninstaller ---
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\Uninstall.exe"

    ; Remove shortcuts
    Delete "$DESKTOP\SpyTV C2.lnk"
    Delete "$SMPROGRAMS\SpyTV\SpyTV C2.lnk"
    Delete "$SMPROGRAMS\SpyTV\Uninstall.lnk"
    RMDir "$SMPROGRAMS\SpyTV"

    ; Remove registry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SpyTV"
    DeleteRegKey HKLM "Software\SpyTV"

    ; Remove directories (only if empty)
    RMDir "$INSTDIR\c2_data\clips\audio"
    RMDir "$INSTDIR\c2_data\clips\video"
    RMDir "$INSTDIR\c2_data\clips"
    RMDir "$INSTDIR\c2_data"
    RMDir "$INSTDIR\logs"
    RMDir "$INSTDIR\certs"
    RMDir "$INSTDIR"
SectionEnd