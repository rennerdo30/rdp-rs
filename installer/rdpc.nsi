; rdpc per-user Windows setup (NSIS 3). Built by scripts/package.ps1:
;   makensis /DVERSION=0.1.0 /DVI_VERSION=0.1.0.0 /DSRC=<dir> /DOUTFILE=<file> installer\rdpc.nsi
; SRC holds rdpc.exe, LICENSE.txt (MIT and Apache-2.0 texts) and
; THIRD-PARTY-NOTICES.txt.
;
; Installs to %LOCALAPPDATA%\Programs\rdpc without admin rights, with a Start
; menu shortcut and an Installed apps entry. No PATH or file-type changes.
; rdpc's updater (crates/rdpc-update) runs this setup with /S /UPDATE: it waits
; for rdpc to close, installs, and starts rdpc again. Uninstall removes only
; installed files; saved connections in %APPDATA%\rdp-rs stay.

!macro REQUIRE name
  !ifndef ${name}
    !error "Pass /D${name}=..."
  !endif
!macroend
!insertmacro REQUIRE VERSION
!insertmacro REQUIRE VI_VERSION
!insertmacro REQUIRE SRC
!insertmacro REQUIRE OUTFILE

Unicode true
ManifestDPIAware true
RequestExecutionLevel user
SetCompressor /SOLID lzma

!include MUI2.nsh
!include LogicLib.nsh
!include FileFunc.nsh

!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\rdpc"

Name "rdpc"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\rdpc"
InstallDirRegKey HKCU "${UNINSTALL_KEY}" "InstallLocation"
BrandingText "rdpc ${VERSION}"

VIProductVersion "${VI_VERSION}"
VIAddVersionKey "ProductName" "rdpc"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "rdpc ${VERSION} setup"
VIAddVersionKey "LegalCopyright" "MIT OR Apache-2.0"

!define MUI_ICON "..\assets\rdpc.ico"
!define MUI_UNICON "..\assets\rdpc.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\rdpc.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start rdpc"

!insertmacro MUI_PAGE_LICENSE "${SRC}\LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Var Update

Function .onInit
  StrCpy $Update 0
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/UPDATE" $1
  ${IfNot} ${Errors}
    StrCpy $Update 1
  ${EndIf}
FunctionEnd

; A running rdpc.exe cannot be replaced. Interactive runs ask to close it;
; silent runs (the updater) wait up to 30 s for rdpc to exit, then fail.
!macro WAIT_FOR_RDPC un
Function ${un}WaitForRdpc
  StrCpy $2 0
  retry:
  ${IfNot} ${FileExists} "$INSTDIR\rdpc.exe"
    Return
  ${EndIf}
  ClearErrors
  FileOpen $0 "$INSTDIR\rdpc.exe" a
  ${IfNot} ${Errors}
    FileClose $0
    Return
  ${EndIf}
  IfSilent wait
  MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "rdpc is running. Close every rdpc window, then choose Retry." /SD IDCANCEL IDRETRY retry
  SetErrorLevel 2
  Quit
  wait:
  ${If} $2 >= 60
    SetErrorLevel 2
    Quit
  ${EndIf}
  Sleep 500
  IntOp $2 $2 + 1
  Goto retry
FunctionEnd
!macroend
!insertmacro WAIT_FOR_RDPC ""
!insertmacro WAIT_FOR_RDPC "un."

Section "rdpc"
  Call WaitForRdpc
  SetOutPath "$INSTDIR"
  File "${SRC}\rdpc.exe"
  File "${SRC}\LICENSE.txt"
  File "${SRC}\THIRD-PARTY-NOTICES.txt"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\rdpc.lnk" "$INSTDIR\rdpc.exe"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "rdpc"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "rennerdo30"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "URLInfoAbout" "https://github.com/rennerdo30/rdp-rs"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\rdpc.exe,0"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "EstimatedSize" "$0"
  ${If} $Update == 1
    Exec '"$INSTDIR\rdpc.exe"'
  ${EndIf}
SectionEnd

Section "Uninstall"
  Call un.WaitForRdpc
  Delete "$INSTDIR\rdpc.exe"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\rdpc.lnk"
  DeleteRegKey HKCU "${UNINSTALL_KEY}"
SectionEnd
