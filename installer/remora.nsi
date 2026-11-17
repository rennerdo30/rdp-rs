; Remora per-user Windows setup (NSIS 3). Built by scripts/package.ps1:
;   makensis /DVERSION=0.1.0 /DVI_VERSION=0.1.0.0 /DSRC=<dir> /DOUTFILE=<file> installer\remora.nsi
; SRC holds remora.exe, remora-agent.exe, LICENSE.txt (MIT and Apache-2.0
; texts) and THIRD-PARTY-NOTICES.txt.
;
; Components (RDP-65): Remora (the app), the server helper (remora-agent), or
; both; /COMPONENTS=app, =helper or =app,helper chooses without the page. A fresh interactive setup preselects Remora, and the helper too on a
; Windows Server or inside a remote session. The choice is kept under the
; uninstall key ("Components"); updates (/S /UPDATE) renew exactly what is
; installed. The helper is set up with its own `remora-agent install` (a
; scheduled task for this user and the Send To shortcut) and started; a helper
; that is running is moved aside (a running program can be renamed) and its
; new version starts at the next sign-in or reconnect, or when Remora updates
; it over the connection.
;
; Installs to %LOCALAPPDATA%\Programs\Remora without admin rights, with a
; Start menu shortcut and an Installed apps entry. No PATH or file-type
; changes. Remora's updater (crates/remora-update) runs this setup with
; /S /UPDATE: it waits for Remora to close, installs, and starts Remora again.
; Uninstall removes only installed files; user data in %APPDATA%\rdp-rs and
; %LOCALAPPDATA%\rdp-rs stays.
;
; Moving from rdpc (the app's name before Remora, 0.1.0-beta.1). rdpc
; installed to %LOCALAPPDATA%\Programs\rdpc (uninstall key ...\Uninstall\rdpc,
; Start menu shortcut rdpc.lnk). Its updater finds this setup under the legacy
; asset name rdpc-<version>-setup.exe and runs it with the same /S /UPDATE.
; The setup then waits for rdpc.exe to exit as for any update, installs
; Remora, and only after that removes rdpc's program files, its folder (only
; if empty), its uninstall key and its shortcuts, then starts remora.exe.
; It never touches the data folders. Every step skips what is already gone,
; so a rerun or a half-removed rdpc install is fine.

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
!include Sections.nsh
!include WinVer.nsh
!include WordFunc.nsh

!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Remora"
; What rdpc 0.1.0-beta.1's setup wrote (installer/rdpc.nsi at v0.1.0-beta.1).
!define RDPC_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\rdpc"

Name "Remora"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\Remora"
InstallDirRegKey HKCU "${UNINSTALL_KEY}" "InstallLocation"
BrandingText "Remora ${VERSION}"

VIProductVersion "${VI_VERSION}"
VIAddVersionKey "ProductName" "Remora"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "Remora ${VERSION} setup"
VIAddVersionKey "LegalCopyright" "MIT OR Apache-2.0"

!define MUI_ICON "..\assets\remora.ico"
!define MUI_UNICON "..\assets\remora.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\remora.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start Remora"

!insertmacro MUI_PAGE_LICENSE "${SRC}\LICENSE.txt"
!define MUI_COMPONENTSPAGE_TEXT_TOP "Remora connects to remote desktops from this PC. The server helper runs on a server (or any PC you connect to) and adds file transfer, links on your PC and better graphics settings."
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE ComponentsLeave
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Var Update
; WaitForExe's arguments: the executable, the name shown for it and what to
; do about it.
Var WaitExe
Var WaitName
Var WaitHow
; 1 when a running helper was moved aside for its update.
Var AgentWasRunning
; rdpc's install folder from its uninstall key, or "" without one.
Var RdpcDir
; 1 when that key names a folder this setup does not remove.
Var KeepRdpcKey



; A running executable cannot be replaced or deleted. Interactive runs ask to
; close it; silent runs (the updaters) wait up to 30 s for it to exit, then
; fail with exit code 2.
!macro WAIT_FOR_EXE un
Function ${un}WaitForExe
  StrCpy $2 0
  retry:
  ${IfNot} ${FileExists} "$WaitExe"
    Return
  ${EndIf}
  ClearErrors
  FileOpen $0 "$WaitExe" a
  ${IfNot} ${Errors}
    FileClose $0
    Return
  ${EndIf}
  IfSilent wait
  MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$WaitName is running. $WaitHow, then choose Retry." /SD IDCANCEL IDRETRY retry
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
!insertmacro WAIT_FOR_EXE ""
!insertmacro WAIT_FOR_EXE "un."

; Waits for rdpc.exe in every folder rdpc may be installed in: the one its
; uninstall key names and the default one. The key's folder counts only if
; it ends in \rdpc, as every folder rdpc's setup offered did; otherwise that
; install and its uninstall key stay as they are.
Function WaitForRdpc
  StrCpy $KeepRdpcKey 0
  ReadRegStr $RdpcDir HKCU "${RDPC_KEY}" "InstallLocation"
  ${If} $RdpcDir != ""
    StrCpy $1 $RdpcDir "" -5
    ${If} $1 != "\rdpc"
      StrCpy $RdpcDir ""
      StrCpy $KeepRdpcKey 1
    ${EndIf}
  ${EndIf}
  StrCpy $WaitName "rdpc"
  StrCpy $WaitHow "Close every rdpc window"
  ${If} $RdpcDir != ""
    StrCpy $WaitExe "$RdpcDir\rdpc.exe"
    Call WaitForExe
  ${EndIf}
  StrCpy $WaitExe "$LOCALAPPDATA\Programs\rdpc\rdpc.exe"
  Call WaitForExe
FunctionEnd

; Removes rdpc's program files from folder $0, exactly the files its setup
; installed, then the folder if it is empty. Never recursive: whatever else
; is in there stays. If $0 is Remora's own folder, only rdpc.exe goes.
Function RemoveRdpcFiles
  ${If} $0 == ""
    Return
  ${EndIf}
  ${IfNot} ${FileExists} "$0\*.*"
    Return
  ${EndIf}
  Delete "$0\rdpc.exe"
  ${If} $0 == $INSTDIR
    Return
  ${EndIf}
  Delete "$0\LICENSE.txt"
  Delete "$0\THIRD-PARTY-NOTICES.txt"
  Delete "$0\uninstall.exe"
  RMDir "$0"
FunctionEnd

; Removes an rdpc install after Remora is in place. Safe to run when rdpc was
; never installed or is partly gone; it never touches user data.
Function RemoveRdpc
  StrCpy $0 $RdpcDir
  Call RemoveRdpcFiles
  StrCpy $0 "$LOCALAPPDATA\Programs\rdpc"
  Call RemoveRdpcFiles
  Delete "$SMPROGRAMS\rdpc.lnk"
  Delete "$DESKTOP\rdpc.lnk"
  ${If} $KeepRdpcKey == 0
    DeleteRegKey HKCU "${RDPC_KEY}"
  ${EndIf}
FunctionEnd

Section "Remora" SecApp
  ; Every running copy must be gone before anything changes, so a refused
  ; setup leaves the existing install (Remora or rdpc) as it was.
  Call WaitForRdpc
  StrCpy $WaitExe "$INSTDIR\remora.exe"
  StrCpy $WaitName "Remora"
  StrCpy $WaitHow "Close every Remora window"
  Call WaitForExe
  SetOutPath "$INSTDIR"
  File "${SRC}\remora.exe"
  CreateShortcut "$SMPROGRAMS\Remora.lnk" "$INSTDIR\remora.exe"
  Call RemoveRdpc
SectionEnd

Section /o "Server helper" SecHelper
  SetOutPath "$INSTDIR"
  Delete "$INSTDIR\remora-agent.exe.old"
  ${If} ${FileExists} "$INSTDIR\remora-agent.exe"
    ClearErrors
    Delete "$INSTDIR\remora-agent.exe"
    ${If} ${Errors}
      ; Running: a running program can be renamed, not replaced. The helper
      ; deletes the .old file when its new version starts.
      Rename "$INSTDIR\remora-agent.exe" "$INSTDIR\remora-agent.exe.old"
      StrCpy $AgentWasRunning 1
    ${EndIf}
  ${EndIf}
  File "${SRC}\remora-agent.exe"
  ; Its scheduled task (this user, at sign-in and reconnect) and Send To.
  nsExec::ExecToLog '"$INSTDIR\remora-agent.exe" install'
  Pop $0
  ${If} $0 != 0
    DetailPrint "remora-agent install exited with $0"
  ${EndIf}
  ${If} $AgentWasRunning == 0
    Exec '"$INSTDIR\remora-agent.exe"'
  ${Else}
    DetailPrint "The running helper switches to this version at the next sign-in or reconnect."
  ${EndIf}
SectionEnd

Section "-Common"
  SetOutPath "$INSTDIR"
  File "${SRC}\LICENSE.txt"
  File "${SRC}\THIRD-PARTY-NOTICES.txt"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  ; What is installed now (an earlier setup may have added the other one).
  StrCpy $0 ""
  ${If} ${FileExists} "$INSTDIR\remora.exe"
    StrCpy $0 "app"
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\remora-agent.exe"
    ${If} $0 == ""
      StrCpy $0 "helper"
    ${Else}
      StrCpy $0 "$0,helper"
    ${EndIf}
  ${EndIf}
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Components" "$0"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "Remora"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "rennerdo30"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "URLInfoAbout" "https://github.com/rennerdo30/rdp-rs"
  ${If} ${FileExists} "$INSTDIR\remora.exe"
    WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\remora.exe,0"
  ${Else}
    WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\remora-agent.exe,0"
  ${EndIf}
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "EstimatedSize" "$0"
  ${If} $Update == 1
  ${AndIf} ${SectionIsSelected} ${SecApp}
    Exec '"$INSTDIR\remora.exe"'
  ${EndIf}
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecApp} "The Remora app: connect to remote desktops from this PC."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecHelper} "The server helper (remora-agent) for this user: install it on the computer you connect to."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; After the sections: it selects them by their index.
Function .onInit
  StrCpy $Update 0
  StrCpy $AgentWasRunning 0
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/UPDATE" $1
  ${IfNot} ${Errors}
    StrCpy $Update 1
  ${EndIf}
  ; What is installed decides an update: the kept choice, else the files.
  ReadRegStr $2 HKCU "${UNINSTALL_KEY}" "Components"
  ReadRegStr $3 HKCU "${UNINSTALL_KEY}" "InstallLocation"
  ${If} $2 != ""
    StrCpy $4 $2
  ${ElseIf} $3 != ""
    StrCpy $4 ""
    ${If} ${FileExists} "$3\remora.exe"
      StrCpy $4 "app"
    ${EndIf}
    ${If} ${FileExists} "$3\remora-agent.exe"
      StrCpy $4 "$4,helper"
    ${EndIf}
  ${Else}
    StrCpy $4 ""
  ${EndIf}
  ; /COMPONENTS=app,helper (for scripted installs on servers) wins.
  ClearErrors
  ${GetOptions} $0 "/COMPONENTS=" $7
  ${IfNot} ${Errors}
    StrCpy $4 $7
  ${EndIf}
  ClearErrors
  ${If} $4 != ""
    ; An existing install: keep its components.
    ${WordFind} $4 "app" "E+1{" $5
    ${If} ${Errors}
      !insertmacro UnselectSection ${SecApp}
    ${EndIf}
    ClearErrors
    ${WordFind} $4 "helper" "E+1{" $5
    ${IfNot} ${Errors}
      !insertmacro SelectSection ${SecHelper}
    ${EndIf}
    ClearErrors
  ${Else}
    ; A fresh install: the helper too on a server or in a remote session.
    System::Call 'user32::GetSystemMetrics(i 0x1000) i .r6'
    ${If} ${IsServerOS}
    ${OrIf} $6 != 0
      !insertmacro SelectSection ${SecHelper}
    ${EndIf}
  ${EndIf}
FunctionEnd

; At least one component.
Function ComponentsLeave
  ${IfNot} ${SectionIsSelected} ${SecApp}
  ${AndIfNot} ${SectionIsSelected} ${SecHelper}
    MessageBox MB_OK|MB_ICONEXCLAMATION "Choose Remora, the server helper, or both."
    Abort
  ${EndIf}
FunctionEnd

Section "Uninstall"
  ${If} ${FileExists} "$INSTDIR\remora-agent.exe"
    ; Its scheduled task, Send To shortcut and link registration go first.
    nsExec::ExecToLog '"$INSTDIR\remora-agent.exe" uninstall'
    Pop $0
    StrCpy $WaitExe "$INSTDIR\remora-agent.exe"
    StrCpy $WaitName "The Remora helper"
    StrCpy $WaitHow "Quit it from its tray icon (Quit helper)"
    Call un.WaitForExe
    Delete "$INSTDIR\remora-agent.exe"
  ${EndIf}
  Delete "$INSTDIR\remora-agent.exe.old"
  StrCpy $WaitExe "$INSTDIR\remora.exe"
  StrCpy $WaitName "Remora"
  StrCpy $WaitHow "Close every Remora window"
  Call un.WaitForExe
  Delete "$INSTDIR\remora.exe"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\Remora.lnk"
  DeleteRegKey HKCU "${UNINSTALL_KEY}"
SectionEnd
