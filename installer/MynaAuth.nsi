Unicode true
!include "MUI2.nsh"
Name "MynaAuth"
OutFile "MynaAuth-${APP_VERSION}-win-x64-Setup.exe"
InstallDir "$PROGRAMFILES64\MynaAuth"
RequestExecutionLevel admin
VIProductVersion "${APP_VERSION}.0"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "Japanese"

Section "MynaAuth"
  SetOutPath "$INSTDIR\app"
  File /r "${SOURCE_DIR}\*"
  CreateShortcut "$SMPROGRAMS\MynaAuth.lnk" "$INSTDIR\app\MynaAuth.Setup.exe"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MynaAuth" "DisplayName" "MynaAuth"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MynaAuth" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MynaAuth" "DisplayIcon" "$INSTDIR\app\MynaAuth.Setup.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MynaAuth" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MynaAuth" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MynaAuth" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$SMPROGRAMS\MynaAuth.lnk"
  RMDir /r "$INSTDIR\app"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MynaAuth"
SectionEnd
