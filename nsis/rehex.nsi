; Reverse Engineer's Hex Editor
; Copyright (C) 2025 Daniel Collins <solemnwarning@solemnwarning.net>
;
; This program is free software; you can redistribute it and/or modify it
; under the terms of the GNU General Public License version 2 as published by
; the Free Software Foundation.
;
; This program is distributed in the hope that it will be useful, but WITHOUT
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
; FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
; more details.
;
; You should have received a copy of the GNU General Public License along with
; this program; if not, write to the Free Software Foundation, Inc., 51
; Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

!include "LogicLib.nsh"
!include "MUI2.nsh"
!include "WinVer.nsh"
!include "x64.nsh"

; !define LANG_ENGLISH 0x0809
!define LANG_ENGLISH 0x0409

!system "if exist build ( rmdir /s /q build )" = 0
!system "mkdir build" = 0

!system "write-version.bat" = 0
!include "build\version.nsh"

; Unpack the files from the distributions into build/arch-indep, build/x86 and build/x64 depending
; whether they are architecture-independent, x86 or x64, respectively. Recent versions of Windows
; include a "tar" which can also read zip archives... so thats handy.
!system "mkdir build\arch-indep build\x64 build\x86" = 0
!system "tar -xf rehex-${SHORT_VERSION}-win-x86.zip -C build\arch-indep --strip-components=1 --exclude=*.exe" = 0
!system "tar -xf rehex-${SHORT_VERSION}-win-x86.zip -C build\x86 --strip-components=1 --include=*.exe" = 0
!system "tar -xf rehex-${SHORT_VERSION}-win-x64.zip -C build\x64 --strip-components=1 --include=*.exe" = 0

;Name and file
Name "Reverse Engineers' Hex Editor"
OutFile "rehex-${SHORT_VERSION}-setup.exe"
Unicode True

VIProductVersion "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "Reverse Engineers' Hex Editor"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${SHORT_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "Daniel Collins"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "2017-2025 Daniel Collins"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "Reverse Engineers' Hex Editor"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${SHORT_VERSION}"

; We need to explicitly support newer Windows versions in the exe manifest or
; else Windows will lie to us about what version we are running on.
ManifestSupportedOS {e2011457-1546-43c5-a5fe-008deee3d3f0} ; Windows Vista
ManifestSupportedOS {35138b9a-5d96-4fbd-8e2d-a2440225f93a} ; Windows 7
ManifestSupportedOS {4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38} ; Windows 8
ManifestSupportedOS {1f676c76-80e1-4239-95bb-83d0f6d0da78} ; Windows 8.1
ManifestSupportedOS {8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a} ; Windows 10

;Default installation folder
InstallDir "$PROGRAMFILES\REHex"

;Request application privileges for Windows Vista
RequestExecutionLevel admin

!define MUI_ABORTWARNING
!define MUI_ICON "..\res\icon.ico"

;--------------------------------
;Pages

!insertmacro MUI_PAGE_WELCOME
; !insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
; !insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;--------------------------------
;Languages

!insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Installer Sections

!ifdef SIGN_CMD
	!finalize '"${SIGN_CMD}" "%1"' = 0
!endif

Function .onInit
	${If} ${RunningX64}
	${AndIf} ${AtLeastWin8.1}
		; Disable WoW64 registry and filesystem redirection when installing the 64-bit version.
		SetRegView 64
		${DisableX64FSRedirection}
		
		StrCpy $INSTDIR "$PROGRAMFILES64\REHex"
	${EndIf}
	
	; Get installation folder from registry if available.
	; We do this rather than using InstallDirRegKey because InstallDirRegKey would not be affected
	; by our call to SetRegView in this function and would read from the WoW64 registry.
	
	ClearErrors
	ReadRegStr $0 HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "InstallLocation"
	
	; Skip over the StrCpy if an error occured (e.g. key/value doesn't exist)
	IfErrors +2 0
	StrCpy $INSTDIR "$0"
FunctionEnd

Section "Application" SecApp
	; This section is mandatory
	SectionIn RO
	
	SetOutPath "$INSTDIR"
	
	; Create uninstaller
	WriteUninstaller "$INSTDIR\Uninstall.exe"
	
	; Registry information for add/remove programs
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "DisplayName" "Reverse Engineers' Hex Editor"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "UninstallString" "$INSTDIR\Uninstall.exe"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "QuietUninstallString" "$INSTDIR\Uninstall.exe /S"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "InstallLocation" "$INSTDIR"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "DisplayIcon" "$INSTDIR\rehex.exe"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "Publisher" "Daniel Collins"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "HelpLink" "https://github.com/solemnwarning/rehex/issues"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "URLInfoAbout" "https://rehex.solemnwarning.net/"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "DisplayVersion" "${LONG_VERSION}"
	; There is no option for modifying or repairing the install
	WriteRegDWORD HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "NoModify" 1
	WriteRegDWORD HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "NoRepair" 1
	
	File /r "build\arch-indep\*"
	
	${If} ${RunningX64}
	${AndIf} ${AtLeastWin8.1}
		File /r "build\x64\*"
	${Else}
		File /r "build\x86\*"
	${EndIf}
	
	; Start Menu
	CreateShortCut "$SMPROGRAMS\Reverse Engineers' Hex Editor.lnk" "$INSTDIR\rehex.exe"
	
	; Add REHex to the "Open with..." list for all file types.
	WriteRegStr HKEY_CLASSES_ROOT "Applications\net.solemnwarning.rehex\shell\open\command" "" "$\"$INSTDIR\rehex.exe$\" $\"%1$\""
	WriteRegNone HKEY_CLASSES_ROOT "*\OpenWithProgIDs" "net.solemnwarning.rehex"
SectionEnd

;--------------------------------
;Uninstaller Section

!ifdef SIGN_CMD
	!uninstfinalize '"${SIGN_CMD}" "%1"' = 0
!endif

Function un.onInit
	${If} ${RunningX64}
	${AndIf} ${AtLeastWin8.1}
		SetRegView 64
		${DisableX64FSRedirection}
	${EndIf}
FunctionEnd

Section "Uninstall"
	Delete "$SMPROGRAMS\Reverse Engineers' Hex Editor.lnk"
	
	DeleteRegValue HKEY_CLASSES_ROOT "*\OpenWithProgIDs" "net.solemnwarning.rehex"
	DeleteRegKey HKEY_CLASSES_ROOT "Applications\net.solemnwarning.rehex"
	
	; Generate and embed list of files/directories from the distribution for deletion.
	!system "UnFiles.cmd build\arch-indep build\uninstall-files.nsh" = 0
	!system "UnFiles.cmd build\x86 build\uninstall-files.nsh" = 0
	!include "build\uninstall-files.nsh"
	
	DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex"
	Delete "$INSTDIR\Uninstall.exe"
	
	RMDir "$INSTDIR"
SectionEnd
