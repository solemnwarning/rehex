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

!include "MUI2.nsh"

; !define LANG_ENGLISH 0x0809
!define LANG_ENGLISH 0x0409

!system "write-version.bat"
!include "version.nsh"

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

;Default installation folder
InstallDir "$PROGRAMFILES\REHex"

;Get installation folder from registry if available
InstallDirRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "InstallLocation"

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

Section "Application" SecApp
	; This section is mandatory
	SectionIn RO
	
	SetOutPath "$INSTDIR"
	
	; Create uninstaller
	WriteUninstaller "$INSTDIR\Uninstall.exe"
	
	; Registry information for add/remove programs
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "DisplayName" "Reverse Engineers' Hex Editor"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "UninstallString" "$INSTDIR\Uninstall.exe"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "InstallLocation" "$INSTDIR"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "DisplayIcon" "$INSTDIR\rehex.exe"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "Publisher" "Daniel Collins"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "HelpLink" "https://github.com/solemnwarning/rehex/issues"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "URLInfoAbout" "https://rehex.solemnwarning.net/"
	WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "DisplayVersion" "${LONG_VERSION}"
	; There is no option for modifying or repairing the install
	WriteRegDWORD HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "NoModify" 1
	WriteRegDWORD HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex" "NoRepair" 1
	
	; Copy everything from the distribution made by the makefile.
	File /r "..\rehex-${SHORT_VERSION}\*"
	
	; Start Menu
	CreateShortCut "$SMPROGRAMS\Reverse Engineers' Hex Editor.lnk" "$INSTDIR\rehex.exe"
	
	; Add REHex to the "Open with..." list for all file types.
	WriteRegStr HKEY_CLASSES_ROOT "Applications\net.solemnwarning.rehex\shell\open\command" "" "$\"$INSTDIR\rehex.exe$\" $\"%1$\""
	WriteRegNone HKEY_CLASSES_ROOT "*\OpenWithProgIDs" "net.solemnwarning.rehex"
SectionEnd

;--------------------------------
;Uninstaller Section

Section "Uninstall"
	Delete "$SMPROGRAMS\Reverse Engineers' Hex Editor.lnk"
	
	DeleteRegValue HKEY_CLASSES_ROOT "*\OpenWithProgIDs" "net.solemnwarning.rehex"
	DeleteRegKey HKEY_CLASSES_ROOT "Applications\net.solemnwarning.rehex"
	
	; Generate and embed list of files/directories from the distribution for deletion.
	!system "IF EXIST uninstall-files.nsh ( DEL uninstall-files.nsh )"
	!system "UnFiles.cmd rehex-${SHORT_VERSION} nsis\uninstall-files.nsh"
	!include "uninstall-files.nsh"
	
	DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\REHex"
	Delete "$INSTDIR\Uninstall.exe"
	
	RMDir "$INSTDIR"
SectionEnd
