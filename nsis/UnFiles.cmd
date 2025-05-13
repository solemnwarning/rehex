@rem NSIS Uninstall Header Recursive File List Maker
@rem Copyright 2014 Aleksandr Ivankiv, 2017 Dani Mantovani

@SET DIR=%~1
@SET HEADER=%~2
@IF "%~1" == "/?" goto Help
@IF NOT DEFINED DIR goto Help
@IF NOT DEFINED HEADER SET HEADER=UnFiles.nsh
@IF NOT EXIST "%DIR%" ECHO Error: Cannot find the folder %DIR%. & SET "DIR=" & goto :EOF

@SetLocal EnableDelayedExpansion

IF %DIR:~-1%==\ SET DIR=%DIR:~0,-1%

@FOR /F "tokens=*" %%f IN ('DIR %DIR%\*.* /A:-D /B /S') DO @(
  set string=%%f
  set string=!string:%CD%\%DIR%=!
  set string=!string:$=$$!
  echo Delete "$OUTDIR\!string:~1!" >> %HEADER%
  echo !string:~1!
)

@FOR /F "tokens=*" %%d IN ('DIR %DIR%\*.* /A:D /B /S ^| SORT /R') DO @(
  set string=%%d
  set string=!string:%CD%\%DIR%=!
  set string=!string:$=$$!
  echo RMDir "$OUTDIR\!string:~1!" >> %HEADER%
  echo !string:~1!
)

@EndLocal
@goto :EOF

:Help
@echo.
@echo Usage: UnFiles FolderName [OutFile]
@echo.
@goto :EOF
