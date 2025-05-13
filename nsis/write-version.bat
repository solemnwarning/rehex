@echo off

call %~dp0\..\msvc\version.bat
if %errorlevel% neq 0 exit /b %errorlevel%

rem Convert comma-delimeted version number to dot-delimeted
set PRODUCT_VERSION=%VERSION_WORDS:,=.%

echo ^!define PRODUCT_VERSION %PRODUCT_VERSION% > %~dp0\build\version.nsh
echo ^!define LONG_VERSION "%LONG_VERSION%" >> %~dp0\build\version.nsh
echo ^!define SHORT_VERSION "%SHORT_VERSION%" >> %~dp0\build\version.nsh

exit /b %errorlevel%
