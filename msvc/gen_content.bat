@echo off

call %~dp0\version.bat
if %errorlevel% neq 0 exit /b %errorlevel%

echo #define LONG_VERSION "%LONG_VERSION%" > %~dp0\..\res\version-defs.h
echo #define SHORT_VERSION "%SHORT_VERSION%" >> %~dp0\..\res\version-defs.h
echo #define VERSION_WORDS %VERSION_WORDS% >> %~dp0\..\res\version-defs.h

if not "%GIT_COMMIT_SHA%" == "" (
	echo #define REHEX_GIT >> %~dp0\..\res\version-defs.h
)

IF "%1" == "Release" (
	echo #define REHEX_RELEASE >> %~dp0\..\res\version-defs.h
)

exit /b %errorlevel%
