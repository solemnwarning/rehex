@echo off

rem This script is CALLed by other batch scripts on Windows to get the REHex version.
rem In releases, this should be replaced with a static script like the following:
rem
rem set LONG_VERSION=Version 1.2.3
rem set SHORT_VERSION=1.2.3
rem set VERSION_WORDS=1,2,3,0

pushd %~dp0
cd ..

for /f "delims=" %%i in ('git log -1 "--format=%%H"') do set GIT_COMMIT_SHA=%%i
if %errorlevel% neq 0 exit /b %errorlevel%

set LONG_VERSION=Snapshot %GIT_COMMIT_SHA%
set SHORT_VERSION=%GIT_COMMIT_SHA%
set VERSION_WORDS=0,0,0,0

popd

exit /b 0
