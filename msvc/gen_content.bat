setlocal enabledelayedexpansion

cd %~dp0
cd ..

git log -1 --format="#define LONG_VERSION \"Snapshot %%H\"" > res\version_msvc.h
if %errorlevel% neq 0 exit /b %errorlevel%

git log -1 --format="#define SHORT_VERSION \"%%H\"" >> res\version_msvc.h
if %errorlevel% neq 0 exit /b %errorlevel%

exit /b 0
