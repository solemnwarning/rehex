setlocal enabledelayedexpansion

cd %~dp0
cd ..

git log -1 --format="#define LONG_VERSION \"Version 0.62.0\"" > res\version_msvc.h
if %errorlevel% neq 0 exit /b %errorlevel%

git log -1 --format="#define SHORT_VERSION \"0.62.0\"" >> res\version_msvc.h
if %errorlevel% neq 0 exit /b %errorlevel%

exit /b 0
