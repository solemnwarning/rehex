setlocal enabledelayedexpansion

cd %~dp0
cd ..
cd res

git log -1 --format="#define LONG_VERSION \"Snapshot %%H\"" > version_msvc.h
if %errorlevel% neq 0 exit /b %errorlevel%

exit /b 0
