setlocal enabledelayedexpansion

set tool_exe="%1"

cd %~dp0
cd ..
cd res

git log -1 --format="#define LONG_VERSION \"%%H\"" > version_msvc.h
if %errorlevel% neq 0 exit /b %errorlevel%


exit /b 0
