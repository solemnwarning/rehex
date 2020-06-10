setlocal enabledelayedexpansion

set tool_exe="%1"

cd %~dp0
cd ..
cd res

%tool_exe% ../LICENSE.txt LICENSE_TXT license.c license.h
if %errorlevel% neq 0 exit /b %errorlevel%

for %%f in (*.png) do (
    set fname=%%~nf
    %tool_exe% !fname!.png !fname!_png !fname!.c !fname!.h
    if %errorlevel% neq 0 exit /b %errorlevel%
)

git log -1 --format="#define LONG_VERSION \"%%H\"" > version_msvc.h
if %errorlevel% neq 0 exit /b %errorlevel%


exit /b 0
