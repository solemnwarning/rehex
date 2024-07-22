setlocal enabledelayedexpansion

cd %~dp0
cd ..

rem Uncomment these lines in favour of the Git snapshot variants when tagging a release.
rem echo #define LONG_VERSION "Version x.y.z" > res\version_msvc.h
rem echo #define SHORT_VERSION "x.y.z" >> res\version_msvc.h

git log -1 --format="#define LONG_VERSION \"Snapshot %%H\"" > res\version_msvc.h
if %errorlevel% neq 0 exit /b %errorlevel%

git log -1 --format="#define SHORT_VERSION \"%%H\"" >> res\version_msvc.h
if %errorlevel% neq 0 exit /b %errorlevel%

exit /b 0
