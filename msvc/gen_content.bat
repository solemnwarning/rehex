setlocal enabledelayedexpansion

cd %~dp0
cd ..

echo #define LONG_VERSION "Version 0.62.1" > res\version_msvc.h
echo #define SHORT_VERSION "0.62.1" >> res\version_msvc.h

exit /b 0
