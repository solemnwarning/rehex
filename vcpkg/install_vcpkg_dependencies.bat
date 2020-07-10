@echo off

REM get vcpkg distribution
if not exist vcpkg git clone https://github.com/Microsoft/vcpkg.git

REM build vcpkg
if not exist vcpkg\vcpkg.exe call vcpkg\bootstrap-vcpkg.bat -disableMetrics

REM install required packages
vcpkg\vcpkg.exe install --triplet x64-windows-static jansson wxwidgets capstone[arm,arm64,mips,ppc,sparc,x86]
