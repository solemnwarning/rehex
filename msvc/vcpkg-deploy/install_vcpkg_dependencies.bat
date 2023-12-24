@echo off

REM get vcpkg distribution
if not exist vcpkg git clone https://github.com/microsoft/vcpkg.git

REM build vcpkg
if not exist vcpkg\vcpkg.exe call vcpkg\bootstrap-vcpkg.bat -disableMetrics

REM install required packages
vcpkg\vcpkg.exe install --overlay-triplets=%2 --triplet %1 botan jansson wxwidgets capstone[arm,arm64,mips,ppc,sparc,x86] lua[tools] libiconv libunistring
