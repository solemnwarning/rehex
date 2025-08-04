@echo off

REM get vcpkg distribution
if not exist vcpkg git clone https://github.com/microsoft/vcpkg.git || exit /b %errorlevel%

REM build vcpkg
if not exist vcpkg\vcpkg.exe call vcpkg\bootstrap-vcpkg.bat -disableMetrics || exit /b %errorlevel%

call %~dp0\..\version.bat
if %errorlevel% neq 0 exit /b %errorlevel%

if not "%GIT_COMMIT_SHA%" == "" (
	rem We are building a development snapshot, automatically bump the baseline version to track
	rem the current HEAD of vcpkg, releases will remain pinned at the tag version.

	pushd vcpkg || exit /b %errorlevel%
	git pull --ff-only || exit /b %errorlevel%
	popd || exit /b %errorlevel%

	vcpkg\vcpkg.exe x-update-baseline --x-manifest-root=vcpkg-deploy || exit /b %errorlevel%
)

copy /Y vcpkg-deploy\vcpkg.json "%2\vcpkg.json" || exit /b %errorlevel%
vcpkg\vcpkg.exe install --overlay-triplets="%~dp0triplets" --overlay-ports="%~dp0ports" --triplet %1 --x-manifest-root="%2" || exit /b %errorlevel%
