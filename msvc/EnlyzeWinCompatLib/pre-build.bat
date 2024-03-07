cd "%~dp0"

rem if not exist EnlyzeWinCompatLib git clone --recursive https://github.com/enlyze/EnlyzeWinCompatLib.git
if not exist EnlyzeWinCompatLib git clone --recursive https://github.com/solemnwarning/EnlyzeWinCompatLib.git

cd EnlyzeWinCompatLib\src || EXIT /B
msbuild EnlyzeWinCompatLib.sln /p:Configuration="Release" /p:Platform="x86" || EXIT /B
msbuild EnlyzeWinCompatLib.sln /p:Configuration="Debug"   /p:Platform="x86" || EXIT /B
