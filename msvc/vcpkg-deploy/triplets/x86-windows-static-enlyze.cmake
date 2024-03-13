# This triplet is tested in vcpkg ci via https://github.com/microsoft/vcpkg/pull/25897
set(VCPKG_TARGET_ARCHITECTURE x86)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)

STRING(REPLACE "\\" "/" SOLUTION_DIR $ENV{REHEX_SOLUTION_DIR})

string(CONCAT VCPKG_LINKER_FLAGS_RELEASE
    "/LIBPATH:\"${SOLUTION_DIR}/EnlyzeWinCompatLib/EnlyzeWinCompatLib/build/Release/EnlyzeWinCompatLib/bin\""
    " /LIBPATH:\"${SOLUTION_DIR}/EnlyzeWinCompatLib/EnlyzeWinCompatLib/build/Release/winpthreads/bin\""
    " /LIBPATH:\"${SOLUTION_DIR}/EnlyzeWinCompatLib/EnlyzeWinCompatLib/build/Release/libc++/bin\""
    " libc++.lib winpthreads.lib libcpmt.lib")

string(CONCAT VCPKG_LINKER_FLAGS_DEBUG
    "/LIBPATH:\"${SOLUTION_DIR}/EnlyzeWinCompatLib/EnlyzeWinCompatLib/build/Debug/EnlyzeWinCompatLib/bin\""
    " /LIBPATH:\"${SOLUTION_DIR}/EnlyzeWinCompatLib/EnlyzeWinCompatLib/build/Debug/winpthreads/bin\""
    " /LIBPATH:\"${SOLUTION_DIR}/EnlyzeWinCompatLib/EnlyzeWinCompatLib/build/Debug/libc++/bin\""
    " libc++.lib winpthreads.lib libcpmtd.lib")

## Toolchain setup
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/x64-win-llvm/x64-win-llvm.toolchain.cmake")
set(VCPKG_LOAD_VCVARS_ENV ON) # Setting VCPKG_CHAINLOAD_TOOLCHAIN_FILE deactivates automatic vcvars setup so reenable it!

if(DEFINED VCPKG_PLATFORM_TOOLSET) # Tricks vcpkg to load vcvars for a VCPKG_PLATFORM_TOOLSET which is not vc14[0-9]
    set(VCPKG_PLATFORM_TOOLSET ClangCL)
endif()
set(VCPKG_ENV_PASSTHROUGH_UNTRACKED "LLVMInstallDir;LLVMToolsVersion") # For the ClangCL toolset
set(VCPKG_QT_TARGET_MKSPEC win32-clang-msvc) # For Qt5

## Policy settings
set(VCPKG_POLICY_SKIP_ARCHITECTURE_CHECK enabled)
set(VCPKG_POLICY_SKIP_DUMPBIN_CHECKS enabled)

set(VCPKG_C_FLAGS "/I\"${SOLUTION_DIR}/EnlyzeWinCompatLib/include\" /I\"${SOLUTION_DIR}/EnlyzeWinCompatLib/EnlyzeWinCompatLib/src/libcxx/src/winpthreads/include\"")
set(VCPKG_CXX_FLAGS "/I\"${SOLUTION_DIR}/EnlyzeWinCompatLib/include\" /I\"${SOLUTION_DIR}/EnlyzeWinCompatLib/EnlyzeWinCompatLib/src/libcxx/include\" /I\"${SOLUTION_DIR}/EnlyzeWinCompatLib/EnlyzeWinCompatLib/src/libcxx/src/winpthreads/include\"")

unset(SOLUTION_DIR)

## Extra scripts which should not directly be hashed so that changes don't nuke the complete installed tree in manifest mode
## Note: This breaks binary caching so don't apply changes to these files unkowningly. 
include("${CMAKE_CURRENT_LIST_DIR}/x64-win-llvm/extra_setup.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/x64-win-llvm/port_specialization.cmake")

set(BOTAN_USE_WINSOCK2 OFF)
