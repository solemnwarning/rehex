vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lunarmodules/luasystem
    REF "v${VERSION}"
    SHA512 c0aaf907bd99e471a01f9fe24ef7876eb64c7225edde799e11cc27fd3b269b1a79cd9d583a3b651a9ae4677dcad433a5739ee1a17540340b54c7d36935ac30a0
    HEAD_REF master)

file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
)

vcpkg_cmake_install()
vcpkg_copy_pdbs()

# Remove debug share
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")

# Handle copyright
vcpkg_install_copyright(FILE_LIST ${SOURCE_PATH}/LICENSE.md)

# Allow empty include directory
set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)

# Allow DLLs without import libraries
set(VCPKG_POLICY_DLLS_WITHOUT_LIBS enabled)

# Allow DLLs in lib (lib/lua specifically)
set(VCPKG_POLICY_ALLOW_DLLS_IN_LIB enabled)
