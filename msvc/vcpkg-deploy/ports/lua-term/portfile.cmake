vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO hoelzro/lua-term
    REF "${VERSION}"
    SHA512 6b4562653d694e0865aeda785d0f3bccef355b0e05e9472892a73d5a649ccaab455a62357ef024fee106aef28390bd3e312a633b34ed4954b813aa9aeadffcd0
    HEAD_REF master
    PATCHES
        win-dll-export.patch)

file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
)

vcpkg_cmake_install()
vcpkg_copy_pdbs()

# Remove debug share
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")

# Handle copyright
vcpkg_install_copyright(FILE_LIST ${SOURCE_PATH}/COPYING)

# Allow empty include directory
set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)

# Allow DLLs without import libraries
set(VCPKG_POLICY_DLLS_WITHOUT_LIBS enabled)

# Allow DLLs in lib (lib/lua specifically)
set(VCPKG_POLICY_ALLOW_DLLS_IN_LIB enabled)
