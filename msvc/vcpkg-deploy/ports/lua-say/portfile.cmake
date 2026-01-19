vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lunarmodules/say
    REF "v${VERSION}"
    SHA512 a6c3477859615d7ae0677ac7aa0cefe8bf6f43424812062b4a06145017952b176801431c5be920cb67f52c07cc3d374e8a6714233e2252a2bb6b7ed4c3e32f90
    HEAD_REF master)

file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
)

vcpkg_cmake_install()

# Remove unused debug directory
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug")

# Handle copyright
vcpkg_install_copyright(FILE_LIST ${SOURCE_PATH}/LICENSE)

# Allow empty include directory
set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)
