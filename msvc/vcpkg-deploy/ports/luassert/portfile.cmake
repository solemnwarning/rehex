vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lunarmodules/luassert
    REF "v${VERSION}"
    SHA512 267d31f0061376a4766c7e978bda9e4a2396c8bf959d4aaa347ad40bd286a3873441e38983e1e86ea07a1be7cf7c92d91248c4ba70d6dd4ec82f02c7f7638e9f
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
