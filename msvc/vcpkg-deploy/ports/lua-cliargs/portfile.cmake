vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lunarmodules/lua_cliargs
    REF "v${VERSION}"
    SHA512 3d9dac4723e8a41284eb28a7d1b5c400add91de055eb59645406929f5091c52bd71640b5f4914597b222b5ce7b43bbc918e4a34a69ce7bae726638bd2447abf8
    HEAD_REF master)

file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_TYPE=${BUILD_TYPE}
)

vcpkg_cmake_install()

# Remove unused debug directory
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug")

# Handle copyright
vcpkg_install_copyright(FILE_LIST ${SOURCE_PATH}/LICENSE)

# Allow empty include directory
set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)
