vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lunarmodules/busted
    REF "v${VERSION}"
    SHA512 5d2079881ea77d4d722016adf0b47937c9304e89924fcb27a4537010a27c1b0bab7c9e30298b1a73f2228a91df32b99089e4dd672c72d80ce3d95fc1f9c3ab05
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
