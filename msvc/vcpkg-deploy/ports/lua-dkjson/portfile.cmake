vcpkg_download_distfile(DKJSON_LUA
    URLS "https://dkolf.de/dkjson-lua/dkjson-${VERSION}.lua"
    FILENAME "dkjson-${VERSION}.lua"
    SHA512 1ae54f58b3cf7c2c38e332605a26979646e2867cc8d1824291a1673516442c14c15d967b5a09494415c6f5eade10c684f86e4c1aea733e072c3c64b9f59e1ee0
)

set(SOURCE_PATH "${CURRENT_BUILDTREES_DIR}/src/")

file(REMOVE_RECURSE "${SOURCE_PATH}")
make_directory("${SOURCE_PATH}")

file(COPY "${DKJSON_LUA}" DESTINATION "${SOURCE_PATH}")
file(RENAME "${SOURCE_PATH}/dkjson-${VERSION}.lua" "${SOURCE_PATH}/dkjson.lua")

file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
)

vcpkg_cmake_install()

# License extracted from the library source
file(WRITE "${CURRENT_PACKAGES_DIR}/share/${PORT}/copyright" [[
Copyright (C) 2010-2024 David Heiko Kolf

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]])

# Remove unused debug directory
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug")

# Allow empty include directory
set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)
