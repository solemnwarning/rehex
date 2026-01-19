cmake_minimum_required(VERSION 3.10)
project(luassert)

install(FILES
    src/array.lua
    src/assert.lua
    src/assertions.lua
    src/compatibility.lua
    src/init.lua
    src/match.lua
    src/mock.lua
    src/modifiers.lua
    src/namespaces.lua
    src/spy.lua
    src/state.lua
    src/stub.lua
    src/util.lua
    DESTINATION share/lua/luassert/)

install(FILES
    src/formatters/init.lua
    src/formatters/binarystring.lua
    DESTINATION share/lua/luassert/formatters/)

install(FILES
    src/languages/ar.lua
    src/languages/de.lua
    src/languages/en.lua
    src/languages/fr.lua
    src/languages/is.lua
    src/languages/ja.lua
    src/languages/nl.lua
    src/languages/ru.lua
    src/languages/ua.lua
    src/languages/zh.lua
    DESTINATION share/lua/luassert/languages/)

install(FILES
    src/matchers/init.lua
    src/matchers/core.lua
    src/matchers/composite.lua
    DESTINATION share/lua/luassert/matchers/)
