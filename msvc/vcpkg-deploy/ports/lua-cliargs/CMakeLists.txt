cmake_minimum_required(VERSION 3.10)
project(lua_cliargs)

install(FILES
    src/cliargs.lua
    DESTINATION share/lua)

install(FILES
    src/cliargs/config_loader.lua
    src/cliargs/constants.lua
    src/cliargs/core.lua
    src/cliargs/parser.lua
    src/cliargs/printer.lua
    DESTINATION share/lua/cliargs)

install(FILES
    src/cliargs/utils/disect.lua
    src/cliargs/utils/disect_argument.lua
    src/cliargs/utils/filter.lua
    src/cliargs/utils/lookup.lua
    src/cliargs/utils/shallow_copy.lua
    src/cliargs/utils/split.lua
    src/cliargs/utils/trim.lua
    src/cliargs/utils/wordwrap.lua
    DESTINATION share/lua/cliargs/utils)
