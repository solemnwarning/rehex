cmake_minimum_required(VERSION 3.10)
project(lua_say)

install(FILES
    src/say/init.lua
    DESTINATION share/lua/say/)
