cmake_minimum_required(VERSION 3.10)
project(lua_mediator)

install(FILES
    src/mediator.lua
    DESTINATION share/lua/)
