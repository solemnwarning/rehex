cmake_minimum_required(VERSION 3.10)
project(lua_penlight)

install(
    DIRECTORY lua/pl
    DESTINATION share/lua/)
