cmake_minimum_required(VERSION 3.10)
project(lua_busted)

install(
    FILES busted.lua
    DESTINATION share/lua/)

install(
    DIRECTORY busted
    DESTINATION share/lua/)

install(
    FILES bin/busted
    DESTINATION share/lua/busted/
    RENAME main.lua)

if(WIN32)
    file(WRITE "busted.bat" [[
        @echo off
        set LUA_PATH=%LUA_PATH%;%~dp0\..\..\share\lua\?.lua;%~dp0\..\..\share\lua\?\init.lua
        set LUA_CPATH=%LUA_PATH%;%~dp0\..\..\lib\lua\?.dll
        "%~dp0\..\lua\lua.exe" -- "%~dp0\..\..\share\lua\busted\main.lua" %*
        exit /b %ERRORLEVEL%
    ]])
    
    install(
        FILES busted.bat
        DESTINATION tools/lua-busted/)
else()
    install(
        FILES bin/busted
        DESTINATION tools/lua-busted/)
endif()
