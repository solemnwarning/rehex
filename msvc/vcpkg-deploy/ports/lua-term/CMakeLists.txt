cmake_minimum_required(VERSION 3.10)
project(lua_term)

find_path(LUA_INCLUDE_DIR lua.h PATH_SUFFIXES lua)
find_library(LUA_LIBRARY lua)

add_library(luaterm core.c)

target_include_directories(luaterm PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(luaterm PRIVATE ${LUA_LIBRARY})

# If BUILD_SHARED_LIBS is ON, then add_library() will build a DLL and we can copy that to lib/lua/
# to be loaded by the Lua interpreter, otherwise the DLL as an extra target for that purpose.

if(BUILD_SHARED_LIBS)
  if(WIN32)
    add_custom_command(TARGET luaterm POST_BUILD 
    COMMAND "${CMAKE_COMMAND}" -E copy 
      "$<TARGET_FILE:luaterm>"
      "${CMAKE_INSTALL_PREFIX}/lib/lua/term/core.dll")
  else()
    add_custom_command(TARGET luaterm POST_BUILD 
    COMMAND "${CMAKE_COMMAND}" -E copy 
      "$<TARGET_FILE:luaterm>"
      "${CMAKE_INSTALL_PREFIX}/lib/lua/term/core.so")
  endif()
else()
  add_library(luaterm-module SHARED core.c)

  target_include_directories(luaterm-module PRIVATE ${LUA_INCLUDE_DIR})
  target_link_libraries(luaterm-module PRIVATE ${LUA_LIBRARY})

  set_target_properties(luaterm-module PROPERTIES OUTPUT_NAME "core")
  set_target_properties(luaterm-module PROPERTIES PREFIX "")

  install(TARGETS luaterm-module
    RUNTIME DESTINATION lib/lua/term
    LIBRARY DESTINATION lib/lua/term)
endif()

install(TARGETS luaterm
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

install(FILES
    term/colors.lua
    term/cursor.lua
    term/init.lua
    DESTINATION share/lua/term)
