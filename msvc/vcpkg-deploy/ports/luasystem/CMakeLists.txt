cmake_minimum_required(VERSION 3.10)
project(luasystem)

find_path(LUA_INCLUDE_DIR lua.h PATH_SUFFIXES lua)
find_library(LUA_LIBRARY lua)

add_library(luasystem
    src/bitflags.c
    src/compat.c
    src/core.c
    src/environment.c
    src/random.c
    src/term.c
    src/time.c
    src/wcwidth.c)

target_include_directories(luasystem PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(luasystem PRIVATE ${LUA_LIBRARY})

if(WIN32)
    target_link_libraries(luasystem PRIVATE Bcrypt winmm)
endif()

# If BUILD_SHARED_LIBS is ON, then add_library() will build a DLL and we can copy that to lib/lua/
# to be loaded by the Lua interpreter, otherwise the DLL as an extra target for that purpose.

if(BUILD_SHARED_LIBS)
  if(WIN32)
    add_custom_command(TARGET luasystem POST_BUILD 
    COMMAND "${CMAKE_COMMAND}" -E copy 
      "$<TARGET_FILE:luasystem>"
      "${CMAKE_INSTALL_PREFIX}/lib/lua/system/core.dll")
  else()
    add_custom_command(TARGET luasystem POST_BUILD 
    COMMAND "${CMAKE_COMMAND}" -E copy 
      "$<TARGET_FILE:luasystem>"
      "${CMAKE_INSTALL_PREFIX}/lib/lua/system/core.so")
  endif()
else()
  add_library(luasystem-module MODULE
    src/bitflags.c
    src/compat.c
    src/core.c
    src/environment.c
    src/random.c
    src/term.c
    src/time.c
    src/wcwidth.c)

  target_include_directories(luasystem-module PRIVATE ${LUA_INCLUDE_DIR})
  target_link_libraries(luasystem-module PRIVATE ${LUA_LIBRARY})

  if(WIN32)
    target_link_libraries(luasystem-module PRIVATE Bcrypt winmm)
  endif()

  set_target_properties(luasystem-module PROPERTIES OUTPUT_NAME "core")
  set_target_properties(luasystem-module PROPERTIES PREFIX "")

  install(TARGETS luasystem-module
    RUNTIME DESTINATION lib/lua/system
    LIBRARY DESTINATION lib/lua/system)
endif()

install(TARGETS luasystem
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

install(FILES
    system/init.lua
    DESTINATION share/lua/system)
