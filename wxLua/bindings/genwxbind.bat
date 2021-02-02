@echo off
REM This batch generates all the wxLua C++ source files from interface files.
REM The C++ source files are only modified if any changes have been made.
REM @echo on
SET LUA=lua.exe

REM Find a suitable lua.exe to run
IF EXIST ..\bin\lua.exe SET LUA=..\bin\lua.exe

IF EXIST ..\bin\gccud_lib\lua.exe SET LUA=..\bin\gccud_lib\lua.exe
IF EXIST ..\bin\gccud_dll\lua.exe SET LUA=..\bin\gccud_dll\lua.exe
IF EXIST ..\bin\gccu_lib\lua.exe SET LUA=..\bin\gccu_lib\lua.exe
IF EXIST ..\bin\gccu_dll\lua.exe SET LUA=..\bin\gccu_dll\lua.exe
IF EXIST ..\bin\gccd_lib\lua.exe SET LUA=..\bin\gccd_lib\lua.exe
IF EXIST ..\bin\gccd_dll\lua.exe SET LUA=..\bin\gccd_dll\lua.exe
IF EXIST ..\bin\gcc_lib\lua.exe SET LUA=..\bin\gcc_lib\lua.exe
IF EXIST ..\bin\gcc_dll\lua.exe SET LUA=..\bin\gcc_dll\lua.exe

IF EXIST ..\bin\vcud_lib\lua.exe SET LUA=..\bin\vcud_lib\lua.exe
IF EXIST ..\bin\vcud_dll\lua.exe SET LUA=..\bin\vcud_dll\lua.exe
IF EXIST ..\bin\vcu_lib\lua.exe SET LUA=..\bin\vcu_lib\lua.exe
IF EXIST ..\bin\vcu_dll\lua.exe SET LUA=..\bin\vcu_dll\lua.exe
IF EXIST ..\bin\vcd_lib\lua.exe SET LUA=..\bin\vcd_lib\lua.exe
IF EXIST ..\bin\vcd_dll\lua.exe SET LUA=..\bin\vcd_dll\lua.exe
IF EXIST ..\bin\vc_lib\lua.exe SET LUA=..\bin\vc_lib\lua.exe
IF EXIST ..\bin\vc_dll\lua.exe SET LUA=..\bin\vc_dll\lua.exe

echo Using this Lua executable: %LUA%

echo Generating wxWidgets wxbase Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxbase_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxcore Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxcore_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxadv Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxadv_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxaui Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxaui_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxgl Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxgl_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxhtml Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxhtml_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxnet Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxnet_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxmedia Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxmedia_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxstc Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxstc_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxxml Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxxml_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxxrc Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxxrc_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxrichtext Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxrichtext_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxpropgrid Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxpropgrid_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxwebview_rules Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxwebview_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxlua Binding
%LUA% -e"rulesFilename=\"wxlua/wxlua_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxluadebugger Binding
%LUA% -e"rulesFilename=\"wxlua_debugger/wxluadebugger_rules.lua\"" genwxbind.lua

echo Generating wxWidgets wxdatatypes Binding
%LUA% -e"rulesFilename=\"wxwidgets/wxdatatypes_rules.lua\"" genwxbind.lua

echo Generating wxLuaCan app Binding
cd ..\apps\wxluacan
%LUA% -e"rulesFilename=\"wxluacan_rules.lua\"" ../../bindings/genwxbind.lua
cd ..\..\bindings

echo Done.
