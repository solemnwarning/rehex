# Make all the bindings in Linux or in Cygwin.

# The root wxLua directory.
WXLUA_DIR    = ../

#----------------------------------------------------------------------------

# If we're using cygwin, the lua executable maybe elsewhere, try some common places.
# Note some other variables cygwin sets don't seem to be exported.
ifeq (Cygwin, $(findstring Cygwin, $(XTERM_VERSION)))
	LUA=$(WXLUA_DIR)/bin/vc_lib/lua.exe
else
	LUA=$(WXLUA_DIR)/bin/lua
endif

LUA_ABS = $(realpath $(LUA))

#----------------------------------------------------------------------------

ALL_BINDINGS = wxbase wxcore wxadv wxaui wxgl wxhtml wxnet wxmedia wxstc wxxml wxxrc wxpropgrid wxrichtext wxwebview wxlua wxlua_debugger wxluacan wxdatatypes

# Always try to build all targets, let the other Makefiles do dep checking
.PHONY: all clean genidocs $(ALL_BINDINGS)

# These have to be in order of their dependencies
all: $(ALL_BINDINGS)

#----------------------------------------------------------------------------
# wxWidgets bindings

wxadv: wxcore
	@echo Building wxAdv
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxadv_rules.lua\"" genwxbind.lua)

wxaui: wxcore
	@echo Building wxAui
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxaui_rules.lua\"" genwxbind.lua)

wxbase:
	@echo Building wxBase
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxbase_rules.lua\"" genwxbind.lua)

wxcore: wxbase
	@echo Building wxCore
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxcore_rules.lua\"" genwxbind.lua)

wxgl: wxcore
	@echo Building wxGL
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxgl_rules.lua\"" genwxbind.lua)

wxhtml: wxcore
	@echo Building wxHtml
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxhtml_rules.lua\"" genwxbind.lua)

wxmedia: wxcore wxnet
	@echo Building wxMedia
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxmedia_rules.lua\"" genwxbind.lua)

wxnet: wxcore
	@echo Building wxNet
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxnet_rules.lua\"" genwxbind.lua)

wxpropgrid: wxcore
	@echo Building wxPropertyGrid
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxpropgrid_rules.lua\"" genwxbind.lua)

wxrichtext: wxcore
	@echo Building wxRichText
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxrichtext_rules.lua\"" genwxbind.lua)

wxstc: wxcore
	@echo Building wxStc
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxstc_rules.lua\"" genwxbind.lua)

wxwebview: wxcore
	@echo Building wxWebView
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxwebview_rules.lua\"" genwxbind.lua)

wxxml: wxbase
	@echo Building wxXml
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxxml_rules.lua\"" genwxbind.lua)

wxxrc: wxcore
	@echo Building wxXrc
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxxrc_rules.lua\"" genwxbind.lua)

# ---------------------------------------------------------------------------
# wxLua bindings

wxlua: wxbase
	@echo Building wxLua
	@($(LUA) -e"rulesFilename=\"wxlua/wxlua_rules.lua\"" genwxbind.lua)

wxlua_debugger: wxcore
	@echo Building wxLuaDebugger
	@($(LUA) -e"rulesFilename=\"wxlua_debugger/wxluadebugger_rules.lua\"" genwxbind.lua)

# ---------------------------------------------------------------------------

wxluacan: wxdatatypes
	@echo Building wxLuaCan
	@(cd $(WXLUA_DIR)/apps/wxluacan && $(MAKE) LUA=$(LUA_ABS) genwxbind)

# ---------------------------------------------------------------------------
# Generate the datatypes file that declares all the known data types.

wxdatatypes: wxadv wxaui wxbase wxcore wxgl wxhtml wxmedia wxnet wxrichtext wxstc wxxml wxxrc
	@echo Building wx DataTypes
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxdatatypes_rules.lua\"" genwxbind.lua)

# ---------------------------------------------------------------------------
# make the wxluaref.htm documentation

genidocs:
	@($(LUA) -e"rulesFilename=\"genidocs_rules.lua\"" genidocs.lua)

# ---------------------------------------------------------------------------
# do nothing to clean

clean:
