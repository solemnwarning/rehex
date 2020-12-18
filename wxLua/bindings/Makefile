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

wxadv:
	@echo Building wxAdv
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxadv_rules.lua\"" genwxbind.lua)

wxaui:
	@echo Building wxAui
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxaui_rules.lua\"" genwxbind.lua)

wxbase:
	@echo Building wxBase
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxbase_rules.lua\"" genwxbind.lua)

wxcore:
	@echo Building wxCore
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxcore_rules.lua\"" genwxbind.lua)

wxgl:
	@echo Building wxGL
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxgl_rules.lua\"" genwxbind.lua)

wxhtml:
	@echo Building wxHtml
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxhtml_rules.lua\"" genwxbind.lua)

wxmedia:
	@echo Building wxMedia
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxmedia_rules.lua\"" genwxbind.lua)

wxnet:
	@echo Building wxNet
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxnet_rules.lua\"" genwxbind.lua)

wxpropgrid:
	@echo Building wxPropertyGrid
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxpropgrid_rules.lua\"" genwxbind.lua)

wxrichtext:
	@echo Building wxRichText
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxrichtext_rules.lua\"" genwxbind.lua)

wxstc:
	@echo Building wxStc
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxstc_rules.lua\"" genwxbind.lua)

wxwebview:
	@echo Building wxWebView
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxwebview_rules.lua\"" genwxbind.lua)

wxxml:
	@echo Building wxXml
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxxml_rules.lua\"" genwxbind.lua)

wxxrc:
	@echo Building wxXrc
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxxrc_rules.lua\"" genwxbind.lua)

# ---------------------------------------------------------------------------
# wxLua bindings

wxlua:
	@echo Building wxLua
	@($(LUA) -e"rulesFilename=\"wxlua/wxlua_rules.lua\"" genwxbind.lua)

wxlua_debugger:
	@echo Building wxLuaDebugger
	@($(LUA) -e"rulesFilename=\"wxlua_debugger/wxluadebugger_rules.lua\"" genwxbind.lua)

# ---------------------------------------------------------------------------

wxluacan:
	@echo Building wxLuaCan
	@(cd $(WXLUA_DIR)/apps/wxluacan && $(MAKE) LUA=$(LUA_ABS) genwxbind)

# ---------------------------------------------------------------------------
# Generate the datatypes file that declares all the known data types.

wxdatatypes:
	@echo Building wx DataTypes
	@($(LUA) -e"rulesFilename=\"wxwidgets/wxdatatypes_rules.lua\"" genwxbind.lua)

# ---------------------------------------------------------------------------
# make the wxluaref.htm documentation

genidocs:
	@($(LUA) -e"rulesFilename=\"genidocs_rules.lua\"" genidocs.lua)

# ---------------------------------------------------------------------------
# do nothing to clean

clean:
