# File:		Makefile
# Author:	John Labenski, J Winwood
# Created:	2002
# Updated:
# Copyright: (c) 2002 Lomtick Software. All rights reserved.
#
# Makefile for wxLuaBinding library using gmake

# Override this on the command line to use your own wxluasetup.h
WXLUASETUP = wxluasetup.h

# ----------------------------------------------------------------------------
# Set path to root of wxLua
WXLUA_DIR = ../../..

# ----------------------------------------------------------------------------
# Include wxLua settings using wx-config for wxWidgets parameters

include $(WXLUA_DIR)/build/Makefile_wx-config.in

# ----------------------------------------------------------------------------

.cpp.o:
	$(CXX) -include $(WXLUASETUP) -c $(CXXFLAGS) $(APPEXTRADEFS) -o $@ $<

all: wxLuaBindAdvLib wxLuaBindAUILib wxLuaBindBaseLib wxLuaBindCoreLib wxLuaBindGLLib wxLuaBindHTMLLib wxLuaBindMediaLib wxLuaBindNetLib wxLuaBindSTCLib wxLuaBindXMLLib wxLuaBindXRCLib

clean: cleanlib cleanwxbind

cleanwxbind:
	@($(MAKE) -f Makefile_wxadv      clean)
	@($(MAKE) -f Makefile_wxaui      clean)
	@($(MAKE) -f Makefile_wxbase     clean)
	@($(MAKE) -f Makefile_wxcore     clean)
	@($(MAKE) -f Makefile_wxgl       clean)
	@($(MAKE) -f Makefile_wxhtml     clean)
	@($(MAKE) -f Makefile_wxmedia    clean)
	@($(MAKE) -f Makefile_wxnet      clean)
	@($(MAKE) -f Makefile_wxrichtext clean)
	@($(MAKE) -f Makefile_wxstc      clean)
	@($(MAKE) -f Makefile_wxxml      clean)
	@($(MAKE) -f Makefile_wxxrc      clean)


# ----------------------------------------------------------------------------
# Include wxLua targets using wx-config for wxWidgets parameters

include $(WXLUA_DIR)/build/Makefile_wx-config_targets.in

-include $(DEPFILES)
