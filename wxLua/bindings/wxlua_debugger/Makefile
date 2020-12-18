# File:		Makefile
# Author:	John Labenski, J Winwood
# Created:	2002
# Updated:
# Copyright: (c) 2002. J Winwood

WXLUA_DIR = ../..

all: genwxbind

genwxbind:
	@(cd $(WXLUA_DIR)/bindings && ../bin/lua -e"rulesFilename=\"wxlua_debugger/wxluadebugger_rules.lua\"" genwxbind.lua)

# do nothing to clean
clean:
