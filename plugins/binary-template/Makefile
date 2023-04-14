# Binary Template plugin for REHex
# Copyright (C) 2021-2023 Daniel Collins <solemnwarning@solemnwarning.net>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

INSTALL_FILES := \
	executor.lua \
	executor/arrayindexvalue.lua \
	executor/arrayvalue.lua \
	executor/filearrayvalue.lua \
	executor/filevalue.lua \
	executor/immediatevalue.lua \
	executor/plainvalue.lua \
	executor/structvalue.lua \
	parser.lua \
	plugin.lua \
	preprocessor.lua \
	lulpeg/lulpeg.lua \
	templates/riff.bt

prefix      ?= /usr/local
exec_prefix ?= $(prefix)
bindir      ?= $(exec_prefix)/bin
datarootdir ?= $(prefix)/share
libdir      ?= $(exec_prefix)/lib

LUA ?= lua

PLUGIN_NAME := binary-template
PLUGINS_INST_DIR ?= $(DESTDIR)$(libdir)/rehex

ifeq ($(BUSTED),)
	# LuaRocks under MinGW doesn't install busted under a bin/ directory - it sticks it
	# elsewhere and puts a .bat that runs it under the right Lua environment for Reasons.
	
	BUSTED := $(shell busted --version > /dev/null 2>&1 && echo busted --lua=$(LUA))
	ifeq ($(BUSTED),)
		BUSTED := $(shell busted.bat --version > /dev/null 2>&1 && echo busted.bat --lua=$(LUA))
	endif
	
	ifeq ($(BUSTED),)
		X := $(error Neither busted or busted.bat found in PATH)
	endif
endif

.PHONY: all
all:

.PHONY: check
check:
	$(BUSTED) .

.PHONY: install
install:
	for f in $(INSTALL_FILES); \
	do \
		mkdir -p $(PLUGINS_INST_DIR)/$(PLUGIN_NAME)/`dirname $${f}`; \
		install -m 0644 $${f} $(PLUGINS_INST_DIR)/$(PLUGIN_NAME)/$${f}; \
	done

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(PLUGINS_INST_DIR)/$(PLUGIN_NAME)/,$(INSTALL_FILES))
	
	rm -df $(PLUGINS_INST_DIR)/$(PLUGIN_NAME)/templates/
	rm -df $(PLUGINS_INST_DIR)/$(PLUGIN_NAME)/lulpeg/
	rm -df $(PLUGINS_INST_DIR)/$(PLUGIN_NAME)/
