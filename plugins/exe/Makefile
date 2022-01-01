# PE EXE/DLL parsing plugin for REHex
# Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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
	bitops52.lua \
	class.lua \
	document_stream.lua \
	enum.lua \
	kaitaistruct.lua \
	microsoft_pe.lua \
	plugin.lua \
	string_decode.lua \
	string_stream.lua \
	utils.lua

prefix      ?= /usr/local
exec_prefix ?= $(prefix)
bindir      ?= $(exec_prefix)/bin
datarootdir ?= $(prefix)/share
libdir      ?= $(exec_prefix)/lib

PLUGIN_NAME := exe
PLUGINS_INST_DIR ?= $(DESTDIR)$(libdir)/rehex

.PHONY: all
all:

.PHONY: check
check:

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
	rm -df $(PLUGINS_INST_DIR)/$(PLUGIN_NAME)/
