# Reverse Engineer's Hex Editor
# Copyright (C) 2017-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

LUA          ?= lua
WX_CONFIG    ?= wx-config
CAPSTONE_PKG ?= capstone
JANSSON_PKG  ?= jansson
LUA_PKG      ?= $(shell pkg-config --exists lua5.3 && echo lua5.3 || echo lua)

EXE ?= rehex
EMBED_EXE ?= ./tools/embed
GTKCONFIG_EXE ?= ./tools/gtk-config
HELP_TARGET ?= help/rehex.htb

# Wrapper around the $(shell) function that aborts the build if the command
# exits with a nonzero status.
shell-or-die = $\
	$(eval sod_out := $$(shell $(1); echo $$$$?))$\
	$(if $(filter 0,$(lastword $(sod_out))),$\
		$(wordlist 1, $(shell echo $$(($(words $(sod_out)) - 1))), $(sod_out)),$\
		$(error $(1) exited with status $(lastword $(sod_out))))

# Check if we are building target(s) that don't need to compile anything and
# skip fetching compiler flags from wx-config/pkg-config/etc if so, this avoids
# having to have our dependencies on build hosts that are going to use a chroot
# or other container for doing the actual build.

NONCOMPILE_TARGETS=clean distclean dist

need_compiler_flags=1
ifneq ($(MAKECMDGOALS),)
	ifeq ($(filter-out $(NONCOMPILE_TARGETS),$(MAKECMDGOALS)),)
		need_compiler_flags=0
	endif
endif

ifeq ($(BUILD_HELP),)
	BUILD_HELP=1
endif

ifeq ($(BUILD_HELP),0)
	HELP_TARGET :=
else
	HELP_CFLAGS := -DBUILD_HELP
	HELP_LIBS := html
endif

ifeq ($(need_compiler_flags),1)
	WX_CXXFLAGS ?= $(call shell-or-die,$(WX_CONFIG) --cxxflags base core aui propgrid adv $(HELP_LIBS))
	WX_LIBS     ?= $(call shell-or-die,$(WX_CONFIG) --libs     base core aui propgrid adv $(HELP_LIBS))
	
	CAPSTONE_CFLAGS ?= $(call shell-or-die,pkg-config $(CAPSTONE_PKG) --cflags)
	CAPSTONE_LIBS   ?= $(call shell-or-die,pkg-config $(CAPSTONE_PKG) --libs)
	
	JANSSON_CFLAGS ?= $(call shell-or-die,pkg-config $(JANSSON_PKG) --cflags)
	JANSSON_LIBS   ?= $(call shell-or-die,pkg-config $(JANSSON_PKG) --libs)
	
	LUA_CFLAGS ?= $(call shell-or-die,pkg-config $(LUA_PKG) --cflags)
	LUA_LIBS   ?= $(call shell-or-die,pkg-config $(LUA_PKG) --libs)
	
	GTK_CFLAGS = $$($(GTKCONFIG_EXE) --cflags)
	GTK_LIBS   = $$($(GTKCONFIG_EXE) --libs)
endif

ifeq ($(DEBUG),)
	DEBUG=0
endif

ifeq ($(DEBUG),0)
	DEBUG_CFLAGS := -DNDEBUG
else
	DEBUG_CFLAGS := -ggdb
endif

ifeq ($(PROFILE),)
	PROFILE=0
endif

ifeq ($(PROFILE),0)
	PROFILE_CFLAGS :=
else
	PROFILE_CFLAGS := -DREHEX_PROFILE
endif

CFLAGS          := -Wall -std=c99   -I. -Iinclude/ -IwxLua/modules/ -DREHEX_CACHE_CHARACTER_BITMAPS $(DEBUG_CFLAGS) $(PROFILE_CFLAGS) $(HELP_CFLAGS) $(CAPSTONE_CFLAGS) $(JANSSON_CFLAGS) $(LUA_CFLAGS) $(CFLAGS)
CXXFLAGS_NO_GTK := -Wall -std=c++11 -I. -Iinclude/ -IwxLua/modules/ -DREHEX_CACHE_CHARACTER_BITMAPS $(DEBUG_CFLAGS) $(PROFILE_CFLAGS) $(HELP_CFLAGS) $(CAPSTONE_CFLAGS) $(JANSSON_CFLAGS) $(LUA_CFLAGS) $(WX_CXXFLAGS) $(CXXFLAGS)
CXXFLAGS        := -Wall -std=c++11 -I. -Iinclude/ -IwxLua/modules/ -DREHEX_CACHE_CHARACTER_BITMAPS $(DEBUG_CFLAGS) $(PROFILE_CFLAGS) $(HELP_CFLAGS) $(CAPSTONE_CFLAGS) $(JANSSON_CFLAGS) $(LUA_CFLAGS) $(WX_CXXFLAGS) $(GTK_CFLAGS) $(CXXFLAGS)

uname_S := $(shell uname -s 2>/dev/null)
ifeq ($(uname_S),FreeBSD)
	LDLIBS += -liconv
endif
ifeq ($(uname_S),OpenBSD)
	LDLIBS += -liconv
endif

LDLIBS := -lunistring $(WX_LIBS) $(GTK_LIBS) $(CAPSTONE_LIBS) $(JANSSON_LIBS) $(LUA_LIBS) $(LDLIBS)

# Define this for releases
VERSION := 0.5.2

ifdef VERSION
	LONG_VERSION := Version $(VERSION)
else
	# Check if we are actually in a git checkout before trying to get the
	# commit hash with `git log`, else we blow up in a git-archive export.
	
	ifneq ($(wildcard .git/*),)
		GIT_COMMIT_SHA ?= $(call shell-or-die,git log -1 --format="%H")
	else
		GIT_COMMIT_SHA ?= UNKNOWN
	endif
	
	GIT_COMMIT_TIME ?= $(call shell-or-die,git log -1 --format="%ct")
	
	VERSION      := 9db2df2bf978e53b876b706dca28ea3ededcbd1a
	LONG_VERSION := Snapshot 9db2df2bf978e53b876b706dca28ea3ededcbd1a
endif

DEPDIR := .d
DEPPRE = @mkdir -p "$(dir $(DEPDIR)/$@.Td)"
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$@.Td
DEPPOST = @mv -f $(DEPDIR)/$@.Td $(DEPDIR)/$@.d && touch $@

WXLUA_BINDINGS := wxLua/bindings/.done

.PHONY: all
all: $(EXE)

# Stop Make from deleting intermediate files at-will. Some intermediates (e.g. resources) are used
# by multiple targets (all and test) and so they should persist. Others are generated as a
# side-effect of another target (wxLua bindings) so Make cannot properly track how to build them
# when it needs to recreate them later.
.SECONDARY:

.PHONY: check
check: tests/all-tests
	./tests/all-tests
	
	for p in $(PLUGINS); \
	do \
		$(MAKE) -C plugins/$${p} LUA=$(LUA) check || exit $$?; \
	done

.PHONY: clean
clean:
	rm -f res/ascii16.c   res/ascii16.h \
	      res/ascii24.c   res/ascii24.h \
	      res/ascii32.c   res/ascii32.h \
	      res/ascii48.c   res/ascii48.h \
	      res/diff_fold16.c res/diff_fold16.h \
	      res/diff_fold24.c res/diff_fold24.h \
	      res/diff_fold32.c res/diff_fold32.h \
	      res/diff_fold48.c res/diff_fold48.h \
	      res/icon16.c    res/icon16.h \
	      res/icon32.c    res/icon32.h \
	      res/icon48.c    res/icon48.h \
	      res/icon64.c    res/icon64.h \
	      res/icon128.c   res/icon128.h \
	      res/license.c   res/license.h   res/license.done \
	      res/offsets16.c res/offsets16.h \
	      res/offsets24.c res/offsets24.h \
	      res/offsets32.c res/offsets32.h \
	      res/offsets48.c res/offsets48.h \
	      res/spinner24.c   res/spinner24.h
	
	rm -f $(APP_OBJS)
	rm -f $(EXE)
	rm -f $(TEST_OBJS)
	rm -f ./tests/all-tests
	rm -f $(EMBED_EXE)
	rm -f $(GTKCONFIG_EXE)
	
	grep -r "generated by genwxbind.lua" wxLua/ --exclude=genwxbind.lua | cut -d: -f1 | sort | uniq | xargs -r rm
	rm -f $(WXLUA_BINDINGS)
	
	rm -f src/lua-bindings/rehex_bind.done src/lua-bindings/rehex_bind.cpp src/lua-bindings/rehex_bind.h
	rm -f src/lua-plugin-preload.done src/lua-plugin-preload.c src/lua-plugin-preload.h

.PHONY: distclean
distclean: clean

WXLUA_OBJS := \
	wxLua/modules/wxlua/bit.o \
	wxLua/modules/wxlua/lbitlib.o \
	wxLua/modules/wxlua/wxlbind.o \
	wxLua/modules/wxlua/wxlcallb.o \
	wxLua/modules/wxlua/wxllua.o \
	wxLua/modules/wxlua/wxlobject.o \
	wxLua/modules/wxlua/wxlstate.o \
	wxLua/modules/wxlua/wxlua_bind.o

WXBIND_OBJS := \
	wxLua/modules/wxbind/src/wxadv_bind.o \
	wxLua/modules/wxbind/src/wxadv_wxladv.o \
	wxLua/modules/wxbind/src/wxaui_bind.o \
	wxLua/modules/wxbind/src/wxbase_base.o \
	wxLua/modules/wxbind/src/wxbase_bind.o \
	wxLua/modules/wxbind/src/wxbase_config.o \
	wxLua/modules/wxbind/src/wxbase_data.o \
	wxLua/modules/wxbind/src/wxbase_datetime.o \
	wxLua/modules/wxbind/src/wxbase_file.o \
	wxLua/modules/wxbind/src/wxcore_appframe.o \
	wxLua/modules/wxbind/src/wxcore_bind.o \
	wxLua/modules/wxbind/src/wxcore_clipdrag.o \
	wxLua/modules/wxbind/src/wxcore_controls.o \
	wxLua/modules/wxbind/src/wxcore_core.o \
	wxLua/modules/wxbind/src/wxcore_defsutils.o \
	wxLua/modules/wxbind/src/wxcore_dialogs.o \
	wxLua/modules/wxbind/src/wxcore_event.o \
	wxLua/modules/wxbind/src/wxcore_gdi.o \
	wxLua/modules/wxbind/src/wxcore_geometry.o \
	wxLua/modules/wxbind/src/wxcore_graphics.o \
	wxLua/modules/wxbind/src/wxcore_help.o \
	wxLua/modules/wxbind/src/wxcore_image.o \
	wxLua/modules/wxbind/src/wxcore_mdi.o \
	wxLua/modules/wxbind/src/wxcore_menutool.o \
	wxLua/modules/wxbind/src/wxcore_picker.o \
	wxLua/modules/wxbind/src/wxcore_print.o \
	wxLua/modules/wxbind/src/wxcore_sizer.o \
	wxLua/modules/wxbind/src/wxcore_windows.o \
	wxLua/modules/wxbind/src/wxcore_wxlcore.o \
	wxLua/modules/wxbind/src/wxpropgrid_bind.o

APP_OBJS := \
	res/actual_size16.o \
	res/ascii16.o \
	res/ascii24.o \
	res/ascii32.o \
	res/ascii48.o \
	res/diff_fold16.o \
	res/diff_fold24.o \
	res/diff_fold32.o \
	res/diff_fold48.o \
	res/fit_to_screen16.o \
	res/icon16.o \
	res/icon32.o \
	res/icon48.o \
	res/icon64.o \
	res/icon128.o \
	res/license.o \
	res/offsets16.o \
	res/offsets24.o \
	res/offsets32.o \
	res/offsets48.o \
	res/spinner24.o \
	res/swap_horiz16.o \
	res/swap_vert16.o \
	res/zoom_in16.o \
	res/zoom_out16.o \
	src/AboutDialog.o \
	src/AppMain.o \
	src/AppSettings.o \
	src/AppTestable.o \
	src/ArtProvider.o \
	src/BasicDataTypes.o \
	src/BitmapTool.o \
	src/buffer.o \
	src/BytesPerLineDialog.o \
	src/ByteRangeSet.o \
	src/CharacterEncoder.o \
	src/CharacterFinder.o \
	src/ClickText.o \
	src/CodeCtrl.o \
	src/CommentTree.o \
	src/ConsoleBuffer.o \
	src/ConsolePanel.o \
	src/DataType.o \
	src/decodepanel.o \
	src/DiffWindow.o \
	src/disassemble.o \
	src/DisassemblyRegion.o \
	src/document.o \
	src/DocumentCtrl.o \
	src/EditCommentDialog.o \
	src/Events.o \
	src/FillRangeDialog.o \
	src/IntelHexExport.o \
	src/IntelHexImport.o \
	src/LicenseDialog.o \
	src/lua-bindings/rehex_bind.o \
	src/lua-plugin-preload.o \
	src/LuaPluginLoader.o \
	src/mainwindow.o \
	src/Palette.o \
	src/profile.o \
	src/search.o \
	src/SelectRangeDialog.o \
	src/StringPanel.o \
	src/textentrydialog.o \
	src/Tab.o \
	src/ToolPanel.o \
	src/util.o \
	src/VirtualMappingDialog.o \
	src/VirtualMappingList.o \
	src/win32lib.o \
	$(WXLUA_OBJS) \
	$(WXBIND_OBJS) \
	$(EXTRA_APP_OBJS)

$(EXE): $(APP_OBJS) $(GTKCONFIG_EXE)
	$(CXX) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -DLIBDIR='"$(libdir)"' -DDATADIR='"$(datadir)"' -c -o res/version.o res/version.cpp
	$(CXX) $(CXXFLAGS) -o $@ $(APP_OBJS) res/version.o $(LDFLAGS) $(LDLIBS)

TEST_OBJS := \
	googletest/src/gtest-all.o \
	res/actual_size16.o \
	res/ascii16.o \
	res/ascii24.o \
	res/ascii32.o \
	res/ascii48.o \
	res/diff_fold16.o \
	res/diff_fold24.o \
	res/diff_fold32.o \
	res/diff_fold48.o \
	res/fit_to_screen16.o \
	res/icon16.o \
	res/icon32.o \
	res/icon48.o \
	res/icon64.o \
	res/icon128.o \
	res/license.o \
	res/offsets16.o \
	res/offsets24.o \
	res/offsets32.o \
	res/offsets48.o \
	res/spinner24.o \
	res/swap_horiz16.o \
	res/swap_vert16.o \
	res/zoom_in16.o \
	res/zoom_out16.o \
	src/AboutDialog.o \
	src/AppSettings.o \
	src/AppTestable.o \
	src/ArtProvider.o \
	src/BasicDataTypes.o \
	src/BitmapTool.o \
	src/buffer.o \
	src/ByteRangeSet.o \
	src/BytesPerLineDialog.o \
	src/CharacterEncoder.o \
	src/CharacterFinder.o \
	src/ClickText.o \
	src/CommentTree.o \
	src/ConsoleBuffer.o \
	src/DataType.o \
	src/DiffWindow.o \
	src/DisassemblyRegion.o \
	src/document.o \
	src/DocumentCtrl.o \
	src/EditCommentDialog.o \
	src/Events.o \
	src/FillRangeDialog.o \
	src/IntelHexExport.o \
	src/IntelHexImport.o \
	src/LicenseDialog.o \
	src/lua-bindings/rehex_bind.o \
	src/lua-plugin-preload.o \
	src/LuaPluginLoader.o \
	src/mainwindow.o \
	src/Palette.o \
	src/search.o \
	src/SelectRangeDialog.o \
	src/StringPanel.o \
	src/Tab.o \
	src/textentrydialog.o \
	src/ToolPanel.o \
	src/util.o \
	src/VirtualMappingDialog.o \
	src/win32lib.o \
	tests/BitmapTool.o \
	tests/buffer.o \
	tests/ByteRangeMap.o \
	tests/ByteRangeSet.o \
	tests/CharacterEncoder.o \
	tests/CharacterFinder.o \
	tests/CommentsDataObject.o \
	tests/CommentTree.o \
	tests/ConsoleBuffer.o \
	tests/DiffWindow.o \
	tests/DisassemblyRegion.o \
	tests/Document.o \
	tests/DocumentCtrl.o \
	tests/FastRectangleFiller.o \
	tests/IntelHexExport.o \
	tests/IntelHexImport.o \
	tests/LuaPluginLoader.o \
	tests/main.o \
	tests/NestedOffsetLengthMap.o \
	tests/NumericTextCtrl.o \
	tests/search-bseq.o \
	tests/search-text.o \
	tests/SearchBase.o \
	tests/SearchValue.o \
	tests/SafeWindowPointer.o \
	tests/SharedDocumentPointer.o \
	tests/StringPanel.o \
	tests/Tab.o \
	tests/testutil.o \
	tests/util.o \
	$(WXLUA_OBJS) \
	$(WXBIND_OBJS) \
	$(EXTRA_TEST_OBJS)

tests/all-tests: $(TEST_OBJS) $(GTKCONFIG_EXE)
	$(CXX) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -DLIBDIR='"$(libdir)"' -DDATADIR='"$(datadir)"' -c -o res/version.o res/version.cpp
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_OBJS) res/version.o $(LDFLAGS) $(LDLIBS)

$(EMBED_EXE): tools/embed.cpp
	$(CXX) $(CXXFLAGS_NO_GTK) -o $@ $<

$(GTKCONFIG_EXE): tools/gtk-config.cpp
	$(CXX) $(CXXFLAGS_NO_GTK) $(WX_CXXFLAGS) -o $@ $<

src/AboutDialog.o: res/icon128.h
src/ArtProvider.o: \
	res/ascii16.h res/ascii24.h res/ascii32.h res/ascii48.h \
	res/diff_fold16.h res/diff_fold24.h res/diff_fold32.h res/diff_fold48.h \
	res/offsets16.h res/offsets24.h res/offsets32.h res/offsets48.h
src/BitmapTool.o: \
	res/actual_size16.h res/fit_to_screen16.h res/swap_horiz16.h \
	res/swap_vert16.h res/zoom_in16.h res/zoom_out16.h
src/DiffWindow.o: res/icon16.h res/icon32.h res/icon48.h res/icon64.h
src/LicenseDialog.o: res/license.h
src/LuaPluginLoader.o: src/lua-bindings/rehex_bind.h src/lua-plugin-preload.h
src/mainwindow.o: res/icon16.h res/icon32.h res/icon48.h res/icon64.h
src/StringPanel.o: res/spinner24.h

res/license.done: LICENSE.txt $(EMBED_EXE)
	$(EMBED_EXE) $< LICENSE_TXT res/license.c res/license.h
	touch $@

res/license.c res/license.h: res/license.done ;

res/%.c res/%.h: res/%.png $(EMBED_EXE)
	$(EMBED_EXE) $< $*_png res/$*.c res/$*.h

res/%.c res/%.h: res/%.gif $(EMBED_EXE)
	$(EMBED_EXE) $< $*_gif res/$*.c res/$*.h

src/lua-bindings/rehex_bind.done: src/lua-bindings/rehex.i src/lua-bindings/rehex_override.hpp src/lua-bindings/rehex_rules.lua $(WXLUA_BINDINGS)
	$(LUA) -e"rulesFilename=\"src/lua-bindings/rehex_rules.lua\"" wxLua/bindings/genwxbind.lua
	
	# genwxbind.lua may not modify individual files if they are already up to date.
	touch -c src/lua-bindings/rehex_bind.cpp
	touch -c src/lua-bindings/rehex_bind.h

src/lua-bindings/rehex_bind.cpp src/lua-bindings/rehex_bind.h: src/lua-bindings/rehex_bind.done ;

$(WXLUA_BINDINGS):
	$(MAKE) -C wxLua/bindings/ wxadv wxaui wxbase wxcore wxlua wxpropgrid LUA=$(LUA)
	touch $@

src/lua-plugin-preload.done: src/lua-plugin-preload.lua $(EMBED_EXE)
	$(EMBED_EXE) $< LUA_PLUGIN_PRELOAD src/lua-plugin-preload.c src/lua-plugin-preload.h
	touch $@

src/lua-plugin-preload.c src/lua-plugin-preload.h: src/lua-plugin-preload.done ;

%.o: %.c $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

tests/%.o: tests/%.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(CXXFLAGS) -I./googletest/include/ $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.o: wxLua/%.cpp $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CXX) $(CXXFLAGS) -Wno-deprecated-declarations $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

googletest/src/%.o: googletest/src/%.cc $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(CXXFLAGS) -I./googletest/include/ -I./googletest/ $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.o: %.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.cpp: $(WXLUA_BINDINGS)
	@true

.PHONY: help/rehex.chm
help/rehex.chm:
	$(MAKE) -C help/ rehex.chm

rehex.chm: help/rehex.chm
	cp $< $@

.PHONY: help/rehex.htb
help/rehex.htb:
	$(MAKE) -C help/ rehex.htb

.PHONY: online-help
online-help:
	$(MAKE) -C help/ online-help

include $(shell test -d .d/ && find .d/ -name '*.d' -type f)

prefix      ?= /usr/local
exec_prefix ?= $(prefix)
bindir      ?= $(exec_prefix)/bin
datarootdir ?= $(prefix)/share
datadir     ?= $(datarootdir)
libdir      ?= $(exec_prefix)/lib

export prefix
export exec_prefix
export bindir
export datarootdir
export datadir
export libdir

PLUGINS := \
	binary-template \
	exe

.PHONY: install
install: $(EXE) $(HELP_TARGET)
	mkdir -p $(DESTDIR)$(bindir)
	install -m 0755 $(INSTALL_STRIP) $(EXE) $(DESTDIR)$(bindir)/$(EXE)
	
	for s in 16 32 48 64 128 256 512; \
	do \
		mkdir -p $(DESTDIR)$(datarootdir)/icons/hicolor/$${s}x$${s}/apps; \
		install -m 0644 res/icon$${s}.png $(DESTDIR)$(datarootdir)/icons/hicolor/$${s}x$${s}/apps/rehex.png; \
	done
	
	mkdir -p $(DESTDIR)$(datarootdir)/applications
	install -m 0644 res/rehex.desktop $(DESTDIR)$(datarootdir)/applications/rehex.desktop
	
ifneq ($(BUILD_HELP),0)
	mkdir -p $(DESTDIR)$(datadir)/rehex
	install -m 0644 help/rehex.htb $(DESTDIR)$(datadir)/rehex/rehex.htb
endif
	
	for p in $(PLUGINS); \
	do \
		$(MAKE) -C plugins/$${p} install || exit $$?; \
	done

.PHONY: install-strip
install-strip:
	$(MAKE) INSTALL_STRIP=-s install

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(bindir)/$(EXE)
	rm -f $(DESTDIR)$(datadir)/rehex/rehex.htb
	rmdir --ignore-fail-on-non-empty $(DESTDIR)$(datadir)/rehex/
	rm -f $(DESTDIR)$(datarootdir)/applications/rehex.desktop
	
	for s in 16 32 48 64 128 256 512; \
	do \
		rm -f $(DESTDIR)$(datarootdir)/icons/hicolor/$${s}x$${s}/apps/rehex.png; \
	done
	
	for p in $(PLUGINS); \
	do \
		$(MAKE) -C plugins/$${p} uninstall || exit $$?; \
	done

.PHONY: dist
dist:
	rm -rf rehex-$(VERSION) rehex-$(VERSION).tar
	mkdir rehex-$(VERSION)/
	
ifneq ("$(wildcard MANIFEST)","")
	# Running from a dist tarball, ship anything in the MANIFEST
	xargs cp --parents -t rehex-$(VERSION)/ < MANIFEST
else
	# Running from the git tree, ship any checked in files
	(git ls-files && echo MANIFEST) | LC_ALL=C sort > rehex-$(VERSION)/MANIFEST
	git ls-files | xargs cp --parents -t rehex-$(VERSION)/
	
	# Inline any references to the HEAD commit sha/timestamp
	sed -i -e "s|\$9db2df2bf978e53b876b706dca28ea3ededcbd1a|9db2df2bf978e53b876b706dca28ea3ededcbd1a|g" rehex-$(VERSION)/Makefile
	sed -i -e "s|\$1656103549|1656103549|g" rehex-$(VERSION)/Makefile
endif
	
	# Generate reproducible tarball. All files use git commit timestamp.
	find rehex-$(VERSION) -print0 | \
		LC_ALL=C sort -z | \
		tar \
			--format=ustar \
			--mtime=@1656103549 \
			--owner=0 --group=0 --numeric-owner \
			--no-recursion --null  -T - \
			-cf - | \
		gzip -9n - > rehex-$(VERSION).tar.gz
