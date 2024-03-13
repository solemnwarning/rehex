# Reverse Engineer's Hex Editor
# Copyright (C) 2017-2023 Daniel Collins <solemnwarning@solemnwarning.net>
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
BOTAN_PKG    ?= botan-2
CAPSTONE_PKG ?= capstone
JANSSON_PKG  ?= jansson
LUA_PKG      ?= $(shell pkg-config --exists lua5.3 && echo lua5.3 || echo lua)
CXXSTD       ?= -std=c++11

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
	WX_CXXFLAGS ?= $(call shell-or-die,$(WX_CONFIG) --cxxflags base core aui propgrid adv net $(HELP_LIBS))
	WX_LIBS     ?= $(call shell-or-die,$(WX_CONFIG) --libs     base core aui propgrid adv net $(HELP_LIBS))
	
	BOTAN_CFLAGS ?= $(call shell-or-die,pkg-config $(BOTAN_PKG) --cflags)
	BOTAN_LIBS   ?= $(call shell-or-die,pkg-config $(BOTAN_PKG) --libs)
	
	CAPSTONE_CFLAGS ?= $(call shell-or-die,pkg-config $(CAPSTONE_PKG) --cflags)
	CAPSTONE_LIBS   ?= $(call shell-or-die,pkg-config $(CAPSTONE_PKG) --libs)
	
	JANSSON_CFLAGS ?= $(call shell-or-die,pkg-config $(JANSSON_PKG) --cflags)
	JANSSON_LIBS   ?= $(call shell-or-die,pkg-config $(JANSSON_PKG) --libs)
	
	LUA_CFLAGS ?= $(call shell-or-die,pkg-config $(LUA_PKG) --cflags)
	LUA_LIBS   ?= $(call shell-or-die,pkg-config $(LUA_PKG) --libs)
	
	GTK_CFLAGS = $$($(GTKCONFIG_EXE) --cflags)
	GTK_LIBS   = $$($(GTKCONFIG_EXE) --libs)
endif

BASE_CFLAGS := -Wall

DEBUG_CFLAGS   := -ggdb
RELEASE_CFLAGS := -g -O2 -DNDEBUG
PROFILE_CFLAGS := $(RELEASE_CFLAGS) -DREHEX_PROFILE

ifeq ($(BUILD_TYPE),)
	BUILD_TYPE := release
endif

ifeq ($(BUILD_TYPE),release)
	BASE_CFLAGS += $(RELEASE_CFLAGS)
else
	ifeq ($(BUILD_TYPE),debug)
		BASE_CFLAGS += $(DEBUG_CFLAGS)
	else
		ifeq ($(BUILD_TYPE),profile)
			BASE_CFLAGS += $(PROFILE_CFLAGS)
		else
			$(error unknown BUILD_TYPE '$(BUILD_TYPE)')
		endif
	endif
endif

CFLAGS          := $(BASE_CFLAGS) -std=c99   -I. -Iinclude/ -IwxLua/modules/ -IwxFreeChart/include/                       -DREHEX_CACHE_CHARACTER_BITMAPS $(HELP_CFLAGS) $(BOTAN_CFLAGS) $(CAPSTONE_CFLAGS) $(JANSSON_CFLAGS) $(LUA_CFLAGS) $(CFLAGS)
CXXFLAGS_NO_GTK := $(BASE_CFLAGS) $(CXXSTD) -I. -Iinclude/ -IwxLua/modules/ -IwxFreeChart/include/ -DwxOVERRIDE=override -DREHEX_CACHE_CHARACTER_BITMAPS $(HELP_CFLAGS) $(BOTAN_CFLAGS) $(CAPSTONE_CFLAGS) $(JANSSON_CFLAGS) $(LUA_CFLAGS) $(WX_CXXFLAGS) $(CXXFLAGS)
CXXFLAGS        := $(BASE_CFLAGS) $(CXXSTD) -I. -Iinclude/ -IwxLua/modules/ -IwxFreeChart/include/ -DwxOVERRIDE=override -DREHEX_CACHE_CHARACTER_BITMAPS $(HELP_CFLAGS) $(BOTAN_CFLAGS) $(CAPSTONE_CFLAGS) $(JANSSON_CFLAGS) $(LUA_CFLAGS) $(WX_CXXFLAGS) $(GTK_CFLAGS) $(CXXFLAGS)

uname_S := $(shell uname -s 2>/dev/null)
ifeq ($(uname_S),FreeBSD)
	LDLIBS += -liconv
endif
ifeq ($(uname_S),OpenBSD)
	LDLIBS += -liconv
endif

LDLIBS := -lunistring $(WX_LIBS) $(GTK_LIBS) $(BOTAN_LIBS) $(CAPSTONE_LIBS) $(JANSSON_LIBS) $(LUA_LIBS) $(LDLIBS)

# Define this for releases
VERSION := 0.61.1

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
	
	VERSION      := 9c50a30d529172ddfc1938c4fad8f6c1572b9733
	LONG_VERSION := Snapshot 9c50a30d529172ddfc1938c4fad8f6c1572b9733
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
	
	rm -f $(filter-out %.$(BUILD_TYPE).o,$(APP_OBJS))
	rm -f $(patsubst %.$(BUILD_TYPE).o,%.debug.o,$(filter %.$(BUILD_TYPE).o,$(APP_OBJS)))
	rm -f $(patsubst %.$(BUILD_TYPE).o,%.release.o,$(filter %.$(BUILD_TYPE).o,$(APP_OBJS)))
	rm -f $(patsubst %.$(BUILD_TYPE).o,%.profile.o,$(filter %.$(BUILD_TYPE).o,$(APP_OBJS)))
	rm -f $(EXE)
	
	rm -f $(filter-out %.$(BUILD_TYPE).o,$(TEST_OBJS))
	rm -f $(patsubst %.$(BUILD_TYPE).o,%.debug.o,$(filter %.$(BUILD_TYPE).o,$(TEST_OBJS)))
	rm -f $(patsubst %.$(BUILD_TYPE).o,%.release.o,$(filter %.$(BUILD_TYPE).o,$(TEST_OBJS)))
	rm -f $(patsubst %.$(BUILD_TYPE).o,%.profile.o,$(filter %.$(BUILD_TYPE).o,$(TEST_OBJS)))
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
	wxLua/modules/wxlua/bit.$(BUILD_TYPE).o \
	wxLua/modules/wxlua/lbitlib.$(BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlbind.$(BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlcallb.$(BUILD_TYPE).o \
	wxLua/modules/wxlua/wxllua.$(BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlobject.$(BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlstate.$(BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlua_bind.$(BUILD_TYPE).o

WXBIND_OBJS := \
	wxLua/modules/wxbind/src/wxadv_bind.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxadv_wxladv.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxaui_bind.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_base.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_bind.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_config.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_data.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_datetime.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_file.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_appframe.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_bind.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_clipdrag.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_controls.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_core.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_defsutils.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_dialogs.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_event.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_gdi.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_geometry.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_graphics.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_help.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_image.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_mdi.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_menutool.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_picker.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_print.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_sizer.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_windows.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_wxlcore.$(BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxpropgrid_bind.$(BUILD_TYPE).o

WXFREECHART_OBJS := \
	wxFreeChart/src/areadraw.$(BUILD_TYPE).o \
	wxFreeChart/src/art.$(BUILD_TYPE).o \
	wxFreeChart/src/axis/axis.$(BUILD_TYPE).o \
	wxFreeChart/src/axis/categoryaxis.$(BUILD_TYPE).o \
	wxFreeChart/src/axis/compdateaxis.$(BUILD_TYPE).o \
	wxFreeChart/src/axis/dateaxis.$(BUILD_TYPE).o \
	wxFreeChart/src/axis/juliandateaxis.$(BUILD_TYPE).o \
	wxFreeChart/src/axis/labelaxis.$(BUILD_TYPE).o \
	wxFreeChart/src/axis/logarithmicnumberaxis.$(BUILD_TYPE).o \
	wxFreeChart/src/axis/numberaxis.$(BUILD_TYPE).o \
	wxFreeChart/src/axisplot.$(BUILD_TYPE).o \
	wxFreeChart/src/bars/barplot.$(BUILD_TYPE).o \
	wxFreeChart/src/bars/barrenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/category/categorydataset.$(BUILD_TYPE).o \
	wxFreeChart/src/category/categoryrenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/category/categorysimpledataset.$(BUILD_TYPE).o \
	wxFreeChart/src/chart.$(BUILD_TYPE).o \
	wxFreeChart/src/chartpanel.$(BUILD_TYPE).o \
	wxFreeChart/src/chartsplitpanel.$(BUILD_TYPE).o \
	wxFreeChart/src/colorscheme.$(BUILD_TYPE).o \
	wxFreeChart/src/crosshair.$(BUILD_TYPE).o \
	wxFreeChart/src/dataset.$(BUILD_TYPE).o \
	wxFreeChart/src/gantt/ganttdataset.$(BUILD_TYPE).o \
	wxFreeChart/src/gantt/ganttplot.$(BUILD_TYPE).o \
	wxFreeChart/src/gantt/ganttrenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/gantt/ganttsimpledataset.$(BUILD_TYPE).o \
	wxFreeChart/src/legend.$(BUILD_TYPE).o \
	wxFreeChart/src/marker.$(BUILD_TYPE).o \
	wxFreeChart/src/multiplot.$(BUILD_TYPE).o \
	wxFreeChart/src/ohlc/movingaverage.$(BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcbarrenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlccandlestickrenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcdataset.$(BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcplot.$(BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcrenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcsimpledataset.$(BUILD_TYPE).o \
	wxFreeChart/src/pie/pieplot.$(BUILD_TYPE).o \
	wxFreeChart/src/plot.$(BUILD_TYPE).o \
	wxFreeChart/src/renderer.$(BUILD_TYPE).o \
	wxFreeChart/src/symbol.$(BUILD_TYPE).o \
	wxFreeChart/src/title.$(BUILD_TYPE).o \
	wxFreeChart/src/tooltips.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/functions/polynom.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/functions/sinefunction.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/juliantimeseriesdataset.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/timeseriesdataset.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/vectordataset.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/xyarearenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/xydataset.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/xydynamicdataset.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/xyhistorenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/xylinerenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/xyplot.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/xyrenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/xy/xysimpledataset.$(BUILD_TYPE).o \
	wxFreeChart/src/xyz/bubbleplot.$(BUILD_TYPE).o \
	wxFreeChart/src/xyz/xyzdataset.$(BUILD_TYPE).o \
	wxFreeChart/src/xyz/xyzrenderer.$(BUILD_TYPE).o \
	wxFreeChart/src/zoompan.$(BUILD_TYPE).o

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
	src/AboutDialog.$(BUILD_TYPE).o \
	src/AppMain.$(BUILD_TYPE).o \
	src/AppSettings.$(BUILD_TYPE).o \
	src/AppTestable.$(BUILD_TYPE).o \
	src/ArtProvider.$(BUILD_TYPE).o \
	src/BasicDataTypes.$(BUILD_TYPE).o \
	src/BitEditor.$(BUILD_TYPE).o \
	src/BitmapTool.$(BUILD_TYPE).o \
	src/buffer.$(BUILD_TYPE).o \
	src/BytesPerLineDialog.$(BUILD_TYPE).o \
	src/ByteRangeSet.$(BUILD_TYPE).o \
	src/CharacterEncoder.$(BUILD_TYPE).o \
	src/CharacterFinder.$(BUILD_TYPE).o \
	src/Checksum.$(BUILD_TYPE).o \
	src/ChecksumImpl.$(BUILD_TYPE).o \
	src/ChecksumPanel.$(BUILD_TYPE).o \
	src/ClickText.$(BUILD_TYPE).o \
	src/CodeCtrl.$(BUILD_TYPE).o \
	src/CommentTree.$(BUILD_TYPE).o \
	src/ConsoleBuffer.$(BUILD_TYPE).o \
	src/ConsolePanel.$(BUILD_TYPE).o \
	src/CustomMessageDialog.$(BUILD_TYPE).o \
	src/DataHistogramPanel.$(BUILD_TYPE).o \
	src/DataType.$(BUILD_TYPE).o \
	src/decodepanel.$(BUILD_TYPE).o \
	src/DetachableNotebook.$(BUILD_TYPE).o \
	src/DiffWindow.$(BUILD_TYPE).o \
	src/disassemble.$(BUILD_TYPE).o \
	src/DisassemblyRegion.$(BUILD_TYPE).o \
	src/document.$(BUILD_TYPE).o \
	src/DocumentCtrl.$(BUILD_TYPE).o \
	src/EditCommentDialog.$(BUILD_TYPE).o \
	src/Events.$(BUILD_TYPE).o \
	src/FileWriter.$(BUILD_TYPE).o \
	src/FillRangeDialog.$(BUILD_TYPE).o \
	src/IntelHexExport.$(BUILD_TYPE).o \
	src/IntelHexImport.$(BUILD_TYPE).o \
	src/IPC.$(BUILD_TYPE).o \
	src/LicenseDialog.$(BUILD_TYPE).o \
	src/LoadingSpinner.$(BUILD_TYPE).o \
	src/lua-bindings/rehex_bind.$(BUILD_TYPE).o \
	src/lua-plugin-preload.$(BUILD_TYPE).o \
	src/LuaPluginLoader.$(BUILD_TYPE).o \
	src/mainwindow.$(BUILD_TYPE).o \
	src/Palette.$(BUILD_TYPE).o \
	src/profile.$(BUILD_TYPE).o \
	src/RangeChoiceLinear.$(BUILD_TYPE).o \
	src/RangeDialog.$(BUILD_TYPE).o \
	src/RangeProcessor.$(BUILD_TYPE).o \
	src/search.$(BUILD_TYPE).o \
	src/StringPanel.$(BUILD_TYPE).o \
	src/textentrydialog.$(BUILD_TYPE).o \
	src/Tab.$(BUILD_TYPE).o \
	src/ThreadPool.$(BUILD_TYPE).o \
	src/ToolPanel.$(BUILD_TYPE).o \
	src/util.$(BUILD_TYPE).o \
	src/VirtualMappingDialog.$(BUILD_TYPE).o \
	src/VirtualMappingList.$(BUILD_TYPE).o \
	src/win32lib.$(BUILD_TYPE).o \
	$(WXLUA_OBJS) \
	$(WXBIND_OBJS) \
	$(WXFREECHART_OBJS) \
	$(EXTRA_APP_OBJS)

$(EXE): $(APP_OBJS) $(GTKCONFIG_EXE)
	$(CXX) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -DSHORT_VERSION='"$(VERSION)"' -DLIBDIR='"$(libdir)"' -DDATADIR='"$(datadir)"' -c -o res/version.o res/version.cpp
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
	src/AboutDialog.$(BUILD_TYPE).o \
	src/AppSettings.$(BUILD_TYPE).o \
	src/AppTestable.$(BUILD_TYPE).o \
	src/ArtProvider.$(BUILD_TYPE).o \
	src/BasicDataTypes.$(BUILD_TYPE).o \
	src/BitmapTool.$(BUILD_TYPE).o \
	src/buffer.$(BUILD_TYPE).o \
	src/ByteRangeSet.$(BUILD_TYPE).o \
	src/BytesPerLineDialog.$(BUILD_TYPE).o \
	src/CharacterEncoder.$(BUILD_TYPE).o \
	src/CharacterFinder.$(BUILD_TYPE).o \
	src/Checksum.$(BUILD_TYPE).o \
	src/ChecksumImpl.$(BUILD_TYPE).o \
	src/ClickText.$(BUILD_TYPE).o \
	src/CommentTree.$(BUILD_TYPE).o \
	src/ConsoleBuffer.$(BUILD_TYPE).o \
	src/CustomMessageDialog.$(BUILD_TYPE).o \
	src/DataType.$(BUILD_TYPE).o \
	src/DetachableNotebook.$(BUILD_TYPE).o \
	src/DiffWindow.$(BUILD_TYPE).o \
	src/DisassemblyRegion.$(BUILD_TYPE).o \
	src/document.$(BUILD_TYPE).o \
	src/DocumentCtrl.$(BUILD_TYPE).o \
	src/EditCommentDialog.$(BUILD_TYPE).o \
	src/Events.$(BUILD_TYPE).o \
	src/FileWriter.$(BUILD_TYPE).o \
	src/FillRangeDialog.$(BUILD_TYPE).o \
	src/IntelHexExport.$(BUILD_TYPE).o \
	src/IntelHexImport.$(BUILD_TYPE).o \
	src/LicenseDialog.$(BUILD_TYPE).o \
	src/LoadingSpinner.$(BUILD_TYPE).o \
	src/lua-bindings/rehex_bind.$(BUILD_TYPE).o \
	src/lua-plugin-preload.$(BUILD_TYPE).o \
	src/LuaPluginLoader.$(BUILD_TYPE).o \
	src/mainwindow.$(BUILD_TYPE).o \
	src/Palette.$(BUILD_TYPE).o \
	src/RangeDialog.$(BUILD_TYPE).o \
	src/RangeProcessor.$(BUILD_TYPE).o \
	src/search.$(BUILD_TYPE).o \
	src/StringPanel.$(BUILD_TYPE).o \
	src/Tab.$(BUILD_TYPE).o \
	src/textentrydialog.$(BUILD_TYPE).o \
	src/ThreadPool.$(BUILD_TYPE).o \
	src/ToolPanel.$(BUILD_TYPE).o \
	src/util.$(BUILD_TYPE).o \
	src/VirtualMappingDialog.$(BUILD_TYPE).o \
	src/win32lib.$(BUILD_TYPE).o \
	tests/BitmapTool.o \
	tests/buffer.o \
	tests/ByteRangeMap.o \
	tests/ByteRangeSet.o \
	tests/ByteRangeTree.o \
	tests/CharacterEncoder.o \
	tests/CharacterFinder.o \
	tests/Checksum.o \
	tests/CommentsDataObject.o \
	tests/CommentTree.o \
	tests/ConsoleBuffer.o \
	tests/DataHistogramAccumulator.o \
	tests/DiffWindow.o \
	tests/DisassemblyRegion.o \
	tests/Document.o \
	tests/DocumentCtrl.o \
	tests/endian_conv.o \
	tests/FastRectangleFiller.o \
	tests/FileWriter.o \
	tests/IntelHexExport.o \
	tests/IntelHexImport.o \
	tests/LuaPluginLoader.o \
	tests/main.o \
	tests/NestedOffsetLengthMap.o \
	tests/NumericTextCtrl.o \
	tests/RangeProcessor.o \
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
	$(CXX) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -DSHORT_VERSION='"$(VERSION)"' -DLIBDIR='"$(libdir)"' -DDATADIR='"$(datadir)"' -c -o res/version.o res/version.cpp
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_OBJS) res/version.o $(LDFLAGS) $(LDLIBS)

$(EMBED_EXE): tools/embed.cpp
	$(CXX) $(CXXFLAGS_NO_GTK) -o $@ $<

$(GTKCONFIG_EXE): tools/gtk-config.cpp
	$(CXX) $(CXXFLAGS_NO_GTK) $(WX_CXXFLAGS) -o $@ $<

src/AboutDialog.$(BUILD_TYPE).o: res/icon128.h
src/ArtProvider.$(BUILD_TYPE).o: \
	res/ascii16.h res/ascii24.h res/ascii32.h res/ascii48.h \
	res/diff_fold16.h res/diff_fold24.h res/diff_fold32.h res/diff_fold48.h \
	res/offsets16.h res/offsets24.h res/offsets32.h res/offsets48.h
src/BitmapTool.$(BUILD_TYPE).o: \
	res/actual_size16.h res/fit_to_screen16.h res/swap_horiz16.h \
	res/swap_vert16.h res/zoom_in16.h res/zoom_out16.h
src/DataHistogramPanel.$(BUILD_TYPE).o: \
	res/spinner24.h res/zoom_in16.h res/zoom_out16.h
src/DiffWindow.$(BUILD_TYPE).o: res/icon16.h res/icon32.h res/icon48.h res/icon64.h
src/LicenseDialog.$(BUILD_TYPE).o: res/license.h
src/LuaPluginLoader.$(BUILD_TYPE).o: src/lua-bindings/rehex_bind.h src/lua-plugin-preload.h
src/mainwindow.$(BUILD_TYPE).o: res/icon16.h res/icon32.h res/icon48.h res/icon64.h
src/StringPanel.$(BUILD_TYPE).o: res/spinner24.h

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

%.$(BUILD_TYPE).o: %.c $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

tests/%.o: tests/%.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(CXXFLAGS) -I./googletest/include/ $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.$(BUILD_TYPE).o: wxLua/%.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(CXXFLAGS) -Wno-deprecated-declarations $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

googletest/src/%.o: googletest/src/%.cc $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(CXXFLAGS) -I./googletest/include/ -I./googletest/ $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.$(BUILD_TYPE).o: %.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
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
	exe \
	pcap

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
	sed -i -e "s|\$9c50a30d529172ddfc1938c4fad8f6c1572b9733|9c50a30d529172ddfc1938c4fad8f6c1572b9733|g" rehex-$(VERSION)/Makefile
	sed -i -e "s|\$1710353139|1710353139|g" rehex-$(VERSION)/Makefile
endif
	
	# Generate reproducible tarball. All files use git commit timestamp.
	find rehex-$(VERSION) -print0 | \
		LC_ALL=C sort -z | \
		tar \
			--format=ustar \
			--mtime=@1710353139 \
			--owner=0 --group=0 --numeric-owner \
			--no-recursion --null  -T - \
			-cf - | \
		gzip -9n - > rehex-$(VERSION).tar.gz
