# Reverse Engineer's Hex Editor
# Copyright (C) 2017-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

# Returns the first of $(1) or $(2) which is defined in the pkg-config
# database, or errors if neither are.
pkg-select-ab = $\
	$(if $(filter yes,$(shell pkg-config --exists $(1) && echo yes)),$(1),$\
		$(if $(filter yes,$(shell pkg-config --exists $(2) && echo yes)),$(2),$\
			$(error Could not find $(1) or $(2) using pkg-config)))

# Check if additional compile/link flags are required to compile a test program on top of the
# general flags used to compile the application. Returns empty string it the additional flags
# weren't required to build the program or the provided flags if they were.
#
# Usage: $(call config-test-flag,tools/config-test-xxx.cpp,-lfoo)
#
config-test-flag = $\
	$(if $(wildcard $(1).aok)$(wildcard $(1).bok),$\
		$(if $(wildcard $(1).aok),,$(if $(wildcard $(1).bok),$(2),)),$\
		$(info Checking if we need $(2)...)$\
		$(if $(shell $(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) -o $(1).aok $(1) $(LDFLAGS) $(LDLIBS_NO_GTK) > /dev/null 2>&1 && echo yes),$\
			$(info No),$\
			$(if $(shell $(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) -o $(1).bok $(1) $(LDFLAGS) $(LDLIBS_NO_GTK) $(2) > /dev/null 2>&1 && echo yes),$\
				$(info Yes)$(2),$\
				$(shell $(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) -o $(1).aok $(1) $(LDFLAGS) $(LDLIBS_NO_GTK) 1>&2)$(error Unable to compile $(1)))))

LUA          ?= lua
WX_CONFIG    ?= wx-config
BOTAN_PKG    ?= $(call pkg-select-ab,botan-3,botan-2)
CAPSTONE_PKG ?= capstone
JANSSON_PKG  ?= jansson
LUA_PKG      ?= $(call pkg-select-ab,lua5.3,lua)
JQ           ?= jq

RELEASE_EXE ?= rehex
DEBUG_EXE   ?= rehex_debug
PROFILE_EXE ?= rehex_profile

RELEASE_TEST_EXE ?= tests/all-tests
DEBUG_TEST_EXE   ?= tests/all-tests_debug

EMBED_EXE ?= ./tools/embed
GTKCONFIG_EXE ?= ./tools/gtk-config
HELP_TARGET ?= help/rehex.htb

DEFAULT_RELEASE_EXE_TARGET  ?= $(RELEASE_EXE)
DEFAULT_DEBUG_EXE_TARGET    ?= $(DEBUG_EXE)
DEFAULT_PROFILE_EXE_TARGET  ?= $(PROFILE_EXE)

DEFAULT_RELEASE_TEST_EXE_TARGET ?= $(RELEASE_TEST_EXE)
DEFAULT_DEBUG_TEST_EXE_TARGET   ?= $(DEBUG_TEST_EXE)

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

NONCOMPILE_TARGETS=clean clean_config distclean dist

need_compiler_flags ?= 1
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
	
	ifeq ($(BOTAN_PKG),botan-3)
		CXXSTD ?= -std=c++20
	else
		CXXSTD ?= -std=c++11
	endif
endif

BASE_CFLAGS := -std=c99 -Wall -Iinclude/ -IwxLua/modules/ $(LUA_CFLAGS)
BASE_CXXFLAGS := $(CXXSTD) -Wall -Iinclude/ -IwxLua/modules/ -IwxFreeChart/include/ $(BOTAN_CFLAGS) $(CAPSTONE_CFLAGS) $(JANSSON_CFLAGS) $(LUA_CFLAGS) $(WX_CXXFLAGS)

DEBUG_CFLAGS   := -ggdb
RELEASE_CFLAGS := -g -O2 -DNDEBUG
PROFILE_CFLAGS := $(RELEASE_CFLAGS) -DREHEX_PROFILE

# BUILD_TYPE may be specified by the user to select the build configuration for
# the application as  a whole, from one of the following:
#
# release (default)  - Optimisations enabled, debug assertions disabled.
# debug              - No optimisations, debug assertions enabled.
# profile              Release with built-in profiling counters and UI enabled.
#
# From BUILD_TYPE, we derive LIB_BUILD_TYPE and DLL_BUILD_TYPE, the first of
# which is the configuration for building/linking any libraries or other code
# outside of the application itself, and the latter is the same but with PIC
# enabled for compiling sources as part of a dynamic library.
#
# +------------+----------------+----------------+
# | BUILD_TYPE | LIB_BUILD_TYPE | DLL_BUILD_TYPE |
# +------------+----------------+----------------+
# | release    | release        | release_pic    |
# | debug      | debug          | debug_pic      |
# | profile    | release        | release_pic    |
# +------------+----------------+----------------+

ifeq ($(BUILD_TYPE),)
	BUILD_TYPE := release
endif

ifeq ($(BUILD_TYPE),release)
	LIB_BUILD_TYPE := release
	
	EXE := $(RELEASE_EXE)
	TEST_EXE := $(RELEASE_TEST_EXE)
else
	ifeq ($(BUILD_TYPE),debug)
		LIB_BUILD_TYPE := debug
		
		EXE := $(DEBUG_EXE)
		TEST_EXE := $(DEBUG_TEST_EXE)
	else
		ifeq ($(BUILD_TYPE),profile)
			LIB_BUILD_TYPE := release
			
			EXE := $(PROFILE_EXE)
			TEST_EXE := check_not_supported_for_profile_build
		else
			X := $(error unknown BUILD_TYPE '$(BUILD_TYPE)' (should be release, debug or profile))
		endif
	endif
endif

DLL_BUILD_TYPE := $(LIB_BUILD_TYPE)_pic

LDLIBS_NO_GTK := -lunistring $(WX_LIBS)             $(BOTAN_LIBS) $(CAPSTONE_LIBS) $(JANSSON_LIBS) $(LUA_LIBS) $(LDLIBS)
LDLIBS        := -lunistring $(WX_LIBS) $(GTK_LIBS) $(BOTAN_LIBS) $(CAPSTONE_LIBS) $(JANSSON_LIBS) $(LUA_LIBS) $(LDLIBS)

# Check if we need to link -latomic for std::atomic support routines.
ifeq ($(need_compiler_flags),1)
	LDLIBS += $(call config-test-flag,tools/config-test-atomic.cpp,-latomic)
endif

# Check if we need to link -liconv for iconv functions.
ifeq ($(need_compiler_flags),1)
	LDLIBS += $(call config-test-flag,tools/config-test-iconv.cpp,-liconv)
endif

# Define this for releases
# NOTE: This *MUST* be of the form a.b.c where each component is an integer to fit the format of
# macOS version numbers and Windows version info resources.
# VERSION := x

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
	
	VERSION      := $(GIT_COMMIT_SHA)
	LONG_VERSION := Snapshot $(GIT_COMMIT_SHA)
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

DLL_EXT ?= so

REHEX_LUA_LIB_DLL ?= src/lua-bindings/rehex_lib.$(LIB_BUILD_TYPE).$(DLL_EXT)
REHEX_LUA_LIB_CPATH ?= $(shell pwd)/src/lua-bindings/?.$(LIB_BUILD_TYPE).$(DLL_EXT)
export REHEX_LUA_LIB_CPATH

.PHONY: check
check: $(TEST_EXE) $(REHEX_LUA_LIB_DLL)
	$(TEST_EXE)
	
	for p in $(PLUGINS); \
	do \
		$(MAKE) -C plugins/$${p} LUA=$(LUA) check || exit $$?; \
	done

.PHONY: clean
clean:
	$(MAKE) BUILD_TYPE=release clean_config
	$(MAKE) BUILD_TYPE=debug   clean_config
	$(MAKE) BUILD_TYPE=profile clean_config
	
	rm -f res/actual_size_dark_16.c  res/actual_size_dark_16.h \
	      res/actual_size_light_16.c res/actual_size_light_16.h \
	      res/ascii16.c   res/ascii16.h \
	      res/ascii24.c   res/ascii24.h \
	      res/ascii32.c   res/ascii32.h \
	      res/ascii48.c   res/ascii48.h \
	      res/bg16.c res/bg16.h \
	      res/diff_fold16.c res/diff_fold16.h \
	      res/diff_fold24.c res/diff_fold24.h \
	      res/diff_fold32.c res/diff_fold32.h \
	      res/diff_fold48.c res/diff_fold48.h \
	      res/dock_bottom.c res/dock_bottom.h \
	      res/dock_left.c   res/dock_left.h \
	      res/dock_right.c  res/dock_right.h \
	      res/dock_top.c    res/dock_top.h \
	      res/fit_to_screen_dark_16.c  res/fit_to_screen_dark_16.h \
	      res/fit_to_screen_light_16.c res/fit_to_screen_light_16.h \
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
	      res/shortcut48.c  res/shortcut48.h \
	      res/spinner24.c   res/spinner24.h \
	      res/swap_horiz_dark_16.c   res/swap_horiz_dark_16.h \
	      res/swap_horiz_light_16.c  res/swap_horiz_light_16.h \
	      res/swap_vert_dark_16.c    res/swap_vert_dark_16.h \
	      res/swap_vert_light_16.c   res/swap_vert_light_16.h \
	      res/zoom_in_dark_16.c    res/zoom_in_dark_16.h \
	      res/zoom_in_light_16.c   res/zoom_in_light_16.h \
	      res/zoom_out_dark_16.c   res/zoom_out_dark_16.h \
	      res/zoom_out_light_16.c  res/zoom_out_light_16.h \
	      res/version.o
	
	rm -f $(RELEASE_EXE) $(DEBUG_EXE) $(PROFILE_EXE)
	rm -f $(RELEASE_TEST_EXE) $(DEBUG_TEST_EXE)
	
	rm -f $(EMBED_EXE)
	rm -f $(GTKCONFIG_EXE)
	
	grep -r "generated by genwxbind.lua" wxLua/ --exclude=genwxbind.lua | cut -d: -f1 | sort | uniq | xargs -r rm
	rm -f $(WXLUA_BINDINGS)
	
	rm -f src/lua-bindings/rehex_lib.debug.$(DLL_EXT) src/lua-bindings/rehex_lib.release.$(DLL_EXT)
	
	rm -f src/lua-bindings/rehex_app_bind.done src/lua-bindings/rehex_app_bind.cpp src/lua-bindings/rehex_app_bind.h src/lua-bindings/rehex_app_datatypes.lua
	rm -f src/lua-bindings/rehex_lib_bind.done src/lua-bindings/rehex_lib_bind.cpp src/lua-bindings/rehex_lib_bind.h src/lua-bindings/rehex_lib_datatypes.lua
	rm -f src/lua-plugin-preload.done src/lua-plugin-preload.c src/lua-plugin-preload.h

	rm -f tools/config-test-atomic.cpp.aok tools/config-test-atomic.cpp.bok
	rm -f tools/config-test-iconv.cpp.aok tools/config-test-iconv.cpp.bok

	rm -rf $(DEPDIR)
	rm -rf $(COMPILE_COMMAND_INTERMEDIATE_DIR)
	rm -f compile_commands.json

.PHONY: clean_config
clean_config:
	rm -f $(APP_OBJS) $(TEST_OBJS) $(LUA_LIB_OBJS)

.PHONY: distclean
distclean: clean

WXLUA_OBJS := \
	wxLua/modules/wxlua/bit.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxlua/lbitlib.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlbind.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlcallb.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxllua.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlobject.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlstate.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlua_bind.$(LIB_BUILD_TYPE).o

WXBIND_OBJS := \
	wxLua/modules/wxbind/src/wxadv_bind.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxadv_wxladv.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxaui_bind.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_base.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_bind.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_config.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_data.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_datetime.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxbase_file.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_appframe.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_bind.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_clipdrag.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_controls.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_core.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_defsutils.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_dialogs.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_event.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_gdi.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_geometry.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_graphics.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_help.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_image.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_mdi.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_menutool.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_picker.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_print.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_sizer.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_windows.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxcore_wxlcore.$(LIB_BUILD_TYPE).o \
	wxLua/modules/wxbind/src/wxpropgrid_bind.$(LIB_BUILD_TYPE).o

WXFREECHART_OBJS := \
	wxFreeChart/src/areadraw.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/art.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/axis/axis.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/axis/categoryaxis.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/axis/compdateaxis.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/axis/dateaxis.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/axis/juliandateaxis.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/axis/labelaxis.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/axis/logarithmicnumberaxis.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/axis/numberaxis.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/axisplot.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/bars/barplot.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/bars/barrenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/category/categorydataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/category/categoryrenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/category/categorysimpledataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/chart.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/chartpanel.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/chartsplitpanel.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/colorscheme.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/crosshair.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/dataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/gantt/ganttdataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/gantt/ganttplot.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/gantt/ganttrenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/gantt/ganttsimpledataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/legend.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/marker.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/multiplot.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/ohlc/movingaverage.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcbarrenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlccandlestickrenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcdataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcplot.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcrenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/ohlc/ohlcsimpledataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/pie/pieplot.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/plot.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/renderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/symbol.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/title.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/tooltips.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/functions/polynom.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/functions/sinefunction.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/juliantimeseriesdataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/timeseriesdataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/vectordataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/xyarearenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/xydataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/xydynamicdataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/xyhistorenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/xylinerenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/xyplot.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/xyrenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xy/xysimpledataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xyz/bubbleplot.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xyz/xyzdataset.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/xyz/xyzrenderer.$(LIB_BUILD_TYPE).o \
	wxFreeChart/src/zoompan.$(LIB_BUILD_TYPE).o

APP_OBJS := \
	res/actual_size_dark_16.o \
	res/actual_size_light_16.o \
	res/ascii16.o \
	res/ascii24.o \
	res/ascii32.o \
	res/ascii48.o \
	res/bg16.o \
	res/diff_fold16.o \
	res/diff_fold24.o \
	res/diff_fold32.o \
	res/diff_fold48.o \
	res/dock_bottom.o \
	res/dock_left.o \
	res/dock_right.o \
	res/dock_top.o \
	res/fit_to_screen_dark_16.o \
	res/fit_to_screen_light_16.o \
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
	res/shortcut48.o \
	res/spinner24.o \
	res/swap_horiz_dark_16.o \
	res/swap_horiz_light_16.o \
	res/swap_vert_dark_16.o \
	res/swap_vert_light_16.o \
	res/zoom_in_dark_16.o \
	res/zoom_in_light_16.o \
	res/zoom_out_dark_16.o \
	res/zoom_out_light_16.o \
	src/AboutDialog.$(BUILD_TYPE).o \
	src/AppMain.$(BUILD_TYPE).o \
	src/AppSettings.$(BUILD_TYPE).o \
	src/AppTestable.$(BUILD_TYPE).o \
	src/ArtProvider.$(BUILD_TYPE).o \
	src/BasicDataTypes.$(BUILD_TYPE).o \
	src/BatchedCharacterRenderer.$(BUILD_TYPE).o \
	src/BitArray.$(BUILD_TYPE).o \
	src/BitEditor.$(BUILD_TYPE).o \
	src/BitOffset.$(BUILD_TYPE).o \
	src/BitmapTool.$(BUILD_TYPE).o \
	src/buffer.$(BUILD_TYPE).o \
	src/BytesPerLineDialog.$(BUILD_TYPE).o \
	src/ByteColourMap.$(BUILD_TYPE).o \
	src/ByteRangeSet.$(BUILD_TYPE).o \
	src/CharacterEncoder.$(BUILD_TYPE).o \
	src/CharacterFinder.$(BUILD_TYPE).o \
	src/Checksum.$(BUILD_TYPE).o \
	src/ChecksumImpl.$(BUILD_TYPE).o \
	src/ChecksumPanel.$(BUILD_TYPE).o \
	src/ClickText.$(BUILD_TYPE).o \
	src/ClipboardUtils.$(BUILD_TYPE).o \
	src/CodeCtrl.$(BUILD_TYPE).o \
	src/ColourPickerCtrl.$(BUILD_TYPE).o \
	src/CommentTree.$(BUILD_TYPE).o \
	src/ConsoleBuffer.$(BUILD_TYPE).o \
	src/ConsolePanel.$(BUILD_TYPE).o \
	src/CustomMessageDialog.$(BUILD_TYPE).o \
	src/CustomNumericType.$(BUILD_TYPE).o \
	src/DataHistogramPanel.$(BUILD_TYPE).o \
	src/DataMapScrollbar.$(BUILD_TYPE).o \
	src/DataMapSource.$(BUILD_TYPE).o \
	src/DataMapTool.$(BUILD_TYPE).o \
	src/DataType.$(BUILD_TYPE).o \
	src/DataView.$(BUILD_TYPE).o \
	src/decodepanel.$(BUILD_TYPE).o \
	src/DetachableNotebook.$(BUILD_TYPE).o \
	src/DiffWindow.$(BUILD_TYPE).o \
	src/disassemble.$(BUILD_TYPE).o \
	src/DisassemblyRegion.$(BUILD_TYPE).o \
	src/document.$(BUILD_TYPE).o \
	src/DocumentCtrl.$(BUILD_TYPE).o \
	src/EditCommentDialog.$(BUILD_TYPE).o \
	src/Events.$(BUILD_TYPE).o \
	src/FileReader.$(BUILD_TYPE).o \
	src/FileWriter.$(BUILD_TYPE).o \
	src/FillRangeDialog.$(BUILD_TYPE).o \
	src/FixedSizeValueRegion.$(BUILD_TYPE).o \
	src/FontCharacterCache.$(BUILD_TYPE).o \
	src/GotoOffsetDialog.$(BUILD_TYPE).o \
	src/HierarchicalByteAccumulator.$(BUILD_TYPE).o \
	src/HighlightColourMap.$(BUILD_TYPE).o \
	src/HSVColour.$(BUILD_TYPE).o \
	src/IntelHexExport.$(BUILD_TYPE).o \
	src/IntelHexImport.$(BUILD_TYPE).o \
	src/IPC.$(BUILD_TYPE).o \
	src/LicenseDialog.$(BUILD_TYPE).o \
	src/LoadingSpinner.$(BUILD_TYPE).o \
	src/lua-bindings/rehex_app_bind.$(BUILD_TYPE).o \
	src/lua-bindings/rehex_lib_bind.$(BUILD_TYPE).o \
	src/lua-plugin-preload.o \
	src/LuaPluginLoader.$(BUILD_TYPE).o \
	src/mainwindow.$(BUILD_TYPE).o \
	src/MathUtils.$(BUILD_TYPE).o \
	src/MultiSplitter.$(BUILD_TYPE).o \
	src/Palette.$(BUILD_TYPE).o \
	src/PopupTipWindow.$(BUILD_TYPE).o \
	src/ProceduralBitmap.$(BUILD_TYPE).o \
	src/profile.$(BUILD_TYPE).o \
	src/ProxyDropTarget.$(BUILD_TYPE).o \
	src/RangeChoiceLinear.$(BUILD_TYPE).o \
	src/RangeDialog.$(BUILD_TYPE).o \
	src/RangeProcessor.$(BUILD_TYPE).o \
	src/search.$(BUILD_TYPE).o \
	src/SettingsDialog.$(BUILD_TYPE).o \
	src/SettingsDialogByteColour.$(BUILD_TYPE).o \
	src/SettingsDialogFont.$(BUILD_TYPE).o \
	src/SettingsDialogGeneral.$(BUILD_TYPE).o \
	src/SettingsDialogHighlights.$(BUILD_TYPE).o \
	src/SettingsDialogKeyboard.$(BUILD_TYPE).o \
	src/StringPanel.$(BUILD_TYPE).o \
	src/textentrydialog.$(BUILD_TYPE).o \
	src/Tab.$(BUILD_TYPE).o \
	src/TempDirectory.$(BUILD_TYPE).o \
	src/ThreadPool.$(BUILD_TYPE).o \
	src/ToolPanel.$(BUILD_TYPE).o \
	src/ToolDock.$(BUILD_TYPE).o \
	src/util.$(BUILD_TYPE).o \
	src/VirtualMappingDialog.$(BUILD_TYPE).o \
	src/VirtualMappingList.$(BUILD_TYPE).o \
	src/win32lib.$(BUILD_TYPE).o \
	src/WindowCommands.$(BUILD_TYPE).o \
	$(WXLUA_OBJS) \
	$(WXBIND_OBJS) \
	$(WXFREECHART_OBJS) \
	$(EXTRA_APP_OBJS)

$(DEFAULT_RELEASE_EXE_TARGET): $(APP_OBJS) $(GTKCONFIG_EXE)
	$(EXTRA_APP_BUILD_COMMAND)
	$(CXX) $(BASE_CXXFLAGS) $(RELEASE_CFLAGS) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -DSHORT_VERSION='"$(VERSION)"' -DLIBDIR='"$(libdir)"' -DDATADIR='"$(datadir)"' -c -o res/version.o res/version.cpp
	$(CXX) $(BASE_CXXFLAGS) $(RELEASE_CFLAGS) $(CXXFLAGS) -o $@ $(APP_OBJS) $(EXTRA_APP_LINK_OBJS) res/version.o $(LDFLAGS) $(LDLIBS)

$(DEFAULT_DEBUG_EXE_TARGET): $(APP_OBJS) $(GTKCONFIG_EXE)
	$(EXTRA_APP_BUILD_COMMAND)
	$(CXX) $(BASE_CXXFLAGS) $(DEBUG_CFLAGS) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -DSHORT_VERSION='"$(VERSION)"' -DLIBDIR='"$(libdir)"' -DDATADIR='"$(datadir)"' -c -o res/version.o res/version.cpp
	$(CXX) $(BASE_CXXFLAGS) $(DEBUG_CFLAGS) $(CXXFLAGS) -o $@ $(APP_OBJS) $(EXTRA_APP_LINK_OBJS) res/version.o $(LDFLAGS) $(LDLIBS)

$(DEFAULT_PROFILE_EXE_TARGET): $(APP_OBJS) $(GTKCONFIG_EXE)
	$(EXTRA_APP_BUILD_COMMAND)
	$(CXX) $(BASE_CXXFLAGS) $(PROFILE_CFLAGS) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -DSHORT_VERSION='"$(VERSION)"' -DLIBDIR='"$(libdir)"' -DDATADIR='"$(datadir)"' -c -o res/version.o res/version.cpp
	$(CXX) $(BASE_CXXFLAGS) $(PROFILE_CFLAGS) $(CXXFLAGS) -o $@ $(APP_OBJS) $(EXTRA_APP_LINK_OBJS) res/version.o $(LDFLAGS) $(LDLIBS)

TEST_OBJS := \
	googletest/src/gtest-all.o \
	res/actual_size_dark_16.o \
	res/actual_size_light_16.o \
	res/ascii16.o \
	res/ascii24.o \
	res/ascii32.o \
	res/ascii48.o \
	res/bg16.o \
	res/diff_fold16.o \
	res/diff_fold24.o \
	res/diff_fold32.o \
	res/diff_fold48.o \
	res/dock_bottom.o \
	res/dock_left.o \
	res/dock_right.o \
	res/dock_top.o \
	res/fit_to_screen_dark_16.o \
	res/fit_to_screen_light_16.o \
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
	res/shortcut48.o \
	res/spinner24.o \
	res/swap_horiz_dark_16.o \
	res/swap_horiz_light_16.o \
	res/swap_vert_dark_16.o \
	res/swap_vert_light_16.o \
	res/zoom_in_dark_16.o \
	res/zoom_in_light_16.o \
	res/zoom_out_dark_16.o \
	res/zoom_out_light_16.o \
	src/AboutDialog.$(BUILD_TYPE).o \
	src/AppSettings.$(BUILD_TYPE).o \
	src/AppTestable.$(BUILD_TYPE).o \
	src/ArtProvider.$(BUILD_TYPE).o \
	src/BasicDataTypes.$(BUILD_TYPE).o \
	src/BatchedCharacterRenderer.$(BUILD_TYPE).o \
	src/BitArray.$(BUILD_TYPE).o \
	src/BitOffset.$(BUILD_TYPE).o \
	src/BitmapTool.$(BUILD_TYPE).o \
	src/buffer.$(BUILD_TYPE).o \
	src/ByteColourMap.$(BUILD_TYPE).o \
	src/ByteRangeSet.$(BUILD_TYPE).o \
	src/BytesPerLineDialog.$(BUILD_TYPE).o \
	src/CharacterEncoder.$(BUILD_TYPE).o \
	src/CharacterFinder.$(BUILD_TYPE).o \
	src/Checksum.$(BUILD_TYPE).o \
	src/ChecksumImpl.$(BUILD_TYPE).o \
	src/ClickText.$(BUILD_TYPE).o \
	src/ClipboardUtils.$(BUILD_TYPE).o \
	src/ColourPickerCtrl.$(BUILD_TYPE).o \
	src/CommentTree.$(BUILD_TYPE).o \
	src/ConsoleBuffer.$(BUILD_TYPE).o \
	src/CustomMessageDialog.$(BUILD_TYPE).o \
	src/CustomNumericType.$(BUILD_TYPE).o \
	src/DataMapScrollbar.$(BUILD_TYPE).o \
	src/DataMapSource.$(BUILD_TYPE).o \
	src/DataType.$(BUILD_TYPE).o \
	src/DataView.$(BUILD_TYPE).o \
	src/DetachableNotebook.$(BUILD_TYPE).o \
	src/DiffWindow.$(BUILD_TYPE).o \
	src/DisassemblyRegion.$(BUILD_TYPE).o \
	src/document.$(BUILD_TYPE).o \
	src/DocumentCtrl.$(BUILD_TYPE).o \
	src/EditCommentDialog.$(BUILD_TYPE).o \
	src/Events.$(BUILD_TYPE).o \
	src/FileReader.$(BUILD_TYPE).o \
	src/FileWriter.$(BUILD_TYPE).o \
	src/FillRangeDialog.$(BUILD_TYPE).o \
	src/FixedSizeValueRegion.$(BUILD_TYPE).o \
	src/FontCharacterCache.$(BUILD_TYPE).o \
	src/GotoOffsetDialog.$(BUILD_TYPE).o \
	src/HierarchicalByteAccumulator.$(BUILD_TYPE).o \
	src/HighlightColourMap.$(BUILD_TYPE).o \
	src/HSVColour.$(BUILD_TYPE).o \
	src/IntelHexExport.$(BUILD_TYPE).o \
	src/IntelHexImport.$(BUILD_TYPE).o \
	src/LicenseDialog.$(BUILD_TYPE).o \
	src/LoadingSpinner.$(BUILD_TYPE).o \
	src/lua-bindings/rehex_app_bind.$(BUILD_TYPE).o \
	src/lua-bindings/rehex_lib_bind.$(BUILD_TYPE).o \
	src/lua-plugin-preload.o \
	src/LuaPluginLoader.$(BUILD_TYPE).o \
	src/mainwindow.$(BUILD_TYPE).o \
	src/MathUtils.$(BUILD_TYPE).o \
	src/MultiSplitter.$(BUILD_TYPE).o \
	src/Palette.$(BUILD_TYPE).o \
	src/PopupTipWindow.$(BUILD_TYPE).o \
	src/ProceduralBitmap.$(BUILD_TYPE).o \
	src/ProxyDropTarget.$(BUILD_TYPE).o \
	src/RangeDialog.$(BUILD_TYPE).o \
	src/RangeProcessor.$(BUILD_TYPE).o \
	src/search.$(BUILD_TYPE).o \
	src/SettingsDialog.$(BUILD_TYPE).o \
	src/SettingsDialogByteColour.$(BUILD_TYPE).o \
	src/SettingsDialogFont.$(BUILD_TYPE).o \
	src/SettingsDialogGeneral.$(BUILD_TYPE).o \
	src/SettingsDialogHighlights.$(BUILD_TYPE).o \
	src/SettingsDialogKeyboard.$(BUILD_TYPE).o \
	src/StringPanel.$(BUILD_TYPE).o \
	src/Tab.$(BUILD_TYPE).o \
	src/TempDirectory.$(BUILD_TYPE).o \
	src/textentrydialog.$(BUILD_TYPE).o \
	src/ThreadPool.$(BUILD_TYPE).o \
	src/ToolPanel.$(BUILD_TYPE).o \
	src/ToolDock.$(BUILD_TYPE).o \
	src/util.$(BUILD_TYPE).o \
	src/VirtualMappingDialog.$(BUILD_TYPE).o \
	src/win32lib.$(BUILD_TYPE).o \
	src/WindowCommands.$(BUILD_TYPE).o \
	tests/BitmapTool.$(LIB_BUILD_TYPE).o \
	tests/BitOffset.$(LIB_BUILD_TYPE).o \
	tests/BufferTest1.$(LIB_BUILD_TYPE).o \
	tests/BufferTest2.$(LIB_BUILD_TYPE).o \
	tests/BufferTest3.$(LIB_BUILD_TYPE).o \
	tests/ByteAccumulator.$(LIB_BUILD_TYPE).o \
	tests/ByteColourMap.$(LIB_BUILD_TYPE).o \
	tests/ByteRangeMap.$(LIB_BUILD_TYPE).o \
	tests/ByteRangeSet.$(LIB_BUILD_TYPE).o \
	tests/ByteRangeTree.$(LIB_BUILD_TYPE).o \
	tests/CharacterEncoder.$(LIB_BUILD_TYPE).o \
	tests/CharacterFinder.$(LIB_BUILD_TYPE).o \
	tests/Checksum.$(LIB_BUILD_TYPE).o \
	tests/CommentsDataObject.$(LIB_BUILD_TYPE).o \
	tests/CommentTree.$(LIB_BUILD_TYPE).o \
	tests/ConsoleBuffer.$(LIB_BUILD_TYPE).o \
	tests/CustomNumericType.$(LIB_BUILD_TYPE).o \
	tests/DataType.$(LIB_BUILD_TYPE).o \
	tests/DataView.$(LIB_BUILD_TYPE).o \
	tests/DataHistogramAccumulator.$(LIB_BUILD_TYPE).o \
	tests/DiffWindow.$(LIB_BUILD_TYPE).o \
	tests/DisassemblyRegion.$(LIB_BUILD_TYPE).o \
	tests/Document.$(LIB_BUILD_TYPE).o \
	tests/DocumentCtrl.$(LIB_BUILD_TYPE).o \
	tests/endian_conv.$(LIB_BUILD_TYPE).o \
	tests/FastRectangleFiller.$(LIB_BUILD_TYPE).o \
	tests/FileReader.$(LIB_BUILD_TYPE).o \
	tests/FileWriter.$(LIB_BUILD_TYPE).o \
	tests/FourCC.$(LIB_BUILD_TYPE).o \
	tests/HierarchicalByteAccumulator.$(LIB_BUILD_TYPE).o \
	tests/HighlightColourMap.$(LIB_BUILD_TYPE).o \
	tests/HSVColour.$(LIB_BUILD_TYPE).o \
	tests/IntelHexExport.$(LIB_BUILD_TYPE).o \
	tests/IntelHexImport.$(LIB_BUILD_TYPE).o \
	tests/LuaPluginLoader.$(LIB_BUILD_TYPE).o \
	tests/main.$(LIB_BUILD_TYPE).o \
	tests/NestedOffsetLengthMap.$(LIB_BUILD_TYPE).o \
	tests/NumericTextCtrl.$(LIB_BUILD_TYPE).o \
	tests/MultiSplitter.$(LIB_BUILD_TYPE).o \
	tests/Range.$(LIB_BUILD_TYPE).o \
	tests/RangeProcessor.$(LIB_BUILD_TYPE).o \
	tests/search-bseq.$(LIB_BUILD_TYPE).o \
	tests/search-text.$(LIB_BUILD_TYPE).o \
	tests/SearchBase.$(LIB_BUILD_TYPE).o \
	tests/SearchValue.$(LIB_BUILD_TYPE).o \
	tests/SafeWindowPointer.$(LIB_BUILD_TYPE).o \
	tests/SharedDocumentPointer.$(LIB_BUILD_TYPE).o \
	tests/StringPanel.$(LIB_BUILD_TYPE).o \
	tests/Tab.$(LIB_BUILD_TYPE).o \
	tests/testutil.$(LIB_BUILD_TYPE).o \
	tests/ThreadPool.$(LIB_BUILD_TYPE).o \
	tests/util.$(LIB_BUILD_TYPE).o \
	tests/WindowCommands.$(LIB_BUILD_TYPE).o \
	$(WXLUA_OBJS) \
	$(WXBIND_OBJS) \
	$(EXTRA_TEST_OBJS)

$(DEFAULT_RELEASE_TEST_EXE_TARGET): $(TEST_OBJS) $(GTKCONFIG_EXE)
	$(CXX) $(BASE_CXXFLAGS) $(RELEASE_CFLAGS) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -DSHORT_VERSION='"$(VERSION)"' -DLIBDIR='"$(libdir)"' -DDATADIR='"$(datadir)"' -c -o res/version.o res/version.cpp
	$(CXX) $(BASE_CXXFLAGS) $(RELEASE_CFLAGS) $(CXXFLAGS) -o $@ $(TEST_OBJS) res/version.o $(LDFLAGS) $(LDLIBS)

$(DEFAULT_DEBUG_TEST_EXE_TARGET): $(TEST_OBJS) $(GTKCONFIG_EXE)
	$(CXX) $(BASE_CXXFLAGS) $(DEBUG_CFLAGS) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -DSHORT_VERSION='"$(VERSION)"' -DLIBDIR='"$(libdir)"' -DDATADIR='"$(datadir)"' -c -o res/version.o res/version.cpp
	$(CXX) $(BASE_CXXFLAGS) $(DEBUG_CFLAGS) $(CXXFLAGS) -o $@ $(TEST_OBJS) res/version.o $(LDFLAGS) $(LDLIBS)

$(EMBED_EXE): tools/embed.cpp
	$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) -o $@ $<

$(GTKCONFIG_EXE): tools/gtk-config.cpp
	$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) -o $@ $<

src/AboutDialog.$(BUILD_TYPE).o: res/icon128.h
src/ArtProvider.$(BUILD_TYPE).o: \
	res/ascii16.h res/ascii24.h res/ascii32.h res/ascii48.h \
	res/diff_fold16.h res/diff_fold24.h res/diff_fold32.h res/diff_fold48.h \
	res/offsets16.h res/offsets24.h res/offsets32.h res/offsets48.h
src/BitmapTool.$(BUILD_TYPE).o: \
	res/actual_size_dark_16.h res/actual_size_light_16.h \
	res/fit_to_screen_dark_16.h res/fit_to_screen_light_16.h \
	res/swap_horiz_dark_16.h res/swap_horiz_light_16.h \
	res/swap_vert_dark_16.h res/swap_vert_light_16.h \
	res/zoom_in_dark_16.h res/zoom_in_light_16.h \
	res/zoom_out_dark_16.h res/zoom_out_light_16.h \
	res/bg16.h
src/DataHistogramPanel.$(BUILD_TYPE).o: \
	res/spinner24.h res/zoom_in_dark_16.h res/zoom_in_light_16.h res/zoom_out_dark_16.h res/zoom_out_light_16.h
src/DiffWindow.$(BUILD_TYPE).o: res/icon16.h res/icon32.h res/icon48.h res/icon64.h
src/LicenseDialog.$(BUILD_TYPE).o: res/license.h
src/LuaPluginLoader.$(BUILD_TYPE).o: src/lua-bindings/rehex_app_bind.h src/lua-bindings/rehex_lib_bind.h src/lua-plugin-preload.h
src/mainwindow.$(BUILD_TYPE).o: res/icon16.h res/icon32.h res/icon48.h res/icon64.h
src/SettingsDialogKeyboard.$(BUILD_TYPE).o: res/shortcut48.h
src/StringPanel.$(BUILD_TYPE).o: res/spinner24.h
src/ToolDock.$(BUILD_TYPE).o: res/dock_bottom.h res/dock_left.h res/dock_right.h res/dock_top.h

res/license.done: LICENSE.txt $(EMBED_EXE)
	$(EMBED_EXE) $< LICENSE_TXT res/license.c res/license.h
	touch $@

res/license.c res/license.h: res/license.done ;

res/%.c res/%.h: res/%.png $(EMBED_EXE)
	$(EMBED_EXE) $< $*_png res/$*.c res/$*.h

res/%.c res/%.h: res/%.gif $(EMBED_EXE)
	$(EMBED_EXE) $< $*_gif res/$*.c res/$*.h

src/lua-bindings/rehex_app_bind.done: src/lua-bindings/rehex_app.i src/lua-bindings/rehex_app_override.hpp src/lua-bindings/rehex_app_rules.lua src/lua-bindings/rehex_lib_datatypes.lua $(WXLUA_BINDINGS)
	$(LUA) -e"rulesFilename=\"src/lua-bindings/rehex_app_rules.lua\"" wxLua/bindings/genwxbind.lua
	
	# genwxbind.lua may not modify individual files if they are already up to date.
	touch -c src/lua-bindings/rehex_app_bind.cpp
	touch -c src/lua-bindings/rehex_app_bind.h

	touch $@

src/lua-bindings/rehex_app_bind.cpp src/lua-bindings/rehex_app_bind.h src/lua-bindings/rehex_app_datatypes.lua: src/lua-bindings/rehex_app_bind.done ;

src/lua-bindings/rehex_lib_bind.done: src/lua-bindings/rehex_lib.i src/lua-bindings/rehex_lib_override.hpp src/lua-bindings/rehex_lib_rules.lua $(WXLUA_BINDINGS)
	$(LUA) -e"rulesFilename=\"src/lua-bindings/rehex_lib_rules.lua\"" wxLua/bindings/genwxbind.lua
	
	# genwxbind.lua may not modify individual files if they are already up to date.
	touch -c src/lua-bindings/rehex_lib_bind.cpp
	touch -c src/lua-bindings/rehex_lib_bind.h

	touch $@

src/lua-bindings/rehex_lib_bind.cpp src/lua-bindings/rehex_lib_bind.h src/lua-bindings/rehex_lib_datatypes.lua: src/lua-bindings/rehex_lib_bind.done ;

$(WXLUA_BINDINGS):
	$(MAKE) -C wxLua/bindings/ wxadv wxaui wxbase wxcore wxlua wxpropgrid LUA=$(LUA)
	touch $@

src/lua-plugin-preload.done: src/lua-plugin-preload.lua $(EMBED_EXE)
	$(EMBED_EXE) $< LUA_PLUGIN_PRELOAD src/lua-plugin-preload.c src/lua-plugin-preload.h
	touch $@

src/lua-plugin-preload.c src/lua-plugin-preload.h: src/lua-plugin-preload.done ;

LUA_LIB_OBJS := \
	src/BitOffset.$(DLL_BUILD_TYPE).o \
	src/ByteRangeSet.$(DLL_BUILD_TYPE).o \
	src/MathUtils.$(DLL_BUILD_TYPE).o \
	src/lua-bindings/rehex_lib_bind.$(DLL_BUILD_TYPE).o \
	src/lua-bindings/rehex_lib_module.$(DLL_BUILD_TYPE).o \
	wxLua/modules/wxlua/bit.$(DLL_BUILD_TYPE).o \
	wxLua/modules/wxlua/lbitlib.$(DLL_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlbind.$(DLL_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlcallb.$(DLL_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxllua.$(DLL_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlobject.$(DLL_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlstate.$(DLL_BUILD_TYPE).o \
	wxLua/modules/wxlua/wxlua_bind.$(DLL_BUILD_TYPE).o

DEFAULT_REHEX_LUA_LIB_TARGET ?= $(REHEX_LUA_LIB_DLL)

$(DEFAULT_REHEX_LUA_LIB_TARGET): $(LUA_LIB_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(EXTRA_LUA_LIB_LDFLAGS) -fPIC -shared -o $@ $^ $(LDLIBS)

tests/%.release.o: tests/%.cpp $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(RELEASE_CFLAGS) $(CXXFLAGS) -I./googletest/include/ $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

tests/%.debug.o: tests/%.cpp $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(DEBUG_CFLAGS) $(CXXFLAGS) -I./googletest/include/ $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.release.o: wxLua/%.c $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CC) $(BASE_CFLAGS) $(RELEASE_CFLAGS) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.debug.o: wxLua/%.c $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CC) $(BASE_CFLAGS) $(DEBUG_CFLAGS) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.release_pic.o: wxLua/%.c $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CC) $(BASE_CFLAGS) $(RELEASE_CFLAGS) $(CFLAGS) -fPIC $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.debug_pic.o: wxLua/%.c $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CC) $(BASE_CFLAGS) $(DEBUG_CFLAGS) $(CFLAGS) -fPIC $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.release.o: wxLua/%.cpp $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(RELEASE_CFLAGS) $(CXXFLAGS) -Wno-deprecated-declarations $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.debug.o: wxLua/%.cpp $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(DEBUG_CFLAGS) $(CXXFLAGS) -Wno-deprecated-declarations $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.release_pic.o: wxLua/%.cpp $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(RELEASE_CFLAGS) $(CXXFLAGS) -fPIC -Wno-deprecated-declarations $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.debug_pic.o: wxLua/%.cpp $(WXLUA_BINDINGS)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(DEBUG_CFLAGS) $(CXXFLAGS) -fPIC -Wno-deprecated-declarations $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

googletest/src/%.o: googletest/src/%.cc
	$(DEPPRE)
	$(CXX) $(CXXFLAGS) -I./googletest/include/ -I./googletest/ $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.release.o: %.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(GTK_CFLAGS) $(RELEASE_CFLAGS) $(HELP_CFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.debug.o: %.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(GTK_CFLAGS) $(DEBUG_CFLAGS) $(HELP_CFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.profile.o: %.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(GTK_CFLAGS) $(PROFILE_CFLAGS) $(HELP_CFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.release_pic.o: %.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(GTK_CFLAGS) $(RELEASE_CFLAGS) $(HELP_CFLAGS) $(CXXFLAGS) -fPIC $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.debug_pic.o: %.cpp $(WXLUA_BINDINGS) $(GTKCONFIG_EXE)
	$(DEPPRE)
	$(CXX) $(BASE_CXXFLAGS) $(GTK_CFLAGS) $(DEBUG_CFLAGS) $(HELP_CFLAGS) $(CXXFLAGS) -fPIC $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.o: %.c
	$(DEPPRE)
	$(CC) $(BASE_CFLAGS) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

wxLua/%.cpp: $(WXLUA_BINDINGS)
	@true

# We can generate a compile_commands.json for use by source checkers and IDEs which know how to
# parse it such as clangd and JetBrains Fleet.
#
# The compile_commands.json fragment for each file is written out under .cc/ and then merged into
# the top-level compile_commands.json, all are rebuilt when the Makefile(s) are changed.

COMPILE_COMMAND_DEPENDENCIES := $(wildcard Makefile Makefile.*) $(JQ)
COMPILE_COMMAND_INTERMEDIATE_DIR := .cc

.PHONY: compile_commands.json
compile_commands.json: $(addprefix $(COMPILE_COMMAND_INTERMEDIATE_DIR)/,$(addsuffix .compile_command.json,$(APP_OBJS) $(TEST_OBJS)))
	cat $^ | $(JQ) -s . > $@

# $(call emit-compile-command,$(COMPILE_COMMAND_INTERMEDIATE_DIR)/foo.o.compile_command.json,foo.c,$(CC) $(CFLAGS))
define emit-compile-command
	@mkdir -p $(dir $(1))
	echo "{ \"directory\": $$(pwd | $(JQ) -R .), \"file\": $$(echo "$(patsubst $(COMPILE_COMMAND_INTERMEDIATE_DIR)/%,%,$(patsubst %.compile_command.json,%,$(2)))" | $(JQ) -R .), \"command\": $$(echo "$(3) -o $(2) $(patsubst $(COMPILE_COMMAND_INTERMEDIATE_DIR)/%,%,$(patsubst %.compile_command.json,%,$(2)))" | $(JQ) -R .) }" > $(1)
endef

$(COMPILE_COMMAND_INTERMEDIATE_DIR)/googletest/src/%.o.compile_command.json: googletest/src/%.cc $(GTKCONFIG_EXE) $(COMPILE_COMMAND_DEPENDENCIES)
	$(call emit-compile-command,$@,$<,$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) -I./googletest/include/ -I./googletest/)

$(COMPILE_COMMAND_INTERMEDIATE_DIR)/tests/%.o.compile_command.json: tests/%.cpp $(GTKCONFIG_EXE) $(COMPILE_COMMAND_DEPENDENCIES)
	$(call emit-compile-command,$@,$<,$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) -I./googletest/include/)

$(COMPILE_COMMAND_INTERMEDIATE_DIR)/tests/%.$(BUILD_TYPE).o.compile_command.json: tests/%.cpp $(GTKCONFIG_EXE) $(COMPILE_COMMAND_DEPENDENCIES)
	$(call emit-compile-command,$@,$<,$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) -I./googletest/include/)

$(COMPILE_COMMAND_INTERMEDIATE_DIR)/%.o.compile_command.json: %.c $(COMPILE_COMMAND_DEPENDENCIES)
	$(call emit-compile-command,$@,$<,$(CC) $(BASE_CFLAGS) $(CFLAGS))

$(COMPILE_COMMAND_INTERMEDIATE_DIR)/%.$(BUILD_TYPE).o.compile_command.json: %.c $(COMPILE_COMMAND_DEPENDENCIES)
	$(call emit-compile-command,$@,$<,$(CC) $(BASE_CFLAGS) $(CFLAGS))

$(COMPILE_COMMAND_INTERMEDIATE_DIR)/%.o.compile_command.json: %.cpp $(GTKCONFIG_EXE) $(COMPILE_COMMAND_DEPENDENCIES)
	$(call emit-compile-command,$@,$<,$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS))

$(COMPILE_COMMAND_INTERMEDIATE_DIR)/%.$(BUILD_TYPE).o.compile_command.json: %.cpp $(GTKCONFIG_EXE) $(COMPILE_COMMAND_DEPENDENCIES)
	$(call emit-compile-command,$@,$<,$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS))

# Dummy rule for jq on platforms where we rely on a system-provided binary.
jq:

.PHONY: help/rehex.chm
help/rehex.chm: $(EXE)
	$(MAKE) -C help/ REHEX=../$(EXE) rehex.chm

rehex.chm: help/rehex.chm
	cp $< $@

.PHONY: help/rehex.htb
help/rehex.htb: $(EXE)
	$(MAKE) -C help/ REHEX=../$(EXE) rehex.htb

.PHONY: online-help
online-help: $(EXE)
	$(MAKE) -C help/ REHEX=../$(EXE) online-help

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
	sed -i -e "s|\$$(GIT_COMMIT_SHA)|$(GIT_COMMIT_SHA)|g" rehex-$(VERSION)/Makefile
	sed -i -e "s|\$$(GIT_COMMIT_TIME)|$(GIT_COMMIT_TIME)|g" rehex-$(VERSION)/Makefile
endif
	
	# Generate reproducible tarball. All files use git commit timestamp.
	find rehex-$(VERSION) -print0 | \
		LC_ALL=C sort -z | \
		tar \
			--format=ustar \
			--mtime=@$(GIT_COMMIT_TIME) \
			--owner=0 --group=0 --numeric-owner \
			--no-recursion --null  -T - \
			-cf - | \
		gzip -9n - > rehex-$(VERSION).tar.gz
