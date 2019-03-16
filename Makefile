# Reverse Engineer's Hex Editor
# Copyright (C) 2017-2019 Daniel Collins <solemnwarning@solemnwarning.net>
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

WX_CONFIG ?= wx-config
LLVM_CONFIG ?= llvm-config

EXE ?= rehex
EMBED_EXE ?= ./tools/embed

WX_CXXFLAGS := $(shell $(WX_CONFIG) --cxxflags base core aui propgrid adv)
WX_LIBS     := $(shell $(WX_CONFIG) --libs     base core aui propgrid adv)

# I would use llvm-config --cxxflags, but that specifies more crap it has no
# business interfering with (e.g. warnings) than things it actually needs.
# Hopefully this is enough to get by everywhere.
LLVM_CXXFLAGS := -I$(shell $(LLVM_CONFIG) --includedir)
LLVM_LIBS     := $(shell $(LLVM_CONFIG) --ldflags --libs --system-libs)

CFLAGS   := -Wall -std=c99   -ggdb -I. -Iinclude/ $(CFLAGS)
CXXFLAGS := -Wall -std=c++11 -ggdb -I. -Iinclude/ $(LLVM_CXXFLAGS) $(WX_CXXFLAGS) $(CXXFLAGS)

LIBS := $(LLVM_LIBS) $(WX_LIBS) -ljansson $(LIBS)

ifeq ($(DEBUG),)
	DEBUG=0
endif

ifeq ($(DEBUG),0)
	CFLAGS   += -DNDEBUG
	CXXFLAGS += -DNDEBUG
else
	CFLAGS   += -g
	CXXFLAGS += -g
endif

VERSION    := Snapshot $(shell git log -1 --format="%H")
BUILD_DATE := $(shell date '+%F')

DEPDIR := .d
$(shell mkdir -p $(DEPDIR)/res/ $(DEPDIR)/src/ $(DEPDIR)/tools/ $(DEPDIR)/tests/tap/)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$@.Td
DEPPOST = @mv -f $(DEPDIR)/$@.Td $(DEPDIR)/$@.d && touch $@

ALL_TESTS := \
	tests/buffer.t \
	tests/CommentTree.t \
	tests/document.t \
	tests/NestedOffsetLengthMap.t \
	tests/NumericTextCtrl.t \
	tests/search-bseq.t \
	tests/search-text.t \
	tests/util.t

.PHONY: all
all: $(EXE)

.PHONY: check
check: $(ALL_TESTS)
	prove tests/

.PHONY: clean
clean:
	rm -f $(APP_OBJS)
	rm -f $(EXE)
	rm -f $(TESTS_BUFFER_OBJS)
	rm -f $(TESTS_DOCUMENT_OBJS)
	rm -f $(TESTS_NUMERICTEXTCTRL_OBJS)
	rm -f $(TESTS_SEARCH_BSEQ_OBJS)
	rm -f $(TESTS_SEARCH_TEXT_OBJS)
	rm -f $(TESTS_UTIL_OBJS)
	rm -f $(ALL_TESTS)
	rm -f $(EMBED_EXE)
	rm -f res/icon16.c res/icon16.h res/icon16.o
	rm -f res/icon32.c res/icon32.h res/icon32.o
	rm -f res/icon48.c res/icon48.h res/icon48.o

APP_OBJS := \
	res/icon16.o \
	res/icon32.o \
	res/icon48.o \
	res/icon64.o \
	res/icon128.o \
	res/license.o \
	res/version.o \
	src/AboutDialog.o \
	src/app.o \
	src/buffer.o \
	src/ClickText.o \
	src/CodeCtrl.o \
	src/CommentTree.o \
	src/decodepanel.o \
	src/disassemble.o \
	src/document.o \
	src/LicenseDialog.o \
	src/mainwindow.o \
	src/Palette.o \
	src/search.o \
	src/textentrydialog.o \
	src/ToolPanel.o \
	src/util.o \
	src/win32lib.o \
	$(EXTRA_APP_OBJS)

$(EXE): $(APP_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_BUFFER_OBJS := \
	src/buffer.o \
	src/win32lib.o \
	tests/buffer.o \
	tests/tap/basic.o

tests/buffer.t: $(TESTS_BUFFER_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_COMMENTTREE_OBJS := \
	src/buffer.o \
	src/CommentTree.o \
	src/document.o \
	src/Palette.o \
	src/textentrydialog.o \
	src/ToolPanel.o \
	src/util.o \
	src/win32lib.o \
	tests/CommentTree.o \
	tests/tap/basic.o

tests/CommentTree.t: $(TESTS_COMMENTTREE_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_DOCUMENT_OBJS := \
	src/buffer.o \
	src/document.o \
	src/Palette.o \
	src/textentrydialog.o \
	src/util.o \
	src/win32lib.o \
	tests/document.o \
	tests/tap/basic.o

tests/document.t: $(TESTS_DOCUMENT_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_NESTEDOFFSETLENGTHMAP_OBJS := \
	tests/NestedOffsetLengthMap.o \
	tests/tap/basic.o

tests/NestedOffsetLengthMap.t: $(TESTS_NESTEDOFFSETLENGTHMAP_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_NUMERICTEXTCTRL_OBJS := \
	tests/NumericTextCtrl.o \
	tests/tap/basic.o

tests/NumericTextCtrl.t: $(TESTS_NUMERICTEXTCTRL_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_SEARCH_BSEQ_OBJS := \
	src/buffer.o \
	src/document.o \
	src/Palette.o \
	src/search.o \
	src/textentrydialog.o \
	src/util.o \
	src/win32lib.o \
	tests/search-bseq.o \
	tests/tap/basic.o

tests/search-bseq.t: $(TESTS_SEARCH_BSEQ_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_SEARCH_TEXT_OBJS := \
	src/buffer.o \
	src/document.o \
	src/Palette.o \
	src/search.o \
	src/textentrydialog.o \
	src/util.o \
	src/win32lib.o \
	tests/search-text.o \
	tests/tap/basic.o

tests/search-text.t: $(TESTS_SEARCH_TEXT_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_UTIL_OBJS := \
	src/util.o \
	tests/util.o \
	tests/tap/basic.o

tests/util.t: $(TESTS_UTIL_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(EMBED_EXE): tools/embed.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

src/AboutDialog.o: res/icon128.h
src/mainwindow.o: res/icon16.h res/icon32.h res/icon48.h res/icon64.h

res/license.c res/license.h: LICENSE.txt $(EMBED_EXE)
	$(EMBED_EXE) $< LICENSE_TXT res/license.c res/license.h

res/%.c res/%.h: res/%.png $(EMBED_EXE)
	$(EMBED_EXE) $< $*_png res/$*.c res/$*.h

.PHONY: res/version.o
res/version.o:
	$(CXX) $(CXXFLAGS) -DVERSION='"$(VERSION)"' -DBUILD_DATE='"$(BUILD_DATE)"' -c -o $@ res/version.cpp

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

include $(shell find .d/ -name '*.d' -type f)

prefix      ?= /usr/local
bindir      ?= $(prefix)/bin
datarootdir ?= $(prefix)/share

.PHONY: install
install: $(EXE)
	install -D -m 0755 $(EXE) $(DESTDIR)$(bindir)/$(EXE)
	
	for s in 16 32 48 64 128 256 512; \
	do \
		install -D -m 0644 res/icon$${s}.png $(DESTDIR)$(datarootdir)/icons/hicolor/$${s}x$${s}/apps/rehex.png; \
	done
	
	install -D -m 0644 res/rehex.desktop $(DESTDIR)$(datarootdir)/applications/rehex.desktop

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(bindir)/$(EXE)
	rm -f $(DESTDIR)$(datarootdir)/applications/rehex.desktop
	
	for s in 16 32 48 64 128 256 512; \
	do \
		rm -f $(DESTDIR)$(datarootdir)/icons/hicolor/$${s}x$${s}/apps/rehex.png; \
	done
