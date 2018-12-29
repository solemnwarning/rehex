# Reverse Engineer's Hex Editor
# Copyright (C) 2017-2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

WX_CONFIG ?= "wx-config"
LLVM_CONFIG ?= "llvm-config"

EXE ?= "rehex"

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

DEPDIR := .d
$(shell mkdir -p $(DEPDIR)/src/ $(DEPDIR)/tools/ $(DEPDIR)/tests/tap/)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$@.Td
DEPPOST = @mv -f $(DEPDIR)/$@.Td $(DEPDIR)/$@.d && touch $@

ALL_TESTS := \
	tests/buffer.t \
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

APP_OBJS := \
	src/app.o \
	src/buffer.o \
	src/CodeCtrl.o \
	src/decodepanel.o \
	src/disassemble.o \
	src/document.o \
	src/mainwindow.o \
	src/search.o \
	src/textentrydialog.o \
	src/util.o \
	src/win32lib.o

$(EXE): $(APP_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_BUFFER_OBJS := \
	src/buffer.o \
	src/win32lib.o \
	tests/buffer.o \
	tests/tap/basic.o

tests/buffer.t: $(TESTS_BUFFER_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

TESTS_DOCUMENT_OBJS := \
	src/buffer.o \
	src/document.o \
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

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

include $(shell find .d/ -name '*.d' -type f)
