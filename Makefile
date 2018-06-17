# Reverse Engineer's Hex Editor
# Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

WX_CXXFLAGS := $(shell $(WX_CONFIG) --cxxflags)
WX_LIBS     := $(shell $(WX_CONFIG) --libs)

CFLAGS   := -Wall -std=c99   -ggdb -I. -Iinclude/                $(CFLAGS)
CXXFLAGS := -Wall -std=c++11 -ggdb -I. -Iinclude/ $(WX_CXXFLAGS) $(CXXFLAGS)

LIBS := $(WX_LIBS) -ljansson $(LIBS)

DEPDIR := .d
$(shell mkdir -p $(DEPDIR)/src/ $(DEPDIR)/tools/ $(DEPDIR)/tests/tap/)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$@.Td
DEPPOST = @mv -f $(DEPDIR)/$@.Td $(DEPDIR)/$@.d && touch $@

TESTS := tests/buffer.t tests/document.t tests/search-bseq.t tests/search-text.t tests/util.t tests/NumericTextCtrl.t

all: rehex$(EXE)

check: $(TESTS)
	prove -v tests/

rehex$(EXE): src/app.o src/mainwindow.o src/document.o src/buffer.o src/textentrydialog.o src/win32lib.o src/decodepanel.o src/search.o src/util.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

tests/buffer.t: src/buffer.o tests/buffer.o tests/tap/basic.o src/win32lib.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

tests/document.t: src/document.o src/buffer.o src/textentrydialog.o tests/document.o tests/tap/basic.o src/win32lib.o src/util.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

tests/NumericTextCtrl.t: tests/NumericTextCtrl.cpp tests/tap/basic.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

tests/search-bseq.t: tests/search-bseq.o src/document.o src/buffer.o src/textentrydialog.o tests/tap/basic.o src/win32lib.o src/search.o src/util.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

tests/search-text.t: tests/search-text.o src/document.o src/buffer.o src/textentrydialog.o tests/tap/basic.o src/win32lib.o src/search.o src/util.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

tests/util.t: tests/util.o src/util.o tests/tap/basic.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

include $(shell find .d/ -name '*.d' -type f)
