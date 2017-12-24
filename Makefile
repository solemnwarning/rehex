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

WX_CXXFLAGS := $(shell wx-config --cxxflags)
WX_LIBS     := $(shell wx-config --libs)

CFLAGS   := -Wall -std=c99   -ggdb -I./
CXXFLAGS := -Wall -std=c++11 -ggdb -I./ $(WX_CXXFLAGS)

DEPDIR := .d
$(shell mkdir -p $(DEPDIR)/src/ $(DEPDIR)/tools/ $(DEPDIR)/tests/tap/)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$@.Td
DEPPOST = @mv -f $(DEPDIR)/$@.Td $(DEPDIR)/$@.d && touch $@

TESTS := tests/buffer.t

all: rehex

check: $(TESTS)
	prove -v tests/

rehex: src/app.o src/mainwindow.o src/document.o src/buffer.o src/textentrydialog.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(WX_LIBS)

tests/buffer.t: src/buffer.o tests/buffer.o tests/tap/basic.o
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

include $(shell find .d/ -name '*.d' -type f)
