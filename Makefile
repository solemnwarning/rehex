# Reverse Engineer's Hex Editor
# Copyright (C) 2017-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

EXE ?= rehex
EMBED_EXE ?= ./tools/embed

# Wrapper around the $(shell) function that aborts the build if the command
# exits with a nonzero status.
shell-or-die = $\
	$(eval sod_out := $(shell $(1); echo $$?))$\
	$(if $(filter 0,$(lastword $(sod_out))),$\
		$(wordlist 1, $(shell echo $$(($(words $(sod_out)) - 1))), $(sod_out)),$\
		$(error $(1) exited with status $(lastword $(sod_out))))

WX_CXXFLAGS := $(call shell-or-die,$(WX_CONFIG) --cxxflags base core aui propgrid adv)
WX_LIBS     := $(call shell-or-die,$(WX_CONFIG) --libs     base core aui propgrid adv)

CFLAGS   := -Wall -std=c99   -ggdb -I. -Iinclude/ $(CFLAGS)
CXXFLAGS := -Wall -std=c++11 -ggdb -I. -Iinclude/ $(WX_CXXFLAGS) $(CXXFLAGS)

LIBS := $(WX_LIBS) -ljansson -lcapstone $(LIBS)

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

# Define this for releases
# VERSION := x

# NOTE: Not evaluated when building from dist
GIT_COMMIT_SHA  ?= $(call shell-or-die,git log -1 --format="%H")
GIT_COMMIT_TIME  = $(call shell-or-die,git log -1 --format="%ct")

ifdef VERSION
	LONG_VERSION := Version $(VERSION)
else
	VERSION      := $(GIT_COMMIT_SHA)
	LONG_VERSION := Snapshot $(GIT_COMMIT_SHA)
endif

DEPDIR := .d
$(shell mkdir -p $(DEPDIR)/res/ $(DEPDIR)/src/ $(DEPDIR)/tools/ $(DEPDIR)/tests/ $(DEPDIR)/googletest/src/)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$@.Td
DEPPOST = @mv -f $(DEPDIR)/$@.Td $(DEPDIR)/$@.d && touch $@

.PHONY: all
all: $(EXE)

.PHONY: check
check: tests/all-tests
	./tests/all-tests

.PHONY: clean
clean:
	rm -f res/ascii16.c   res/ascii16.h \
	      res/ascii24.c   res/ascii24.h \
	      res/ascii32.c   res/ascii32.h \
	      res/ascii48.c   res/ascii48.h \
	      res/icon16.c    res/icon16.h \
	      res/icon32.c    res/icon32.h \
	      res/icon48.c    res/icon48.h \
	      res/icon64.c    res/icon64.h \
	      res/icon128.c   res/icon128.h \
	      res/license.c   res/license.h \
	      res/offsets16.c res/offsets16.h \
	      res/offsets24.c res/offsets24.h \
	      res/offsets32.c res/offsets32.h \
	      res/offsets48.c res/offsets48.h
	
	rm -f $(APP_OBJS)
	rm -f $(EXE)
	rm -f $(TEST_OBJS)
	rm -f ./tests/all-tests
	rm -f $(EMBED_EXE)

.PHONY: distclean
distclean: clean

APP_OBJS := \
	res/ascii16.o \
	res/ascii24.o \
	res/ascii32.o \
	res/ascii48.o \
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
	src/AboutDialog.o \
	src/app.o \
	src/ArtProvider.o \
	src/buffer.o \
	src/ByteRangeSet.o \
	src/ClickText.o \
	src/CodeCtrl.o \
	src/CommentTree.o \
	src/decodepanel.o \
	src/DiffWindow.o \
	src/disassemble.o \
	src/document.o \
	src/DocumentCtrl.o \
	src/EditCommentDialog.o \
	src/Events.o \
	src/LicenseDialog.o \
	src/mainwindow.o \
	src/Palette.o \
	src/search.o \
	src/SelectRangeDialog.o \
	src/textentrydialog.o \
	src/Tab.o \
	src/ToolPanel.o \
	src/util.o \
	src/win32lib.o \
	$(EXTRA_APP_OBJS)

$(EXE): $(APP_OBJS)
	$(CXX) $(CXXFLAGS) -DLONG_VERSION='"$(LONG_VERSION)"' -c -o res/version.o res/version.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ res/version.o $(LIBS)

TEST_OBJS := \
	googletest/src/gtest-all.o \
	res/ascii16.o \
	res/ascii24.o \
	res/ascii32.o \
	res/ascii48.o \
	res/icon16.o \
	res/icon32.o \
	res/icon48.o \
	res/icon64.o \
	res/offsets16.o \
	res/offsets24.o \
	res/offsets32.o \
	res/offsets48.o \
	src/ArtProvider.o \
	src/buffer.o \
	src/ByteRangeSet.o \
	src/CommentTree.o \
	src/DiffWindow.o \
	src/document.o \
	src/DocumentCtrl.o \
	src/EditCommentDialog.o \
	src/Events.o \
	src/Palette.o \
	src/search.o \
	src/textentrydialog.o \
	src/ToolPanel.o \
	src/util.o \
	src/win32lib.o \
	tests/buffer.o \
	tests/ByteRangeSet.o \
	tests/CommentsDataObject.o \
	tests/CommentTree.o \
	tests/DiffWindow.o \
	tests/Document.o \
	tests/main.o \
	tests/NestedOffsetLengthMap.o \
	tests/NumericTextCtrl.o \
	tests/search-bseq.o \
	tests/search-text.o \
	tests/SearchValue.o \
	tests/SafeWindowPointer.o \
	tests/SharedDocumentPointer.o \
	tests/util.o

tests/all-tests: $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(EMBED_EXE): tools/embed.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

src/AboutDialog.o: res/icon128.h
src/ArtProvider.o: res/ascii16.h res/ascii24.h res/ascii32.h res/ascii48.h res/offsets16.h res/offsets24.h res/offsets32.h res/offsets48.h
src/DiffWindow.o: res/icon16.h res/icon32.h res/icon48.h res/icon64.h
src/LicenseDialog.o: res/license.h
src/mainwindow.o: res/icon16.h res/icon32.h res/icon48.h res/icon64.h

res/license.c res/license.h: LICENSE.txt $(EMBED_EXE)
	$(EMBED_EXE) $< LICENSE_TXT res/license.c res/license.h

res/%.c res/%.h: res/%.png $(EMBED_EXE)
	$(EMBED_EXE) $< $*_png res/$*.c res/$*.h

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

tests/%.o: tests/%.cpp
	$(CXX) $(CXXFLAGS) -I./googletest/include/ $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

googletest/src/%.o: googletest/src/%.cc
	$(CXX) $(CXXFLAGS) -I./googletest/include/ -I./googletest/ $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<
	$(DEPPOST)

include $(shell find .d/ -name '*.d' -type f)

prefix      ?= /usr/local
exec_prefix ?= $(prefix)
bindir      ?= $(exec_prefix)/bin
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
