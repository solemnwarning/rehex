# Reverse Engineer's Hex Editor
# Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

HHC ?= "C:\Program Files (x86)\HTML Help Workshop\hhc.exe"
PERL ?= perl

PAGES := \
	index \
	virt-mapping

.PHONY: all
all:
	@echo "Usage: make rehex.htb OR rehex.chm OR online-help" 1>&2
	@false

# Don't leave empty/incomplete pages if rendering fails
.DELETE_ON_ERROR:

.PHONY: clean
clean:
	rm -rf chm/output/
	rm -rf wx/output/
	rm -rf online/output/

CHM_TARGETS := \
	$(addsuffix .html,$(addprefix chm/output/,$(PAGES))) \
	chm/output/rehex.hhc \
	chm/output/rehex.hhk

CHM_TEMPLATE_PATH := chm/templates/:pages/

rehex.chm: $(CHM_TARGETS)
	cp content/* chm/rehex.hhp chm/output/
	# hhc.exe returns 0 on failure and 1 on success... good job Microsoft.
	# https://stackoverflow.com/a/39040033
	! $(HHC) chm/output/rehex.hhp
	cp chm/output/rehex.chm $@

chm/output/rehex.hhc: chm/templates/hhc.tt
	$(PERL) template.pl hhc $(CHM_TEMPLATE_PATH) > chm/output/rehex.hhc

chm/output/rehex.hhk: chm/templates/hhk.tt
	$(PERL) template.pl hhk $(CHM_TEMPLATE_PATH) > chm/output/rehex.hhk

chm/output/%.html: pages/%.tt
	@mkdir -p chm/output/
	$(PERL) template.pl $* $(CHM_TEMPLATE_PATH) > $@

WX_TARGETS := \
	$(addsuffix .html,$(addprefix wx/output/,$(PAGES))) \
	wx/output/rehex.hhc \
	wx/output/rehex.hhk

WX_TEMPLATE_PATH := wx/templates/:pages/

rehex.htb: $(WX_TARGETS)
	cp content/* wx/rehex.hhp wx/output/
	zip -rj rehex.htb wx/output/

wx/output/rehex.hhc: wx/templates/hhc.tt
	$(PERL) template.pl hhc $(WX_TEMPLATE_PATH) > wx/output/rehex.hhc

wx/output/rehex.hhk: wx/templates/hhk.tt
	$(PERL) template.pl hhk $(WX_TEMPLATE_PATH) > wx/output/rehex.hhk

wx/output/%.html: pages/%.tt
	@mkdir -p wx/output/
	$(PERL) template.pl $* $(WX_TEMPLATE_PATH) > $@

ONLINE_TARGETS := \
	$(addsuffix .html,$(addprefix online/output/,$(PAGES)))

ONLINE_TEMPLATE_PATH := online/templates/:pages/

.PHONY: online-help
online-help: $(ONLINE_TARGETS)
	cp content/* online/content/* online/output/

online/output/%.html: pages/%.tt
	@mkdir -p online/output/
	$(PERL) template.pl $* $(ONLINE_TEMPLATE_PATH) > $@
