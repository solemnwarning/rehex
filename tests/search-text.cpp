/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#undef NDEBUG
#include <assert.h>

#include <stdio.h>
#include <wx/init.h>
#include <wx/wx.h>

#include "tests/tap/basic.h"

#include "../src/document.hpp"
#include "../src/search.hpp"

#define TMPFILE  "tests/.tmpfile"

int main(int argc, char **argv)
{
	wxApp::SetInstance(new wxApp());
	wxEntryStart(argc, argv);
	wxTheApp->OnInit();
	
	plan_lazy();
	
	FILE *tmp = fopen(TMPFILE, "wb");
	assert(tmp != NULL);
	assert(fwrite("abcdefghijklmnop", 16, 1, tmp) == 1);
	fclose(tmp);
	
	/* Basic tests */
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "abc");
		
		is_int(0, s.find_next(0), "REHEX::Search::Text::find_next() finds string at start of file");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "def");
		
		is_int(3, s.find_next(0), "REHEX::Search::Text::find_next() finds string in middle of file");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "nop");
		
		is_int(13, s.find_next(0), "REHEX::Search::Text::find_next() finds string at end of file");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "abcdefghijklmnop");
		
		is_int(0, s.find_next(0), "REHEX::Search::Text::find_next() finds string which is whole file");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "def");
		
		is_int(3, s.find_next(2), "REHEX::Search::Text::find_next() finds string starting after from_offset");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "def");
		
		is_int(3, s.find_next(3), "REHEX::Search::Text::find_next() finds string starting at from_offset");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "def");
		
		is_int(-1, s.find_next(4), "REHEX::Search::Text::find_next() doesn't find string starting before from_offset");
	}
	
	/* Range limiting */
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "bcd");
		
		s.limit_range(1, 15);
		
		is_int(1, s.find_next(0), "REHEX::Search::Text::find_next() finds string at start of range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "def");
		
		s.limit_range(1, 15);
		
		is_int(3, s.find_next(0), "REHEX::Search::Text::find_next() finds string in middle of range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "mno");
		
		s.limit_range(1, 15);
		
		is_int(12, s.find_next(0), "REHEX::Search::Text::find_next() finds string at end of range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "bcdefghijklmno");
		
		s.limit_range(1, 15);
		
		is_int(1, s.find_next(0), "REHEX::Search::Text::find_next() finds string which is whole range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "abc");
		
		s.limit_range(1, 15);
		
		is_int(-1, s.find_next(0), "REHEX::Search::Text::find_next() doesn't find string starting before range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "nop");
		
		s.limit_range(1, 15);
		
		is_int(-1, s.find_next(0), "REHEX::Search::Text::find_next() doesn't find string ending beyond range");
	}
	
	/* Alignment */
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "def");
		
		s.require_alignment(3);
		
		is_int(3, s.find_next(0), "REHEX::Search::Text::find_next() finds strings which are aligned");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "def");
		
		s.require_alignment(2);
		
		is_int(-1, s.find_next(0), "REHEX::Search::Text::find_next() doesn't find strings which aren't aligned");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "efg");
		
		s.require_alignment(3, 1);
		
		is_int(4, s.find_next(0), "REHEX::Search::Text::find_next() finds strings which are relatively aligned");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "efg");
		
		s.require_alignment(2, 1);
		
		is_int(-1, s.find_next(0), "REHEX::Search::Text::find_next() doesn't find strings which aren't relatively aligned");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "efg");
		
		s.require_alignment(3, 10);
		
		is_int(4, s.find_next(0), "REHEX::Search::Text::find_next() finds strings which are relatively aligned to a later offset");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "efg");
		
		s.require_alignment(2, 3);
		
		is_int(-1, s.find_next(0), "REHEX::Search::Text::find_next() doesn't find strings which aren't relatively aligned to a later offset");
	}
	
	/* Case sensitivity */
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "ABC", true);
		
		is_int(-1, s.find_next(0), "REHEX::Search::Text::find_next() is case-sensitive when case sensitivity is enabled");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "ABC", false);
		
		is_int(0, s.find_next(0), "REHEX::Search::Text::find_next() is case-insensitive when case sensitivity is disabled");
	}
	
	/* Window sizing */
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "de");
		
		is_int(3, s.find_next(0, 4), "REHEX::Search::Text::find_next() finds strings which span multiple search windows");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "efg");
		
		is_int(4, s.find_next(0, 4), "REHEX::Search::Text::find_next() finds strings beyond the first search window");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		REHex::Search::Text s(&frame, *doc, "efgh");
		
		is_int(4, s.find_next(0, 4), "REHEX::Search::Text::find_next() finds strings which span an entire search window");
	}
	
	wxTheApp->OnExit();
	wxEntryCleanup();
	
	return 0;
}
