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

#include <assert.h>
#include <stdio.h>
#include <vector>
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
	for(int c = 0; c < 128; ++c) { fputc(c, tmp); }
	for(int c = 0; c < 256; ++c) { fputc(c, tmp); }
	fclose(tmp);
	
	/* Basic tests */
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x00, 0x01, 0x02 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		is_int(0, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequence at start of file");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x20, 0x21, 0x22, 0x23 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 4));
		
		is_int(0x20, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequence in middle of file");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x20, 0x21, 0x22, 0x23 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 4));
		
		is_int(128 + 0x20, s.find_next(0x21), "REHEX::Search::ByteSequence::find_next() finds repeated byte sequence in middle of file");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0xFE, 0xFF };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		is_int(128 + 0xFE, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequence at end of file");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		std::vector<unsigned char> search_data;
		
		for(int c = 0; c < 128; ++c) { search_data.push_back(c); }
		for(int c = 0; c < 256; ++c) { search_data.push_back(c); }
		
		REHex::Search::ByteSequence s(&frame, *doc, search_data);
		
		is_int(0, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequence which is whole file");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0xAA, 0xAB };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		is_int(128 + 0xAA, s.find_next(128 + 0xA9), "REHEX::Search::ByteSequence::find_next() finds byte sequence starting after from_offset");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0xAA, 0xAB };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		is_int(128 + 0xAA, s.find_next(128 + 0xAA), "REHEX::Search::ByteSequence::find_next() finds byte sequence starting at from_offset");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0xAA, 0xAB };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		is_int(-1, s.find_next(128 + 0xAB), "REHEX::Search::ByteSequence::find_next() doesn't find string starting before from_offset");
	}
	
	/* Range limiting */
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x14, 0x14 + 20);
		
		is_int(0x14, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequence at start of range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x10, 0x10 + 20);
		
		is_int(0x14, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequence in middle of range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x12, 0x12 + 5);
		
		is_int(0x14, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequence at end of range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x14, 0x14 + 3);
		
		is_int(0x14, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequence which is whole range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x15, 0x15 + 20);
		
		is_int(-1, s.find_next(0), "REHEX::Search::ByteSequence::find_next() doesn't find byte sequence starting before range");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x12, 0x12 + 4);
		
		is_int(-1, s.find_next(0), "REHEX::Search::ByteSequence::find_next() doesn't find byte sequence ending beyond range");
	}
	
	/* Alignment */
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x03, 0x04, 0x05 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(3);
		
		is_int(3, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequences which are aligned");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x03, 0x04, 0x05 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(2);
		
		is_int(-1, s.find_next(0), "REHEX::Search::ByteSequence::find_next() doesn't find byte sequences which aren't aligned");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(3, 1);
		
		is_int(4, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequences which are relatively aligned");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(2, 1);
		
		is_int(-1, s.find_next(0), "REHEX::Search::ByteSequence::find_next() doesn't find byte sequences which aren't relatively aligned");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(3, 10);
		
		is_int(4, s.find_next(0), "REHEX::Search::ByteSequence::find_next() finds byte sequences which are relatively aligned to a later offset");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(4, 10);
		
		is_int(-1, s.find_next(0), "REHEX::Search::ByteSequence::find_next() doesn't find byte sequences which aren't relatively aligned to a later offset");
	}
	
	/* Window sizing */
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x03, 0x04 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		is_int(3, s.find_next(0, 4), "REHEX::Search::ByteSequence::find_next() finds byte sequences which span multiple search windows");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		is_int(4, s.find_next(0, 4), "REHEX::Search::ByteSequence::find_next() finds byte sequences beyond the first search window");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06, 0x07 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 4));
		
		is_int(4, s.find_next(0, 4), "REHEX::Search::ByteSequence::find_next() finds byte sequences which span an entire search window");
	}
	
	{
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, TMPFILE);
		
		const unsigned char SEARCH_DATA[] = { 0x06, 0x07, 0x08, 0x09 };
		REHex::Search::ByteSequence s(&frame, *doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 4));
		
		is_int(6, s.find_next(0, 4), "REHEX::Search::ByteSequence::find_next() finds search-window-sized byte sequences which span two windows");
	}
	
	wxTheApp->OnExit();
	wxEntryCleanup();
	
	return 0;
}
