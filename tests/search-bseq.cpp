/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/platform.hpp"

#include <gtest/gtest.h>
#include <stdio.h>
#include <vector>
#include <wx/init.h>
#include <wx/wx.h>

#include "testutil.hpp"

#include "../src/document.hpp"
#include "../src/search.hpp"
#include "../src/SharedDocumentPointer.hpp"

TEST(Search, ByteSequence)
{
	std::vector<unsigned char> file_data;
	for(int c = 0; c < 128; ++c) { file_data.push_back(c); }
	for(int c = 0; c < 256; ++c) { file_data.push_back(c); }
	
	TempFile file(file_data.data(), file_data.size());
	
	/* Basic tests */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x00, 0x01, 0x02 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		EXPECT_EQ(s.find_next(0), 0) << "REHEX::Search::ByteSequence::find_next() finds byte sequence at start of file";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x20, 0x21, 0x22, 0x23 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 4));
		
		EXPECT_EQ(s.find_next(0), 0x20) << "REHEX::Search::ByteSequence::find_next() finds byte sequence in middle of file";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x20, 0x21, 0x22, 0x23 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 4));
		
		EXPECT_EQ(s.find_next(0x21), (128 + 0x20)) << "REHEX::Search::ByteSequence::find_next() finds repeated byte sequence in middle of file";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0xFE, 0xFF };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		EXPECT_EQ(s.find_next(0), (128 + 0xFE)) << "REHEX::Search::ByteSequence::find_next() finds byte sequence at end of file";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		std::vector<unsigned char> search_data;
		
		for(int c = 0; c < 128; ++c) { search_data.push_back(c); }
		for(int c = 0; c < 256; ++c) { search_data.push_back(c); }
		
		REHex::Search::ByteSequence s(frame, doc, search_data);
		
		EXPECT_EQ(s.find_next(0), 0) << "REHEX::Search::ByteSequence::find_next() finds byte sequence which is whole file";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0xAA, 0xAB };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		EXPECT_EQ(s.find_next(128 + 0xA9), (128 + 0xAA)) << "REHEX::Search::ByteSequence::find_next() finds byte sequence starting after from_offset";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0xAA, 0xAB };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		EXPECT_EQ(s.find_next(128 + 0xAA), 128 + 0xAA) << "REHEX::Search::ByteSequence::find_next() finds byte sequence starting at from_offset";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0xAA, 0xAB };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		EXPECT_EQ(s.find_next(128 + 0xAB), -1) << "REHEX::Search::ByteSequence::find_next() doesn't find string starting before from_offset";
	}
	
	/* Range limiting */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x14, 0x14 + 20);
		
		EXPECT_EQ(s.find_next(0), 0x14) << "REHEX::Search::ByteSequence::find_next() finds byte sequence at start of range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x10, 0x10 + 20);
		
		EXPECT_EQ(s.find_next(0), 0x14) << "REHEX::Search::ByteSequence::find_next() finds byte sequence in middle of range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x12, 0x12 + 5);
		
		EXPECT_EQ(s.find_next(0), 0x14) << "REHEX::Search::ByteSequence::find_next() finds byte sequence at end of range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x14, 0x14 + 3);
		
		EXPECT_EQ(s.find_next(0), 0x14) << "REHEX::Search::ByteSequence::find_next() finds byte sequence which is whole range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x15, 0x15 + 20);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::ByteSequence::find_next() doesn't find byte sequence starting before range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x14, 0x15, 0x16 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.limit_range(0x12, 0x12 + 4);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::ByteSequence::find_next() doesn't find byte sequence ending beyond range";
	}
	
	/* Alignment */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x03, 0x04, 0x05 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(3);
		
		EXPECT_EQ(s.find_next(0), 3) << "REHEX::Search::ByteSequence::find_next() finds byte sequences which are aligned";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x03, 0x04, 0x05 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(2);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::ByteSequence::find_next() doesn't find byte sequences which aren't aligned";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(3, 1);
		
		EXPECT_EQ(s.find_next(0), 4) << "REHEX::Search::ByteSequence::find_next() finds byte sequences which are relatively aligned";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(2, 1);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::ByteSequence::find_next() doesn't find byte sequences which aren't relatively aligned";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(3, 10);
		
		EXPECT_EQ(s.find_next(0), 4) << "REHEX::Search::ByteSequence::find_next() finds byte sequences which are relatively aligned to a later offset";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		s.require_alignment(4, 10);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::ByteSequence::find_next() doesn't find byte sequences which aren't relatively aligned to a later offset";
	}
	
	/* Window sizing */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x03, 0x04 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 2));
		
		EXPECT_EQ(s.find_next(0, 4), 3) << "REHEX::Search::ByteSequence::find_next() finds byte sequences which span multiple search windows";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 3));
		
		EXPECT_EQ(s.find_next(0, 4), 4) << "REHEX::Search::ByteSequence::find_next() finds byte sequences beyond the first search window";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x04, 0x05, 0x06, 0x07 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 4));
		
		EXPECT_EQ(s.find_next(0, 4), 4) << "REHEX::Search::ByteSequence::find_next() finds byte sequences which span an entire search window";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		
		const unsigned char SEARCH_DATA[] = { 0x06, 0x07, 0x08, 0x09 };
		REHex::Search::ByteSequence s(frame, doc, std::vector<unsigned char>(SEARCH_DATA, SEARCH_DATA + 4));
		
		EXPECT_EQ(s.find_next(0, 4), 6) << "REHEX::Search::ByteSequence::find_next() finds search-window-sized byte sequences which span two windows";
	}
}
