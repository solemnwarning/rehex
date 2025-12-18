/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/init.h>
#include <wx/wx.h>

#include "testutil.hpp"

#include "../src/document.hpp"
#include "../src/DocumentCtrl.hpp"
#include "../src/search.hpp"
#include "../src/SharedDocumentPointer.hpp"

TEST(Search, Text)
{
	TempFile file(
		"abcdefghijklmnop"
		
		/* The forbidden Unicode lands */
		
		/* offset = 16 */
		"n\xCC\x83" /* LATIN SMALL LETTER N (U+006E), COMBINING TILDE (U+0303) */
		"N\xCC\x83" /* LATIN CAPITAL LETTER N (U+004E), COMBINING TILDE (U+0303) */
		
		/* offset = 22 */
		"\xC3\xB1" /* LATIN SMALL LETTER N WITH TILDE (U+00F1) */
		"\xC3\x91" /* LATIN CAPITAL LETTER N WITH TILDE (U+00D1) */
		
		/* offset = 26 */
		"o\xCC\x80\xCC\x83" /* LATIN SMALL LETTER O (U+006E), COMBINING GRAVE ACCENT (U+0300), COMBINING TILDE (U+0303) */
		"o\xCC\x83\xCC\x80" /* LATIN SMALL LETTER O (U+006E), COMBINING TILDE (U+0303), COMBINING GRAVE ACCENT (U+0300) */
		
		/* offset = 36 */
		"\xd0\x90\xd0\x91\xd0\x92\xd0\x93\xd0\x94\xd0\x95\xd0\x96\xd0\x97" /* "АБВГДЕЖЗ" */
		"\xd0\xb0\xd0\xb1\xd0\xb2\xd0\xb3\xd0\xb4\xd0\xb5\xd0\xb6\xd0\xb7" /* "абвгдежз" */
		
		, 68);
	
	/* Basic tests */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "abc");
		
		EXPECT_EQ(s.find_next(0), 0) << "REHEX::Search::Text::find_next() finds string at start of file";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "def");
		
		EXPECT_EQ(s.find_next(0), 3) << "REHEX::Search::Text::find_next() finds string in middle of file";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "nop");
		
		EXPECT_EQ(s.find_next(0), 13) << "REHEX::Search::Text::find_next() finds string at end of file";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "abcdefghijklmnop");
		
		EXPECT_EQ(s.find_next(0), 0) << "REHEX::Search::Text::find_next() finds string which is whole file";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "def");
		
		EXPECT_EQ(s.find_next(2), 3) << "REHEX::Search::Text::find_next() finds string starting after from_offset";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "def");
		
		EXPECT_EQ(s.find_next(3), 3) << "REHEX::Search::Text::find_next() finds string starting at from_offset";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "def");
		
		EXPECT_EQ(s.find_next(4), -1) << "REHEX::Search::Text::find_next() doesn't find string starting before from_offset";
	}
	
	/* Range limiting */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "bcd");
		
		s.limit_range(1, 15);
		
		EXPECT_EQ(s.find_next(0), 1) << "REHEX::Search::Text::find_next() finds string at start of range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "def");
		
		s.limit_range(1, 15);
		
		EXPECT_EQ(s.find_next(0), 3) << "REHEX::Search::Text::find_next() finds string in middle of range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "mno");
		
		s.limit_range(1, 15);
		
		EXPECT_EQ(s.find_next(0), 12) << "REHEX::Search::Text::find_next() finds string at end of range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "bcdefghijklmno");
		
		s.limit_range(1, 15);
		
		EXPECT_EQ(s.find_next(0), 1) << "REHEX::Search::Text::find_next() finds string which is whole range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "abc");
		
		s.limit_range(1, 15);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::Text::find_next() doesn't find string starting before range";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "nop");
		
		s.limit_range(1, 15);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::Text::find_next() doesn't find string ending beyond range";
	}
	
	/* Alignment */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "def");
		
		s.require_alignment(3);
		
		EXPECT_EQ(s.find_next(0), 3) << "REHEX::Search::Text::find_next() finds strings which are aligned";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "def");
		
		s.require_alignment(2);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::Text::find_next() doesn't find strings which aren't aligned";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "efg");
		
		s.require_alignment(3, 1);
		
		EXPECT_EQ(s.find_next(0), 4) << "REHEX::Search::Text::find_next() finds strings which are relatively aligned";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "efg");
		
		s.require_alignment(2, 1);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::Text::find_next() doesn't find strings which aren't relatively aligned";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "efg");
		
		s.require_alignment(3, 10);
		
		EXPECT_EQ(s.find_next(0), 4) << "REHEX::Search::Text::find_next() finds strings which are relatively aligned to a later offset";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "efg");
		
		s.require_alignment(2, 3);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::Text::find_next() doesn't find strings which aren't relatively aligned to a later offset";
	}
	
	/* Case sensitivity */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "ABC", true);
		
		EXPECT_EQ(s.find_next(0), -1) << "REHEX::Search::Text::find_next() is case-sensitive when case sensitivity is enabled";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "ABC", false);
		
		EXPECT_EQ(s.find_next(0), 0) << "REHEX::Search::Text::find_next() is case-insensitive when case sensitivity is disabled";
	}
	
	/* Window sizing */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "de");
		
		EXPECT_EQ(s.find_next(0, 4), 3) << "REHEX::Search::Text::find_next() finds strings which span multiple search windows";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "efg");
		
		EXPECT_EQ(s.find_next(0, 4), 4) << "REHEX::Search::Text::find_next() finds strings beyond the first search window";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, "efgh");
		
		EXPECT_EQ(s.find_next(0, 4), 4) << "REHEX::Search::Text::find_next() finds strings which span an entire search window";
	}
	
	/* UNICODE */
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, wxString::FromUTF8("\xC3\xB1" /* LATIN SMALL LETTER N WITH TILDE (U+00F1) */), true, "UTF-8");
		
		EXPECT_EQ(s.find_next(0), 16) << "REHEX::Search::Text::find_next() matches combining characters";
		EXPECT_EQ(s.find_next(17), 22) << "REHEX::Search::Text::find_next() matches combining characters";
		EXPECT_EQ(s.find_next(23), -1) << "REHEX::Search::Text::find_next() matches combining characters";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, wxString::FromUTF8("n\xCC\x83" /* LATIN SMALL LETTER N (U+006E), COMBINING TILDE (U+0303) */), true, "UTF-8");
		
		EXPECT_EQ(s.find_next(0), 16) << "REHEX::Search::Text::find_next() matches combining characters";
		EXPECT_EQ(s.find_next(17), 22) << "REHEX::Search::Text::find_next() matches combining characters";
		EXPECT_EQ(s.find_next(23), -1) << "REHEX::Search::Text::find_next() matches combining characters";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, wxString::FromUTF8("\xC3\xB1" /* LATIN SMALL LETTER N WITH TILDE (U+00F1) */), false, "UTF-8");
		
		EXPECT_EQ(s.find_next(0), 16) << "REHEX::Search::Text::find_next() matches combining characters (case insensitive)";
		EXPECT_EQ(s.find_next(17), 19) << "REHEX::Search::Text::find_next() matches combining characters (case insensitive)";
		EXPECT_EQ(s.find_next(20), 22) << "REHEX::Search::Text::find_next() matches combining characters (case insensitive)";
		EXPECT_EQ(s.find_next(23), 24) << "REHEX::Search::Text::find_next() matches combining characters (case insensitive)";
		EXPECT_EQ(s.find_next(25), -1) << "REHEX::Search::Text::find_next() matches combining characters (case insensitive)";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, wxString::FromUTF8("o\xCC\x80\xCC\x83" /* LATIN SMALL LETTER O (U+006E), COMBINING GRAVE ACCENT (U+0300), COMBINING TILDE (U+0303) */), true, "UTF-8");
		
		EXPECT_EQ(s.find_next(0), 26) << "REHEX::Search::Text::find_next() matches multiple combining characters";
		EXPECT_EQ(s.find_next(27), -1) << "REHEX::Search::Text::find_next() doesn't match out-of-order combining characters";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, wxString::FromUTF8("o\xCC\x83\xCC\x80" /* LATIN SMALL LETTER O (U+006E), COMBINING TILDE (U+0303), COMBINING GRAVE ACCENT (U+0300) */), true, "UTF-8");
		
		EXPECT_EQ(s.find_next(0), 31) << "REHEX::Search::Text::find_next() matches multiple combining characters";
		EXPECT_EQ(s.find_next(32), -1) << "REHEX::Search::Text::find_next() doesn't match out-of-order combining characters";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, wxString::FromUTF8("\xd0\x90\xd0\x91\xd0\x92\xd0\x93\xd0\x94\xd0\x95\xd0\x96\xd0\x97" /* "АБВГДЕЖЗ" */), true, "UTF-8");
		
		EXPECT_EQ(s.find_next(0), 36) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
		EXPECT_EQ(s.find_next(37), -1) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, wxString::FromUTF8("\xd0\xb0\xd0\xb1\xd0\xb2\xd0\xb3\xd0\xb4\xd0\xb5\xd0\xb6\xd0\xb7" /* "абвгдежз" */), true, "UTF-8");
		
		EXPECT_EQ(s.find_next(0), 52) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
		EXPECT_EQ(s.find_next(53), -1) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, wxString::FromUTF8("\xd0\x90\xd0\x91\xd0\x92\xd0\x93\xd0\x94\xd0\x95\xd0\x96\xd0\x97" /* "АБВГДЕЖЗ" */), false, "UTF-8");
		
		EXPECT_EQ(s.find_next(0), 36) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
		EXPECT_EQ(s.find_next(37), 52) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
		EXPECT_EQ(s.find_next(53), -1) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
	}
	
	{
		AutoFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make(file.tmpfile));
		REHex::DocumentCtrl *doc_ctrl = new REHex::DocumentCtrl(frame, doc);
		
		REHex::Search::Text s(frame, doc, doc_ctrl, wxString::FromUTF8("\xd0\xb0\xd0\xb1\xd0\xb2\xd0\xb3\xd0\xb4\xd0\xb5\xd0\xb6\xd0\xb7" /* "абвгдежз" */), false, "UTF-8");
		
		EXPECT_EQ(s.find_next(0), 36) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
		EXPECT_EQ(s.find_next(37), 52) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
		EXPECT_EQ(s.find_next(53), -1) << "REHEX::Search::Text::find_next() handles case-sensitivity on cyrillic characters correctly";
	}
}
