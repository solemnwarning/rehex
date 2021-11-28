/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <stdint.h>
#include <string>
#include <string.h>
#include <vector>
#include <wx/frame.h>

#include "../src/document.hpp"
#include "../src/Events.hpp"

static const char *IPSUM =
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor"
	" incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud"
	" exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure"
	" dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.";

using namespace REHex;

/* Used by Google Test to print out Range values. */
std::ostream& operator<<(std::ostream& os, const ByteRangeMap<off_t>::Range &range)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "{ offset = %jd, length = %jd }", (intmax_t)(range.offset), (intmax_t)(range.length));
	
	return os << buf;
}

class DocumentTest: public ::testing::Test
{
	protected:
		Document *doc;
		std::vector<std::string> events;
		
		DocumentTest()
		{
			doc = new Document();
			
			doc->Bind(DATA_ERASE, [this](OffsetLengthEvent &event)
			{
				char event_s[64];
				snprintf(event_s, sizeof(event_s), "DATA_ERASE(%d, %d)", (int)(event.offset), (int)(event.length));
				events.push_back(event_s);
			});
			
			doc->Bind(DATA_INSERT, [this](OffsetLengthEvent &event)
			{
				char event_s[64];
				snprintf(event_s, sizeof(event_s), "DATA_INSERT(%d, %d)", (int)(event.offset), (int)(event.length));
				events.push_back(event_s);
			});
			
			doc->Bind(DATA_OVERWRITE, [this](OffsetLengthEvent &event)
			{
				char event_s[64];
				snprintf(event_s, sizeof(event_s), "DATA_OVERWRITE(%d, %d)", (int)(event.offset), (int)(event.length));
				events.push_back(event_s);
			});
			
			doc->Bind(CURSOR_UPDATE, [this](CursorUpdateEvent &event)
			{
				char event_s[64];
				snprintf(event_s, sizeof(event_s), "CURSOR_UPDATE(%d, %d)", (int)(event.cursor_pos), (int)(event.cursor_state));
				events.push_back(event_s);
			});
			
			doc->Bind(EV_COMMENT_MODIFIED, [this](wxCommandEvent &event)
			{
				events.push_back("EV_COMMENT_MODIFIED");
			});
			
			doc->Bind(EV_HIGHLIGHTS_CHANGED, [this](wxCommandEvent &event)
			{
				events.push_back("EV_HIGHLIGHTS_CHANGED");
			});
			
			doc->Bind(EV_MAPPINGS_CHANGED, [this](wxCommandEvent &event)
			{
				events.push_back("EV_MAPPINGS_CHANGED");
			});
		}
		
		~DocumentTest()
		{
			delete doc;
		}
};

#define EXPECT_EVENTS(...) \
{ \
	const std::vector<std::string>expected_events = { __VA_ARGS__ }; \
	EXPECT_EQ(expected_events, events); \
}

#define ASSERT_DATA(s) \
{ \
	std::vector<unsigned char> doc_data_ = doc->read_data(0, 9999); \
	std::string doc_data((const char*)(doc_data_.data()), doc_data_.size()); \
	std::string expect_data(s); \
	ASSERT_EQ(doc_data, expect_data); \
}

#define EXPECT_DATA(s) \
{ \
	std::vector<unsigned char> doc_data_ = doc->read_data(0, 9999); \
	std::string doc_data((const char*)(doc_data_.data()), doc_data_.size()); \
	std::string expect_data(s); \
	EXPECT_EQ(doc_data, expect_data); \
}

#define EXPECT_DATA_TYPES(...) \
{ \
	const std::vector< std::pair<ByteRangeMap<std::string>::Range, std::string> > expect_types = {  __VA_ARGS__ }; \
	EXPECT_EQ(doc->get_data_types().get_ranges(), expect_types); \
}

#define DATA_TYPE(offset, length, type) \
	std::make_pair(ByteRangeMap<std::string>::Range(offset, length), type)

TEST_F(DocumentTest, InsertData)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "straight";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1), 4, Document::CSTATE_ASCII, "dapper");
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 8)",
		"CURSOR_UPDATE(4, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 4)                   << "Document::insert_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::insert_data() sets cursor to requested state";
	
	ASSERT_DATA("straight");
	
	/* Insert at beginning of document... */
	
	events.clear();
	
	const char *DATA2 = "impress";
	doc->insert_data(0, (const unsigned char*)(DATA2), strlen(DATA2), 0, Document::CSTATE_HEX, "uppity");
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 7)",
		"CURSOR_UPDATE(0, 0)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 0)                 << "Document::insert_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX) << "Document::insert_data() sets cursor to requested state";
	
	ASSERT_DATA("impressstraight");
	
	/* Insert at end of document... */
	
	events.clear();
	
	const char *DATA3 = "bubble";
	doc->insert_data(15, (const unsigned char*)(DATA3), strlen(DATA3), 10, Document::CSTATE_HEX_MID, "seed");
	
	EXPECT_EVENTS(
		"DATA_INSERT(15, 6)",
		"CURSOR_UPDATE(10, 1)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 10)                    << "Document::insert_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX_MID) << "Document::insert_data() sets cursor to requested state";
	
	ASSERT_DATA("impressstraightbubble");
	
	/* Insert at middle of document... */
	
	events.clear();
	
	const char *DATA4 = "yellow";
	doc->insert_data(7, (const unsigned char*)(DATA4), strlen(DATA4), -1, Document::CSTATE_CURRENT, "imaginary");
	
	EXPECT_EVENTS(
		"DATA_INSERT(7, 6)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 10)                    << "Document::insert_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX_MID) << "Document::insert_data() sets cursor to requested state";
	
	ASSERT_DATA("impressyellowstraightbubble");
}

TEST_F(DocumentTest, InsertDataUndo)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "straight";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1), 4, Document::CSTATE_ASCII, "dapper");
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 8)",
		"CURSOR_UPDATE(4, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 4)                   << "Document::insert_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::insert_data() sets cursor to requested state";
	
	ASSERT_DATA("straight");
	
	/* Undo the insert... */
	
	events.clear();
	
	doc->undo();
	
	EXPECT_EVENTS(
		"DATA_ERASE(0, 8)",
		"CURSOR_UPDATE(0, 0)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 0)                 << "Document::undo() restores cursor to position before Document::insert_data() call";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX) << "Document::undo() restores cursor state to before Document::insert_data() call";
	
	ASSERT_DATA("");
	
	/* Redo the insert... */
	
	events.clear();
	
	doc->redo();
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 8)",
		"CURSOR_UPDATE(4, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 4)                   << "Document::redo() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::redo() sets cursor to requested state";
	
	ASSERT_DATA("straight");
}

TEST_F(DocumentTest, OverwriteData)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "creditlibrarydaughter";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	ASSERT_DATA("creditlibrarydaughter");
	
	/* Overwrite at beginning of document... */
	
	events.clear();
	
	const char *DATA2 = "CREDIT";
	doc->overwrite_data(0, (const unsigned char*)(DATA2), strlen(DATA2), 6, Document::CSTATE_ASCII, "aloof");
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(0, 6)",
		"CURSOR_UPDATE(6, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 6)                   << "Document::overwrite_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::overwrite_data() sets cursor to requested state";
	
	ASSERT_DATA("CREDITlibrarydaughter");
	
	/* Overwrite at end of document... */
	
	events.clear();
	
	const char *DATA3 = "DAUGHTER";
	doc->overwrite_data(13, (const unsigned char*)(DATA3), strlen(DATA3), -1, Document::CSTATE_CURRENT, "shallow");
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(13, 8)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 6)                   << "Document::overwrite_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::overwrite_data() sets cursor to requested state";
	
	ASSERT_DATA("CREDITlibraryDAUGHTER");
	
	/* Overwrite middle of document... */
	
	events.clear();
	
	const char *DATA4 = "LIBRARY";
	doc->overwrite_data(6, (const unsigned char*)(DATA4), strlen(DATA4), 0, Document::CSTATE_HEX, "sail");
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(6, 7)",
		"CURSOR_UPDATE(0, 0)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 0)                 << "Document::overwrite_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX) << "Document::overwrite_data() sets cursor to requested state";
	
	ASSERT_DATA("CREDITLIBRARYDAUGHTER");
}

TEST_F(DocumentTest, OverwriteDataUndo)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "creditlibrarydaughter";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	ASSERT_DATA("creditlibrarydaughter");
	
	/* Overwrite at beginning of document... */
	
	events.clear();
	
	const char *DATA2 = "CREDIT";
	doc->overwrite_data(0, (const unsigned char*)(DATA2), strlen(DATA2), 6, Document::CSTATE_ASCII, "aloof");
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(0, 6)",
		"CURSOR_UPDATE(6, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 6)                   << "Document::overwrite_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::overwrite_data() sets cursor to requested state";
	
	ASSERT_DATA("CREDITlibrarydaughter");
	
	/* Undo the overwrite... */
	
	events.clear();
	
	doc->undo();
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(0, 6)",
		"CURSOR_UPDATE(0, 0)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 0)                 << "Document::undo() restores cursor to position before Document::overwrite_data() call";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX) << "Document::undo() restores cursor state to before Document::overwrite_data() call";
	
	ASSERT_DATA("creditlibrarydaughter");
	
	/* Redo the overwrite... */
	
	events.clear();
	
	doc->redo();
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(0, 6)",
		"CURSOR_UPDATE(6, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 6)                   << "Document::redo() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::redo() sets cursor to requested state";
	
	ASSERT_DATA("CREDITlibrarydaughter");
}

TEST_F(DocumentTest, EraseData)
{
	/* Preload document with data. */
	const char *DATA1 = "signROOMYgateMUGgraceful";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	ASSERT_DATA("signROOMYgateMUGgraceful");
	
	/* Erase from middle of document... */
	
	events.clear();
	
	doc->erase_data(4, 5, 4, Document::CSTATE_HEX, "next");
	
	EXPECT_EVENTS(
		"DATA_ERASE(4, 5)",
		"CURSOR_UPDATE(4, 0)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 4)                 << "Document::erase_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX) << "Document::erase_data() sets cursor to requested state";
	
	ASSERT_DATA("signgateMUGgraceful");
	
	/* Erase from beginning of document... */
	
	events.clear();
	
	doc->erase_data(0, 4, 0, Document::CSTATE_ASCII, "bridge");
	
	EXPECT_EVENTS(
		"DATA_ERASE(0, 4)",
		"CURSOR_UPDATE(0, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 0)                   << "Document::erase_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::erase_data() sets cursor to requested state";
	
	ASSERT_DATA("gateMUGgraceful");
	
	/* Erase from end of document... */
	
	events.clear();
	
	doc->erase_data(7, 8, 6, Document::CSTATE_GOTO, "question");
	
	EXPECT_EVENTS(
		"DATA_ERASE(7, 8)",
		"CURSOR_UPDATE(6, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 6)                   << "Document::erase_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::erase_data() sets cursor to requested state";
	
	ASSERT_DATA("gateMUG");
}

TEST_F(DocumentTest, EraseDataUndo)
{
	/* Preload document with data. */
	const char *DATA1 = "signROOMYgateMUGgraceful";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	ASSERT_DATA("signROOMYgateMUGgraceful");
	
	/* Erase from middle of document... */
	
	events.clear();
	
	doc->erase_data(4, 5, 4, Document::CSTATE_HEX, "next");
	
	EXPECT_EVENTS(
		"DATA_ERASE(4, 5)",
		"CURSOR_UPDATE(4, 0)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 4)                 << "Document::erase_data() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX) << "Document::erase_data() sets cursor to requested state";
	
	ASSERT_DATA("signgateMUGgraceful");
	
	/* Undo the erase... */
	
	events.clear();
	
	doc->undo();
	
	EXPECT_EVENTS(
		"DATA_INSERT(4, 5)",
		"CURSOR_UPDATE(0, 0)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 0)                 << "Document::undo() restores cursor to position before Document::overwrite_data() call";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX) << "Document::undo() restores cursor state to before Document::overwrite_data() call";
	
	ASSERT_DATA("signROOMYgateMUGgraceful");
	
	/* Redo the erase... */
	
	events.clear();
	
	doc->redo();
	
	EXPECT_EVENTS(
		"DATA_ERASE(4, 5)",
		"CURSOR_UPDATE(4, 0)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 4)                 << "Document::redo() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_HEX) << "Document::redo() sets cursor to requested state";
	
	ASSERT_DATA("signgateMUGgraceful");
}

TEST_F(DocumentTest, SetHighlight)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	events.clear();
	
	ASSERT_TRUE(doc->set_highlight(10, 20, 0)) << "Document::set_highlight() allows range within file";
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED"
	);
	
	NestedOffsetLengthMap<int> expect_highlights;
	expect_highlights[ NestedOffsetLengthMapKey(10, 20) ] = 0;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
}

TEST_F(DocumentTest, SetHighlightWholeFile)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	events.clear();
	
	ASSERT_TRUE(doc->set_highlight(0, strlen(IPSUM), 1)) << "Document::set_highlight() allows highlight spanning entire file";
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights;
	expect_highlights[ NestedOffsetLengthMapKey(0, strlen(IPSUM)) ] = 1;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
}

TEST_F(DocumentTest, SetHighlightMultiple)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	events.clear();
	
	ASSERT_TRUE(doc->set_highlight(0,  10, 2));
	ASSERT_TRUE(doc->set_highlight(20, 10, 3));
	ASSERT_TRUE(doc->set_highlight(30, 10, 4));
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
		"EV_HIGHLIGHTS_CHANGED",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights;
	expect_highlights[ NestedOffsetLengthMapKey(0,  10) ] = 2;
	expect_highlights[ NestedOffsetLengthMapKey(20, 10) ] = 3;
	expect_highlights[ NestedOffsetLengthMapKey(30, 10) ] = 4;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
}

TEST_F(DocumentTest, SetHighlightNested)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	events.clear();
	
	ASSERT_TRUE(doc->set_highlight(0,  20, 1));
	ASSERT_TRUE(doc->set_highlight(0,  10, 2));
	ASSERT_TRUE(doc->set_highlight(40, 10, 3));
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
		"EV_HIGHLIGHTS_CHANGED",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights;
	expect_highlights[ NestedOffsetLengthMapKey(0,  10) ] = 2;
	expect_highlights[ NestedOffsetLengthMapKey(0,  20) ] = 1;
	expect_highlights[ NestedOffsetLengthMapKey(40, 10) ] = 3;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
}

TEST_F(DocumentTest, SetHighlightOverwrite)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	events.clear();
	
	ASSERT_TRUE(doc->set_highlight(0, 20, 1));
	ASSERT_TRUE(doc->set_highlight(0, 20, 2));
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights;
	expect_highlights[ NestedOffsetLengthMapKey(0, 20) ] = 2;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
}

TEST_F(DocumentTest, SetHighlightConflict)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	events.clear();
	
	ASSERT_TRUE (doc->set_highlight(10, 20, 1));
	ASSERT_FALSE(doc->set_highlight( 0, 20, 2));
	ASSERT_FALSE(doc->set_highlight(20, 20, 3));
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights;
	expect_highlights[ NestedOffsetLengthMapKey(10, 20) ] = 1;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
}

TEST_F(DocumentTest, SetHighlightAtEndOfFile)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	events.clear();
	
	ASSERT_FALSE(doc->set_highlight(strlen(IPSUM), 0, 0)) << "Document::set_highlight() rejects offset at end of file";
	EXPECT_EVENTS();
}

TEST_F(DocumentTest, SetHighlightRunOverEndOfFile)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	events.clear();
	
	ASSERT_FALSE(doc->set_highlight((strlen(IPSUM) - 1), 2, 0)) << "Document::set_highlight() rejects range that runs over end of file";
	EXPECT_EVENTS();
}

TEST_F(DocumentTest, SetHighlightUndo)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	events.clear();
	
	ASSERT_TRUE(doc->set_highlight(10, 20, 0)) << "Document::set_highlight() allows range within file";
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED"
	);
	
	NestedOffsetLengthMap<int> expect_highlights;
	expect_highlights[ NestedOffsetLengthMapKey(10, 20) ] = 0;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
	
	/* Undo the highlight... */
	
	events.clear();
	doc->undo();
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> no_highlights;
	EXPECT_EQ(doc->get_highlights(), no_highlights);
	
	/* Redo the highlight... */
	
	events.clear();
	doc->redo();
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
}

TEST_F(DocumentTest, InsertBeforeHighlight)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	ASSERT_TRUE(doc->set_highlight(20, 10, 1));
	ASSERT_TRUE(doc->set_highlight(40, 10, 2));
	
	events.clear();
	
	doc->insert_data(20, (const unsigned char*)(IPSUM), 5);
	
	EXPECT_EVENTS(
		"DATA_INSERT(20, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights_pre;
	expect_highlights_pre[ NestedOffsetLengthMapKey(20, 10) ] = 1;
	expect_highlights_pre[ NestedOffsetLengthMapKey(40, 10) ] = 2;
	
	NestedOffsetLengthMap<int> expect_highlights_post;
	expect_highlights_post[ NestedOffsetLengthMapKey(25, 10) ] = 1;
	expect_highlights_post[ NestedOffsetLengthMapKey(45, 10) ] = 2;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
	
	/* Undo the insert... */
	
	events.clear();
	doc->undo();
	
	EXPECT_EVENTS(
		"DATA_ERASE(20, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_pre);
	
	/* Redo the highlight... */
	
	events.clear();
	doc->redo();
	
	EXPECT_EVENTS(
		"DATA_INSERT(20, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
}

TEST_F(DocumentTest, InsertWithinHighlight)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	ASSERT_TRUE(doc->set_highlight(20, 10, 1));
	
	events.clear();
	
	doc->insert_data(25, (const unsigned char*)(IPSUM), 5);
	
	EXPECT_EVENTS(
		"DATA_INSERT(25, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights_pre;
	expect_highlights_pre[ NestedOffsetLengthMapKey(20, 10) ] = 1;
	
	NestedOffsetLengthMap<int> expect_highlights_post;
	expect_highlights_post[ NestedOffsetLengthMapKey(20, 15) ] = 1;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
	
	/* Undo the insert... */
	
	events.clear();
	doc->undo();
	
	EXPECT_EVENTS(
		"DATA_ERASE(25, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_pre);
	
	/* Redo the insert... */
	
	events.clear();
	doc->redo();
	
	EXPECT_EVENTS(
		"DATA_INSERT(25, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
}

TEST_F(DocumentTest, InsertAfterHighlight)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	ASSERT_TRUE(doc->set_highlight(20, 10, 1));
	ASSERT_TRUE(doc->set_highlight(40, 10, 2));
	
	events.clear();
	
	doc->insert_data(50, (const unsigned char*)(IPSUM), 5);
	
	EXPECT_EVENTS(
		"DATA_INSERT(50, 5)",
	);
	
	NestedOffsetLengthMap<int> expect_highlights;
	expect_highlights[ NestedOffsetLengthMapKey(20, 10) ] = 1;
	expect_highlights[ NestedOffsetLengthMapKey(40, 10) ] = 2;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
	
	/* Undo the insert... */
	
	events.clear();
	doc->undo();
	
	EXPECT_EVENTS(
		"DATA_ERASE(50, 5)",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
	
	/* Redo the insert... */
	
	events.clear();
	doc->redo();
	
	EXPECT_EVENTS(
		"DATA_INSERT(50, 5)",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
}

TEST_F(DocumentTest, EraseBeforeHighlight)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	ASSERT_TRUE(doc->set_highlight(20, 10, 1));
	ASSERT_TRUE(doc->set_highlight(40, 10, 2));
	
	events.clear();
	
	doc->erase_data(15, 5);
	
	EXPECT_EVENTS(
		"DATA_ERASE(15, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights_pre;
	expect_highlights_pre[ NestedOffsetLengthMapKey(20, 10) ] = 1;
	expect_highlights_pre[ NestedOffsetLengthMapKey(40, 10) ] = 2;
	
	NestedOffsetLengthMap<int> expect_highlights_post;
	expect_highlights_post[ NestedOffsetLengthMapKey(15, 10) ] = 1;
	expect_highlights_post[ NestedOffsetLengthMapKey(35, 10) ] = 2;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
	
	/* Undo the erase... */
	
	events.clear();
	doc->undo();
	
	EXPECT_EVENTS(
		"DATA_INSERT(15, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_pre);
	
	/* Redo the erase... */
	
	events.clear();
	doc->redo();
	
	EXPECT_EVENTS(
		"DATA_ERASE(15, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
}

TEST_F(DocumentTest, EraseWithinHighlight)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	ASSERT_TRUE(doc->set_highlight(20, 10, 1));
	
	events.clear();
	
	doc->erase_data(20, 5);
	
	EXPECT_EVENTS(
		"DATA_ERASE(20, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights_pre;
	expect_highlights_pre[ NestedOffsetLengthMapKey(20, 10) ] = 1;
	
	NestedOffsetLengthMap<int> expect_highlights_post;
	expect_highlights_post[ NestedOffsetLengthMapKey(20, 5) ] = 1;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
	
	/* Undo the erase... */
	
	events.clear();
	doc->undo();
	
	EXPECT_EVENTS(
		"DATA_INSERT(20, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_pre);
	
	/* Redo the erase... */
	
	events.clear();
	doc->redo();
	
	EXPECT_EVENTS(
		"DATA_ERASE(20, 5)",
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
}

TEST_F(DocumentTest, EraseAfterHighlight)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	ASSERT_TRUE(doc->set_highlight(20, 10, 1));
	ASSERT_TRUE(doc->set_highlight(40, 10, 2));
	
	events.clear();
	
	doc->erase_data(50, 5);
	
	EXPECT_EVENTS(
		"DATA_ERASE(50, 5)",
	);
	
	NestedOffsetLengthMap<int> expect_highlights;
	expect_highlights[ NestedOffsetLengthMapKey(20, 10) ] = 1;
	expect_highlights[ NestedOffsetLengthMapKey(40, 10) ] = 2;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
	
	/* Undo the erase... */
	
	events.clear();
	doc->undo();
	
	EXPECT_EVENTS(
		"DATA_INSERT(50, 5)",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
	
	/* Redo the erase... */
	
	events.clear();
	doc->redo();
	
	EXPECT_EVENTS(
		"DATA_ERASE(50, 5)",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights);
}

TEST_F(DocumentTest, EraseHighlight)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	ASSERT_TRUE(doc->set_highlight(10, 20, 0));
	
	NestedOffsetLengthMap<int> expect_highlights_pre;
	expect_highlights_pre[ NestedOffsetLengthMapKey(10, 20) ] = 0;
	
	ASSERT_EQ(doc->get_highlights(), expect_highlights_pre);
	
	events.clear();
	
	ASSERT_FALSE(doc->erase_highlight(10,  5)) << "Document::erase_highlight() returns false when length doesn't match existing key";
	ASSERT_FALSE(doc->erase_highlight(20, 20)) << "Document::erase_highlight() returns false when offset doesn't match existing key";
	
	EXPECT_EVENTS();
	
	events.clear();
	
	ASSERT_TRUE(doc->erase_highlight(10, 20));
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights_post;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
}

TEST_F(DocumentTest, EraseHighlightNested)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	ASSERT_TRUE(doc->set_highlight(10, 20, 0));
	ASSERT_TRUE(doc->set_highlight(10,  5, 1));
	
	NestedOffsetLengthMap<int> expect_highlights_pre;
	expect_highlights_pre[ NestedOffsetLengthMapKey(10, 20) ] = 0;
	expect_highlights_pre[ NestedOffsetLengthMapKey(10,  5) ] = 1;
	
	ASSERT_EQ(doc->get_highlights(), expect_highlights_pre);
	
	events.clear();
	
	ASSERT_TRUE(doc->erase_highlight(10, 20));
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	NestedOffsetLengthMap<int> expect_highlights_post;
	expect_highlights_post[ NestedOffsetLengthMapKey(10,  5) ] = 1;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
}

TEST_F(DocumentTest, EraseHighlightUndo)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	ASSERT_TRUE(doc->set_highlight(10, 20, 0));
	
	NestedOffsetLengthMap<int> expect_highlights_pre;
	expect_highlights_pre[ NestedOffsetLengthMapKey(10, 20) ] = 0;
	
	ASSERT_EQ(doc->get_highlights(), expect_highlights_pre);
	
	ASSERT_TRUE(doc->erase_highlight(10, 20));
	
	NestedOffsetLengthMap<int> expect_highlights_post;
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
	
	/* Undo the erase... */
	
	events.clear();
	doc->undo();
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_pre);
	
	/* Redo the erase... */
	
	events.clear();
	doc->redo();
	
	EXPECT_EVENTS(
		"EV_HIGHLIGHTS_CHANGED",
	);
	
	EXPECT_EQ(doc->get_highlights(), expect_highlights_post);
}

TEST_F(DocumentTest, SetVirtMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	events.clear();
	EXPECT_TRUE(doc->set_virt_mapping(10, 1000, 20));
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	events.clear();
	EXPECT_TRUE(doc->set_virt_mapping(30, 2000, 40));
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	events.clear();
	EXPECT_TRUE(doc->set_virt_mapping(70, 1020, 10));
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, SetVirtMappingUndo)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	/* Undo the last op... */
	
	events.clear();
	doc->undo();
	
	EXPECT_EVENTS(
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {};
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {};
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
	
	/* Redo the last op... */
	
	events.clear();
	doc->redo();
	
	EXPECT_EVENTS(
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, SetVirtMappingRealConflict)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	EXPECT_TRUE(doc->set_virt_mapping(10, 1000, 20));
	
	events.clear();
	EXPECT_FALSE(doc->set_virt_mapping(20, 2000, 40));
	EXPECT_EVENTS();
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, SetVirtMappingVirtConflict)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	EXPECT_TRUE(doc->set_virt_mapping(10, 1000, 20));
	
	events.clear();
	EXPECT_FALSE(doc->set_virt_mapping(30, 1010, 40));
	EXPECT_EVENTS();
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingRWholeMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_r(10, 20);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingRStartOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_r(30, 10);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(40, 30), 2010),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2010, 30), 40),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingREndOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_r(75, 5);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70,  5), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020,  5), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingRMiddleOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_r(15, 8);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10,  5), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(23,  7), 1013),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000,  5), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1013,  7), 23),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingRMultipleMappings)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_r(15, 60);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 5), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(75, 5), 1025),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 5), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1025, 5), 75),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingRNoMatches)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_r(80, 60);
	EXPECT_EVENTS();
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingRNoMappingsDefined)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {};
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {};
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_r(80, 60);
	EXPECT_EVENTS();
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {};
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {};
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingVWholeMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_v(1000, 20);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingVStartOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_v(2000, 10);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(40, 30), 2010),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2010, 30), 40),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingVEndOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_v(1025, 5);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70,  5), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020,  5), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingVMiddleOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_v(1005, 8);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10,  5), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(23,  7), 1013),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000,  5), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1013,  7), 23),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingVMultipleMappings)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_v(1005, 1010);
	EXPECT_EVENTS("EV_MAPPINGS_CHANGED");
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10,  5), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(45, 25), 2015),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000,  5), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(2015, 25), 45),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingVNoMatches)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_v(1030, 60);
	EXPECT_EVENTS();
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, ClearVirtMappingVNoMappingsDefined)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {};
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {};
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->clear_virt_mapping_v(80, 60);
	EXPECT_EVENTS();
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {};
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {};
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, RealToVirtOffset)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	EXPECT_EQ(doc->real_to_virt_offset( 9), -1);
	EXPECT_EQ(doc->real_to_virt_offset(10), 1000);
	EXPECT_EQ(doc->real_to_virt_offset(11), 1001);
	EXPECT_EQ(doc->real_to_virt_offset(29), 1019);
	EXPECT_EQ(doc->real_to_virt_offset(30), 2000);
	EXPECT_EQ(doc->real_to_virt_offset(40), 2010);
	EXPECT_EQ(doc->real_to_virt_offset(69), 2039);
	EXPECT_EQ(doc->real_to_virt_offset(70), 1020);
	EXPECT_EQ(doc->real_to_virt_offset(79), 1029);
	EXPECT_EQ(doc->real_to_virt_offset(80), -1);
}

TEST_F(DocumentTest, VirtToRealOffset)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(10, 1000, 20);
	doc->set_virt_mapping(30, 2000, 40);
	doc->set_virt_mapping(70, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(10, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(30, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(70, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 10),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 70),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 30),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	EXPECT_EQ(doc->virt_to_real_offset(   0), -1);
	EXPECT_EQ(doc->virt_to_real_offset( 999), -1);
	EXPECT_EQ(doc->virt_to_real_offset(1000), 10);
	EXPECT_EQ(doc->virt_to_real_offset(1010), 20);
	EXPECT_EQ(doc->virt_to_real_offset(1019), 29);
	EXPECT_EQ(doc->virt_to_real_offset(1020), 70);
	EXPECT_EQ(doc->virt_to_real_offset(1029), 79);
	EXPECT_EQ(doc->virt_to_real_offset(1030), -1);
	EXPECT_EQ(doc->virt_to_real_offset(1999), -1);
	EXPECT_EQ(doc->virt_to_real_offset(2000), 30);
	EXPECT_EQ(doc->virt_to_real_offset(2039), 69);
	EXPECT_EQ(doc->virt_to_real_offset(2040), -1);
}

TEST_F(DocumentTest, EraseDataBetweenMappings)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->erase_data(180, 20);
	EXPECT_EVENTS(
		"DATA_ERASE(180, 20)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(180, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(280, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 280),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 180),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, EraseDataOverlappingStartOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->erase_data(295, 10);
	EXPECT_EVENTS(
		"DATA_ERASE(295, 10)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(295,  5), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020,  5), 295),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, EraseDataAtStartOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->erase_data(100, 10);
	EXPECT_EVENTS(
		"DATA_ERASE(100, 10)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 10), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(190, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(290, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 10), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 290),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 190),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, EraseDataInMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->erase_data(210, 10);
	EXPECT_EVENTS(
		"DATA_ERASE(210, 10)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 30), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(290, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 290),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 30), 200),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, EraseDataAtEndOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->erase_data(110, 10);
	EXPECT_EVENTS(
		"DATA_ERASE(110, 10)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 10), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(190, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(290, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 10), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 290),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 190),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, EraseDataOverlappingEndOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->erase_data(235, 10);
	EXPECT_EVENTS(
		"DATA_ERASE(235, 10)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 35), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(290, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 290),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 35), 200),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, InsertDataBetweenMappings)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->insert_data(180, (const unsigned char*)(IPSUM), 20);
	EXPECT_EVENTS(
		"DATA_INSERT(180, 20)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(220, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(320, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 320),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 220),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, InsertDataBeforeMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->insert_data(300, (const unsigned char*)(IPSUM), 20);
	EXPECT_EVENTS(
		"DATA_INSERT(300, 20)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(320, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 320),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, InsertDataAtStartOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->insert_data(101, (const unsigned char*)(IPSUM), 20);
	EXPECT_EVENTS(
		"DATA_INSERT(101, 20)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100,  1), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(121, 19), 1001),
			std::make_pair(ByteRangeMap<off_t>::Range(220, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(320, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000,  1), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1001, 19), 121),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 320),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 220),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, InsertDataAtEndOfMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->insert_data(239, (const unsigned char*)(IPSUM), 20);
	EXPECT_EVENTS(
		"DATA_INSERT(239, 20)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 39), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(259,  1), 2039),
			std::make_pair(ByteRangeMap<off_t>::Range(320, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 320),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 39), 200),
			std::make_pair(ByteRangeMap<off_t>::Range(2039,  1), 259),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, InsertDataAfterMapping)
{
	/* Preload document with data. */
	doc->insert_data(0, (const unsigned char*)(IPSUM), strlen(IPSUM));
	
	doc->set_virt_mapping(100, 1000, 20);
	doc->set_virt_mapping(200, 2000, 40);
	doc->set_virt_mapping(300, 1020, 10);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(200, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(300, 10), 1020),
		};
		
		ASSERT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V) << "Sanity check";
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 300),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 200),
		};
		
		ASSERT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R)  << "Sanity check";
	}
	
	events.clear();
	doc->insert_data(120, (const unsigned char*)(IPSUM), 10);
	EXPECT_EVENTS(
		"DATA_INSERT(120, 10)",
		"EV_MAPPINGS_CHANGED",
	);
	
	{
		const std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_R2V = {
			std::make_pair(ByteRangeMap<off_t>::Range(100, 20), 1000),
			std::make_pair(ByteRangeMap<off_t>::Range(210, 40), 2000),
			std::make_pair(ByteRangeMap<off_t>::Range(310, 10), 1020),
		};
		
		EXPECT_EQ(doc->get_real_to_virt_segs().get_ranges(), EXPECT_R2V);
	}
	
	{
		std::vector< std::pair<ByteRangeMap<off_t>::Range, off_t> > EXPECT_V2R = {
			std::make_pair(ByteRangeMap<off_t>::Range(1000, 20), 100),
			std::make_pair(ByteRangeMap<off_t>::Range(1020, 10), 310),
			std::make_pair(ByteRangeMap<off_t>::Range(2000, 40), 210),
		};
		
		EXPECT_EQ(doc->get_virt_to_real_segs().get_ranges(), EXPECT_V2R);
	}
}

TEST_F(DocumentTest, UndoTransaction)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "smoothorangemixed";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1), -1, Document::CSTATE_CURRENT, "initialise");
	
	ASSERT_DATA("smoothorangemixed");
	
	/* Start a transaction. */
	doc->transact_begin("greet");
	
	events.clear();
	
	/* Insert at beginning of document. */
	const char *DATA2 = "MAGIC";
	doc->insert_data(0, (const unsigned char*)(DATA2), strlen(DATA2));
	
	/* Erase in middle of document. */
	doc->erase_data(5, 6);
	
	/* Overwrite at end of document... */
	const char *DATA3 = "RINGS";
	doc->overwrite_data(11, (const unsigned char*)(DATA3), strlen(DATA3));
	
	/* Commit transaction. */
	doc->transact_commit();
	
	{
		const char *undo_desc = doc->undo_desc();
		EXPECT_EQ(std::string(undo_desc ? undo_desc : "(null)"), "greet");
	}
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 5)",
		"DATA_ERASE(5, 6)",
		"DATA_OVERWRITE(11, 5)",
	);
	
	ASSERT_DATA("MAGICorangeRINGS");
	
	/* Undo the transaction... */
	
	events.clear();
	
	doc->undo();
	
	{
		const char *undo_desc = doc->undo_desc();
		EXPECT_EQ(std::string(undo_desc ? undo_desc : "(null)"), "initialise");
	}
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(11, 5)",
		"DATA_INSERT(5, 6)",
		"DATA_ERASE(0, 5)",
	);
	
	ASSERT_DATA("smoothorangemixed");
	
	/* Redo the overwrite... */
	
	events.clear();
	
	doc->redo();
	
	{
		const char *undo_desc = doc->undo_desc();
		EXPECT_EQ(std::string(undo_desc ? undo_desc : "(null)"), "greet");
	}
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 5)",
		"DATA_ERASE(5, 6)",
		"DATA_OVERWRITE(11, 5)",
	);
	
	ASSERT_DATA("MAGICorangeRINGS");
}

TEST_F(DocumentTest, RollbackTransaction)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "smoothorangemixed";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1), -1, Document::CSTATE_CURRENT, "initialise");
	
	ASSERT_DATA("smoothorangemixed");
	
	/* Start a transaction. */
	doc->transact_begin("greet");
	
	events.clear();
	
	/* Insert at beginning of document. */
	const char *DATA2 = "MAGIC";
	doc->insert_data(0, (const unsigned char*)(DATA2), strlen(DATA2));
	
	/* Erase in middle of document. */
	doc->erase_data(5, 6);
	
	/* Overwrite at end of document... */
	const char *DATA3 = "RINGS";
	doc->overwrite_data(11, (const unsigned char*)(DATA3), strlen(DATA3));
	
	{
		const char *undo_desc = doc->undo_desc();
		EXPECT_EQ(std::string(undo_desc ? undo_desc : "(null)"), "greet");
	}
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 5)",
		"DATA_ERASE(5, 6)",
		"DATA_OVERWRITE(11, 5)",
	);
	
	ASSERT_DATA("MAGICorangeRINGS");
	
	/* Rollback transaction. */
	
	events.clear();
	
	doc->transact_rollback();
	
	{
		const char *undo_desc = doc->undo_desc();
		EXPECT_EQ(std::string(undo_desc ? undo_desc : "(null)"), "initialise");
	}
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(11, 5)",
		"DATA_INSERT(5, 6)",
		"DATA_ERASE(0, 5)",
	);
	
	ASSERT_DATA("smoothorangemixed");
	
	/* Make sure you can't redo a rolled back transaction. */
	
	{
		const char *redo_desc = doc->redo_desc();
		EXPECT_EQ(std::string(redo_desc ? redo_desc : "(null)"), "(null)");
	}
}

#define EXPECT_RANGE_DIRTY(offset, length, desc) \
{ \
	for(off_t i = offset; i < (offset + length); ++i) \
	{ \
		EXPECT_TRUE(doc->is_byte_dirty(i)) << desc << " (i = " << i << ")"; \
	} \
}

#define EXPECT_RANGE_CLEAN(offset, length, desc) \
{ \
	for(off_t i = offset; i < (offset + length); ++i) \
	{ \
		EXPECT_FALSE(doc->is_byte_dirty(i)) << desc << " (i = " << i << ")"; \
	} \
}

TEST_F(DocumentTest, DirtyState)
{
	EXPECT_FALSE(doc->is_dirty()) << "New Document is initially clean";
	EXPECT_FALSE(doc->is_buffer_dirty());
	
	/* Insert into empty document... */
	const char *DATA1 = "smoothorangemixed";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1), -1, Document::CSTATE_CURRENT, "initialise");
	
	/* Insert at beginning of document. */
	const char *DATA2 = "MAGIC";
	doc->insert_data(0, (const unsigned char*)(DATA2), strlen(DATA2));
	
	/* Erase in middle of document. */
	doc->erase_data(5, 6);
	
	/* Overwrite at end of document... */
	const char *DATA3 = "RINGS";
	doc->overwrite_data(11, (const unsigned char*)(DATA3), strlen(DATA3));
	
	ASSERT_DATA("MAGICorangeRINGS");
	
	events.clear();
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty before saving";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty before saving";
	EXPECT_RANGE_DIRTY(0, 16, "Document is dirty before saving");
	
	/* Save the file. */
	char tmpfile[L_tmpnam];
	tmpnam(tmpfile);
	doc->save(tmpfile);
	
	EXPECT_EVENTS();
	
	EXPECT_FALSE(doc->is_dirty()) << "Document is clean after saving";
	EXPECT_FALSE(doc->is_buffer_dirty()) << "Document is clean after saving";
	EXPECT_RANGE_CLEAN(0, 16, "Document is clean after saving");
	
	/* Make some more changes. */
	
	/* Insert at end of document */
	const char *DATA4 = "fixedflapbone";
	doc->insert_data(16, (const unsigned char*)(DATA4), strlen(DATA4));
	
	/* Insert before last insertion. */
	const char *DATA5 = "CABLE";
	doc->insert_data(16, (const unsigned char*)(DATA5), strlen(DATA5));
	
	/* Erase "fixed". */
	doc->erase_data(21, 5);
	
	/* Overwrite at start of document... */
	const char *DATA6 = "STRIP";
	doc->overwrite_data(0, (const unsigned char*)(DATA6), strlen(DATA6));
	
	ASSERT_DATA("STRIPorangeRINGSCABLEflapbone");
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty after making changes";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty after making changes";
	EXPECT_RANGE_DIRTY( 0,  5, "Modified range dirty after making changes");
	EXPECT_RANGE_CLEAN( 5, 11, "Unmodified range clean after making changes");
	EXPECT_RANGE_DIRTY(16, 13, "Modified range dirty after making changes");
	
	/* Undo everything but the first post-save insert. */
	doc->undo();
	doc->undo();
	doc->undo();
	
	ASSERT_DATA("MAGICorangeRINGSfixedflapbone");
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty after undoing some changes";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty after undoing some changes";
	EXPECT_RANGE_CLEAN( 0, 16, "Unmodified range clean after undoing changes");
	EXPECT_RANGE_DIRTY(16, 13, "Modified range dirty after undoing changes");
	
	/* Undo remaining post-save change. */
	doc->undo();
	
	ASSERT_DATA("MAGICorangeRINGS");
	
	EXPECT_FALSE(doc->is_dirty()) << "Document is clean after undoing all changes";
	EXPECT_FALSE(doc->is_buffer_dirty()) << "Document is clean after undoing all changes";
	EXPECT_RANGE_CLEAN(0, 16, "Unmodified range clean after undoing changes");
	
	/* Redo it all... */
	doc->redo();
	doc->redo();
	doc->redo();
	doc->redo();
	
	ASSERT_DATA("STRIPorangeRINGSCABLEflapbone");
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty after redoing changes";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty after redoing changes";
	EXPECT_RANGE_DIRTY( 0,  5, "Modified range dirty after redoing changes");
	EXPECT_RANGE_CLEAN( 5, 11, "Unmodified range clean after redoing changes");
	EXPECT_RANGE_DIRTY(16, 13, "Modified range dirty after redoing changes");
	
	/* Re-undo it all... */
	doc->undo();
	doc->undo();
	doc->undo();
	doc->undo();
	
	ASSERT_DATA("MAGICorangeRINGS");
	
	EXPECT_FALSE(doc->is_dirty()) << "Document is clean after undoing all changes";
	EXPECT_FALSE(doc->is_buffer_dirty()) << "Document is clean after undoing all changes";
	EXPECT_RANGE_CLEAN(0, 16, "Unmodified range clean after undoing changes");
	
	/* Undo changes prior to save... */
	doc->undo();
	
	ASSERT_DATA("MAGICorangemixed");
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty after undoing change made prior to save";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty after ungoing change made prior to save";
	EXPECT_RANGE_CLEAN( 0, 11, "Unmodified range clean after undoing change made prior to save");
	EXPECT_RANGE_DIRTY(11,  5, "Modified range dirty after undoing change made prior to save");
	
	/* Undo some more... */
	doc->undo();
	doc->undo();
	
	ASSERT_DATA("smoothorangemixed");
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty after undoing changes made prior to save";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty after undoing changes made prior to save";
	EXPECT_RANGE_DIRTY( 0,  6, "Modified range dirty after undoing changes made prior to save");
	EXPECT_RANGE_CLEAN( 6,  6, "Unmodified range clean after undoing changes made prior to save");
	EXPECT_RANGE_DIRTY(12,  5, "Modified range dirty after undoing changes made prior to save");
	
	/* Redo them until clean... */
	doc->redo();
	doc->redo();
	doc->redo();
	
	ASSERT_DATA("MAGICorangeRINGS");
	
	EXPECT_FALSE(doc->is_dirty()) << "Document is clean after redoing all changes";
	EXPECT_FALSE(doc->is_buffer_dirty()) << "Document is clean after redoing all changes";
	EXPECT_RANGE_CLEAN(0, 16, "Unmodified range clean after redoing all changes");
	
	/* Undo a couple again... */
	doc->undo();
	doc->undo();
	
	ASSERT_DATA("MAGICsmoothorangemixed");
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty after undoing changes made prior to save";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty after undoing changes made prior to save";
	EXPECT_RANGE_CLEAN( 0,  5, "Unmodified range clean after undoing changes made prior to save");
	EXPECT_RANGE_DIRTY( 5,  6, "Modified range dirty after undoing changes made prior to save");
	EXPECT_RANGE_CLEAN(11,  6, "Unmodified range clean after undoing changes made prior to save");
	EXPECT_RANGE_DIRTY(17,  5, "Modified range dirty after undoing changes made prior to save");
	
	/* Make NEW changes from here, making it impossible to return to a clean state. */
	
	const char *DATA7 = "follow";
	doc->overwrite_data(11, (const unsigned char*)(DATA7), strlen(DATA7));
	
	const char *DATA8 = "farm";
	doc->insert_data(22, (const unsigned char*)(DATA8), strlen(DATA8));
	
	ASSERT_DATA("MAGICsmoothfollowmixedfarm");
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty after undoing changes made prior to save and then making new changes";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty after undoing changes made prior to save and then making new changes";
	EXPECT_RANGE_CLEAN( 0,  5, "Unmodified range clean after undoing changes made prior to save and then making new changes");
	EXPECT_RANGE_DIRTY( 5, 21, "Modified range dirty after undoing changes made prior to save and then making new changes");
	
	/* Undo the new changes. */
	
	doc->undo();
	doc->undo();
	
	ASSERT_DATA("MAGICsmoothorangemixed");
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty after undoing changes made prior to save";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty after undoing changes made prior to save";
	EXPECT_RANGE_CLEAN( 0,  5, "Unmodified range clean after undoing changes made prior to save");
	EXPECT_RANGE_DIRTY( 5,  6, "Modified range dirty after undoing changes made prior to save");
	EXPECT_RANGE_CLEAN(11,  6, "Unmodified range clean after undoing changes made prior to save");
	EXPECT_RANGE_DIRTY(17,  5, "Modified range dirty after undoing changes made prior to save");
	
	/* Redo the new changes. */
	
	doc->redo();
	doc->redo();
	
	ASSERT_DATA("MAGICsmoothfollowmixedfarm");
	
	EXPECT_TRUE(doc->is_dirty()) << "Document is dirty after undoing changes made prior to save and then making new changes";
	EXPECT_TRUE(doc->is_buffer_dirty()) << "Document is dirty after undoing changes made prior to save and then making new changes";
	EXPECT_RANGE_CLEAN( 0,  5, "Unmodified range clean after undoing changes made prior to save and then making new changes");
	EXPECT_RANGE_DIRTY( 5, 21, "Modified range dirty after undoing changes made prior to save and then making new changes");
}

TEST_F(DocumentTest, OverwriteTextLatin1)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "colossalsupremefrighten";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	doc->set_data_type(0, strlen(DATA1), "text:ISO-8859-1");
	
	ASSERT_DATA("colossalsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 23, "text:ISO-8859-1"),
	);
	
	/* Write some nice simple 7-bit characters... */
	
	events.clear();
	
	EXPECT_EQ(
		doc->overwrite_text(0, "piquant", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(0, 7)",
		"CURSOR_UPDATE(7, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 7)                   << "Document::overwrite_text() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::overwrite_text() sets cursor to requested state";
	
	ASSERT_DATA("piquantlsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 23, "text:ISO-8859-1"),
	);
	
	/* Write some 8-bit characters... */
	
	events.clear();
	
	// LATIN CAPITAL LETTER AE
	// Division Sign
	// Latin Capital Letter Thorn
	EXPECT_EQ(
		doc->overwrite_text(8, "\xC3\x86\xC3\xB7\xC3\x9E", -1, Document::CSTATE_CURRENT, "average"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(8, 3)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 7)                   << "Document::overwrite_text() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::overwrite_text() sets cursor to requested state";
	
	ASSERT_DATA("piquantl" "\xC6\xF7\xDE" "remefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 23, "text:ISO-8859-1"),
	);
	
	/* Write a mixture of 7-bit, 8-bit and unrepresentable characters */
	
	events.clear();
	
	// A
	// LATIN CAPITAL LETTER AE
	// !
	// Division Sign
	// Snowman
	// Latin Capital Letter Thorn
	// Hammer and Sickle
	EXPECT_EQ(
		doc->overwrite_text(15, "A" "\xC3\x86" "!" "\xC3\xB7\xE2\x98\x83\xC3\x9E\xE2\x98\xAD", -1, Document::CSTATE_CURRENT, "average"),
		+Document::WRITE_TEXT_SKIPPED);
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(15, 5)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 7)                   << "Document::overwrite_text() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::overwrite_text() sets cursor to requested state";
	
	ASSERT_DATA("piquantl" "\xC6\xF7\xDE" "remeA" "\xC6" "!" "\xF7\xDE" "ten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 23, "text:ISO-8859-1"),
	);
	
	/* Write some characters that won't all fit in the file */
	
	events.clear();
	
	EXPECT_EQ(
		doc->overwrite_text(20, "ABCD", -1, Document::CSTATE_CURRENT, "lackadaisical"),
		+Document::WRITE_TEXT_TRUNCATED);
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(20, 3)",
	);
	
	ASSERT_DATA("piquantl" "\xC6\xF7\xDE" "remeA" "\xC6" "!" "\xF7\xDE" "ABC");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 23, "text:ISO-8859-1"),
	);
}

TEST_F(DocumentTest, OverwriteTextUTF8)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "colossalsupremefrighten";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	doc->set_data_type(0, strlen(DATA1), "text:UTF-8");
	
	ASSERT_DATA("colossalsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 23, "text:UTF-8"),
	);
	
	/* Write some nice simple 7-bit characters... */
	
	events.clear();
	
	EXPECT_EQ(
		doc->overwrite_text(0, "piquant", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(0, 7)",
		"CURSOR_UPDATE(7, 2)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 7)                   << "Document::overwrite_text() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::overwrite_text() sets cursor to requested state";
	
	ASSERT_DATA("piquantlsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 23, "text:UTF-8"),
	);
	
	/* Write some 8-bit characters... */
	
	events.clear();
	
	// LATIN CAPITAL LETTER AE
	// Division Sign
	// Latin Capital Letter Thorn
	EXPECT_EQ(
		doc->overwrite_text(8, "\xC3\x86\xC3\xB7\xC3\x9E", -1, Document::CSTATE_CURRENT, "average"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(8, 6)",
	);
	
	EXPECT_EQ(doc->get_cursor_position(), 7)                   << "Document::overwrite_text() moves cursor to requested position";
	EXPECT_EQ(doc->get_cursor_state(), Document::CSTATE_ASCII) << "Document::overwrite_text() sets cursor to requested state";
	
	ASSERT_DATA("piquantl" "\xC3\x86\xC3\xB7\xC3\x9E" "efrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 23, "text:UTF-8"),
	);
	
	/* Write some characters that won't all fit in the file */
	
	events.clear();
	
	EXPECT_EQ(
		doc->overwrite_text(20, "\xC3\x86\xC3\xB7", -1, Document::CSTATE_CURRENT, "lackadaisical"),
		+Document::WRITE_TEXT_TRUNCATED);
	
	EXPECT_EVENTS(
		"DATA_OVERWRITE(20, 2)",
	);
	
	ASSERT_DATA("piquantl" "\xC3\x86\xC3\xB7\xC3\x9E" "efrigh" "\xC3\x86" "n");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 23, "text:UTF-8"),
	);
}

TEST_F(DocumentTest, InsertText7Bit)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "colossalsupremefrighten";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	doc->set_data_type( 0, 8, "text:ISO-8859-1");
	doc->set_data_type( 8, 7, "text:UTF-8");
	doc->set_data_type(15, 8, "text:ISO-8859-1");
	
	ASSERT_DATA("colossalsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 8, "text:ISO-8859-1"),
		DATA_TYPE( 8, 7, "text:UTF-8"),
		DATA_TYPE(15, 8, "text:ISO-8859-1"),
	);
	
	/* Write some nice simple 7-bit characters... */
	
	events.clear();
	
	EXPECT_EQ(
		doc->insert_text(0, "piquant", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EQ(
		doc->insert_text(15, "zesty", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 7)",
		"CURSOR_UPDATE(7, 2)",
		"DATA_INSERT(15, 5)",
		"CURSOR_UPDATE(20, 2)",
	);
	
	ASSERT_DATA("piquantcolossalzestysupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 15, "text:ISO-8859-1"),
		DATA_TYPE(15, 12, "text:UTF-8"),
		DATA_TYPE(27, 8, "text:ISO-8859-1"),
	);
}

TEST_F(DocumentTest, InsertText8Bit)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "colossalsupremefrighten";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	doc->set_data_type( 0, 8, "text:ISO-8859-1");
	doc->set_data_type( 8, 7, "text:UTF-8");
	doc->set_data_type(15, 8, "text:ISO-8859-1");
	
	ASSERT_DATA("colossalsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 8, "text:ISO-8859-1"),
		DATA_TYPE( 8, 7, "text:UTF-8"),
		DATA_TYPE(15, 8, "text:ISO-8859-1"),
	);
	
	/* Write some 8-bit characters... */
	
	events.clear();
	
	// LATIN CAPITAL LETTER AE
	// Division Sign
	// Latin Capital Letter Thorn
	
	EXPECT_EQ(
		doc->insert_text(0, "\xC3\x86\xC3\xB7\xC3\x9E", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EQ(
		doc->insert_text(11, "\xC3\x86\xC3\xB7\xC3\x9E", -1, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 3)",
		"CURSOR_UPDATE(3, 2)",
		"DATA_INSERT(11, 6)",
	);
	
	ASSERT_DATA("\xC6\xF7\xDE" "colossal" "\xC3\x86\xC3\xB7\xC3\x9E" "supremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 11, "text:ISO-8859-1"),
		DATA_TYPE(11, 13, "text:UTF-8"),
		DATA_TYPE(24, 8, "text:ISO-8859-1"),
	);
}

TEST_F(DocumentTest, InsertTextMixed)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "colossalsupremefrighten";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	doc->set_data_type( 0, 8, "text:ISO-8859-1");
	doc->set_data_type( 8, 7, "text:UTF-8");
	doc->set_data_type(15, 8, "text:ISO-8859-1");
	
	ASSERT_DATA("colossalsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 8, "text:ISO-8859-1"),
		DATA_TYPE( 8, 7, "text:UTF-8"),
		DATA_TYPE(15, 8, "text:ISO-8859-1"),
	);
	
	/* Write a mixture of 7-bit, 8-bit and unrepresentable (in ISO-8859-1) characters */
	
	events.clear();
	
	// A
	// LATIN CAPITAL LETTER AE
	// !
	// Division Sign
	// Snowman
	// Latin Capital Letter Thorn
	// Hammer and Sickle
	
	EXPECT_EQ(
		doc->insert_text(0, "A" "\xC3\x86" "!" "\xC3\xB7\xE2\x98\x83\xC3\x9E\xE2\x98\xAD", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_SKIPPED);
	
	EXPECT_EQ(
		doc->insert_text(13, "A" "\xC3\x86" "!" "\xC3\xB7\xE2\x98\x83\xC3\x9E\xE2\x98\xAD", -1, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_INSERT(0, 5)",
		"CURSOR_UPDATE(5, 2)",
		"DATA_INSERT(13, 14)",
	);
	
	ASSERT_DATA("A" "\xC6" "!" "\xF7\xDE" "colossalA" "\xC3\x86" "!" "\xC3\xB7\xE2\x98\x83\xC3\x9E\xE2\x98\xAD" "supremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 13, "text:ISO-8859-1"),
		DATA_TYPE(13, 21, "text:UTF-8"),
		DATA_TYPE(34,  8, "text:ISO-8859-1"),
	);
}

TEST_F(DocumentTest, ReplaceText7Bit)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "colossalsupremefrighten";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	doc->set_data_type( 0, 8, "text:ISO-8859-1");
	doc->set_data_type( 8, 7, "text:UTF-8");
	doc->set_data_type(15, 8, "text:ISO-8859-1");
	
	ASSERT_DATA("colossalsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 8, "text:ISO-8859-1"),
		DATA_TYPE( 8, 7, "text:UTF-8"),
		DATA_TYPE(15, 8, "text:ISO-8859-1"),
	);
	
	/* Write some nice simple 7-bit characters... */
	
	events.clear();
	
	EXPECT_EQ(
		doc->replace_text(0, 8, "piquant", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EQ(
		doc->replace_text(7, 7, "zesty", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_ERASE(0, 8)",
		"DATA_INSERT(0, 7)",
		"CURSOR_UPDATE(7, 2)",
		"DATA_ERASE(7, 7)",
		"DATA_INSERT(7, 5)",
		"CURSOR_UPDATE(12, 2)",
	);
	
	ASSERT_DATA("piquantzestyfrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 7, "text:ISO-8859-1"),
		DATA_TYPE( 7, 5, "text:UTF-8"),
		DATA_TYPE(12, 8, "text:ISO-8859-1"),
	);
}

TEST_F(DocumentTest, ReplaceText8Bit)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "colossalsupremefrighten";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	doc->set_data_type( 0, 8, "text:ISO-8859-1");
	doc->set_data_type( 8, 7, "text:UTF-8");
	doc->set_data_type(15, 8, "text:ISO-8859-1");
	
	ASSERT_DATA("colossalsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 8, "text:ISO-8859-1"),
		DATA_TYPE( 8, 7, "text:UTF-8"),
		DATA_TYPE(15, 8, "text:ISO-8859-1"),
	);
	
	/* Write some 8-bit characters... */
	
	events.clear();
	
	// LATIN CAPITAL LETTER AE
	// Division Sign
	// Latin Capital Letter Thorn
	
	EXPECT_EQ(
		doc->replace_text(0, 8, "\xC3\x86\xC3\xB7\xC3\x9E", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EQ(
		doc->replace_text(3, 7, "\xC3\x86\xC3\xB7\xC3\x9E", -1, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_ERASE(0, 8)",
		"DATA_INSERT(0, 3)",
		"CURSOR_UPDATE(3, 2)",
		"DATA_ERASE(3, 7)",
		"DATA_INSERT(3, 6)",
	);
	
	ASSERT_DATA("\xC6\xF7\xDE\xC3\x86\xC3\xB7\xC3\x9E" "frighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE(0, 3, "text:ISO-8859-1"),
		DATA_TYPE(3, 6, "text:UTF-8"),
		DATA_TYPE(9, 8, "text:ISO-8859-1"),
	);
}

TEST_F(DocumentTest, ReplaceTextMixed)
{
	/* Insert into empty document... */
	
	const char *DATA1 = "colossalsupremefrighten";
	doc->insert_data(0, (const unsigned char*)(DATA1), strlen(DATA1));
	
	doc->set_data_type( 0, 8, "text:ISO-8859-1");
	doc->set_data_type( 8, 7, "text:UTF-8");
	doc->set_data_type(15, 8, "text:ISO-8859-1");
	
	ASSERT_DATA("colossalsupremefrighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0, 8, "text:ISO-8859-1"),
		DATA_TYPE( 8, 7, "text:UTF-8"),
		DATA_TYPE(15, 8, "text:ISO-8859-1"),
	);
	
	/* Write a mixture of 7-bit, 8-bit and unrepresentable (in ISO-8859-1) characters */
	
	events.clear();
	
	// A
	// LATIN CAPITAL LETTER AE
	// !
	// Division Sign
	// Snowman
	// Latin Capital Letter Thorn
	// Hammer and Sickle
	
	EXPECT_EQ(
		doc->replace_text(0, 10, "A" "\xC3\x86" "!" "\xC3\xB7\xE2\x98\x83\xC3\x9E\xE2\x98\xAD", Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_SKIPPED);
	
	EXPECT_EQ(
		doc->replace_text(5, 5, "A" "\xC3\x86" "!" "\xC3\xB7\xE2\x98\x83\xC3\x9E\xE2\x98\xAD", -1, Document::CSTATE_ASCII, "elite"),
		+Document::WRITE_TEXT_OK);
	
	EXPECT_EVENTS(
		"DATA_ERASE(0, 10)",
		"DATA_INSERT(0, 5)",
		"CURSOR_UPDATE(5, 2)",
		"DATA_ERASE(5, 5)",
		"DATA_INSERT(5, 14)",
	);
	
	ASSERT_DATA("A" "\xC6" "!" "\xF7\xDE" "A" "\xC3\x86" "!" "\xC3\xB7\xE2\x98\x83\xC3\x9E\xE2\x98\xAD" "frighten");
	
	EXPECT_DATA_TYPES(
		DATA_TYPE( 0,  5, "text:ISO-8859-1"),
		DATA_TYPE( 5, 14, "text:UTF-8"),
		DATA_TYPE(19,  8, "text:ISO-8859-1"),
	);
}
