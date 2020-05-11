/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <gtest/gtest.h>

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
		}
		
		~DocumentTest()
		{
			delete doc;
		}
};

#define EXPECT_EVENTS(...) \
{ \
	const char *expected_events_[] = { __VA_ARGS__ }; \
	std::vector<std::string> expected_events(expected_events_, expected_events_ + (sizeof(expected_events_) / sizeof(*expected_events_))); \
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
