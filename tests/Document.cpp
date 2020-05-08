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
		"EV_HIGHLIGHTS_CHANGED", /* BUG */
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
		"EV_HIGHLIGHTS_CHANGED", /* BUG */
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
