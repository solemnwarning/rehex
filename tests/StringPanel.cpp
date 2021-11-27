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
#include <list>
#include <vector>
#include <wx/frame.h>

#include "../src/document.hpp"
#include "../src/DocumentCtrl.hpp"
#include "../src/SharedDocumentPointer.hpp"
#include "../src/StringPanel.hpp"

using namespace REHex;

class StringPanelTest: public ::testing::Test
{
	protected:
		enum {
			ID_CHECK_TIMER = 1,
			ID_TIMEOUT_TIMER,
		};
		
		wxFrame frame;
		
		SharedDocumentPointer doc;
		DocumentCtrl *main_doc_ctrl;
		
		StringPanel *string_panel;
		
		wxTimer *check_timer;
		wxTimer *timeout_timer;
		
		StringPanelTest():
			frame(NULL, wxID_ANY, "REHex Tests"),
			doc(SharedDocumentPointer::make())
		{
			main_doc_ctrl = new DocumentCtrl(&frame, doc);
			
			/* Need to put a Region in the DocumentCtrl to avoid crashes. */
			std::vector<DocumentCtrl::Region*> regions;
			regions.push_back(new DocumentCtrl::DataRegion(0, 0, 0));
			main_doc_ctrl->replace_all_regions(regions);
			
			check_timer = new wxTimer(&frame, ID_CHECK_TIMER);
			timeout_timer = new wxTimer(&frame, ID_TIMEOUT_TIMER);
			
			frame.Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
			{
				if(string_panel->get_num_threads() == 0)
				{
					wxTheApp->ExitMainLoop();
				}
			}, ID_CHECK_TIMER, ID_CHECK_TIMER);
			
			frame.Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
			{
				wxTheApp->ExitMainLoop();
			}, ID_TIMEOUT_TIMER, ID_TIMEOUT_TIMER);
		}
		
		void wait_for_idle(unsigned int timeout_ms)
		{
			check_timer->Start(100, wxTIMER_CONTINUOUS);
			timeout_timer->Start(timeout_ms, wxTIMER_ONE_SHOT);
			
			wxTheApp->OnRun();
			
			timeout_timer->Stop();
			check_timer->Stop();
		}
};

TEST_F(StringPanelTest, EmptyFile)
{
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel doesn't spawn workers for an empty file";
	
	ByteRangeSet strings = string_panel->get_strings();
	std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
	
	const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {};
	
	EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel doesn't find any strings in an empty file";
}

TEST_F(StringPanelTest, TextOnlyFile)
{
	const std::vector<unsigned char> DATA((1024 * 1024), 'A');
	doc->insert_data(0, DATA.data(), DATA.size());
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	EXPECT_NE(string_panel->get_num_threads(), 0U) << "StringPanel spawns workers for non-empty file";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), (1024 * 1024)) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	ByteRangeSet strings = string_panel->get_strings();
	std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
	
	const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
		ByteRangeSet::Range(0, (1024 * 1024)),
	};
	
	EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel finds string encompassing entire text file";
}

TEST_F(StringPanelTest, BinaryOnlyFile)
{
	const std::vector<unsigned char> DATA((1024 * 1024), 255);
	doc->insert_data(0, DATA.data(), DATA.size());
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	EXPECT_TRUE(string_panel->get_num_threads() > 0U) << "StringPanel spawns workers for non-empty file";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), (1024 * 1024)) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	ByteRangeSet strings = string_panel->get_strings();
	std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
	
	const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {};
	
	EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel doesn't find any strings in non-text file";
}

TEST_F(StringPanelTest, MixedFile)
{
	std::vector<unsigned char> data;
	
	for(off_t i = 0; i < 1024; ++i)
	{
		data.push_back(i % 256);
	}
	
	doc->insert_data(0, data.data(), data.size());
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	EXPECT_NE(string_panel->get_num_threads(), 0U) << "StringPanel spawns workers for non-empty file";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1024U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	ByteRangeSet strings = string_panel->get_strings();
	std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
	
	const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
		ByteRangeSet::Range( 32, 95),
		ByteRangeSet::Range(288, 95),
		ByteRangeSet::Range(544, 95),
		ByteRangeSet::Range(800, 95),
	};
	
	EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel finds strings in mixed file";
}

TEST_F(StringPanelTest, OverwriteDataTruncatesString)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "cemetery tedious lunchroom", 26);
	doc->overwrite_data(256, "crazy nutty grass", 17);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 26),
			ByteRangeSet::Range(256, 17),
		};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	doc->overwrite_data(150, BIN_DATA.data(), 4);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an overwrite";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1024U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 22),
			ByteRangeSet::Range(256, 17),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel adjusts strings truncated by overwrite";
	}
}

TEST_F(StringPanelTest, OverwriteDataSplitsString)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "gold rapid macho", 16);
	doc->overwrite_data(256, "broad slope peep", 16);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 16),
			ByteRangeSet::Range(256, 16),
		};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	doc->overwrite_data(132, BIN_DATA.data(), 7);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an overwrite";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1024U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 4),
			ByteRangeSet::Range(139, 5),
			ByteRangeSet::Range(256, 16),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel adjusts strings split by overwrite";
	}
}

TEST_F(StringPanelTest, OverwriteDataSplitsInvalidatesString)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "gold rapid macho", 16);
	doc->overwrite_data(256, "broad slope peep", 16);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 16),
			ByteRangeSet::Range(256, 16),
		};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	doc->overwrite_data(131, BIN_DATA.data(), 8);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an overwrite";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1024U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(139, 5),
			ByteRangeSet::Range(256, 16),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel adjusts strings split and invalidated by overwrite";
	}
}

TEST_F(StringPanelTest, OverwriteDataCompletesString)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "abc", 3);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	unsigned const char DATA[] = { 'd' };
	doc->overwrite_data(131, DATA, 1);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an overwrite";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1024U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 4),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel finds string completed by overwrite";
	}
}

TEST_F(StringPanelTest, InsertData)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "bent historical malicious", 25);
	doc->overwrite_data(256, "jog idiotic flight", 18);
	doc->overwrite_data(512, "knowledge spotty identify", 25);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 25),
			ByteRangeSet::Range(256, 18),
			ByteRangeSet::Range(512, 25),
		};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	const unsigned char INSERT_DATA[] = { 0x1B, 'A', 'A', 'A', 'A', 0x1B, 'B' };
	
	doc->insert_data(259, INSERT_DATA, 7);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an insert";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1031U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 25),
			ByteRangeSet::Range(260, 4),
			ByteRangeSet::Range(265, 16),
			ByteRangeSet::Range(519, 25),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel adjusts strings affected by insert";
	}
}

TEST_F(StringPanelTest, InsertDataCompletesString)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "abc", 3);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	const unsigned char INSERT_DATA[] = { 'd' };
	
	doc->insert_data(131, INSERT_DATA, 1);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an insert";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1025U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 4),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel finds strings completed by insert";
	}
}

TEST_F(StringPanelTest, EraseData)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "harm morning homeless", 21);
	doc->overwrite_data(256, "rightful group cave",   19);
	doc->overwrite_data(512, "pumped stick feeble",   19);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 21),
			ByteRangeSet::Range(256, 19),
			ByteRangeSet::Range(512, 19),
		};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	doc->erase_data(260, 6);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an erase";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1018U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 21),
			ByteRangeSet::Range(256, 13),
			ByteRangeSet::Range(506, 19),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel adjusts strings affected by erase";
	}
}

TEST_F(StringPanelTest, EraseDataInvalidate)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "murder lyrical touch", 20);
	doc->overwrite_data(256, "sturdy books scrape", 19);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 20),
			ByteRangeSet::Range(256, 19),
		};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	doc->erase_data(259, 16);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an erase";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1008U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 20),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel removes string invalidated by erase";
	}
}

TEST_F(StringPanelTest, EraseDataMerge)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "salty peep party", 16);
	doc->overwrite_data(256, "kettle kneel supply", 19);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 16),
			ByteRangeSet::Range(256, 19),
		};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	doc->erase_data(142, 114);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an erase";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 910U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 33),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel merges strings merged by erase";
	}
}

TEST_F(StringPanelTest, EraseDataCompletesString)
{
	const std::vector<unsigned char> BIN_DATA(1024, 0x1B);
	
	doc->insert_data(0, BIN_DATA.data(), BIN_DATA.size());
	
	doc->overwrite_data(128, "abc", 3);
	doc->overwrite_data(132, "d", 1);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 1024U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	doc->erase_data(131, 1);
	
	EXPECT_EQ(string_panel->get_num_threads(), 1U) << "StringPanel spawns a worker for an erase";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1023U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(128, 4),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel finds strings completed by erase";
	}
}

TEST_F(StringPanelTest, BackToBackModifications)
{
	static const size_t kiB = 1024;
	static const size_t MiB = kiB * 1024;
	
	const std::vector<unsigned char> BIN_DATA(16 * MiB, 0x1B);
	const std::vector<unsigned char> TEXT_DATA(16 * MiB, 'X');
	
	doc->insert_data(0, BIN_DATA.data(), 16 * MiB);
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(5000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), (off_t)(16 * MiB));
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {};
		
		ASSERT_EQ(got_strings, EXPECT_STRINGS);
	}
	
	doc->insert_data(1 * MiB, TEXT_DATA.data(), 1 * MiB);
	doc->insert_data(4 * MiB, TEXT_DATA.data(), 512 * kiB);
	doc->insert_data(1536 * kiB, TEXT_DATA.data(), 1 * MiB);
	doc->overwrite_data(5 * MiB, BIN_DATA.data(), 256 * kiB);
	doc->erase_data(5 * MiB, 128 * kiB);
	doc->overwrite_data(256 * kiB, TEXT_DATA.data(), 256 * kiB);
	doc->erase_data(300 * kiB, 64 * kiB);
	doc->insert_data(10 * MiB, TEXT_DATA.data(), 16 * MiB);
	doc->insert_data(1 * MiB, BIN_DATA.data(), 16 * MiB);
	doc->erase_data(41 * MiB, 1 * MiB);
	
	EXPECT_NE(string_panel->get_num_threads(), 0U) << "StringPanel spawned worker threads";
	
	wait_for_idle(10000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), (off_t)(49 * MiB + 320 * kiB)) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0U) << "StringPanel workers exited";
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(256 * kiB, 192 * kiB),
			ByteRangeSet::Range(1 * MiB - 64 * kiB, 64 * kiB),
			ByteRangeSet::Range(17 * MiB, 2 * MiB - 64 * kiB),
			ByteRangeSet::Range(21 * MiB + 64 * kiB, 256 * kiB),
			ByteRangeSet::Range(26 * MiB, 15 * MiB),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS) << "StringPanel finds strings in result of combined operations";
	}
}

TEST_F(StringPanelTest, UTF8)
{
	const unsigned char DATA[] = {
		/* Padding */
		/* 0x00 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		
		/* Short ASCII-only string */
		/* 0x08 */ 'A', 'B', 'C', 0x00, 0x00, 0x00, 0x00, 0x00,
		
		/* ASCII-only string */
		/* 0x10 */ 'A', 'B', 'C', 'D', 'E', 'F', 0x00, 0x00,
		
		/* Short (enough bytes, but not enough code points) UTF-8 string */
		/* 0x18 */ 0xC2, 0xA3, 0xE2, 0x98, 0xAD, 0xE2, 0x98, 0x83,
		
		/* Padding */
		/* 0x20 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		
		/* UTF-8 string */
		/* 0x28 */ 0xC3, 0xA8, 0xC3, 0xB4, 0xC3, 0xBC, 0xC3, 0xA1,
		
		/* Padding */
		/* 0x30 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		
		/* Mixed ASCII/UTF-8 string */
		/* 0x38 */ 'A', 'B', 0xC3, 0xB4, 0xC3, 0xBC, 0x00, 0x00,
		
		/* "Hello" in UTF-16LE */
		/* 0x40 */ 'H', 0x00,  'e', 0x00,  'l', 0x00,  'l', 0x00,
		/* 0x48 */ 'o', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		
	};
	
	doc->insert_data(0, DATA, sizeof(DATA));
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_encoding("UTF-8");
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 0x50U);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(0x10, 6),
			ByteRangeSet::Range(0x28, 8),
			ByteRangeSet::Range(0x38, 6),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS);
	}
}

TEST_F(StringPanelTest, UTF16)
{
	const unsigned char DATA[] = {
		/* Padding */
		/* 0x00 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		
		/* Short ASCII-only string */
		/* 0x08 */ 'A', 'B', 'C', 0x00, 0x00, 0x00, 0x00, 0x00,
		
		/* ASCII-only string */
		/* 0x10 */ 'A', 'B', 'C', 'D', 'E', 'F', 0x00, 0x00,
		
		/* Padding */
		/* 0x18 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		
		/* Mixed ASCII/UTF-8 string */
		/* 0x20 */ 'A', 'B', 0xC3, 0xB4, 0xC3, 0xBC, 0x00, 0x00,
		
		/* "Hello" in UTF-16LE */
		/* 0x28 */ 'H', 0x00,  'e', 0x00,  'l', 0x00,  'l', 0x00,
		/* 0x30 */ 'o', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		
	};
	
	doc->insert_data(0, DATA, sizeof(DATA));
	
	string_panel = new StringPanel(&frame, doc, main_doc_ctrl);
	string_panel->set_encoding("UTF-16LE");
	string_panel->set_min_string_length(4);
	string_panel->set_visible(true);
	
	wait_for_idle(1000);
	
	ASSERT_EQ(string_panel->get_clean_bytes(), 0x38);
	ASSERT_EQ(string_panel->get_num_threads(), 0U);
	
	{
		ByteRangeSet strings = string_panel->get_strings();
		std::vector<ByteRangeSet::Range> got_strings(strings.begin(), strings.end());
		
		const std::vector<ByteRangeSet::Range> EXPECT_STRINGS = {
			ByteRangeSet::Range(0x28, 10),
		};
		
		EXPECT_EQ(got_strings, EXPECT_STRINGS);
	}
}
