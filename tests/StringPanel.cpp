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

#include "../src/platform.hpp"

#include <gtest/gtest.h>
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
	
	EXPECT_EQ(string_panel->get_num_threads(), 0) << "StringPanel doesn't spawn workers for an empty file";
	
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
	
	EXPECT_NE(string_panel->get_num_threads(), 0) << "StringPanel spawns workers for non-empty file";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), (1024 * 1024)) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0) << "StringPanel workers exited";
	
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
	
	EXPECT_TRUE(string_panel->get_num_threads() > 0) << "StringPanel spawns workers for non-empty file";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), (1024 * 1024)) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0) << "StringPanel workers exited";
	
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
	
	EXPECT_NE(string_panel->get_num_threads(), 0) << "StringPanel spawns workers for non-empty file";
	
	wait_for_idle(1000);
	
	EXPECT_EQ(string_panel->get_clean_bytes(), 1024U) << "StringPanel processed all data in file";
	EXPECT_EQ(string_panel->get_num_threads(), 0) << "StringPanel workers exited";
	
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
