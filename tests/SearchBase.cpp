/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include "../src/platform.hpp"
#include <assert.h>

#include <gtest/gtest.h>
#include <wx/evtloop.h>
#include <wx/frame.h>

#include "../src/document.hpp"
#include "../src/search.hpp"
#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

class SearchBaseDummy: public Search
{
	public:
		bool should_wrap;
		bool wrap_requested;
		bool nothing_found;
		
		SearchBaseDummy(wxWindow *parent, SharedDocumentPointer &doc):
			Search(parent, doc, "Dummy search class"),
			should_wrap(false),
			wrap_requested(false),
			nothing_found(false) {}
		
		/* NOTE: end_search() is called from subclass destructor rather than base to ensure search
		 * is stopped before the subclass becomes invalid, else there is a race where the base
		 * class will try calling the subclass's test() method and trigger undefined behaviour.
		*/
		virtual ~SearchBaseDummy()
		{
			if(running)
			{
				end_search();
			}
		}
		
		virtual bool test(const void *data, size_t data_size)
		{
			return (data_size >= 6 && memcmp(data, "foobar", 6) == 0)
				|| (data_size >= 3 && memcmp(data, "baz", 3) == 0);
		}
		
		virtual size_t test_max_window() override
		{
			return 6;
		}
		
		void set_range(off_t range_begin, off_t range_end)
		{
			this->range_begin = range_begin;
			this->range_end   = range_end;
		}
		
		bool is_running()
		{
			return running;
		}
		
		off_t get_match()
		{
			return match_found_at;
		}
		
	protected:
		virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer) override {}
		virtual bool read_window_controls() override { return false; }
		
		virtual bool wrap_query(const char *message) override
		{
			wrap_requested = true;
			return should_wrap;
		}
		
		virtual void not_found_notification() override
		{
			nothing_found = true;
		}
};

class SearchBaseTest: public ::testing::Test {
	protected:
		enum {
			ID_CHECK_TIMER = 1,
			ID_TIMEOUT_TIMER,
		};
		
		wxFrame frame;
		SharedDocumentPointer doc;
		SearchBaseDummy s;
		
		wxTimer check_timer;
		wxTimer timeout_timer;
		
		SearchBaseTest():
			frame(NULL, wxID_ANY, "REHex Tests"),
			doc(SharedDocumentPointer::make()),
			s(&frame, doc),
			check_timer(&frame, ID_CHECK_TIMER),
			timeout_timer(&frame, ID_TIMEOUT_TIMER)
		{
			const std::vector<unsigned char> DATA(0x8192, 0x00);
			doc->insert_data(0, DATA.data(), DATA.size());
			
			frame.Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
			{
				if(!s.is_running())
				{
					wxTheApp->GetMainLoop()->ScheduleExit();
				}
			}, ID_CHECK_TIMER, ID_CHECK_TIMER);
			
			frame.Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
			{
				wxTheApp->GetMainLoop()->ScheduleExit();
			}, ID_TIMEOUT_TIMER, ID_TIMEOUT_TIMER);
		}
		
		void wait_for_search()
		{
			check_timer.Start(100, wxTIMER_CONTINUOUS);
			timeout_timer.Start(5000, wxTIMER_ONE_SHOT);
			
			wxTheApp->OnRun();
			
			timeout_timer.Stop();
			check_timer.Stop();
		}
		
		void search_for_match(off_t sub_range_begin, off_t sub_range_end, Search::SearchDirection direction, off_t expect_match_at, off_t window_size = 128)
		{
			/* Starting a search will create a wxProgressDialog, which will install its
			 * own event loop(!) if one isn't already set up, which there isn't when
			 * running the tests, furthermore the dialog gets destroyed WITHIN the
			 * event loop that gets created by wxApp::OnRun() later, and the
			 * out-of-order event loop setup/destruction leads to a dangling event loop
			 * pointer! Yay!
			 *
			 * So we set up our own event loop just while the dialog is being created
			 * to avoid that.
			*/
			
			{
				wxEventLoop loop;
				wxEventLoopActivator activate(&loop);
				
				s.begin_search(sub_range_begin, sub_range_end, direction, window_size);
			}
			
			wait_for_search();
			
			EXPECT_FALSE(s.is_running());
			EXPECT_EQ(s.get_match(), expect_match_at);
			
			if(s.should_wrap)
			{
				EXPECT_TRUE(s.wrap_requested);
			}
			
			EXPECT_FALSE(s.nothing_found);
		}
		
		void search_for_no_match(off_t sub_range_begin, off_t sub_range_end, Search::SearchDirection direction, off_t window_size = 128)
		{
			/* Starting a search will create a wxProgressDialog, which will install its
			 * own event loop(!) if one isn't already set up, which there isn't when
			 * running the tests, furthermore the dialog gets destroyed WITHIN the
			 * event loop that gets created by wxApp::OnRun() later, and the
			 * out-of-order event loop setup/destruction leads to a dangling event loop
			 * pointer! Yay!
			 *
			 * So we set up our own event loop just while the dialog is being created
			 * to avoid that.
			*/
			
			{
				wxEventLoop loop;
				wxEventLoopActivator activate(&loop);
				
				s.begin_search(sub_range_begin, sub_range_end, direction, window_size);
			}
			
			wait_for_search();
			
			EXPECT_FALSE(s.is_running());
			EXPECT_EQ(s.get_match(), -1);
			
			if(s.should_wrap)
			{
				EXPECT_TRUE(s.wrap_requested);
				EXPECT_TRUE(s.nothing_found);
			}
			else{
				EXPECT_TRUE(s.wrap_requested ^ s.nothing_found);
			}
		}
};

TEST_F(SearchBaseTest, ForwardsNoMatch)
{
	s.set_range(0, 8192);
	
	search_for_no_match(0, 8192, Search::SearchDirection::FORWARDS);
}

TEST_F(SearchBaseTest, BackwardsNoMatch)
{
	s.set_range(0, 8192);
	
	search_for_no_match(0, 8192, Search::SearchDirection::BACKWARDS);
}

TEST_F(SearchBaseTest, ForwardsMatch)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(0, 8192);
	
	search_for_match(0, 8192, Search::SearchDirection::FORWARDS, 1000);
}

TEST_F(SearchBaseTest, BackwardsMatch)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(0, 8192);
	
	search_for_match(0, 8192, Search::SearchDirection::BACKWARDS, 1500);
}

TEST_F(SearchBaseTest, ForwardsMatchBeforeRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(1501, 8192);
	
	search_for_no_match(1501, 8192, Search::SearchDirection::FORWARDS);
}

TEST_F(SearchBaseTest, ForwardsMatchAfterRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(0, 1005);
	
	search_for_no_match(0, 1005, Search::SearchDirection::FORWARDS);
}

TEST_F(SearchBaseTest, BackwardsMatchBeforeRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(1501, 8192);
	
	search_for_no_match(1501, 8192, Search::SearchDirection::BACKWARDS);
}

TEST_F(SearchBaseTest, BackwardsMatchAfterRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(0, 1005);
	
	search_for_no_match(0, 1005, Search::SearchDirection::BACKWARDS);
}

TEST_F(SearchBaseTest, ForwardsMatchBeforeSubRangeNoWrap)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(0, 8192);
	
	search_for_no_match(1501, 8192, Search::SearchDirection::FORWARDS);
}

TEST_F(SearchBaseTest, ForwardsMatchBeforeSubRangeWrap)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(0, 8192);
	s.should_wrap = true;
	
	search_for_match(1501, 8192, Search::SearchDirection::FORWARDS, 1000);
}

TEST_F(SearchBaseTest, ForwardsMatchAtStartOfRangeBeforeSubRangeWrap)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(1000, 8192);
	s.should_wrap = true;
	
	search_for_match(1600, 8192, Search::SearchDirection::FORWARDS, 1000);
}

TEST_F(SearchBaseTest, ForwardsMatchStraddlingEndOfSubRangeBeforeSubRangeWrap)
{
	doc->overwrite_data(1500, "baz", 3);
	
	s.set_range(0, 8192);
	s.should_wrap = true;
	
	search_for_match(1502, 8192, Search::SearchDirection::FORWARDS, 1500);
}

TEST_F(SearchBaseTest, BackwardsMatchAfterSubRangeNoWrap)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(0, 8192);
	
	search_for_no_match(0, 1005, Search::SearchDirection::BACKWARDS);
}

TEST_F(SearchBaseTest, BackwardsMatchAfterSubRangeWrap)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(0, 8192);
	s.should_wrap = true;
	
	search_for_match(0, 1005, Search::SearchDirection::BACKWARDS, 1500);
}

TEST_F(SearchBaseTest, BackwardsMatchAtEndOfRangeAfterSubRangeWrap)
{
	doc->overwrite_data(1500, "baz", 3);
	
	s.set_range(0, 1503);
	s.should_wrap = true;
	
	search_for_match(0, 1005, Search::SearchDirection::BACKWARDS, 1500);
}

TEST_F(SearchBaseTest, BackwardsMatchStraddlingStartOfSubRangeAfterSubRangeWrap)
{
	doc->overwrite_data(1000, "foobar", 6);
	
	s.set_range(0, 8192);
	s.should_wrap = true;
	
	search_for_match(0, 1002, Search::SearchDirection::BACKWARDS, 1000);
}

TEST_F(SearchBaseTest, ForwardsMatchStartingBeforeRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(1000, 8192);
	
	search_for_match(0, 8192, Search::SearchDirection::FORWARDS, 1000);
}

TEST_F(SearchBaseTest, ForwardsMatchStartingAfterRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(1000, 4096);
	s.should_wrap = true;
	
	search_for_match(6000, 4096, Search::SearchDirection::FORWARDS, 1000);
}

TEST_F(SearchBaseTest, BackwardsMatchToBeforeRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(1000, 4096);
	s.should_wrap = true;
	
	search_for_match(1000, 800, Search::SearchDirection::BACKWARDS, 1500);
}

TEST_F(SearchBaseTest, BackwardsMatchToAfterRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(1000, 4096);
	
	search_for_match(1000, 8000, Search::SearchDirection::BACKWARDS, 1500);
}

TEST_F(SearchBaseTest, ForwardsZeroLengthRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(1000, 1000);
	
	search_for_no_match(1000, 1000, Search::SearchDirection::FORWARDS);
}

TEST_F(SearchBaseTest, BackwardsZeroLengthRange)
{
	doc->overwrite_data(1000, "foobar", 6);
	doc->overwrite_data(1500, "baz",    3);
	
	s.set_range(1000, 1000);
	
	search_for_no_match(1000, 1000, Search::SearchDirection::BACKWARDS);
}
