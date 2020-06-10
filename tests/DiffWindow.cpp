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
#include <tuple>

#include <wx/frame.h>

#include "../src/DiffWindow.hpp"
#include "../src/document.hpp"
#include "../src/DocumentCtrl.hpp"
#include "../src/SafeWindowPointer.hpp"
#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

class DiffWindowTest: public ::testing::Test
{
	protected:
		wxFrame frame;
		
		SharedDocumentPointer doc1;
		DocumentCtrl *main_doc_ctrl1;
		
		SharedDocumentPointer doc2;
		DocumentCtrl *main_doc_ctrl2;
		
		DiffWindow *diff_window;
		
		DiffWindowTest():
			frame(NULL, wxID_ANY, "REHex Tests"),
			doc1(SharedDocumentPointer::make()),
			doc2(SharedDocumentPointer::make())
		{
			unsigned char doc1_buf[1024], doc2_buf[1024];
			
			for(off_t i = 0, x = 0; i < 1024; ++i)
			{
				
				if(x < 256)
				{
					doc1_buf[i] = x;
					doc2_buf[i] = x;
				}
				else if(x < 264)
				{
					doc1_buf[i] = 0x01;
					doc2_buf[i] = 0x02;
				}
				
				if(++x >= 264)
				{
					x = 0;
				}
			}
			
			doc1->insert_data(0, doc1_buf, sizeof(doc1_buf));
			doc2->insert_data(0, doc2_buf, sizeof(doc2_buf));
			
			main_doc_ctrl1 = new DocumentCtrl(&frame, doc1);
			main_doc_ctrl2 = new DocumentCtrl(&frame, doc2);
			
			diff_window = new DiffWindow(NULL);
		}
		
		~DiffWindowTest()
		{
			diff_window->Destroy();
		}
};

TEST_F(DiffWindowTest, InsertDataBeforeRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(99, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 110) << "Range offset increased by inserting data before it";
	EXPECT_EQ(ranges.back().get_length(), 100) << "Range length not affected by inserting data before it";
}

TEST_F(DiffWindowTest, InsertDataAtStartOfRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(100, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 110) << "Range offset increased by inserting data at start of it";
	EXPECT_EQ(ranges.back().get_length(), 100) << "Range length not affected by inserting data at start of it";
}

TEST_F(DiffWindowTest, InsertDataAtEndOfRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(199, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 100) << "Range offset not affected by inserting data at end of it";
	EXPECT_EQ(ranges.back().get_length(), 110) << "Range length increased by inserting data at end of it";
}

TEST_F(DiffWindowTest, InsertDataAfterRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(200, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 100) << "Range offset not affected by inserting data after it";
	EXPECT_EQ(ranges.back().get_length(), 100) << "Range length not affected by inserting data after it";
}

TEST_F(DiffWindowTest, InsertDataBeforeCursor)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_cursor_position(150);
	
	unsigned char x[10] = { 0 };
	doc1->insert_data( 25, x, 10); /* Insert before range */
	doc1->insert_data(149, x, 10); /* Insert within range, but before cursor */
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 170) << "Cursor position increased by inserting data before it";
}

TEST_F(DiffWindowTest, InsertDataAtCursor)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_cursor_position(150);
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(150, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 160) << "Cursor position increased by inserting data at it";
}

TEST_F(DiffWindowTest, InsertDataAfterCursor)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_cursor_position(150);
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(151, x, 10); /* Insert within range, but after cursor */
	doc1->insert_data(251, x, 10); /* Insert after range */
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 150) << "Cursor position not affected by inserting data after it";
}

TEST_F(DiffWindowTest, InsertDataBeforeSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	unsigned char x[10] = { 0 };
	doc1->insert_data( 25, x, 10); /* Insert before range */
	doc1->insert_data(125, x, 10); /* Insert within range, but before selection */
	doc1->insert_data(150, x, 10); /* Insert within range, at start of selection */
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_off,    180) << "Selection offset increased by inserting data before selection";
	EXPECT_EQ(selection_length,  10) << "Selection length not affected by inserting data before selection";
}

TEST_F(DiffWindowTest, InsertDataWithinSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(159, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by inserting data within selection";
}

TEST_F(DiffWindowTest, InsertDataAfterSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(160, x, 10); /* Insert within range, immediately after selection */
	doc1->insert_data(260, x, 10); /* Insert after range */
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_off,    150) << "Selection offset not affected by inserting data after selection";
	EXPECT_EQ(selection_length,  10) << "Selection length not affected by inserting data after selection";
}

TEST_F(DiffWindowTest, InsertDataBeforeFullSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(100, 100);
	
	unsigned char x[10] = { 0 };
	doc1->insert_data( 25, x, 10); /* Insert before range */
	doc1->insert_data(100, x, 10); /* Insert at start of range/selection */
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_off,    120) << "Selection offset increased by inserting data before selection encompassing whole range";
	EXPECT_EQ(selection_length, 100) << "Selection length not affected by inserting data before selection encompassing whole range";
}

TEST_F(DiffWindowTest, InsertDataWithinFullSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(100, 100);
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(199, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by inserting data within selection encompassing whole range";
}

TEST_F(DiffWindowTest, InsertDataAfterFullSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(100, 100);
	
	unsigned char x[10] = { 0 };
	doc1->insert_data(200, x, 10); /* Insert after range/selection */
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_off,    100) << "Selection offset not affected by inserting data after selection encompassing whole range";
	EXPECT_EQ(selection_length, 100) << "Selection length not affected by inserting data after selection encompassing whole range";
}

TEST_F(DiffWindowTest, EraseDataBeforeRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	doc1->erase_data(90, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 90)  << "Range offset reduced by erasing data before it";
	EXPECT_EQ(ranges.back().get_length(), 100) << "Range length not affected by erasing data before it";
}

TEST_F(DiffWindowTest, EraseDataOverlappingStartOfRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	doc1->erase_data(90, 15);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 90) << "Range offset reduced by erasing data overlapping start of it";
	EXPECT_EQ(ranges.back().get_length(), 95) << "Range length reduced by erasing data overlapping start of it";
}

TEST_F(DiffWindowTest, EraseDataAtStartOfRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	doc1->erase_data(100, 15);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 100) << "Range offset not affected by erasing data at start of it";
	EXPECT_EQ(ranges.back().get_length(), 85)  << "Range length reduced by erasing data at start of it";
}

TEST_F(DiffWindowTest, EraseDataAtEndOfRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	doc1->erase_data(190, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 100) << "Range offset not affected by erasing data at end of it";
	EXPECT_EQ(ranges.back().get_length(), 90)  << "Range length reduced by erasing data at end of it";
}

TEST_F(DiffWindowTest, EraseDataOverlappingEndOfRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	doc1->erase_data(195, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 100) << "Range offset not affected by erasing data overlapping end of it";
	EXPECT_EQ(ranges.back().get_length(), 95)  << "Range length reduced by erasing data overlapping end of it";
}

TEST_F(DiffWindowTest, EraseDataAfterEndOfRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	doc1->erase_data(200, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(ranges.back().get_offset(), 100) << "Range offset not affected by erasing data after end";
	EXPECT_EQ(ranges.back().get_length(), 100) << "Range length not affected by erasing data after end";
}

TEST_F(DiffWindowTest, EraseDataWholeRange)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	doc1->erase_data(100, 100);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 0U) << "Range is erased when all data in it is erased";
}

TEST_F(DiffWindowTest, EraseDataWholeDocument)
{
	diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	
	doc1->erase_data(0, doc1->buffer_length());
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 0U) << "Range is erased when all data in Document is erased";
}

TEST_F(DiffWindowTest, EraseDataBeforeCursor)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_cursor_position(150);
	
	doc1->erase_data(120, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 140) << "Cursor position reduced by erasing data before it";
}

TEST_F(DiffWindowTest, EraseDataOverlappingCursor)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_cursor_position(150);
	
	doc1->erase_data(145, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 145) << "Cursor position reduced by erasing data overlapping it";
}

TEST_F(DiffWindowTest, EraseDataAtCursor)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_cursor_position(150);
	
	doc1->erase_data(150, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 150) << "Cursor position not affected by erasing data at it";
}

TEST_F(DiffWindowTest, EraseDataAtCursorEndOfRange)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_cursor_position(199);
	
	doc1->erase_data(199, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 198) << "Cursor position reduced from end of range by erasing data at it";
}

TEST_F(DiffWindowTest, EraseDataAfterCursor)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_cursor_position(150);
	
	doc1->erase_data(160, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 150) << "Cursor position not affected by erasing data after it";
}

TEST_F(DiffWindowTest, EraseDataBeforeSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	doc1->erase_data(140, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_off,    140) << "Selection offset reduced by erasing data before selection";
	EXPECT_EQ(selection_length,  10) << "Selection length not affected by erasing data before selection";
}

TEST_F(DiffWindowTest, EraseDataOverlappingStartOfSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	doc1->erase_data(140, 15);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by erasing data overlapping start of selection";
}

TEST_F(DiffWindowTest, EraseDataAtStartOfSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	doc1->erase_data(150, 1);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by erasing data at start of selection";
}

TEST_F(DiffWindowTest, EraseDataAtEndOfSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	doc1->erase_data(159, 1);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by erasing data at end of selection";
}

TEST_F(DiffWindowTest, EraseDataOverlappingEndOfSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	doc1->erase_data(155, 15);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by erasing data overlapping end of selection";
}

TEST_F(DiffWindowTest, EraseDataAfterSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	doc1->erase_data(160, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_off,    150) << "Selection offset not affected by erasing data after selection";
	EXPECT_EQ(selection_length,  10) << "Selection length not affected by erasing data after selection";
}

TEST_F(DiffWindowTest, OverwriteDataBeforeSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	unsigned char x[10] = { 0 };
	doc1->overwrite_data(140, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_off,    150) << "Selection offset not affected by overwriting data before selection";
	EXPECT_EQ(selection_length,  10) << "Selection length not affected by overwriting data before selection";
}

TEST_F(DiffWindowTest, OverwriteDataOverlappingStartOfSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	unsigned char x[10] = { 0 };
	doc1->overwrite_data(145, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by overwriting data overlapping start of selection";
}

TEST_F(DiffWindowTest, OverwriteDataAtStartOfSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	unsigned char x[10] = { 0 };
	doc1->overwrite_data(150, x, 1);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by overwriting data at start of selection";
}

TEST_F(DiffWindowTest, OverwriteDataAtEndOfSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	unsigned char x[10] = { 0 };
	doc1->overwrite_data(159, x, 1);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by overwriting data at end of selection";
}

TEST_F(DiffWindowTest, OverwriteDataOverlappingEndOfSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	unsigned char x[10] = { 0 };
	doc1->overwrite_data(155, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_length, 0) << "Selection cleared by overwriting data overlapping end of selection";
}

TEST_F(DiffWindowTest, OverwriteDataAfterSelection)
{
	auto range = diff_window->add_range(DiffWindow::Range(doc1, main_doc_ctrl1, 100, 100));
	SafeWindowPointer<DocumentCtrl> doc_ctrl(range->_im_a_test_give_me_doc_ctrl());
	
	doc_ctrl->set_selection(150, 10);
	
	unsigned char x[10] = { 0 };
	doc1->overwrite_data(160, x, 10);
	
	auto ranges = diff_window->get_ranges();
	ASSERT_EQ(ranges.size(), 1U);
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	EXPECT_EQ(selection_off,    150) << "Selection offset not affected by overwriting data after selection";
	EXPECT_EQ(selection_length,  10) << "Selection length not affected by overwriting data after selection";
}
