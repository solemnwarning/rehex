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
#include <wx/event.h>
#include <wx/frame.h>

#include "../src/document.hpp"
#include "../src/DocumentCtrl.hpp"
#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

class DocumentCtrlTest: public ::testing::Test
{
	protected:
		wxFrame frame;
		
		SharedDocumentPointer doc;
		DocumentCtrl *doc_ctrl;
		
		DocumentCtrlTest();
		
		void process_size_event();
		void process_char_event(int key_code, wxKeyModifier modifiers = wxMOD_NONE);
};

DocumentCtrlTest::DocumentCtrlTest():
	frame(NULL, wxID_ANY, "REHex Tests"),
	doc(SharedDocumentPointer::make())
{
	doc_ctrl = new DocumentCtrl(&frame, doc);
	
	/* Need a data region to avoid crashing during wxEVT_SIZE handler. */
	std::vector<DocumentCtrl::Region*> regions = { new DocumentCtrl::DataRegion(0, 0) };
	doc_ctrl->replace_all_regions(regions);
	
	/* Give the DocumentCtrl an initial size. */
	doc_ctrl->SetSize(wxSize(1024, 768));
	process_size_event();
}

void DocumentCtrlTest::process_size_event()
{
	wxSize dc_size = doc_ctrl->GetSize();
	int dc_id = doc_ctrl->GetId();
	
	wxSizeEvent size_event(dc_size, dc_id);
	doc_ctrl->GetEventHandler()->ProcessEvent(size_event);
}

void DocumentCtrlTest::process_char_event(int key_code, wxKeyModifier modifiers)
{
	wxKeyEvent event(wxEVT_CHAR);
	event.m_keyCode = key_code; /* No setter API, but the member is public... */
	
	event.SetControlDown(    !!(modifiers & wxMOD_CONTROL)     );
	event.SetRawControlDown( !!(modifiers & wxMOD_RAW_CONTROL) );
	event.SetShiftDown(      !!(modifiers & wxMOD_SHIFT)       );
	event.SetAltDown(        !!(modifiers & wxMOD_ALT)         );
	event.SetMetaDown(       !!(modifiers & wxMOD_META)        );
	
	doc_ctrl->GetEventHandler()->ProcessEvent(event);
}

class FixedHeightRegion: public DocumentCtrl::Region
{
	private:
		int64_t height;
		
	public:
		FixedHeightRegion(int64_t height, off_t indent_offset, off_t indent_length):
			Region(indent_offset, indent_length),
			height(height) {}
		
		virtual void calc_height(DocumentCtrl &doc, wxDC &dc) override
		{
			y_lines = height + indent_final;
		}
		
		virtual void draw(DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override {}
		
		int64_t get_y_position() const { return y_offset; }
		int64_t get_height() const { return y_lines; }
		
		int get_indent_depth() const { return indent_depth; }
		int get_indent_final() const { return indent_final; }
};

TEST_F(DocumentCtrlTest, ReplaceAllRegions)
{
	FixedHeightRegion *r1 = new FixedHeightRegion(4, 0, 0);
	FixedHeightRegion *r2 = new FixedHeightRegion(8, 0, 0);
	FixedHeightRegion *r3 = new FixedHeightRegion(6, 0, 0);
	FixedHeightRegion *r4 = new FixedHeightRegion(3, 0, 0);
	
	/* Indented regions. */
	FixedHeightRegion *r5  = new FixedHeightRegion(2,  0, 20);
	FixedHeightRegion *r6  = new FixedHeightRegion(2,  0,  4);
	FixedHeightRegion *r7  = new FixedHeightRegion(2,  4,  2);
	FixedHeightRegion *r8  = new FixedHeightRegion(2,  7, 13);
	FixedHeightRegion *r9  = new FixedHeightRegion(2, 10, 10);
	FixedHeightRegion *r10 = new FixedHeightRegion(2, 12,  2);
	FixedHeightRegion *r11 = new FixedHeightRegion(2, 14,  0);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11 };
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->get_regions()[0], r1);
	EXPECT_EQ(doc_ctrl->get_regions()[1], r2);
	EXPECT_EQ(doc_ctrl->get_regions()[2], r3);
	EXPECT_EQ(doc_ctrl->get_regions()[3], r4);
	
	EXPECT_EQ(r1->get_y_position(),  0);
	EXPECT_EQ(r1->get_height(),      4);
	EXPECT_EQ(r2->get_y_position(),  4);
	EXPECT_EQ(r2->get_height(),      8);
	EXPECT_EQ(r3->get_y_position(), 12);
	EXPECT_EQ(r3->get_height(),      6);
	EXPECT_EQ(r4->get_y_position(), 18);
	EXPECT_EQ(r4->get_height(),      3);
	
	EXPECT_EQ(r5->get_indent_depth(), 0);
	EXPECT_EQ(r5->get_indent_final(), 0);
		EXPECT_EQ(r6->get_indent_depth(), 1);
		EXPECT_EQ(r6->get_indent_final(), 1);
		
		EXPECT_EQ(r7->get_indent_depth(), 1);
		EXPECT_EQ(r7->get_indent_final(), 1);
		
		EXPECT_EQ(r8->get_indent_depth(), 1);
		EXPECT_EQ(r8->get_indent_final(), 0);
			EXPECT_EQ(r9->get_indent_depth(), 2);
			EXPECT_EQ(r9->get_indent_final(), 0);
				EXPECT_EQ(r10->get_indent_depth(), 3);
				EXPECT_EQ(r10->get_indent_final(), 1);
				
				EXPECT_EQ(r11->get_indent_depth(), 3);
				EXPECT_EQ(r11->get_indent_final(), 3);
}

TEST_F(DocumentCtrlTest, GetRegionByYOffset)
{
	std::vector<DocumentCtrl::Region*> regions;
	regions.push_back(new FixedHeightRegion(4, 0, 0));
	regions.push_back(new FixedHeightRegion(8, 0, 0));
	regions.push_back(new FixedHeightRegion(4, 0, 0));
	
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(
		doc_ctrl->region_by_y_offset(0),
		std::next(doc_ctrl->get_regions().begin(), 0));
	
	EXPECT_EQ(
		doc_ctrl->region_by_y_offset(1),
		std::next(doc_ctrl->get_regions().begin(), 0));
	
	EXPECT_EQ(
		doc_ctrl->region_by_y_offset(3),
		std::next(doc_ctrl->get_regions().begin(), 0));
	
	EXPECT_EQ(
		doc_ctrl->region_by_y_offset(4),
		std::next(doc_ctrl->get_regions().begin(), 1));
	
	EXPECT_EQ(
		doc_ctrl->region_by_y_offset(11),
		std::next(doc_ctrl->get_regions().begin(), 1));
	
	EXPECT_EQ(
		doc_ctrl->region_by_y_offset(12),
		std::next(doc_ctrl->get_regions().begin(), 2));
	
	EXPECT_EQ(
		doc_ctrl->region_by_y_offset(15),
		std::next(doc_ctrl->get_regions().begin(), 2));
}

TEST_F(DocumentCtrlTest, GetDataRegionByOffset)
{
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 10);
	DocumentCtrl::Region *r2 = new FixedHeightRegion(4, 40, 0);
	DocumentCtrl::Region *r3 = new DocumentCtrl::DataRegion(40, 5);
	DocumentCtrl::Region *r4 = new DocumentCtrl::DataRegion(45, 5);
	DocumentCtrl::Region *r5 = new FixedHeightRegion(4, 60, 0);
	DocumentCtrl::Region *r6 = new FixedHeightRegion(4, 60, 0);
	DocumentCtrl::Region *r7 = new DocumentCtrl::DataRegion(60, 10);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2, r3, r4, r5, r6, r7 };
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->data_region_by_offset( 0), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset( 9), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(10), r1);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(19), r1);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(20), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(39), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(40), r3);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(44), r3);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(45), r4);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(49), r4);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(50), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(59), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(60), r7);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(69), r7);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(70), r7);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(71), (DocumentCtrl::Region*)(NULL));
}

TEST_F(DocumentCtrlTest, CursorLeftWithinRegion)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 32);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 32);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(70);
	
	process_char_event(WXK_LEFT);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 69) << "Cursor moved back within DataRegion";
}

TEST_F(DocumentCtrlTest, CursorLeftToPrevRegion)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 32);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 32);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(60);
	
	process_char_event(WXK_LEFT);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 41) << "Cursor moved to end of previous data region";
}

TEST_F(DocumentCtrlTest, CursorLeftNowhereToGo)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 32);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 32);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(10);
	
	process_char_event(WXK_LEFT);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 10) << "Cursor not moved";
}

TEST_F(DocumentCtrlTest, CursorRightWithinRegion)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 32);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 32);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(70);
	
	process_char_event(WXK_RIGHT);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 71) << "Cursor moved forward within DataRegion";
}

TEST_F(DocumentCtrlTest, CursorRightToNextRegion)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 32);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 32);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(41);
	
	process_char_event(WXK_RIGHT);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 60) << "Cursor moved to start of next data region";
}

TEST_F(DocumentCtrlTest, CursorRightNowhereToGo)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 32);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 32);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(91);
	
	process_char_event(WXK_RIGHT);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 91) << "Cursor not moved";
}

TEST_F(DocumentCtrlTest, CursorUpWithinRegionFixedWidth)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(75);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 65) << "Cursor moved up within DataRegion";
}

TEST_F(DocumentCtrlTest, CursorUpWithinRegionFixedWidthClampStartOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(74);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 65) << "Cursor clamped to first column of previous line within DataRegion";
}

TEST_F(DocumentCtrlTest, CursorUpWithinRegionAutoWidth)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(DocumentCtrl::BYTES_PER_LINE_FIT_BYTES);
	doc_ctrl->set_bytes_per_group(50);
	
	doc_ctrl->set_show_offsets(false);
	doc_ctrl->set_show_ascii(false);
	
	/* Set the DocumentCtrl size to fit 10 bytes per line. */
	doc_ctrl->SetClientSize(wxSize(doc_ctrl->hf_string_width(20), 256));
	process_size_event();
	
	doc_ctrl->set_cursor_position(25);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 15) << "Cursor moved up within DataRegion";
}

TEST_F(DocumentCtrlTest, CursorUpToPrevRegionFixedWidth)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(62, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(63);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 33) << "Cursor moved up to matching column in last line of previous data region";
}

TEST_F(DocumentCtrlTest, CursorUpToPrevRegionFixedWidthStartOfRow)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(50, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(50);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 20) << "Cursor moved up to matching column in last line of previous data region";
}

TEST_F(DocumentCtrlTest, CursorUpToPrevRegionFixedWidthEndOfRow)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(50, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(59);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 29) << "Cursor moved up to matching column in last line of previous data region";
}

TEST_F(DocumentCtrlTest, CursorUpToPrevRegionFixedWidthClampStartOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 2);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(62, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(63);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 15) << "Cursor moved up to start of last line of previous data region";
}

TEST_F(DocumentCtrlTest, CursorUpToPrevRegionFixedWidthClampEndOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 2);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(62, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(69);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 16) << "Cursor moved up to end of last line of previous data region";
}

TEST_F(DocumentCtrlTest, CursorUpToPrevRegionAutoWidth)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(62, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(DocumentCtrl::BYTES_PER_LINE_FIT_BYTES);
	doc_ctrl->set_bytes_per_group(11);
	
	doc_ctrl->set_show_offsets(false);
	doc_ctrl->set_show_ascii(false);
	
	/* Set the DocumentCtrl size to fit 10 bytes per line. */
	doc_ctrl->SetClientSize(wxSize(doc_ctrl->hf_string_width(20), 256));
	process_size_event();
	
	doc_ctrl->set_cursor_position(63);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 26) << "Cursor moved up to matching column in last line of previous data region";
}

TEST_F(DocumentCtrlTest, CursorUpToPrevRegionAutoWidthClampStartOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 5);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(62, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(DocumentCtrl::BYTES_PER_LINE_FIT_BYTES);
	doc_ctrl->set_bytes_per_group(11);
	
	doc_ctrl->set_show_offsets(false);
	doc_ctrl->set_show_ascii(false);
	
	/* Set the DocumentCtrl size to fit 10 bytes per line. */
	doc_ctrl->SetClientSize(wxSize(doc_ctrl->hf_string_width(20), 256));
	process_size_event();
	
	doc_ctrl->set_cursor_position(70);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 19) << "Cursor moved up to last column in last line of previous data region";
}

TEST_F(DocumentCtrlTest, CursorUpNowhereToGo)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(15);
	
	process_char_event(WXK_UP);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 15) << "Cursor not moved";
}

TEST_F(DocumentCtrlTest, CursorDownWithinRegionFixedWidth)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(65);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 75) << "Cursor moved down within DataRegion";
}

TEST_F(DocumentCtrlTest, CursorDownWithinRegionFixedWidthClampEndOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(75);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 84) << "Cursor clamped to last column of next line within DataRegion";
}

TEST_F(DocumentCtrlTest, CursorDownWithinRegionAutoWidth)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(DocumentCtrl::BYTES_PER_LINE_FIT_BYTES);
	doc_ctrl->set_bytes_per_group(50);
	
	doc_ctrl->set_show_offsets(false);
	doc_ctrl->set_show_ascii(false);
	
	/* Set the DocumentCtrl size to fit 10 bytes per line. */
	doc_ctrl->SetClientSize(wxSize(doc_ctrl->hf_string_width(20), 256));
	process_size_event();
	
	doc_ctrl->set_cursor_position(15);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 25) << "Cursor moved down within DataRegion";
}

TEST_F(DocumentCtrlTest, CursorDownToNextRegionFixedWidth)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(62, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(33);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 63) << "Cursor moved down to matching column in first line of next data region";
}

TEST_F(DocumentCtrlTest, CursorDownToNextRegionFixedWidthStartOfRow)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(50, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(20);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 50) << "Cursor moved down to matching column in first line of next data region";
}

TEST_F(DocumentCtrlTest, CursorDownToNextRegionFixedWidthEndOfRow)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(50, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(29);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 59) << "Cursor moved down to matching column in first line of next data region";
}

TEST_F(DocumentCtrlTest, CursorDownToNextRegionFixedWidthClampStartOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(64, 2);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(32);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 64) << "Cursor moved down to start of first line of next data region";
}

TEST_F(DocumentCtrlTest, CursorDownToNextRegionFixedWidthClampEndOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 25);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(64, 2);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(38);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 65) << "Cursor moved down to end of first line of next data region";
}

TEST_F(DocumentCtrlTest, CursorDownToNextRegionAutoWidth)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(62, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(DocumentCtrl::BYTES_PER_LINE_FIT_BYTES);
	doc_ctrl->set_bytes_per_group(11);
	
	doc_ctrl->set_show_offsets(false);
	doc_ctrl->set_show_ascii(false);
	
	/* Set the DocumentCtrl size to fit 10 bytes per line. */
	doc_ctrl->SetClientSize(wxSize(doc_ctrl->hf_string_width(20), 256));
	process_size_event();
	
	doc_ctrl->set_cursor_position(26);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 63) << "Cursor moved down to matching column in first line of next data region";
}

TEST_F(DocumentCtrlTest, CursorDownToNextRegionAutoWidthClampEndOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 2);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(DocumentCtrl::BYTES_PER_LINE_FIT_BYTES);
	doc_ctrl->set_bytes_per_group(11);
	
	doc_ctrl->set_show_offsets(false);
	doc_ctrl->set_show_ascii(false);
	
	/* Set the DocumentCtrl size to fit 10 bytes per line. */
	doc_ctrl->SetClientSize(wxSize(doc_ctrl->hf_string_width(20), 256));
	process_size_event();
	
	doc_ctrl->set_cursor_position(34);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 61) << "Cursor moved up to last column in first line of next data region";
}

TEST_F(DocumentCtrlTest, CursorDownNowhereToGo)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(80);
	
	process_char_event(WXK_DOWN);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 80) << "Cursor not moved";
}

TEST_F(DocumentCtrlTest, CursorToStartOfDocument)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(70);
	
	process_char_event(WXK_HOME, wxMOD_CONTROL);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 15) << "Cursor moved to start of first data region";
}

TEST_F(DocumentCtrlTest, CursorToStartOfDocumentNowhereToGo)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(15);
	
	process_char_event(WXK_HOME, wxMOD_CONTROL);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 15) << "Cursor not moved";
}

TEST_F(DocumentCtrlTest, CursorToStartOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(74);
	
	process_char_event(WXK_HOME);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 70) << "Cursor moved to start of line";
}

TEST_F(DocumentCtrlTest, CursorToStartOfLineClamp)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(67);
	
	process_char_event(WXK_HOME);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 65) << "Cursor moved to start of line";
}

TEST_F(DocumentCtrlTest, CursorToStartOfLineNowhereToGo)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(70);
	
	process_char_event(WXK_HOME);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 70) << "Cursor not moved";
}

TEST_F(DocumentCtrlTest, CursorToEndOfDocument)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(20);
	
	process_char_event(WXK_END, wxMOD_CONTROL);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 84) << "Cursor moved to end of last data region";
}

TEST_F(DocumentCtrlTest, CursorToEndOfDocumentNowhereToGo)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(84);
	
	process_char_event(WXK_END, wxMOD_CONTROL);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 84) << "Cursor not moved";
}

TEST_F(DocumentCtrlTest, CursorToEndOfLine)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(16);
	
	process_char_event(WXK_END);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 19) << "Cursor moved to end of line";
}

TEST_F(DocumentCtrlTest, CursorToEndOfLineClamp)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(30);
	
	process_char_event(WXK_END);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 34) << "Cursor moved to end of line";
}

TEST_F(DocumentCtrlTest, CursorToEndOfLineNowhereToGo)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(15, 20);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(65, 20);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	doc_ctrl->set_cursor_position(29);
	
	process_char_event(WXK_END);
	
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 29) << "Cursor moved to end of line";
}

TEST_F(DocumentCtrlTest, CursorPageUpAllDataRegions)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 30);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 150);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_cursor_position(128);
	doc_ctrl->set_scroll_yoff(6);
	
	process_char_event(WXK_PAGEUP);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 1) << "Screen scrolled up by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 28) << "Cursor moved to nearest column in first visible data line";
}

TEST_F(DocumentCtrlTest, CursorPageUpMixedRegions)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new FixedHeightRegion(10, 0, 0);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(10, 30);
	DocumentCtrl::Region *r3 = new DocumentCtrl::DataRegion(60, 150);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2, r3 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_scroll_yoff(13);
	doc_ctrl->set_cursor_position(76);
	
	process_char_event(WXK_PAGEUP);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 8) << "Screen scrolled up by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 16) << "Cursor moved to nearest column in first visible data line";
}

TEST_F(DocumentCtrlTest, CursorPageUpNoDataRegions)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new FixedHeightRegion(10, 0, 0);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(10, 30);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_scroll_yoff(8);
	doc_ctrl->set_cursor_position(14);
	
	process_char_event(WXK_PAGEUP);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 3) << "Screen scrolled up by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 14) << "Cursor not moved";
}

TEST_F(DocumentCtrlTest, CursorPageUpLimitScroll)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 30);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 150);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_scroll_yoff(2);
	doc_ctrl->set_cursor_position(25);
	
	process_char_event(WXK_PAGEUP);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 0) << "Screen scrolled up to limit";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 15) << "Cursor moved to nearest column in first visible data line";
}

TEST_F(DocumentCtrlTest, CursorPageUpClampStartOfLine)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(28, 2);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 150);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_cursor_position(70);
	doc_ctrl->set_scroll_yoff(5);
	
	process_char_event(WXK_PAGEUP);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 0) << "Screen scrolled up by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 28) << "Cursor moved to nearest column in first visible data line";
}

TEST_F(DocumentCtrlTest, CursorPageUpClampEndOfLine)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 2);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 150);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_cursor_position(78);
	doc_ctrl->set_scroll_yoff(5);
	
	process_char_event(WXK_PAGEUP);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 0) << "Screen scrolled up by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 11) << "Cursor moved to nearest column in first visible data line";
}

TEST_F(DocumentCtrlTest, CursorPageDownAllDataRegions)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 30);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 150);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_cursor_position(14);
	doc_ctrl->set_scroll_yoff(0);
	
	process_char_event(WXK_PAGEDOWN);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 5) << "Screen scrolled down by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 124) << "Cursor moved to nearest column in last fully visible data line";
}

TEST_F(DocumentCtrlTest, CursorPageDownMixedRegions)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 30);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 40);
	DocumentCtrl::Region *r3 = new FixedHeightRegion(10, 100, 0);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2, r3 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_cursor_position(14);
	doc_ctrl->set_scroll_yoff(0);
	
	process_char_event(WXK_PAGEDOWN);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 5) << "Screen scrolled down by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 94) << "Cursor moved to nearest column in last fully visible data line";
}

TEST_F(DocumentCtrlTest, CursorPageDownNoDataRegions)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 30);
	DocumentCtrl::Region *r2 = new FixedHeightRegion(14, 100, 0);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_cursor_position(14);
	doc_ctrl->set_scroll_yoff(0);
	
	process_char_event(WXK_PAGEDOWN);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 5) << "Screen scrolled down by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 14) << "Cursor not moved";
}

TEST_F(DocumentCtrlTest, CursorPageDownLimitScroll)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 30);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(60, 40);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_cursor_position(14);
	doc_ctrl->set_scroll_yoff(0);
	
	process_char_event(WXK_PAGEDOWN);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 2) << "Screen scrolled down to limit";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 94) << "Cursor moved to nearest column in last fully visible data line";
}

TEST_F(DocumentCtrlTest, CursorPageDownClampStartOfLine)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 90);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(106, 2);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_cursor_position(14);
	doc_ctrl->set_scroll_yoff(0);
	
	process_char_event(WXK_PAGEDOWN);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 5) << "Screen scrolled down by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 106) << "Cursor moved to nearest column in last fully visible data line";
}

TEST_F(DocumentCtrlTest, CursorPageDownClampEndOfLine)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(10, 90);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(102, 2);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2 };
	doc_ctrl->replace_all_regions(regions);
	doc_ctrl->set_bytes_per_line(10);
	
	/* Set the DocumentCtrl size to fit 5.5 lines on screen. */
	int line_height = doc_ctrl->hf_char_height();
	doc_ctrl->SetClientSize(1024, (line_height * 5) + (line_height / 2));
	process_size_event();
	
	doc_ctrl->set_cursor_position(18);
	doc_ctrl->set_scroll_yoff(0);
	
	process_char_event(WXK_PAGEDOWN);
	
	EXPECT_EQ(doc_ctrl->get_scroll_yoff(), 5) << "Screen scrolled down by visible number of lines";
	EXPECT_EQ(doc_ctrl->get_cursor_position(), 103) << "Cursor moved to nearest column in last fully visible data line";
}
