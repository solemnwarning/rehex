/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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
	std::vector<DocumentCtrl::Region*> regions = { new DocumentCtrl::DataRegion(doc, 0, 0, 0) };
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
		
		virtual void calc_height(DocumentCtrl &doc) override
		{
			y_lines = height + indent_final;
		}
		
		virtual void draw(DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override {}
		
		virtual std::pair<BitOffset, BitOffset> indent_offset_at_y(DocumentCtrl &doc_ctrl, int64_t y_lines_rel) override
		{
			return std::make_pair(indent_offset, indent_offset);
		}
		
		int64_t get_y_position() const { return y_offset; }
		int64_t get_height() const { return y_lines; }
		
		int get_indent_depth() const { return indent_depth; }
		int get_indent_final() const { return indent_final; }
};

class FixedHeightDataRegion: public DocumentCtrl::GenericDataRegion
{
	private:
		int64_t height;
		
	public:
		FixedHeightDataRegion(int64_t height, off_t d_offset, off_t d_length, off_t indent_offset):
			GenericDataRegion(d_offset, d_length, d_offset, indent_offset),
			height(height) {}
		
		virtual void calc_height(DocumentCtrl &doc) override
		{
			y_lines = height + indent_final;
		}
		
		virtual void draw(DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override {}
		
		virtual std::pair<BitOffset, ScreenArea> offset_at_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines) override { abort(); }
		virtual std::pair<BitOffset, ScreenArea> offset_near_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override { abort(); }
		virtual BitOffset cursor_left_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
		virtual BitOffset cursor_right_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
		virtual BitOffset cursor_up_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
		virtual BitOffset cursor_down_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
		virtual BitOffset cursor_home_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
		virtual BitOffset cursor_end_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
		virtual int cursor_column(BitOffset pos) override { abort(); }
		virtual BitOffset first_row_nearest_column(int column) override { abort(); }
		virtual BitOffset last_row_nearest_column(int column) override { abort(); }
		virtual BitOffset nth_row_nearest_column(int64_t row, int column) override { abort(); }
		
		virtual DocumentCtrl::Rect calc_offset_bounds(BitOffset offset, DocumentCtrl *doc_ctrl) override
		{
			return DocumentCtrl::Rect(y_offset, 1, 1, 1);
		}
		
		virtual ScreenArea screen_areas_at_offset(BitOffset offset, DocumentCtrl *doc_ctrl) override
		{
			return SA_HEX;
		}
		
		virtual wxCursor cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px) override { abort(); }
		
		int64_t get_y_position() const { return y_offset; }
		int64_t get_height() const { return y_lines; }
		
		int get_indent_depth() const { return indent_depth; }
		int get_indent_final() const { return indent_final; }
};

TEST_F(DocumentCtrlTest, ReplaceAllRegions)
{
	FixedHeightDataRegion *r1 = new FixedHeightDataRegion(4, 0, 0, 0);
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
	regions.push_back(new FixedHeightDataRegion(4,  0, 10,  0));
	regions.push_back(new FixedHeightDataRegion(8, 10, 10, 10));
	regions.push_back(new FixedHeightDataRegion(4, 20, 10, 20));
	
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
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 10, 10);
	DocumentCtrl::Region *r2 = new FixedHeightRegion(4, 40, 0);
	DocumentCtrl::Region *r3 = new DocumentCtrl::DataRegion(doc, 40, 5, 40);
	DocumentCtrl::Region *r4 = new DocumentCtrl::DataRegion(doc, 45, 5, 45);
	DocumentCtrl::Region *r5 = new FixedHeightRegion(4, 60, 0);
	DocumentCtrl::Region *r6 = new FixedHeightRegion(4, 60, 0);
	DocumentCtrl::Region *r7 = new DocumentCtrl::DataRegion(doc, 60, 10, 60);
	
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

TEST_F(DocumentCtrlTest, GetDataRegionByOffsetVirtualOrder)
{
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 40,  5, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 10, 10, 20);
	DocumentCtrl::Region *r3 = new DocumentCtrl::DataRegion(doc, 60, 10, 30);
	DocumentCtrl::Region *r4 = new DocumentCtrl::DataRegion(doc, 45,  5, 40);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2, r3, r4 };
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->data_region_by_offset( 0), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset( 9), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(10), r2);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(19), r2);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(20), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(39), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(40), r1);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(44), r1);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(45), r4);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(49), r4);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(50), r4);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(59), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(60), r3);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(69), r3);
	EXPECT_EQ(doc_ctrl->data_region_by_offset(70), (DocumentCtrl::Region*)(NULL));
	EXPECT_EQ(doc_ctrl->data_region_by_offset(71), (DocumentCtrl::Region*)(NULL));
}

TEST_F(DocumentCtrlTest, CursorLeftWithinRegion)
{
	std::vector<unsigned char> Z_DATA(128);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 32, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 32, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 32, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 32, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 32, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 32, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 32, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 32, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 32, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 32, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 32, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 32, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 62, 20, 62);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 20, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 50, 20, 50);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 20, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 50, 20, 50);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 2, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 62, 20, 62);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 2, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 62, 20, 62);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 62, 20, 62);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 5, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 62, 20, 62);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 62, 20, 62);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 20, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 50, 20, 50);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 20, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 50, 20, 50);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 64, 2, 64);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 25, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 64, 2, 64);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 62, 20, 62);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 2, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 15, 20, 15);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 65, 20, 65);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 30, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 150, 60);
	
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
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 10, 30, 10);
	DocumentCtrl::Region *r3 = new DocumentCtrl::DataRegion(doc, 60, 150, 60);
	
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
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 10, 30, 10);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 30, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 150, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 28, 2, 28);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 150, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 2, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 150, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 30, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 150, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 30, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 40, 60);
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 30, 10);
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 30, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 60, 40, 60);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 90, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 106, 2, 106);
	
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
	
	DocumentCtrl::Region *r1 = new DocumentCtrl::DataRegion(doc, 10, 90, 10);
	DocumentCtrl::Region *r2 = new DocumentCtrl::DataRegion(doc, 102, 2, 102);
	
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

TEST_F(DocumentCtrlTest, RegionOffsetAddSimple)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc,  0, 10,  0),
		new DocumentCtrl::DataRegion(doc, 10, 10, 10),
		new DocumentCtrl::DataRegion(doc, 20, 10, 20),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->region_offset_add( 0,  0),  0);
	EXPECT_EQ(doc_ctrl->region_offset_add( 0,  5),  5);
	EXPECT_EQ(doc_ctrl->region_offset_add( 5 , 0),  5);
	EXPECT_EQ(doc_ctrl->region_offset_add(10, 19), 29);
	EXPECT_EQ(doc_ctrl->region_offset_add(10, 20), 30);
	EXPECT_EQ(doc_ctrl->region_offset_add(10, 21), -1);
	EXPECT_EQ(doc_ctrl->region_offset_add(29,  0), 29);
	EXPECT_EQ(doc_ctrl->region_offset_add(30,  0), 30);
	EXPECT_EQ(doc_ctrl->region_offset_add(31,  0), -1);
}

TEST_F(DocumentCtrlTest, RegionOffsetSubSimple)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc,  0, 10,  0),
		new DocumentCtrl::DataRegion(doc, 10, 10, 10),
		new DocumentCtrl::DataRegion(doc, 20, 10, 20),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub( 0,  0),  0);
	EXPECT_EQ(doc_ctrl->region_offset_sub( 0,  1), -1);
	EXPECT_EQ(doc_ctrl->region_offset_sub( 5,  0),  5);
	EXPECT_EQ(doc_ctrl->region_offset_sub( 5,  1),  4);
	EXPECT_EQ(doc_ctrl->region_offset_sub( 5,  5),  0);
	EXPECT_EQ(doc_ctrl->region_offset_sub( 5,  6), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(10,  0), 10);
	EXPECT_EQ(doc_ctrl->region_offset_sub(10,  1),  9);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(29,  0), 29);
	EXPECT_EQ(doc_ctrl->region_offset_sub(29, 29),  0);
	EXPECT_EQ(doc_ctrl->region_offset_sub(29, 30), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(30,  0), 30);
	EXPECT_EQ(doc_ctrl->region_offset_sub(30, 30),  0);
	EXPECT_EQ(doc_ctrl->region_offset_sub(30, 31), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(31,  0), -1);
}

TEST_F(DocumentCtrlTest, RegionOffsetAddDiscontiguous)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc,  0, 10,  0),
		new DocumentCtrl::DataRegion(doc, 20, 20, 20),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->region_offset_add( 0,  9),  9);
	EXPECT_EQ(doc_ctrl->region_offset_add( 9 , 0),  9);
	EXPECT_EQ(doc_ctrl->region_offset_add( 0, 10), 20);
	EXPECT_EQ(doc_ctrl->region_offset_add(11,  0), -1);
	EXPECT_EQ(doc_ctrl->region_offset_add(19,  0), -1);
	EXPECT_EQ(doc_ctrl->region_offset_add(20,  0), 20);
	EXPECT_EQ(doc_ctrl->region_offset_add(20, 19), 39);
	EXPECT_EQ(doc_ctrl->region_offset_add(20, 20), 40);
	EXPECT_EQ(doc_ctrl->region_offset_add(20, 21), -1);
	EXPECT_EQ(doc_ctrl->region_offset_add(39,  0), 39);
	EXPECT_EQ(doc_ctrl->region_offset_add(40,  0), 40);
	EXPECT_EQ(doc_ctrl->region_offset_add(41,  0), -1);
}

TEST_F(DocumentCtrlTest, RegionOffsetSubDiscontiguous)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc,  0, 10,  0),
		new DocumentCtrl::DataRegion(doc, 20, 20, 20),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub( 9,  0),  9);
	EXPECT_EQ(doc_ctrl->region_offset_sub( 9,  9),  0);
	EXPECT_EQ(doc_ctrl->region_offset_sub( 9, 10), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(10,  0), -1);
	EXPECT_EQ(doc_ctrl->region_offset_sub(19,  0), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(20,  0), 20);
	EXPECT_EQ(doc_ctrl->region_offset_sub(20,  1),  9);
	EXPECT_EQ(doc_ctrl->region_offset_sub(20, 10),  0);
	EXPECT_EQ(doc_ctrl->region_offset_sub(20, 11), -1);
}

TEST_F(DocumentCtrlTest, RegionOffsetAddOutOfOrder)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc, 50, 10,  0),
		new DocumentCtrl::DataRegion(doc, 20, 20, 20),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->region_offset_add(49,  0), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_add(50,  0), 50);
	EXPECT_EQ(doc_ctrl->region_offset_add(50,  9), 59);
	EXPECT_EQ(doc_ctrl->region_offset_add(50, 10), 20);
	EXPECT_EQ(doc_ctrl->region_offset_add(59,  0), 59);
	
	EXPECT_EQ(doc_ctrl->region_offset_add(20,  0), 20);
	EXPECT_EQ(doc_ctrl->region_offset_add(20, 19), 39);
	EXPECT_EQ(doc_ctrl->region_offset_add(20, 20), 40);
	EXPECT_EQ(doc_ctrl->region_offset_add(20, 21), -1);
}

TEST_F(DocumentCtrlTest, RegionOffsetSubOutOfOrder)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc, 50, 10,  0),
		new DocumentCtrl::DataRegion(doc, 20, 20, 20),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(49,  0), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(50,  0), 50);
	EXPECT_EQ(doc_ctrl->region_offset_sub(50,  1), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(59,  0), 59);
	EXPECT_EQ(doc_ctrl->region_offset_sub(59,  9), 50);
	EXPECT_EQ(doc_ctrl->region_offset_sub(59, 10), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(20,  0), 20);
	EXPECT_EQ(doc_ctrl->region_offset_sub(20,  1), 59);
	EXPECT_EQ(doc_ctrl->region_offset_sub(20, 10), 50);
	EXPECT_EQ(doc_ctrl->region_offset_sub(20, 11), -1);
	
	EXPECT_EQ(doc_ctrl->region_offset_sub(39, 29), 50);
	EXPECT_EQ(doc_ctrl->region_offset_sub(39, 30), -1);
}

TEST_F(DocumentCtrlTest, RegionRangeLinear)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc, 100, 50, 1000),
		
		new DocumentCtrl::DataRegion(doc, 200, 50, 2000),
		new DocumentCtrl::DataRegion(doc, 250, 50, 2050),
		
		new DocumentCtrl::DataRegion(doc, 300, 50, 3000),
		new DocumentCtrl::DataRegion(doc, 360, 40, 3050),
		
		new DocumentCtrl::DataRegion(doc, 450, 50, 4000),
		new DocumentCtrl::DataRegion(doc, 400, 50, 4050),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	/* Basic tests. */
	EXPECT_FALSE( doc_ctrl->region_range_linear(  0,   9)  );
	EXPECT_FALSE( doc_ctrl->region_range_linear( 99,  99)  );
	EXPECT_FALSE( doc_ctrl->region_range_linear( 99, 100)  );
	EXPECT_TRUE(  doc_ctrl->region_range_linear(100, 100)  );
	EXPECT_TRUE(  doc_ctrl->region_range_linear(100, 149)  );
	EXPECT_FALSE( doc_ctrl->region_range_linear(100, 150)  );
	EXPECT_TRUE(  doc_ctrl->region_range_linear(149, 149)  );
	EXPECT_FALSE( doc_ctrl->region_range_linear(150, 150)  );
	
	/* Consecutive regions. */
	EXPECT_TRUE(  doc_ctrl->region_range_linear(200, 249)  );
	EXPECT_TRUE(  doc_ctrl->region_range_linear(200, 299)  );
	EXPECT_TRUE(  doc_ctrl->region_range_linear(250, 299)  );
	
	/* Discontiguous regions. */
	EXPECT_TRUE(  doc_ctrl->region_range_linear(300, 349)  );
	EXPECT_FALSE( doc_ctrl->region_range_linear(300, 350)  );
	EXPECT_FALSE( doc_ctrl->region_range_linear(300, 389)  );
	EXPECT_TRUE(  doc_ctrl->region_range_linear(360, 389)  );
	
	/* Out of order regions. */
	EXPECT_TRUE(  doc_ctrl->region_range_linear(400, 449)  );
	EXPECT_FALSE( doc_ctrl->region_range_linear(400, 499)  );
	EXPECT_TRUE(  doc_ctrl->region_range_linear(450, 499)  );
}

TEST_F(DocumentCtrlTest, GetSelectionRangesWithinRegion)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc, 100, 50, 100),
		
		new DocumentCtrl::DataRegion(doc, 200, 50, 200),
		new DocumentCtrl::DataRegion(doc, 250, 50, 250),
		new DocumentCtrl::DataRegion(doc, 300, 50, 300),
		new DocumentCtrl::DataRegion(doc, 350, 50, 350),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	/* 100 - */
	
	doc_ctrl->set_selection_raw(BitOffset(120, 0), BitOffset(129, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(120, 0), BitOffset(10, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(100, 0), BitOffset(119, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(100, 0), BitOffset(20, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(120, 0), BitOffset(149, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(120, 0), BitOffset(30, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(100, 0), BitOffset(149, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(100, 0), BitOffset(50, 0)));
	
	/* 350 - */
	
	doc_ctrl->set_selection_raw(BitOffset(370, 0), BitOffset(379, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(370, 0), BitOffset(10, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(350, 0), BitOffset(369, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(350, 0), BitOffset(20, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(370, 0), BitOffset(399, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(370, 0), BitOffset(30, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(350, 0), BitOffset(399, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(350, 0), BitOffset(50, 0)));
}

TEST_F(DocumentCtrlTest, GetSelectionRangesSpanningContiguousRegions)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc, 100, 50, 100),
		
		new DocumentCtrl::DataRegion(doc, 200, 50, 200),
		new DocumentCtrl::DataRegion(doc, 250, 50, 250),
		new DocumentCtrl::DataRegion(doc, 300, 50, 300),
		new DocumentCtrl::DataRegion(doc, 350, 50, 350),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_selection_raw(BitOffset(220, 0), BitOffset(269, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet()
			.set_range(BitOffset(220, 0), BitOffset(30, 0))
			.set_range(BitOffset(250, 0), BitOffset(20, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(200, 0), BitOffset(299, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet()
			.set_range(BitOffset(200, 0), BitOffset(50, 0))
			.set_range(BitOffset(250, 0), BitOffset(50, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(200, 0), BitOffset(399, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet()
			.set_range(BitOffset(200, 0), BitOffset(50, 0))
			.set_range(BitOffset(250, 0), BitOffset(50, 0))
			.set_range(BitOffset(300, 0), BitOffset(50, 0))
			.set_range(BitOffset(350, 0), BitOffset(50, 0)));
}

TEST_F(DocumentCtrlTest, GetSelectionRangesSpanningDiscontiguousRegions)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc, 100, 50, 100),
		
		new DocumentCtrl::DataRegion(doc, 200, 50, 200),
		new DocumentCtrl::DataRegion(doc, 250, 50, 250),
		new DocumentCtrl::DataRegion(doc, 300, 50, 300),
		new DocumentCtrl::DataRegion(doc, 350, 50, 350),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_selection_raw(BitOffset(120, 0), BitOffset(219, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet()
			.set_range(BitOffset(120, 0), BitOffset(30, 0))
			.set_range(BitOffset(200, 0), BitOffset(20, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(100, 0), BitOffset(299, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet()
			.set_range(BitOffset(100, 0), BitOffset(50, 0))
			.set_range(BitOffset(200, 0), BitOffset(50, 0))
			.set_range(BitOffset(250, 0), BitOffset(50, 0)));
}

TEST_F(DocumentCtrlTest, GetSelectionRangesSpanningOutOfOrderRegions)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc, 200, 50, 200),
		new DocumentCtrl::DataRegion(doc, 150, 50, 250),
		new DocumentCtrl::DataRegion(doc, 300, 50, 300),
		new DocumentCtrl::DataRegion(doc, 350, 50, 350),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_selection_raw(BitOffset(220, 0), BitOffset(319, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet()
			.set_range(BitOffset(220, 0), BitOffset(30, 0))
			.set_range(BitOffset(150, 0), BitOffset(50, 0))
			.set_range(BitOffset(300, 0), BitOffset(20, 0)));
	
	doc_ctrl->set_selection_raw(BitOffset(200, 0), BitOffset(349, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet()
			.set_range(BitOffset(200, 0), BitOffset(50, 0))
			.set_range(BitOffset(150, 0), BitOffset(50, 0))
			.set_range(BitOffset(300, 0), BitOffset(50, 0)));
}

TEST_F(DocumentCtrlTest, GetSelectionRangesBitAligned)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc, 100, 50, 100),
		
		new DocumentCtrl::DataRegion(doc, 200, 50, 200),
		new DocumentCtrl::DataRegion(doc, 250, 50, 250),
		new DocumentCtrl::DataRegion(doc, 300, 50, 300),
		new DocumentCtrl::DataRegion(doc, 350, 50, 350),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_selection_raw(BitOffset(120, 4), BitOffset(129, 7));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(120, 4), BitOffset(9, 4)));
	
	doc_ctrl->set_selection_raw(BitOffset(120, 0), BitOffset(129, 3));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet().set_range(BitOffset(120, 0), BitOffset(9, 4)));
	
	doc_ctrl->set_selection_raw(BitOffset(120, 2), BitOffset(370, 1));
	EXPECT_EQ(
		doc_ctrl->get_selection_ranges(),
		OrderedBitRangeSet()
			.set_range(BitOffset(120, 2), BitOffset(29, 6))
			.set_range(BitOffset(200, 0), BitOffset(50, 0))
			.set_range(BitOffset(250, 0), BitOffset(50, 0))
			.set_range(BitOffset(300, 0), BitOffset(50, 0))
			.set_range(BitOffset(350, 0), BitOffset(20, 2)));
}

TEST_F(DocumentCtrlTest, RegionOffsetCompare)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	std::vector<DocumentCtrl::Region*> regions = {
		new DocumentCtrl::DataRegion(doc, 200, 50,  200),
		new DocumentCtrl::DataRegion(doc, 150, 50,  250),
		new DocumentCtrl::DataRegion(doc, 300, 50,  300),
		new DocumentCtrl::DataRegion(doc, 350, 100, 350),
	};
	
	doc_ctrl->replace_all_regions(regions);
	
	EXPECT_EQ(doc_ctrl->region_offset_cmp(150, 150), 0);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(350, 350), 0);
	
	EXPECT_EQ(doc_ctrl->region_offset_cmp(150, 180), -30);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(200, 150), -50);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(300, 350), -50);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(200, 350), -150);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(200, 399), -199);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(220, 350), -130);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(220, 390), -170);
	
	EXPECT_EQ(doc_ctrl->region_offset_cmp(180, 150), 30);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(150, 200), 50);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(350, 300), 50);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(350, 200), 150);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(399, 200), 199);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(350, 220), 130);
	EXPECT_EQ(doc_ctrl->region_offset_cmp(390, 220), 170);
	
	EXPECT_THROW(doc_ctrl->region_offset_cmp(100, 150), std::invalid_argument);
	EXPECT_THROW(doc_ctrl->region_offset_cmp(150, 100), std::invalid_argument);
}

TEST_F(DocumentCtrlTest, GetSelectionInRegion)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::DataRegion *r1 = new DocumentCtrl::DataRegion(doc, 200, 50, 200);
	DocumentCtrl::DataRegion *r2 = new DocumentCtrl::DataRegion(doc, 250, 50, 250);
	DocumentCtrl::DataRegion *r3 = new DocumentCtrl::DataRegion(doc, 300, 50, 300);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2, r3 };
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_selection_raw(BitOffset(200, 0), BitOffset(219, 7));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r1),
		std::make_pair(BitOffset(200, 0), BitOffset(20, 0)));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r2),
		std::make_pair(BitOffset::INVALID, BitOffset::INVALID));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r3),
		std::make_pair(BitOffset::INVALID, BitOffset::INVALID));
	
	doc_ctrl->set_selection_raw(BitOffset(220, 0), BitOffset(319, 7));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r1),
		std::make_pair(BitOffset(220, 0), BitOffset(30, 0)));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r2),
		std::make_pair(BitOffset(250, 0), BitOffset(50, 0)));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r3),
		std::make_pair(BitOffset(300, 0), BitOffset(20, 0)));
}

TEST_F(DocumentCtrlTest, GetSelectionInRegionBitAligned)
{
	std::vector<unsigned char> Z_DATA(256);
	doc->insert_data(0, Z_DATA.data(), Z_DATA.size());
	
	DocumentCtrl::DataRegion *r1 = new DocumentCtrl::DataRegion(doc, 200, 50, 200);
	DocumentCtrl::DataRegion *r2 = new DocumentCtrl::DataRegion(doc, 250, 50, 250);
	DocumentCtrl::DataRegion *r3 = new DocumentCtrl::DataRegion(doc, 300, 50, 300);
	
	std::vector<DocumentCtrl::Region*> regions = { r1, r2, r3 };
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_selection_raw(BitOffset(200, 2), BitOffset(219, 6));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r1),
		std::make_pair(BitOffset(200, 2), BitOffset(19, 5)));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r2),
		std::make_pair(BitOffset::INVALID, BitOffset::INVALID));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r3),
		std::make_pair(BitOffset::INVALID, BitOffset::INVALID));
	
	doc_ctrl->set_selection_raw(BitOffset(220, 4), BitOffset(319, 1));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r1),
		std::make_pair(BitOffset(220, 4), BitOffset(29, 4)));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r2),
		std::make_pair(BitOffset(250, 0), BitOffset(50, 0)));
	
	EXPECT_EQ(
		doc_ctrl->get_selection_in_region(r3),
		std::make_pair(BitOffset(300, 0), BitOffset(19, 2)));
}
