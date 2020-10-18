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
		
		DocumentCtrlTest():
			frame(NULL, wxID_ANY, "REHex Tests"),
			doc(SharedDocumentPointer::make())
		{
			doc_ctrl = new DocumentCtrl(&frame, doc);
		}
};

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
