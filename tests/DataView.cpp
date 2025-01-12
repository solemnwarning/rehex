/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "testutil.hpp"

#include "../src/DataView.hpp"
#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

class LinearVirtualDocumentViewTest: public ::testing::Test
{
	protected:
		SharedDocumentPointer document;
		std::unique_ptr<LinearVirtualDocumentView> view;
		
		std::vector<std::string> events;
		
		LinearVirtualDocumentViewTest():
			document(SharedDocumentPointer::make())
		{
			const unsigned char DATA[] = {
				0x01, 0x23, 0x45, 0x67,             /* virt offset 0x200 */
				0xAA, 0xAA, 0xAA, 0xAA,             /* not mapped */
				0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, /* virt offset 0x100 */
				0x12, 0x34, 0x56, 0x78,             /* virt offset 0x300 */
				0xAA, 0xAA, 0xAA, 0xAA,             /* not mapped */
			};
			
			document->insert_data(0, DATA, sizeof(DATA));
			
			document->set_virt_mapping( 8, 0x100, 6);
			document->set_virt_mapping( 0, 0x200, 4);
			document->set_virt_mapping(14, 0x300, 4);
			
			view.reset(new LinearVirtualDocumentView(document));
			
			view->Bind(DATA_ERASE, [this](OffsetLengthEvent &event)
			{
				char event_s[64];
				snprintf(event_s, sizeof(event_s), "DATA_ERASE(%d, %d)", (int)(event.offset), (int)(event.length));
				events.push_back(event_s);
			});
			
			view->Bind(DATA_INSERT, [this](OffsetLengthEvent &event)
			{
				char event_s[64];
				snprintf(event_s, sizeof(event_s), "DATA_INSERT(%d, %d)", (int)(event.offset), (int)(event.length));
				events.push_back(event_s);
			});
			
			view->Bind(DATA_OVERWRITE, [this](OffsetLengthEvent &event)
			{
				char event_s[64];
				snprintf(event_s, sizeof(event_s), "DATA_OVERWRITE(%d, %d)", (int)(event.offset), (int)(event.length));
				events.push_back(event_s);
			});
			
			view->Bind(DATA_MODIFY_BEGIN, [this](wxCommandEvent &event)
			{
				events.push_back("DATA_MODIFY_BEGIN()");
			});
			
			view->Bind(DATA_MODIFY_END, [this](wxCommandEvent &event)
			{
				events.push_back("DATA_MODIFY_END()");
			});
		}
};

TEST_F(LinearVirtualDocumentViewTest, ReadData)
{
	EXPECT_EQ(view->view_length(), 14);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 20),
		std::vector<unsigned char>({ 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78 }));
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 1),
		std::vector<unsigned char>({ 0x89 }));
	
	EXPECT_EQ(
		view->read_data(BitOffset(5, 0), 2),
		std::vector<unsigned char>({ 0xDC, 0x01 }));
	
	EXPECT_EQ(
		view->read_data(BitOffset(10, 0), 20),
		std::vector<unsigned char>({ 0x12, 0x34, 0x56, 0x78 }));
}

TEST_F(LinearVirtualDocumentViewTest, ReadDataBitAligned)
{
	EXPECT_EQ(view->view_length(), 14);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 4), 20),
		std::vector<unsigned char>({ 0x9A, 0xBC, 0xDE, 0xFF, 0xED, 0xC0, 0x12, 0x34, 0x56, 0x71, 0x23, 0x45, 0x67 }));
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 4), 1),
		std::vector<unsigned char>({ 0x9A }));
	
	EXPECT_EQ(
		view->read_data(BitOffset(5, 4), 2),
		std::vector<unsigned char>({ 0xC0, 0x12 }));
	
	EXPECT_EQ(
		view->read_data(BitOffset(10, 4), 20),
		std::vector<unsigned char>({ 0x23, 0x45, 0x67 }));
}

TEST_F(LinearVirtualDocumentViewTest, ReadBits)
{
	EXPECT_EQ(
		view->read_bits(BitOffset(0, 0), 12),
		std::vector<bool>({
			1, 0, 0, 0, 1, 0, 0, 1,
			1, 0, 1, 0,
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(4, 0), 32),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 0,
			1, 1, 0, 1, 1, 1, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 1, 0, 0, 0, 1, 1,
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(12, 0), 32),
		std::vector<bool>({
			0, 1, 0, 1, 0, 1, 1, 0,
			0, 1, 1, 1, 1, 0, 0, 0,
		}));
}

TEST_F(LinearVirtualDocumentViewTest, ReadBitsBitAligned)
{
	EXPECT_EQ(
		view->read_bits(BitOffset(0, 4), 8),
		std::vector<bool>({
			1, 0, 0, 1,
			1, 0, 1, 0,
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(4, 4), 28),
		std::vector<bool>({
			            1, 1, 1, 0,
			1, 1, 0, 1, 1, 1, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 1, 0, 0, 0, 1, 1,
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(12, 4), 32),
		std::vector<bool>({
			            0, 1, 1, 0,
			0, 1, 1, 1, 1, 0, 0, 0,
		}));
}

TEST_F(LinearVirtualDocumentViewTest, ViewToRealOffset)
{
	EXPECT_EQ(view->view_offset_to_real_offset(BitOffset(0, 0)), BitOffset(8, 0));
	EXPECT_EQ(view->view_offset_to_real_offset(BitOffset(5, 7)), BitOffset(13, 7));
	EXPECT_EQ(view->view_offset_to_real_offset(BitOffset(6, 0)), BitOffset(0, 0));
	EXPECT_EQ(view->view_offset_to_real_offset(BitOffset(10, 0)), BitOffset(14, 0));
}

TEST_F(LinearVirtualDocumentViewTest, ViewToVirtOffset)
{
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(0, 0)), BitOffset(0x100, 0));
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(5, 7)), BitOffset(0x105, 7));
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(6, 0)), BitOffset(0x200, 0));
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(10, 0)), BitOffset(0x300, 0));
}

TEST_F(LinearVirtualDocumentViewTest, OverwriteDataUnmapped)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->overwrite_data(4, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({}));
}

TEST_F(LinearVirtualDocumentViewTest, OverwriteDataInSegment)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->overwrite_data(10, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_OVERWRITE(2, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 8),
		std::vector<unsigned char>({ 0x89, 0xAB, 0x88, 0x77, 0x66, 0x55, 0x01, 0x23 }));
}

TEST_F(LinearVirtualDocumentViewTest, OverwriteDataSpanningSegments)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->overwrite_data(11, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_OVERWRITE(3, 3)",
		"DATA_OVERWRITE(10, 1)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 12),
		std::vector<unsigned char>({ 0x89, 0xAB, 0xCD, 0x88, 0x77, 0x66, 0x01, 0x23, 0x45, 0x67, 0x55, 0x34, }));
}

TEST_F(LinearVirtualDocumentViewTest, OverwriteDataEncompassingSegments)
{
	const unsigned char data[] = { 0xBB, 0xBB, 0x98, 0xBA, 0xCD, 0xEF, 0xFE, 0xDC, 0x12, 0x34, 0x56, 0x99, 0xAA, 0xAA };
	document->overwrite_data(6, data, 14);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_OVERWRITE(0, 6)",
		"DATA_OVERWRITE(10, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 20),
		std::vector<unsigned char>({ 0x98, 0xBA, 0xCD, 0xEF, 0xFE, 0xDC, 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x99 }));
}

TEST_F(LinearVirtualDocumentViewTest, EraseDataBetweenSegments)
{
	document->erase_data(4, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 14);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 20),
		std::vector<unsigned char>({ 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78 }));
}

TEST_F(LinearVirtualDocumentViewTest, EraseDataInSegment)
{
	document->erase_data(0, 2);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(6, 2)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 20),
		std::vector<unsigned char>({ 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78 }));
}

TEST_F(LinearVirtualDocumentViewTest, UnmapBytes)
{
	document->clear_virt_mapping_v(0x100, 2);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(0, 14)",
		"DATA_INSERT(0, 12)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 20),
		std::vector<unsigned char>({ 0xCD, 0xEF, 0xFE, 0xDC, 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78 }));
}

TEST_F(LinearVirtualDocumentViewTest, MapBytes)
{
	document->set_virt_mapping(4, 0x120, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(0, 14)",
		"DATA_INSERT(0, 18)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 18);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 20),
		std::vector<unsigned char>({ 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xAA, 0xAA, 0xAA, 0xAA, 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78 }));
}
