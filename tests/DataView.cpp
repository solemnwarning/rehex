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

class DataViewTest: public ::testing::Test
{
	protected:
		SharedDocumentPointer document;
		
		std::vector<std::string> events;
		
		DataViewTest():
			document(SharedDocumentPointer::make()) {}
		
		void setup_view(DataView *view)
		{
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

class FlatDocumentViewTest: public DataViewTest
{
	protected:
		std::unique_ptr<FlatDocumentView> view;
		
		FlatDocumentViewTest()
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
			
			view.reset(new FlatDocumentView(document));
			setup_view(view.get());
		}
};

TEST_F(FlatDocumentViewTest, ReadData)
{
	EXPECT_EQ(view->view_length(), 22);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x01, 0x23, 0x45, 0x67,
			0xAA, 0xAA, 0xAA, 0xAA,
			0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
			0x12, 0x34, 0x56, 0x78,
			0xAA, 0xAA, 0xAA, 0xAA,
		}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(4, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0xAA, 0xAA,
			0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
			0x12, 0x34, 0x56, 0x78,
			0xAA, 0xAA, 0xAA, 0xAA,
		}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(8, 0), 6),
		std::vector<unsigned char>({
			0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
		}));
}

TEST_F(FlatDocumentViewTest, ReadDataBitAligned)
{
	EXPECT_EQ(view->view_length(), 22);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 4), 20),
		std::vector<unsigned char>({
			0x12, 0x34, 0x56, 0x7A, 0xAA, 0xAA,
			0xAA, 0xA8, 0x9A, 0xBC, 0xDE, 0xFF,
			0xED, 0xC1, 0x23, 0x45, 0x67, 0x8A,
			0xAA, 0xAA,
		}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(4, 4), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0xAA, 0xA8, 0x9A, 0xBC,
			0xDE, 0xFF, 0xED, 0xC1, 0x23, 0x45,
			0x67, 0x8A, 0xAA, 0xAA, 0xAA,
		}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(8, 4), 6),
		std::vector<unsigned char>({
			0x9A, 0xBC, 0xDE, 0xFF, 0xED, 0xC1
		}));
}

TEST_F(FlatDocumentViewTest, ReadBits)
{
	EXPECT_EQ(
		view->read_bits(BitOffset(0, 0), 12),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 1, 0,
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(8, 0), 32),
		std::vector<bool>({
			1, 0, 0, 0, 1, 0, 0, 1,
			1, 0, 1, 0, 1, 0, 1, 1,
			1, 1, 0, 0, 1, 1, 0, 1,
			1, 1, 1, 0, 1, 1, 1, 1,
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(18, 0), 32),
		std::vector<bool>({
			1, 0, 1, 0, 1, 0, 1, 0,
			1, 0, 1, 0, 1, 0, 1, 0,
			1, 0, 1, 0, 1, 0, 1, 0,
			1, 0, 1, 0, 1, 0, 1, 0,
		}));
}

TEST_F(FlatDocumentViewTest, ReadBitsBitAligned)
{
	EXPECT_EQ(
		view->read_bits(BitOffset(0, 4), 8),
		std::vector<bool>({
			0, 0, 0, 1,
			0, 0, 1, 0,
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(10, 4), 28),
		std::vector<bool>({
			            1, 1, 0, 1,
			1, 1, 1, 0, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 0,
			1, 1, 0, 1, 1, 1, 0, 0,
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(16, 4), 64),
		std::vector<bool>({
			            0, 1, 1, 0,
			0, 1, 1, 1, 1, 0, 0, 0,
			1, 0, 1, 0, 1, 0, 1, 0,
			1, 0, 1, 0, 1, 0, 1, 0,
			1, 0, 1, 0, 1, 0, 1, 0,
			1, 0, 1, 0, 1, 0, 1, 0,
		}));
}

TEST_F(FlatDocumentViewTest, OverwriteData)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->overwrite_data(10, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_OVERWRITE(10, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 22);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x01, 0x23, 0x45, 0x67,
			0xAA, 0xAA, 0xAA, 0xAA,
			0x89, 0xAB, 0x88, 0x77, 0x66, 0x55,
			0x12, 0x34, 0x56, 0x78,
			0xAA, 0xAA, 0xAA, 0xAA,
		}));
}

TEST_F(FlatDocumentViewTest, InsertData)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->insert_data(10, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_INSERT(10, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 26);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x01, 0x23, 0x45, 0x67, 0xAA, 0xAA,
			0xAA, 0xAA, 0x89, 0xAB, 0x88, 0x77,
			0x66, 0x55, 0xCD, 0xEF, 0xFE, 0xDC,
			0x12, 0x34, 0x56, 0x78, 0xAA, 0xAA,
			0xAA, 0xAA,
		}));
}

TEST_F(FlatDocumentViewTest, EraseData)
{
	document->erase_data(10, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(10, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 18);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x01, 0x23, 0x45, 0x67, 0xAA, 0xAA,
			0xAA, 0xAA, 0x89, 0xAB, 0x12, 0x34,
			0x56, 0x78, 0xAA, 0xAA, 0xAA, 0xAA,
		}));
}

TEST_F(FlatDocumentViewTest, ViewToRealOffset)
{
	EXPECT_EQ(view->view_offset_to_real_offset(BitOffset(0, 0)), BitOffset(0, 0));
	EXPECT_EQ(view->view_offset_to_real_offset(BitOffset(5, 7)), BitOffset(5, 7));
	EXPECT_EQ(view->view_offset_to_real_offset(BitOffset(6, 0)), BitOffset(6, 0));
	EXPECT_EQ(view->view_offset_to_real_offset(BitOffset(10, 0)), BitOffset(10, 0));
}

TEST_F(FlatDocumentViewTest, RealToViewOffset)
{
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(0, 0)), BitOffset(0, 0));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(5, 7)), BitOffset(5, 7));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(6, 0)), BitOffset(6, 0));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(10, 0)), BitOffset(10, 0));
}

TEST_F(FlatDocumentViewTest, ViewToVirtOffset)
{
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(0, 0)), BitOffset(0, 0));
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(5, 7)), BitOffset(5, 7));
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(6, 0)), BitOffset(6, 0));
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(10, 0)), BitOffset(10, 0));
}

TEST_F(FlatDocumentViewTest, VirtToViewOffset)
{
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0, 0)), BitOffset(0, 0));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(5, 7)), BitOffset(5, 7));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(6, 0)), BitOffset(6, 0));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(10, 0)), BitOffset(10, 0));
}

class FlatRangeViewTest: public DataViewTest
{
	protected:
		std::unique_ptr<FlatRangeView> view;
		
		FlatRangeViewTest()
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
			
			view.reset(new FlatRangeView(document, BitOffset(6, 0), 12));
			setup_view(view.get());
		}
};

TEST_F(FlatRangeViewTest, ReadData)
{
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0x89, 0xAB, 0xCD, 0xEF,
			0xFE, 0xDC, 0x12, 0x34, 0x56, 0x78,
		}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(4, 0), 64),
		std::vector<unsigned char>({
			0xCD, 0xEF, 0xFE, 0xDC, 0x12, 0x34,
			0x56, 0x78,
		}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(4, 0), 4),
		std::vector<unsigned char>({
			0xCD, 0xEF, 0xFE, 0xDC,
		}));
}

TEST_F(FlatRangeViewTest, ReadDataBitAligned)
{
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 4), 64),
		std::vector<unsigned char>({
			0xAA, 0xA8, 0x9A, 0xBC, 0xDE, 0xFF,
			0xED, 0xC1, 0x23, 0x45, 0x67,
		}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(4, 4), 64),
		std::vector<unsigned char>({
			0xDE, 0xFF, 0xED, 0xC1, 0x23, 0x45, 0x67,
		}));
	
	EXPECT_EQ(
		view->read_data(BitOffset(4, 4), 4),
		std::vector<unsigned char>({
			0xDE, 0xFF, 0xED, 0xC1,
		}));
}

TEST_F(FlatRangeViewTest, OverwriteDataInsideRange)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->overwrite_data(8, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_OVERWRITE(2, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0x88, 0x77, 0x66, 0x55,
			0xFE, 0xDC, 0x12, 0x34, 0x56, 0x78,
		}));
}

TEST_F(FlatRangeViewTest, OverwriteDataEncompassingRange)
{
	const unsigned char data[] = { 
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF,
		0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55,
	};
	
	document->overwrite_data(0, data, 20);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_OVERWRITE(0, 12)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD,
			0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77,
		}));
}

TEST_F(FlatRangeViewTest, OverwriteDataBeforeRange)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->overwrite_data(2, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0x89, 0xAB, 0xCD, 0xEF,
			0xFE, 0xDC, 0x12, 0x34, 0x56, 0x78,
		}));
}

TEST_F(FlatRangeViewTest, OverwriteDataStraddlingStartOfRange)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->overwrite_data(4, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_OVERWRITE(0, 2)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x66, 0x55, 0x89, 0xAB, 0xCD, 0xEF,
			0xFE, 0xDC, 0x12, 0x34, 0x56, 0x78,
		}));
}

TEST_F(FlatRangeViewTest, OverwriteDataStraddlingEndOfRange)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->overwrite_data(15, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_OVERWRITE(9, 3)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0x89, 0xAB, 0xCD, 0xEF,
			0xFE, 0xDC, 0x12, 0x88, 0x77, 0x66,
		}));
}

TEST_F(FlatRangeViewTest, OverwriteDataAfterRange)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->overwrite_data(18, data, 2);
	
	EXPECT_EQ(events, std::vector<std::string>({}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0x89, 0xAB, 0xCD, 0xEF,
			0xFE, 0xDC, 0x12, 0x34, 0x56, 0x78,
		}));
}

TEST_F(FlatRangeViewTest, InsertDataBeforeRange)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->insert_data(1, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_INSERT(0, 4)",
		"DATA_ERASE(12, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x45, 0x67, 0xAA, 0xAA,
			0xAA, 0xAA, 0x89, 0xAB, 0xCD, 0xEF,
			0xFE, 0xDC,
		}));
}

TEST_F(FlatRangeViewTest, InsertDataInRange)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->insert_data(8, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_INSERT(2, 4)",
		"DATA_ERASE(12, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0x88, 0x77, 0x66, 0x55,
			0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
		}));
}

TEST_F(FlatRangeViewTest, InsertDataAfterRange)
{
	const unsigned char data[] = { 0x88, 0x77, 0x66, 0x55 };
	document->insert_data(18, data, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({ }));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0x89, 0xAB, 0xCD, 0xEF,
			0xFE, 0xDC, 0x12, 0x34, 0x56, 0x78,
		}));
}

TEST_F(FlatRangeViewTest, EraseDataBeforeRange)
{
	document->erase_data(2, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(0, 4)",
		"DATA_INSERT(8, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xCD, 0xEF,
			0xFE, 0xDC, 0x12, 0x34, 0x56, 0x78,
			0xAA, 0xAA, 0xAA, 0xAA,
		}));
}

TEST_F(FlatRangeViewTest, EraseDataInRange)
{
	document->erase_data(10, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(4, 4)",
		"DATA_INSERT(8, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0x89, 0xAB,
			0x12, 0x34, 0x56, 0x78,
			0xAA, 0xAA, 0xAA, 0xAA,
		}));
}

TEST_F(FlatRangeViewTest, EraseDataAfterRange)
{
	document->erase_data(18, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({ }));
	
	EXPECT_EQ(view->view_length(), 12);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0xAA, 0xAA, 0x89, 0xAB, 0xCD, 0xEF,
			0xFE, 0xDC, 0x12, 0x34, 0x56, 0x78,
		}));
}

TEST_F(FlatRangeViewTest, ReadBits)
{
	EXPECT_EQ(
		view->read_bits(BitOffset(0, 0), 48),
		std::vector<bool>({
			1, 0, 1, 0, 1, 0, 1, 0, /* 0xAA */
			1, 0, 1, 0, 1, 0, 1, 0, /* 0xAA */
			1, 0, 0, 0, 1, 0, 0, 1, /* 0x89 */
			1, 0, 1, 0, 1, 0, 1, 1, /* 0xAB */
			1, 1, 0, 0, 1, 1, 0, 1, /* 0xCD */
			1, 1, 1, 0, 1, 1, 1, 1, /* 0xEF */
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(10, 0), 24),
		std::vector<bool>({
			0, 1, 0, 1, 0, 1, 1, 0, /* 0x56  */
			0, 1, 1, 1, 1, 0, 0, 0, /* 0x78 */
		}));
}

TEST_F(FlatRangeViewTest, ReadBitsBitAligned)
{
	EXPECT_EQ(
		view->read_bits(BitOffset(2, 4), 16),
		std::vector<bool>({
			1, 0, 0, 1, 1, 0, 1, 0, /* 0x8A */
			1, 0, 1, 1, 1, 1, 0, 0, /* 0xBC */
		}));
	
	EXPECT_EQ(
		view->read_bits(BitOffset(10, 4), 24),
		std::vector<bool>({
			            0, 1, 1, 0, /* 0xX6  */
			0, 1, 1, 1, 1, 0, 0, 0, /* 0x78 */
		}));
}

TEST_F(FlatRangeViewTest, RealToViewOffset)
{
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(0, 0)), BitOffset::INVALID);
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(5, 7)), BitOffset::INVALID);
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(6, 0)), BitOffset(0, 0));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(6, 4)), BitOffset(0, 4));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(10, 0)), BitOffset(4, 0));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(17, 7)), BitOffset(11, 7));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(18, 0)), BitOffset::INVALID);
}

TEST_F(FlatRangeViewTest, VirtToViewOffset)
{
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0, 0)), BitOffset::INVALID);
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(5, 7)), BitOffset::INVALID);
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(6, 0)), BitOffset(0, 0));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(6, 4)), BitOffset(0, 4));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(10, 0)), BitOffset(4, 0));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(17, 7)), BitOffset(11, 7));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(18, 0)), BitOffset::INVALID);
}

class FlatDocumentViewEmptyTest: public DataViewTest
{
	protected:
		std::unique_ptr<FlatRangeView> view;
		
		FlatDocumentViewEmptyTest()
		{
			view.reset(new FlatRangeView(document, BitOffset(16, 0), 10));
			setup_view(view.get());
		}
};

TEST_F(FlatDocumentViewEmptyTest, Sequence)
{
	/* Insert data to the base of our range. */
	
	const unsigned char DATA1[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
	
	document->insert_data(0, DATA1, 8);
	document->insert_data(8, DATA1, 8);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_MODIFY_END()",
		"DATA_MODIFY_BEGIN()",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 0);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({}));
	
	events.clear();
	
	/* Insert some data at the start of the range. */
	
	const unsigned char DATA2[] = { 0x08, 0x09, 0x0A, 0x0B };
	
	document->insert_data(16, DATA2, 4);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_INSERT(0, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 4);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x08, 0x09, 0x0A, 0x0B,
		}));
	
	events.clear();
	
	/* Insert some more data earlier in the file. */
	
	document->insert_data(8, DATA2, 2);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_INSERT(0, 2)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 6);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
		}));
	
	events.clear();
	
	/* Insert some data in the middle of the range, filling it and beyond. */
	
	document->insert_data(20, DATA1, 8);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_INSERT(4, 6)",
		"DATA_ERASE(10, 2)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 10);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		}));
	
	events.clear();
	
	/* Delete some data from the middle of the range. */
	
	document->erase_data(20, 2);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(4, 2)",
		"DATA_INSERT(8, 2)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 10);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x06, 0x07, 0x08, 0x09, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		}));
	
	events.clear();
	
	/* Delete all data from the middle of the range. */
	
	document->erase_data(20, 8);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(4, 6)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 4);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x06, 0x07, 0x08, 0x09,
		}));
	
	events.clear();
	
	/* Delete data from before the range to the end of the file. */
	
	document->erase_data(14, 6);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(0, 4)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 0);
	
	EXPECT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({ }));
	
	events.clear();
}

class FlatDocumentViewEmptyBitAlignedTest: public DataViewTest
{
	protected:
		std::unique_ptr<FlatRangeView> view;
		
		FlatDocumentViewEmptyBitAlignedTest()
		{
			view.reset(new FlatRangeView(document, BitOffset(8, 4), 8));
			setup_view(view.get());
		}
};

TEST_F(FlatDocumentViewEmptyBitAlignedTest, InsertData)
{
	const unsigned char DATA1[] = { 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18 };
	
	/* Insert data up to the BYTE offset where our range starts... */
	
	document->insert_data(0, DATA1, 8);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 0);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({}));
	
	events.clear();
	
	/* Insert one more byte, resulting in 4 bits (zero bytes) in range... */
	
	document->insert_data(8, DATA1, 1);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 0);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({}));
	
	events.clear();
	
	/* And one more byte - first full byte in the range... */
	
	document->insert_data(9, (DATA1 + 1), 1);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_INSERT(0, 1)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 1);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x1B,
		}));
	
	events.clear();
	
	/* Fill in all but the last byte of the range... */
	
	document->insert_data(10, DATA1, 6);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_INSERT(1, 6)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 7);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x1B, 0x2A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F,
		}));
	
	events.clear();
	
	/* Fill in the last byte of the range... */
	
	document->insert_data(16, (DATA1 + 6), 1);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_INSERT(7, 1)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 8);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x1B, 0x2A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60,
		}));
	
	events.clear();
	
	/* Write some data past the end of the range... */
	
	document->insert_data(17, DATA1, 8);
	
	EXPECT_EQ(events, std::vector<std::string>({ }));
	
	EXPECT_EQ(view->view_length(), 8);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x1B, 0x2A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60,
		}));
	
	events.clear();
}

TEST_F(FlatDocumentViewEmptyBitAlignedTest, EraseData)
{
	const unsigned char DATA1[] = { 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18 };
	
	/* Pre-fill file with data. */
	
	document->insert_data(0,  DATA1, 8);
	document->insert_data(8,  DATA1, 8);
	document->insert_data(16, DATA1, 8);
	
	events.clear();
	
	EXPECT_EQ(view->view_length(), 8);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x8A,
		}));
	
	/* Erase data from beyond the end of the range. */
	
	document->erase_data(17, 7);
	
	EXPECT_EQ(events, std::vector<std::string>({ }));
	
	EXPECT_EQ(view->view_length(), 8);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x8A,
		}));
	
	events.clear();
	
	/* Erase last byte in the range. */
	
	document->erase_data(16, 1);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(7, 1)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 7);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71,
		}));
	
	events.clear();
	
	/* Erase everything past the first byte in the range. */
	
	document->erase_data(10, 6);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(1, 6)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 1);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({
			0x1B,
		}));
	
	events.clear();
	
	/* Erase the first byte in the range. */
	
	document->erase_data(9, 1);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_ERASE(0, 1)",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 0);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({ }));
	
	events.clear();
	
	/* Erase the last byte before the range */
	
	document->erase_data(8, 1);
	
	EXPECT_EQ(events, std::vector<std::string>({
		"DATA_MODIFY_BEGIN()",
		"DATA_MODIFY_END()",
	}));
	
	EXPECT_EQ(view->view_length(), 0);
	
	ASSERT_EQ(
		view->read_data(BitOffset(0, 0), 64),
		std::vector<unsigned char>({ }));
	
	events.clear();
}

class LinearVirtualDocumentViewTest: public DataViewTest
{
	protected:
		std::unique_ptr<LinearVirtualDocumentView> view;
		
		LinearVirtualDocumentViewTest()
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
			setup_view(view.get());
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

TEST_F(LinearVirtualDocumentViewTest, RealToViewOffset)
{
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(0, 0)), BitOffset(6, 0));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(3, 7)), BitOffset(9, 7));
	
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(4, 0)), BitOffset::INVALID);
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(7, 7)), BitOffset::INVALID);
	
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(8, 0)), BitOffset(0, 0));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(13, 7)), BitOffset(5, 7));
	
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(14, 0)), BitOffset(10, 0));
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(17, 7)), BitOffset(13, 7));
	
	EXPECT_EQ(view->real_offset_to_view_offset(BitOffset(20, 0)), BitOffset::INVALID);
}

TEST_F(LinearVirtualDocumentViewTest, ViewToVirtOffset)
{
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(0, 0)), BitOffset(0x100, 0));
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(5, 7)), BitOffset(0x105, 7));
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(6, 0)), BitOffset(0x200, 0));
	EXPECT_EQ(view->view_offset_to_virt_offset(BitOffset(10, 0)), BitOffset(0x300, 0));
}

TEST_F(LinearVirtualDocumentViewTest, VirtToViewOffset)
{
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x99, 0)), BitOffset::INVALID);
	
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x100, 0)), BitOffset(0, 0));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x105, 7)), BitOffset(5, 7));
	
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x106, 0)), BitOffset::INVALID);
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x199, 7)), BitOffset::INVALID);
	
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x200, 0)), BitOffset(6, 0));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x203, 7)), BitOffset(9, 7));
	
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x204, 0)), BitOffset::INVALID);
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x299, 7)), BitOffset::INVALID);
	
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x300, 0)), BitOffset(10, 0));
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x303, 7)), BitOffset(13, 7));
	
	EXPECT_EQ(view->virt_offset_to_view_offset(BitOffset(0x304, 0)), BitOffset::INVALID);
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
