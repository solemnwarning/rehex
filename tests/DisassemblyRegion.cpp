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
#include <memory>

#include "../src/DisassemblyRegion.hpp"
#include "../src/document.hpp"
#include "../src/DocumentCtrl.hpp"
#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

TEST(DisassemblyRegion, ProcessFile)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, CS_ARCH_X86, CS_MODE_64));
	
	/* Ensure no data is initially processed. */
	
	{
		const std::vector<DisassemblyRegion::InstructionRange> &ranges = region->get_processed();
		EXPECT_EQ(ranges.size(), 0U);
		
		EXPECT_EQ(region->processed_by_offset(0x46F0), ranges.end());
		EXPECT_EQ(region->processed_by_line(0), ranges.end());
		
		EXPECT_EQ(region->unprocessed_offset(), 0x46F0);
		EXPECT_EQ(region->unprocessed_bytes(), 0x125BE /* 75,198 bytes */);
		EXPECT_EQ(region->processed_lines(), 0);
	}
	
	/* Ensure calling check() once processes one InstructionRange. */
	
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	{
		const std::vector<DisassemblyRegion::InstructionRange> &ranges = region->get_processed();
		ASSERT_EQ(ranges.size(), 1U);
		
		EXPECT_EQ(ranges[0].offset, 0x46F0);
		EXPECT_EQ(ranges[0].length, (0x6EF4 - 0x46F0) /* 10,244 bytes */);
		EXPECT_EQ(ranges[0].rel_y_offset, 0);
		EXPECT_EQ(ranges[0].y_lines, 2237);
		
		EXPECT_EQ(region->processed_by_offset(0x46F0),  std::next(ranges.begin(), 0));
		EXPECT_EQ(region->processed_by_offset(0x6EF3),  std::next(ranges.begin(), 0));
		EXPECT_EQ(region->processed_by_line(0),         std::next(ranges.begin(), 0));
		EXPECT_EQ(region->processed_by_line(2236),      std::next(ranges.begin(), 0));
		
		EXPECT_EQ(region->processed_by_offset(0x6EF4),  ranges.end());
		EXPECT_EQ(region->processed_by_line(2237),      ranges.end());
		
		EXPECT_EQ(region->unprocessed_offset(), 0x6EF4);
		EXPECT_EQ(region->unprocessed_bytes(), 0xFDBA /* 64,954 bytes */);
		EXPECT_EQ(region->processed_lines(), 2237);
	}
	
	/* Ensure calling check() more processes the rest of the file. */
	
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_FALSE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	{
		const std::vector<DisassemblyRegion::InstructionRange> &ranges = region->get_processed();
		ASSERT_EQ(ranges.size(), 8U);
		
		EXPECT_EQ(region->processed_by_offset(0x46EF),  ranges.end());
		
		EXPECT_EQ(ranges[0].offset, 0x46F0);
		EXPECT_EQ(ranges[0].length, (0x6EF4 - 0x46F0) /* 10,244 bytes */);
		EXPECT_EQ(ranges[0].rel_y_offset, 0);
		EXPECT_EQ(ranges[0].y_lines, 2237);
		
		EXPECT_EQ(region->processed_by_offset(0x46F0),  std::next(ranges.begin(), 0));
		EXPECT_EQ(region->processed_by_offset(0x6EF3),  std::next(ranges.begin(), 0));
		EXPECT_EQ(region->processed_by_line(0),         std::next(ranges.begin(), 0));
		EXPECT_EQ(region->processed_by_line(2236),      std::next(ranges.begin(), 0));
		
		EXPECT_EQ(ranges[1].offset, 0x6EF4);
		EXPECT_EQ(ranges[1].length, (0x96F5 - 0x6EF4) /* 10,241 bytes */);
		EXPECT_EQ(ranges[1].rel_y_offset, 2237);
		EXPECT_EQ(ranges[1].y_lines, 2453);
		
		EXPECT_EQ(region->processed_by_offset(0x6EF4),  std::next(ranges.begin(), 1));
		EXPECT_EQ(region->processed_by_offset(0x96F4),  std::next(ranges.begin(), 1));
		EXPECT_EQ(region->processed_by_line(2237),      std::next(ranges.begin(), 1));
		EXPECT_EQ(region->processed_by_line(4689),      std::next(ranges.begin(), 1));
		
		EXPECT_EQ(ranges[2].offset, 0x96F5);
		EXPECT_EQ(ranges[2].length, (0xBEF7 - 0x96F5) /* 10,242 bytes */);
		EXPECT_EQ(ranges[2].rel_y_offset, 4690);
		EXPECT_EQ(ranges[2].y_lines, 2457);
		
		EXPECT_EQ(ranges[3].offset, 0xBEF7);
		EXPECT_EQ(ranges[3].length, (0xE6FA - 0xBEF7) /* 10,243 bytes */);
		EXPECT_EQ(ranges[3].rel_y_offset, 7147);
		EXPECT_EQ(ranges[3].y_lines, 2751);
		
		EXPECT_EQ(ranges[4].offset, 0xE6FA);
		EXPECT_EQ(ranges[4].length, (0x10EFA - 0xE6FA) /* 10,240 bytes */);
		EXPECT_EQ(ranges[4].rel_y_offset, 9898);
		EXPECT_EQ(ranges[4].y_lines, 2783);
		
		EXPECT_EQ(ranges[5].offset, 0x10EFA);
		EXPECT_EQ(ranges[5].length, (0x136FA - 0x10EFA) /* 10,240 bytes */);
		EXPECT_EQ(ranges[5].rel_y_offset, 12681);
		EXPECT_EQ(ranges[5].y_lines, 2547);
		
		EXPECT_EQ(ranges[6].offset, 0x136FA);
		EXPECT_EQ(ranges[6].length, (0x15EFA - 0x136FA) /* 10,240 bytes */);
		EXPECT_EQ(ranges[6].rel_y_offset, 15228);
		EXPECT_EQ(ranges[6].y_lines, 2581);
		
		EXPECT_EQ(ranges[7].offset, 0x15EFA);
		EXPECT_EQ(ranges[7].length, (0x16CAE - 0x15EFA) /* 3,508 bytes */);
		EXPECT_EQ(ranges[7].rel_y_offset, 17809);
		EXPECT_EQ(ranges[7].y_lines, 1031);
		
		EXPECT_EQ(region->processed_by_offset(0x15EFA),  std::next(ranges.begin(), 7));
		EXPECT_EQ(region->processed_by_offset(0x16CAD),  std::next(ranges.begin(), 7));
		EXPECT_EQ(region->processed_by_line(17809),      std::next(ranges.begin(), 7));
		EXPECT_EQ(region->processed_by_line(18839),      std::next(ranges.begin(), 7));
		
		EXPECT_EQ(region->processed_by_offset(0x16CAE),  ranges.end());
		EXPECT_EQ(region->processed_by_line(18840),      ranges.end());
		
		EXPECT_EQ(region->unprocessed_offset(), 0x16CAE);
		EXPECT_EQ(region->unprocessed_bytes(), 0);
		EXPECT_EQ(region->processed_lines(), 18840);
	}
}
