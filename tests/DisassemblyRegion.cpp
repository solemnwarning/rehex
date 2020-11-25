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
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, CS_ARCH_X86, CS_MODE_64));

	{	
		const std::vector<DisassemblyRegion::InstructionRange> &ranges = region->get_processed();
		EXPECT_EQ(ranges.size(), 0U);
	}
	
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	{	
		const std::vector<DisassemblyRegion::InstructionRange> &ranges = region->get_processed();
		ASSERT_EQ(ranges.size(), 1U);
		
		EXPECT_EQ(ranges[0].offset, 0x46F0);
		EXPECT_EQ(ranges[0].length, 10244);
	}
	
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
		
		EXPECT_EQ(ranges[0].offset, 0x46F0);
		EXPECT_EQ(ranges[0].length, (0x6EF4 - 0x46F0));
		
		EXPECT_EQ(ranges[1].offset, 0x6EF4);
		EXPECT_EQ(ranges[1].length, (0x96F5 - 0x6EF4));
		
		EXPECT_EQ(ranges[2].offset, 0x96F5);
		EXPECT_EQ(ranges[2].length, (0xBEF7 - 0x96F5));
		
		EXPECT_EQ(ranges[3].offset, 0xBEF7);
		EXPECT_EQ(ranges[3].length, (0xE6FA - 0xBEF7));
		
		EXPECT_EQ(ranges[4].offset, 0xE6FA);
		EXPECT_EQ(ranges[4].length, (0x10EFA - 0xE6FA));
		
		EXPECT_EQ(ranges[5].offset, 0x10EFA);
		EXPECT_EQ(ranges[5].length, (0x136FA - 0x10EFA));
		
		EXPECT_EQ(ranges[6].offset, 0x136FA);
		EXPECT_EQ(ranges[6].length, (0x15EFA - 0x136FA));
		
		EXPECT_EQ(ranges[7].offset, 0x15EFA);
		EXPECT_EQ(ranges[7].length, (0x16CAE - 0x15EFA));
	}
}
