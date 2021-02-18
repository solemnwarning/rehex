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
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64));
	
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

TEST(DisassemblyRegion, InstructionByOffset)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64));
	
	/* Check the region is unprocessed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x46F0);
	
	{
		auto x = region->instruction_by_offset(0);
		EXPECT_EQ(x.second, x.first.end());
	}
	
	{
		auto x = region->instruction_by_offset(0x46F0);
		EXPECT_EQ(x.second, x.first.end());
	}
	
	{
		auto x = region->instruction_by_offset(0x16CAE);
		EXPECT_EQ(x.second, x.first.end());
	}
	
	region->check();
	region->check();
	region->check();
	region->check();
	
	/* Check the region is partially processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0xE6FA);
	
	{
		auto x = region->instruction_by_offset(0x46EF);
		EXPECT_EQ(x.second, x.first.end());
	}
	
	{
		auto x = region->instruction_by_offset(0x46F0);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x46F0);
		EXPECT_EQ(x.second->length, 5);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xE8, 0x8B, 0xF9, 0xFF, 0xFF}));
		EXPECT_EQ(x.second->disasm, "call    0x4080");
		EXPECT_EQ(x.second->rel_y_offset, 0);
	}
	
	{
		auto x = region->instruction_by_offset(0x46F4);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x46F0);
		EXPECT_EQ(x.second->length, 5);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xE8, 0x8B, 0xF9, 0xFF, 0xFF}));
		EXPECT_EQ(x.second->disasm, "call    0x4080");
		EXPECT_EQ(x.second->rel_y_offset, 0);
	}
	
	{
		auto x = region->instruction_by_offset(0x46F5);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x46F5);
		EXPECT_EQ(x.second->length, 5);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xE8, 0x86, 0xF9, 0xFF, 0xFF}));
		EXPECT_EQ(x.second->disasm, "call    0x4080");
		EXPECT_EQ(x.second->rel_y_offset, 1);
	}
	
	{
		auto x = region->instruction_by_offset(0x4730);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x4730);
		EXPECT_EQ(x.second->length, 2);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x41, 0x57}));
		EXPECT_EQ(x.second->disasm, "push    r15");
		EXPECT_EQ(x.second->rel_y_offset, 12);
	}
	
	{
		auto x = region->instruction_by_offset(0xE6F9);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0xE6F6);
		EXPECT_EQ(x.second->length, 4);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x48, 0x89, 0x55, 0x48}));
		EXPECT_EQ(x.second->disasm, "mov     qword ptr [rbp + 0x48], rdx");
		EXPECT_EQ(x.second->rel_y_offset, 9897);
	}
	
	{
		auto x = region->instruction_by_offset(0xE6FA);
		EXPECT_EQ(x.second, x.first.end());
	}
	
	region->check();
	region->check();
	region->check();
	region->check();
	
	/* Ensure region is fully processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x16CAE);
	
	{
		auto x = region->instruction_by_offset(0xE6FA);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0xE6FA);
		EXPECT_EQ(x.second->length, 4);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x48, 0x8B, 0x53, 0x08}));
		EXPECT_EQ(x.second->disasm, "mov     rdx, qword ptr [rbx + 8]");
		EXPECT_EQ(x.second->rel_y_offset, 9898);
	}
	
	{
		auto x = region->instruction_by_offset(0x16CAA);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x16CA9);
		EXPECT_EQ(x.second->length, 5);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xE9, 0x22, 0xD9, 0xFE, 0xFF}));
		EXPECT_EQ(x.second->disasm, "jmp     0x45d0");
		EXPECT_EQ(x.second->rel_y_offset, 18839);
	}
	
	{
		auto x = region->instruction_by_offset(0x16CAE);
		ASSERT_EQ(x.second, x.first.end());
	}
}

TEST(DisassemblyRegion, InstructionByLine)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64));
	
	/* Check the region is unprocessed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x46F0);
	
	{
		auto x = region->instruction_by_line(0);
		EXPECT_EQ(x.second, x.first.end());
	}
	
	region->check();
	region->check();
	region->check();
	region->check();
	
	/* Check the region is half-processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0xE6FA);
	
	{
		auto x = region->instruction_by_line(0);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x46F0);
		EXPECT_EQ(x.second->length, 5);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xE8, 0x8B, 0xF9, 0xFF, 0xFF}));
		EXPECT_EQ(x.second->disasm, "call    0x4080");
		EXPECT_EQ(x.second->rel_y_offset, 0);
	}
	
	{
		auto x = region->instruction_by_line(1);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x46F5);
		EXPECT_EQ(x.second->length, 5);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xE8, 0x86, 0xF9, 0xFF, 0xFF}));
		EXPECT_EQ(x.second->disasm, "call    0x4080");
		EXPECT_EQ(x.second->rel_y_offset, 1);
	}
	
	{
		auto x = region->instruction_by_line(12);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x4730);
		EXPECT_EQ(x.second->length, 2);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x41, 0x57}));
		EXPECT_EQ(x.second->disasm, "push    r15");
		EXPECT_EQ(x.second->rel_y_offset, 12);
	}
	
	{
		auto x = region->instruction_by_line(9897);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0xE6F6);
		EXPECT_EQ(x.second->length, 4);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x48, 0x89, 0x55, 0x48}));
		EXPECT_EQ(x.second->disasm, "mov     qword ptr [rbp + 0x48], rdx");
		EXPECT_EQ(x.second->rel_y_offset, 9897);
	}
	
	{
		auto x = region->instruction_by_offset(9898);
		EXPECT_EQ(x.second, x.first.end());
	}
	
	region->check();
	region->check();
	region->check();
	region->check();
	
	/* Ensure region is fully processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x16CAE);
	
	{
		auto x = region->instruction_by_line(9898);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0xE6FA);
		EXPECT_EQ(x.second->length, 4);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x48, 0x8B, 0x53, 0x08}));
		EXPECT_EQ(x.second->disasm, "mov     rdx, qword ptr [rbx + 8]");
		EXPECT_EQ(x.second->rel_y_offset, 9898);
	}
	
	{
		auto x = region->instruction_by_line(18839);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x16CA9);
		EXPECT_EQ(x.second->length, 5);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xE9, 0x22, 0xD9, 0xFE, 0xFF}));
		EXPECT_EQ(x.second->disasm, "jmp     0x45d0");
		EXPECT_EQ(x.second->rel_y_offset, 18839);
	}
	
	{
		auto x = region->instruction_by_line(18840);
		ASSERT_EQ(x.second, x.first.end());
	}
}

TEST(DisassemblyRegion, InstructionSpanningEndOfRegion)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 9, 0x46F0, CS_ARCH_X86, CS_MODE_64));
	
	region->check();
	region->check();
	
	{
		const std::vector<DisassemblyRegion::InstructionRange> &ranges = region->get_processed();
		ASSERT_EQ(ranges.size(), 1U);
		
		EXPECT_EQ(ranges[0].offset, 0x46F0);
		EXPECT_EQ(ranges[0].length, 9);
		EXPECT_EQ(ranges[0].rel_y_offset, 0);
		EXPECT_EQ(ranges[0].y_lines, 4);
	}
	
	{
		auto x = region->instruction_by_offset(0x46F0);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x46F0);
		EXPECT_EQ(x.second->length, 5);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xE8, 0x8B, 0xF9, 0xFF, 0xFF}));
		EXPECT_EQ(x.second->disasm, "call    0x4080");
		EXPECT_EQ(x.second->rel_y_offset, 0);
	}
	
	{
		auto x = region->instruction_by_offset(0x46F5);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x46F5);
		EXPECT_EQ(x.second->length, 1);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xE8}));
		EXPECT_EQ(x.second->disasm, ".byte   0xe8");
		EXPECT_EQ(x.second->rel_y_offset, 1);
	}
	
	{
		auto x = region->instruction_by_offset(0x46F6);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x46F6);
		EXPECT_EQ(x.second->length, 2);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x86, 0xF9}));
		EXPECT_EQ(x.second->disasm, "xchg    cl, bh");
		EXPECT_EQ(x.second->rel_y_offset, 2);
	}
	
	{
		auto x = region->instruction_by_offset(0x46F8);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x46F8);
		EXPECT_EQ(x.second->length, 1);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0xFF}));
		EXPECT_EQ(x.second->disasm, ".byte   0xff");
		EXPECT_EQ(x.second->rel_y_offset, 3);
	}
	
	{
		auto x = region->instruction_by_offset(0x49F9);
		ASSERT_EQ(x.second, x.first.end());
	}
	
}

TEST(DisassemblyRegion, InvalidInstructionAMD64)
{
	/* Prepare Document with test data. */
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = {
		0x00, 0x01,  /* add     byte ptr [rcx], al */
		0x02, 0x03,  /* add     al, byte ptr [rbx] */
		0x04, 0x05,  /* add     al, 5 */
		0x06,
		0x07,
		0x08, 0x09,  /* or      byte ptr [rcx], cl */
		0x0A, 0x0B,  /* or      cl, byte ptr [rbx] */
		0x0C, 0x0D,  /* or      al, 0xd */
		0x0E,
	};
	
	doc->insert_data(0, DATA, sizeof(DATA));
	
	/* Create region covering our test data */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0, 15, 0, CS_ARCH_X86, CS_MODE_64));
	
	/* Check the region is unprocessed. */
	ASSERT_EQ(region->unprocessed_offset(), 0);
	
	/* Data is small, so should process in one go. */
	EXPECT_FALSE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	/* Check the region is fully. */
	EXPECT_EQ(region->unprocessed_offset(), 15);
	
	{
		auto x = region->instruction_by_offset(0x00);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x00);
		EXPECT_EQ(x.second->length, 2);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x00, 0x01}));
		EXPECT_EQ(x.second->disasm, "add     byte ptr [rcx], al");
	}
	
	{
		auto x = region->instruction_by_offset(0x04);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x04);
		EXPECT_EQ(x.second->length, 2);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x04, 0x05}));
		EXPECT_EQ(x.second->disasm, "add     al, 5");
	}
	
	{
		auto x = region->instruction_by_offset(0x06);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x06);
		EXPECT_EQ(x.second->length, 1);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x06}));
		EXPECT_EQ(x.second->disasm, ".byte   0x06");
	}
	
	{
		auto x = region->instruction_by_offset(0x07);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x07);
		EXPECT_EQ(x.second->length, 1);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x07}));
		EXPECT_EQ(x.second->disasm, ".byte   0x07");
	}
	
	{
		auto x = region->instruction_by_offset(0x08);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x08);
		EXPECT_EQ(x.second->length, 2);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x08, 0x09}));
		EXPECT_EQ(x.second->disasm, "or      byte ptr [rcx], cl");
	}
	
	{
		auto x = region->instruction_by_offset(0x0C);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x0C);
		EXPECT_EQ(x.second->length, 2);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x0C, 0x0D}));
		EXPECT_EQ(x.second->disasm, "or      al, 0xd");
	}
	
	{
		auto x = region->instruction_by_offset(0x0E);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x0E);
		EXPECT_EQ(x.second->length, 1);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x0E}));
		EXPECT_EQ(x.second->disasm, ".byte   0x0e");
	}
}

TEST(DisassemblyRegion, InvalidInstructionARM64)
{
	/* Prepare Document with test data. */
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = {
		0x04, 0x05, 0x06, 0x07,  /* .byte   0x04, 0x05, 0x06, 0x07 */
		0x08, 0x09, 0x0A, 0x0B,  /* add     w8, w8, w10, lsl #2 */
		0x0C, 0x0D, 0x0E, 0x0F,  /* .byte   0x0c, 0x0d, 0x0e, 0x0f */
		0x10, 0x11, 0x12, 0x13,  /* sbfiz   w16, w8, #0xe, #5 */
		0x14,                    /* .byte   0x14 */
		0x15,                    /* .byte   0x15 */
		
		0x00, 0x00, 0x00, 0x00,
	};
	
	doc->insert_data(0, DATA, sizeof(DATA));
	
	/* Create region covering our test data */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0, 18, 0, CS_ARCH_ARM64, (cs_mode)(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)));
	
	/* Check the region is unprocessed. */
	ASSERT_EQ(region->unprocessed_offset(), 0);
	
	/* Data is small, so should process in one go. */
	EXPECT_FALSE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	/* Check the region is fully. */
	EXPECT_EQ(region->unprocessed_offset(), 18);
	
	{
		auto x = region->instruction_by_offset(0x00);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x00);
		EXPECT_EQ(x.second->length, 4);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x04, 0x05, 0x06, 0x07}));
		EXPECT_EQ(x.second->disasm, ".byte   0x04, 0x05, 0x06, 0x07");
	}
	
	{
		auto x = region->instruction_by_offset(0x04);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x04);
		EXPECT_EQ(x.second->length, 4);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x08, 0x09, 0x0A, 0x0B}));
		EXPECT_EQ(x.second->disasm, "add     w8, w8, w10, lsl #2");
	}
	
	{
		auto x = region->instruction_by_offset(0x08);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x08);
		EXPECT_EQ(x.second->length, 4);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x0C, 0x0D, 0x0E, 0x0F}));
		EXPECT_EQ(x.second->disasm, ".byte   0x0c, 0x0d, 0x0e, 0x0f");
	}
	
	{
		auto x = region->instruction_by_offset(0x0C);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x0C);
		EXPECT_EQ(x.second->length, 4);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x10, 0x11, 0x12, 0x13}));
		EXPECT_EQ(x.second->disasm, "sbfiz   w16, w8, #0xe, #5");
	}
	
	{
		auto x = region->instruction_by_offset(0x10);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x10);
		EXPECT_EQ(x.second->length, 1);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x14}));
		EXPECT_EQ(x.second->disasm, ".byte   0x14");
	}
	
	{
		auto x = region->instruction_by_offset(0x11);
		
		ASSERT_NE(x.second, x.first.end());
		
		EXPECT_EQ(x.second->offset, 0x11);
		EXPECT_EQ(x.second->length, 1);
		EXPECT_EQ(x.second->data,   std::vector<unsigned char>({0x15}));
		EXPECT_EQ(x.second->disasm, ".byte   0x15");
	}
}

TEST(DisassemblyRegion, OverwriteDataBeforeRegion)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64));
	
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	/* Check the region is half-processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0xE6FA);
	
	ByteRangeSet expect_dirty;
	expect_dirty.set_range(0xE6FA, (0x125BE - (0xE6FA - 0x46F0)));
	
	ASSERT_EQ(region->get_dirty().get_ranges(), expect_dirty.get_ranges());
	
	char data[4] = { 0 };
	doc->overwrite_data(0x46EC, data, 4);
	
	EXPECT_EQ(region->unprocessed_offset(), 0xE6FA) << "Region not affected by data overwrite before d_offset";
	
	EXPECT_EQ(region->get_dirty().get_ranges(), expect_dirty.get_ranges()) << "Region not affected by data overwrite before d_offset";
}

TEST(DisassemblyRegion, OverwriteDataAtStart)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64));
	
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	/* Check the region is half-processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0xE6FA);
	
	char data[4] = { 0 };
	doc->overwrite_data(0x46EE, data, 4);
	
	EXPECT_EQ(region->unprocessed_offset(), 0x46F0) << "Processing reset by overwrite straddling d_offset";
	
	ByteRangeSet expect_dirty;
	expect_dirty.set_range(0x46F0, 0x125BE);
	
	EXPECT_EQ(region->get_dirty().get_ranges(), expect_dirty.get_ranges()) << "Processing reset by overwrite straddling d_offset";
}

TEST(DisassemblyRegion, OverwriteDataInRegion)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64));
	
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	/* Check the region is half-processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0xE6FA);
	
	char data[4] = { 0 };
	doc->overwrite_data(0xAAAA, data, 4);
	
	EXPECT_EQ(region->unprocessed_offset(), 0x96F5) << "Processing reset to InstructionRange where overwrite happened";
	
	ByteRangeSet expect_dirty;
	expect_dirty.set_range(0x96F5, (0x125BE - (0x96F5 - 0x46F0)));
	
	EXPECT_EQ(region->get_dirty().get_ranges(), expect_dirty.get_ranges()) << "Processing reset to InstructionRange where overwrite happened";
}

TEST(DisassemblyRegion, OverwriteDataAtEnd)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64));
	
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_FALSE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	/* Check the region is fully processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x16CAE);
	
	char data[4] = { 0 };
	doc->overwrite_data(0x16CAC, data, 4);
	
	EXPECT_EQ(region->unprocessed_offset(), 0x15EFA) << "Processing reset to InstructionRange where overwrite happened";
	
	ByteRangeSet expect_dirty;
	expect_dirty.set_range(0x15EFA, (0x125BE - (0x15EFA - 0x46F0)));
	
	EXPECT_EQ(region->get_dirty().get_ranges(), expect_dirty.get_ranges()) << "Processing reset to InstructionRange where overwrite happened";
}

TEST(DisassemblyRegion, OverwriteDataAfterRegion)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	std::unique_ptr<DisassemblyRegion> region(new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64));
	
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_TRUE(region->check() & DocumentCtrl::Region::PROCESSING);
	EXPECT_FALSE(region->check() & DocumentCtrl::Region::PROCESSING);
	
	/* Check the region is fully processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x16CAE);
	
	const ByteRangeSet EMPTY_SET;
	ASSERT_EQ(region->get_dirty().get_ranges(), EMPTY_SET.get_ranges());
	
	char data[4] = { 0 };
	doc->overwrite_data(0x16CAE, data, 4);
	
	EXPECT_EQ(region->unprocessed_offset(), 0x16CAE) << "Region not affected by overwriting data after it";
	
	EXPECT_EQ(region->get_dirty().get_ranges(), EMPTY_SET.get_ranges()) << "Region not affected by overwriting data after it";
}

TEST(DisassemblyRegion, CopyWholeInstructions)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	DisassemblyRegion* region = new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64);
	
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	
	/* Check the region is fully processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x16CAE);
	
	wxFrame frame(NULL, wxID_ANY, "REHex Tests");
	DocumentCtrl *doc_ctrl = new DocumentCtrl(&frame, doc);
	
	std::vector<DocumentCtrl::Region*> regions(&region, &region + 1);
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(0x7150, Document::CSTATE_SPECIAL);
	doc_ctrl->set_selection(0x7150, 22);
	
	wxDataObject *data_obj = region->OnCopy(*doc_ctrl);
	
	ASSERT_NE(data_obj, (wxDataObject*)(NULL));
	
	wxTextDataObject *tdo = dynamic_cast<wxTextDataObject*>(data_obj);
	ASSERT_NE(tdo, (wxTextDataObject*)(NULL));
	
	EXPECT_EQ(tdo->GetText(),
		"push    r12\n"
		"push    rbp\n"
		"mov     rbp, rsi\n"
		"mov     rsi, rdx\n"
		"push    rbx\n"
		"mov     ebx, edi\n"
		"mov     edi, 4\n"
		"call    0x14630");
	
	delete data_obj;
}

TEST(DisassemblyRegion, CopyInHexView)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	DisassemblyRegion* region = new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64);
	
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	
	/* Check the region is fully processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x16CAE);
	
	wxFrame frame(NULL, wxID_ANY, "REHex Tests");
	DocumentCtrl *doc_ctrl = new DocumentCtrl(&frame, doc);
	
	std::vector<DocumentCtrl::Region*> regions(&region, &region + 1);
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(0x7150, Document::CSTATE_HEX);
	doc_ctrl->set_selection(0x7150, 22);
	
	wxDataObject *data_obj = region->OnCopy(*doc_ctrl);
	
	EXPECT_EQ(data_obj, (wxDataObject*)(NULL));
}

TEST(DisassemblyRegion, CopyPartialInstructions)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	DisassemblyRegion* region = new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64);
	
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	
	/* Check the region is fully processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x16CAE);
	
	wxFrame frame(NULL, wxID_ANY, "REHex Tests");
	DocumentCtrl *doc_ctrl = new DocumentCtrl(&frame, doc);
	
	std::vector<DocumentCtrl::Region*> regions(&region, &region + 1);
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(0x7150, Document::CSTATE_SPECIAL);
	doc_ctrl->set_selection(0x7151, 20);
	
	wxDataObject *data_obj = region->OnCopy(*doc_ctrl);
	
	ASSERT_NE(data_obj, (wxDataObject*)(NULL));
	
	wxTextDataObject *tdo = dynamic_cast<wxTextDataObject*>(data_obj);
	ASSERT_NE(tdo, (wxTextDataObject*)(NULL));
	
	EXPECT_EQ(tdo->GetText(),
		"push    rbp\n"
		"mov     rbp, rsi\n"
		"mov     rsi, rdx\n"
		"push    rbx\n"
		"mov     ebx, edi\n"
		"mov     edi, 4");
	
	delete data_obj;
}

TEST(DisassemblyRegion, CopyPartialInstruction)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make("tests/ls.x86_64"));
	
	/* Create region covering the entire .text section */
	DisassemblyRegion* region = new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, CS_ARCH_X86, CS_MODE_64);
	
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	region->check();
	
	/* Check the region is fully processed. */
	ASSERT_EQ(region->unprocessed_offset(), 0x16CAE);
	
	wxFrame frame(NULL, wxID_ANY, "REHex Tests");
	DocumentCtrl *doc_ctrl = new DocumentCtrl(&frame, doc);
	
	std::vector<DocumentCtrl::Region*> regions(&region, &region + 1);
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(0x7150, Document::CSTATE_SPECIAL);
	doc_ctrl->set_selection(0x7153, 2);
	
	wxDataObject *data_obj = region->OnCopy(*doc_ctrl);
	
	EXPECT_EQ(data_obj, (wxDataObject*)(NULL));
}
