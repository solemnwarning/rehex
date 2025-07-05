/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "BufferTest.h"

#include "testutil.hpp"

TEST(Buffer, DefaultConstructor)
{
	REHex::Buffer b;
	
	ASSERT_EQ(b.blocks.size(), 1U) << "Constructor creates correct number of blocks";
	
	EXPECT_EQ(b.blocks[0].virt_offset, 0) << "Constructor creates block with correct offset";
	EXPECT_EQ(b.blocks[0].virt_length, 0) << "Constructor creates block with correct length";
	
	EXPECT_EQ(b.blocks[0].state, REHex::Buffer::Block::DIRTY) << "Constructor marks blocks as clean";
	
	EXPECT_TRUE(b.blocks[0].data.empty()) << "Constructor doesn't populate block data";
	
	EXPECT_EQ(b.length(), 0) << "Buffer::length() returns correct value";
}

TEST(Buffer, LoadConstructorNonEmptyFile)
{
	const std::vector<unsigned char> file_data = {
		0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
		0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
		0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
	};
	
	TempFile tmpfile(file_data.data(), file_data.size());
	
	REHex::Buffer b(tmpfile.tmpfile, 8);
	
	ASSERT_EQ(b.blocks.size(), 3U) << "Constructor creates correct number of blocks";
	
	EXPECT_EQ(b.blocks[0].virt_offset, 0)  << "Constructor creates block with correct offset";
	EXPECT_EQ(b.blocks[0].virt_length, 8)  << "Constructor creates block with correct length";
	EXPECT_EQ(b.blocks[1].virt_offset, 8)  << "Constructor creates block with correct offset";
	EXPECT_EQ(b.blocks[1].virt_length, 8)  << "Constructor creates block with correct length";
	EXPECT_EQ(b.blocks[2].virt_offset, 16) << "Constructor creates block with correct offset";
	EXPECT_EQ(b.blocks[2].virt_length, 7)  << "Constructor creates block with correct length";
	
	EXPECT_EQ(b.blocks[0].state, REHex::Buffer::Block::UNLOADED) << "Constructor marks blocks as unloaded";
	EXPECT_EQ(b.blocks[1].state, REHex::Buffer::Block::UNLOADED) << "Constructor marks blocks as unloaded";
	EXPECT_EQ(b.blocks[2].state, REHex::Buffer::Block::UNLOADED) << "Constructor marks blocks as unloaded";
	
	EXPECT_TRUE(b.blocks[0].data.empty()) << "Constructor doesn't populate block data";
	EXPECT_TRUE(b.blocks[1].data.empty()) << "Constructor doesn't populate block data";
	EXPECT_TRUE(b.blocks[2].data.empty()) << "Constructor doesn't populate block data";
	
	EXPECT_EQ(b.length(), 23) << "Buffer::length() returns correct value";
}

TEST(Buffer, LoadConstructorEmptyFile)
{
	TempFile tmpfile(NULL, 0);
	
	REHex::Buffer b(tmpfile.tmpfile, 8);
	
	ASSERT_EQ(b.blocks.size(), 1U) << "Constructor creates correct number of blocks";
	
	EXPECT_EQ(b.blocks[0].virt_offset, 0) << "Constructor creates block with correct offset";
	EXPECT_EQ(b.blocks[0].virt_length, 0) << "Constructor creates block with correct length";
	
	EXPECT_EQ(b.blocks[0].state, REHex::Buffer::Block::UNLOADED) << "Constructor marks blocks as unloaded";
	
	EXPECT_TRUE(b.blocks[0].data.empty()) << "Constructor doesn't populate block data";
	
	EXPECT_EQ(b.length(), 0) << "Buffer::length() returns correct value";
}

#define READ_DATA_PREPARE() \
	const std::vector<unsigned char> file_data = { \
		0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01, \
		0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8, \
		0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C, \
	}; \
	TempFile tmpfile(file_data.data(), file_data.size()); \
	\
	REHex::Buffer b(tmpfile.tmpfile, 8);

#define READ_DATA_UNLOADED(block_i) \
{ \
	EXPECT_EQ(b.blocks[block_i].state, REHex::Buffer::Block::UNLOADED) << "Unread block not loaded"; \
	EXPECT_TRUE(b.blocks[block_i].data.empty()) << "Unread block has no data buffer"; \
}

#define READ_DATA_CLEAN(block_i, len) \
{ \
	EXPECT_EQ(b.blocks[block_i].state, REHex::Buffer::Block::CLEAN) << "Read block loaded"; \
	EXPECT_TRUE(b.blocks[block_i].data.size() >= len) << "Read block has data buffer"; \
}

TEST(Buffer, ReadFirstBlock)
{
	READ_DATA_PREPARE();
	
	std::vector<unsigned char> got_data = b.read_data(0, 8);
	std::vector<unsigned char> expect_data(file_data.data(), file_data.data() + 8);
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
	
	READ_DATA_CLEAN(0, 8);
	READ_DATA_UNLOADED(1);
	READ_DATA_UNLOADED(2);
}

TEST(Buffer, ReadFirstBlockPartial)
{
	READ_DATA_PREPARE();
	
	std::vector<unsigned char> got_data = b.read_data(2, 5);
	std::vector<unsigned char> expect_data(file_data.data() + 2, file_data.data() + 2 + 5);
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
	
	READ_DATA_CLEAN(0, 8);
	READ_DATA_UNLOADED(1);
	READ_DATA_UNLOADED(2);
}

TEST(Buffer, ReadSecondBlock)
{
	READ_DATA_PREPARE();
	
	std::vector<unsigned char> got_data = b.read_data(8, 8);
	std::vector<unsigned char> expect_data(file_data.data() + 8, file_data.data() + 8 + 8);
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
	
	READ_DATA_UNLOADED(0);
	READ_DATA_CLEAN(1, 8);
	READ_DATA_UNLOADED(2);
}

TEST(Buffer, ReadAcrossBlocks)
{
	READ_DATA_PREPARE();
	
	std::vector<unsigned char> got_data = b.read_data(2, 10);
	std::vector<unsigned char> expect_data(file_data.data() + 2, file_data.data() + 2 + 10);
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
	
	READ_DATA_CLEAN(0, 8);
	READ_DATA_CLEAN(1, 8);
	READ_DATA_UNLOADED(2);
}

TEST(Buffer, ReadAcrossBlocksShifted)
{
	READ_DATA_PREPARE();
	
	const std::vector<unsigned char> expect_data = {
		0x57, 0x47, 0xBD, 0xA7, 0xB0, 0x11, 0xB8, 0x40,
		0x97, 0x68,
	};
	
	std::vector<unsigned char> got_data = b.read_data(REHex::BitOffset(2, 4), 10);
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
}

TEST(Buffer, ReadToEndShifted)
{
	READ_DATA_PREPARE();
	
	const std::vector<unsigned char> expect_data = {
		94, 19, 16, 152
	};
	
	std::vector<unsigned char> got_data = b.read_data(REHex::BitOffset(18, 2), 10);
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
}

TEST(Buffer, ReadWholeFile)
{
	READ_DATA_PREPARE();
	
	std::vector<unsigned char> got_data = b.read_data(0, 23);
	std::vector<unsigned char> expect_data(file_data.data(), file_data.data() + 23);
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
	
	READ_DATA_CLEAN(0, 8);
	READ_DATA_CLEAN(1, 8);
	READ_DATA_CLEAN(2, 7);
}

TEST(Buffer, ReadMoreThanFile)
{
	READ_DATA_PREPARE();
	
	std::vector<unsigned char> got_data = b.read_data(0, 50);
	std::vector<unsigned char> expect_data(file_data.data(), file_data.data() + 23);
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
	
	READ_DATA_CLEAN(0, 8);
	READ_DATA_CLEAN(1, 8);
	READ_DATA_CLEAN(2, 7);
}

TEST(Buffer, ReadFromEnd)
{
	READ_DATA_PREPARE();
	
	std::vector<unsigned char> got_data = b.read_data(23, 50);
	std::vector<unsigned char> expect_data;
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
	
	READ_DATA_UNLOADED(0);
	READ_DATA_UNLOADED(1);
	READ_DATA_UNLOADED(2);
}

TEST(Buffer, ReadFromBeyondEnd)
{
	READ_DATA_PREPARE();
	
	std::vector<unsigned char> got_data = b.read_data(30, 50);
	std::vector<unsigned char> expect_data;
	
	EXPECT_EQ(got_data, expect_data) << "Buffer::read_data() returns the correct data";
	
	READ_DATA_UNLOADED(0);
	READ_DATA_UNLOADED(1);
	READ_DATA_UNLOADED(2);
}

TEST(Buffer, OverwriteTinyFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF0, 0x0D, 0x77, 0xA4, 0xE2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(0, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 5);
			});
			
			TEST_LENGTH(5);
		}
	);
}

TEST(Buffer, OverwriteTinyFileEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF8, 0xD1, 0x77, 0xF0, 0x0D,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(3, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 5);
			});
			
			TEST_LENGTH(5);
		}
	);
}

TEST(Buffer, OverwriteTinyFileAll)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x65, 0x87, 0x49, 0x7A, 0x06,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(0, (std::vector<unsigned char>{ 0x65, 0x87, 0x49, 0x7A, 0x06, }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 5);
			});
			
			TEST_LENGTH(5);
		}
	);
}

TEST(Buffer, OverwriteTinyFileAllAndThenSome)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_FAIL(0, (std::vector<unsigned char>{ 0x65, 0x87, 0x49, 0x7A, 0x06, 0xAA }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 5);
			});
			
			TEST_LENGTH(5);
		}
	);
}

TEST(Buffer, OverwriteTinyFileFromEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_FAIL(5, (std::vector<unsigned char>{ 0x65 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 5);
			});
			
			TEST_LENGTH(5);
		}
	);
}

TEST(Buffer, OverwriteSingleBlockFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF0, 0x0D, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(0, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, OverwriteSingleBlockFileEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0xF0, 0x0D,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(6, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, OverwriteSingleBlockFileAll)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x34, 0x89, 0x3D, 0x7B, 0x6F, 0xBF, 0x13, 0xC0,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(0, (std::vector<unsigned char>{ 0x34, 0x89, 0x3D, 0x7B, 0x6F, 0xBF, 0x13, 0xC0, }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, OverwriteSingleBlockFileAllAndThenSome)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_FAIL(0, (std::vector<unsigned char>{ 0x87, 0x6A, 0x6E, 0xCB, 0xB3, 0x99, 0xF4, 0xE7, 0xAA }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, OverwriteSingleBlockFileFromEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_FAIL(8, (std::vector<unsigned char>{ 0x65 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileFirstBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF0, 0x0D, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(0, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileFirstBlockEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0xF0, 0x0D,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(6, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileSecondBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xF0, 0x0D, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(8, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(DIRTY,    8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileSecondBlockEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0xF0, 0x0D,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(14, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(DIRTY,    8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileLastBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0xF0, 0x0D, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(24, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileLastBlockEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0xF0, 0x0D,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(28, (std::vector<unsigned char>{ 0xF0, 0x0D }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileAcrossBlocks)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0xF0, 0x0D,
		0xB4, 0x70, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(6, (std::vector<unsigned char>{ 0xF0, 0x0D, 0xB4, 0x70 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  8);
				TEST_BLOCK_DEF(DIRTY,    8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileAll)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x6A, 0xD1, 0xBE, 0x3A, 0x09, 0x75, 0xD8, 0x7E,
		0x27, 0x4F, 0xEF, 0xAF, 0xE2, 0x4E, 0x04, 0xAA,
		0x35, 0x0C, 0xFD, 0xCF, 0x07, 0xDD, 0xE4, 0x7F,
		0xF5, 0x69, 0x64, 0x35, 0xB1, 0x9A,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(0, END_DATA);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0,  8);
				TEST_BLOCK_DEF(DIRTY, 8,  8);
				TEST_BLOCK_DEF(DIRTY, 16, 8);
				TEST_BLOCK_DEF(DIRTY, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileAllAndThenSome)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> TOOMUCH = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9, 0xAA
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_FAIL(0, TOOMUCH);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultiBlockFileFromEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_FAIL(30, (std::vector<unsigned char>{ 0x65 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteEmptyFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {};
	const std::vector<unsigned char> END_DATA   = {};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_FAIL(0, (std::vector<unsigned char>{ 0x65 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 0);
			});
			
			TEST_LENGTH(0);
		}
	);
}

TEST(Buffer, OverwriteShifted)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0xAB, 0xE4, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(REHex::BitOffset(1, 1), (std::vector<unsigned char>{ 0x57 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteShiftedToEndOfBlock)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x98, 0x92,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(REHex::BitOffset(6, 7), (std::vector<unsigned char>{ 0x49 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteShiftedOverEndOfBlock)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x98, 0x93,
		0x55, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(REHex::BitOffset(6, 7), (std::vector<unsigned char>{ 0x49, 0xAA }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  8);
				TEST_BLOCK_DEF(DIRTY,    8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteShiftedAcrossBlocks)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x98, 0x93,
		0x55, 0x54, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(REHex::BitOffset(6, 7), (std::vector<unsigned char>{ 0x49, 0xAA, 0xAA }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  8);
				TEST_BLOCK_DEF(DIRTY,    8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteShiftedToEndOfFile)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x6A, 0xB9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_OK(REHex::BitOffset(28, 4), (std::vector<unsigned char>{ 0xAB }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteShiftedOverEndOfFile)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_FAIL(REHex::BitOffset(28, 4), (std::vector<unsigned char>{ 0xAB, 0xCD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteEmptyFileBeyondEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {};
	const std::vector<unsigned char> END_DATA   = {};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_FAIL(2, (std::vector<unsigned char>{ 0x65 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 0);
			});
			
			TEST_LENGTH(0);
		}
	);
}

TEST(Buffer, OverwriteSingleBit)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x16, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_BITS_OK(REHex::BitOffset(1, 0),
				0
			);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteMultipleBits)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD3,
		0xD2, 0xDB, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_BITS_OK(REHex::BitOffset(15, 6),
				                  1, 1,
				1, 1, 0, 1, 0, 0, 1, 0,
				1, 1, 0,
			);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(DIRTY,    8,  8);
				TEST_BLOCK_DEF(DIRTY,    16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteBitsToEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC3,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_BITS_OK(REHex::BitOffset(29, 4),
				0, 0, 1, 1,
			);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}

TEST(Buffer, OverwriteBitsPastEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_OVERWRITE_BITS_FAIL(REHex::BitOffset(29, 4),
				0, 0, 1, 1, 0,
			);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 6);
			});
			
			TEST_LENGTH(30);
		}
	);
}
