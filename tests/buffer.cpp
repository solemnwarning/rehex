/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2019 Daniel Collins <solemnwarning@solemnwarning.net>
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

#undef NDEBUG
#include "../src/platform.hpp"
#include <assert.h>

#include <errno.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "testutil.hpp"

#define UNIT_TEST
#include "../src/buffer.hpp"

#define TMPFILE  "tests/.tmpfile"
#define TMPFILE2 "tests/.tmpfile2"

static void write_file(const char *filename, const std::vector<unsigned char>& data)
{
	FILE *fh = fopen(filename, "wb");
	assert(fh);	// Ensure the 'tests' directory can be accessed when hitting this
	
	if(data.size() > 0)
		assert(fwrite(data.data(), data.size(), 1, fh) == 1);
	
	fclose(fh);
}

static std::vector<unsigned char> read_file(const char *filename)
{
	FILE *fh = fopen(filename, "rb");
	assert(fh);
	
	std::vector<unsigned char> data;
	
	unsigned char buf[1024];
	size_t len;
	while((len = fread(buf, 1, sizeof(buf), fh)) > 0)
	{
		data.insert(data.end(), buf, buf + len);
	}
	
	assert(!ferror(fh));
	
	fclose(fh);
	
	return data;
}

#define TEST_BUFFER_MANIP(buffer_manip_code) \
{ \
	write_file(TMPFILE, BEGIN_DATA); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	std::vector<unsigned char> got_data = b.read_data(0, 1024); \
	EXPECT_EQ(got_data, END_DATA) << "Buffer::read_data() returns correct data"; \
} \
{ \
	write_file(TMPFILE, BEGIN_DATA); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	b.write_inplace(); \
	std::vector<unsigned char> got_data = read_file(TMPFILE); \
	EXPECT_EQ(got_data, END_DATA) << "write_inplace() produces file with correct data"; \
} \
{ \
	write_file(TMPFILE, BEGIN_DATA); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	b.write_copy(TMPFILE2); \
	std::vector<unsigned char> got_data = read_file(TMPFILE2); \
	EXPECT_EQ(got_data, END_DATA) << "write_copy() produces file with correct data"; \
} \
{ \
	write_file(TMPFILE, BEGIN_DATA); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	b.write_inplace(TMPFILE); \
	std::vector<unsigned char> got_data = read_file(TMPFILE); \
	EXPECT_EQ(got_data, END_DATA) << "write_inplace(<same file>) produces file with correct data"; \
} \
{ \
	write_file(TMPFILE, BEGIN_DATA); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	assert(unlink(TMPFILE2) == 0 || errno == ENOENT);\
	b.write_inplace(TMPFILE2); \
	std::vector<unsigned char> got_data = read_file(TMPFILE2); \
	EXPECT_EQ(got_data, END_DATA) << "write_inplace(<new file>) produces file with correct data"; \
} \
if(END_DATA.size() > 0) \
{ \
	write_file(TMPFILE, BEGIN_DATA); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	std::vector<unsigned char> tf2data((END_DATA.size() - 1), 0xFF); \
	write_file(TMPFILE2, tf2data); \
	b.write_inplace(TMPFILE2); \
	std::vector<unsigned char> got_data = read_file(TMPFILE2); \
	EXPECT_EQ(got_data, END_DATA) << "write_inplace(<smaller file>) produces file with correct data"; \
} \
{ \
	write_file(TMPFILE, BEGIN_DATA); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	std::vector<unsigned char> tf2data((END_DATA.size() + 1), 0xFF); \
	write_file(TMPFILE2, tf2data); \
	b.write_inplace(TMPFILE2); \
	std::vector<unsigned char> got_data = read_file(TMPFILE2); \
	EXPECT_EQ(got_data, END_DATA) << "write_inplace(<larger file>) produces file with correct data"; \
}

#define TEST_BLOCKS(blocks_code) \
{ \
	unsigned int n_blocks = 0; \
	blocks_code; \
	EXPECT_EQ(b.blocks.size(), n_blocks) << "Buffer has correct number of blocks"; \
}

#define TEST_BLOCK_DEF(expect_state, expect_vo, expect_vl) \
{ \
	if(b.blocks.size() > (unsigned)(n_blocks)) { \
		EXPECT_EQ(b.blocks[n_blocks].state, REHex::Buffer::Block::expect_state) << "blocks[" << n_blocks << "] has correct state"; \
		EXPECT_EQ(b.blocks[n_blocks].virt_offset, expect_vo)                    << "blocks[" << n_blocks << "] has correct virt_offset"; \
		EXPECT_EQ(b.blocks[n_blocks].virt_length, expect_vl)                   << "blocks[" << n_blocks << "] has correct virt_length"; \
	} \
	++n_blocks; \
}

#define TEST_LENGTH(expect_length) \
{ \
	EXPECT_EQ(expect_length, b.length()) << "Buffer::length() returns correct length"; \
}

#define TEST_OVERWRITE_OK(offset, data_vec) \
{ \
	EXPECT_TRUE(b.overwrite_data(offset, data_vec.data(), data_vec.size())) << "Buffer::overwrite_data() returns true"; \
}

#define TEST_OVERWRITE_FAIL(offset, data_vec) \
{ \
	EXPECT_FALSE(b.overwrite_data(offset, data_vec.data(), data_vec.size())) << "Buffer::overwrite_data() returns false"; \
}

#define TEST_ERASE_OK(offset, length) \
{ \
	EXPECT_TRUE(b.erase_data(offset, length)) << "Buffer::erase_data() returns true"; \
}

#define TEST_ERASE_FAIL(offset, length) \
{ \
	EXPECT_FALSE(b.erase_data(offset, length)) << "Buffer::erase_data() returns false"; \
}

#define TEST_INSERT_OK(offset, data_vec) \
{ \
	EXPECT_TRUE(b.insert_data(offset, data_vec.data(), data_vec.size())) << "Buffer::insert_data() returns true"; \
}

#define TEST_INSERT_FAIL(offset, data_vec) \
{ \
	EXPECT_FALSE(b.insert_data(offset, data_vec.data(), data_vec.size())) << "Buffer::insert_data() returns false"; \
}

TEST(Buffer, DefaultConstructor)
{
	REHex::Buffer b;
	
	ASSERT_EQ(b.blocks.size(), 1U) << "Constructor creates correct number of blocks";
	
	EXPECT_EQ(b.blocks[0].virt_offset, 0) << "Constructor creates block with correct offset";
	EXPECT_EQ(b.blocks[0].virt_length, 0) << "Constructor creates block with correct length";
	
	EXPECT_EQ(b.blocks[0].state, REHex::Buffer::Block::CLEAN) << "Constructor marks blocks as clean";
	
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
	
	write_file(TMPFILE, file_data);
	
	REHex::Buffer b(TMPFILE, 8);
	
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
	const std::vector<unsigned char> file_data;
	write_file(TMPFILE, file_data);
	
	REHex::Buffer b(TMPFILE, 8);
	
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
	write_file(TMPFILE, file_data); \
	\
	REHex::Buffer b(TMPFILE, 8);

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

TEST(Buffer, EraseTinyFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x77, 0xA4, 0xE2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(0, 2);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 3);
			});
			
			TEST_LENGTH(3);
		}
	);
}

TEST(Buffer, EraseTinyFileEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF8, 0xD1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(2, 3);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 2);
			});
			
			TEST_LENGTH(2);
		}
	);
}

TEST(Buffer, EraseTinyFileMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF8, 0xD1, 0xE2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(2, 2);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 3);
			});
			
			TEST_LENGTH(3);
		}
	);
}

TEST(Buffer, EraseTinyFileAll)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(0, 5);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 0);
			});
			
			TEST_LENGTH(0);
		}
	);
}

TEST(Buffer, EraseTinyFileAllAndThemSome)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_FAIL(0, 6);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 5);
			});
			
			TEST_LENGTH(5);
		}
	);
}

TEST(Buffer, EraseTinyFileFromEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xF8, 0xD1, 0x77, 0xA4, 0xE2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_FAIL(5, 1);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 5);
			});
			
			TEST_LENGTH(5);
		}
	);
}

TEST(Buffer, EraseSingleBlockFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		/* 0xF0, 0x0D, */ 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(0, 2);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 6);
			});
			
			TEST_LENGTH(6);
		}
	);
}

TEST(Buffer, EraseSingleBlockFileEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, /* 0x74, 0x50, 0xD2, */
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(5, 3);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 5);
			});
			
			TEST_LENGTH(5);
		}
	);
}

TEST(Buffer, EraseSingleBlockFileMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x09, 0x7E, /* 0x9B, 0x25, 0xCB, 0x74, */ 0x50, 0xD2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(2, 4);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 4);
			});
			
			TEST_LENGTH(4);
		}
	);
}

TEST(Buffer, EraseSingleBlockFileAll)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		/* 0x34, 0x89, 0x3D, 0x7B, 0x6F, 0xBF, 0x13, 0xC0, */
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(0, 8);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 0);
			});
			
			TEST_LENGTH(0);
		}
	);
}

TEST(Buffer, EraseSingleBlockFileAllAndThenSome)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_FAIL(0, 9);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, EraseSingleBlockFileFromEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_FAIL(8, 1);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, EraseMultiBlockFileFirstBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		/* 0x06, 0x96, */ 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(0, 2);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  6);
				TEST_BLOCK_DEF(UNLOADED, 6,  8);
				TEST_BLOCK_DEF(UNLOADED, 14, 8);
				TEST_BLOCK_DEF(UNLOADED, 22, 6);
			});
			
			TEST_LENGTH(28);
		}
	);
}

TEST(Buffer, EraseMultiBlockFileFirstBlockEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, /* 0xB5, 0x99, 0x4E, */
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(5, 3);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  5);
				TEST_BLOCK_DEF(UNLOADED, 5,  8);
				TEST_BLOCK_DEF(UNLOADED, 13, 8);
				TEST_BLOCK_DEF(UNLOADED, 21, 6);
			});
			
			TEST_LENGTH(27);
		}
	);
}

TEST(Buffer, EraseMultiBlockFileSecondBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		/* 0xE7, 0xA8, 0x06, */ 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(8, 3);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(DIRTY,    8,  5);
				TEST_BLOCK_DEF(UNLOADED, 13, 8);
				TEST_BLOCK_DEF(UNLOADED, 21, 6);
			});
			
			TEST_LENGTH(27);
		}
	);
}

TEST(Buffer, EraseMultiBlockFileSecondBlockEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, /* 0x8C, 0xD1, */
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(14, 2);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(DIRTY,    8,  6);
				TEST_BLOCK_DEF(UNLOADED, 14, 8);
				TEST_BLOCK_DEF(UNLOADED, 22, 6);
			});
			
			TEST_LENGTH(28);
		}
	);
}

TEST(Buffer, EraseMultiBlockFileLastBlockStart)
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
		/* 0x51, 0xA0, */ 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(24, 2);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 4);
			});
			
			TEST_LENGTH(28);
		}
	);
}

TEST(Buffer, EraseMultiBlockFileLastBlockEnd)
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
		0x51, 0xA0, 0x0D, 0xAD, /* 0x67, 0xC9, */
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(28, 2);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 4);
			});
			
			TEST_LENGTH(28);
		}
	);
}

TEST(Buffer, EraseMultiBlockFilePartialBlocks)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, /* 0x99, 0x4E,
		0xE7, 0xA8, */ 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(6, 4);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  6);
				TEST_BLOCK_DEF(DIRTY,    6,  6);
				TEST_BLOCK_DEF(UNLOADED, 12, 8);
				TEST_BLOCK_DEF(UNLOADED, 20, 6);
			});
			
			TEST_LENGTH(26);
		}
	);
}

TEST(Buffer, EraseMultiBlockFilePartialBlocksMore)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, /* 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, */ 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(3, 24);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 3);
				TEST_BLOCK_DEF(DIRTY, 3, 0);
				TEST_BLOCK_DEF(DIRTY, 3, 0);
				TEST_BLOCK_DEF(DIRTY, 3, 3);
			});
			
			TEST_LENGTH(6);
		}
	);
}

TEST(Buffer, EraseMultiBlockFileAll)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(0, 30);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 0);
				TEST_BLOCK_DEF(DIRTY, 0, 0);
				TEST_BLOCK_DEF(DIRTY, 0, 0);
				TEST_BLOCK_DEF(DIRTY, 0, 0);
			});
			
			TEST_LENGTH(0);
		}
	);
}

TEST(Buffer, EraseMultiBlockFileAllAndThemSome)
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
			TEST_ERASE_FAIL(0, 31);
			
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

TEST(Buffer, EraseMultiBlockFileFromEnd)
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
			TEST_ERASE_FAIL(30, 1);
			
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

TEST(Buffer, EraseEmptyFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {};
	const std::vector<unsigned char> END_DATA   = {};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_FAIL(0, 1);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 0);
			});
			
			TEST_LENGTH(0);
		}
	);
}

TEST(Buffer, EraseZeroBytes)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(0, 0);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, EraseSequence1)
{
	/* Test erasing in sequence so we can see erase_data() handles
	 * zero-length blocks and blocks with the same offset correctly.
	*/
	
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		/* 0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E, */
		/* 0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1, */
		/* 0xE0, 0x3B, 0x0F, 0x7C, */ 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(0, 8);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  0);
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 6);
			});
			
			TEST_LENGTH(22);
			
			TEST_ERASE_OK(0, 8);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0, 0);
				TEST_BLOCK_DEF(DIRTY,    0, 0);
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
				TEST_BLOCK_DEF(UNLOADED, 8, 6);
			});
			
			TEST_LENGTH(14);
			
			TEST_ERASE_OK(0, 4);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0, 0);
				TEST_BLOCK_DEF(DIRTY,    0, 0);
				TEST_BLOCK_DEF(DIRTY,    0, 4);
				TEST_BLOCK_DEF(UNLOADED, 4, 6);
			});
			
			TEST_LENGTH(10);
		}
	);
}

TEST(Buffer, EraseSequence2)
{
	/* Test erasing in sequence so we can see erase_data() handles
	 * zero-length blocks and blocks with the same offset correctly.
	*/
	
	const std::vector<unsigned char> BEGIN_DATA = {
		0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
	};
	
	const std::vector<unsigned char> END_DATA = {
		/* 0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E, */
		/* 0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1, */
		0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
		/* 0x51, 0xA0, 0x0D, 0xAD, */ 0x67, 0xC9,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_ERASE_OK(0, 8);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  0);
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 6);
			});
			
			TEST_LENGTH(22);
			
			TEST_ERASE_OK(0, 8);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0, 0);
				TEST_BLOCK_DEF(DIRTY,    0, 0);
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
				TEST_BLOCK_DEF(UNLOADED, 8, 6);
			});
			
			TEST_LENGTH(14);
			
			TEST_ERASE_OK(8, 4);
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0, 0);
				TEST_BLOCK_DEF(DIRTY,    0, 0);
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
				TEST_BLOCK_DEF(DIRTY,    8, 2);
			});
			
			TEST_LENGTH(10);
		}
	);
}

TEST(Buffer, InsertEmptyFile)
{
	const std::vector<unsigned char> BEGIN_DATA = {};
	const std::vector<unsigned char> END_DATA   = { 0xAA, 0xBB, 0xCC, 0xDD };
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 4);
			});
			
			TEST_LENGTH(4);
		}
	);
}

TEST(Buffer, InsertEmptyFileMulti)
{
	const std::vector<unsigned char> BEGIN_DATA = {};
	const std::vector<unsigned char> END_DATA   = { 0xAA, 0x00, 0x11, 0xBB, 0xCC, 0xEE, 0xFF, 0xDD };
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			TEST_INSERT_OK(3, (std::vector<unsigned char>{ 0xEE, 0xFF }));
			TEST_INSERT_OK(1, (std::vector<unsigned char>{ 0x00, 0x11 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, InsertEmptyFileBeyondEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {};
	const std::vector<unsigned char> END_DATA   = {};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_FAIL(1, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 0);
			});
			
			TEST_LENGTH(0);
		}
	);
}

TEST(Buffer, InsertTinyFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xAA, 0xBB, 0xCC, 0xDD,
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 10);
			});
			
			TEST_LENGTH(10);
		}
	);
}

TEST(Buffer, InsertTinyFileMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB,
		0xAA, 0xBB, 0xCC, 0xDD,
		0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(2, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 10);
			});
			
			TEST_LENGTH(10);
		}
	);
}

TEST(Buffer, InsertTinyFileEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
		0xAA, 0xBB, 0xCC, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(6, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 10);
			});
			
			TEST_LENGTH(10);
		}
	);
}

TEST(Buffer, InsertTinyFileMulti)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		/* > */ 0xAA, 0x00, 0x11, 0xBB, 0xCC, 0xDD, /* < */
		0x68, 0xAB, /* > */ 0xEE, 0xFF, /* < */ 0x8A, 0xEF, 0x5F, 0xCA,
		
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 10);
			});
			
			TEST_INSERT_OK(6, (std::vector<unsigned char>{ 0xEE, 0xFF }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_INSERT_OK(1, (std::vector<unsigned char>{ 0x00, 0x11 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 14);
			});
			
			TEST_LENGTH(14);
		}
	);
}

TEST(Buffer, InsertTinyFileBeyondEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_FAIL(7, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 6);
			});
			
			TEST_LENGTH(6);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xAA, 0xBB, 0xCC, 0xDD,
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_LENGTH(12);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB,
		0xAA, 0xBB, 0xCC, 0xDD,
		0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(2, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_LENGTH(12);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		0xAA, 0xBB, 0xCC, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(8, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_LENGTH(12);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileMulti)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xAA, 0x00, 0x11, 0xBB, 0xCC, 0xDD,
		0x68, 0xAB, 0xEE, 0xFF, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_INSERT_OK(6, (std::vector<unsigned char>{ 0xEE, 0xFF }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 14);
			});
			
			TEST_INSERT_OK(1, (std::vector<unsigned char>{ 0x00, 0x11 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 16);
			});
			
			TEST_LENGTH(16);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileBeyondEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_FAIL(9, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileFirstBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xAA, 0xBB, 0xCC, 0xDD,
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  12);
				TEST_BLOCK_DEF(UNLOADED, 12, 8);
				TEST_BLOCK_DEF(UNLOADED, 20, 8);
				TEST_BLOCK_DEF(UNLOADED, 28, 5);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileFirstBlockMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8,
						0xAA, 0xBB, 0xCC, 0xDD,
						0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(5, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  12);
				TEST_BLOCK_DEF(UNLOADED, 12, 8);
				TEST_BLOCK_DEF(UNLOADED, 20, 8);
				TEST_BLOCK_DEF(UNLOADED, 28, 5);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileThirdBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xAA, 0xBB, 0xCC, 0xDD,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(16, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(DIRTY,    16, 12);
				TEST_BLOCK_DEF(UNLOADED, 28, 5);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileThirdBlockMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0,
			0xAA, 0xBB, 0xCC, 0xDD,
			0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(17, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(DIRTY,    16, 12);
				TEST_BLOCK_DEF(UNLOADED, 28, 5);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileLastBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0xAA, 0xBB, 0xCC, 0xDD,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(24, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 9);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileLastBlockMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24,
				0xAA, 0xBB, 0xCC, 0xDD,
				0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(26, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 9);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileLastBlockEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
						0xAA, 0xBB, 0xCC, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(29, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 9);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileMulti)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, /* > */ 0xAA, 0xBB, 0xCC, 0xDD, /* < */ 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, /* > */ 0x00, 0x11, /* < */ 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, /* > */ 0xEE, 0xFF, /* < */ 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(4,  (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			TEST_INSERT_OK(22, (std::vector<unsigned char>{ 0xEE, 0xFF }));
			TEST_INSERT_OK(16, (std::vector<unsigned char>{ 0x00, 0x11 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  12);
				TEST_BLOCK_DEF(DIRTY,    12, 10);
				TEST_BLOCK_DEF(DIRTY,    22, 10);
				TEST_BLOCK_DEF(UNLOADED, 32, 5);
			});
			
			TEST_LENGTH(37);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileBeyondEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_FAIL(30, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 5);
			});
			
			TEST_LENGTH(29);
		}
	);
}

/* Verifies we can read/write files containing any bytes without any funky
 * behaviour occuring (see 52de6b2a41d7ad82761764e250f92b359cafd072).
*/
TEST(Buffer, ReadWriteAnyBytes)
{
	std::vector<unsigned char> BEGIN_DATA(512, 0);
	std::vector<unsigned char> END_DATA(512, 0);
	
	for(int i = 0; i < 512; ++i)
	{
		BEGIN_DATA[i] = (i % 255);
		END_DATA[i]   = (i % 255);
	}
	
	TEST_BUFFER_MANIP({});
}

#ifndef _WIN32
TEST(Buffer, DeleteBackingFileAndRestore)
{
	TempFilename f1, f2;
	
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	
	REHex::Buffer b(f1.tmpfile);
	b.read_data(0, 1024); /* Buffer file. */
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	ASSERT_FALSE(b.file_deleted());
	ASSERT_FALSE(b.file_modified());
	
	ASSERT_EQ(rename(f1.tmpfile, f2.tmpfile), 0) << "Moving backing file aside succeeds";
	
	run_wx_until([&]() { return b.file_deleted(); });
	
	EXPECT_TRUE(b.file_deleted())   << "REHex::Buffer::file_deleted() returns true when backing file has been removed";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false when backing file has been removed";
	
	b.write_inplace();
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false after file is re-written by REHex::Buffer::write_inplace()";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false after file is re-written by REHex::Buffer::write_inplace()";
	
	std::vector<unsigned char> file_data = read_file(f1.tmpfile);
	EXPECT_EQ(file_data, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 })) << "File is restored with correct data";
}

TEST(Buffer, ReplaceBackingFileAndRestore)
{
	TempFilename f1, f2, f3;
	
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	write_file(f2.tmpfile, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }));
	
	REHex::Buffer b(f1.tmpfile);
	b.read_data(0, 1024); /* Buffer file. */
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	ASSERT_FALSE(b.file_deleted());
	ASSERT_FALSE(b.file_modified());
	
	ASSERT_EQ(rename(f1.tmpfile, f3.tmpfile), 0) << "Moving backing file aside succeeds";
	ASSERT_EQ(rename(f2.tmpfile, f1.tmpfile), 0) << "Replacing backing file succeeds";
	
	run_wx_until([&]() { return b.file_deleted(); });
	
	EXPECT_TRUE(b.file_deleted())   << "REHex::Buffer::file_deleted() returns true when backing file has been replaced";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false when backing file has been replaced";
	
	b.write_inplace();
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false after file is re-written by REHex::Buffer::write_inplace()";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false after file is re-written by REHex::Buffer::write_inplace()";
	
	std::vector<unsigned char> file_data = read_file(f1.tmpfile);
	EXPECT_EQ(file_data, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 })) << "File is restored with correct data";
}

TEST(Buffer, ReplaceBackingFileAndReload)
{
	TempFilename f1, f2, f3;
	
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	write_file(f2.tmpfile, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }));
	
	REHex::Buffer b(f1.tmpfile);
	b.read_data(0, 1024); /* Buffer file. */
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	ASSERT_FALSE(b.file_deleted());
	ASSERT_FALSE(b.file_modified());
	
	ASSERT_EQ(rename(f1.tmpfile, f3.tmpfile), 0) << "Moving backing file aside succeeds";
	ASSERT_EQ(rename(f2.tmpfile, f1.tmpfile), 0) << "Replacing backing file succeeds";
	
	run_wx_until([&]() { return b.file_deleted(); });
	
	EXPECT_TRUE(b.file_deleted())   << "REHex::Buffer::file_deleted() returns true when backing file has been replaced";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false when backing file has been replaced";
	
	b.reload();
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false after REHex::Buffer::reload() is called";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false after REHex::Buffer::reload() is called";
	
	std::vector<unsigned char> file_data = b.read_data(0, 1024);
	EXPECT_EQ(file_data, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })) << "Buffer contains new content";
}
#endif

TEST(Buffer, ModifyBackingFileAndReload)
{
	TempFilename f1;
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	
	REHex::Buffer b(f1.tmpfile);
	b.read_data(0, 1024); /* Buffer file. */
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	ASSERT_FALSE(b.file_deleted());
	ASSERT_FALSE(b.file_modified());
	
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }));
	
	run_wx_until([&]() { return b.file_modified(); });
	
	EXPECT_TRUE(b.file_modified()) << "REHex::Buffer::file_modified() returns true when backing file has been modified";
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false when backing file has been modified";
	
	b.reload();
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false after REHex::Buffer::reload() is called";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false after REHex::Buffer::reload() is called";
	
	std::vector<unsigned char> file_data = b.read_data(0, 1024);
	EXPECT_EQ(file_data, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })) << "Buffer contains new content";
}
