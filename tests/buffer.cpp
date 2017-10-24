/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <assert.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tests/tap/basic.h"

#define UNIT_TEST
#include "../src/buffer.hpp"

#define TMPFILE  "tests/.tmpfile"
#define TMPFILE2 "tests/.tmpfile2"

static void write_file(const char *filename, const void *data, size_t length)
{
	FILE *fh = fopen(filename, "wb");
	assert(fh);
	
	if(length > 0)
		assert(fwrite(data, length, 1, fh) == 1);
	
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

#define TEST_BUFFER_MANIP(desc, buffer_manip_code) \
{ \
	diag(desc ", checking result with read_data()"); \
	write_file(TMPFILE, BEGIN_DATA, sizeof(BEGIN_DATA)); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	std::vector<unsigned char> data = b.read_data(0, 40); \
	is_int(sizeof(END_DATA), data.size(), "Buffer::read_data() returns correct number of bytes") \
		&& is_blob(END_DATA, data.data(), sizeof(END_DATA), "Buffer::read_data() returns correct data"); \
} \
{ \
	diag(desc ", checking result with write_inplace()"); \
	write_file(TMPFILE, BEGIN_DATA, sizeof(BEGIN_DATA)); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	b.write_inplace(); \
	std::vector<unsigned char> data = read_file(TMPFILE); \
	is_int(sizeof(END_DATA), data.size(), "File is correct length") \
		&& is_blob(END_DATA, data.data(), sizeof(END_DATA), "File contains correct data"); \
} \
{ \
	diag(desc ", checking result with write_copy()"); \
	write_file(TMPFILE, BEGIN_DATA, sizeof(BEGIN_DATA)); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	b.write_copy(TMPFILE2); \
	std::vector<unsigned char> data = read_file(TMPFILE2); \
	is_int(sizeof(END_DATA), data.size(), "File is correct length") \
		&& is_blob(END_DATA, data.data(), sizeof(END_DATA), "File contains correct data"); \
}

#define TEST_BLOCKS(blocks_code) \
{ \
	int n_blocks = 0; \
	blocks_code; \
	is_int(n_blocks, b.blocks.size(), "Buffer has correct number of blocks"); \
}

#define TEST_BLOCK_DEF(expect_state, expect_vo, expect_vl) \
{ \
	if(b.blocks.size() > (unsigned)(n_blocks)) { \
		ok((b.blocks[n_blocks].state == REHex::Buffer::Block::expect_state), "blocks[%d] has correct state", n_blocks); \
		is_int(expect_vo, b.blocks[n_blocks].virt_offset, "blocks[%d] has correct virt_offset", n_blocks); \
		is_int(expect_vl, b.blocks[n_blocks].virt_length, "blocks[%d] has correct virt_length", n_blocks); \
	} \
	++n_blocks; \
}

#define TEST_LENGTH(expect_length) \
{ \
	is_int(expect_length, b.length(), "Buffer::length() returns correct length"); \
}

#define TEST_INSERT_OK(offset, data) \
{ \
	ok(b.insert_data(offset, data, sizeof(data)), "Buffer::insert_data() returns true"); \
}

#define TEST_INSERT_FAIL(offset, data) \
{ \
	ok(!b.insert_data(offset, data, sizeof(data)), "Buffer::insert_data() returns false"); \
}

static void ctor_tests()
{
	{
		const char *test_desc = "Buffer()";
		
		REHex::Buffer b;
		
		is_int(1, b.blocks.size(), "%s create a block", test_desc);
		
		is_int(0, b.blocks[0].virt_offset, "%s creates block with correct offset", test_desc);
		is_int(0, b.blocks[0].virt_length, "%s creates block with correct length", test_desc);
		
		ok((b.blocks[0].state == REHex::Buffer::Block::CLEAN), "%s marks blocks as clean", test_desc);
		
		ok(b.blocks[0].data.empty(), "%s doesn't populate block data", test_desc);
		
		is_int(0, b.length(), "Buffer::length() returns correct value");
	}
	
	{
		const char *test_desc = "Buffer(<non-empty file>)";
		
		const unsigned char file_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		write_file(TMPFILE, file_data, sizeof(file_data));
		
		REHex::Buffer b(TMPFILE, 8);
		
		is_int(3, b.blocks.size(), "%s creates correct number of blocks", test_desc);
		
		is_int(0,  b.blocks[0].virt_offset, "%s creates blocks with correct offset", test_desc);
		is_int(8,  b.blocks[0].virt_length, "%s creates blocks with correct length", test_desc);
		is_int(8,  b.blocks[1].virt_offset, "%s creates blocks with correct offset", test_desc);
		is_int(8,  b.blocks[1].virt_length, "%s creates blocks with correct length", test_desc);
		is_int(16, b.blocks[2].virt_offset, "%s creates blocks with correct offset", test_desc);
		is_int(7,  b.blocks[2].virt_length, "%s creates blocks with correct length", test_desc);
		
		ok((b.blocks[0].state == REHex::Buffer::Block::UNLOADED), "%s marks blocks as unloaded", test_desc);
		ok((b.blocks[1].state == REHex::Buffer::Block::UNLOADED), "%s marks blocks as unloaded", test_desc);
		ok((b.blocks[2].state == REHex::Buffer::Block::UNLOADED), "%s marks blocks as unloaded", test_desc);
		
		ok(b.blocks[0].data.empty(), "%s doesn't populate block data", test_desc);
		ok(b.blocks[1].data.empty(), "%s doesn't populate block data", test_desc);
		ok(b.blocks[2].data.empty(), "%s doesn't populate block data", test_desc);
		
		is_int(23, b.length(), "Buffer::length() returns correct value");
	}
	
	{
		const char *test_desc = "Buffer(<empty file>)";
		
		write_file(TMPFILE, NULL, 0);
		
		REHex::Buffer b(TMPFILE, 8);
		
		is_int(1, b.blocks.size(), "%s create a block", test_desc);
		
		is_int(0, b.blocks[0].virt_offset, "%s creates block with correct offset", test_desc);
		is_int(0, b.blocks[0].virt_length, "%s creates block with correct length", test_desc);
		
		ok((b.blocks[0].state == REHex::Buffer::Block::UNLOADED), "%s marks blocks as unloaded", test_desc);
		
		ok(b.blocks[0].data.empty(), "%s doesn't populate block data", test_desc);
		
		is_int(0, b.length(), "Buffer::length() returns correct value");
	}
}

#define READ_DATA_PREPARE() \
	const unsigned char file_data[] = { \
		0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01, \
		0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8, \
		0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C, \
	}; \
	\
	write_file(TMPFILE, file_data, sizeof(file_data)); \
	\
	REHex::Buffer b(TMPFILE, 8);

#define READ_DATA_UNLOADED(block_i) \
{ \
	ok((b.blocks[block_i].state == REHex::Buffer::Block::UNLOADED), "Unread block not loaded"); \
	ok(b.blocks[block_i].data.empty(), "Unread block has no data buffer"); \
}

#define READ_DATA_CLEAN(block_i, len) \
{ \
	ok((b.blocks[block_i].state == REHex::Buffer::Block::CLEAN), "Read block loaded"); \
	ok((b.blocks[block_i].data.size() >= len), "Read block has data buffer"); \
}

static void read_data_tests()
{
	{
		diag("Reading first block...");
		
		READ_DATA_PREPARE();
		
		std::vector<unsigned char> data = b.read_data(0, 8);
		
		is_int(8, data.size(), "Buffer::read_data() returns the correct number of bytes")
			&& is_blob(file_data, data.data(), 8, "Buffer::read_data() returns the correct data");
		
		READ_DATA_CLEAN(0, 8);
		READ_DATA_UNLOADED(1);
		READ_DATA_UNLOADED(2);
	}
	
	{
		diag("Reading part of first block...");
		
		READ_DATA_PREPARE();
		
		std::vector<unsigned char> data = b.read_data(2, 5);
		
		is_int(5, data.size(), "Buffer::read_data() returns the correct number of bytes")
			&& is_blob(file_data + 2, data.data(), 5, "Buffer::read_data() returns the correct data");
		
		READ_DATA_CLEAN(0, 8);
		READ_DATA_UNLOADED(1);
		READ_DATA_UNLOADED(2);
	}
	
	{
		diag("Reading second block...");
		
		READ_DATA_PREPARE();
		
		std::vector<unsigned char> data = b.read_data(8, 8);
		
		is_int(8, data.size(), "Buffer::read_data() returns the correct number of bytes")
			&& is_blob(file_data + 8, data.data(), 8, "Buffer::read_data() returns the correct data");
		
		READ_DATA_UNLOADED(0);
		READ_DATA_CLEAN(1, 8);
		READ_DATA_UNLOADED(2);
	}
	
	{
		diag("Reading part of first and second blocks...");
		
		READ_DATA_PREPARE();
		
		std::vector<unsigned char> data = b.read_data(2, 10);
		
		is_int(10, data.size(), "Buffer::read_data() returns the correct number of bytes")
			&& is_blob(file_data + 2, data.data(), 10, "Buffer::read_data() returns the correct data");
		
		READ_DATA_CLEAN(0, 8);
		READ_DATA_CLEAN(1, 8);
		READ_DATA_UNLOADED(2);
	}
	
	{
		diag("Reading whole file...");
		
		READ_DATA_PREPARE();
		
		std::vector<unsigned char> data = b.read_data(0, 23);
		
		is_int(23, data.size(), "Buffer::read_data() returns the correct number of bytes")
			&& is_blob(file_data, data.data(), 23, "Buffer::read_data() returns the correct data");
		
		READ_DATA_CLEAN(0, 8);
		READ_DATA_CLEAN(1, 8);
		READ_DATA_CLEAN(2, 7);
	}
	
	{
		diag("Reading more than the whole file...");
		
		READ_DATA_PREPARE();
		
		std::vector<unsigned char> data = b.read_data(0, 50);
		
		is_int(23, data.size(), "Buffer::read_data() returns the correct number of bytes")
			&& is_blob(file_data, data.data(), 23, "Buffer::read_data() returns the correct data");
		
		READ_DATA_CLEAN(0, 8);
		READ_DATA_CLEAN(1, 8);
		READ_DATA_CLEAN(2, 7);
	}
	
	{
		diag("Reading from the end of the file...");
		
		READ_DATA_PREPARE();
		
		std::vector<unsigned char> data = b.read_data(23, 50);
		
		is_int(0, data.size(), "Buffer::read_data() returns the correct number of bytes");
		
		READ_DATA_UNLOADED(0);
		READ_DATA_UNLOADED(1);
		READ_DATA_UNLOADED(2);
	}
	
	{
		diag("Reading from beyond the end of the file...");
		
		READ_DATA_PREPARE();
		
		std::vector<unsigned char> data = b.read_data(30, 50);
		
		is_int(0, data.size(), "Buffer::read_data() returns the correct number of bytes");
		
		READ_DATA_UNLOADED(0);
		READ_DATA_UNLOADED(1);
		READ_DATA_UNLOADED(2);
	}
}

#define OVERWRITE_PREPARE() \
	const unsigned char file_data[] = { \
		0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01, \
		0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8, \
		0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C, \
	}; \
	\
	write_file(TMPFILE, file_data, sizeof(file_data)); \
	\
	REHex::Buffer b(TMPFILE, 8);

#define OVERWRITE_DIRTY(block_i, len) \
{ \
	ok((b.blocks[block_i].state == REHex::Buffer::Block::DIRTY), "Changed block marked dirty"); \
	ok((b.blocks[block_i].data.size() >= len), "Changed block has data buffer"); \
}

#define OVERWRITE_UNLOADED(block_i) \
{ \
	ok((b.blocks[block_i].state == REHex::Buffer::Block::UNLOADED), "Unchanged block not loaded"); \
	ok(b.blocks[block_i].data.empty(), "Unchanged block has no data buffer"); \
}

#define OVERWRITE_SANITY() \
{ \
	is_int(3, b.blocks.size(), "Block count unchanged"); \
	\
	is_int(0,  b.blocks[0].virt_offset, "Block offset unchanged"); \
	is_int(8,  b.blocks[0].virt_length, "Block length unchanged"); \
	is_int(8,  b.blocks[1].virt_offset, "Block offset unchanged"); \
	is_int(8,  b.blocks[1].virt_length, "Block length unchanged"); \
	is_int(16, b.blocks[2].virt_offset, "Block offset unchanged"); \
	is_int(7,  b.blocks[2].virt_length, "Block length unchanged"); \
}

static void overwrite_tests()
{
	{
		diag("Overwriting start of first block...");
		
		OVERWRITE_PREPARE();
		
		const unsigned char pattern[] = { 0x5E, 0xF6, 0xDB, 0x36 };
		
		ok(b.overwrite_data(0, pattern, 4), "Buffer::overwrite_data() returns true");
		
		OVERWRITE_SANITY();
		
		OVERWRITE_DIRTY(0, 8);
		OVERWRITE_UNLOADED(1);
		OVERWRITE_UNLOADED(2);
		
		const unsigned char new_block0[] = { 0x5E, 0xF6, 0xDB, 0x36, 0x7B, 0xDA, 0x7B, 0x01 };
		
		is_blob(new_block0, b.blocks[0].data.data(), 8, "Block data loaded and updated correctly");
	}
	
	{
		diag("Overwriting end of first block...");
		
		OVERWRITE_PREPARE();
		
		const unsigned char pattern[] = { 0x5E, 0xF6, 0xDB, 0x36 };
		
		ok(b.overwrite_data(4, pattern, 4), "Buffer::overwrite_data() returns true");
		
		OVERWRITE_SANITY();
		
		OVERWRITE_DIRTY(0, 8);
		OVERWRITE_UNLOADED(1);
		OVERWRITE_UNLOADED(2);
		
		const unsigned char new_block0[] = { 0x60, 0x96, 0x45, 0x74, 0x5E, 0xF6, 0xDB, 0x36 };
		
		is_blob(new_block0, b.blocks[0].data.data(), 8, "Block data loaded and updated correctly");
	}
	
	{
		diag("Overwriting start of second block...");
		
		OVERWRITE_PREPARE();
		
		const unsigned char pattern[] = { 0x5E, 0xF6, 0xDB, 0x36 };
		
		ok(b.overwrite_data(8, pattern, 4), "Buffer::overwrite_data() returns true");
		
		OVERWRITE_SANITY();
		
		OVERWRITE_UNLOADED(0);
		OVERWRITE_DIRTY(1, 8);
		OVERWRITE_UNLOADED(2);
		
		const unsigned char new_block1[] = { 0x5E, 0xF6, 0xDB, 0x36, 0x8D, 0xAC, 0xFC, 0xF8 };
		
		is_blob(new_block1, b.blocks[1].data.data(), 8, "Block data loaded and updated correctly");
	}
	
	{
		diag("Overwriting part of first and second block...");
		
		OVERWRITE_PREPARE();
		
		const unsigned char pattern[] = { 0x5E, 0xF6, 0xDB, 0x36 };
		
		ok(b.overwrite_data(6, pattern, 4), "Buffer::overwrite_data() returns true");
		
		OVERWRITE_SANITY();
		
		OVERWRITE_DIRTY(0, 8);
		OVERWRITE_DIRTY(1, 8);
		OVERWRITE_UNLOADED(2);
		
		const unsigned char new_block0[] = { 0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x5E, 0xF6 };
		const unsigned char new_block1[] = { 0xDB, 0x36, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8 };
		
		is_blob(new_block0, b.blocks[0].data.data(), 8, "Block data loaded and updated correctly");
		is_blob(new_block1, b.blocks[1].data.data(), 8, "Block data loaded and updated correctly");
	}
	
	{
		diag("Overwriting end of last block...");
		
		OVERWRITE_PREPARE();
		
		const unsigned char pattern[] = { 0x5E, 0xF6, 0xDB, 0x36 };
		
		ok(b.overwrite_data(19, pattern, 4), "Buffer::overwrite_data() returns true");
		
		OVERWRITE_SANITY();
		
		OVERWRITE_UNLOADED(0);
		OVERWRITE_UNLOADED(1);
		OVERWRITE_DIRTY(2, 7);
		
		const unsigned char new_block2[] = { 0x8B, 0xC8, 0x97, 0x5E, 0xF6, 0xDB, 0x36 };
		
		is_blob(new_block2, b.blocks[2].data.data(), 7, "Block data loaded and updated correctly");
	}
	
	{
		diag("Overwriting past end of last block...");
		
		OVERWRITE_PREPARE();
		
		const unsigned char pattern[] = { 0x5E, 0xF6, 0xDB, 0x36 };
		
		ok(!b.overwrite_data(20, pattern, 4), "Buffer::overwrite_data() returns false");
		
		OVERWRITE_SANITY();
		
		OVERWRITE_UNLOADED(0);
		OVERWRITE_UNLOADED(1);
		OVERWRITE_UNLOADED(2);
	}
	
	{
		diag("Overwriting from past end of last block...");
		
		OVERWRITE_PREPARE();
		
		const unsigned char pattern[] = { 0x5E, 0xF6, 0xDB, 0x36 };
		
		ok(!b.overwrite_data(30, pattern, 4), "Buffer::overwrite_data() returns false");
		
		OVERWRITE_SANITY();
		
		OVERWRITE_UNLOADED(0);
		OVERWRITE_UNLOADED(1);
		OVERWRITE_UNLOADED(2);
	}
	
	{
		diag("Overwriting whole buffer...");
		
		OVERWRITE_PREPARE();
		
		const unsigned char pattern[] = {
			0xFA, 0x7C, 0xB2, 0x77, 0xA1, 0x46, 0x66, 0x1D,
			0x5C, 0x74, 0x1D, 0x97, 0x0E, 0x1E, 0x8E, 0x5C,
			0x8E, 0x7D, 0xA3, 0x9E, 0x7B, 0xE5, 0x55,
		};
		
		ok(b.overwrite_data(0, pattern, 23), "Buffer::overwrite_data() returns true");
		
		OVERWRITE_SANITY();
		
		OVERWRITE_DIRTY(0, 8);
		OVERWRITE_DIRTY(1, 8);
		OVERWRITE_DIRTY(2, 7);
		
		is_blob(pattern,      b.blocks[0].data.data(), 8, "Block data updated correctly");
		is_blob(pattern + 8,  b.blocks[1].data.data(), 8, "Block data updated correctly");
		is_blob(pattern + 16, b.blocks[2].data.data(), 7, "Block data updated correctly");
	}
}

#define ERASE_PREPARE() \
	const unsigned char file_data[] = { \
		0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01, \
		0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8, \
		0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C, \
	}; \
	\
	write_file(TMPFILE, file_data, sizeof(file_data)); \
	\
	REHex::Buffer b(TMPFILE, 8);

#define ERASE_DIRTY(block_i, len) \
{ \
	ok((b.blocks[block_i].state == REHex::Buffer::Block::DIRTY), "Changed block marked dirty"); \
	ok((b.blocks[block_i].data.size() >= len), "Changed block has data buffer"); \
}

#define ERASE_UNLOADED(block_i) \
{ \
	ok((b.blocks[block_i].state == REHex::Buffer::Block::UNLOADED), "Unchanged block not loaded"); \
	ok(b.blocks[block_i].data.empty(), "Unchanged block has no data buffer"); \
}

static void erase_tests()
{
	{
		diag("Erasing data from start of first block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(0, 2), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(6, b.blocks[0].virt_length, "First block length reduced");
		ERASE_DIRTY(0, 6);
		
		is_int(6, b.blocks[1].virt_offset, "Second block offset reduced");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(14, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(7,  b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(21, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			/* 0x60, 0x96, */ 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing data from middle of first block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(2, 2), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(6, b.blocks[0].virt_length, "First block length reduced");
		ERASE_DIRTY(0, 6);
		
		is_int(6, b.blocks[1].virt_offset, "Second block offset reduced");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(14, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(7,  b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(21, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, /* 0x45, 0x74, */ 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing data from end of first block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(4, 4), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(4, b.blocks[0].virt_length, "First block length reduced");
		ERASE_DIRTY(0, 4);
		
		is_int(4, b.blocks[1].virt_offset, "Second block offset reduced");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(12, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(7,  b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(19, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, /* 0x7B, 0xDA, 0x7B, 0x01, */
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing whole first block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(0, 8), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(0, b.blocks[0].virt_length, "First block length reduced");
		ERASE_DIRTY(0, 0);
		
		is_int(0, b.blocks[1].virt_offset, "Second block offset reduced");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(8, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(7, b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(15, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			/* 0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01, */
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing data from start of second block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(8, 3), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(5, b.blocks[1].virt_length, "Second block length reduced");
		ERASE_DIRTY(1, 5);
		
		is_int(13, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(7,  b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(20, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			/* 0x1B, 0x84, 0x09, */ 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing data from end of second block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(14, 2), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(6, b.blocks[1].virt_length, "Second block length reduced");
		ERASE_DIRTY(1, 6);
		
		is_int(14, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(7,  b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(21, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, /* 0xFC, 0xF8, */
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
		
	}
	
	{
		diag("Erasing second block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(8, 8), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(0, b.blocks[1].virt_length, "Second block length reduced");
		ERASE_DIRTY(1, 0);
		
		is_int(8, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(7, b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(15, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			/* 0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8, */
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing part of first and second blocks...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(6, 8), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(6, b.blocks[0].virt_length, "First block length reduced");
		ERASE_DIRTY(0, 6);
		
		is_int(6, b.blocks[1].virt_offset, "Second block offset reduced");
		is_int(2, b.blocks[1].virt_length, "Second block length reduced");
		ERASE_DIRTY(1, 2);
		
		is_int(8, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(7, b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(15, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, /* 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, */ 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing all of first and second blocks...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(0, 16), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(0, b.blocks[0].virt_length, "First block length reduced");
		ERASE_DIRTY(0, 0);
		
		is_int(0, b.blocks[1].virt_offset, "Second block offset reduced");
		is_int(0, b.blocks[1].virt_length, "Second block length reduced");
		ERASE_DIRTY(1, 0);
		
		is_int(0, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(7, b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(7, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			/* 0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8, */
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing start of third block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(16, 2), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(16, b.blocks[2].virt_offset, "Third block offset unchanged");
		is_int(5,  b.blocks[2].virt_length, "Third block length reduced");
		ERASE_DIRTY(2, 5);
		
		is_int(21, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			/* 0x8B, 0xC8, */ 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing end of third block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(20, 3), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(16, b.blocks[2].virt_offset, "Third block offset unchanged");
		is_int(4,  b.blocks[2].virt_length, "Third block length reduced");
		ERASE_DIRTY(2, 4);
		
		is_int(20, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, /* 0xC4, 0x26, 0x2C, */
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing third block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(16, 7), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(16, b.blocks[2].virt_offset, "Third block offset unchanged");
		is_int(0,  b.blocks[2].virt_length, "Third block length reduced");
		ERASE_DIRTY(2, 0);
		
		is_int(16, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			/* 0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C, */
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing whole file...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(0, 23), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(0, b.blocks[0].virt_length, "First block length reduced");
		ERASE_DIRTY(0, 0);
		
		is_int(0, b.blocks[1].virt_offset, "Second block offset reduced");
		is_int(0, b.blocks[1].virt_length, "Second block length reduced");
		ERASE_DIRTY(1, 0);
		
		is_int(0, b.blocks[2].virt_offset, "Third block offset reduced");
		is_int(0, b.blocks[2].virt_length, "Third block length reduced");
		ERASE_DIRTY(2, 0);
		
		is_int(0, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			/* 0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C, */
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing beyond end of third block...");
		
		ERASE_PREPARE();
		
		ok(!b.erase_data(20, 4), "Buffer::erase_data() returns false");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(16, b.blocks[2].virt_offset, "Third block offset unchanged");
		is_int(7,  b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(23, b.length(), "Buffer::length() reflects unchanged file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing from end of third block...");
		
		ERASE_PREPARE();
		
		ok(!b.erase_data(23, 4), "Buffer::erase_data() returns false");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(16, b.blocks[2].virt_offset, "Third block offset unchanged");
		is_int(7,  b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(23, b.length(), "Buffer::length() reflects unchanged file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing from beyond end of third block...");
		
		ERASE_PREPARE();
		
		ok(!b.erase_data(30, 4), "Buffer::erase_data() returns false");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(16, b.blocks[2].virt_offset, "Third block offset unchanged");
		is_int(7,  b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(23, b.length(), "Buffer::length() reflects unchanged file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		diag("Erasing zero bytes from first block...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(0, 0), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(8, b.blocks[0].virt_length, "First block length unchanged");
		ERASE_UNLOADED(0);
		
		is_int(8, b.blocks[1].virt_offset, "Second block offset unchanged");
		is_int(8, b.blocks[1].virt_length, "Second block length unchanged");
		ERASE_UNLOADED(1);
		
		is_int(16, b.blocks[2].virt_offset, "Third block offset unchanged");
		is_int(7,  b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_UNLOADED(2);
		
		is_int(23, b.length(), "Buffer::length() reflects unchanged file length");
		
		const unsigned char expect_data[] = {
			0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C,
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
	
	{
		/* Test erasing in sequence so we can see erase_data() handles
		 * zero-length blocks and blocks with the same offset correctly.
		*/
		
		diag("Erasing all blocks, in sequence...");
		
		ERASE_PREPARE();
		
		ok(b.erase_data(0, 8), "Buffer::erase_data() returns true");
		ok(b.erase_data(0, 8), "Buffer::erase_data() returns true");
		ok(b.erase_data(0, 7), "Buffer::erase_data() returns true");
		
		is_int(0, b.blocks[0].virt_offset, "First block offset unchanged");
		is_int(0, b.blocks[0].virt_length, "First block length reduced");
		ERASE_DIRTY(0, 0);
		
		is_int(0, b.blocks[1].virt_offset, "Second block offset reduced");
		is_int(0, b.blocks[1].virt_length, "Second block length reduced");
		ERASE_DIRTY(1, 0);
		
		is_int(0, b.blocks[2].virt_offset, "Third block offset unchanged");
		is_int(0, b.blocks[2].virt_length, "Third block length unchanged");
		ERASE_DIRTY(2, 0);
		
		is_int(0, b.length(), "Buffer::length() reflects new file length");
		
		const unsigned char expect_data[] = {
			/* 0x60, 0x96, 0x45, 0x74, 0x7B, 0xDA, 0x7B, 0x01,
			0x1B, 0x84, 0x09, 0x76, 0x8D, 0xAC, 0xFC, 0xF8,
			0x8B, 0xC8, 0x97, 0x84, 0xC4, 0x26, 0x2C, */
		};
		
		std::vector<unsigned char> data = b.read_data(0, 40);
		
		is_int(sizeof(expect_data), data.size(), "Buffer::read_data() returns correct number of bytes")
			&& is_blob(expect_data, data.data(), sizeof(expect_data), "Buffer::read_data() returns correct data");
	}
}

static void insert_tests()
{
	{
		const unsigned char BEGIN_DATA[] = {};
		const unsigned char END_DATA[]   = { 0xAA, 0xBB, 0xCC, 0xDD };
		
		TEST_BUFFER_MANIP(
			"Inserting into an empty file",
			{
				TEST_INSERT_OK(0, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 4);
				});
				
				TEST_LENGTH(4);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {};
		const unsigned char END_DATA[]   = { 0xAA, 0x00, 0x11, 0xBB, 0xCC, 0xEE, 0xFF, 0xDD };
		
		TEST_BUFFER_MANIP(
			"Multiple inserts into an empty file",
			{
				TEST_INSERT_OK(0, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				TEST_INSERT_OK(3, ((const unsigned char[]){ 0xEE, 0xFF }));
				TEST_INSERT_OK(1, ((const unsigned char[]){ 0x00, 0x11 }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {};
		const unsigned char END_DATA[]   = {};
		
		TEST_BUFFER_MANIP(
			"Inserting beyond the end of an empty file",
			{
				TEST_INSERT_FAIL(1, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 0);
				});
				
				TEST_LENGTH(0);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
		};
		
		const unsigned char END_DATA[] = {
			0xAA, 0xBB, 0xCC, 0xDD,
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting at the start of a <1 block file",
			{
				TEST_INSERT_OK(0, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 10);
				});
				
				TEST_LENGTH(10);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
		};
		
		const unsigned char END_DATA[] = {
			0x68, 0xAB,
			0xAA, 0xBB, 0xCC, 0xDD,
			0x8A, 0xEF, 0x5F, 0xCA,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting into a <1 block file",
			{
				TEST_INSERT_OK(2, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 10);
				});
				
				TEST_LENGTH(10);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
		};
		
		const unsigned char END_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
			0xAA, 0xBB, 0xCC, 0xDD,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting at the end of a <1 block file",
			{
				TEST_INSERT_OK(6, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 10);
				});
				
				TEST_LENGTH(10);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
		};
		
		const unsigned char END_DATA[] = {
			/* > */ 0xAA, 0x00, 0x11, 0xBB, 0xCC, 0xDD, /* < */
			0x68, 0xAB, /* > */ 0xEE, 0xFF, /* < */ 0x8A, 0xEF, 0x5F, 0xCA,
			
		};
		
		TEST_BUFFER_MANIP(
			"Multiple inserts into a <1 block file",
			{
				TEST_INSERT_OK(0, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 10);
				});
				
				TEST_INSERT_OK(6, ((const unsigned char[]){ 0xEE, 0xFF }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 12);
				});
				
				TEST_INSERT_OK(1, ((const unsigned char[]){ 0x00, 0x11 }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 14);
				});
				
				TEST_LENGTH(14);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
		};
		
		const unsigned char END_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting beyond the end of a <1 block file",
			{
				TEST_INSERT_FAIL(7, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 6);
				});
				
				TEST_LENGTH(6);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		};
		
		const unsigned char END_DATA[] = {
			0xAA, 0xBB, 0xCC, 0xDD,
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting at the start of a 1 block file",
			{
				TEST_INSERT_OK(0, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 12);
				});
				
				TEST_LENGTH(12);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		};
		
		const unsigned char END_DATA[] = {
			0x68, 0xAB,
			0xAA, 0xBB, 0xCC, 0xDD,
			0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting into a 1 block file",
			{
				TEST_INSERT_OK(2, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 12);
				});
				
				TEST_LENGTH(12);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		};
		
		const unsigned char END_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
			0xAA, 0xBB, 0xCC, 0xDD,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting at the end of a 1 block file",
			{
				TEST_INSERT_OK(8, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 12);
				});
				
				TEST_LENGTH(12);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		};
		
		const unsigned char END_DATA[] = {
			0xAA, 0x00, 0x11, 0xBB, 0xCC, 0xDD,
			0x68, 0xAB, 0xEE, 0xFF, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		};
		
		TEST_BUFFER_MANIP(
			"Multiple inserts into a 1 block file",
			{
				TEST_INSERT_OK(0, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 12);
				});
				
				TEST_INSERT_OK(6, ((const unsigned char[]){ 0xEE, 0xFF }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 14);
				});
				
				TEST_INSERT_OK(1, ((const unsigned char[]){ 0x00, 0x11 }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 16);
				});
				
				TEST_LENGTH(16);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		};
		
		const unsigned char END_DATA[] = {
			0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting beyond the end of a 1 block file",
			{
				TEST_INSERT_FAIL(9, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		const unsigned char END_DATA[] = {
			0xAA, 0xBB, 0xCC, 0xDD,
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting at the start of a 4 block file",
			{
				TEST_INSERT_OK(0, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		const unsigned char END_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8,
			                              0xAA, 0xBB, 0xCC, 0xDD,
			                              0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting into the first block in a 4 block file",
			{
				TEST_INSERT_OK(5, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		const unsigned char END_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xAA, 0xBB, 0xCC, 0xDD,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting at the start of a block in a 4 block file",
			{
				TEST_INSERT_OK(16, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		const unsigned char END_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0,
			      0xAA, 0xBB, 0xCC, 0xDD,
			      0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting into a block in a 4 block file",
			{
				TEST_INSERT_OK(17, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		const unsigned char END_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0xAA, 0xBB, 0xCC, 0xDD,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting at the start of the last block in a 4 block file",
			{
				TEST_INSERT_OK(24, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		const unsigned char END_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24,
			            0xAA, 0xBB, 0xCC, 0xDD,
			            0x3C, 0x43, 0xE1,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting into the last block in a 4 block file",
			{
				TEST_INSERT_OK(26, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		const unsigned char END_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
			                              0xAA, 0xBB, 0xCC, 0xDD,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting at the end of the last block in a 4 block file",
			{
				TEST_INSERT_OK(29, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		const unsigned char END_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, /* > */ 0xAA, 0xBB, 0xCC, 0xDD, /* < */ 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, /* > */ 0x00, 0x11, /* < */ 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, /* > */ 0xEE, 0xFF, /* < */ 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		TEST_BUFFER_MANIP(
			"Multiple inserts into a 4 block file",
			{
				TEST_INSERT_OK(4,  ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				TEST_INSERT_OK(22, ((const unsigned char[]){ 0xEE, 0xFF }));
				TEST_INSERT_OK(16, ((const unsigned char[]){ 0x00, 0x11 }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		const unsigned char END_DATA[] = {
			0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
			0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
			0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
			0x7D, 0x24, 0x3C, 0x43, 0xE1,
		};
		
		TEST_BUFFER_MANIP(
			"Inserting beyond the end of a 4 block file",
			{
				TEST_INSERT_FAIL(30, ((const unsigned char[]){ 0xAA, 0xBB, 0xCC, 0xDD }));
				
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
}

int main()
{
	plan_lazy();
	
	ctor_tests();
	read_data_tests();
	overwrite_tests();
	erase_tests();
	insert_tests();
	
	return 0;
}
