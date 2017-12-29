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
#include <errno.h>
#include <fcntl.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
} \
{ \
	diag(desc ", checking result with write_inplace(<filename>) (same file)"); \
	write_file(TMPFILE, BEGIN_DATA, sizeof(BEGIN_DATA)); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	b.write_inplace(TMPFILE); \
	std::vector<unsigned char> data = read_file(TMPFILE); \
	is_int(sizeof(END_DATA), data.size(), "File is correct length") \
		&& is_blob(END_DATA, data.data(), sizeof(END_DATA), "File contains correct data"); \
} \
{ \
	diag(desc ", checking result with write_inplace(<filename>) (new file)"); \
	write_file(TMPFILE, BEGIN_DATA, sizeof(BEGIN_DATA)); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	assert(unlink(TMPFILE2) == 0 || errno == ENOENT);\
	b.write_inplace(TMPFILE2); \
	std::vector<unsigned char> data = read_file(TMPFILE2); \
	is_int(sizeof(END_DATA), data.size(), "File is correct length") \
		&& is_blob(END_DATA, data.data(), sizeof(END_DATA), "File contains correct data"); \
} \
if(sizeof(END_DATA) > 0) \
{ \
	diag(desc ", checking result with write_inplace(<filename>) (smaller file)"); \
	write_file(TMPFILE, BEGIN_DATA, sizeof(BEGIN_DATA)); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	std::vector<unsigned char> tf2data((sizeof(END_DATA) - 1), 0xFF); \
	write_file(TMPFILE2, tf2data.data(), tf2data.size()); \
	b.write_inplace(TMPFILE2); \
	std::vector<unsigned char> data = read_file(TMPFILE2); \
	is_int(sizeof(END_DATA), data.size(), "File is correct length") \
		&& is_blob(END_DATA, data.data(), sizeof(END_DATA), "File contains correct data"); \
} \
{ \
	diag(desc ", checking result with write_inplace(<filename>) (larger file)"); \
	write_file(TMPFILE, BEGIN_DATA, sizeof(BEGIN_DATA)); \
	REHex::Buffer b(TMPFILE, 8); \
	buffer_manip_code; \
	std::vector<unsigned char> tf2data((sizeof(END_DATA) + 1), 0xFF); \
	write_file(TMPFILE2, tf2data.data(), tf2data.size()); \
	b.write_inplace(TMPFILE2); \
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

#define TEST_OVERWRITE_OK(offset, data) \
{ \
	ok(b.overwrite_data(offset, data, sizeof(data)), "Buffer::overwrite_data() returns true"); \
}

#define TEST_OVERWRITE_FAIL(offset, data) \
{ \
	ok(!b.overwrite_data(offset, data, sizeof(data)), "Buffer::overwrite_data() returns false"); \
}

#define TEST_ERASE_OK(offset, length) \
{ \
	ok(b.erase_data(offset, length), "Buffer::erase_data() returns true"); \
}

#define TEST_ERASE_FAIL(offset, length) \
{ \
	ok(!b.erase_data(offset, length), "Buffer::erase_data() returns false"); \
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

static void overwrite_tests()
{
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0xF0, 0x0D, 0x77, 0xA4, 0xE2,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting start of a <1 block file",
			{
				TEST_OVERWRITE_OK(0, ((const unsigned char[]){ 0xF0, 0x0D }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 5);
				});
				
				TEST_LENGTH(5);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0xF8, 0xD1, 0x77, 0xF0, 0x0D,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting end of a <1 block file",
			{
				TEST_OVERWRITE_OK(3, ((const unsigned char[]){ 0xF0, 0x0D }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 5);
				});
				
				TEST_LENGTH(5);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0x65, 0x87, 0x49, 0x7A, 0x06,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting all of a <1 block file",
			{
				TEST_OVERWRITE_OK(0, ((const unsigned char[]){ 0x65, 0x87, 0x49, 0x7A, 0x06, }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 5);
				});
				
				TEST_LENGTH(5);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting more than all of a <1 block file",
			{
				TEST_OVERWRITE_FAIL(0, ((const unsigned char[]){ 0x65, 0x87, 0x49, 0x7A, 0x06, 0xAA }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 5);
				});
				
				TEST_LENGTH(5);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting beyond end of a <1 block file",
			{
				TEST_OVERWRITE_FAIL(5, ((const unsigned char[]){ 0x65 }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 5);
				});
				
				TEST_LENGTH(5);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			0xF0, 0x0D, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting start of a 1 block file",
			{
				TEST_OVERWRITE_OK(0, ((const unsigned char[]){ 0xF0, 0x0D }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0xF0, 0x0D,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting end of a 1 block file",
			{
				TEST_OVERWRITE_OK(6, ((const unsigned char[]){ 0xF0, 0x0D }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			0x34, 0x89, 0x3D, 0x7B, 0x6F, 0xBF, 0x13, 0xC0,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting all of a 1 block file",
			{
				TEST_OVERWRITE_OK(0, ((const unsigned char[]){ 0x34, 0x89, 0x3D, 0x7B, 0x6F, 0xBF, 0x13, 0xC0, }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting more than all of a 1 block file",
			{
				TEST_OVERWRITE_FAIL(0, ((const unsigned char[]){ 0x87, 0x6A, 0x6E, 0xCB, 0xB3, 0x99, 0xF4, 0xE7, 0xAA }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting beyond end of a 1 block file",
			{
				TEST_OVERWRITE_FAIL(8, ((const unsigned char[]){ 0x65 }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0xF0, 0x0D, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting start of the first block in a 4 block file",
			{
				TEST_OVERWRITE_OK(0, ((const unsigned char[]){ 0xF0, 0x0D }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0xF0, 0x0D,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting end of the first block in a 4 block file",
			{
				TEST_OVERWRITE_OK(6, ((const unsigned char[]){ 0xF0, 0x0D }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xF0, 0x0D, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting start of the second block in a 4 block file",
			{
				TEST_OVERWRITE_OK(8, ((const unsigned char[]){ 0xF0, 0x0D }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0xF0, 0x0D,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting end of the second block in a 4 block file",
			{
				TEST_OVERWRITE_OK(14, ((const unsigned char[]){ 0xF0, 0x0D }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0xF0, 0x0D, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting start of the last block in a 4 block file",
			{
				TEST_OVERWRITE_OK(24, ((const unsigned char[]){ 0xF0, 0x0D }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0xF0, 0x0D,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting end of the last block in a 4 block file",
			{
				TEST_OVERWRITE_OK(28, ((const unsigned char[]){ 0xF0, 0x0D }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0xF0, 0x0D,
			0xB4, 0x70, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting part of first and second blocks in a 4 block file",
			{
				TEST_OVERWRITE_OK(6, ((const unsigned char[]){ 0xF0, 0x0D, 0xB4, 0x70 }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x6A, 0xD1, 0xBE, 0x3A, 0x09, 0x75, 0xD8, 0x7E,
			0x27, 0x4F, 0xEF, 0xAF, 0xE2, 0x4E, 0x04, 0xAA,
			0x35, 0x0C, 0xFD, 0xCF, 0x07, 0xDD, 0xE4, 0x7F,
			0xF5, 0x69, 0x64, 0x35, 0xB1, 0x9A,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting all of a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char TOOMUCH[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9, 0xAA
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting more than all of a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Overwriting beyond end of a 4 block file",
			{
				TEST_OVERWRITE_FAIL(30, ((const unsigned char[]){ 0x65 }));
				
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
	
	{
		const unsigned char BEGIN_DATA[] = {};
		const unsigned char END_DATA[]   = {};
		
		TEST_BUFFER_MANIP(
			"Overwriting at start of an empty file",
			{
				TEST_OVERWRITE_FAIL(0, ((const unsigned char[]){ 0x65 }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 0);
				});
				
				TEST_LENGTH(0);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {};
		const unsigned char END_DATA[]   = {};
		
		TEST_BUFFER_MANIP(
			"Overwriting in an empty file",
			{
				TEST_OVERWRITE_FAIL(2, ((const unsigned char[]){ 0x65 }));
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 0);
				});
				
				TEST_LENGTH(0);
			}
		);
	}
}

static void erase_tests()
{
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0x77, 0xA4, 0xE2,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing start of a <1 block file",
			{
				TEST_ERASE_OK(0, 2);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 3);
				});
				
				TEST_LENGTH(3);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0xF8, 0xD1,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing end of a <1 block file",
			{
				TEST_ERASE_OK(2, 3);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 2);
				});
				
				TEST_LENGTH(2);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0xF8, 0xD1, 0xE2,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing part of a <1 block file",
			{
				TEST_ERASE_OK(2, 2);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 3);
				});
				
				TEST_LENGTH(3);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {};
		
		TEST_BUFFER_MANIP(
			"Erasing all of a <1 block file",
			{
				TEST_ERASE_OK(0, 5);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 0);
				});
				
				TEST_LENGTH(0);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing more than all of a <1 block file",
			{
				TEST_ERASE_FAIL(0, 6);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 5);
				});
				
				TEST_LENGTH(5);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		const unsigned char END_DATA[] = {
			0xF8, 0xD1, 0x77, 0xA4, 0xE2,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing beyond end of a <1 block file",
			{
				TEST_ERASE_FAIL(5, 1);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 5);
				});
				
				TEST_LENGTH(5);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			/* 0xF0, 0x0D, */ 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing start of a 1 block file",
			{
				TEST_ERASE_OK(0, 2);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 6);
				});
				
				TEST_LENGTH(6);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, /* 0x74, 0x50, 0xD2, */
		};
		
		TEST_BUFFER_MANIP(
			"Erasing end of a 1 block file",
			{
				TEST_ERASE_OK(5, 3);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 5);
				});
				
				TEST_LENGTH(5);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			0x09, 0x7E, /* 0x9B, 0x25, 0xCB, 0x74, */ 0x50, 0xD2,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing part of a 1 block file",
			{
				TEST_ERASE_OK(2, 4);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 4);
				});
				
				TEST_LENGTH(4);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			/* 0x34, 0x89, 0x3D, 0x7B, 0x6F, 0xBF, 0x13, 0xC0, */
		};
		
		TEST_BUFFER_MANIP(
			"Erasing all of a 1 block file",
			{
				TEST_ERASE_OK(0, 8);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(DIRTY, 0, 0);
				});
				
				TEST_LENGTH(0);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing more than all of a 1 block file",
			{
				TEST_ERASE_FAIL(0, 9);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		const unsigned char END_DATA[] = {
			0x09, 0x7E, 0x9B, 0x25, 0xCB, 0x74, 0x50, 0xD2,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing beyond end of a 1 block file",
			{
				TEST_ERASE_FAIL(8, 1);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			/* 0x06, 0x96, */ 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing start of the first block in a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, /* 0xB5, 0x99, 0x4E, */
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing end of the first block in a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			/* 0xE7, 0xA8, 0x06, */ 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing start of the second block in a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, /* 0x8C, 0xD1, */
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing end of the second block in a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			/* 0x51, 0xA0, */ 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing start of the last block in a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, /* 0x67, 0xC9, */
		};
		
		TEST_BUFFER_MANIP(
			"Erasing end of the last block in a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, /* 0x99, 0x4E,
			0xE7, 0xA8, */ 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing part of first and second blocks in a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, /* 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, */ 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing all but the start/end in a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {};
		
		TEST_BUFFER_MANIP(
			"Erasing all of a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing more than all of a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing beyond end of a 4 block file",
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
	
	{
		const unsigned char BEGIN_DATA[] = {};
		const unsigned char END_DATA[]   = {};
		
		TEST_BUFFER_MANIP(
			"Erasing at start of an empty file",
			{
				TEST_ERASE_FAIL(0, 1);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 0);
				});
				
				TEST_LENGTH(0);
			}
		);
	}
	
	{
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		};
		
		const unsigned char END_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing zero bytes from a file",
			{
				TEST_ERASE_OK(0, 0);
				
				TEST_BLOCKS({
					TEST_BLOCK_DEF(UNLOADED, 0, 8);
				});
				
				TEST_LENGTH(8);
			}
		);
	}
	
	{
		/* Test erasing in sequence so we can see erase_data() handles
		 * zero-length blocks and blocks with the same offset correctly.
		*/
		
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			/* 0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E, */
			/* 0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1, */
			/* 0xE0, 0x3B, 0x0F, 0x7C, */ 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing blocks in sequence",
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
	
	{
		/* Test erasing in sequence so we can see erase_data() handles
		 * zero-length blocks and blocks with the same offset correctly.
		*/
		
		const unsigned char BEGIN_DATA[] = {
			0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E,
			0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1,
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			0x51, 0xA0, 0x0D, 0xAD, 0x67, 0xC9,
		};
		
		const unsigned char END_DATA[] = {
			/* 0x06, 0x96, 0x64, 0x58, 0xC9, 0xB5, 0x99, 0x4E, */
			/* 0xE7, 0xA8, 0x06, 0x24, 0xEC, 0xB6, 0x8C, 0xD1, */
			0xE0, 0x3B, 0x0F, 0x7C, 0xAD, 0x80, 0xB3, 0xB4,
			/* 0x51, 0xA0, 0x0D, 0xAD, */ 0x67, 0xC9,
		};
		
		TEST_BUFFER_MANIP(
			"Erasing blocks in non-contiguous sequence",
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
