/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#define TEST_OVERWRITE_BITS_OK(offset, ...) \
{ \
	EXPECT_TRUE(b.overwrite_bits(offset, std::vector<bool>({ __VA_ARGS__ }))) << "Buffer::overwrite_data() returns true"; \
}

#define TEST_OVERWRITE_BITS_FAIL(offset, ...) \
{ \
	EXPECT_FALSE(b.overwrite_bits(offset, std::vector<bool>({ __VA_ARGS__ }))) << "Buffer::overwrite_data() returns false"; \
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
