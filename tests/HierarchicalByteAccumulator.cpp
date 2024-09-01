/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <vector>

#include "testutil.hpp"
#include "../src/HierarchicalByteAccumulator.hpp"
#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

static void append_block(Document *document, size_t block_size, const std::vector<unsigned char> &base_data = {})
{
	std::vector<unsigned char> data(block_size, 0);
	memcpy(data.data(), base_data.data(), base_data.size());
	
	document->insert_data(document->buffer_length(), data.data(), data.size());
}

TEST(HierarchicalByteAccumulator, SmallFileFullRange)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	append_block(document, 1024, { 4, 2, 1 });
	append_block(document, 1024, { 4, 10 });
	
	HierarchicalByteAccumulator hba(document, BitOffset(0, 0), 2048);
	
	hba.wait_for_completion();
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), 2048U);
	EXPECT_EQ(result.get_byte_sum(), 21U);
	
	EXPECT_EQ(result.get_byte_count(0), 2043U);
	EXPECT_EQ(result.get_byte_count(1), 1U);
	EXPECT_EQ(result.get_byte_count(2), 1U);
	EXPECT_EQ(result.get_byte_count(3), 0U);
	EXPECT_EQ(result.get_byte_count(4), 2U);
	EXPECT_EQ(result.get_byte_count(10), 1U);
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 10U);
}

TEST(HierarchicalByteAccumulator, SmallFilePartialRange)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	append_block(document, 1024, { 4, 2, 1 });
	append_block(document, 1024, { 4, 10 });
	
	{
		HierarchicalByteAccumulator hba(document, BitOffset(1, 0), 100);
		
		hba.wait_for_completion();
		ByteAccumulator result = hba.get_result();
		
		EXPECT_EQ(result.get_total_bytes(), 100U);
		EXPECT_EQ(result.get_byte_sum(), 3U);
		
		EXPECT_EQ(result.get_byte_count(0), 98U);
		EXPECT_EQ(result.get_byte_count(1), 1U);
		EXPECT_EQ(result.get_byte_count(2), 1U);
		EXPECT_EQ(result.get_byte_count(3), 0U);
		EXPECT_EQ(result.get_byte_count(4), 0U);
		EXPECT_EQ(result.get_byte_count(10), 0U);
		
		EXPECT_EQ(result.get_min_byte(), 0U);
		EXPECT_EQ(result.get_max_byte(), 2U);
	}
	
	{
		HierarchicalByteAccumulator hba(document, BitOffset(1024, 0), 2);
		
		hba.wait_for_completion();
		ByteAccumulator result = hba.get_result();
		
		EXPECT_EQ(result.get_total_bytes(), 2U);
		EXPECT_EQ(result.get_byte_sum(), 14U);
		
		EXPECT_EQ(result.get_byte_count (0), 0U);
		EXPECT_EQ(result.get_byte_count (1), 0U);
		EXPECT_EQ(result.get_byte_count (2), 0U);
		EXPECT_EQ(result.get_byte_count (3), 0U);
		EXPECT_EQ(result.get_byte_count (4), 1U);
		EXPECT_EQ(result.get_byte_count(10), 1U);
		
		EXPECT_EQ(result.get_min_byte(), 4U);
		EXPECT_EQ(result.get_max_byte(), 10U);
	}
}

TEST(HierarchicalByteAccumulator, BitAlignment)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	append_block(document, 1024, { 4, 2, 1 });
	append_block(document, 1024, { 4, 10 });
	
	{
		HierarchicalByteAccumulator hba(document, BitOffset(1024, 2), 100);
		
		hba.wait_for_completion();
		ByteAccumulator result = hba.get_result();
		
		EXPECT_EQ(result.get_total_bytes(), 100U);
		EXPECT_EQ(result.get_byte_sum(), 56U);
		
		EXPECT_EQ(result.get_byte_count(0), 98U);
		EXPECT_EQ(result.get_byte_count(1), 0U);
		EXPECT_EQ(result.get_byte_count(2), 0U);
		EXPECT_EQ(result.get_byte_count(3), 0U);
		EXPECT_EQ(result.get_byte_count(16), 1U);
		EXPECT_EQ(result.get_byte_count(40), 1U);
		
		EXPECT_EQ(result.get_min_byte(), 0U);
		EXPECT_EQ(result.get_max_byte(), 40U);
	}
}

TEST(HierarchicalByteAccumulator, SingleChunk)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	append_block(document, HierarchicalByteAccumulator::CHUNK_SIZE, { 4, 4, 1 });
	
	{
		HierarchicalByteAccumulator hba(document, BitOffset(0, 0), document->buffer_length());
		
		hba.wait_for_completion();
		ByteAccumulator result = hba.get_result();
		
		EXPECT_EQ((off_t)(result.get_total_bytes()), document->buffer_length());
		EXPECT_EQ(result.get_byte_sum(), 9U);
		
		EXPECT_EQ(result.get_byte_count(1),  1U);
		EXPECT_EQ(result.get_byte_count(2),  0U);
		EXPECT_EQ(result.get_byte_count(4),  2U);
		EXPECT_EQ(result.get_byte_count(16), 0U);
		
		EXPECT_EQ(result.get_min_byte(), 0U);
		EXPECT_EQ(result.get_max_byte(), 4U);
	}
}

TEST(HierarchicalByteAccumulator, SingleChunkAndSome)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	append_block(document, HierarchicalByteAccumulator::CHUNK_SIZE, { 4, 4, 1 });
	append_block(document, 10, { 8, 8 });
	
	{
		HierarchicalByteAccumulator hba(document, BitOffset(0, 0), document->buffer_length());
		
		hba.wait_for_completion();
		ByteAccumulator result = hba.get_result();
		
		EXPECT_EQ((off_t)(result.get_total_bytes()), document->buffer_length());
		EXPECT_EQ(result.get_byte_sum(), 25U);
		
		EXPECT_EQ(result.get_byte_count(1), 1U);
		EXPECT_EQ(result.get_byte_count(2), 0U);
		EXPECT_EQ(result.get_byte_count(4), 2U);
		EXPECT_EQ(result.get_byte_count(8), 2U);
		
		EXPECT_EQ(result.get_min_byte(), 0U);
		EXPECT_EQ(result.get_max_byte(), 8U);
	}
}

TEST(HierarchicalByteAccumulator, AlmostFullL1Cache)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	for(size_t i = 0; i < (HierarchicalByteAccumulator::L1_CACHE_SIZE - 1); ++i)
	{
		append_block(document, HierarchicalByteAccumulator::CHUNK_SIZE, {});
	}
	
	append_block(document, 10, { 4, 4, 1 });
	
	{
		HierarchicalByteAccumulator hba(document, BitOffset(0, 0), document->buffer_length());
		
		hba.wait_for_completion();
		ByteAccumulator result = hba.get_result();
		
		EXPECT_EQ((off_t)(result.get_total_bytes()), document->buffer_length());
		EXPECT_EQ(result.get_byte_sum(), 9U);
		
		EXPECT_EQ(result.get_byte_count(1), 1U);
		EXPECT_EQ(result.get_byte_count(2), 0U);
		EXPECT_EQ(result.get_byte_count(4), 2U);
		EXPECT_EQ(result.get_byte_count(8), 0U);
		
		EXPECT_EQ(result.get_min_byte(), 0U);
		EXPECT_EQ(result.get_max_byte(), 4U);
	}
}

TEST(HierarchicalByteAccumulator, FullL1Cache)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	for(size_t i = 0; i < (HierarchicalByteAccumulator::L1_CACHE_SIZE - 1); ++i)
	{
		append_block(document, HierarchicalByteAccumulator::CHUNK_SIZE, {});
	}
	
	append_block(document, HierarchicalByteAccumulator::CHUNK_SIZE, { 4, 4, 1 });
	
	{
		HierarchicalByteAccumulator hba(document, BitOffset(0, 0), document->buffer_length());
		
		hba.wait_for_completion();
		ByteAccumulator result = hba.get_result();
		
		EXPECT_EQ((off_t)(result.get_total_bytes()), document->buffer_length());
		EXPECT_EQ(result.get_byte_sum(), 9U);
		
		EXPECT_EQ(result.get_byte_count(1), 1U);
		EXPECT_EQ(result.get_byte_count(2), 0U);
		EXPECT_EQ(result.get_byte_count(4), 2U);
		EXPECT_EQ(result.get_byte_count(8), 0U);
		
		EXPECT_EQ(result.get_min_byte(), 0U);
		EXPECT_EQ(result.get_max_byte(), 4U);
	}
}

TEST(HierarchicalByteAccumulator, FullL1CacheAndHalf)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	for(size_t i = 0; i < (HierarchicalByteAccumulator::L1_CACHE_SIZE + (HierarchicalByteAccumulator::L1_CACHE_SIZE / 2) - 1); ++i)
	{
		append_block(document, HierarchicalByteAccumulator::CHUNK_SIZE, {});
	}
	
	append_block(document, HierarchicalByteAccumulator::CHUNK_SIZE, { 4, 4, 1 });
	
	{
		HierarchicalByteAccumulator hba(document, BitOffset(0, 0), document->buffer_length());
		
		hba.wait_for_completion();
		ByteAccumulator result = hba.get_result();
		
		EXPECT_EQ((off_t)(result.get_total_bytes()), document->buffer_length());
		EXPECT_EQ(result.get_byte_sum(), 9U);
		
		EXPECT_EQ(result.get_byte_count(1), 1U);
		EXPECT_EQ(result.get_byte_count(2), 0U);
		EXPECT_EQ(result.get_byte_count(4), 2U);
		EXPECT_EQ(result.get_byte_count(8), 0U);
		
		EXPECT_EQ(result.get_min_byte(), 0U);
		EXPECT_EQ(result.get_max_byte(), 4U);
	}
}

TEST(HierarchicalByteAccumulator, FullL1CacheAndHalfAndSome)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	for(size_t i = 0; i < (HierarchicalByteAccumulator::L1_CACHE_SIZE + (HierarchicalByteAccumulator::L1_CACHE_SIZE / 2) - 1); ++i)
	{
		append_block(document, HierarchicalByteAccumulator::CHUNK_SIZE, {});
	}
	
	append_block(document, HierarchicalByteAccumulator::CHUNK_SIZE, { 4, 4, 1 });
	append_block(document, 10, { 8, 8 });
	
	{
		HierarchicalByteAccumulator hba(document, BitOffset(0, 0), document->buffer_length());
		
		hba.wait_for_completion();
		ByteAccumulator result = hba.get_result();
		
		EXPECT_EQ((off_t)(result.get_total_bytes()), document->buffer_length());
		EXPECT_EQ(result.get_byte_sum(), 25U);
		
		EXPECT_EQ(result.get_byte_count(1), 1U);
		EXPECT_EQ(result.get_byte_count(2), 0U);
		EXPECT_EQ(result.get_byte_count(4), 2U);
		EXPECT_EQ(result.get_byte_count(8), 2U);
		
		EXPECT_EQ(result.get_min_byte(), 0U);
		EXPECT_EQ(result.get_max_byte(), 8U);
	}
}
