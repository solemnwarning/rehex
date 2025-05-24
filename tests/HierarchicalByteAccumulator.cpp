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
#include <vector>

#include "testutil.hpp"
#include "../src/DataView.hpp"
#include "../src/HierarchicalByteAccumulator.hpp"
#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

static void append_block(Document *document, size_t block_size, const std::vector<unsigned char> &base_data = {})
{
	std::vector<unsigned char> data(block_size, 0);
	memcpy(data.data(), base_data.data(), base_data.size());
	
	document->insert_data(document->buffer_length(), data.data(), data.size());
}

TEST(HierarchicalByteAccumulator, SmallFile)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	append_block(document, 1024, { 4, 2, 1 });
	append_block(document, 1024, { 4, 10 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document));
	
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
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 1U);
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, 2048);
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), 2048U);
		EXPECT_EQ(shards[0].result.get_byte_sum(), 21U);
		
		EXPECT_EQ(shards[0].result.get_byte_count(0), 2043U);
		EXPECT_EQ(shards[0].result.get_byte_count(1), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(2), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(3), 0U);
		EXPECT_EQ(shards[0].result.get_byte_count(4), 2U);
		EXPECT_EQ(shards[0].result.get_byte_count(10), 1U);
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 10U);
	}
}

TEST(HierarchicalByteAccumulator, BigFile)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	uint64_t byte_sum = 0;
	
	for(int i = 0; i < 100; ++i)
	{
		std::vector<unsigned char> data((1024 * 1024), i);
		document->insert_data(document->buffer_length(), data.data(), data.size());
		
		byte_sum += (1024 * 1024 * i);
	}
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document));
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), (1024U * 1024U * 100U));
	EXPECT_EQ(result.get_byte_sum(), byte_sum);
	
	for(int i = 0; i < 100; ++i)
	{
		EXPECT_EQ(result.get_byte_count(i), (1024U * 1024U));
	}
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 99U);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 1U);
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, (1024U * 1024U * 100U));
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), (1024U * 1024U * 100U));
		EXPECT_EQ(shards[0].result.get_byte_sum(), byte_sum);
		
		for(int i = 0; i < 100; ++i)
		{
			EXPECT_EQ(shards[0].result.get_byte_count(i), (1024U * 1024U));
		}
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 99U);
	}
}

TEST(HierarchicalByteAccumulator, SmallFileEvenShards)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	append_block(document, 1024, { 4, 2, 1 });
	append_block(document, 1024, { 4, 10 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 4);
	
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
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	EXPECT_EQ(shards.size(), 4U);
	
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, 512);
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), 512U);
		EXPECT_EQ(shards[0].result.get_byte_sum(), 7U);
		
		EXPECT_EQ(shards[0].result.get_byte_count(0), 509U);
		EXPECT_EQ(shards[0].result.get_byte_count(1), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(2), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(3), 0U);
		EXPECT_EQ(shards[0].result.get_byte_count(4), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(10), 0U);
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 4U);
	}
	
	if(shards.size() >= 2)
	{
		EXPECT_EQ(shards[1].offset, BitOffset(512, 0));
		EXPECT_EQ(shards[1].length, 512);
		
		EXPECT_EQ(shards[1].result.get_total_bytes(), 512U);
		EXPECT_EQ(shards[1].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[1].result.get_byte_count(0), 512U);
		EXPECT_EQ(shards[1].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(3), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(10), 0U);
		
		EXPECT_EQ(shards[1].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[1].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 3)
	{
		EXPECT_EQ(shards[2].offset, BitOffset(1024, 0));
		EXPECT_EQ(shards[2].length, 512);
		
		EXPECT_EQ(shards[2].result.get_total_bytes(), 512U);
		EXPECT_EQ(shards[2].result.get_byte_sum(), 14U);
		
		EXPECT_EQ(shards[2].result.get_byte_count(0), 510U);
		EXPECT_EQ(shards[2].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(3), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(4), 1U);
		EXPECT_EQ(shards[2].result.get_byte_count(10), 1U);
		
		EXPECT_EQ(shards[2].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[2].result.get_max_byte(), 10U);
	}
	
	if(shards.size() >= 4)
	{
		EXPECT_EQ(shards[3].offset, BitOffset(1536, 0));
		EXPECT_EQ(shards[3].length, 512);
		
		EXPECT_EQ(shards[3].result.get_total_bytes(), 512U);
		EXPECT_EQ(shards[3].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[3].result.get_byte_count(0), 512U);
		EXPECT_EQ(shards[3].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(3), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(10), 0U);
		
		EXPECT_EQ(shards[3].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[3].result.get_max_byte(), 0U);
	}
}

TEST(HierarchicalByteAccumulator, SmallFileMaxShards)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	append_block(document, 1024, { 4, 2, 1 });
	append_block(document, 1024, { 4, 10 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 4000);
	
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
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	EXPECT_EQ(shards.size(), 2048U);
	
	for(size_t i = 0; i < std::min<size_t>(shards.size(), 2048U); ++i)
	{
		unsigned char this_byte;
		
		switch(i)
		{
			case    0: this_byte =  4; break;
			case    1: this_byte =  2; break;
			case    2: this_byte =  1; break;
			case 1024: this_byte =  4; break;
			case 1025: this_byte = 10; break;
			default:   this_byte =  0; break;
		}
		
		EXPECT_EQ(shards[i].offset, BitOffset(i, 0));
		EXPECT_EQ(shards[i].length, 1);
		
		EXPECT_EQ(shards[i].result.get_total_bytes(), 1U);
		EXPECT_EQ(shards[i].result.get_byte_sum(), this_byte);
		
		EXPECT_EQ(shards[i].result.get_byte_count(this_byte), 1U);
		
		EXPECT_EQ(shards[i].result.get_min_byte(), this_byte);
		EXPECT_EQ(shards[i].result.get_max_byte(), this_byte);
	}
}

TEST(HierarchicalByteAccumulator, BigFileEvenShards)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	uint64_t byte_sum = 0;
	
	for(int i = 0; i < 100; ++i)
	{
		std::vector<unsigned char> data((1024 * 1024), i);
		document->insert_data(document->buffer_length(), data.data(), data.size());
		
		byte_sum += (1024 * 1024 * i);
	}
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 100);
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), (1024U * 1024U * 100U));
	EXPECT_EQ(result.get_byte_sum(), byte_sum);
	
	for(int i = 0; i < 100; ++i)
	{
		EXPECT_EQ(result.get_byte_count(i), (1024U * 1024U));
	}
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 99U);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 100U);
	
	for(size_t i = 0; i < std::min<size_t>(shards.size(), 100U); ++i)
	{
		EXPECT_EQ(shards[i].offset, BitOffset((i * 1024 * 1024), 0));
		EXPECT_EQ(shards[i].length, (1024 * 1024));
		
		EXPECT_EQ(shards[i].result.get_total_bytes(), (1024U * 1024U));
		EXPECT_EQ(shards[i].result.get_byte_sum(), (1024 * 1024 * i));
		
		for(size_t j = 0; j < 256; ++j)
		{
			if(i == j)
			{
				EXPECT_EQ(shards[i].result.get_byte_count(j), (1024U * 1024U));
			}
			else{
				EXPECT_EQ(shards[i].result.get_byte_count(j), 0U);
			}
		}
		
		EXPECT_EQ(shards[i].result.get_min_byte(), i);
		EXPECT_EQ(shards[i].result.get_max_byte(), i);
	}
}

TEST(HierarchicalByteAccumulator, BigFileUnalignedShards)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	
	uint64_t byte_sum = 0;
	
	for(int i = 0; i < 100; ++i)
	{
		std::vector<unsigned char> data((1024 * 1024), i);
		document->insert_data(document->buffer_length(), data.data(), data.size());
		
		byte_sum += (1024 * 1024 * i);
	}
	
	{
		unsigned char ff = 0xFE;
		document->insert_data(document->buffer_length(), &ff, 1);
		
		byte_sum += 0xFE;
	}
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 100);
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), ((1024U * 1024U * 100U) + 1));
	EXPECT_EQ(result.get_byte_sum(), byte_sum);
	
	for(int i = 0; i < 100; ++i)
	{
		EXPECT_EQ(result.get_byte_count(i), (1024U * 1024U));
	}
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 0xFE);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 100U);
	
	for(size_t i = 0; i < std::min<size_t>(shards.size(), 99U); ++i)
	{
		EXPECT_EQ(shards[i].offset, BitOffset((i * 1048578), 0));
		EXPECT_EQ(shards[i].length, 1048578);
		
		EXPECT_EQ(shards[i].result.get_total_bytes(), 1048578U);
	}
	
	if(shards.size() >= 1)
	{
		for(size_t i = 0; i < 256; ++i)
		{
			if(i == 0)
			{
				EXPECT_EQ(shards[0].result.get_byte_count(i), (1024U * 1024U));
			}
			else if(i == 1)
			{
				EXPECT_EQ(shards[0].result.get_byte_count(i), 2U);
			}
			else{
				EXPECT_EQ(shards[0].result.get_byte_count(i), 0U);
			}
		}
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0);
		EXPECT_EQ(shards[0].result.get_max_byte(), 1);
		
		EXPECT_EQ(shards[0].result.get_byte_sum(), 2U);
	}
	
	if(shards.size() >= 2)
	{
		for(size_t i = 0; i < 256; ++i)
		{
			if(i == 1)
			{
				EXPECT_EQ(shards[1].result.get_byte_count(i), (1024U * 1024U - 2));
			}
			else if(i == 2)
			{
				EXPECT_EQ(shards[1].result.get_byte_count(i), 4U);
			}
			else{
				EXPECT_EQ(shards[1].result.get_byte_count(i), 0U);
			}
		}
		
		EXPECT_EQ(shards[1].result.get_min_byte(), 1);
		EXPECT_EQ(shards[1].result.get_max_byte(), 2);
		
		EXPECT_EQ(shards[1].result.get_byte_sum(), ((1024U * 1024U - 2) + (4 * 2)));
	}
	
	if(shards.size() >= 100)
	{
		EXPECT_EQ(shards[99].offset, BitOffset((99 * 1048578), 0));
		EXPECT_EQ(shards[99].length, 1048379);
		
		EXPECT_EQ(shards[99].result.get_total_bytes(), 1048379U);
		EXPECT_EQ(shards[99].result.get_byte_sum(), ((1048378U * 99U) + 0xFE));
		
		for(size_t j = 0; j < 256; ++j)
		{
			if(j == 99)
			{
				EXPECT_EQ(shards[99].result.get_byte_count(j), 1048378U);
			}
			else if(j == 0xFE)
			{
				EXPECT_EQ(shards[99].result.get_byte_count(j), 1U);
			}
			else{
				EXPECT_EQ(shards[99].result.get_byte_count(j), 0U);
			}
		}
		
		EXPECT_EQ(shards[99].result.get_min_byte(), 99U);
		EXPECT_EQ(shards[99].result.get_max_byte(), 0xFE);
	}
}

TEST(HierarchicalByteAccumulator, OverwriteData)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	append_block(document, 1024, { 4 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 4);
	hba.wait_for_completion();
	
	{
		unsigned char b1 = 1;
		document->overwrite_data(0, &b1, 1);
		
		unsigned char b2 = 2;
		document->overwrite_data(700, &b2, 1);
	}
	
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), 1024U);
	EXPECT_EQ(result.get_byte_sum(), 3U);
	
	EXPECT_EQ(result.get_byte_count(0), 1022U);
	EXPECT_EQ(result.get_byte_count(1), 1U);
	EXPECT_EQ(result.get_byte_count(2), 1U);
	EXPECT_EQ(result.get_byte_count(4), 0U);
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 2U);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 4U);
	
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, 256);
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), 256U);
		EXPECT_EQ(shards[0].result.get_byte_sum(), 1U);
		
		EXPECT_EQ(shards[0].result.get_byte_count(0), 255U);
		EXPECT_EQ(shards[0].result.get_byte_count(1), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[0].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 1U);
	}
	
	if(shards.size() >= 2)
	{
		EXPECT_EQ(shards[1].offset, BitOffset(256, 0));
		EXPECT_EQ(shards[1].length, 256);
		
		EXPECT_EQ(shards[1].result.get_total_bytes(), 256U);
		EXPECT_EQ(shards[1].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[1].result.get_byte_count(0), 256U);
		EXPECT_EQ(shards[1].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[1].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[1].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 3)
	{
		EXPECT_EQ(shards[2].offset, BitOffset(512, 0));
		EXPECT_EQ(shards[2].length, 256);
		
		EXPECT_EQ(shards[2].result.get_total_bytes(), 256U);
		EXPECT_EQ(shards[2].result.get_byte_sum(), 2U);
		
		EXPECT_EQ(shards[2].result.get_byte_count(0), 255U);
		EXPECT_EQ(shards[2].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(2), 1U);
		EXPECT_EQ(shards[2].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[2].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[2].result.get_max_byte(), 2U);
	}
}

TEST(HierarchicalByteAccumulator, OverwriteDataCacheMiss)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	append_block(document, 1024, { 4 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 4);
	hba.wait_for_completion();
	
	{
		hba.flush_l2_cache();
		
		unsigned char b1 = 1;
		document->overwrite_data(0, &b1, 1);
		
		unsigned char b2 = 2;
		document->overwrite_data(700, &b2, 1);
	}
	
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), 1024U);
	EXPECT_EQ(result.get_byte_sum(), 3U);
	
	EXPECT_EQ(result.get_byte_count(0), 1022U);
	EXPECT_EQ(result.get_byte_count(1), 1U);
	EXPECT_EQ(result.get_byte_count(2), 1U);
	EXPECT_EQ(result.get_byte_count(4), 0U);
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 2U);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 4U);
	
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, 256);
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), 256U);
		EXPECT_EQ(shards[0].result.get_byte_sum(), 1U);
		
		EXPECT_EQ(shards[0].result.get_byte_count(0), 255U);
		EXPECT_EQ(shards[0].result.get_byte_count(1), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[0].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 1U);
	}
	
	if(shards.size() >= 2)
	{
		EXPECT_EQ(shards[1].offset, BitOffset(256, 0));
		EXPECT_EQ(shards[1].length, 256);
		
		EXPECT_EQ(shards[1].result.get_total_bytes(), 256U);
		EXPECT_EQ(shards[1].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[1].result.get_byte_count(0), 256U);
		EXPECT_EQ(shards[1].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[1].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[1].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 3)
	{
		EXPECT_EQ(shards[2].offset, BitOffset(512, 0));
		EXPECT_EQ(shards[2].length, 256);
		
		EXPECT_EQ(shards[2].result.get_total_bytes(), 256U);
		EXPECT_EQ(shards[2].result.get_byte_sum(), 2U);
		
		EXPECT_EQ(shards[2].result.get_byte_count(0), 255U);
		EXPECT_EQ(shards[2].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(2), 1U);
		EXPECT_EQ(shards[2].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[2].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[2].result.get_max_byte(), 2U);
	}
}

TEST(HierarchicalByteAccumulator, InsertData)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	append_block(document, 1024, { 4 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 4);
	hba.wait_for_completion();
	
	{
		unsigned char b1 = 1;
		document->insert_data(0, &b1, 1);
		
		unsigned char b2 = 2;
		document->insert_data(700, &b2, 1);
	}
	
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), 1026U);
	EXPECT_EQ(result.get_byte_sum(), 7U);
	
	EXPECT_EQ(result.get_byte_count(0), 1023U);
	EXPECT_EQ(result.get_byte_count(1), 1U);
	EXPECT_EQ(result.get_byte_count(2), 1U);
	EXPECT_EQ(result.get_byte_count(4), 1U);
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 4U);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 4U);
	
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, 257);
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), 257U);
		EXPECT_EQ(shards[0].result.get_byte_sum(), 5U);
		
		EXPECT_EQ(shards[0].result.get_byte_count(0), 255U);
		EXPECT_EQ(shards[0].result.get_byte_count(1), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[0].result.get_byte_count(4), 1U);
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 4U);
	}
	
	if(shards.size() >= 2)
	{
		EXPECT_EQ(shards[1].offset, BitOffset(257, 0));
		EXPECT_EQ(shards[1].length, 256);
		
		EXPECT_EQ(shards[1].result.get_total_bytes(), 256U);
		EXPECT_EQ(shards[1].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[1].result.get_byte_count(0), 256U);
		EXPECT_EQ(shards[1].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[1].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[1].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 3)
	{
		EXPECT_EQ(shards[2].offset, BitOffset(513, 0));
		EXPECT_EQ(shards[2].length, 257);
		
		EXPECT_EQ(shards[2].result.get_total_bytes(), 257U);
		EXPECT_EQ(shards[2].result.get_byte_sum(), 2U);
		
		EXPECT_EQ(shards[2].result.get_byte_count(0), 256U);
		EXPECT_EQ(shards[2].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(2), 1U);
		EXPECT_EQ(shards[2].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[2].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[2].result.get_max_byte(), 2U);
	}
}

TEST(HierarchicalByteAccumulator, InsertDataEmptyFile)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	append_block(document, 1024, { 4 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 4);
	hba.wait_for_completion();
	
	{
		unsigned char b1 = 1;
		document->insert_data(0, &b1, 1);
		
		unsigned char b2 = 2;
		document->insert_data(700, &b2, 1);
	}
	
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), 1026U);
	EXPECT_EQ(result.get_byte_sum(), 7U);
	
	EXPECT_EQ(result.get_byte_count(0), 1023U);
	EXPECT_EQ(result.get_byte_count(1), 1U);
	EXPECT_EQ(result.get_byte_count(2), 1U);
	EXPECT_EQ(result.get_byte_count(4), 1U);
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 4U);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 4U);
	
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, 257);
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), 257U);
		EXPECT_EQ(shards[0].result.get_byte_sum(), 5U);
		
		EXPECT_EQ(shards[0].result.get_byte_count(0), 255U);
		EXPECT_EQ(shards[0].result.get_byte_count(1), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[0].result.get_byte_count(4), 1U);
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 4U);
	}
	
	if(shards.size() >= 2)
	{
		EXPECT_EQ(shards[1].offset, BitOffset(257, 0));
		EXPECT_EQ(shards[1].length, 256);
		
		EXPECT_EQ(shards[1].result.get_total_bytes(), 256U);
		EXPECT_EQ(shards[1].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[1].result.get_byte_count(0), 256U);
		EXPECT_EQ(shards[1].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[1].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[1].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 3)
	{
		EXPECT_EQ(shards[2].offset, BitOffset(513, 0));
		EXPECT_EQ(shards[2].length, 257);
		
		EXPECT_EQ(shards[2].result.get_total_bytes(), 257U);
		EXPECT_EQ(shards[2].result.get_byte_sum(), 2U);
		
		EXPECT_EQ(shards[2].result.get_byte_count(0), 256U);
		EXPECT_EQ(shards[2].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(2), 1U);
		EXPECT_EQ(shards[2].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[2].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[2].result.get_max_byte(), 2U);
	}
}

TEST(HierarchicalByteAccumulator, InsertDataCacheMiss)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	append_block(document, 1024, { 4 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 4);
	hba.wait_for_completion();
	
	{
		hba.flush_l2_cache();
		
		unsigned char b1 = 1;
		document->insert_data(0, &b1, 1);
		
		unsigned char b2 = 2;
		document->insert_data(700, &b2, 1);
	}
	
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), 1026U);
	EXPECT_EQ(result.get_byte_sum(), 7U);
	
	EXPECT_EQ(result.get_byte_count(0), 1023U);
	EXPECT_EQ(result.get_byte_count(1), 1U);
	EXPECT_EQ(result.get_byte_count(2), 1U);
	EXPECT_EQ(result.get_byte_count(4), 1U);
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 4U);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 4U);
	
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, 257);
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), 257U);
		EXPECT_EQ(shards[0].result.get_byte_sum(), 5U);
		
		EXPECT_EQ(shards[0].result.get_byte_count(0), 255U);
		EXPECT_EQ(shards[0].result.get_byte_count(1), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[0].result.get_byte_count(4), 1U);
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 4U);
	}
	
	if(shards.size() >= 2)
	{
		EXPECT_EQ(shards[1].offset, BitOffset(257, 0));
		EXPECT_EQ(shards[1].length, 256);
		
		EXPECT_EQ(shards[1].result.get_total_bytes(), 256U);
		EXPECT_EQ(shards[1].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[1].result.get_byte_count(0), 256U);
		EXPECT_EQ(shards[1].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[1].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[1].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 3)
	{
		EXPECT_EQ(shards[2].offset, BitOffset(513, 0));
		EXPECT_EQ(shards[2].length, 257);
		
		EXPECT_EQ(shards[2].result.get_total_bytes(), 257U);
		EXPECT_EQ(shards[2].result.get_byte_sum(), 2U);
		
		EXPECT_EQ(shards[2].result.get_byte_count(0), 256U);
		EXPECT_EQ(shards[2].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(2), 1U);
		EXPECT_EQ(shards[2].result.get_byte_count(4), 0U);
		
		EXPECT_EQ(shards[2].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[2].result.get_max_byte(), 2U);
	}
}

TEST(HierarchicalByteAccumulator, EraseData)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	append_block(document, 600, { 1, 2, 4 });
	append_block(document, 424, { 6 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 4);
	hba.wait_for_completion();
	
	document->erase_data(2, 2);
	document->erase_data(590, 22);
	
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), 1000U);
	EXPECT_EQ(result.get_byte_sum(), 3U);
	
	EXPECT_EQ(result.get_byte_count(0), 998U);
	EXPECT_EQ(result.get_byte_count(1), 1U);
	EXPECT_EQ(result.get_byte_count(2), 1U);
	EXPECT_EQ(result.get_byte_count(4), 0U);
	EXPECT_EQ(result.get_byte_count(6), 0U);
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 2U);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 4U);
	
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, 250);
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), 250U);
		EXPECT_EQ(shards[0].result.get_byte_sum(), 3U);
		
		EXPECT_EQ(shards[0].result.get_byte_count(0), 248U);
		EXPECT_EQ(shards[0].result.get_byte_count(1), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(2), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[0].result.get_byte_count(6), 0U);
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 2U);
	}
	
	if(shards.size() >= 2)
	{
		EXPECT_EQ(shards[1].offset, BitOffset(250, 0));
		EXPECT_EQ(shards[1].length, 252);
		
		EXPECT_EQ(shards[1].result.get_total_bytes(), 252U);
		EXPECT_EQ(shards[1].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[1].result.get_byte_count(0), 252U);
		EXPECT_EQ(shards[1].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(6), 0U);
		
		EXPECT_EQ(shards[1].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[1].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 3)
	{
		EXPECT_EQ(shards[2].offset, BitOffset(502, 0));
		EXPECT_EQ(shards[2].length, 250);
		
		EXPECT_EQ(shards[2].result.get_total_bytes(), 250U);
		EXPECT_EQ(shards[2].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[2].result.get_byte_count(0), 250U);
		EXPECT_EQ(shards[2].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(6), 0U);
		
		EXPECT_EQ(shards[2].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[2].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 4)
	{
		EXPECT_EQ(shards[3].offset, BitOffset(752, 0));
		EXPECT_EQ(shards[3].length, 248);
		
		EXPECT_EQ(shards[3].result.get_total_bytes(), 248U);
		EXPECT_EQ(shards[3].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[3].result.get_byte_count(0), 248U);
		EXPECT_EQ(shards[3].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(6), 0U);
		
		EXPECT_EQ(shards[3].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[3].result.get_max_byte(), 0U);
	}
}

TEST(HierarchicalByteAccumulator, EraseDataCacheMiss)
{
	SharedDocumentPointer document = SharedDocumentPointer::make();
	append_block(document, 600, { 1, 2, 4 });
	append_block(document, 424, { 6 });
	
	HierarchicalByteAccumulator hba(SharedEvtHandler<FlatDocumentView>::make(document), 4);
	hba.wait_for_completion();
	
	hba.flush_l2_cache();
	
	document->erase_data(2, 2);
	document->erase_data(590, 22);
	
	hba.wait_for_completion();
	
	ByteAccumulator result = hba.get_result();
	
	EXPECT_EQ(result.get_total_bytes(), 1000U);
	EXPECT_EQ(result.get_byte_sum(), 3U);
	
	EXPECT_EQ(result.get_byte_count(0), 998U);
	EXPECT_EQ(result.get_byte_count(1), 1U);
	EXPECT_EQ(result.get_byte_count(2), 1U);
	EXPECT_EQ(result.get_byte_count(4), 0U);
	EXPECT_EQ(result.get_byte_count(6), 0U);
	
	EXPECT_EQ(result.get_min_byte(), 0U);
	EXPECT_EQ(result.get_max_byte(), 2U);
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = hba.get_shards();
	
	EXPECT_EQ(shards.size(), 4U);
	
	if(shards.size() >= 1)
	{
		EXPECT_EQ(shards[0].offset, BitOffset(0, 0));
		EXPECT_EQ(shards[0].length, 250);
		
		EXPECT_EQ(shards[0].result.get_total_bytes(), 250U);
		EXPECT_EQ(shards[0].result.get_byte_sum(), 3U);
		
		EXPECT_EQ(shards[0].result.get_byte_count(0), 248U);
		EXPECT_EQ(shards[0].result.get_byte_count(1), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(2), 1U);
		EXPECT_EQ(shards[0].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[0].result.get_byte_count(6), 0U);
		
		EXPECT_EQ(shards[0].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[0].result.get_max_byte(), 2U);
	}
	
	if(shards.size() >= 2)
	{
		EXPECT_EQ(shards[1].offset, BitOffset(250, 0));
		EXPECT_EQ(shards[1].length, 252);
		
		EXPECT_EQ(shards[1].result.get_total_bytes(), 252U);
		EXPECT_EQ(shards[1].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[1].result.get_byte_count(0), 252U);
		EXPECT_EQ(shards[1].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[1].result.get_byte_count(6), 0U);
		
		EXPECT_EQ(shards[1].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[1].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 3)
	{
		EXPECT_EQ(shards[2].offset, BitOffset(502, 0));
		EXPECT_EQ(shards[2].length, 250);
		
		EXPECT_EQ(shards[2].result.get_total_bytes(), 250U);
		EXPECT_EQ(shards[2].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[2].result.get_byte_count(0), 250U);
		EXPECT_EQ(shards[2].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[2].result.get_byte_count(6), 0U);
		
		EXPECT_EQ(shards[2].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[2].result.get_max_byte(), 0U);
	}
	
	if(shards.size() >= 4)
	{
		EXPECT_EQ(shards[3].offset, BitOffset(752, 0));
		EXPECT_EQ(shards[3].length, 248);
		
		EXPECT_EQ(shards[3].result.get_total_bytes(), 248U);
		EXPECT_EQ(shards[3].result.get_byte_sum(), 0U);
		
		EXPECT_EQ(shards[3].result.get_byte_count(0), 248U);
		EXPECT_EQ(shards[3].result.get_byte_count(1), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(2), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(4), 0U);
		EXPECT_EQ(shards[3].result.get_byte_count(6), 0U);
		
		EXPECT_EQ(shards[3].result.get_min_byte(), 0U);
		EXPECT_EQ(shards[3].result.get_max_byte(), 0U);
	}
}
