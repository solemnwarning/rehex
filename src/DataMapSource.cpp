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

#include "platform.hpp"

#include <stdint.h>

#include "DataMapSource.hpp"

REHex::EntropyDataMapSource::EntropyDataMapSource(const SharedDocumentPointer &document, size_t max_points):
	document(document),
	range_offset(BitOffset::ZERO),
	range_length(-1),
	max_points(max_points)
{
	accumulator.reset(new HierarchicalByteAccumulator(document, max_points));
}

REHex::EntropyDataMapSource::EntropyDataMapSource(const SharedDocumentPointer &document, BitOffset range_offset, off_t range_length, size_t max_points):
	document(document),
	range_offset(range_offset),
	range_length(range_length),
	max_points(max_points)
{
	accumulator.reset(new HierarchicalByteAccumulator(document, range_offset, range_length, max_points));
}

REHex::BitRangeMap<wxColour> REHex::EntropyDataMapSource::get_data_map()
{
	BitRangeMap<wxColour> result;
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = accumulator->get_shards();
	
	for(auto it = shards.begin(); it != shards.end(); ++it)
	{
		const ByteAccumulator &sub_range_result = it->result;
		uint64_t total_bytes = sub_range_result.get_total_bytes();
		
		if(total_bytes == 0)
		{
			continue;
		}
		
		uint64_t count_d256_floor = total_bytes / 256;
		uint64_t count_d256_ceil = ((total_bytes - 1) / 256) + 1;
		
		uint64_t entropy_num = total_bytes;
		uint64_t entropy_den = total_bytes;
		
		for(int i = 0; i < 256; ++i)
		{
			uint64_t byte_count = sub_range_result.get_byte_count(i);
			
			if(byte_count < count_d256_floor)
			{
				entropy_num -= (count_d256_floor - byte_count);
			}
			else if(byte_count > count_d256_ceil)
			{
				entropy_den += (byte_count - count_d256_ceil);
			}
		}
		
		int entropy_8bit = (entropy_num * 255) / std::max<uint64_t>(entropy_den, 1);
		wxColour colour(255, (255 - entropy_8bit), (255 - entropy_8bit));
		
		result.set_range(it->offset, it->length, colour);
	}
	
	return result;
}
