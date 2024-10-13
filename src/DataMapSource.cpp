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

REHex::EntropyDataMapSource::EntropyDataMapSource(const SharedEvtHandler<DataView> &view, size_t max_points):
	max_points(max_points)
{
	accumulator.reset(new HierarchicalByteAccumulator(view, max_points));
}

REHex::EntropyDataMapSource::EntropyDataMapSource(const SharedEvtHandler<DataView> &view, BitOffset range_offset, off_t range_length, size_t max_points):
	max_points(max_points)
{
	accumulator.reset(new HierarchicalByteAccumulator(view, range_offset, range_length, max_points));
}

REHex::BitRangeMap<REHex::DataMapSource::MapValue> REHex::EntropyDataMapSource::get_data_map()
{
	BitRangeMap<MapValue> result;
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = accumulator->get_shards();
	
	for(auto it = shards.begin(); it != shards.end(); ++it)
	{
		const ByteAccumulator &sub_range_result = it->result;
		uint64_t total_bytes = sub_range_result.get_total_bytes();
		
		double entropy = 0.0f;
		
		for(int i = 0; i < 256; ++i)
		{
			uint64_t byte_count = sub_range_result.get_byte_count(i);
			
			if(byte_count > 0)
			{
				double byte_prob = (double)(byte_count) / (double)(total_bytes);
				entropy += -byte_prob * log2(byte_prob);
			}
		}
		
		entropy = abs(entropy / 8.0f);
		
		int entropy_8bit = (int)(entropy * 255.0f);
		wxColour colour(255, (255 - entropy_8bit), (255 - entropy_8bit));
		
		char s[128];
		snprintf(s, sizeof(s), "Entropy: %d%%\n", (int)(entropy * 100.0f));
		result.set_range(it->offset, it->length, MapValue(colour, s));
	}
	
	return result;
}

REHex::BasicStatDataMapSource::BasicStatDataMapSource(const SharedEvtHandler<DataView> &view, size_t max_points)
{
	accumulator.reset(new HierarchicalByteAccumulator(view, max_points));
}

REHex::BasicStatDataMapSource::BasicStatDataMapSource(const SharedEvtHandler<DataView> &view, BitOffset range_offset, off_t range_length, size_t max_points)
{
	accumulator.reset(new HierarchicalByteAccumulator(view, range_offset, range_length, max_points));
}

REHex::BitRangeMap<REHex::DataMapSource::MapValue> REHex::BasicStatDataMapSource::get_data_map()
{
	BitRangeMap<MapValue> result;
	
	std::vector<HierarchicalByteAccumulator::Shard> shards = accumulator->get_shards();
	
	for(auto it = shards.begin(); it != shards.end(); ++it)
	{
		const ByteAccumulator &sub_range_result = it->result;
		
		int value = sub_range_result.get_min_byte();
		wxColour colour(255, (255 - value), (255 - value));
		
		result.set_range(it->offset, it->length, MapValue(colour, ""));
	}
	
	return result;
}
