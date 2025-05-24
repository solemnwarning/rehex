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

#include "platform.hpp"

#include <math.h>
#include <stdint.h>

#include "DataMapSource.hpp"
#include "Palette.hpp"

static constexpr off_t MIN_SHARD_SIZE = 100;

REHex::EntropyDataMapSource::EntropyDataMapSource(const SharedEvtHandler<DataView> &view, size_t max_points, double log_multi):
	view(view),
	max_points(max_points),
	log_multi(log_multi)
{
	accumulator.reset(new HierarchicalByteAccumulator(view, max_points, MIN_SHARD_SIZE));
	
	accumulator->Bind(PROCESSING_START, &REHex::EntropyDataMapSource::OnProcessingStart, this);
	accumulator->Bind(PROCESSING_STOP, &REHex::EntropyDataMapSource::OnProcessingStop, this);
}

REHex::EntropyDataMapSource::~EntropyDataMapSource()
{
	/* Ensure accumulator won't raise any processing start/stop events while we aren't fully
	 * constructed.
	*/
	accumulator.reset(nullptr);
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
		
		entropy = log(entropy * log_multi + 1.0f) / log(log_multi + 1.0f);
		
		wxColour colour = active_palette->blend_colours(Palette::PAL_NORMAL_TEXT_BG, *wxBLUE, entropy);
		
		char s[128];
		snprintf(s, sizeof(s), "Entropy: %d%%\n", (int)(entropy * 100.0f));
		result.set_range(it->offset, it->length, MapValue(colour, s));
	}
	
	return result;
}

bool REHex::EntropyDataMapSource::processing()
{
	return accumulator->processing();
}

void REHex::EntropyDataMapSource::reset_max_points(size_t max_points)
{
	if(accumulator->get_requested_num_shards() != max_points)
	{
		accumulator.reset(new HierarchicalByteAccumulator(view, max_points, MIN_SHARD_SIZE));
		
		accumulator->Bind(PROCESSING_START, &REHex::EntropyDataMapSource::OnProcessingStart, this);
		accumulator->Bind(PROCESSING_STOP, &REHex::EntropyDataMapSource::OnProcessingStop, this);
	}
}

void REHex::EntropyDataMapSource::OnProcessingStart(wxCommandEvent &event)
{
	wxCommandEvent my_event(PROCESSING_START);
	my_event.SetEventObject(this);
	ProcessEvent(my_event);
	
	event.Skip();
}

void REHex::EntropyDataMapSource::OnProcessingStop(wxCommandEvent &event)
{
	wxCommandEvent my_event(PROCESSING_STOP);
	my_event.SetEventObject(this);
	ProcessEvent(my_event);
	
	event.Skip();
}

REHex::BasicStatDataMapSource::BasicStatDataMapSource(const SharedEvtHandler<DataView> &view, size_t max_points)
{
	accumulator.reset(new HierarchicalByteAccumulator(view, max_points));
	
	accumulator->Bind(PROCESSING_START, &REHex::BasicStatDataMapSource::OnProcessingStart, this);
	accumulator->Bind(PROCESSING_STOP, &REHex::BasicStatDataMapSource::OnProcessingStop, this);
}

REHex::BasicStatDataMapSource::~BasicStatDataMapSource()
{
	/* Ensure accumulator won't raise any processing start/stop events while we aren't fully
	 * constructed.
	*/
	accumulator.reset(nullptr);
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

bool REHex::BasicStatDataMapSource::processing()
{
	return accumulator->processing();
}

void REHex::BasicStatDataMapSource::OnProcessingStart(wxCommandEvent &event)
{
	wxCommandEvent my_event(PROCESSING_START);
	my_event.SetEventObject(this);
	ProcessEvent(my_event);
	
	event.Skip();
}

void REHex::BasicStatDataMapSource::OnProcessingStop(wxCommandEvent &event)
{
	wxCommandEvent my_event(PROCESSING_STOP);
	my_event.SetEventObject(this);
	ProcessEvent(my_event);
	
	event.Skip();
}
