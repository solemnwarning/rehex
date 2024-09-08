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
	this->document.auto_cleanup_bind(DATA_ERASE,  &REHex::EntropyDataMapSource::OnDocumentDataErase,  this);
	this->document.auto_cleanup_bind(DATA_INSERT, &REHex::EntropyDataMapSource::OnDocumentDataInsert, this);
	
	repopulate_sub_ranges();
}

REHex::EntropyDataMapSource::EntropyDataMapSource(const SharedDocumentPointer &document, BitOffset range_offset, off_t range_length, size_t max_points):
	document(document),
	range_offset(range_offset),
	range_length(range_length),
	max_points(max_points)
{
	this->document.auto_cleanup_bind(DATA_ERASE,  &REHex::EntropyDataMapSource::OnDocumentDataErase,  this);
	this->document.auto_cleanup_bind(DATA_INSERT, &REHex::EntropyDataMapSource::OnDocumentDataInsert, this);
	
	repopulate_sub_ranges();
}

REHex::EntropyDataMapSource::~EntropyDataMapSource()
{
	for(auto it = sub_ranges.begin(); it != sub_ranges.end(); ++it)
	{
		it->accumulator->pre_destroy();
	}
}

void REHex::EntropyDataMapSource::repopulate_sub_ranges()
{
	for(auto old_sr = sub_ranges.begin(); old_sr != sub_ranges.end(); ++old_sr)
	{
		old_sr->accumulator->pre_destroy();
	}
	
	sub_ranges.clear();
	
	off_t actual_range_length = range_length >= 0
		? range_length
		: document->buffer_length();
	
	off_t bytes_per_sub_range = std::max<off_t>((actual_range_length / (off_t)(max_points)), 1);
	off_t next_rel_offset = 0;
	
	while(next_rel_offset < actual_range_length)
	{
		off_t sub_range_length = (sub_ranges.size() + 1) == max_points
			? (actual_range_length - next_rel_offset)
			: bytes_per_sub_range;
		
		sub_ranges.emplace_back(document, range_offset, next_rel_offset, sub_range_length);
		next_rel_offset += sub_range_length;
	}
}

void REHex::EntropyDataMapSource::OnDocumentDataErase(OffsetLengthEvent &event)
{
	if(range_length < 0)
	{
		repopulate_sub_ranges();
	}
	
	event.Skip();
}

void REHex::EntropyDataMapSource::OnDocumentDataInsert(OffsetLengthEvent &event)
{
	if(range_length < 0)
	{
		repopulate_sub_ranges();
	}
	
	event.Skip();
}

REHex::BitRangeMap<wxColour> REHex::EntropyDataMapSource::get_data_map()
{
	BitRangeMap<wxColour> result;
	
	for(auto it = sub_ranges.begin(); it != sub_ranges.end(); ++it)
	{
		const ByteAccumulator &sub_range_result = it->accumulator->get_result();
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
		
		result.set_range((range_offset + BitOffset(it->rel_offset, 0)), it->length, colour);
	}
	
	return result;
}
