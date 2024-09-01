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

#include "App.hpp"
#include "HierarchicalByteAccumulator.hpp"

constexpr size_t REHex::HierarchicalByteAccumulator::CHUNK_SIZE;
constexpr size_t REHex::HierarchicalByteAccumulator::L1_CACHE_SIZE;
constexpr size_t REHex::HierarchicalByteAccumulator::L2_CACHE_SIZE;

REHex::HierarchicalByteAccumulator::HierarchicalByteAccumulator(const SharedDocumentPointer &document, BitOffset range_offset, off_t range_length):
	document(document),
	range_offset(range_offset),
	range_length(range_length),
	l2_cache(L2_CACHE_SIZE),
	processor([this](off_t offset, off_t length) { process_range(offset, length); }, CHUNK_SIZE)
{
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::HierarchicalByteAccumulator::OnDataErase,     this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::HierarchicalByteAccumulator::OnDataInsert,    this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::HierarchicalByteAccumulator::OnDataOverwrite, this);
	
	this->document.auto_cleanup_bind(DATA_ERASING,              &REHex::HierarchicalByteAccumulator::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_ERASE_ABORTED,        &REHex::HierarchicalByteAccumulator::OnDataModifyAborted,    this);
	this->document.auto_cleanup_bind(DATA_INSERTING,            &REHex::HierarchicalByteAccumulator::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_INSERT_ABORTED,       &REHex::HierarchicalByteAccumulator::OnDataModifyAborted,    this);
	
	l1_slot_base_size = range_length / L1_CACHE_SIZE;
	
	if(l1_slot_base_size < (off_t)(CHUNK_SIZE))
	{
		l1_slot_base_size = CHUNK_SIZE;
	}
	else if((l1_slot_base_size % CHUNK_SIZE) != 0)
	{
		l1_slot_base_size -= (l1_slot_base_size % CHUNK_SIZE);
	}
	
	l1_slot_count = range_length / l1_slot_base_size;
	
	if((range_length % l1_slot_base_size) != 0)
	{
		++l1_slot_count;
	}
	
	if(l1_slot_count > L1_CACHE_SIZE)
	{
		l1_slot_count = L1_CACHE_SIZE;
	}
	
	processor.queue_range(0, range_length);
}

const REHex::ByteAccumulator &REHex::HierarchicalByteAccumulator::get_result()
{
	if(result_rebuild_pending)
	{
		result_rebuild_pending = false;
		
		std::unique_lock<std::mutex> l1_lock_guard(l1_mutex);
		
		result.reset();
		
		for(size_t i = 0; i < l1_slot_count; ++i)
		{
			result += l1_cache[i].accumulator;
		}
	}
	
	return result;
}

void REHex::HierarchicalByteAccumulator::wait_for_completion()
{
	return processor.wait_for_completion();
}

void REHex::HierarchicalByteAccumulator::process_range(off_t offset, off_t length)
{
	off_t chunk_offset = offset - (offset % CHUNK_SIZE);
	off_t chunk_length = std::min<off_t>(CHUNK_SIZE, (range_length - chunk_offset));
	
	if((chunk_offset + (off_t)(CHUNK_SIZE)) < (offset + length))
	{
		/* We've been given a range which overlaps multiple chunks... this *should* only
		 * straddle up to two chunks if a range in the middle was updated.
		 *
		 * Return the overflow to the RangeProcessor to be processed later.
		*/
		
		assert((chunk_offset + (off_t)(CHUNK_SIZE * 2)) >= (offset + length));
		
		off_t next_chunk_offset = chunk_offset + CHUNK_SIZE;
		off_t length_from_next_chunk = length - (next_chunk_offset - offset);
		
		processor.queue_range(next_chunk_offset, length_from_next_chunk);
	}
	
	ByteAccumulator prev_chunk_accumulator;
	bool l2_cache_hit = false;
	
	{
		std::unique_lock<std::mutex> l2_lock_guard(l2_mutex);
		
		const ByteAccumulator *l2_cache_ptr = l2_cache.get(chunk_offset);
		if(l2_cache_ptr != NULL)
		{
			prev_chunk_accumulator = *l2_cache_ptr;
			l2_cache_hit = true;
		}
	}
	
	if(!l2_cache_hit)
	{
		std::unique_lock<std::mutex> l1_lock_guard(l1_mutex);
		
		if(l1_counted.isset(chunk_offset, CHUNK_SIZE))
		{
			/* Our chunk wasn't found in the L2 cache but has been recorded in the L1
			 * cache, we don't know the previous values to subtract, so every chunk in
			 * the L1 cache slot needs to be re-counted.
			 *
			 * All relevant chunks will be re-queued to the RangeProcessor within the
			 * l1_cache_reset_slot() call, causing us to be called again in the future,
			 * so we just return afterwards.
			*/
			
			l1_cache_reset_slot(relative_offset_to_l1_cache_idx(chunk_offset));
			return;
		}
	}
	
	ByteAccumulator chunk_accumulator;
	
	std::vector<unsigned char> data;
	try {
		data = document->read_data((range_offset + BitOffset(chunk_offset, 0)), chunk_length);
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("Exception in REHex::HierarchicalByteAccumulator::process_range: %s\n", e.what());
		return;
	}
	
	for(size_t i = 0; i < data.size(); ++i)
	{
		chunk_accumulator.add_byte(data[i]);
	}
	
	{
		std::unique_lock<std::mutex> l2_lock_guard(l2_mutex);
		l2_cache.set(chunk_offset, chunk_accumulator);
	}
	
	size_t l1_slot_idx = relative_offset_to_l1_cache_idx(chunk_offset);
	
	{
		std::unique_lock<std::mutex> l1_lock_guard(l1_mutex);
		
		if(l1_counted.isset(chunk_offset, chunk_length))
		{
			/* This range was previously recorded in the L1 accumulator, subtract the last
			* counts from it before adding the new ones.
			*/
			
			l1_cache[l1_slot_idx].accumulator -= prev_chunk_accumulator;
		}
		else{
			l1_counted.set_range(chunk_offset, chunk_length);
		}
		
		l1_cache[l1_slot_idx].accumulator += chunk_accumulator;
	}
	
	result_rebuild_pending = true;
}

size_t REHex::HierarchicalByteAccumulator::relative_offset_to_l1_cache_idx(off_t relative_offset)
{
	assert(relative_offset >= 0);
	assert(relative_offset < range_length);
	
	size_t idx = std::min<size_t>((relative_offset / l1_slot_base_size), (L1_CACHE_SIZE - 1));
	return idx;
}

off_t REHex::HierarchicalByteAccumulator::l1_cache_idx_relative_offset(size_t l1_cache_idx)
{
	assert(l1_cache_idx < l1_slot_count);
	
	return (off_t)(l1_cache_idx) * l1_slot_base_size;
}

off_t REHex::HierarchicalByteAccumulator::l1_cache_idx_length(size_t l1_cache_idx)
{
	assert(l1_cache_idx < l1_slot_count);
	
	if((l1_cache_idx + 1) == l1_slot_count)
	{
		return range_length - l1_cache_idx_relative_offset(l1_cache_idx);
	}
	else{
		return l1_slot_base_size;
	}
}

void REHex::HierarchicalByteAccumulator::l1_cache_reset_slot(size_t l1_cache_idx)
{
	assert(l1_cache_idx < l1_slot_count);
	
	off_t slot_relative_offset = l1_cache_idx_relative_offset(l1_cache_idx);
	off_t slot_length = l1_cache_idx_length(l1_cache_idx);
	
	{
		std::unique_lock<std::mutex> l1_lock_guard(l1_mutex);
		
		l1_counted.clear_range(slot_relative_offset, slot_length);
		l1_cache[l1_cache_idx].accumulator.reset();
	}
	
	processor.queue_range(slot_relative_offset, slot_length);
}

void REHex::HierarchicalByteAccumulator::OnDataModifying(OffsetLengthEvent &event)
{
	processor.pause_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::HierarchicalByteAccumulator::OnDataModifyAborted(OffsetLengthEvent &event)
{
	processor.resume_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::HierarchicalByteAccumulator::OnDataErase(OffsetLengthEvent &event)
{
	/* TODO */
	
	processor.resume_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::HierarchicalByteAccumulator::OnDataInsert(OffsetLengthEvent &event)
{
	/* TODO */
	
	processor.resume_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::HierarchicalByteAccumulator::OnDataOverwrite(OffsetLengthEvent &event)
{
	/* TODO */
	
	processor.resume_threads();
	
	/* Continue propogation. */
	event.Skip();
}
