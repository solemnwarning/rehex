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
#include "profile.hpp"

constexpr size_t REHex::HierarchicalByteAccumulator::L2_CACHE_SIZE;

REHex::HierarchicalByteAccumulator::HierarchicalByteAccumulator(const SharedDocumentPointer &document, size_t num_shards):
	document(document),
	range_offset(BitOffset::ZERO),
	range_length(document->buffer_length()),
	whole_file(true),
	target_num_shards(num_shards),
	chunk_size(0),
	l2_cache(L2_CACHE_SIZE)
{
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::HierarchicalByteAccumulator::OnDataErase,     this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::HierarchicalByteAccumulator::OnDataInsert,    this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::HierarchicalByteAccumulator::OnDataOverwrite, this);
	
	this->document.auto_cleanup_bind(DATA_ERASING,              &REHex::HierarchicalByteAccumulator::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_ERASE_ABORTED,        &REHex::HierarchicalByteAccumulator::OnDataModifyAborted,    this);
	this->document.auto_cleanup_bind(DATA_INSERTING,            &REHex::HierarchicalByteAccumulator::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_INSERT_ABORTED,       &REHex::HierarchicalByteAccumulator::OnDataModifyAborted,    this);
	
	/* Placeholder. */
	processor.reset(new RangeProcessor([this](off_t offset, off_t length) {}, 1024));
	
	/* Initialise chunk_size, populate l1 cache and queue up work. */
	update_chunk_size();
}

REHex::HierarchicalByteAccumulator::HierarchicalByteAccumulator(const SharedDocumentPointer &document, BitOffset range_offset, off_t range_length, size_t num_shards):
	document(document),
	range_offset(range_offset),
	range_length(range_length),
	whole_file(false),
	target_num_shards(num_shards),
	chunk_size(0),
	l2_cache(L2_CACHE_SIZE)
{
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::HierarchicalByteAccumulator::OnDataErase,     this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::HierarchicalByteAccumulator::OnDataInsert,    this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::HierarchicalByteAccumulator::OnDataOverwrite, this);
	
	this->document.auto_cleanup_bind(DATA_ERASING,              &REHex::HierarchicalByteAccumulator::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_ERASE_ABORTED,        &REHex::HierarchicalByteAccumulator::OnDataModifyAborted,    this);
	this->document.auto_cleanup_bind(DATA_INSERTING,            &REHex::HierarchicalByteAccumulator::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_INSERT_ABORTED,       &REHex::HierarchicalByteAccumulator::OnDataModifyAborted,    this);
	
	/* Placeholder. */
	processor.reset(new RangeProcessor([this](off_t offset, off_t length) {}, 1024));
	
	/* Initialise chunk_size, populate l1 cache and queue up work. */
	update_chunk_size();
}

void REHex::HierarchicalByteAccumulator::pre_destroy()
{
	processor->pre_destroy();
}

const REHex::ByteAccumulator &REHex::HierarchicalByteAccumulator::get_result()
{
	if(result_rebuild_pending)
	{
		result_rebuild_pending = false;
		
		std::unique_lock<std::mutex> l1_lock_guard(l1_mutex);
		
		result.reset();
		
		for(size_t i = 0; i < l1_cache.size(); ++i)
		{
			result += *(l1_cache[i].accumulator);
		}
	}
	
	return result;
}

std::vector<REHex::HierarchicalByteAccumulator::Shard> REHex::HierarchicalByteAccumulator::get_shards()
{
	std::vector<Shard> shards;
	
	{
		std::unique_lock<std::mutex> l1_lock_guard(l1_mutex);
		
		size_t l1_slots_per_shard = std::max<size_t>((l1_cache.size() / target_num_shards), 1);
		
		for(size_t i = 0, j = 0; i < l1_cache.size() && j < target_num_shards; ++j)
		{
			Shard shard((range_offset + BitOffset(l1_cache[i].offset, 0)), 0);
			
			for(size_t k = 0; (k < l1_slots_per_shard || (j + 1) == target_num_shards) && i < l1_cache.size(); ++k, ++i)
			{
				shard.length += l1_cache[i].length;
				shard.result += *(l1_cache[i].accumulator);
			}
			
			shards.push_back(shard);
		}
	}
	
	return shards;
}

void REHex::HierarchicalByteAccumulator::wait_for_completion()
{
	return processor->wait_for_completion();
}

void REHex::HierarchicalByteAccumulator::flush_l2_cache()
{
	l2_cache.clear();
}

std::pair<size_t, size_t> REHex::HierarchicalByteAccumulator::calc_chunk_size()
{
	/* The "chunk size" is the size of a single block of data read in from the file to be
	 * processed at a time, it is the size of an L2 cache entry and all shard and L1 cache
	 * offsets are aligned to it.
	 *
	 * To allow for up to 64k shards at a time, we start off with the following range length
	 * to chunk size mapping:
	 *
	 * >= 32GiB -> 512KiB
	 * >= 16GiB -> 256KiB
	 * ...
	 * >= 8MiB -> 128 bytes
	 * >= 4MiB ->  64 bytes
	 * >= 0    ->  32 bytes
	*/
	
	size_t chunk_size;
	
	if(     range_length >= (32LL * 1024LL * 1024LL * 1024LL)) { chunk_size = 512 * 1024; }
	else if(range_length >= (16LL * 1024LL * 1024LL * 1024LL)) { chunk_size = 256 * 1024; }
	else if(range_length >= ( 8LL * 1024LL * 1024LL * 1024LL)) { chunk_size = 128 * 1024; }
	else if(range_length >= ( 4LL * 1024LL * 1024LL * 1024LL)) { chunk_size =  64 * 1024; }
	else if(range_length >= ( 2LL * 1024LL * 1024LL * 1024LL)) { chunk_size =  32 * 1024; }
	else if(range_length >= (       1024LL * 1024LL * 1024LL)) { chunk_size =  16 * 1024; }
	else if(range_length >= (        512LL * 1024LL * 1024LL)) { chunk_size =  8  * 1024; }
	else if(range_length >= (        256LL * 1024LL * 1024LL)) { chunk_size =  4  * 1024; }
	else if(range_length >= (        128LL * 1024LL * 1024LL)) { chunk_size =  2  * 1024; }
	else if(range_length >= (         64LL * 1024LL * 1024LL)) { chunk_size =       1024; }
	else if(range_length >= (         32LL * 1024LL * 1024LL)) { chunk_size =        512; }
	else if(range_length >= (         16LL * 1024LL * 1024LL)) { chunk_size =        256; }
	else if(range_length >= (          8LL * 1024LL * 1024LL)) { chunk_size =        128; }
	else if(range_length >= (          4LL * 1024LL * 1024LL)) { chunk_size =         64; }
	else                                                       { chunk_size =         32; }
	
	/* For low (<256) target shard counts, multiply it to the largest multiple which is <=256
	 * for better cache efficiency/performance at the cost of up to half a MiB of memory or so.
	*/
	
	size_t num_l1_slots = target_num_shards < 256
		? target_num_shards * (256 / target_num_shards)
		: target_num_shards;
	
	/* For less extreme numbers of shards, we multiply the chunk size for better performance
	 * since the range doesn't need to be split into so many chunks.
	 *
	 * At 16k shards:
	 *
	 * >= 32GiB -> 2MiB
	 * >= 16GiB -> 1MiB
	 * ...
	 * >= 8MiB -> 512 bytes
	 * >= 4MiB -> 256 bytes
	 * >= 0    -> 128 bytes
	 *
	 * At 1k shards:
	 *
	 * >= 32GiB -> 32MiB
	 * >= 16GiB -> 16MiB
	 * ...
	 * >= 8MiB -> 8KiB
	 * >= 4MiB -> 4KiB
	 * >= 0    -> 2KiB
	 *
	 * At 128 shards:
	 *
	 * >= 32GiB -> 256MiB
	 * >= 16GiB -> 128MiB
	 * ...
	 * >= 8MiB -> 64KiB
	 * >= 4MiB -> 32KiB
	 * >= 0    -> 16KiB
	*/
	
	if(num_l1_slots <= 32768) { chunk_size *= 2; }
	if(num_l1_slots <= 16384) { chunk_size *= 2; }
	if(num_l1_slots <= 8192)  { chunk_size *= 2; }
	if(num_l1_slots <= 4096)  { chunk_size *= 2; }
	if(num_l1_slots <= 2048)  { chunk_size *= 2; }
	if(num_l1_slots <= 1024)  { chunk_size *= 2; }
	if(num_l1_slots <= 512)   { chunk_size *= 2; }
	if(num_l1_slots <= 256)   { chunk_size *= 2; }
	if(num_l1_slots <= 128)   { chunk_size *= 2; }
	
	/* And finally, we cap the chunk size at 8MiB to ensure a single chunk can't tie up a
	 * worker thread for a noticable amount of time.
	*/
	
	chunk_size = std::min<size_t>(chunk_size, (8 * 1024 * 1024));
	
	return std::make_pair(chunk_size, num_l1_slots);
}

void REHex::HierarchicalByteAccumulator::update_chunk_size()
{
	size_t new_chunk_size, l1_slot_count;
	std::tie(new_chunk_size, l1_slot_count) = calc_chunk_size();
	
	if(new_chunk_size == chunk_size)
	{
		return;
	}
	
	processor->pause_threads();
	
	std::vector<L1CacheNode> new_l1_cache;
	new_l1_cache.reserve(l1_slot_count);
	
	off_t l1_slot_base_size = range_length / l1_slot_count;
	
	if(l1_slot_base_size == 0)
	{
		l1_slot_base_size = 1;
	}
	else if(l1_slot_base_size > (off_t)(new_chunk_size) && (l1_slot_base_size % new_chunk_size) != 0)
	{
		l1_slot_base_size -= l1_slot_base_size % new_chunk_size;
	}
	
	off_t next_l1_offset = 0;
	
	for(size_t i = 0;
		(i + 1) < (l1_slot_count) && (next_l1_offset + (off_t)(l1_slot_base_size)) <= range_length;
		++i, next_l1_offset += l1_slot_base_size)
	{
		new_l1_cache.emplace_back(next_l1_offset, l1_slot_base_size, true);
	}
	
	if(next_l1_offset < range_length)
	{
		new_l1_cache.emplace_back(next_l1_offset, (range_length - next_l1_offset), true);
	}
	
	chunk_size = new_chunk_size;
	l1_cache = std::move(new_l1_cache);
	
	processor.reset(new RangeProcessor([this](off_t offset, off_t length) { process_range(offset, length); }, chunk_size));
	processor->queue_range(0, range_length);
}

void REHex::HierarchicalByteAccumulator::process_range(off_t offset, off_t length)
{
	PROFILE_BLOCK("REHex::HierarchicalByteAccumulator::process_range");
	
	off_t chunk_offset = offset;
	off_t chunk_length = length;
	
	size_t l1_slot_idx;
	{
		std::unique_lock<std::mutex> l1_lock_guard(l1_mutex);
		
		l1_slot_idx = relative_offset_to_l1_cache_idx(offset);
		
		/* Step back to the start of the L2 slots which are aligned relative to the start
		 * of the L1 slot (if necessary).
		*/
		if(((chunk_offset - l1_cache[l1_slot_idx].offset) % chunk_size) != 0)
		{
			chunk_offset -= (chunk_offset - l1_cache[l1_slot_idx].offset) % chunk_size;
		}
		
		off_t l1_remaining = l1_cache[l1_slot_idx].length - (chunk_offset - l1_cache[l1_slot_idx].offset);
		
		assert((chunk_offset + l1_remaining) == (l1_cache[l1_slot_idx].offset + l1_cache[l1_slot_idx].length));
		
		chunk_length = std::min<off_t>(chunk_size, l1_remaining);
		
		assert(chunk_offset <= offset);
		// assert(chunk_length == (off_t)(chunk_size) || chunk_length == (l1_cache[l1_slot_idx].offset + l1_cache[l1_slot_idx].length));
		
		if((offset + length) > (chunk_offset + chunk_length))
		{
			/* We've been given a range which overlaps multiple chunks, return the
			 * overflow to the RangeProcessor to be processed later.
			*/
			
			processor->queue_range_in_worker((chunk_offset + chunk_length), ((offset + length) - (chunk_offset + chunk_length)));
		}
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
		
		if(l1_counted.isset(chunk_offset, chunk_length))
		{
			/* Our chunk wasn't found in the L2 cache but has been recorded in the L1
			 * cache, we don't know the previous values to subtract, so every chunk in
			 * the L1 cache slot needs to be re-counted.
			 *
			 * All relevant chunks will be re-queued to the RangeProcessor within the
			 * l1_cache_reset_slot() call, causing us to be called again in the future,
			 * so we just return afterwards.
			*/
			
			l1_counted.clear_range(l1_cache[l1_slot_idx].offset, l1_cache[l1_slot_idx].length);
			l1_cache[l1_slot_idx].accumulator->reset();
			
			processor->queue_range_in_worker(l1_cache[l1_slot_idx].offset, l1_cache[l1_slot_idx].length);
			
			std::unique_lock<std::mutex> l2_lock_guard(l2_mutex);
			
			l2_cache.erase(l1_cache[l1_slot_idx].offset, (l1_cache[l1_slot_idx].offset + l1_cache[l1_slot_idx].length));
			
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
	
	{
		std::unique_lock<std::mutex> l1_lock_guard(l1_mutex);
		
		if(l1_counted.isset(chunk_offset, chunk_length))
		{
			/* This range was previously recorded in the L1 accumulator, subtract the last
			* counts from it before adding the new ones.
			*/
			
			*(l1_cache[l1_slot_idx].accumulator) -= prev_chunk_accumulator;
		}
		else{
			l1_counted.set_range(chunk_offset, chunk_length);
		}
		
		*(l1_cache[l1_slot_idx].accumulator) += chunk_accumulator;
	}
	
	result_rebuild_pending = true;
}

size_t REHex::HierarchicalByteAccumulator::relative_offset_to_l1_cache_idx(off_t relative_offset)
{
	assert(relative_offset >= 0);
	assert(relative_offset < range_length);
	
	auto it = std::upper_bound(l1_cache.begin(), l1_cache.end(), L1CacheNode(relative_offset, 0, false),
		[](const L1CacheNode &a, const L1CacheNode &b) { return a.offset < b.offset; });
	
	return (--it) - l1_cache.begin();
}

void REHex::HierarchicalByteAccumulator::OnDataModifying(OffsetLengthEvent &event)
{
	processor->pause_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::HierarchicalByteAccumulator::OnDataModifyAborted(OffsetLengthEvent &event)
{
	processor->resume_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::HierarchicalByteAccumulator::OnDataErase(OffsetLengthEvent &event)
{
	if(whole_file)
	{
		/* Following document size. */
		
		/* Repopulate the work queue, adjusting the offset of any previously queued ranges
		 * at/after the insertion point to be correct.
		*/
		
		ByteRangeSet pending_ranges = processor->get_queue();
		processor->clear_queue();
		
		pending_ranges.data_erased(event.offset, event.length);
		
		for(auto r = pending_ranges.begin(); r != pending_ranges.end(); ++r)
		{
			processor->queue_range(r->offset, r->length);
		}
		
		/* Find the L1 slot covering the start of the erased range. */
		size_t l1_slot_idx = relative_offset_to_l1_cache_idx(event.offset);
		
		off_t erase_remaining = event.length;
		off_t l1_slot_offset = event.offset - l1_cache[l1_slot_idx].offset;
		
		for(size_t i = l1_slot_idx; i < l1_cache.size();)
		{
			if(erase_remaining > 0)
			{
				off_t erase_from_this_slot = std::min(erase_remaining, (l1_cache[i].length - l1_slot_offset));
				
				l1_cache[i].length -= erase_from_this_slot;
				erase_remaining -= erase_from_this_slot;
				
				if(l1_cache[i].length == 0)
				{
					l1_cache.erase(std::next(l1_cache.begin(), i));
				}
				else{
					if(l1_cache[i].offset > event.offset)
					{
						l1_cache[i].offset -= event.length;
					}
					
					/* Flag the whole L1 cache slot to be re-scanned. */
					processor->queue_range(l1_cache[i].offset, l1_cache[i].length);
					
					++i;
				}
				
				l1_slot_offset = 0; /* Erase resumes at start of next slot. */
			}
			else{
				l1_cache[i].offset -= event.length;
				++i;
			}
		}
		
		assert(erase_remaining == 0);
		
		/* Clear all L2 cache entries from the erased point - we need to repopulate it
		 * from scratch since L2 cache key alignment will no longer be correct.
		*/
		l2_cache.erase(event.offset, (event.offset + (range_length - event.offset)));
		
		/* Grow range_length to new file size. */
		range_length -= event.length;
	}
	else{
		/* Fixed range. Refresh any offsets affected by the erase. */
		
		if(event.offset <= range_offset.byte())
		{
			processor->queue_range(0, range_length);
		}
		else if(event.offset < (range_offset.byte_round_up() + range_length))
		{
			off_t refresh_from = event.offset - range_offset.byte();
			off_t refresh_length = range_length - refresh_from;
			
			processor->queue_range(refresh_from, refresh_length);
		}
	}
	
	processor->resume_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::HierarchicalByteAccumulator::OnDataInsert(OffsetLengthEvent &event)
{
	if(whole_file)
	{
		/* Following document size. */
		
		/* Find the L1 slot covering the insertion offset. */
		size_t l1_slot_idx = relative_offset_to_l1_cache_idx(event.offset);
		
		/* Clear all L2 cache entries within the L1 cache slot - we need to repopulate it
		 * from scratch since L2 cache key alignment will no longer be correct.
		*/
		l2_cache.erase(l1_cache[l1_slot_idx].offset, (l1_cache[l1_slot_idx].offset + l1_cache[l1_slot_idx].length));
		
		/* Extend the L1 cache slot range to cover the newly inserted data. */
		l1_cache[l1_slot_idx].length += event.length;
		
		/* Shuffle the offset of any subsequent L1 slots along. */
		for(size_t i = (l1_slot_idx + 1); i < l1_cache.size(); ++i)
		{
			l1_cache[i].offset += event.length;
		}
		
		/* Grow range_length to new file size. */
		range_length += event.length;
		
		/* Repopulate the work queue, adjusting the offset of any previously queued ranges
		 * at/after the insertion point to be correct.
		*/
		
		ByteRangeSet pending_ranges = processor->get_queue();
		processor->clear_queue();
		
		for(auto r = pending_ranges.begin(); r != pending_ranges.end(); ++r)
		{
			if((range_offset.byte() + r->offset) < event.offset)
			{
				processor->queue_range(r->offset, r->length);
			}
			else{
				processor->queue_range((r->offset + event.length), r->length);
			}
		}
		
		/* Flag the whole L1 cache slot to be re-scanned. */
		processor->queue_range(l1_cache[l1_slot_idx].offset, l1_cache[l1_slot_idx].length);
	}
	else{
		/* Fixed range. Refresh any offsets affected by the insert. */
		
		if(event.offset <= range_offset.byte())
		{
			processor->queue_range(0, range_length);
		}
		else if(event.offset < (range_offset.byte_round_up() + range_length))
		{
			off_t refresh_from = event.offset - range_offset.byte();
			off_t refresh_length = range_length - refresh_from;
			
			processor->queue_range(refresh_from, refresh_length);
		}
	}
	
	processor->resume_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::HierarchicalByteAccumulator::OnDataOverwrite(OffsetLengthEvent &event)
{
	off_t clamped_offset, clamped_length;
	std::tie(clamped_offset, clamped_length) = event.get_clamped_range(range_offset.byte(), range_length);
	
	if(clamped_length > 0)
	{
		processor->queue_range((clamped_offset - range_offset.byte()), clamped_length);
	}
	
	processor->resume_threads();
	
	/* Continue propogation. */
	event.Skip();
}
