/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <algorithm>
#include <assert.h>
#include <mutex>
#include <numeric>
#include <thread>

#include "ByteRangeSet.hpp"

REHex::ByteRangeSet &REHex::ByteRangeSet::set_range(off_t offset, off_t length)
{
	if(length <= 0)
	{
		return *this;
	}
	
	Range range(offset, length);
	set_ranges(&range, (&range) + 1);
	
	return *this;
}

void REHex::ByteRangeSet::clear_range(off_t offset, off_t length)
{
	if(length <= 0)
	{
		return;
	}
	
	Range range(offset, length);
	clear_ranges(&range, (&range) + 1);
}

void REHex::ByteRangeSet::clear_all()
{
	ranges.clear();
}

bool REHex::ByteRangeSet::isset(off_t offset, off_t length) const
{
	auto lb = std::lower_bound(ranges.begin(), ranges.end(), Range(offset, 0));
	
	if(lb != ranges.end() && lb->offset == offset && (lb->offset + lb->length) >= (offset + length))
	{
		return true;
	}
	else if(lb != ranges.begin())
	{
		--lb;
		
		if(lb->offset <= offset && (lb->offset + lb->length) >= (offset + length))
		{
			return true;
		}
	}
	
	return false;
}

bool REHex::ByteRangeSet::isset_any(off_t offset, off_t length) const
{
	ByteRangeSet check;
	check.set_range(offset, length);
	
	ByteRangeSet i = intersection(*this, check);
	
	return !i.empty();
}

off_t REHex::ByteRangeSet::total_bytes() const
{
	off_t total_bytes = std::accumulate(ranges.begin(), ranges.end(),
		(off_t)(0), [](off_t sum, const Range &range) { return sum + range.length; });
	
	return total_bytes;
}

const std::vector<REHex::ByteRangeSet::Range> &REHex::ByteRangeSet::get_ranges() const
{
	return ranges;
}

std::vector<REHex::ByteRangeSet::Range>::const_iterator REHex::ByteRangeSet::begin() const
{
	return ranges.begin();
}

std::vector<REHex::ByteRangeSet::Range>::const_iterator REHex::ByteRangeSet::end() const
{
	return ranges.end();
}

const REHex::ByteRangeSet::Range &REHex::ByteRangeSet::operator[](size_t idx) const
{
	assert(idx < ranges.size());
	return ranges[idx];
}

size_t REHex::ByteRangeSet::size() const
{
	return ranges.size();
}

bool REHex::ByteRangeSet::empty() const
{
	return ranges.empty();
}

void REHex::ByteRangeSet::data_inserted(off_t offset, off_t length)
{
	std::mutex lock;
	std::vector<Range> insert_elem;
	size_t insert_idx;
	
	auto process_block = [&](size_t work_base, size_t work_length)
	{
		for(size_t i = work_base; i < (work_base + work_length); ++i)
		{
			Range *range = &(ranges[i]);
			
			if(range->offset >= offset)
			{
				/* Range begins after the insertion point, offset it. */
				range->offset += length;
			}
			else if(range->offset < offset && (range->offset + range->length) > offset)
			{
				/* Range straddles the insertion point, split it.
				 *
				 * The first half of the new range is queued for insertion later,
				 * after processing is done so threads don't need to synchronise or
				 * handle the vector moving around.
				 *
				 * Second half of the new range replaces the range.
				*/
				
				std::unique_lock<std::mutex> l(lock);
				
				assert(insert_elem.empty());
				
				insert_elem.push_back(Range(range->offset, (offset - range->offset)));
				insert_idx = i;
				
				range->length -= (offset - range->offset);
				range->offset = offset + length;
			}
		}
	};
	
	/* Split the ranges vector up into blocks which can be processed by different threads.
	 * A thread is spawned for each block up to the CPU limit (including the current thread).
	*/
	
	unsigned int max_threads = std::thread::hardware_concurrency();
	
	size_t next_block = 0;
	size_t thread_block_size = ranges.size() / max_threads;
	
	if(ranges.size() < DATA_INSERTED_THREAD_MIN)
	{
		/* We don't have enough data to be worth the overhead of spawning threads. */
		thread_block_size = 0;
	}
	
	std::vector<std::thread> threads;
	
	for(unsigned int i = 1; thread_block_size > 0 && i < max_threads; ++i)
	{
		threads.emplace_back(process_block, next_block, thread_block_size);
		next_block += thread_block_size;
	}
	
	/* We process the last block in this thread, up to the end of the vector as
	 * thread_block_size is likely to have rounding errors.
	*/
	process_block(next_block, (ranges.size() - next_block));
	
	/* Wait for other threads to finish. */
	for(auto t = threads.begin(); t != threads.end(); ++t)
	{
		t->join();
	}
	
	/* Perform queued insertion, if there was a range straddling the insertion point. */
	if(!insert_elem.empty())
	{
		assert(insert_elem.size() == 1);
		ranges.insert(std::next(ranges.begin(), insert_idx), insert_elem[0]);
	}
}

void REHex::ByteRangeSet::data_erased(off_t offset, off_t length)
{
	/* Find the range of elements overlapping the range to be erased. */
	
	auto next = std::lower_bound(ranges.begin(), ranges.end(), Range((offset + length), 0));
	
	std::vector<Range>::iterator erase_begin = next;
	std::vector<Range>::iterator erase_end   = next;
	
	while(erase_begin != ranges.begin())
	{
		auto sb_prev = std::prev(erase_begin);
		
		if((sb_prev->offset + sb_prev->length) > offset)
		{
			erase_begin = sb_prev;
		}
		else{
			break;
		}
	}
	
	/* Add a single range encompassing the existing range(s) immediately before or after the
	 * erase window (if any exist).
	*/
	
	if(erase_begin != erase_end)
	{
		auto erase_last = std::prev(erase_end);
		
		off_t begin = std::min(erase_begin->offset, offset);
		off_t end   = erase_last->offset + erase_last->length;
		
		erase_end = ranges.erase(erase_begin, erase_end);
		
		if(end > (offset + length))
		{
			end -= length;
			erase_end = ranges.insert(erase_end, Range(begin, (end - begin)));
			++erase_end;
		}
		else if(begin < offset)
		{
			end = offset;
			erase_end = ranges.insert(erase_end, Range(begin, (end - begin)));
			++erase_end;
		}
	}
	
	/* Adjust the offset of ranges after the erase window. */
	
	while(erase_end != ranges.end())
	{
		erase_end->offset -= length;
		++erase_end;
	}
}

REHex::ByteRangeSet REHex::ByteRangeSet::intersection(const ByteRangeSet &a, const ByteRangeSet &b)
{
	if(a.empty() || b.empty())
	{
		return ByteRangeSet();
	}
	
	ByteRangeSet intersection;
	
	auto ai = a.begin();
	auto bi = b.begin();
	
	while(ai != a.end() && bi != b.end())
	{
		off_t a_end = ai->offset + ai->length;
		off_t b_end = bi->offset + bi->length;
		
		if(a_end <= bi->offset)
		{
			++ai;
		}
		else if(b_end <= ai->offset)
		{
			++bi;
		}
		else{
			off_t overlap_begin = std::max(ai->offset, bi->offset);
			off_t overlap_end   = std::min(a_end, b_end);
			
			if(overlap_end > overlap_begin)
			{
				intersection.set_range(overlap_begin, (overlap_end - overlap_begin));
			}
			
			if(a_end < b_end)
			{
				++ai;
			}
			else if(b_end < a_end)
			{
				++bi;
			}
			else{
				++ai;
				++bi;
			}
		}
	}
	
	return intersection;
}

REHex::OrderedByteRangeSet &REHex::OrderedByteRangeSet::set_range(off_t offset, off_t length)
{
	/* Exclude any ranges already set from the offset/length so we can push exclusive ranges
	 * onto the sorted_ranges vector.
	*/
	
	ByteRangeSet ranges_to_set;
	ranges_to_set.set_range(offset, length);
	
	for(auto i = sorted_ranges.begin(); i != sorted_ranges.end(); ++i)
	{
		ranges_to_set.clear_range(i->offset, i->length);
	}
	
	/* Set any resulting ranges in the internal ByteRangeSet and our sorted_ranges vector. */
	
	for(auto i = ranges_to_set.begin(); i != ranges_to_set.end(); ++i)
	{
		brs.set_range(offset, length);
		sorted_ranges.push_back(*i);
	}
	
	return *this;
}

bool REHex::OrderedByteRangeSet::isset(off_t offset, off_t length) const
{
	return brs.isset(offset, length);
}

bool REHex::OrderedByteRangeSet::isset_any(off_t offset, off_t length) const
{
	return brs.isset_any(offset, length);
}

off_t REHex::OrderedByteRangeSet::total_bytes() const
{
	return brs.total_bytes();
}

const std::vector<REHex::ByteRangeSet::Range> &REHex::OrderedByteRangeSet::get_ranges() const
{
	return sorted_ranges;
}

std::vector<REHex::ByteRangeSet::Range>::const_iterator REHex::OrderedByteRangeSet::begin() const
{
	return sorted_ranges.begin();
}

std::vector<REHex::ByteRangeSet::Range>::const_iterator REHex::OrderedByteRangeSet::end() const
{
	return sorted_ranges.end();
}

const REHex::ByteRangeSet::Range &REHex::OrderedByteRangeSet::operator[](size_t idx) const
{
	assert(idx < sorted_ranges.size());
	return sorted_ranges[idx];
}

size_t REHex::OrderedByteRangeSet::size() const
{
	return sorted_ranges.size();
}

bool REHex::OrderedByteRangeSet::empty() const
{
	return sorted_ranges.empty();
}
