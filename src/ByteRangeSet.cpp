/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

static const long long INT61_MIN = -0x1000000000000000LL;
static const long long INT61_MAX = 0xFFFFFFFFFFFFFFFLL;

template<> off_t REHex::RangeSet<off_t>::MAX()
{
	return std::numeric_limits<off_t>::max();
}

template<> REHex::BitOffset REHex::RangeSet<REHex::BitOffset>::MAX()
{
	return BitOffset(INT61_MAX, 7);
}

template<typename OT> REHex::RangeSet<OT> &REHex::RangeSet<OT>::set_range(OT offset, OT length)
{
	if(length <= 0)
	{
		return *this;
	}
	
	Range range(offset, length);
	set_ranges(&range, (&range) + 1);
	
	return *this;
}

template<typename OT> void REHex::RangeSet<OT>::clear_range(OT offset, OT length)
{
	if(length <= 0)
	{
		return;
	}
	
	Range range(offset, length);
	clear_ranges(&range, (&range) + 1);
}

template<typename OT> void REHex::RangeSet<OT>::clear_all()
{
	ranges.clear();
}

template<typename OT> bool REHex::RangeSet<OT>::isset(OT offset, OT length) const
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

template<typename OT> bool REHex::RangeSet<OT>::isset_any(OT offset, OT length) const
{
	RangeSet<OT> check;
	check.set_range(offset, length);
	
	RangeSet<OT> i = intersection(*this, check);
	
	return !i.empty();
}

template<typename OT> typename REHex::RangeSet<OT>::const_iterator REHex::RangeSet<OT>::find_first_in(OT offset, OT length) const
{
	auto i = std::lower_bound(ranges.begin(), ranges.end(), Range(offset, 0));
	
	if(i != ranges.begin())
	{
		--i;
	}
	
	OT end = (MAX() - length) < offset
		? MAX()
		: offset + length;
	
	for(; i != ranges.end() && (i->offset < end || end < offset); ++i)
	{
		OT i_end = i->offset + i->length;
		
		if((i->offset < end || end < offset) && offset < i_end)
		{
			return i;
		}
	}
	
	/* No match. */
	return ranges.end();
}

template<typename OT> typename REHex::RangeSet<OT>::const_iterator REHex::RangeSet<OT>::find_last_in(OT offset, OT length) const
{
	auto i = find_first_in((offset + length), std::numeric_limits<off_t>::max());
	
	if(i != ranges.end() && i->offset < (offset + length))
	{
		/* This is a Range spanning the end of the search range, match. */
		return i;
	}
	
	if(i != ranges.begin())
	{
		/* Step back from the end or first Range following the search range... */
		--i;
		
		if((i->offset + i->length) > offset)
		{
			/* ...the preceeding one ends somewhere in the search range, match. */
			return i;
		}
	}
	
	/* No match. */
	return ranges.end();
}

template<typename OT> OT REHex::RangeSet<OT>::total_bytes() const
{
	OT total_bytes = std::accumulate(ranges.begin(), ranges.end(),
		(OT)(0), [](OT sum, const Range &range) { return sum + range.length; });
	
	return total_bytes;
}

template<typename OT> const std::vector<typename REHex::RangeSet<OT>::Range> &REHex::RangeSet<OT>::get_ranges() const
{
	return ranges;
}

template<typename OT> typename REHex::RangeSet<OT>::const_iterator REHex::RangeSet<OT>::begin() const
{
	return ranges.begin();
}

template<typename OT> typename REHex::RangeSet<OT>::const_iterator REHex::RangeSet<OT>::end() const
{
	return ranges.end();
}

template<typename OT> const typename REHex::RangeSet<OT>::Range &REHex::RangeSet<OT>::operator[](size_t idx) const
{
	assert(idx < ranges.size());
	return ranges[idx];
}

template<typename OT> size_t REHex::RangeSet<OT>::size() const
{
	return ranges.size();
}

template<typename OT> bool REHex::RangeSet<OT>::empty() const
{
	return ranges.empty();
}

template<typename OT> void REHex::RangeSet<OT>::data_inserted_impl(OT offset, OT length)
{
	REHEX_BYTERANGESET_CHECK_PRE(ranges.begin(), ranges.end());
	
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
	
	REHEX_BYTERANGESET_CHECK_POST(ranges.begin(), ranges.end());
}

template<> void REHex::RangeSet<off_t>::data_inserted(off_t offset, off_t length)
{
	data_inserted_impl(offset, length);
}

template<> void REHex::RangeSet<REHex::BitOffset>::data_inserted(off_t offset, off_t length)
{
	data_inserted_impl(BitOffset(offset, 0), BitOffset(length, 0));
}

template<typename OT> void REHex::RangeSet<OT>::data_erased_impl(OT offset, OT length)
{
	REHEX_BYTERANGESET_CHECK_PRE(ranges.begin(), ranges.end());
	
	/* Find the range of elements overlapping the range to be erased. */
	
	auto next = std::lower_bound(ranges.begin(), ranges.end(), Range((offset + length + 1), 0));
	
	typename std::vector<Range>::iterator erase_begin = next;
	typename std::vector<Range>::iterator erase_end   = next;
	
	while(erase_begin != ranges.begin())
	{
		auto sb_prev = std::prev(erase_begin);
		
		if((sb_prev->offset + sb_prev->length) >= offset)
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
		
		OT begin = std::min(erase_begin->offset, offset);
		OT end   = erase_last->offset + erase_last->length;
		
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
	
	REHEX_BYTERANGESET_CHECK_POST(ranges.begin(), ranges.end());
}

template<> void REHex::RangeSet<off_t>::data_erased(off_t offset, off_t length)
{
	data_erased_impl(offset, length);
}

template<> void REHex::RangeSet<REHex::BitOffset>::data_erased(off_t offset, off_t length)
{
	data_erased_impl(BitOffset(offset, 0), BitOffset(length, 0));
}

template<typename OT> REHex::RangeSet<OT> REHex::RangeSet<OT>::intersection(const RangeSet<OT> &a, const RangeSet<OT> &b)
{
	if(a.empty() || b.empty())
	{
		return RangeSet<OT>();
	}
	
	RangeSet<OT> intersection;
	
	auto ai = a.begin();
	auto bi = b.begin();
	
	while(ai != a.end() && bi != b.end())
	{
		OT a_end = ai->offset + ai->length;
		OT b_end = bi->offset + bi->length;
		
		if(a_end <= bi->offset)
		{
			++ai;
		}
		else if(b_end <= ai->offset)
		{
			++bi;
		}
		else{
			OT overlap_begin = std::max(ai->offset, bi->offset);
			OT overlap_end   = std::min(a_end, b_end);
			
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
	
	REHEX_BYTERANGESET_CHECK(intersection.begin(), intersection.end());
	
	return intersection;
}

/* Instantiate ByteRangeSet and BitRangeSet methods. */
template class REHex::RangeSet<off_t>;
template class REHex::RangeSet<REHex::BitOffset>;

template<typename OT> REHex::OrderedRangeSet<OT> &REHex::OrderedRangeSet<OT>::set_range(OT offset, OT length)
{
	/* Exclude any ranges already set from the offset/length so we can push exclusive ranges
	 * onto the sorted_ranges vector.
	*/
	
	RangeSet<OT> ranges_to_set;
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

template<typename OT> bool REHex::OrderedRangeSet<OT>::isset(OT offset, OT length) const
{
	return brs.isset(offset, length);
}

template<typename OT> bool REHex::OrderedRangeSet<OT>::isset_any(OT offset, OT length) const
{
	return brs.isset_any(offset, length);
}

template<typename OT> OT REHex::OrderedRangeSet<OT>::total_bytes() const
{
	return brs.total_bytes();
}

template<typename OT> const std::vector<typename REHex::RangeSet<OT>::Range> &REHex::OrderedRangeSet<OT>::get_ranges() const
{
	return sorted_ranges;
}

template<typename OT> typename std::vector<typename REHex::RangeSet<OT>::Range>::const_iterator REHex::OrderedRangeSet<OT>::begin() const
{
	return sorted_ranges.begin();
}

template<typename OT> typename std::vector<typename REHex::RangeSet<OT>::Range>::const_iterator REHex::OrderedRangeSet<OT>::end() const
{
	return sorted_ranges.end();
}

template<typename OT> const typename REHex::RangeSet<OT>::Range &REHex::OrderedRangeSet<OT>::operator[](size_t idx) const
{
	assert(idx < sorted_ranges.size());
	return sorted_ranges[idx];
}

template<typename OT> size_t REHex::OrderedRangeSet<OT>::size() const
{
	return sorted_ranges.size();
}

template<typename OT> bool REHex::OrderedRangeSet<OT>::empty() const
{
	return sorted_ranges.empty();
}

/* Instantiate OrderedByteRangeSet and OrderedBitRangeSet methods. */
template class REHex::OrderedRangeSet<off_t>;
template class REHex::OrderedRangeSet<REHex::BitOffset>;
