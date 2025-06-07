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

#ifndef REHEX_BYTERANGEMAP_HPP
#define REHEX_BYTERANGEMAP_HPP

#include <algorithm>
#include <assert.h>
#include <atomic>
#include <functional>
#include <iterator>
#include <mutex>
#include <sys/types.h>
#include <thread>
#include <utility>
#include <vector>

#include "BitOffset.hpp"
#include "shared_mutex.hpp"

namespace REHex
{
	/**
	 * @brief Associative container for mapping byte ranges to values.
	 *
	 * This class is a wrapper around std::vector that can be used for associating values with
	 * ranges in the file. Any ranges which are adjacent or overlapping and have the same value
	 * will be merged to reduce memory consumption, so only each unique contiguous range added
	 * will take space in memory.
	 *
	 * You probably want to use the BitRangeMap<T> and/or ByteRangeMap<T> specialisations of
	 * this class.
	*/
	template<typename OT, typename T> class RangeMap
	{
		public:
			/**
			 * @brief A range stored within a RangeMap.
			*/
			struct Range
			{
				OT offset;
				OT length;
				
				Range(OT offset, OT length):
					offset(offset), length(length) {}
				
				bool operator<(const Range &rhs) const
				{
					if(offset != rhs.offset)
					{
						return offset < rhs.offset;
					}
					else{
						return length < rhs.length;
					}
				}
				
				bool operator==(const Range &rhs) const
				{
					return offset == rhs.offset && length == rhs.length;
				}
			};
			
			typedef typename std::vector< std::pair<Range, T> >::iterator iterator;
			typedef typename std::vector< std::pair<Range, T> >::const_iterator const_iterator;
			
			template<typename OT2 = OT>
			static typename std::enable_if<std::is_same<OT2, off_t>::value, OT>::type
			OT_MAX()
			{
				return std::numeric_limits<off_t>::max();
			}
			
			template<typename OT2 = OT>
			static typename std::enable_if<std::is_same<OT2, BitOffset>::value, OT>::type
			OT_MAX()
			{
				return BitOffset::MAX;
			}
			
		private:
			T default_value;
			
			std::vector< std::pair<Range, T> > ranges;
			
			/* Last iterator returned by get_range(), used to avoid a lookup from
			 * scratch when a nearby offset is requested again.
			*/
			mutable typename std::vector< std::pair<Range, T> >::const_iterator last_get_iter;
			mutable shared_mutex lgi_mutex;
			
		public:
			/**
			 * @brief Construct an empty map.
			*/
			RangeMap(const T &default_value = T()):
				default_value(default_value),
				last_get_iter(ranges.end()) {}
			
			RangeMap(const RangeMap &src):
				default_value(src.default_value),
				ranges(src.ranges),
				last_get_iter(ranges.end()) {}
			
			RangeMap &operator=(const RangeMap<OT, T> &rhs)
			{
				default_value = rhs.default_value;
				ranges = rhs.ranges;
				last_get_iter = ranges.end();
				
				return *this;
			}
			
			bool operator==(const RangeMap<OT, T> &rhs) const
			{
				return ranges == rhs.ranges;
			}
			
			bool operator!=(const RangeMap<OT, T> &rhs) const
			{
				return ranges != rhs.ranges;
			}
			
			/**
			 * @brief Construct a map from a sequence of ranges.
			 *
			 * NOTE: The ranges MUST be in order and MUST NOT be adjacent
			 * (unless the values differ).
			*/
			template<typename I> RangeMap(const I begin, const I end, const T &default_value = T()):
				default_value(default_value),
				ranges(begin, end),
				last_get_iter(ranges.end()) {}
			
			/**
			 * @brief Search the map for a range encompassing the given offset.
			 *
			 * Returns an iterator to the relevant range, end if there isn't one.
			*/
			const_iterator get_range(OT offset) const;
			
			/**
			 * @brief Search the map for a range intersecting with the given range.
			 *
			 * Returns an iterator to the first intersecting range, end if there aren't
			 * any.
			*/
			const_iterator get_range_in(OT offset, OT length) const;
			
			/**
			 * @brief Set a range of bytes in the map.
			 *
			 * This method adds a range of bytes to the set. Any existing ranges
			 * adjacent to or within the new range will be merged into the new range
			 * and removed from the set.
			*/
			void set_range(OT offset, OT length, const T &value);
			
			/**
			 * @brief Clear a range of bytes in the map.
			 *
			 * This method removes any elements from the map overlapping the given byte
			 * range. If any elements partially intersect the given range, the portion
			 * outside of the range will be preserved.
			*/
			void clear_range(OT offset, OT length);
			
			/**
			 * @brief Get a subset of the ranges defined in the map.
			 *
			 * This method builds a RangeMap containing any ranges intersecting the
			 * given range, clamped to the ends of the range.
			*/
			RangeMap<OT, T> get_slice(OT offset, OT length) const;
			
			/**
			 * @brief Set all keys defined in another RangeMap.
			 *
			 * This method copies ranges from another RangeMap, overwriting any
			 * already set in this one.
			*/
			void set_slice(const RangeMap<OT, T> &slice);
			
			/**
			 * @brief Transform all values defined in the map.
			 *
			 * This method transforms ALL values in the map through the given function.
			 *
			 * The existing map is modified and a reference to it is returned as a
			 * convenience to allow for chaining.
			 *
			 * WARNING: The transform MUST NOT cause values that were previously equal
			 * to become not-equal or vice-versa.
			*/
			RangeMap<OT, T> &transform(const std::function<T(const T &value)> &func);
			
			/**
			 * @brief Get a reference to the internal std::vector.
			*/
			const std::vector< std::pair<Range, T> > &get_ranges() const
			{
				return ranges;
			}
			
			const_iterator begin() const { return ranges.begin(); }
			const_iterator end() const { return ranges.end(); }
			bool empty() const { return ranges.empty(); }
			size_t size() const { return ranges.size(); }
			const std::pair<Range, T> &front() const { assert(!ranges.empty()); return ranges.front(); }
			const std::pair<Range, T> &back() const { assert(!ranges.empty()); return ranges.back(); }
			void clear() { ranges.clear(); }
			
		private:
			bool data_inserted_impl(OT offset, OT length);
			bool data_erased_impl(OT offset, OT length);

			static bool elem_key_less(const std::pair<Range, T> &a, const std::pair<Range, T> &b);
			
		public:
			/**
			 * @brief Adjust for data being inserted into file.
			 *
			 * Ranges after the insertion will be moved along by the size of the
			 * insertion. Ranges spanning the insertion will be split.
			*/
			
			template<typename OT2 = OT>
			inline typename std::enable_if<std::is_same<OT2, off_t>::value, bool>::type
			data_inserted(off_t offset, off_t length)
			{
				return data_inserted_impl(offset, length);
			}
			
			template<typename OT2 = OT>
			inline typename std::enable_if<std::is_same<OT2, BitOffset>::value, bool>::type
			data_inserted(off_t offset, off_t length)
			{
				return data_inserted_impl(BitOffset(offset, 0), BitOffset(length, 0));
			}
			
			/**
			 * @brief Minimum number of ranges to make data_inserted() use threads.
			*/
			static const size_t DATA_INSERTED_THREAD_MIN = 100000;
			
			/**
			 * @brief Adjust for data being erased from file.
			 *
			 * Ranges after the section erased will be moved back by the size of the
			 * insertion. Ranges wholly within the erased section will be lost. Ranges
			 * on either side of the erase will be truncated and merged as necessary.
			*/
			
			template<typename OT2 = OT>
			inline typename std::enable_if<std::is_same<OT2, off_t>::value, bool>::type
			data_erased(off_t offset, off_t length)
			{
				return data_erased_impl(offset, length);
			}
			
			template<typename OT2 = OT>
			inline typename std::enable_if<std::is_same<OT2, BitOffset>::value, bool>::type
			data_erased(off_t offset, off_t length)
			{
				return data_erased_impl(BitOffset(offset, 0), BitOffset(length, 0));
			}
	};
	
	template<typename T> using ByteRangeMap = RangeMap<off_t, T>;
	template<typename T> using BitRangeMap = RangeMap<BitOffset, T>;
}

template<typename OT, typename T> typename REHex::RangeMap<OT, T>::const_iterator REHex::RangeMap<OT, T>::get_range(OT offset) const
{
	{
		shared_lock lock_guard(lgi_mutex);
		
		if(last_get_iter != ranges.end() && last_get_iter->first.offset <= offset && (last_get_iter->first.offset + last_get_iter->first.length) > offset)
		{
			return last_get_iter;
		}
	}
	
	/* Starting from the first element after us (or the end of the vector)... */
	auto i = std::lower_bound(ranges.begin(), ranges.end(), std::make_pair(Range((offset + 1), 0), default_value), &elem_key_less);
	
	/* ...check to see if there is an element prior... */
	if(i != ranges.begin())
	{
		--i;
		
		/* ...and if it encompasses the given offset... */
		if(i->first.offset <= offset && (i->first.offset + i->first.length) > offset)
		{
			/* ...it does, return it. */
			
			{
				std::unique_lock<shared_mutex> lock_guard(lgi_mutex);
				last_get_iter = i;
			}
			
			return i;
		}
	}
	
	/* No match. */
	return end();
}

template<typename OT, typename T> typename REHex::RangeMap<OT, T>::const_iterator REHex::RangeMap<OT, T>::get_range_in(OT offset, OT length) const
{
	if(length <= 0)
	{
		return ranges.end();
	}
	
	auto i = std::lower_bound(ranges.begin(), ranges.end(), std::make_pair(Range(offset, 0), default_value), &elem_key_less);
	
	if(i != ranges.begin())
	{
		--i;
	}
	
	OT end = (OT_MAX() - length) < offset
		? OT_MAX()
		: offset + length;
	
	for(; i != ranges.end() && i->first.offset < end; ++i)
	{
		OT i_end = i->first.offset + i->first.length;
		
		if((i->first.offset < end || end < offset) && offset < i_end)
		{
			return i;
		}
	}
	
	/* No match. */
	return ranges.end();
}

template<typename OT, typename T> void REHex::RangeMap<OT, T>::set_range(OT offset, OT length, const T &value)
{
	if(length <= 0)
	{
		return;
	}
	
	/* Find the range of elements that intersects the one we are inserting. They will be erased
	 * and the one we are creating will grow on either end as necessary to encompass them.
	*/
	
	/* Starting from the first element after us (or the end of the vector)... */
	auto next = std::lower_bound(ranges.begin(), ranges.end(), std::make_pair(Range((offset + length), 0), default_value), &elem_key_less);
	
	typename std::vector< std::pair<Range, T> >::iterator erase_begin = next;
	typename std::vector< std::pair<Range, T> >::iterator erase_end   = next;
	
	std::vector< std::pair<Range, T> > insert_before;
	std::vector< std::pair<Range, T> > insert_after;
	
	while(erase_begin != ranges.begin())
	{
		/* ...walking backwards... */
		auto eb_prev = std::prev(erase_begin);
		
		if((eb_prev->first.offset + eb_prev->first.length) >= offset)
		{
			/* ...the previous element intersects the range we wish to set to some extent... */
			
			if(eb_prev->first.offset < offset && eb_prev->second != value)
			{
				/* ...the previous element starts before the range we want to set
				 *    and has a different value, split the first half of it out to
				 *    be replaced afterwards and fold the other half into this
				 *    erase/replace operation.
				*/
				
				insert_before.push_back(std::make_pair(Range(eb_prev->first.offset, (offset - eb_prev->first.offset)), eb_prev->second));
				
				eb_prev->first.length -= (offset - eb_prev->first.offset);
				eb_prev->first.offset = offset;
			}
			
			if((eb_prev->first.offset + eb_prev->first.length) > (offset + length) && eb_prev->second != value)
			{
				/* ...the previous element ends after the range we want to set and
				 *    has a different value, split the second half of it out to be
				 *    replaced afterwards and fold the other half into this
				 *    erase/replace operation.
				*/
				
				OT begin = offset + length;
				OT end   = eb_prev->first.offset + eb_prev->first.length;
				
				insert_after.push_back(std::make_pair(Range(begin, (end - begin)), eb_prev->second));
				
				eb_prev->first.length = begin - eb_prev->first.offset;
			}
			
			/* ...merge any part of this element not already split out by the above
			 *    blocks into our work...
			*/
			
			OT merged_begin = std::min(eb_prev->first.offset, offset);
			OT merged_end   = std::max((eb_prev->first.offset + eb_prev->first.length), (offset + length));
			
			offset = merged_begin;
			length = merged_end - merged_begin;
			
			erase_begin = eb_prev;
		}
		else{
			break;
		}
	}
	
	assert(insert_before.size() <= 1);
	assert(insert_after.size() <= 1);
	
	if(erase_end != ranges.end() && erase_end->first.offset == (offset + length) && erase_end->second == value)
	{
		/* The range we wish to set is directly followed by another range with the same
		 * value, merge it.
		*/
		
		length += erase_end->first.length;
		++erase_end;
	}
	
	/* Erase adjacent and/or overlapping ranges. */
	erase_end = ranges.erase(erase_begin, erase_end);
	
	assert(length > 0);
	
	if(!insert_before.empty())
	{
		/* Re-insert range with different value immediately before the range beging set
		 * that was lost above.
		*/
		
		erase_end = ranges.insert(erase_end, insert_before.front());
		++erase_end;
	}
	
	/* Insert new range. */
	erase_end = ranges.insert(erase_end, std::make_pair(Range(offset, length), value));
	++erase_end;
	
	if(!insert_after.empty())
	{
		/* Re-insert range with different value immediately after the range beging set
		 * that was lost above.
		*/
		
		erase_end = ranges.insert(erase_end, insert_after.front());
		++erase_end;
	}
	
	last_get_iter = ranges.end();
}

template<typename OT, typename T> void REHex::RangeMap<OT, T>::clear_range(OT offset, OT length)
{
	if(length <= 0)
	{
		return;
	}
	
	/* Find the range of elements that intersects the one we are inserting. They will be erased
	 * and the one we are creating will grow on either end as necessary to encompass them.
	*/
	
	/* Starting from the first element after us (or the end of the vector)... */
	auto next = std::lower_bound(ranges.begin(), ranges.end(), std::make_pair(Range((offset + length), 0), default_value), &elem_key_less);
	
	typename std::vector< std::pair<Range, T> >::iterator erase_begin = next;
	typename std::vector< std::pair<Range, T> >::iterator erase_end   = next;
	
	std::vector< std::pair<Range, T> > insert_before;
	std::vector< std::pair<Range, T> > insert_after;
	
	while(erase_begin != ranges.begin())
	{
		/* ...walking backwards... */
		auto eb_prev = std::prev(erase_begin);
		
		if((eb_prev->first.offset + eb_prev->first.length) >= offset)
		{
			/* ...the previous element intersects the range we wish to erase to some extent... */
			
			if(eb_prev->first.offset < offset)
			{
				insert_before.push_back(std::make_pair(Range(eb_prev->first.offset, (offset - eb_prev->first.offset)), eb_prev->second));
			}
			
			if((eb_prev->first.offset + eb_prev->first.length) > (offset + length))
			{
				OT begin = offset + length;
				OT end   = eb_prev->first.offset + eb_prev->first.length;
				
				insert_after.push_back(std::make_pair(Range(begin, (end - begin)), eb_prev->second));
			}
			
			erase_begin = eb_prev;
		}
		else{
			break;
		}
	}
	
	assert(insert_before.size() <= 1);
	assert(insert_after.size() <= 1);
	
	/* Erase adjacent and/or overlapping ranges. */
	erase_end = ranges.erase(erase_begin, erase_end);
	
	if(!insert_before.empty())
	{
		/* Re-insert range with different value immediately before the range beging set
		 * that was lost above.
		*/
		
		erase_end = ranges.insert(erase_end, insert_before.front());
		++erase_end;
	}
	
	if(!insert_after.empty())
	{
		/* Re-insert range with different value immediately after the range beging set
		 * that was lost above.
		*/
		
		erase_end = ranges.insert(erase_end, insert_after.front());
		++erase_end;
	}
	
	last_get_iter = ranges.end();
}

template<typename OT, typename T> REHex::RangeMap<OT, T> REHex::RangeMap<OT, T>::get_slice(OT offset, OT length) const
{
	OT end = offset + length;
	
	RangeMap<OT, T> slice;
	
	for(auto i = get_range_in(offset, length); i != this->end() && i->first.offset < end; ++i)
	{
		OT slice_off = std::max(i->first.offset, offset);
		OT slice_len = std::min(i->first.length, (end - slice_off));
		
		slice.set_range(slice_off, slice_len, i->second);
	}
	
	return slice;
}

template<typename OT, typename T> void REHex::RangeMap<OT, T>::set_slice(const RangeMap<OT, T> &slice)
{
	for(auto i = slice.begin(); i != slice.end(); ++i)
	{
		set_range(i->first.offset, i->first.length, i->second);
	}
}

template<typename OT, typename T> REHex::RangeMap<OT, T> &REHex::RangeMap<OT, T>::transform(const std::function<T(const T &value)> &func)
{
	for(auto i = ranges.begin(); i != ranges.end(); ++i)
	{
		i->second = func(i->second);
	}
	
	return *this;
}

template<typename OT, typename T> bool REHex::RangeMap<OT, T>::data_inserted_impl(OT offset, OT length)
{
	std::mutex lock;
	std::vector< std::pair<Range, T> > insert_elem;
	size_t insert_idx;
	
	std::atomic<bool> elements_changed(false);
	
	auto process_block = [&](size_t work_base, size_t work_length)
	{
		for(size_t i = work_base; i < (work_base + work_length); ++i)
		{
			std::pair<Range, T> *range = &(ranges[i]);
			
			if(range->first.offset >= offset)
			{
				/* Range begins after the insertion point, offset it. */
				range->first.offset += length;
				
				elements_changed = true;
			}
			else if(range->first.offset < offset && (range->first.offset + range->first.length) > offset)
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
				
				insert_elem.push_back(std::make_pair(Range(range->first.offset, (offset - range->first.offset)), range->second));
				insert_idx = i;
				
				range->first.length -= (offset - range->first.offset);
				range->first.offset = offset + length;
				
				elements_changed = true;
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
	
	last_get_iter = ranges.end();
	
	return elements_changed;
}

template<typename OT, typename T> bool REHex::RangeMap<OT, T>::data_erased_impl(OT offset, OT length)
{
	/* Find the range of elements overlapping the range to be erased. */
	
	auto next = std::lower_bound(ranges.begin(), ranges.end(), std::make_pair(Range((offset + length), 0), default_value), &elem_key_less);
	
	typename std::vector< std::pair<Range, T> >::iterator erase_begin = next;
	typename std::vector< std::pair<Range, T> >::iterator erase_end   = next;
	
	while(erase_begin != ranges.begin())
	{
		auto sb_prev = std::prev(erase_begin);
		
		if((sb_prev->first.offset + sb_prev->first.length) > offset)
		{
			erase_begin = sb_prev;
		}
		else{
			break;
		}
	}
	
	bool elements_changed = false;
	
	/* Add range(s) encompassing the existing byte ranges immediately before or after the erase
	 * window (if either exist).
	*/
	
	if(erase_begin != erase_end)
	{
		auto erase_last = std::prev(erase_end);
		
		OT begin = std::min(erase_begin->first.offset, offset);
		OT end   = erase_last->first.offset + erase_last->first.length;
		
		T begin_value = erase_begin->second;
		T last_value  = erase_last->second;
		
		erase_end = ranges.erase(erase_begin, erase_end);
		
		if(end > (offset + length))
		{
			end -= length;
			
			if(begin_value == last_value)
			{
				erase_end = ranges.insert(erase_end, std::make_pair(Range(begin, (end - begin)), begin_value));
				++erase_end;
			}
			else{
				if(begin < offset)
				{
					erase_end = ranges.insert(erase_end, std::make_pair(Range(begin, (offset - begin)), begin_value));
					++erase_end;
				}
				
				assert(offset < end);
				
				erase_end = ranges.insert(erase_end, std::make_pair(Range(offset, (end - offset)), last_value));
				++erase_end;
			}
		}
		else if(begin < offset)
		{
			end = offset;
			erase_end = ranges.insert(erase_end, std::make_pair(Range(begin, (end - begin)), begin_value));
			++erase_end;
		}
		
		elements_changed = true;
	}
	
	/* Adjust the offset of ranges after the erase window. */
	
	while(erase_end != ranges.end())
	{
		erase_end->first.offset -= length;
		++erase_end;
		
		elements_changed = true;
	}
	
	last_get_iter = ranges.end();
	
	return elements_changed;
}

template<typename OT, typename T> bool REHex::RangeMap<OT, T>::elem_key_less(const std::pair<Range, T> &a, const std::pair<Range, T> &b)
{
	return a.first < b.first;
}

#endif /* !REHEX_BYTERANGEMAP_HPP */
