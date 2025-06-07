/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_BYTERANGESET_HPP
#define REHEX_BYTERANGESET_HPP

#include <assert.h>
#include <iterator>
#include <sys/types.h>
#include <vector>

#include "BitOffset.hpp"
#include "util.hpp"

#ifdef MAX
#undef MAX /* Fuck you GLib */
#endif

#ifdef NDEBUG
#define REHEX_BYTERANGESET_CHECK_PRE(begin, end) {}
#define REHEX_BYTERANGESET_CHECK_POST(begin, end) {}
#define REHEX_BYTERANGESET_CHECK(begin, end) {}

#else
#define REHEX_BYTERANGESET_CHECK_PRE(begin, end) \
	std::vector<Range> _pre_check_ranges(begin, end);

#define REHEX_BYTERANGESET_CHECK_POST(begin_i, end_i) \
{ \
	if(!dbg_check_order(begin_i, end_i)) \
	{ \
		fprintf(stderr, "ByteRangeSet inconsistency detected at %s:%d\n\n", __FILE__, __LINE__); \
		\
		fprintf(stderr, "Dumping previous (good) state:\n"); \
		dbg_dump(_pre_check_ranges.begin(), _pre_check_ranges.end()); \
		fprintf(stderr, "\n"); \
		\
		fprintf(stderr, "Dumping current (bad) state:\n"); \
		dbg_dump(begin_i, end_i); \
		fprintf(stderr, "\n"); \
		\
		assert(false && dbg_check_order(begin_i, end_i)); \
	} \
}

#define REHEX_BYTERANGESET_CHECK(begin, end) \
{ \
	if(!dbg_check_order(begin, end)) \
	{ \
		fprintf(stderr, "ByteRangeSet inconsistency detected at %s:%d\n\n", __FILE__, __LINE__); \
		\
		fprintf(stderr, "Dumping values:\n"); \
		dbg_dump(begin, end); \
		fprintf(stderr, "\n"); \
		\
		assert(false && dbg_check_order(begin, end)); \
	} \
}
#endif

namespace REHex
{
	/**
	 * @brief Stores ranges of bytes and provides set operations.
	 *
	 * This class is a wrapper around std::vector that can be used for efficiently storing
	 * ranges. Any ranges which are adjacent or overlapping will be merged to reduce memory
	 * consumption, so only each unique contiguous range added will take space in memory.
	*/
	template<typename OT> class RangeSet
	{
		public:
			/**
			 * @brief A range stored within a RangeSet.
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
			
			static OT MAX();
			
			typedef typename std::vector<Range>::iterator iterator;
			typedef typename std::vector<Range>::const_iterator const_iterator;
			
		private:
			std::vector<Range> ranges;
			
		public:
			/**
			 * @brief Construct an empty set.
			*/
			RangeSet() {}
			
			/**
			 * @brief Construct a set from a sequence of ranges.
			 *
			 * NOTE: The ranges MUST be in order and MUST NOT be adjacent.
			*/
			template<typename T> RangeSet(const T begin, const T end):
				ranges(begin, end) {}
			
			bool operator==(const RangeSet<OT> &rhs) const
			{
				return ranges == rhs.ranges;
			}
			
			/**
			 * @brief Set a range of bytes in the set.
			 *
			 * This method adds a range of bytes to the set. Any existing ranges
			 * adjacent to or within the new range will be merged into the new range
			 * and removed from the set.
			 *
			 * Returns a reference to the set to allow for chaining.
			*/
			RangeSet<OT> &set_range(OT offset, OT length);
			
			/**
			 * @brief Set multiple ranges of bytes in the set.
			 *
			 * This method takes a pair of Range iterators (or pointers) and adds all
			 * of the ranges to the set. It is more efficient than calling set_range()
			 * multiple times.
			 *
			 * NOTE: The ranges MUST be in order and MUST NOT be adjacent.
			 *
			 * If size_hint is provided and the internal vector is near its limit, the
			 * vector's capacity will be expanded to size_hint elements instead of only
			 * growing enough to accomodate this operation.
			*/
			template<typename T> void set_ranges(const T begin, const T end, size_t size_hint = 0);
			
			/**
			 * @brief Clear a range of bytes in the set.
			 *
			 * This method clears a range of bytes in the set. Ranges within the set
			 * will be split if necessary to preserve bytes outside of the range to be
			 * cleared.
			*/
			void clear_range(OT offset, OT length);
			
			/**
			 * @brief Clear multiple ranges of bytes in the set.
			 *
			 * This method takes a pair of Range iterators (or pointers) and removes
			 * all of the ranges from the set. It is more efficient than calling
			 * clear_range() multiple times.
			 *
			 * NOTE: The ranges MUST be in order, MUST NOT be adjacent and MUST NOT be
			 * within the set itself.
			*/
			template<typename T> void clear_ranges(const T begin, const T end);
			
			/**
			 * @brief Clear all ranges in the set.
			*/
			void clear_all();
			
			/**
			 * @brief Check if a range is set in the set.
			*/
			bool isset(OT offset, OT length = 1) const;
			
			/**
			 * @brief Check if any bytes in a range are set in the set.
			*/
			bool isset_any(OT offset, OT length) const;
			
			/**
			 * @brief Find the first Range that intersects the given range.
			 * @return An iterator into the internal vector, or end.
			*/
			const_iterator find_first_in(OT offset, OT length) const;
			
			/**
			 * @brief Find the last Range that intersects the given range.
			 * @return An iterator into the internal vector, or end.
			*/
			const_iterator find_last_in(OT offset, OT length) const;
			
			/**
			 * @brief Get the total number of bytes encompassed by the set.
			*/
			OT total_bytes() const;
			
			/**
			 * @brief Get a reference to the internal std::vector.
			*/
			const std::vector<Range> &get_ranges() const;
			
			/**
			 * @brief Returns a const_iterator to the first Range in the set.
			*/
			const_iterator begin() const;
			
			/**
			 * @brief Returns a const_iterator to the end of the set.
			*/
			const_iterator end() const;
			
			/**
			 * @brief Access the n-th range in the set.
			*/
			const Range &operator[](size_t idx) const;
			
			/**
			 * @brief Access the first range in the set.
			*/
			const Range &first() const { return ranges.front(); }
			
			/**
			 * @brief Access the last range in the set.
			*/
			const Range &last() const { return ranges.back(); }
			
			/**
			 * @brief Returns the number of ranges in the set.
			*/
			size_t size() const;
			
			/**
			 * @brief Returns true if the set is empty.
			*/
			bool empty() const;
			
			/**
			 * @brief Adjust for data being inserted into file.
			 *
			 * Ranges after the insertion will be moved along by the size of the
			 * insertion. Ranges spanning the insertion will be split.
			*/
			void data_inserted(off_t offset, off_t length);
			
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
			void data_erased(off_t offset, off_t length);
			
			/**
			 * @brief Find the intersection of two sets.
			 *
			 * Returns a RangeSet<OT> containing only the ranges of bytes which are set
			 * in BOTH sets.
			*/
			static RangeSet<OT> intersection(const RangeSet<OT> &a, const RangeSet<OT> &b);
			
			#ifndef NDEBUG
			template<typename T> static bool dbg_check_order(T begin, T end);
			template<typename T> static void dbg_dump(T begin, T end);
			#endif
			
		private:
			void data_inserted_impl(OT offset, OT length);
			void data_erased_impl(OT offset, OT length);
	};
	
	using ByteRangeSet = RangeSet<off_t>;
	using BitRangeSet = RangeSet<BitOffset>;
	
	/**
	 * @brief Variant of RangeSet that preserves insertion order of ranges.
	 *
	 * This class is similar to RangeSet, except when iterating over the ranges in the set
	 * you will get them in the order they were inserted rather than sorted by offset.
	 *
	 * An OrderedRangeSet can be implicitly converted to a RangeSet, but the reverse is
	 * not true.
	 *
	 * NOTE: Doesn't implement all functionality of RangeSet, uses more memory and is
	 * slower - only use it if you need the ordered behaviour.
	 *
	 * Use OrderedByteRangeSet or OrderedBitRangeSet rather than instantiating this template
	 * directly.
	*/
	template<typename OT> class OrderedRangeSet
	{
		private:
			RangeSet<OT> brs;
			std::vector<typename RangeSet<OT>::Range> sorted_ranges;
			
		public:
			bool operator==(const OrderedRangeSet<OT> &rhs) const
			{
				return sorted_ranges == rhs.sorted_ranges;
			}
			
			/* Allow conversion to a (const) ByteRangeSet reference. */
			operator const RangeSet<OT>&() const
			{
				return brs;
			}
			
			/**
			 * @see ByteRangeSet::set_range()
			*/
			OrderedRangeSet<OT> &set_range(OT offset, OT length);
			
			/**
			 * @see ByteRangeSet::isset()
			*/
			bool isset(OT offset, OT length = 1) const;
			
			/**
			 * @see ByteRangeSet::isset_any()
			*/
			bool isset_any(OT offset, OT length) const;
			
			/**
			 * @see ByteRangeSet::total_bytes()
			*/
			OT total_bytes() const;
			
			/**
			 * @see ByteRangeSet::get_ranges()
			*/
			const std::vector<typename RangeSet<OT>::Range> &get_ranges() const;
			
			/**
			 * @see ByteRangeSet::begin()
			*/
			typename std::vector<typename RangeSet<OT>::Range>::const_iterator begin() const;
			
			/**
			 * @see ByteRangeSet::end()
			*/
			typename std::vector<typename RangeSet<OT>::Range>::const_iterator end() const;
			
			/**
			 * @brief Access the n-th range in the set.
			*/
			const typename RangeSet<OT>::Range &operator[](size_t idx) const;
			
			/**
			 * @see ByteRangeSet::size()
			*/
			size_t size() const;
			
			/**
			 * @see ByteRangeSet::empty()
			*/
			bool empty() const;
	};
	
	using OrderedByteRangeSet = OrderedRangeSet<off_t>;
	using OrderedBitRangeSet = OrderedRangeSet<BitOffset>;
}

#ifndef NDEBUG
template<typename OT> template<typename T> bool REHex::RangeSet<OT>::dbg_check_order(T begin, T end)
{
	for(auto r = begin; r != end; ++r)
	{
		if(r != begin && (std::prev(r)->offset + std::prev(r)->length) >= r->offset)
		{
			return false;
		}
	}
	
	return true;
}

template<> template<typename T> void REHex::RangeSet<off_t>::dbg_dump(T begin, T end)
{
	for(auto r = begin; r != end; ++r)
	{
		fprintf(stderr, "{ offset = %lld, length = %lld }\n", (long long)(r->offset), (long long)(r->length));
	}
}

template<> template<typename T> void REHex::RangeSet<REHex::BitOffset>::dbg_dump(T begin, T end)
{
	for(auto r = begin; r != end; ++r)
	{
		fprintf(stderr, "{ offset = %lld.%d, length = %lld.%d }\n",
			(long long)(r->offset.byte()), r->offset.bit(),
			(long long)(r->length.byte()), r->length.bit());
	}
}
#endif

template<typename OT> template<typename T> void REHex::RangeSet<OT>::set_ranges(const T begin, const T end, size_t size_hint)
{
	REHEX_BYTERANGESET_CHECK_PRE(ranges.begin(), ranges.end());
	
	size_t min_size_hint = ranges.size() + std::distance(begin, end);
	if(ranges.capacity() < min_size_hint)
	{
		/* Round up to the nearest page size (assuming 4KiB pages and 64-bit off_t) */
		if((min_size_hint % 256) != 0)
		{
			min_size_hint += 256 - (min_size_hint % 256);
		}
		
		ranges.reserve(std::max(min_size_hint, size_hint));
	}
	
	auto next = ranges.begin();
	
	/* Existing elements which intersect the ones we are inserting are erased and the new ones
	 * expand to encompass the whole range.
	 *
	 * Adjacent erase and insert operations are merged for performance. The group_erase_begin
	 * and group_erase_end iterators encompass the full range of adjacent elements to be erased
	 * from sequential inserts and group_ranges contains all adjacent elements to be inserted.
	*/
	typename std::vector<Range>::iterator group_erase_begin;
	typename std::vector<Range>::iterator group_erase_end;
	typename std::vector<Range> group_ranges;
	
	for(auto r = begin; r != end;)
	{
		assert(r == begin || (std::prev(r)->offset + std::prev(r)->length) < r->offset);
		
		OT offset = r->offset;
		OT length = r->length;
		
		/* Find the range of elements that intersects the one we are inserting. They will be erased
		 * and the one we are creating will grow on either end as necessary to encompass them.
		*/
		
		next = std::lower_bound(next, ranges.end(), Range((offset + length), 0));
		
		typename std::vector<Range>::iterator erase_begin = next;
		typename std::vector<Range>::iterator erase_end   = next;
		
		while(erase_begin != ranges.begin())
		{
			auto eb_prev = std::prev(erase_begin);
			
			if((eb_prev->offset + eb_prev->length) >= offset)
			{
				OT merged_begin = std::min(eb_prev->offset, offset);
				OT merged_end   = std::max((eb_prev->offset + eb_prev->length), (offset + length));
				
				offset = merged_begin;
				length = merged_end - merged_begin;
				
				erase_begin = eb_prev;
			}
			else{
				break;
			}
		}
		
		if(erase_end != ranges.end() && erase_end->offset == (offset + length))
		{
			length += erase_end->length;
			++erase_end;
		}
		
		assert(length > 0);
		
		if(!group_ranges.empty() && erase_begin != group_erase_end)
		{
			/* We have elements pending to be inserted earlier in the vector, flush
			 * them out so we can start a new group.
			*/
			
			next = ranges.erase(group_erase_begin, group_erase_end);
			
			/* Workaround for older GCC/libstd++ which have the wrong return type
			 * (void) on multi-element std::vector::insert(), even under C++11 mode.
			 *
			 * Not 100% sure which version actually fixed it.
			*/
			
			#if !defined(__clang__) && defined(__GNUC__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 9))
			for(auto i = group_ranges.begin(); i != group_ranges.end(); ++i)
			{
				next = ranges.insert(next, *i);
				++next;
			}
			#else
			next = ranges.insert(next, group_ranges.begin(), group_ranges.end());
			std::advance(next, group_ranges.size());
			#endif
			
			group_ranges.clear();
			
			/* The erase and insert operations have invalidated the erase_begin and
			 * erase_end iterators, so start processing this Range again.
			*/
			continue;
		}
		
		if(group_ranges.empty())
		{
			/* We are starting a new range of insertions, initialize group_erase_begin
			 * to the erase_begin of this range.
			*/
			group_erase_begin = erase_begin;
		}
		
		/* Advance group_erase_end to the end of this range's erase block. */
		group_erase_end = erase_end;
		
		group_ranges.push_back(Range(offset, length));
		
		++r;
	}
	
	if(!group_ranges.empty())
	{
		/* Flush pending erase/insert operations. */
		
		next = ranges.erase(group_erase_begin, group_erase_end);
		ranges.insert(next, group_ranges.begin(), group_ranges.end());
	}
	
	REHEX_BYTERANGESET_CHECK_POST(ranges.begin(), ranges.end());
}

template<typename OT> template<typename T> void REHex::RangeSet<OT>::clear_ranges(const T begin, const T end)
{
	REHEX_BYTERANGESET_CHECK_PRE(ranges.begin(), ranges.end());
	
	auto next = ranges.begin();
	
	/* Existing elements which intersect the ones we are clearing are erased and any adjacent
	 * bytes which become cleared as a side effect are re-inserted as new ranges.
	 *
	 * Adjacent erase and insert operations are merged for performance. The group_erase_begin
	 * and group_erase_end iterators encompass the full range of adjacent elements to be erased
	 * from sequential inserts and group_replacements contains all adjacent ranges to be
	 * re-inserted at the same position.
	*/
	typename std::vector<Range>::iterator group_erase_begin = ranges.end();
	typename std::vector<Range>::iterator group_erase_end   = ranges.end();
	typename std::vector<Range> group_replacements;
	
	for(auto r = begin; r != end;)
	{
		assert(r == begin || (std::prev(r)->offset + std::prev(r)->length) < r->offset);
		
		OT offset = r->offset;
		OT length = r->length;
		
		/* Find the range of elements overlapping the range to be cleared. */
		
		next = std::lower_bound(next, ranges.end(), Range(add_clamp_overflow(offset, length), 0));
		
		typename std::vector<Range>::iterator erase_begin = next;
		typename std::vector<Range>::iterator erase_end   = next;
		
		while(erase_begin != ranges.begin())
		{
			auto eb_prev = std::prev(erase_begin);
			
			if((eb_prev->offset + eb_prev->length) >= offset)
			{
				erase_begin = eb_prev;
			}
			else{
				break;
			}
		}
		
		if(group_erase_begin != group_erase_end)
		{
			if(erase_begin != group_erase_end)
			{
				/* We have elements pending to be erased/replaced earlier in the
				 * vector, flush them out so we can start a new group.
				*/
				
				next = ranges.erase(group_erase_begin, group_erase_end);
				
				/* Workaround for older GCC/libstd++ which have the wrong return type
				 * (void) on multi-element std::vector::insert(), even under C++11 mode.
				 *
				 * Not 100% sure which version actually fixed it.
				*/
				
				#if !defined(__clang__) && defined(__GNUC__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 9))
				for(auto i = group_replacements.begin(); i != group_replacements.end(); ++i)
				{
					next = ranges.insert(next, *i);
					++next;
				}
				#else
				next = ranges.insert(next, group_replacements.begin(), group_replacements.end());
				std::advance(next, group_replacements.size());
				#endif
				
				group_erase_begin = ranges.end();
				group_erase_end   = ranges.end();
				group_replacements.clear();
				
				/* The erase and insert operations have invalidated the erase_begin
				 * and erase_end iterators, so start processing this Range again.
				*/
				continue;
			}
		}
		else{
			group_erase_begin = erase_begin;
		}
		
		/* Advance group_erase_end to the end of this range's erase block. */
		group_erase_end = erase_end;
		
		/* If the elements to be erased to not fall fully within the given range, then we shall
		 * populate group_replacements with up to two elements to re-instate the lost ranges.
		*/
		
		if(erase_begin != erase_end)
		{
			if(erase_begin->offset < offset)
			{
				/* Clear range is within erase range, so create a new Range from
				 * the start of the range to be erased up to the start of the range
				 * to be cleared.
				*/
				
				group_replacements.push_back(Range(erase_begin->offset, (offset - erase_begin->offset)));
			}
			
			auto erase_last = std::prev(erase_end);
			
			if((erase_last->offset + erase_last->length) > add_clamp_overflow(offset, length))
			{
				/* Clear range falls short of the end of the range to be erased, so
				 * create a range from the end of the clear range to the end of the
				 * erase range.
				*/
				
				OT from = add_clamp_overflow(offset, length);
				OT to   = erase_last->offset + erase_last->length;
				
				assert(to > from);
				
				group_replacements.push_back(Range(from, (to - from)));
			}
		}
		
		++r;
	}
	
	/* Flush pending erase/insert operations. */
	
	next = ranges.erase(group_erase_begin, group_erase_end);
	ranges.insert(next, group_replacements.begin(), group_replacements.end());
	
	REHEX_BYTERANGESET_CHECK_POST(ranges.begin(), ranges.end());
}

#endif /* !REHEX_BYTERANGESET_HPP */
