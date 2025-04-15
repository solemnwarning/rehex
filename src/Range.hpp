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

#ifndef REHEX_RANGE_HPP
#define REHEX_RANGE_HPP

#include "BitOffset.hpp"

namespace REHex
{
	/**
	 * @brief Representation of a range in a file/memory/etc
	 *
	 * The Range struct represents a range of values as a start offset and
	 * length and provides convinience methods for working with them.
	*/
	template<typename OT> struct Range
	{
		OT offset;
		OT length;
		
		/**
		 * @brief Construct a new Range from an offset and a length.
		*/
		Range(OT offset, OT length):
			offset(offset),
			length(length) {}
		
		/**
		 * @brief Get the end (i.e. offset + length) of the range.
		*/
		inline OT end() const
		{
			return offset + length;
		}
		
		/**
		 * @brief Check if the range overlaps with another.
		*/
		inline bool overlaps(const Range &other) const
		{
			return offset < other.end() && other.offset < end();
		}
		
		/**
		 * @brief Check if another range fully fits within this range.
		*/
		inline bool contains(const Range &other) const
		{
			return other.offset >= offset && other.end() <= end();
		}
		
		/**
		 * @brief Get the intersection of two ranges.
		*/
		static Range intersection(const Range &a, const Range &b)
		{
			OT i_offset = std::max(a.offset, b.offset);
			OT i_end = std::min(a.end(), b.end());
			
			if(i_offset < i_end)
			{
				return Range(i_offset, (i_end - i_offset));
			}
			else{
				return Range(i_offset, (i_offset - i_offset));
			}
		}
		
		/**
		 * @brief Check if the length of this range is zero.
		*/
		inline bool empty() const
		{
			return offset == end();
		}
		
		inline bool operator<(const Range &rhs) const
		{
			if(offset != rhs.offset)
			{
				return offset < rhs.offset;
			}
			else{
				return length < rhs.length;
			}
		}
		
		inline bool operator==(const Range &rhs) const
		{
			return offset == rhs.offset && length == rhs.length;
		}
	};
	
	using ByteRange = Range<off_t>;
	using BitRange = Range<BitOffset>;
};

#endif /* !REHEX_RANGE_HPP */
