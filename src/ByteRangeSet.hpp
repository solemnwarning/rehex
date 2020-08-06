/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <set>
#include <sys/types.h>

namespace REHex
{
	/**
	 * @brief Wrapper around std::set for storing ranges in a file.
	 *
	 * This class is a wrapper around std::set that can be used for storing ranges. Any ranges
	 * which are adjacent or overlapping will be merged to reduce memory consumption, so only
	 * each unique contiguous range added will take space in memory.
	*/
	class ByteRangeSet
	{
		public:
			/**
			 * @brief A range stored within a ByteRangeSet.
			*/
			struct Range
			{
				off_t offset;
				off_t length;
				
				Range(off_t offset, off_t length):
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
			
		private:
			std::set<Range> ranges;
			
		public:
			/**
			 * @brief Set a range of bytes in the set.
			 *
			 * This method adds a range of bytes to the set. Any existing ranges
			 * adjacent to or within the new range will be merged into the new range
			 * and removed from the set.
			*/
			void set_range(off_t offset, off_t length);
			
			/**
			 * @brief Clear a range of bytes in the set.
			 *
			 * This method clears a range of bytes in the set. Ranges within the set
			 * will be split if necessary to preserve bytes outside of the range to be
			 * cleared.
			*/
			void clear_range(off_t offset, off_t length);
			
			/**
			 * @brief Clear all ranges in the set.
			*/
			void clear_all();
			
			/**
			 * @brief Check if a byte is set in the set.
			*/
			bool isset(off_t offset) const;
			
			/**
			 * @brief Get a reference to the internal std::set.
			*/
			const std::set<Range> &get_ranges() const;
			
			/**
			 * @brief Adjust for data being inserted into file.
			 *
			 * Ranges after the insertion will be moved along by the size of the
			 * insertion. Ranges spanning the insertion will be split.
			*/
			void data_inserted(off_t offset, off_t length);
			
			/**
			 * @brief Adjust for data being erased from file.
			 *
			 * Ranges after the section erased will be moved back by the size of the
			 * insertion. Ranges wholly within the erased section will be lost. Ranges
			 * on either side of the erase will be truncated and merged as necessary.
			*/
			void data_erased(off_t offset, off_t length);
	};
}

#endif /* !REHEX_BYTERANGESET_HPP */
