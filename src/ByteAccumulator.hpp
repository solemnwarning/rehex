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

#ifndef REHEX_BYTEACCUMULATOR_HPP
#define REHEX_BYTEACCUMULATOR_HPP

#include <algorithm>
#include <stdint.h>

namespace REHex
{
	/**
	 * @brief Accumulate byte values for statistical analysis.
	 *
	 * This class records individual byte values and presents the following statistics:
	 *
	 * - Total number of bytes recorded.
	 * - Number of times each byte value was recorded.
	 * - Sum of all bytes values.
	 * - Lowest recorded byte value.
	 * - Highest recorded byte value.
	*/
	class ByteAccumulator
	{
		private:
			uint64_t count;
			uint64_t byte_counts[256];
			
			uint64_t sum;
			uint8_t min;
			uint8_t max;
			
		public:
			/**
			 * @brief Initialise a ByteAccumulator with counters at zero.
			*/
			ByteAccumulator()
			{
				reset();
			}
			
			/**
			 * @brief Reset counters to zero.
			*/
			void reset()
			{
				count = 0;
				sum = 0;
				
				for(int i = 0; i < 256; ++i)
				{
					byte_counts[i] = 0;
				}
			}
			
			/**
			 * @brief Add a byte value to the counters.
			*/
			void add_byte(uint8_t byte)
			{
				if(count > 0)
				{
					min = std::min(min, byte);
					max = std::max(max, byte);
				}
				else{
					min = byte;
					max = byte;
				}
				
				sum += byte;
				
				++count;
				++(byte_counts[byte]);
			}
			
			ByteAccumulator &operator+=(const ByteAccumulator &rhs)
			{
				if(count == 0)
				{
					min = rhs.min;
					max = rhs.max;
				}
				else if(rhs.count > 0)
				{
					min = std::min(min, rhs.min);
					max = std::max(max, rhs.max);
				}
				
				count += rhs.count;
				sum += rhs.sum;
				
				for(int i = 0; i < 256; ++i)
				{
					byte_counts[i] += rhs.byte_counts[i];
				}
				
				return *this;
			}
			
			ByteAccumulator &operator-=(const ByteAccumulator &rhs)
			{
				/* Assertions trigger on underflow since we cannot go negative. */
				
				assert(count >= rhs.count);
				count -= rhs.count;
				
				assert(sum >= rhs.sum);
				sum -= rhs.sum;
				
				min = 255;
				max = 0;
				
				for(int i = 0; i < 256; ++i)
				{
					assert(byte_counts[i] >= rhs.byte_counts[i]);
					byte_counts[i] -= rhs.byte_counts[i];
					
					if(byte_counts[i] > 0)
					{
						min = std::min<uint8_t>(min, i);
						max = std::max<uint8_t>(max, i);
					}
				}
				
				return *this;
			}
			
			/**
			 * @brief Get the number of bytes recorded.
			*/
			uint64_t get_total_bytes() const
			{
				return count;
			}
			
			/**
			 * @brief Get the number of bytes recorded with a specific value.
			*/
			uint64_t get_byte_count(uint8_t byte) const
			{
				return byte_counts[byte];
			}
			
			/**
			 * @brief Get the sum of all recorded byte values.
			*/
			uint64_t get_byte_sum() const
			{
				return sum;
			}
			
			/**
			 * @brief Get the smallest recorded byte.
			 *
			 * NOTE: Calling when no bytes have been recorded is undefined behaviour.
			*/
			uint8_t get_min_byte() const
			{
				assert(count > 0);
				return min;
			}
			
			/**
			 * @brief Get the largest recorded byte.
			 *
			 * NOTE: Calling when no bytes have been recorded is undefined behaviour.
			*/
			uint8_t get_max_byte() const
			{
				assert(count > 0);
				return max;
			}
	};
}

#endif /* !REHEX_BYTEACCUMULATOR_HPP */
