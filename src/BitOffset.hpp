/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_BITOFFSET_HPP
#define REHEX_BITOFFSET_HPP

#include <stdint.h>

namespace REHex
{
	/**
	 * @brief Stores an offset/length with bit resolution.
	 *
	 * This class stores a file offset with bit precision represented by
	 * a signed 61-bit byte quantity and a signed 4-bit bit quantity (the
	 * sign bit is shared between both values).
	*/
	class BitOffset
	{
		private:
			int64_t value;
		
		public:
			BitOffset():
				value(0) {}
			
			BitOffset(off_t byte, int bit = 0)
			{
				assert(bit >= -7);
				assert(bit <= 7);
				assert((byte <= 0 && bit <= 0) || (byte >= 0 && bit >= 0));
				
				if(byte == 0)
				{
					value = bit;
				}
				else if(bit < 0)
				{
					value = ((int64_t)(byte) << 3) | (int64_t)(8 + bit);
				}
				else{
					value = ((int64_t)(byte) << 3) | (int64_t)(bit);
				}
				
				//value = ((int64_t)(byte) * 8) + (int64_t)(bit);
				
// 				if(byte == 0)
// 				{
// 					value = bit;
// 				}
// 				else{
// 					value = ((int64_t)(byte) << 3) | (int64_t)(bit);
// 				}
			}
			
			inline off_t byte() const
			{
				//return (value & ~(int64_t)(7)) / 8;
				return value >> 3;
			}
			
			inline int bit() const
			{
				return value % 8;
			}
			
			inline bool byte_aligned() const
			{
				return bit() == 0;
			}
			
			inline bool operator<(const BitOffset &rhs) const
			{
				return value < rhs.value;
			}
			
			inline off_t byte_round_up() const
			{
				return byte_aligned()
					? byte()
					: byte() + 1;
			}
	};
}

#endif /* !REHEX_BITOFFSET_HPP */
