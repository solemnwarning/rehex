/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <assert.h>
#include <jansson.h>
#include <stdint.h>
#include <string>

#ifdef MAX
#undef MAX /* Fuck you GLib */
#endif

namespace REHex
{
	enum class NumBase
	{
		BIN,
		OCT,
		DEC,
		HEX,
	};
	
	enum class NumFormat
	{
		NONE = 0,    /**< No special formatting, just a number. */
		PREFIX = 1,  /**< Include base prefix (where applicable). */
	};
	
	inline constexpr NumFormat operator|(NumFormat lhs, NumFormat rhs)
	{
		return (NumFormat)((unsigned)(lhs) | (unsigned)(rhs));
	}
	
	inline constexpr NumFormat operator&(NumFormat lhs, NumFormat rhs)
	{
		return (NumFormat)((unsigned)(lhs) & (unsigned)(rhs));
	}
	
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
			static const BitOffset &INVALID;
			static const BitOffset &ZERO;
			
			static const BitOffset &MIN;
			static const BitOffset &MAX;
			
			BitOffset():
				value(0) {}
			
			BitOffset(off_t byte, int bit = 0)
			{
				assert(bit >= -7);
				assert(bit <= 7);
				assert((byte <= 0 && bit <= 0) || (byte >= 0 && bit >= 0));
				
				value = ((int64_t)(byte) * 8) + (int64_t)(bit);
			}
			
			class ConstantTag {};
			constexpr BitOffset(off_t byte, int bit, ConstantTag tag):
				value(((int64_t)(byte) * 8) + (int64_t)(bit)) {}
			
			/**
			 * @brief Reconstruct a BitOffset previously serialised to JSON.
			*/
			static BitOffset from_json(json_t *json);
			
			/**
			 * @brief Serialise BitOffset to JSON.
			*/
			json_t *to_json() const;
			
			/**
			 * @brief Unpack a BitOffset previously packed into an int64_t.
			*/
			static inline BitOffset from_int64(int64_t value)
			{
				return BitOffset((value / 8), (value % 8));
			}
			
			/**
			 * @brief Pack a BitOffset into an int64_t.
			*/
			int64_t to_int64() const
			{
				return value;
			}
			
			std::string to_string(NumBase base, NumFormat format) const;
			
			static inline BitOffset BITS(int bits)
			{
				return BitOffset((bits / 8), (bits % 8));
			}
			
			static inline BitOffset BYTES(off_t bytes)
			{
				return BitOffset(bytes, 0);
			}
			
			inline off_t byte() const
			{
				return value / 8;
			}
			
			inline int bit() const
			{
				return value % 8;
			}
			
			inline int64_t total_bits() const
			{
				return value;
			}
			
			inline bool byte_aligned() const
			{
				return bit() == 0;
			}
			
			inline bool operator<(const BitOffset &rhs) const
			{
				return value < rhs.value;
			}
			
			inline bool operator>(const BitOffset &rhs) const
			{
				return value > rhs.value;
			}
			
			inline bool operator<=(const BitOffset &rhs) const
			{
				return value <= rhs.value;
			}
			
			inline bool operator>=(const BitOffset &rhs) const
			{
				return value >= rhs.value;
			}
			
			inline off_t byte_round_up() const
			{
				return byte_aligned()
					? byte()
					: byte() + 1;
			}
			
			inline bool operator==(const BitOffset &rhs) const
			{
				return value == rhs.value;
			}
			
			inline bool operator!=(const BitOffset &rhs) const
			{
				return value != rhs.value;
			}
			
			inline BitOffset &operator+=(const BitOffset &rhs)
			{
				value += rhs.value;
				return *this;
			}
			
			inline BitOffset &operator-=(const BitOffset &rhs)
			{
				value -= rhs.value;
				return *this;
			}
			
			inline BitOffset operator+(const BitOffset &rhs) const
			{
				BitOffset b;
				b.value = value + rhs.value;
				
				return b;
			}
			
			inline BitOffset operator-(const BitOffset &rhs) const
			{
				BitOffset b;
				b.value = value - rhs.value;
				
				return b;
			}
			
			inline BitOffset operator%(const BitOffset &rhs) const
			{
				BitOffset b;
				b.value = value % rhs.value;
				
				return b;
			}
			
			inline BitOffset operator-() const
			{
				BitOffset b;
				b.value = -value;
				
				return b;
			}
	};
}

#endif /* !REHEX_BITOFFSET_HPP */
