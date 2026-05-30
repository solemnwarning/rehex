/* Reverse Engineer's Hex Editor
 * Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_FOURCC_HPP
#define REHEX_FOURCC_HPP

#include <portable_endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

namespace REHex
{
	class FourCC
	{
		private:
			union {
				uint32_t m_code;
				const char m_string[5];
			};

		public:
			template<size_t N>
			constexpr FourCC(char const (&str)[N]):
				m_string{ str[0], str[1], str[2], str[3], 0 }
			{
				static_assert(N == 5, "FourCC code must be a 4 character string");
			}

			constexpr FourCC(char a, char b, char c, char d):
				m_string{a, b, c, d, '\0'} {}

			bool operator==(const FourCC &rhs) const
			{
				return m_code == rhs.m_code;
			}

			bool operator!=(const FourCC &rhs) const
			{
				return m_code != rhs.m_code;
			}

			bool operator<(const FourCC &rhs) const
			{
				/* Compare big endian number. */
				return memcmp(&m_code, &(rhs.m_code), sizeof(m_code)) < 0;
			}

			uint32_t code() const
			{
				return m_code;
			}

			const char *string() const
			{
				return m_string;
			}
	};
}

#endif /* !REHEX_FOURCC_HPP */
