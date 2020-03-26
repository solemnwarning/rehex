/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_UTIL_HPP
#define REHEX_UTIL_HPP

#include <stdexcept>
#include <string>
#include <vector>

namespace REHex {
	class ParseError: public std::runtime_error
	{
		public:
			ParseError(const char *what);
	};
	
	class ClipboardGuard
	{
		private:
			bool open;
			
		public:
			ClipboardGuard();
			~ClipboardGuard();
			
			void close();
			
			operator bool() const
			{
				return open;
			}
	};
	
	std::vector<unsigned char> parse_hex_string(const std::string &hex_string);
	unsigned char parse_ascii_nibble(char c);
	
	void file_manager_show_file(const std::string &filename);
	
	enum OffsetBase {
		OFFSET_BASE_HEX = 1,
		OFFSET_BASE_DEC = 2,
		
		OFFSET_BASE_MIN = 1,
		OFFSET_BASE_MAX = 2,
	};
	
	std::string format_offset(off_t offset, OffsetBase base, off_t upper_bound = -1);
}

#endif /* !REHEX_UTIL_HPP */
