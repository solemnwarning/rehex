/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_INTELHEXEXPORT_HPP
#define REHEX_INTELHEXEXPORT_HPP

#include <string>

#include "document.hpp"

namespace REHex
{
	enum class IntelHexAddressingMode
	{
		IHA_16BIT,
		IHA_SEGMENTED,
		IHA_LINEAR,
	};
	
	enum class IntelHexRecordType
	{
		IRT_DATA = 0,
		IRT_EOF = 1,
		IRT_EXTENDED_SEGMENT_ADDRESS = 2,
		IRT_START_SEGMENT_ADDRESS = 3,
		IRT_EXTENDED_LINEAR_ADDRESS = 4,
		IRT_START_LINEAR_ADDRESS = 5,
	};
	
	void write_hex_file(const std::string &filename, const Document *doc, bool use_segments, IntelHexAddressingMode address_mode, const uint32_t *start_segment_address, const uint32_t *start_linear_address);
}

#endif /* !REHEX_INTELHEXEXPORT_HPP */
