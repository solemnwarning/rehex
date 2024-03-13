/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "platform.hpp"

#include "BitOffset.hpp"

static const int64_t INT61_MIN = -0x1000000000000000LL;
static const int64_t INT61_MAX = 0xFFFFFFFFFFFFFFFLL;

const REHex::BitOffset REHex::BitOffset::INVALID(-1, 0);
const REHex::BitOffset REHex::BitOffset::ZERO(0, 0);

const REHex::BitOffset REHex::BitOffset::MIN(INT61_MIN + 1, -7);
const REHex::BitOffset REHex::BitOffset::MAX(INT61_MAX, 7);

REHex::BitOffset REHex::BitOffset::from_json(json_t *json)
{
	if(json_is_integer(json))
	{
		return BitOffset(json_integer_value(json), 0);
	}
	else if(json_array_size(json) == 2) /* json_array_size() returns zero for non-arrays. */
	{
		json_t *json_byte = json_array_get(json, 0);
		json_t *json_bit  = json_array_get(json, 1);
		
		if(json_is_integer(json_byte) && json_is_integer(json_bit))
		{
			int64_t byte = json_integer_value(json_byte);
			int bit      = json_integer_value(json_bit);
			
			if(byte >= INT61_MIN && byte <= 0 && bit >= -7 && bit <= 0)
			{
				return BitOffset(byte, bit);
			}
			else if(byte >= 0 && byte <= INT61_MAX && bit >= 0 && bit <= 7)
			{
				return BitOffset(byte,bit);
			}
		}
	}
	
	return INVALID;
}

json_t *REHex::BitOffset::to_json() const
{
	json_t *js_offset = NULL;
	
	if(byte_aligned())
	{
		js_offset = json_integer(byte());
	}
	else{
		js_offset = json_array();
		
		if(json_array_append_new(js_offset, json_integer(byte())) == -1
			|| json_array_append_new(js_offset, json_integer(bit())) == -1)
		{
			json_decref(js_offset);
			js_offset = NULL;
		}
	}
	
	return js_offset;
}
