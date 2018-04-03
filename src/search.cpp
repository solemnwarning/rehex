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

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <utility>

#include "search.hpp"

REHex::Search::Search(REHex::Document &doc):
	doc(doc), range_begin(0), range_end(-1), align_to(1), align_from(0) {}

void REHex::Search::limit_range(off_t range_begin, off_t range_end)
{
	assert(range_begin >= 0);
	
	this->range_begin = range_begin;
	this->range_end   = range_end;
}

void REHex::Search::require_alignment(off_t alignment, off_t relative_to_offset)
{
	assert(alignment > 0);
	assert(relative_to_offset >= 0);
	
	align_to   = alignment;
	align_from = relative_to_offset;
}

off_t REHex::Search::find_next(off_t from_offset)
{
	from_offset = std::max(from_offset, range_begin);
	
	if(((from_offset - align_from) % align_to) != 0)
	{
		from_offset += (align_to - ((from_offset - align_from) % align_to));
	}
	
	off_t end = (range_end >= 0 ? range_end : doc.buffer_length());
	
	for(off_t at = from_offset; at < end; at += align_to)
	{
		if(test(at, (end - at)))
		{
			return at;
		}
	}
	
	return -1;
}

REHex::Search::Text::Text(REHex::Document &doc, const std::string &search_for, bool case_sensitive):
	Search(doc), search_for(search_for), case_sensitive(case_sensitive) {}

bool REHex::Search::Text::test(off_t offset, off_t max_length)
{
	off_t read_bytes = std::min(max_length, (off_t)(search_for.size()));
	
	std::vector<unsigned char> data = doc.read_data(offset, read_bytes);
	
	if(case_sensitive)
	{
		return (data.size() >= search_for.size()
			&& strncmp((char*)(data.data()), search_for.c_str(), search_for.size()) == 0);
	}
	else{
		return (data.size() >= search_for.size()
			&& strncasecmp((char*)(data.data()), search_for.c_str(), search_for.size()) == 0);
	}
}
